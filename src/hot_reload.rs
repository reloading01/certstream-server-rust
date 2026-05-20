use arc_swap::ArcSwap;
use notify::{Config as NotifyConfig, Event, RecommendedWatcher, RecursiveMode, Watcher};
use std::path::Path;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

use crate::config::{AuthConfig, ConnectionLimitConfig, RateLimitConfig};

#[derive(Debug, Clone)]
pub struct HotReloadableConfig {
    pub connection_limit: ConnectionLimitConfig,
    pub rate_limit: RateLimitConfig,
    pub auth: AuthConfig,
}

pub struct HotReloadManager {
    config: ArcSwap<HotReloadableConfig>,
}

impl HotReloadManager {
    pub fn new(initial: HotReloadableConfig) -> Arc<Self> {
        Arc::new(Self {
            config: ArcSwap::new(Arc::new(initial)),
        })
    }

    pub fn get(&self) -> Arc<HotReloadableConfig> {
        self.config.load_full()
    }

    pub fn update(&self, new_config: HotReloadableConfig) {
        self.config.store(Arc::new(new_config));
        info!("hot reload: configuration updated");
        metrics::counter!("certstream_config_reloads").increment(1);
    }

    pub fn start_watching(self: Arc<Self>, config_path: Option<String>, cancel: CancellationToken) {
        let Some(path) = config_path else {
            info!("hot reload: no config file specified, disabled");
            return;
        };

        if !Path::new(&path).exists() {
            warn!(path = %path, "hot reload: config file not found, disabled");
            return;
        }

        let path_clone = path.clone();
        let manager = self.clone();

        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("failed to build runtime for config watcher");

            rt.block_on(async move {
                let (tx, mut rx) = tokio::sync::mpsc::channel::<notify::Result<Event>>(100);

                let mut watcher = match RecommendedWatcher::new(
                    move |res| {
                        let _ = tx.blocking_send(res);
                    },
                    NotifyConfig::default(),
                ) {
                    Ok(w) => w,
                    Err(e) => {
                        error!(error = %e, "hot reload: failed to create file watcher");
                        return;
                    }
                };

                if let Err(e) = watcher.watch(Path::new(&path_clone), RecursiveMode::NonRecursive) {
                    error!(path = %path_clone, error = %e, "hot reload: failed to watch config file");
                    return;
                }

                info!(path = %path_clone, "hot reload: watching config file for changes");

                loop {
                    tokio::select! {
                        _ = cancel.cancelled() => {
                            info!("hot reload: shutdown signal received, stopping watcher");
                            break;
                        }
                        event = rx.recv() => {
                            match event {
                                Some(Ok(event)) => {
                                    if event.kind.is_modify() || event.kind.is_create() {
                                        info!("hot reload: config file changed, reloading...");
                                        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

                                        let current = manager.get();
                                        if let Some(new_config) =
                                            load_hot_reloadable_config(&path_clone, &current)
                                        {
                                            manager.update(new_config);
                                        }
                                    }
                                }
                                Some(Err(e)) => {
                                    warn!(error = %e, "hot reload: file watch error");
                                }
                                None => break,
                            }
                        }
                    }
                }
            });
        });
    }
}

/// Load a partial config from YAML, falling back to the CURRENT in-memory
/// hot-reloadable state for any section that's absent or unparseable.
///
/// **Security-critical fix (formerly P0)**: pre-1.5.0 this returned
/// `AuthConfig::default()` for a missing `auth:` block — which is
/// `enabled = false`. A deployment that enabled auth via env-only
/// (`CERTSTREAM_AUTH_ENABLED=true`) plus a YAML without an explicit `auth:`
/// section would silently DROP authentication on the first config-file
/// modification. The fix keeps each section's *current* state unless the
/// reload explicitly overrides it.
fn load_hot_reloadable_config(
    path: &str,
    current: &HotReloadableConfig,
) -> Option<HotReloadableConfig> {
    use serde::Deserialize;

    #[derive(Deserialize, Default)]
    struct PartialConfig {
        #[serde(default)]
        connection_limit: Option<ConnectionLimitConfig>,
        #[serde(default)]
        rate_limit: Option<RateLimitConfig>,
        #[serde(default)]
        auth: Option<AuthConfig>,
    }

    match std::fs::read_to_string(path) {
        Ok(content) => match serde_yaml::from_str::<PartialConfig>(&content) {
            Ok(cfg) => {
                let config = HotReloadableConfig {
                    // Missing section → keep current. NEVER fall back to
                    // Default::default() (which would disable auth/rate-limit).
                    connection_limit: cfg
                        .connection_limit
                        .unwrap_or_else(|| current.connection_limit.clone()),
                    rate_limit: cfg
                        .rate_limit
                        .unwrap_or_else(|| current.rate_limit.clone()),
                    auth: cfg.auth.unwrap_or_else(|| current.auth.clone()),
                };
                info!(
                    connection_limit_enabled = config.connection_limit.enabled,
                    rate_limit_enabled = config.rate_limit.enabled,
                    auth_enabled = config.auth.enabled,
                    "hot reload: loaded new configuration"
                );
                Some(config)
            }
            Err(e) => {
                error!(error = %e, "hot reload: failed to parse config file");
                None
            }
        },
        Err(e) => {
            error!(error = %e, "hot reload: failed to read config file");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_default_config() -> HotReloadableConfig {
        HotReloadableConfig {
            connection_limit: ConnectionLimitConfig::default(),
            rate_limit: RateLimitConfig::default(),
            auth: AuthConfig::default(),
        }
    }

    #[test]
    fn test_new_returns_initial_config() {
        let initial = make_default_config();
        let manager = HotReloadManager::new(initial);
        let config = manager.get();
        assert!(!config.connection_limit.enabled);
        assert!(!config.rate_limit.enabled);
        assert!(!config.auth.enabled);
    }

    #[test]
    fn test_update_changes_config() {
        let initial = make_default_config();
        let manager = HotReloadManager::new(initial);

        let mut updated = make_default_config();
        updated.connection_limit.enabled = true;
        updated.auth.enabled = true;
        manager.update(updated);

        let config = manager.get();
        assert!(config.connection_limit.enabled);
        assert!(config.auth.enabled);
    }

    #[test]
    fn test_load_valid_yaml() {
        let dir = std::env::temp_dir().join("certstream_test_valid.yaml");
        let yaml = r#"
connection_limit:
  enabled: true
  max_connections: 500
rate_limit:
  enabled: false
auth:
  enabled: true
  tokens:
    - "test-token-123"
"#;
        std::fs::write(&dir, yaml).unwrap();

        let result = load_hot_reloadable_config(dir.to_str().unwrap(), &make_default_config());
        assert!(result.is_some());
        let config = result.unwrap();
        assert!(config.connection_limit.enabled);
        assert_eq!(config.connection_limit.max_connections, 500);
        assert!(!config.rate_limit.enabled);
        assert!(config.auth.enabled);

        let _ = std::fs::remove_file(&dir);
    }

    #[test]
    fn test_load_invalid_yaml() {
        let dir = std::env::temp_dir().join("certstream_test_invalid.yaml");
        std::fs::write(&dir, ":::not: [valid yaml").unwrap();
        let result = load_hot_reloadable_config(dir.to_str().unwrap(), &make_default_config());
        assert!(result.is_none());
        let _ = std::fs::remove_file(&dir);
    }

    #[test]
    fn test_load_missing_file() {
        let result = load_hot_reloadable_config(
            "/tmp/certstream_nonexistent_config_xyz.yaml",
            &make_default_config(),
        );
        assert!(result.is_none());
    }

    #[test]
    fn test_load_empty_yaml_keeps_current() {
        // Regression: pre-1.5.0 an empty YAML returned all-defaults, which
        // SILENTLY DISABLED auth/rate-limit even if they were on at startup.
        // Now an empty (or partial) YAML must preserve the current state.
        let dir = std::env::temp_dir().join("certstream_test_empty.yaml");
        std::fs::write(&dir, "").unwrap();

        let mut current = make_default_config();
        current.auth.enabled = true;
        current.auth.tokens = vec!["startup-token".into()];
        current.rate_limit.enabled = true;

        let result = load_hot_reloadable_config(dir.to_str().unwrap(), &current);
        assert!(result.is_some());
        let cfg = result.unwrap();
        assert!(cfg.auth.enabled, "auth must NOT be silently disabled");
        assert_eq!(cfg.auth.tokens, vec!["startup-token".to_string()]);
        assert!(cfg.rate_limit.enabled, "rate-limit must NOT be silently disabled");

        let _ = std::fs::remove_file(&dir);
    }

    #[test]
    fn test_partial_yaml_only_overrides_specified_sections() {
        // YAML that only sets connection_limit must not touch auth/rate_limit.
        let dir = std::env::temp_dir().join("certstream_test_partial.yaml");
        std::fs::write(
            &dir,
            "connection_limit:\n  enabled: true\n  max_connections: 42\n",
        )
        .unwrap();

        let mut current = make_default_config();
        current.auth.enabled = true;
        current.rate_limit.enabled = true;

        let result = load_hot_reloadable_config(dir.to_str().unwrap(), &current).unwrap();
        assert!(result.connection_limit.enabled);
        assert_eq!(result.connection_limit.max_connections, 42);
        assert!(result.auth.enabled, "auth must be preserved");
        assert!(result.rate_limit.enabled, "rate_limit must be preserved");

        let _ = std::fs::remove_file(&dir);
    }
}
