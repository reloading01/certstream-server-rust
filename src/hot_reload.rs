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

                                        if let Some(new_config) = load_hot_reloadable_config(&path_clone) {
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

fn load_hot_reloadable_config(path: &str) -> Option<HotReloadableConfig> {
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
                    connection_limit: cfg.connection_limit.unwrap_or_default(),
                    rate_limit: cfg.rate_limit.unwrap_or_default(),
                    auth: cfg.auth.unwrap_or_default(),
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

        let result = load_hot_reloadable_config(dir.to_str().unwrap());
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
        // Write content that is valid YAML but will fail to parse into PartialConfig
        // A bare scalar won't deserialize into the expected struct
        std::fs::write(&dir, ":::not: [valid yaml").unwrap();

        let result = load_hot_reloadable_config(dir.to_str().unwrap());
        assert!(result.is_none());

        let _ = std::fs::remove_file(&dir);
    }

    #[test]
    fn test_load_missing_file() {
        let result = load_hot_reloadable_config("/tmp/certstream_nonexistent_config_xyz.yaml");
        assert!(result.is_none());
    }

    #[test]
    fn test_load_empty_yaml_uses_defaults() {
        let dir = std::env::temp_dir().join("certstream_test_empty.yaml");
        std::fs::write(&dir, "").unwrap();

        let result = load_hot_reloadable_config(dir.to_str().unwrap());
        assert!(result.is_some());
        let config = result.unwrap();
        assert!(!config.connection_limit.enabled);
        assert!(!config.rate_limit.enabled);
        assert!(!config.auth.enabled);

        let _ = std::fs::remove_file(&dir);
    }
}
