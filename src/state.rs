use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LogState {
    pub current_index: u64,
    pub tree_size: u64,
    pub last_success: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct StateFile {
    version: u32,
    logs: std::collections::HashMap<String, LogState>,
}

pub struct StateManager {
    file_path: Option<String>,
    states: DashMap<String, LogState>,
    dirty: AtomicBool,
}

impl StateManager {
    pub fn new(file_path: Option<String>) -> Arc<Self> {
        let manager = Arc::new(Self {
            file_path: file_path.clone(),
            states: DashMap::new(),
            dirty: AtomicBool::new(false),
        });

        if let Some(ref path) = file_path {
            manager.load_from_file(path);
        }

        manager
    }

    fn load_from_file(&self, path: &str) {
        if !Path::new(path).exists() {
            debug!(path = %path, "state file does not exist, starting fresh");
            return;
        }

        match fs::read_to_string(path) {
            Ok(content) => match serde_json::from_str::<StateFile>(&content) {
                Ok(state_file) => {
                    for (log_url, state) in state_file.logs {
                        self.states.insert(log_url, state);
                    }
                    info!(
                        path = %path,
                        logs = self.states.len(),
                        "loaded state from file"
                    );
                }
                Err(e) => {
                    warn!(path = %path, error = %e, "failed to parse state file, starting fresh");
                }
            },
            Err(e) => {
                warn!(path = %path, error = %e, "failed to read state file, starting fresh");
            }
        }
    }

    pub fn get_index(&self, log_url: &str) -> Option<u64> {
        self.states.get(log_url).map(|s| s.current_index)
    }

    pub fn update_index(&self, log_url: &str, index: u64, tree_size: u64) {
        let now = chrono::Utc::now().timestamp();
        self.states.insert(
            log_url.to_string(),
            LogState {
                current_index: index,
                tree_size,
                last_success: now,
            },
        );
        self.dirty.store(true, Ordering::Relaxed);
    }

    pub async fn save_if_dirty(&self) {
        if !self.dirty.load(Ordering::Relaxed) {
            return;
        }

        if let Some(ref path) = self.file_path {
            self.save_to_file(path).await;
        }
    }

    /// Write `data` to `path` and call `sync_all()` before returning, so the
    /// bytes reach durable storage before the caller renames the file.
    async fn write_and_sync(path: &str, data: &[u8]) -> std::io::Result<()> {
        use tokio::io::AsyncWriteExt;
        let mut file = tokio::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)
            .await?;
        file.write_all(data).await?;
        file.sync_all().await?;
        Ok(())
    }

    async fn save_to_file(&self, path: &str) {
        let mut logs = std::collections::HashMap::new();
        for entry in self.states.iter() {
            logs.insert(entry.key().clone(), entry.value().clone());
        }

        let state_file = StateFile { version: 1, logs };

        match serde_json::to_string_pretty(&state_file) {
            Ok(content) => {
                let tmp_path = format!("{}.tmp", path);
                match Self::write_and_sync(&tmp_path, content.as_bytes()).await {
                    Ok(()) => match tokio::fs::rename(&tmp_path, path).await {
                        Ok(_) => {
                            self.dirty.store(false, Ordering::Relaxed);
                            debug!(path = %path, "saved state to file");
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                            // Concurrent save completed first — state already written
                            self.dirty.store(false, Ordering::Relaxed);
                            debug!(path = %path, "state already saved by concurrent flush");
                        }
                        Err(e) => {
                            error!(path = %path, error = %e, "failed to rename state file");
                            let _ = tokio::fs::remove_file(&tmp_path).await;
                        }
                    },
                    Err(e) => {
                        error!(tmp_path = %tmp_path, error = %e, "failed to write temp state file");
                    }
                }
            }
            Err(e) => {
                error!(error = %e, "failed to serialize state");
            }
        }
    }

    pub fn start_periodic_save(self: Arc<Self>, interval: Duration, cancel: CancellationToken) {
        let manager = self.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(interval);
            loop {
                tokio::select! {
                    _ = cancel.cancelled() => {
                        info!("periodic save task stopping");
                        manager.save_if_dirty().await;
                        break;
                    }
                    _ = tick.tick() => {
                        manager.save_if_dirty().await;
                    }
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn temp_state_path(name: &str) -> String {
        format!("/tmp/certstream_test_state_{}.json", name)
    }

    fn cleanup_file(path: &str) {
        let _ = fs::remove_file(path);
        let _ = fs::remove_file(format!("{}.tmp", path));
    }

    #[test]
    fn test_new_without_file() {
        let manager = StateManager::new(None);
        assert!(manager.get_index("some_log").is_none());
    }

    #[test]
    fn test_new_with_nonexistent_file() {
        let path = temp_state_path("nonexistent");
        cleanup_file(&path);
        let manager = StateManager::new(Some(path.clone()));
        assert!(manager.get_index("some_log").is_none());
        cleanup_file(&path);
    }

    #[test]
    fn test_update_and_get_index() {
        let manager = StateManager::new(None);
        assert!(manager.get_index("log1").is_none());

        manager.update_index("log1", 100, 500);
        assert_eq!(manager.get_index("log1"), Some(100));

        manager.update_index("log1", 200, 600);
        assert_eq!(manager.get_index("log1"), Some(200));

        manager.update_index("log2", 50, 300);
        assert_eq!(manager.get_index("log2"), Some(50));
        assert_eq!(manager.get_index("log1"), Some(200));
    }

    #[test]
    fn test_dirty_flag() {
        let manager = StateManager::new(None);
        assert!(!manager.dirty.load(Ordering::Relaxed));

        manager.update_index("log1", 100, 500);
        // After update, should be dirty
        assert!(manager.dirty.load(Ordering::Relaxed));
    }

    #[tokio::test]
    async fn test_save_and_load_roundtrip() {
        let path = temp_state_path("roundtrip");
        cleanup_file(&path);

        // Create manager, add data, save
        {
            let manager = StateManager::new(Some(path.clone()));
            manager.update_index("https://log1.example.com", 100, 500);
            manager.update_index("https://log2.example.com", 200, 600);
            manager.save_if_dirty().await;
        }

        // Load into new manager
        {
            let manager = StateManager::new(Some(path.clone()));
            assert_eq!(manager.get_index("https://log1.example.com"), Some(100));
            assert_eq!(manager.get_index("https://log2.example.com"), Some(200));
        }

        cleanup_file(&path);
    }

    #[tokio::test]
    async fn test_save_if_dirty_skips_when_clean() {
        let path = temp_state_path("clean_skip");
        cleanup_file(&path);

        let manager = StateManager::new(Some(path.clone()));
        manager.save_if_dirty().await;
        assert!(!std::path::Path::new(&path).exists());

        cleanup_file(&path);
    }

    #[tokio::test]
    async fn test_save_clears_dirty_flag() {
        let path = temp_state_path("dirty_clear");
        cleanup_file(&path);

        let manager = StateManager::new(Some(path.clone()));
        manager.update_index("log1", 100, 500);
        assert!(manager.dirty.load(Ordering::Relaxed));

        manager.save_if_dirty().await;
        assert!(!manager.dirty.load(Ordering::Relaxed));

        cleanup_file(&path);
    }

    #[test]
    fn test_load_corrupt_file() {
        let path = temp_state_path("corrupt");
        cleanup_file(&path);
        fs::write(&path, "not valid json").unwrap();

        let manager = StateManager::new(Some(path.clone()));
        // Should start fresh, no crash
        assert!(manager.get_index("anything").is_none());

        cleanup_file(&path);
    }

    #[test]
    fn test_load_valid_state_file() {
        let path = temp_state_path("valid_load");
        cleanup_file(&path);

        let content = r#"{
            "version": 1,
            "logs": {
                "https://ct.example.com": {
                    "current_index": 42,
                    "tree_size": 1000,
                    "last_success": 1700000000
                }
            }
        }"#;
        fs::write(&path, content).unwrap();

        let manager = StateManager::new(Some(path.clone()));
        assert_eq!(manager.get_index("https://ct.example.com"), Some(42));

        cleanup_file(&path);
    }

    #[tokio::test]
    async fn test_periodic_save_stops_on_cancel() {
        let path = temp_state_path("periodic_cancel");
        cleanup_file(&path);

        let manager = StateManager::new(Some(path.clone()));
        manager.update_index("log1", 100, 500);

        let cancel = CancellationToken::new();
        manager
            .clone()
            .start_periodic_save(Duration::from_millis(50), cancel.clone());

        // Let it run a bit
        tokio::time::sleep(Duration::from_millis(100)).await;

        cancel.cancel();

        // Give time for shutdown flush
        tokio::time::sleep(Duration::from_millis(100)).await;

        // State should have been saved (either periodic or shutdown flush)
        assert!(std::path::Path::new(&path).exists());

        cleanup_file(&path);
    }

    #[test]
    fn test_multiple_logs_state() {
        let manager = StateManager::new(None);

        for i in 0..10 {
            manager.update_index(&format!("log_{}", i), i * 100, i * 1000);
        }

        for i in 0..10 {
            assert_eq!(
                manager.get_index(&format!("log_{}", i)),
                Some(i * 100)
            );
        }
    }

    #[tokio::test]
    async fn test_atomic_write_no_partial_file() {
        let path = temp_state_path("atomic");
        cleanup_file(&path);

        let manager = StateManager::new(Some(path.clone()));
        manager.update_index("log1", 100, 500);
        manager.save_if_dirty().await;

        // File should exist and be valid JSON
        let content = fs::read_to_string(&path).unwrap();
        let state: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert_eq!(state["version"], 1);
        assert!(state["logs"]["log1"]["current_index"].as_u64() == Some(100));

        // Temp file should not exist
        assert!(!std::path::Path::new(&format!("{}.tmp", path)).exists());

        cleanup_file(&path);
    }
}
