use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use crate::config::StateRecovery;

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

/// A state file that exists but could not be turned into positions.
///
/// Carried out of `StateManager::new` rather than logged and swallowed so the
/// `state_recovery: fail` policy has something to refuse to start on.
#[derive(Debug, thiserror::Error)]
#[error("state file {path} is unusable: {source}")]
pub struct StateLoadError {
    pub path: String,
    #[source]
    pub source: StateLoadCause,
}

#[derive(Debug, thiserror::Error)]
pub enum StateLoadCause {
    #[error("read failed: {0}")]
    Read(#[from] std::io::Error),
    #[error("parse failed: {0}")]
    Parse(#[from] serde_json::Error),
}

pub struct StateManager {
    file_path: Option<String>,
    states: DashMap<String, LogState>,
    dirty: AtomicBool,
    /// When set, the position written to disk is the one a durable output has
    /// acknowledged, not the one the watcher has read. Saving the read
    /// position with a durable sink configured would let a restart skip
    /// entries that were read but never stored.
    ack_gate: arc_swap::ArcSwapOption<crate::nats::AckTracker>,
}

impl StateManager {
    /// Load the saved positions, applying `recovery` to a state file that is
    /// present but unusable. A missing file is a first run under either
    /// policy and is never an error.
    pub fn new(
        file_path: Option<String>,
        recovery: StateRecovery,
    ) -> Result<Arc<Self>, StateLoadError> {
        let manager = Arc::new(Self {
            file_path: file_path.clone(),
            states: DashMap::new(),
            dirty: AtomicBool::new(false),
            ack_gate: arc_swap::ArcSwapOption::empty(),
        });

        if let Some(ref path) = file_path
            && let Err(e) = manager.load_from_file(path)
        {
            match recovery {
                StateRecovery::Fail => return Err(e),
                StateRecovery::Fresh => {
                    warn!(
                        path = %path,
                        error = %e.source,
                        "state file unusable, starting from the log head \
                         (set ct_log.state_recovery: fail to refuse instead)"
                    );
                }
            }
        }

        Ok(manager)
    }

    fn load_from_file(&self, path: &str) -> Result<(), StateLoadError> {
        if !Path::new(path).exists() {
            debug!(path = %path, "state file does not exist, starting fresh");
            return Ok(());
        }

        let fail = |source: StateLoadCause| StateLoadError {
            path: path.to_string(),
            source,
        };

        let content = fs::read_to_string(path).map_err(|e| fail(e.into()))?;
        let state_file =
            serde_json::from_str::<StateFile>(&content).map_err(|e| fail(e.into()))?;

        for (log_url, state) in state_file.logs {
            self.states.insert(log_url, state);
        }
        info!(
            path = %path,
            logs = self.states.len(),
            "loaded state from file"
        );
        Ok(())
    }

    /// Persist acknowledged positions instead of read positions, and seed the
    /// tracker from what is already on disk — anything saved was acknowledged
    /// before it was written, so that is where each log's acknowledged prefix
    /// resumes.
    pub fn gate_saves_on_acks(&self, acks: Arc<crate::nats::AckTracker>) {
        for entry in self.states.iter() {
            acks.resume_at(entry.key(), entry.value().current_index);
        }
        self.ack_gate.store(Some(acks));
    }

    /// What to write for this log: the read position normally, and the
    /// acknowledged prefix when a durable output is gating saves.
    fn savable_index(&self, log_url: &str, read_index: u64) -> u64 {
        match self.ack_gate.load().as_ref() {
            Some(acks) => acks
                .acked_index(log_url)
                .map_or(read_index, |acked| acked.min(read_index)),
            None => read_index,
        }
    }

    pub fn get_index(&self, log_url: &str) -> Option<u64> {
        self.states.get(log_url).map(|s| s.current_index)
    }

    /// Last persisted tree_size for this log, used by static-CT watchers to
    /// re-seed their rollback high-water across restarts.
    pub fn get_tree_size(&self, log_url: &str) -> Option<u64> {
        self.states.get(log_url).map(|s| s.tree_size)
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
        // Clear the dirty flag *before* snapshotting so that any concurrent
        // update_index call during the save re-marks dirty and gets caught
        // by the next tick. If we cleared after the snapshot (the previous
        // behaviour), an update that landed between snapshot and clear would
        // be silently dropped from the next save's trigger.
        if !self.dirty.swap(false, Ordering::AcqRel) {
            return;
        }

        if let Some(ref path) = self.file_path
            && !self.save_to_file(path).await
        {
            // Save failed — re-arm so the next tick retries.
            self.dirty.store(true, Ordering::Release);
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

    /// Returns true on a fully successful write+rename, false otherwise.
    /// Caller re-arms the dirty flag on false.
    async fn save_to_file(&self, path: &str) -> bool {
        let mut logs = std::collections::HashMap::new();
        for entry in self.states.iter() {
            let mut state = entry.value().clone();
            state.current_index = self.savable_index(entry.key(), state.current_index);
            logs.insert(entry.key().clone(), state);
        }

        let state_file = StateFile { version: 1, logs };

        let content = match serde_json::to_string(&state_file) {
            Ok(c) => c,
            Err(e) => {
                error!(error = %e, "failed to serialize state");
                return false;
            }
        };

        let tmp_path = format!("{}.tmp", path);
        if let Err(e) = Self::write_and_sync(&tmp_path, content.as_bytes()).await {
            error!(tmp_path = %tmp_path, error = %e, "failed to write temp state file");
            return false;
        }

        match tokio::fs::rename(&tmp_path, path).await {
            Ok(_) => {
                debug!(path = %path, "saved state to file");
                true
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                debug!(path = %path, "state already saved by concurrent flush");
                true
            }
            Err(e) => {
                error!(path = %path, error = %e, "failed to rename state file");
                let _ = tokio::fs::remove_file(&tmp_path).await;
                false
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
        let manager = StateManager::new(None, StateRecovery::Fresh).unwrap();
        assert!(manager.get_index("some_log").is_none());
    }

    #[test]
    fn test_new_with_nonexistent_file() {
        let path = temp_state_path("nonexistent");
        cleanup_file(&path);
        let manager = StateManager::new(Some(path.clone()), StateRecovery::Fresh).unwrap();
        assert!(manager.get_index("some_log").is_none());
        cleanup_file(&path);
    }

    #[test]
    fn test_update_and_get_index() {
        let manager = StateManager::new(None, StateRecovery::Fresh).unwrap();
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
        let manager = StateManager::new(None, StateRecovery::Fresh).unwrap();
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
            let manager = StateManager::new(Some(path.clone()), StateRecovery::Fresh).unwrap();
            manager.update_index("https://log1.example.com", 100, 500);
            manager.update_index("https://log2.example.com", 200, 600);
            manager.save_if_dirty().await;
        }

        // Load into new manager
        {
            let manager = StateManager::new(Some(path.clone()), StateRecovery::Fresh).unwrap();
            assert_eq!(manager.get_index("https://log1.example.com"), Some(100));
            assert_eq!(manager.get_index("https://log2.example.com"), Some(200));
        }

        cleanup_file(&path);
    }

    #[tokio::test]
    async fn test_save_if_dirty_skips_when_clean() {
        let path = temp_state_path("clean_skip");
        cleanup_file(&path);

        let manager = StateManager::new(Some(path.clone()), StateRecovery::Fresh).unwrap();
        manager.save_if_dirty().await;
        assert!(!std::path::Path::new(&path).exists());

        cleanup_file(&path);
    }

    #[tokio::test]
    async fn test_save_clears_dirty_flag() {
        let path = temp_state_path("dirty_clear");
        cleanup_file(&path);

        let manager = StateManager::new(Some(path.clone()), StateRecovery::Fresh).unwrap();
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

        let manager = StateManager::new(Some(path.clone()), StateRecovery::Fresh).unwrap();
        // Should start fresh, no crash
        assert!(manager.get_index("anything").is_none());

        cleanup_file(&path);
    }

    /// `state_recovery: fail` exists so a deployment that cares about
    /// continuity is told the saved position is gone instead of silently
    /// re-reading from the head.
    #[test]
    fn corrupt_file_is_an_error_under_fail_recovery() {
        let path = temp_state_path("corrupt_fail");
        cleanup_file(&path);
        fs::write(&path, "not valid json").unwrap();

        let Err(err) = StateManager::new(Some(path.clone()), StateRecovery::Fail) else {
            panic!("fail policy must refuse a corrupt state file");
        };
        assert_eq!(err.path, path);
        assert!(matches!(err.source, StateLoadCause::Parse(_)));

        cleanup_file(&path);
    }

    /// A first run has no state file. That is not corruption, and `fail` must
    /// not turn a fresh install into a startup failure.
    #[test]
    fn missing_file_is_not_a_failure_under_fail_recovery() {
        let path = temp_state_path("missing_fail");
        cleanup_file(&path);

        let Ok(manager) = StateManager::new(Some(path.clone()), StateRecovery::Fail) else {
            panic!("a missing state file is a first run, not an error");
        };
        assert!(manager.get_index("anything").is_none());

        cleanup_file(&path);
    }

    /// An unreadable (as opposed to unparseable) file takes the same path.
    #[test]
    #[cfg(unix)]
    fn unreadable_file_is_an_error_under_fail_recovery() {
        use std::os::unix::fs::PermissionsExt;

        let path = temp_state_path("unreadable_fail");
        cleanup_file(&path);
        fs::write(&path, "{}").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o000)).unwrap();

        // Running as root defeats the permission bits; skip rather than fail.
        if fs::read_to_string(&path).is_ok() {
            cleanup_file(&path);
            return;
        }

        let Err(err) = StateManager::new(Some(path.clone()), StateRecovery::Fail) else {
            panic!("fail policy must refuse an unreadable state file");
        };
        assert!(matches!(err.source, StateLoadCause::Read(_)));

        let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o644));
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

        let manager = StateManager::new(Some(path.clone()), StateRecovery::Fresh).unwrap();
        assert_eq!(manager.get_index("https://ct.example.com"), Some(42));

        cleanup_file(&path);
    }

    #[tokio::test]
    async fn test_periodic_save_stops_on_cancel() {
        let path = temp_state_path("periodic_cancel");
        cleanup_file(&path);

        let manager = StateManager::new(Some(path.clone()), StateRecovery::Fresh).unwrap();
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

    /// After a catch-up jump the file still holds the acknowledged position,
    /// and moves over the skipped range once the records before it are stored.
    #[tokio::test]
    async fn test_saved_position_follows_acks_across_a_jump() {
        let path = temp_state_path("jump_acks");
        cleanup_file(&path);
        let url = "https://jump.example";
        let manager = StateManager::new(Some(path.clone()), StateRecovery::Fresh).unwrap();
        let acks = Arc::new(crate::nats::AckTracker::default());
        manager.gate_saves_on_acks(Arc::clone(&acks));
        acks.resume_at(url, 100);
        let key: Arc<str> = Arc::from(url);
        let saved = || -> u64 {
            let content = fs::read_to_string(&path).unwrap();
            let state: StateFile = serde_json::from_str(&content).unwrap();
            state.logs[url].current_index
        };

        acks.record_ack(&key, 100);
        acks.record_skipped_range(&key, 102, 9_000);
        manager.update_index(url, 9_000, 9_500);
        manager.save_if_dirty().await;
        assert_eq!(saved(), 101, "record 101 is not stored yet");

        acks.record_ack(&key, 101);
        manager.update_index(url, 9_000, 9_500);
        manager.save_if_dirty().await;
        assert_eq!(saved(), 9_000);

        cleanup_file(&path);
    }

    #[test]
    fn test_multiple_logs_state() {
        let manager = StateManager::new(None, StateRecovery::Fresh).unwrap();

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

    /// The rollback guard's `high_water_tree_size` is re-seeded from the state
    /// file on restart. Starting it at zero instead would let a shrunken tree
    /// through on the first poll after every restart.
    #[test]
    fn test_get_tree_size_after_reload() {
        let path = temp_state_path("tree_size_reload");
        cleanup_file(&path);

        // First "process": write a tree_size for a log.
        {
            let mgr = StateManager::new(Some(path.clone()), StateRecovery::Fresh).unwrap();
            mgr.update_index("https://static.example.com", 1000, 12_345_678);
            // Manually serialize since save_if_dirty is async
            let mut logs = std::collections::HashMap::new();
            for entry in mgr.states.iter() {
                logs.insert(entry.key().clone(), entry.value().clone());
            }
            let sf = StateFile { version: 1, logs };
            fs::write(&path, serde_json::to_string(&sf).unwrap()).unwrap();
        }

        // Second "process": load the same file, assert get_tree_size returns it.
        {
            let mgr = StateManager::new(Some(path.clone()), StateRecovery::Fresh).unwrap();
            assert_eq!(
                mgr.get_tree_size("https://static.example.com"),
                Some(12_345_678),
                "high_water must be reloadable across restart"
            );
            assert_eq!(
                mgr.get_index("https://static.example.com"),
                Some(1000),
            );
            // Unknown logs return None (not 0!) so the watcher falls back to fresh start.
            assert_eq!(mgr.get_tree_size("https://unknown.example.com"), None);
        }

        cleanup_file(&path);
    }

    #[tokio::test]
    async fn test_atomic_write_no_partial_file() {
        let path = temp_state_path("atomic");
        cleanup_file(&path);

        let manager = StateManager::new(Some(path.clone()), StateRecovery::Fresh).unwrap();
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
