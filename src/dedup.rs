use dashmap::DashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info};

/// Default capacity bumped from 500K (v1.3.x) to 1M because static-ct logs
/// (Sycamore, Willow, Cloudflare Raio, Geomys Tuscolo, …) issue tiles in tight
/// 60-second MMD windows, and during the RFC6962/static-CT transition the same
/// certificate often appears in 3-4 logs within minutes. Holding a wider window
/// keeps the duplicate filter effective without forcing premature eviction.
const DEFAULT_CAPACITY: usize = 1_000_000;
/// 15 minutes — comfortably covers the typical multi-log SCT propagation window
/// (a few minutes) plus headroom for slower static-ct shards. Configurable via
/// `dedup.ttl_secs` in YAML or `CERTSTREAM_DEDUP_TTL_SECS`.
const DEFAULT_TTL_SECS: u64 = 900;
const DEFAULT_CLEANUP_INTERVAL_SECS: u64 = 60;

/// Issue #1: Use raw [u8; 32] SHA-256 bytes as the key — fixed-size, stack-allocated,
/// trivially hashable. Eliminates one heap allocation per certificate on every lookup.
pub struct DedupFilter {
    seen: DashMap<[u8; 32], Instant>,
    capacity: usize,
    ttl: Duration,
}

impl DedupFilter {
    pub fn new() -> Self {
        Self::with_config(DEFAULT_CAPACITY, Duration::from_secs(DEFAULT_TTL_SECS))
    }

    pub fn with_config(capacity: usize, ttl: Duration) -> Self {
        Self {
            seen: DashMap::with_capacity(capacity.max(4) / 4),
            capacity: capacity.max(1),
            ttl,
        }
    }

    /// Returns true if this SHA-256 fingerprint has NOT been seen before (i.e., is new).
    /// Takes the raw 32-byte digest — zero heap allocation on both hit and miss.
    pub fn is_new(&self, sha256_raw: &[u8; 32]) -> bool {
        let now = Instant::now();

        // Duplicate path (common case): get_mut with fixed-size key — no allocation.
        if let Some(mut ts) = self.seen.get_mut(sha256_raw) {
            let age = now.duration_since(*ts);
            if age > self.ttl {
                // Expired entry: treat as new and refresh timestamp.
                *ts = now;
                return true;
            }
            metrics::counter!("certstream_duplicates_filtered").increment(1);
            return false;
        }

        // New key — capacity guard before insert.
        if self.seen.len() >= self.capacity {
            self.cleanup();
            if self.seen.len() >= self.capacity {
                info!(size = self.seen.len(), "dedup cache full after cleanup, clearing");
                self.seen.clear();
                metrics::counter!("certstream_dedup_cache_clears").increment(1);
            }
        }

        self.seen.insert(*sha256_raw, now);
        true
    }

    pub fn cleanup(&self) {
        let before = self.seen.len();
        let now = Instant::now();
        self.seen.retain(|_, v| now.duration_since(*v) < self.ttl);
        let removed = before.saturating_sub(self.seen.len());
        if removed > 0 {
            debug!(removed = removed, remaining = self.seen.len(), "dedup cleanup");
        }
        metrics::gauge!("certstream_dedup_cache_size").set(self.seen.len() as f64);
    }

    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.seen.len()
    }

    pub fn start_cleanup_task(self: Arc<Self>, cancel: CancellationToken) {
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(DEFAULT_CLEANUP_INTERVAL_SECS));
            loop {
                tokio::select! {
                    _ = cancel.cancelled() => {
                        info!("dedup cleanup task stopping");
                        break;
                    }
                    _ = tick.tick() => {
                        self.cleanup();
                    }
                }
            }
        });
    }
}

impl Default for DedupFilter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    fn key(n: u8) -> [u8; 32] {
        let mut k = [0u8; 32];
        k[0] = n;
        k
    }

    #[test]
    fn test_is_new_first_seen() {
        let filter = DedupFilter::new();
        assert!(filter.is_new(&key(1)));
        assert!(filter.is_new(&key(2)));
    }

    #[test]
    fn test_is_new_duplicate() {
        let filter = DedupFilter::new();
        assert!(filter.is_new(&key(1)));
        assert!(!filter.is_new(&key(1))); // second time → duplicate
        assert!(!filter.is_new(&key(1))); // third time → still duplicate
    }

    #[test]
    fn test_is_new_different_keys() {
        let filter = DedupFilter::new();
        assert!(filter.is_new(&key(1)));
        assert!(filter.is_new(&key(2)));
        assert!(filter.is_new(&key(3)));
        assert!(!filter.is_new(&key(1)));
        assert!(!filter.is_new(&key(2)));
    }

    #[test]
    fn test_is_new_ttl_expiry() {
        let filter = DedupFilter {
            seen: DashMap::with_capacity(100),
            capacity: DEFAULT_CAPACITY,
            ttl: Duration::from_millis(50),
        };

        let k = key(42);
        assert!(filter.is_new(&k));
        assert!(!filter.is_new(&k));

        thread::sleep(Duration::from_millis(60));

        // Should be treated as new again after TTL expiry
        assert!(filter.is_new(&k));
    }

    #[test]
    fn test_is_new_capacity_overflow() {
        let filter = DedupFilter {
            seen: DashMap::with_capacity(4),
            capacity: 5, // Very small capacity
            ttl: Duration::from_secs(300),
        };

        for i in 0u8..5 {
            assert!(filter.is_new(&key(i)));
        }
        assert_eq!(filter.len(), 5);

        // Next insert should trigger clear
        assert!(filter.is_new(&key(255)));
        // After clear + insert, only the new key should be present
        assert_eq!(filter.len(), 1);
    }

    #[test]
    fn test_cleanup_removes_expired() {
        let filter = DedupFilter {
            seen: DashMap::with_capacity(100),
            capacity: DEFAULT_CAPACITY,
            ttl: Duration::from_millis(50),
        };

        filter.is_new(&key(1));
        filter.is_new(&key(2));
        assert_eq!(filter.len(), 2);

        thread::sleep(Duration::from_millis(60));

        // Add a fresh entry
        filter.is_new(&key(3));

        filter.cleanup();

        // key1 and key2 should be removed, key3 should remain
        assert_eq!(filter.len(), 1);
        assert!(filter.is_new(&key(1))); // key1 was cleaned up, so it's new again
    }

    #[test]
    fn test_cleanup_keeps_fresh_entries() {
        let filter = DedupFilter::new();
        filter.is_new(&key(1));
        filter.is_new(&key(2));
        filter.is_new(&key(3));

        filter.cleanup();

        // All entries are fresh, none removed
        assert_eq!(filter.len(), 3);
        assert!(!filter.is_new(&key(1))); // still a duplicate
    }

    #[test]
    fn test_len() {
        let filter = DedupFilter::new();
        assert_eq!(filter.len(), 0);

        filter.is_new(&key(1));
        assert_eq!(filter.len(), 1);

        filter.is_new(&key(2));
        assert_eq!(filter.len(), 2);

        filter.is_new(&key(1)); // duplicate, no new entry
        assert_eq!(filter.len(), 2);
    }

    #[test]
    fn test_zero_key() {
        let filter = DedupFilter::new();
        let z = [0u8; 32];
        assert!(filter.is_new(&z));
        assert!(!filter.is_new(&z));
    }

    #[tokio::test]
    async fn test_cleanup_task_stops_on_cancellation() {
        let filter = Arc::new(DedupFilter::new());
        let cancel = CancellationToken::new();

        filter.clone().start_cleanup_task(cancel.clone());

        tokio::time::sleep(Duration::from_millis(50)).await;

        cancel.cancel();

        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}
