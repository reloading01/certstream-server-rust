use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use dashmap::DashMap;
use serde::Serialize;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use parking_lot::RwLock;

use crate::ct::watcher::HealthStatus;
use crate::models::{LeafCert, Subject};

/// Issue #15: Use byte-level ASCII operations — avoids the ToUppercase struct overhead
/// that flat_map(|c| c.to_uppercase()) allocates for each char in the common ASCII case.
#[inline]
fn normalize_hash(hash: &str) -> String {
    hash.bytes()
        .filter(|b| b.is_ascii_hexdigit())
        .map(|b| b.to_ascii_uppercase() as char)
        .collect()
}

#[derive(Debug, Clone, Serialize)]
pub struct StatsResponse {
    pub uptime_seconds: u64,
    pub connections: ConnectionStats,
    pub throughput: ThroughputStats,
    pub memory: MemoryStats,
}

#[derive(Debug, Clone, Serialize)]
pub struct ConnectionStats {
    pub total: u64,
    pub websocket: u64,
    pub sse: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ThroughputStats {
    pub messages_sent: u64,
    pub certificates_processed: u64,
    pub bytes_sent: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct MemoryStats {
    pub cache_entries: usize,
    pub cache_capacity: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct LogStatus {
    pub name: String,
    pub url: String,
    pub operator: String,
    pub status: String,
    pub current_index: u64,
    pub tree_size: u64,
    pub total_errors: u64,
    pub last_success: Option<i64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct LogsResponse {
    pub total_logs: usize,
    pub healthy: usize,
    pub degraded: usize,
    pub unhealthy: usize,
    pub logs: Vec<LogStatus>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CertDetail {
    pub fingerprint: String,
    pub sha1: String,
    pub sha256: String,
    pub serial_number: String,
    pub subject: Subject,
    pub issuer: Subject,
    pub not_before: i64,
    pub not_after: i64,
    pub is_ca: bool,
    pub all_domains: Vec<String>,
    pub signature_algorithm: String,
    pub seen: f64,
    pub source: String,
    pub cert_index: u64,
    pub cert_link: String,
}

/// Issue #2: CachedCert shares the Arc<LeafCert> from the message — zero field clones
/// when building from a parsed cert. Memory for the API cache drops ~50% vs owned fields.
pub struct CachedCert {
    pub leaf: Arc<LeafCert>,
    pub seen: f64,
    pub source_name: String,
    pub source_url: String,
    pub cert_index: u64,
}

pub struct CertificateCache {
    entries: RwLock<VecDeque<Arc<CachedCert>>>,
    hash_index: DashMap<String, Arc<CachedCert>>,
    capacity: usize,
}

impl CertificateCache {
    pub fn new(capacity: usize) -> Self {
        Self {
            entries: RwLock::new(VecDeque::with_capacity(capacity)),
            hash_index: DashMap::with_capacity(capacity * 3),
            capacity,
        }
    }

    pub fn push(&self, cert: CachedCert) {
        let cert = Arc::new(cert);

        // Issue #4: Insert into hash_index first (DashMap — no global lock).
        self.hash_index.insert(normalize_hash(&cert.leaf.sha256), Arc::clone(&cert));
        self.hash_index.insert(normalize_hash(&cert.leaf.sha1), Arc::clone(&cert));
        self.hash_index.insert(normalize_hash(&cert.leaf.fingerprint), Arc::clone(&cert));

        // Lock only the VecDeque for queue management, not for hash_index operations.
        let evicted = {
            let mut entries = self.entries.write();
            let evicted = if entries.len() >= self.capacity {
                entries.pop_front()
            } else {
                None
            };
            entries.push_back(Arc::clone(&cert));
            evicted
        };

        // Remove evicted cert from hash_index after releasing the VecDeque lock.
        if let Some(old) = evicted {
            self.hash_index.remove(&normalize_hash(&old.leaf.sha256));
            self.hash_index.remove(&normalize_hash(&old.leaf.sha1));
            self.hash_index.remove(&normalize_hash(&old.leaf.fingerprint));
        }
    }

    #[inline]
    pub fn get_by_hash(&self, hash: &str) -> Option<Arc<CachedCert>> {
        let key = normalize_hash(hash);
        self.hash_index.get(&key).map(|r| Arc::clone(r.value()))
    }

    pub fn len(&self) -> usize {
        self.entries.read().len()
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }
}

pub struct LogTracker {
    /// Keyed by the normalised log URL. DashMap sharding replaces the single
    /// RwLock<Vec<…>>, giving O(1) updates with no global write-lock contention.
    logs: DashMap<String, TrackedLog>,
}

pub struct TrackedLog {
    pub name: String,
    pub url: String,
    pub operator: String,
    pub status: HealthStatus,
    pub current_index: u64,
    pub tree_size: u64,
    pub total_errors: u64,
    pub last_success: Option<i64>,
}

impl LogTracker {
    pub fn new() -> Self {
        Self {
            logs: DashMap::new(),
        }
    }

    pub fn register(&self, name: String, url: String, operator: String) {
        self.logs.insert(url.clone(), TrackedLog {
            name,
            url,
            operator,
            status: HealthStatus::Healthy,
            current_index: 0,
            tree_size: 0,
            total_errors: 0,
            last_success: None,
        });
    }

    pub fn update(&self, url: &str, status: HealthStatus, current_index: u64, tree_size: u64, total_errors: u64) {
        if let Some(mut entry) = self.logs.get_mut(url) {
            entry.status = status;
            entry.current_index = current_index;
            entry.tree_size = tree_size;
            entry.total_errors = total_errors;
            entry.last_success = Some(chrono::Utc::now().timestamp());
        }
    }

    pub fn get_all(&self) -> Vec<LogStatus> {
        self.logs
            .iter()
            .map(|entry| {
                let l = entry.value();
                LogStatus {
                    name: l.name.clone(),
                    url: l.url.clone(),
                    operator: l.operator.clone(),
                    status: match l.status {
                        HealthStatus::Healthy => "healthy".to_string(),
                        HealthStatus::Degraded => "degraded".to_string(),
                        HealthStatus::Unhealthy => "unhealthy".to_string(),
                    },
                    current_index: l.current_index,
                    tree_size: l.tree_size,
                    total_errors: l.total_errors,
                    last_success: l.last_success,
                }
            })
            .collect()
    }

    pub fn count_by_status(&self) -> (usize, usize, usize) {
        let mut healthy = 0usize;
        let mut degraded = 0usize;
        let mut unhealthy = 0usize;
        for entry in self.logs.iter() {
            match entry.status {
                HealthStatus::Healthy => healthy += 1,
                HealthStatus::Degraded => degraded += 1,
                HealthStatus::Unhealthy => unhealthy += 1,
            }
        }
        (healthy, degraded, unhealthy)
    }
}

pub struct ServerStats {
    pub start_time: Instant,
    pub messages_sent: AtomicU64,
    pub certificates_processed: AtomicU64,
    pub bytes_sent: AtomicU64,
}

impl ServerStats {
    pub fn new() -> Self {
        Self {
            start_time: Instant::now(),
            messages_sent: AtomicU64::new(0),
            certificates_processed: AtomicU64::new(0),
            bytes_sent: AtomicU64::new(0),
        }
    }

    pub fn uptime_seconds(&self) -> u64 {
        self.start_time.elapsed().as_secs()
    }
}

pub struct ApiState {
    pub stats: Arc<ServerStats>,
    pub cache: Arc<CertificateCache>,
    pub log_tracker: Arc<LogTracker>,
    pub ws_state: Arc<crate::websocket::AppState>,
}

pub async fn handle_stats(State(state): State<Arc<ApiState>>) -> Json<StatsResponse> {
    Json(StatsResponse {
        uptime_seconds: state.stats.uptime_seconds(),
        connections: ConnectionStats {
            total: state.ws_state.connections.total()
                + crate::sse::sse_connection_count(),
            websocket: state.ws_state.connections.total(),
            sse: crate::sse::sse_connection_count(),
        },
        throughput: ThroughputStats {
            messages_sent: state.stats.messages_sent.load(Ordering::Relaxed),
            certificates_processed: state.stats.certificates_processed.load(Ordering::Relaxed),
            bytes_sent: state.stats.bytes_sent.load(Ordering::Relaxed),
        },
        memory: MemoryStats {
            cache_entries: state.cache.len(),
            cache_capacity: state.cache.capacity(),
        },
    })
}

pub async fn handle_logs(State(state): State<Arc<ApiState>>) -> Json<LogsResponse> {
    let logs = state.log_tracker.get_all();
    let (healthy, degraded, unhealthy) = state.log_tracker.count_by_status();
    Json(LogsResponse {
        total_logs: logs.len(),
        healthy,
        degraded,
        unhealthy,
        logs,
    })
}

pub async fn handle_cert(
    State(state): State<Arc<ApiState>>,
    Path(hash): Path<String>,
) -> impl IntoResponse {
    match state.cache.get_by_hash(&hash) {
        Some(cert) => {
            let cert_link = format!(
                "{}/ct/v1/get-entries?start={}&end={}",
                cert.source_url, cert.cert_index, cert.cert_index
            );
            Json(CertDetail {
                fingerprint: cert.leaf.fingerprint.to_string(),
                sha1: cert.leaf.sha1.clone(),
                sha256: cert.leaf.sha256.clone(),
                serial_number: cert.leaf.serial_number.clone(),
                subject: cert.leaf.subject.clone(),
                issuer: cert.leaf.issuer.clone(),
                not_before: cert.leaf.not_before,
                not_after: cert.leaf.not_after,
                is_ca: cert.leaf.is_ca,
                all_domains: cert.leaf.all_domains.to_vec(),
                signature_algorithm: cert.leaf.signature_algorithm.to_string(),
                seen: cert.seen,
                source: cert.source_name.clone(),
                cert_index: cert.cert_index,
                cert_link,
            })
            .into_response()
        }
        None => (StatusCode::NOT_FOUND, "Certificate not found").into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ct::watcher::HealthStatus;
    use crate::models::{Extensions, LeafCert};
    use std::borrow::Cow;

    fn make_cert(sha256: &str, sha1: &str, fingerprint: &str) -> CachedCert {
        CachedCert {
            leaf: Arc::new(LeafCert {
                fingerprint: Arc::from(fingerprint),
                sha1: sha1.to_string(),
                sha256: sha256.to_string(),
                sha256_raw: [0u8; 32],
                serial_number: "00".to_string(),
                subject: Subject {
                    cn: Some("example.com".to_string()),
                    ..Subject::default()
                },
                issuer: Subject {
                    cn: Some("Test CA".to_string()),
                    ..Subject::default()
                },
                not_before: 0,
                not_after: 1_000_000,
                is_ca: false,
                all_domains: smallvec::smallvec!["example.com".to_string()],
                signature_algorithm: Cow::Borrowed("SHA256withRSA"),
                as_der: None,
                extensions: Extensions::default(),
            }),
            seen: 1.0,
            source_name: "test-log".to_string(),
            source_url: "https://ct.test/log".to_string(),
            cert_index: 42,
        }
    }

    #[test]
    fn normalize_hash_lowercase_hex_to_uppercase() {
        let cache = CertificateCache::new(8);
        let cert = make_cert("aabbccdd", "11223344", "deadbeef");
        cache.push(cert);

        // Lookup with lowercase — should still find via normalized uppercase
        let found = cache.get_by_hash("aabbccdd");
        assert!(found.is_some(), "lowercase lookup should succeed");
        assert_eq!(found.unwrap().leaf.sha256, "aabbccdd");
    }

    #[test]
    fn normalize_hash_strips_colons() {
        let cache = CertificateCache::new(8);
        let cert = make_cert("AA:BB:CC:DD", "11:22:33:44", "DE:AD:BE:EF");
        cache.push(cert);

        // Lookup using colons should match
        let found = cache.get_by_hash("AA:BB:CC:DD");
        assert!(found.is_some(), "colon-separated lookup should succeed");

        // Lookup without colons should also match
        let found2 = cache.get_by_hash("AABBCCDD");
        assert!(found2.is_some(), "plain hex lookup should succeed after colon normalization");
    }

    #[test]
    fn normalize_hash_mixed_case() {
        let cache = CertificateCache::new(8);
        let cert = make_cert("AaBbCcDd", "1a2B3c4D", "dEaDbEeF");
        cache.push(cert);

        // Lookup with different casing should still resolve
        let found = cache.get_by_hash("aabbccdd");
        assert!(found.is_some(), "mixed case lookup should succeed");

        let found2 = cache.get_by_hash("AABBCCDD");
        assert!(found2.is_some(), "uppercase lookup for mixed-case stored hash should succeed");
    }

    #[test]
    fn cache_new_is_empty() {
        let cache = CertificateCache::new(16);
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn cache_push_increments_len() {
        let cache = CertificateCache::new(16);
        cache.push(make_cert("AA", "BB", "CC"));
        assert_eq!(cache.len(), 1);
        cache.push(make_cert("DD", "EE", "FF"));
        assert_eq!(cache.len(), 2);
    }

    #[test]
    fn cache_get_by_sha256() {
        let cache = CertificateCache::new(16);
        cache.push(make_cert("ABCD1234", "FFFF0000", "12345678"));

        let found = cache.get_by_hash("ABCD1234");
        assert!(found.is_some());
        assert_eq!(found.unwrap().leaf.sha256, "ABCD1234");
    }

    #[test]
    fn cache_get_by_sha1() {
        let cache = CertificateCache::new(16);
        cache.push(make_cert("ABCD1234", "FFFF0000", "12345678"));

        let found = cache.get_by_hash("FFFF0000");
        assert!(found.is_some());
        assert_eq!(found.unwrap().leaf.sha1, "FFFF0000");
    }

    #[test]
    fn cache_get_by_fingerprint() {
        let cache = CertificateCache::new(16);
        cache.push(make_cert("ABCD1234", "FFFF0000", "12345678"));

        let found = cache.get_by_hash("12345678");
        assert!(found.is_some());
        assert_eq!(&*found.unwrap().leaf.fingerprint, "12345678");
    }

    #[test]
    fn cache_eviction_when_capacity_exceeded() {
        let cache = CertificateCache::new(2);
        cache.push(make_cert("AAAA", "BBBB", "CCCC")); // entry 1
        cache.push(make_cert("DDDD", "EEEE", "FFFF")); // entry 2
        assert_eq!(cache.len(), 2);

        // Pushing a third entry should evict the oldest (entry 1)
        cache.push(make_cert("1111", "2222", "3333"));
        assert_eq!(cache.len(), 2, "len should stay at capacity after eviction");

        // The evicted cert should no longer be findable by any of its hashes
        assert!(cache.get_by_hash("AAAA").is_none(), "evicted sha256 should be gone");
        assert!(cache.get_by_hash("BBBB").is_none(), "evicted sha1 should be gone");
        assert!(cache.get_by_hash("CCCC").is_none(), "evicted fingerprint should be gone");

        // The remaining certs should still be findable
        assert!(cache.get_by_hash("DDDD").is_some(), "second entry should remain");
        assert!(cache.get_by_hash("1111").is_some(), "third entry should remain");
    }

    #[test]
    fn cache_eviction_old_cert_not_findable() {
        let cache = CertificateCache::new(1);
        cache.push(make_cert("FIRST", "F1", "FP1"));
        assert!(cache.get_by_hash("FIRST").is_some());

        cache.push(make_cert("SECOND", "S1", "SP1"));
        assert!(cache.get_by_hash("FIRST").is_none(), "old cert must not be findable after eviction");
        assert!(cache.get_by_hash("SECOND").is_some(), "new cert must be findable");
    }

    #[test]
    fn cache_capacity_returns_correct_value() {
        let cache = CertificateCache::new(42);
        assert_eq!(cache.capacity(), 42);

        let cache2 = CertificateCache::new(1000);
        assert_eq!(cache2.capacity(), 1000);
    }

    #[test]
    fn log_tracker_new_is_empty() {
        let tracker = LogTracker::new();
        let all = tracker.get_all();
        assert!(all.is_empty());
        let (h, d, u) = tracker.count_by_status();
        assert_eq!((h, d, u), (0, 0, 0));
    }

    #[test]
    fn log_tracker_register_adds_log_with_healthy_status() {
        let tracker = LogTracker::new();
        tracker.register(
            "Test Log".to_string(),
            "https://ct.test/log".to_string(),
            "Test Operator".to_string(),
        );

        let all = tracker.get_all();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].name, "Test Log");
        assert_eq!(all[0].url, "https://ct.test/log");
        assert_eq!(all[0].operator, "Test Operator");
        assert_eq!(all[0].status, "healthy");
        assert_eq!(all[0].current_index, 0);
        assert_eq!(all[0].tree_size, 0);
        assert_eq!(all[0].total_errors, 0);
        assert!(all[0].last_success.is_none());
    }

    #[test]
    fn log_tracker_update_changes_fields() {
        let tracker = LogTracker::new();
        tracker.register(
            "Log A".to_string(),
            "https://ct.test/a".to_string(),
            "Op A".to_string(),
        );

        tracker.update("https://ct.test/a", HealthStatus::Degraded, 500, 1000, 3);

        let all = tracker.get_all();
        assert_eq!(all[0].status, "degraded");
        assert_eq!(all[0].current_index, 500);
        assert_eq!(all[0].tree_size, 1000);
        assert_eq!(all[0].total_errors, 3);
        assert!(all[0].last_success.is_some(), "last_success should be set after update");
    }

    #[test]
    fn log_tracker_get_all_returns_correct_status_strings() {
        let tracker = LogTracker::new();
        tracker.register("H".to_string(), "https://h".to_string(), "op".to_string());
        tracker.register("D".to_string(), "https://d".to_string(), "op".to_string());
        tracker.register("U".to_string(), "https://u".to_string(), "op".to_string());

        tracker.update("https://d", HealthStatus::Degraded, 0, 0, 0);
        tracker.update("https://u", HealthStatus::Unhealthy, 0, 0, 0);

        let all = tracker.get_all();
        let mut statuses: Vec<&str> = all.iter().map(|l| l.status.as_str()).collect();
        statuses.sort(); // DashMap iteration order is not guaranteed
        assert_eq!(statuses, vec!["degraded", "healthy", "unhealthy"]);
    }

    #[test]
    fn log_tracker_count_by_status() {
        let tracker = LogTracker::new();
        tracker.register("H1".to_string(), "https://h1".to_string(), "op".to_string());
        tracker.register("H2".to_string(), "https://h2".to_string(), "op".to_string());
        tracker.register("D1".to_string(), "https://d1".to_string(), "op".to_string());
        tracker.register("U1".to_string(), "https://u1".to_string(), "op".to_string());
        tracker.register("U2".to_string(), "https://u2".to_string(), "op".to_string());

        tracker.update("https://d1", HealthStatus::Degraded, 0, 0, 0);
        tracker.update("https://u1", HealthStatus::Unhealthy, 0, 0, 0);
        tracker.update("https://u2", HealthStatus::Unhealthy, 0, 0, 0);

        let (h, d, u) = tracker.count_by_status();
        assert_eq!(h, 2, "should have 2 healthy logs");
        assert_eq!(d, 1, "should have 1 degraded log");
        assert_eq!(u, 2, "should have 2 unhealthy logs");
    }

    #[test]
    fn server_stats_new_initializes_all_counters_to_zero() {
        let stats = ServerStats::new();
        assert_eq!(stats.messages_sent.load(Ordering::Relaxed), 0);
        assert_eq!(stats.certificates_processed.load(Ordering::Relaxed), 0);
        assert_eq!(stats.bytes_sent.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn server_stats_uptime_seconds_returns_reasonable_value() {
        let stats = ServerStats::new();
        let uptime = stats.uptime_seconds();
        assert!(uptime < 2, "uptime should be less than 2 seconds right after creation, got {uptime}");
    }
}
