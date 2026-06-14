pub mod catalog;
mod log_list;
mod normalize;
mod parser;
pub mod static_ct;
pub mod watcher;

pub use log_list::*;
pub use normalize::normalize_operator;
pub use parser::*;

use std::sync::atomic::Ordering;
use std::sync::Arc;
use tokio::sync::broadcast;
use tokio_util::sync::CancellationToken;

/// Per-operator rate limiter to avoid hitting CT log rate limits.
///
/// Semantics: at most one call may complete `tick()` per `min_interval`.
/// The mutex is held across the sleep so concurrent callers serialize and
/// each one waits its full slice — equivalent to a single-permit token bucket
/// refilled at `1 / min_interval` Hz. Simpler and more obviously correct than
/// sharing a `tokio::time::Interval`, which has non-trivial missed-tick
/// semantics under contention.
pub type OperatorRateLimiter = Arc<OperatorLimiter>;

pub struct OperatorLimiter {
    last_tick: tokio::sync::Mutex<tokio::time::Instant>,
    min_interval: std::time::Duration,
}

impl OperatorLimiter {
    pub fn new(min_interval: std::time::Duration) -> Self {
        // Initialise last_tick in the past so the first caller doesn't wait.
        let now = tokio::time::Instant::now();
        let seed = now.checked_sub(min_interval).unwrap_or(now);
        Self {
            last_tick: tokio::sync::Mutex::new(seed),
            min_interval,
        }
    }

    pub async fn tick(&self) {
        let mut last = self.last_tick.lock().await;
        let now = tokio::time::Instant::now();
        let elapsed = now.duration_since(*last);
        if elapsed < self.min_interval {
            tokio::time::sleep(self.min_interval - elapsed).await;
        }
        *last = tokio::time::Instant::now();
    }
}

use crate::api::{CachedCert, CertificateCache, LogTracker, ServerStats};
use crate::config::{CtLogConfig, StreamConfig};
use crate::dedup::DedupFilter;
use crate::models::{CertificateMessage, LeafCert, PreSerializedMessage};
use crate::state::StateManager;
use static_ct::IssuerCache;

/// Shared context for CT log watcher tasks.
#[derive(Clone)]
pub struct WatcherContext {
    pub client: reqwest::Client,
    pub tx: broadcast::Sender<Arc<PreSerializedMessage>>,
    pub config: Arc<CtLogConfig>,
    pub state_manager: Arc<StateManager>,
    pub cache: Arc<CertificateCache>,
    pub stats: Arc<ServerStats>,
    pub tracker: Arc<LogTracker>,
    pub shutdown: CancellationToken,
    pub dedup: Arc<DedupFilter>,
    pub rate_limiter: Option<OperatorRateLimiter>,
    pub streams: Arc<StreamConfig>,
    /// Single issuer-DER cache shared across ALL static-CT watchers. Pre-1.5.0
    /// each watcher had its own 10K-entry cache, so 55 static-CT logs meant
    /// up to 550K cached issuer DERs (each multi-KB). Sharing collapses the
    /// effective footprint to one cache and lets distinct logs amortise
    /// fetches for common roots (Let's Encrypt R10, ISRG X1, …).
    pub issuer_cache: Arc<IssuerCache>,
}

/// Issue #2: Build a CachedCert sharing the Arc<LeafCert> — zero field clones.
pub fn build_cached_cert(
    leaf: Arc<LeafCert>,
    seen: f64,
    source_name: &str,
    source_url: &str,
    cert_index: u64,
) -> CachedCert {
    CachedCert {
        leaf,
        seen,
        source_name: source_name.to_string(),
        source_url: source_url.to_string(),
        cert_index,
    }
}

/// Serialize and broadcast a certificate message to all subscribers.
/// Issue #3: `messages_counter` is pre-registered outside the hot loop — no label allocation.
///
/// Idle-server optimisation: skip the (up to) three-format JSON serialisation
/// entirely when no WebSocket/SSE subscriber is listening. The cache push and
/// stats updates still run so REST clients of `/api/cert/{hash}` keep working.
pub fn broadcast_cert(
    msg: CertificateMessage,
    tx: &broadcast::Sender<Arc<PreSerializedMessage>>,
    cache: &CertificateCache,
    cached: CachedCert,
    stats: &ServerStats,
    messages_counter: &metrics::Counter,
    streams: &StreamConfig,
) {
    cache.push(cached);

    // No live subscribers? Skip the serialise round-trip — it can be ~1-3 KB
    // of JSON per cert × tens of thousands per second × three formats.
    if tx.receiver_count() == 0 {
        stats.certificates_processed.fetch_add(1, Ordering::Relaxed);
        return;
    }

    if let Some(serialized) = msg.pre_serialize(streams) {
        let msg_size =
            serialized.full.len() + serialized.lite.len() + serialized.domains_only.len();
        let _ = tx.send(serialized);
        stats.messages_sent.fetch_add(1, Ordering::Relaxed);
        stats
            .certificates_processed
            .fetch_add(1, Ordering::Relaxed);
        stats
            .bytes_sent
            .fetch_add(msg_size as u64, Ordering::Relaxed);
        messages_counter.increment(1);
    }
}

#[cfg(test)]
mod broadcast_tests {
    use super::*;
    use crate::models::{CertificateData, CertificateMessage, LeafCert, Source, Subject};
    use std::borrow::Cow;
    use std::sync::Arc;
    use std::time::Instant;

    fn make_leaf() -> Arc<LeafCert> {
        Arc::new(LeafCert {
            subject: Subject::default(),
            issuer: Subject::default(),
            extensions: Default::default(),
            not_before: 0,
            not_after: 0,
            serial_number: String::new(),
            fingerprint: Arc::from(""),
            sha1: String::new(),
            sha256: String::new(),
            signature_algorithm: Cow::Borrowed("test"),
            is_ca: false,
            all_domains: smallvec::SmallVec::new(),
            as_der: None,
            sha256_raw: [0u8; 32],
        })
    }

    fn dummy_msg() -> CertificateMessage {
        CertificateMessage {
            message_type: Cow::Borrowed("certificate_update"),
            data: CertificateData {
                update_type: Cow::Borrowed("X509LogEntry"),
                leaf_cert: make_leaf(),
                chain: None,
                cert_index: 0,
                cert_link: String::new(),
                seen: 0.0,
                submission_timestamp: 0.0,
                source: Arc::new(Source {
                    name: Arc::from("t"),
                    url: Arc::from("u"),
                }),
            },
        }
    }

    fn dummy_cached() -> CachedCert {
        build_cached_cert(make_leaf(), 0.0, "t", "u", 0)
    }

    /// Regression for #13: with **no** subscribers, broadcast_cert must skip
    /// serialisation entirely. Pre-1.5.0 the `_rx` placeholder in main pinned
    /// receiver_count at 1, so this guard never fired and idle servers
    /// burned CPU on serialise. The fix removed the placeholder.
    #[test]
    fn receiver_count_guard_skips_serialise_when_no_subs() {
        let (tx, _) = broadcast::channel::<Arc<PreSerializedMessage>>(16);
        // Drop the placeholder receiver immediately — mirrors v1.5.0 main.
        // (we use `_` so the binding is discarded right away)
        assert_eq!(
            tx.receiver_count(),
            0,
            "no live receivers expected — if this asserts, a placeholder is leaking"
        );

        let stats = Arc::new(ServerStats::new());
        let cache = Arc::new(CertificateCache::new(10));
        let counter = metrics::counter!("test_messages_sent_guard");
        let streams = StreamConfig::default();

        let before_msgs = stats.messages_sent.load(Ordering::Relaxed);
        let before_proc = stats.certificates_processed.load(Ordering::Relaxed);

        broadcast_cert(
            dummy_msg(),
            &tx,
            &cache,
            dummy_cached(),
            &stats,
            &counter,
            &streams,
        );

        // certificates_processed still increments (REST cache stays warm).
        assert_eq!(
            stats.certificates_processed.load(Ordering::Relaxed) - before_proc,
            1,
            "certificates_processed must still increment"
        );
        // messages_sent must NOT increment — that's the guard.
        assert_eq!(
            stats.messages_sent.load(Ordering::Relaxed) - before_msgs,
            0,
            "messages_sent must stay at 0 when no subscribers"
        );
    }

    /// With a live subscriber, broadcast_cert must serialise and increment.
    #[test]
    fn broadcast_cert_increments_when_subscribed() {
        let (tx, _rx) = broadcast::channel::<Arc<PreSerializedMessage>>(16);
        assert_eq!(tx.receiver_count(), 1);

        let stats = Arc::new(ServerStats::new());
        let cache = Arc::new(CertificateCache::new(10));
        let counter = metrics::counter!("test_messages_sent_active");
        let streams = StreamConfig::default();

        let before = stats.messages_sent.load(Ordering::Relaxed);
        broadcast_cert(
            dummy_msg(),
            &tx,
            &cache,
            dummy_cached(),
            &stats,
            &counter,
            &streams,
        );
        assert_eq!(
            stats.messages_sent.load(Ordering::Relaxed) - before,
            1,
            "messages_sent must increment when a subscriber is alive"
        );

        // And drain so we don't deadlock the channel.
        let _ = _rx;
        let _wall_time = Instant::now();
    }

    /// Direct OperatorLimiter timing test for #7. Two back-to-back ticks must
    /// take at least `min_interval` wall time when the limiter is contended.
    #[tokio::test]
    async fn operator_limiter_enforces_min_interval() {
        let limiter = Arc::new(OperatorLimiter::new(std::time::Duration::from_millis(100)));
        // First tick consumes the seeded "in the past" credit, returns immediately.
        let t0 = Instant::now();
        limiter.tick().await;
        let first = t0.elapsed();
        assert!(
            first < std::time::Duration::from_millis(20),
            "first tick should be fast (seeded), got {:?}",
            first
        );

        // Second tick must wait ~100ms.
        let t1 = Instant::now();
        limiter.tick().await;
        let second = t1.elapsed();
        assert!(
            second >= std::time::Duration::from_millis(90),
            "second tick should respect min_interval, got {:?}",
            second
        );
    }
}
