pub mod catalog;
mod log_list;
mod normalize;
mod parser;
pub mod static_ct;
pub mod watcher;

pub use log_list::*;
pub use normalize::normalize_operator;
pub use parser::*;

use std::sync::Arc;
use std::sync::atomic::Ordering;
use tokio::sync::broadcast;
use tokio_util::sync::CancellationToken;

/// Per-operator rate limiter to avoid hitting CT log rate limits.
///
/// Token bucket: refilled at `1 / min_interval` Hz, holding at most `burst`
/// tokens. The long-run request rate is therefore identical to the old
/// one-permit design (one request per `min_interval`), but up to `burst`
/// requests may start back-to-back — which is what lets a watcher pipeline
/// `fetch_concurrency` get-entries/tile fetches without violating operator
/// politeness over any window longer than the burst itself.
pub type OperatorRateLimiter = Arc<OperatorLimiter>;

pub struct OperatorLimiter {
    state: tokio::sync::Mutex<BucketState>,
    min_interval: std::time::Duration,
    burst: f64,
}

struct BucketState {
    tokens: f64,
    last_refill: tokio::time::Instant,
}

impl OperatorLimiter {
    pub fn with_burst(min_interval: std::time::Duration, burst: u32) -> Self {
        Self {
            // Seed with a full bucket so startup doesn't serialize the first
            // burst of requests (parity with the old "first tick is free").
            state: tokio::sync::Mutex::new(BucketState {
                tokens: burst.max(1) as f64,
                last_refill: tokio::time::Instant::now(),
            }),
            min_interval,
            burst: burst.max(1) as f64,
        }
    }

    pub async fn tick(&self) {
        if self.min_interval.is_zero() {
            return;
        }
        loop {
            let wait = {
                let mut s = self.state.lock().await;
                let now = tokio::time::Instant::now();
                let refill = now.duration_since(s.last_refill).as_secs_f64()
                    / self.min_interval.as_secs_f64();
                s.tokens = (s.tokens + refill).min(self.burst);
                s.last_refill = now;
                if s.tokens >= 1.0 {
                    // Deduct and return without awaiting — a caller cancelled
                    // mid-`tick` can never leak a token.
                    s.tokens -= 1.0;
                    return;
                }
                self.min_interval.mul_f64(1.0 - s.tokens)
            };
            // Sleep outside the lock so other operators'/watchers' callers
            // aren't serialized behind our wait, then re-check.
            tokio::time::sleep(wait).await;
        }
    }
}

/// Outcome of one pipelined get-entries/tile fetch. The body is downloaded
/// inside the concurrent stage so network transfer overlaps across the
/// `buffered(fetch_concurrency)` window; the sequential processing stage only
/// sees finished results.
pub(crate) enum FetchOutcome {
    /// 2xx with the full body.
    Body(bytes::Bytes),
    /// Non-success HTTP status; for 429 the second field carries the
    /// canonicalized Retry-After backoff in ms.
    Http(reqwest::StatusCode, Option<u64>),
    /// Transport/body error, stringified.
    Net(String),
}

use crate::api::{CachedCert, CertificateCache, LogTracker, ServerStats};
use crate::config::{CtLogConfig, StreamConfig};
use crate::dedup::DedupFilter;
use crate::models::{CertificateMessage, LeafCert, PreSerializedMessage, Source};
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

/// Issue #2: Build a CachedCert sharing the Arc<LeafCert> and Arc<Source> —
/// zero field clones, zero per-cert String allocations.
pub fn build_cached_cert(
    leaf: Arc<LeafCert>,
    seen: f64,
    source: Arc<Source>,
    cert_index: u64,
) -> CachedCert {
    CachedCert {
        leaf,
        seen,
        source,
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
        stats.certificates_processed.fetch_add(1, Ordering::Relaxed);
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
        let source = Arc::new(Source {
            name: Arc::from("t"),
            url: Arc::from("u"),
        });
        build_cached_cert(make_leaf(), 0.0, source, 0)
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

    /// Burst semantics: a bucket of N allows N immediate ticks, then the
    /// (N+1)th must wait ~min_interval. Long-run rate is unchanged.
    #[tokio::test]
    async fn operator_limiter_burst_allows_n_then_throttles() {
        let limiter = OperatorLimiter::with_burst(std::time::Duration::from_millis(100), 3);

        let t0 = Instant::now();
        for _ in 0..3 {
            limiter.tick().await;
        }
        assert!(
            t0.elapsed() < std::time::Duration::from_millis(50),
            "first `burst` ticks must not wait, got {:?}",
            t0.elapsed()
        );

        let t1 = Instant::now();
        limiter.tick().await;
        assert!(
            t1.elapsed() >= std::time::Duration::from_millis(80),
            "tick beyond the burst must wait ~min_interval, got {:?}",
            t1.elapsed()
        );
    }

    /// Direct OperatorLimiter timing test for #7. Two back-to-back ticks must
    /// take at least `min_interval` wall time when the limiter is contended.
    #[tokio::test]
    async fn operator_limiter_enforces_min_interval() {
        let limiter = Arc::new(OperatorLimiter::with_burst(
            std::time::Duration::from_millis(100),
            1,
        ));
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
