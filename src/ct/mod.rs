pub mod catalog;
pub mod merkle;
pub mod names_tiles;
mod log_list;
mod normalize;
mod parser;
pub mod static_ct;
pub mod watcher;

pub use log_list::*;
pub use normalize::normalize_operator;
pub use parser::*;

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::broadcast;
use tokio_util::sync::CancellationToken;

/// Per-operator rate limiter to avoid hitting CT log rate limits.
///
/// Token bucket: refilled at `1 / interval` Hz, holding at most `burst`
/// tokens, so up to `burst` requests may start back-to-back, which is what
/// lets a watcher pipeline `fetch_concurrency` get-entries/tile fetches.
///
/// The interval is not fixed. It starts at the configured floor, the fastest
/// the operator is asked, and follows what the operator says: when a quarter
/// of its answers are 429 it slows by a quarter, up to a ceiling, and a quiet
/// stretch speeds it up again by a tenth at a time. An operator that serves
/// heavy monitoring traffic is then read at full speed, and one that rate
/// limits is slowed to what it tolerates without a number having to be
/// guessed for every operator in advance.
pub type OperatorRateLimiter = Arc<OperatorLimiter>;

/// The slowest an operator is ever slowed to.
const SLOWEST_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);
/// Requests between judgements of how many were refused, and the share of
/// refusals at which the interval is slowed.
const JUDGE_EVERY: u32 = 20;
const SLOW_DOWN_AT_PERCENT: u32 = 25;
/// Answers older than this no longer count towards the next judgement.
const JUDGE_WITHIN: std::time::Duration = std::time::Duration::from_secs(60);
/// A burst of 429s from requests already in flight is one signal, not many.
const BACKOFF_WINDOW: std::time::Duration = std::time::Duration::from_secs(1);
/// How long without a 429 before the interval starts coming down, and how
/// often it steps down after that.
const RECOVERY_QUIET: std::time::Duration = std::time::Duration::from_secs(5);
const RECOVERY_STEP: std::time::Duration = std::time::Duration::from_secs(1);

pub struct OperatorLimiter {
    state: tokio::sync::Mutex<BucketState>,
    /// Fastest and slowest interval, in microseconds. Equal for a fixed limiter.
    floor_us: u64,
    ceiling_us: u64,
    /// Interval in force, between the two.
    interval_us: AtomicU64,
    burst: f64,
    /// Operator key for the interval gauge; empty for no gauge.
    name: String,
    adapt: parking_lot::Mutex<Adapt>,
}

struct BucketState {
    tokens: f64,
    last_refill: tokio::time::Instant,
}

#[derive(Default)]
struct Adapt {
    requests: u32,
    limited: u32,
    window_start: Option<tokio::time::Instant>,
    last_limited: Option<tokio::time::Instant>,
    last_backoff: Option<tokio::time::Instant>,
    last_step: Option<tokio::time::Instant>,
}

impl OperatorLimiter {
    /// A limiter whose interval never changes.
    #[cfg(test)]
    pub fn with_burst(min_interval: std::time::Duration, burst: u32) -> Self {
        Self::build(String::new(), min_interval, min_interval, burst)
    }

    /// A limiter that starts at `floor` and slows down when the operator
    /// answers 429.
    pub fn adaptive(name: String, floor: std::time::Duration, burst: u32) -> Self {
        let limiter = Self::build(name, floor, floor.max(SLOWEST_INTERVAL), burst);
        limiter.publish(limiter.floor_us);
        limiter
    }

    fn build(name: String, floor: std::time::Duration, ceiling: std::time::Duration, burst: u32) -> Self {
        let floor_us = floor.as_micros() as u64;
        Self {
            // Seed with a full bucket so startup doesn't serialize the first
            // burst of requests (parity with the old "first tick is free").
            state: tokio::sync::Mutex::new(BucketState {
                tokens: burst.max(1) as f64,
                last_refill: tokio::time::Instant::now(),
            }),
            floor_us,
            ceiling_us: ceiling.as_micros() as u64,
            interval_us: AtomicU64::new(floor_us),
            burst: burst.max(1) as f64,
            name,
            adapt: parking_lot::Mutex::new(Adapt::default()),
        }
    }

    pub async fn tick(&self) {
        loop {
            let interval_us = self.interval_us.load(Ordering::Relaxed);
            if interval_us == 0 {
                return;
            }
            let interval = std::time::Duration::from_micros(interval_us);
            let wait = {
                let mut s = self.state.lock().await;
                let now = tokio::time::Instant::now();
                let refill = now.duration_since(s.last_refill).as_secs_f64() / interval.as_secs_f64();
                s.tokens = (s.tokens + refill).min(self.burst);
                s.last_refill = now;
                if s.tokens >= 1.0 {
                    // Deduct and return without awaiting — a caller cancelled
                    // mid-`tick` can never leak a token.
                    s.tokens -= 1.0;
                    return;
                }
                interval.mul_f64(1.0 - s.tokens)
            };
            // Sleep outside the lock so other operators'/watchers' callers
            // aren't serialized behind our wait, then re-check.
            tokio::time::sleep(wait).await;
        }
    }

    /// The operator answered 429: slow down.
    pub fn on_rate_limited(&self) {
        self.observe(true);
    }

    /// A request went through: speed up again once it has been quiet for a while.
    pub fn on_success(&self) {
        self.observe(false);
        self.recover_at(tokio::time::Instant::now());
    }

    /// Operators answer a fraction of requests with 429 whatever the pace, so
    /// one answer is not a reason to slow down. Every `JUDGE_EVERY` requests
    /// the interval is slowed if `SLOW_DOWN_AT_PERCENT` or more of them were refused.
    fn observe(&self, limited: bool) {
        if self.floor_us == self.ceiling_us {
            return;
        }
        let heavy = {
            let now = tokio::time::Instant::now();
            let mut adapt = self.adapt.lock();
            if adapt.window_start.is_none_or(|t| now.duration_since(t) > JUDGE_WITHIN) {
                adapt.window_start = Some(now);
                adapt.requests = 0;
                adapt.limited = 0;
            }
            adapt.requests += 1;
            if limited {
                adapt.limited += 1;
                adapt.last_limited = Some(now);
            }
            if adapt.requests < JUDGE_EVERY {
                return;
            }
            let heavy = adapt.limited * 100 >= adapt.requests * SLOW_DOWN_AT_PERCENT;
            adapt.window_start = None;
            heavy
        };
        if heavy {
            self.back_off_at(tokio::time::Instant::now());
        }
    }

    fn back_off_at(&self, now: tokio::time::Instant) {
        if self.floor_us == self.ceiling_us {
            return;
        }
        let mut adapt = self.adapt.lock();
        let current = self.interval_us.load(Ordering::Relaxed);
        let window = BACKOFF_WINDOW.max(std::time::Duration::from_micros(current));
        if adapt.last_backoff.is_some_and(|t| now.duration_since(t) < window) {
            return;
        }
        adapt.last_backoff = Some(now);
        self.publish((current + current / 4).min(self.ceiling_us));
    }

    fn recover_at(&self, now: tokio::time::Instant) {
        let current = self.interval_us.load(Ordering::Relaxed);
        if current <= self.floor_us {
            return;
        }
        let mut adapt = self.adapt.lock();
        let quiet = [adapt.last_backoff, adapt.last_limited]
            .into_iter()
            .flatten()
            .all(|t| now.duration_since(t) >= RECOVERY_QUIET);
        let due = adapt.last_step.is_none_or(|t| now.duration_since(t) >= RECOVERY_STEP);
        if quiet && due {
            adapt.last_step = Some(now);
            self.publish((current - current / 10).max(self.floor_us));
        }
    }

    fn publish(&self, interval_us: u64) {
        self.interval_us.store(interval_us, Ordering::Relaxed);
        if !self.name.is_empty() {
            metrics::gauge!("certstream_operator_request_interval_ms", "operator" => self.name.clone())
                .set(interval_us as f64 / 1000.0);
        }
    }
}

/// Tells the operator's limiter what a request got back; a watcher without a
/// limiter (a log configured by hand) has nothing to tell.
pub(crate) fn note_rate_limited(limiter: &Option<OperatorRateLimiter>) {
    if let Some(limiter) = limiter {
        limiter.on_rate_limited();
    }
}

pub(crate) fn note_success(limiter: &Option<OperatorRateLimiter>) {
    if let Some(limiter) = limiter {
        limiter.on_success();
    }
}

/// Wait before a caught-up watcher asks for the head again: the poll interval,
/// doubled for each poll that found the head unmoved, up to four times.
pub(crate) fn idle_poll_delay(
    poll_interval: std::time::Duration,
    unchanged_polls: u32,
) -> std::time::Duration {
    poll_interval * (1 << unchanged_polls.min(2))
}

#[cfg(test)]
mod idle_poll_tests {
    use super::idle_poll_delay;
    use std::time::Duration;

    #[test]
    fn delay_doubles_per_unchanged_poll_up_to_four_times() {
        let base = Duration::from_millis(1000);
        let delays: Vec<_> = (0..6).map(|n| idle_poll_delay(base, n)).collect();
        let expected: Vec<_> = [1000, 2000, 4000, 4000, 4000, 4000]
            .into_iter()
            .map(Duration::from_millis)
            .collect();
        assert_eq!(delays, expected);
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
    /// Server-side subscription filters. The watcher only consults
    /// [`FilterHub::active`], to decide whether the broadcast payload has to
    /// carry the parsed leaf for matching.
    pub filters: Arc<crate::filter::FilterHub>,
    /// Durable output. `None` unless `nats.enabled`.
    pub nats: Option<crate::nats::NatsSink>,
    /// One issuer-DER cache for every static-CT watcher. A cache per watcher
    /// would hold the same multi-KB issuer DERs once per log; sharing it also
    /// lets distinct logs amortise fetches for the roots they have in common
    /// (Let's Encrypt R10, ISRG X1, …).
    pub issuer_cache: Arc<IssuerCache>,
}

/// Builds the cache entry from the `Arc`s the message already holds, so it
/// shares the leaf and source rather than copying their fields.
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
/// `messages_counter` is registered by the caller, outside the hot loop, so
/// this does not allocate its labels per certificate.
///
/// Idle-server optimisation: skip the (up to) three-format JSON serialisation
/// entirely when no WebSocket/SSE subscriber is listening. The cache push and
/// stats updates still run so REST clients of `/api/cert/{hash}` keep working.
/// How far behind wall-clock the newest entry a watcher just ingested is.
///
/// `certstream_ct_log_lag_entries` answers "how many records behind the head
/// am I"; this answers "how old is what I just delivered". A watcher sitting a
/// constant 200 entries behind a busy log and one sitting 200 entries behind an
/// idle log are indistinguishable in entry count and nothing alike here, and
/// only the second number tells a consumer how current its view of the CT
/// ecosystem is.
///
/// Called once per ingested batch, not once per certificate: the value is the
/// newest entry in the batch, which is the freshest thing the watcher has.
pub fn record_ingest_delay(log_name: &str, newest_submission_secs: f64, now_secs: f64) {
    // 0.0 is "no usable timestamp" (a leaf we could not date); a submission
    // slightly ahead of our clock is skew, not negative delay.
    if newest_submission_secs <= 0.0 {
        return;
    }
    metrics::gauge!("certstream_ct_log_ingest_delay_seconds", "log" => log_name.to_string())
        .set((now_secs - newest_submission_secs).max(0.0));
}

/// Publish an entry read from a names tile.
///
/// Separate from [`broadcast_cert`] because there is no certificate: no
/// hashes for the cache or for cross-log dedup, and nothing to build the
/// full, lite or v2 payloads from. The message type says so — a consumer must
/// never have to guess whether the names it received were checked against a
/// signed tree.
pub fn broadcast_names(
    entry: &crate::ct::names_tiles::NamesEntry,
    tx: &broadcast::Sender<Arc<PreSerializedMessage>>,
    stats: &ServerStats,
    messages_counter: &metrics::Counter,
) {
    stats.certificates_processed.fetch_add(1, Ordering::Relaxed);
    if tx.receiver_count() == 0 {
        return;
    }

    #[derive(serde::Serialize)]
    struct UnauthenticatedNames<'a> {
        message_type: &'a str,
        data: &'a crate::models::DomainList,
    }

    let Some(payload) = crate::models::serialize_utf8(
        &UnauthenticatedNames {
            message_type: "dns_entries_unauthenticated",
            data: &entry.domains,
        },
        512,
    ) else {
        return;
    };

    let size = payload.len();
    let _ = tx.send(Arc::new(PreSerializedMessage {
        full: axum::extract::ws::Utf8Bytes::from_static(""),
        lite: axum::extract::ws::Utf8Bytes::from_static(""),
        domains_only: payload,
        v2: axum::extract::ws::Utf8Bytes::from_static(""),
        leaf: None,
    }));
    stats.messages_sent.fetch_add(1, Ordering::Relaxed);
    stats.bytes_serialized.fetch_add(size as u64, Ordering::Relaxed);
    metrics::counter!("certstream_bytes_serialized_total").increment(size as u64);
    messages_counter.increment(1);
}

/// Everything a broadcast needs beyond the message itself. Resolved once per
/// batch rather than threaded through as six separate arguments.
pub struct BroadcastTargets<'a> {
    pub tx: &'a broadcast::Sender<Arc<PreSerializedMessage>>,
    pub cache: &'a CertificateCache,
    pub stats: &'a ServerStats,
    pub messages_counter: &'a metrics::Counter,
    pub streams: &'a StreamConfig,
    /// Whether a server-side filter exists and so the payload must keep the
    /// parsed leaf for matching.
    pub retain_leaf: bool,
}

pub fn broadcast_cert(msg: CertificateMessage, cached: CachedCert, to: &BroadcastTargets<'_>) {
    let BroadcastTargets {
        tx,
        cache,
        stats,
        messages_counter,
        streams,
        retain_leaf,
    } = *to;

    cache.push(cached);

    // No live subscribers? Skip the serialise round-trip — it can be ~1-3 KB
    // of JSON per cert × tens of thousands per second × three formats.
    if tx.receiver_count() == 0 {
        stats.certificates_processed.fetch_add(1, Ordering::Relaxed);
        return;
    }

    if let Some(serialized) = msg.pre_serialize(streams, retain_leaf) {
        // This is what serialization produced, not what went out on the wire.
        // A single domains-only subscriber still pays for `full` and `lite`
        // being serialized when those formats are enabled, and the gap between
        // this counter and `bytes_sent` is exactly that waste: measured at
        // 26.8 GB serialized against 555 MB actually sent over two hours with
        // one domains-only subscriber and all three formats enabled.
        let serialized_size =
            serialized.full.len() + serialized.lite.len() + serialized.domains_only.len();
        let _ = tx.send(serialized);
        stats.messages_sent.fetch_add(1, Ordering::Relaxed);
        stats.certificates_processed.fetch_add(1, Ordering::Relaxed);
        stats
            .bytes_serialized
            .fetch_add(serialized_size as u64, Ordering::Relaxed);
        metrics::counter!("certstream_bytes_serialized_total").increment(serialized_size as u64);
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
                verification: Default::default(),
                update_type: Cow::Borrowed("X509LogEntry"),
                leaf_cert: make_leaf(),
                chain: None,
                cert_index: 0,
                cert_link: String::new(),
                seen: 0.0,
                submission_timestamp: 0.0,
                source: Arc::new(Source {
                    log_id: None,
                    operator: Arc::from("Test"),
                    log_type: "rfc6962",
                    name: Arc::from("t"),
                    url: Arc::from("u"),
                }),
            },
        }
    }

    fn dummy_cached() -> CachedCert {
        let source = Arc::new(Source {
            log_id: None,
            operator: Arc::from("Test"),
            log_type: "rfc6962",
            name: Arc::from("t"),
            url: Arc::from("u"),
        });
        build_cached_cert(make_leaf(), 0.0, source, 0)
    }

    /// Regression for #13: with **no** subscribers, broadcast_cert must skip
    /// serialisation entirely. A long-lived placeholder receiver would pin
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
            dummy_cached(),
            &BroadcastTargets {
                tx: &tx,
                cache: &cache,
                stats: &stats,
                messages_counter: &counter,
                streams: &streams,
                retain_leaf: false,
            },
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
            dummy_cached(),
            &BroadcastTargets {
                tx: &tx,
                cache: &cache,
                stats: &stats,
                messages_counter: &counter,
                streams: &streams,
                retain_leaf: false,
            },
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

    fn adaptive(floor_ms: u64) -> OperatorLimiter {
        OperatorLimiter::adaptive(String::new(), std::time::Duration::from_millis(floor_ms), 1)
    }

    fn interval_ms(l: &OperatorLimiter) -> u64 {
        l.interval_us.load(Ordering::Relaxed) / 1000
    }

    #[test]
    fn a_429_slows_the_interval_by_a_quarter_once_per_window() {
        let l = adaptive(100);
        let t0 = tokio::time::Instant::now();
        assert_eq!(interval_ms(&l), 100);

        l.back_off_at(t0);
        assert_eq!(interval_ms(&l), 125);
        // Requests already in flight answer 429 too: one signal, not three.
        l.back_off_at(t0 + std::time::Duration::from_millis(200));
        l.back_off_at(t0 + std::time::Duration::from_millis(900));
        assert_eq!(interval_ms(&l), 125);

        l.back_off_at(t0 + std::time::Duration::from_secs(2));
        assert_eq!(interval_ms(&l), 156);
    }

    #[test]
    fn the_interval_stops_at_the_ceiling() {
        let l = adaptive(500);
        let mut t = tokio::time::Instant::now();
        for _ in 0..10 {
            l.back_off_at(t);
            t += std::time::Duration::from_secs(10);
        }
        assert_eq!(l.interval_us.load(Ordering::Relaxed), SLOWEST_INTERVAL.as_micros() as u64);
    }

    #[test]
    fn the_interval_comes_back_down_after_a_quiet_stretch_and_stops_at_the_floor() {
        let l = adaptive(100);
        let t0 = tokio::time::Instant::now();
        l.back_off_at(t0);
        l.back_off_at(t0 + std::time::Duration::from_secs(2));
        l.back_off_at(t0 + std::time::Duration::from_secs(4));
        assert_eq!(interval_ms(&l), 195);

        // Not quiet long enough yet.
        l.recover_at(t0 + std::time::Duration::from_secs(6));
        assert_eq!(interval_ms(&l), 195);

        // Quiet: a tenth faster each step, no more often than every step.
        let mut t = t0 + std::time::Duration::from_secs(10);
        l.recover_at(t);
        assert_eq!(interval_ms(&l), 175);
        l.recover_at(t + std::time::Duration::from_millis(500));
        assert_eq!(interval_ms(&l), 175, "a step is not repeated inside RECOVERY_STEP");

        for _ in 0..80 {
            t += RECOVERY_STEP;
            l.recover_at(t);
        }
        assert_eq!(interval_ms(&l), 100, "recovery must stop at the floor");
    }

    #[test]
    fn an_occasional_429_does_not_slow_the_interval_but_a_run_of_them_does() {
        let l = adaptive(100);
        for _ in 0..5 {
            for _ in 0..JUDGE_EVERY - 2 {
                l.observe(false);
            }
            l.observe(true);
            l.observe(false);
        }
        assert_eq!(interval_ms(&l), 100, "1 in 20 refused is normal");

        for _ in 0..JUDGE_EVERY {
            l.observe(true);
        }
        assert_eq!(interval_ms(&l), 125);
    }

    #[test]
    fn a_fixed_limiter_never_adapts() {
        let l = OperatorLimiter::with_burst(std::time::Duration::from_millis(200), 1);
        l.back_off_at(tokio::time::Instant::now());
        assert_eq!(interval_ms(&l), 200);
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
