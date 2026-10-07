use std::borrow::Cow;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::{Duration, Instant};

use tracing::{debug, error, info};

use super::{
    CtLog, ParseOptions, WatcherContext, broadcast_cert, build_cached_cert,
    parse_leaf_input_with_options,
};
use crate::models::{CertificateData, CertificateMessage, Source};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HealthStatus {
    Healthy,
    Degraded,
    Unhealthy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitState {
    Closed,
    Open,
    HalfOpen,
}

/// All mutable circuit-breaker / health state under one lock, eliminating
/// the inconsistent multi-lock ordering that existed before.
#[derive(Debug, Clone, Copy)]
struct LogHealthInner {
    consecutive_failures: u32,
    consecutive_successes: u32,
    total_errors: u64,
    status: HealthStatus,
    circuit: CircuitState,
    circuit_opened_at: Option<Instant>,
    current_backoff_ms: u64,
}

/// Mirror of `inner.circuit`, kept in sync under the same lock. Lets the
/// common Closed case be read without touching the Mutex.
const CIRCUIT_CLOSED: u8 = 0;
const CIRCUIT_OPEN: u8 = 1;
const CIRCUIT_HALF_OPEN: u8 = 2;

/// Full responses in a row before the get-entries window is grown by a
/// quarter; growing rebuilds the pipeline, so it is not done on every response.
const GROW_AFTER_FULL: u32 = 16;

/// Follows what the server serves per get-entries call. A short response sets
/// the window to what was served; a run of full ones grows it. Returns whether
/// the pipeline must be rebuilt, because its prefetched windows were sized for
/// the old window.
fn adapt_window(
    window: &mut u64,
    full_streak: &mut u32,
    served: u64,
    requested: u64,
    max_window: u64,
    more_to_read: bool,
) -> bool {
    if served < requested {
        *full_streak = 0;
        if more_to_read {
            *window = served.max(1);
        }
        return true;
    }
    if *window < max_window {
        *full_streak += 1;
        if *full_streak >= GROW_AFTER_FULL {
            *full_streak = 0;
            *window = (*window + *window / 4 + 1).min(max_window);
            return true;
        }
    }
    false
}

/// Shortest page boundary worth learning; a shorter run of zero bits in the
/// index a response stopped at is as likely to be chance as a boundary.
const MIN_PAGE_BOUNDARY: u64 = 32;

/// Where a log cuts get-entries pages: Sectigo, DigiCert and Cloudflare at
/// multiples of 256, Google and TrustAsia of 32. A request that starts mid-page
/// gets the tail only, and following tails with `adapt_window` shrinks the window.
#[derive(Default, Clone, Copy)]
struct PageBoundary {
    /// Requests never cross a multiple of this; 0 until two cuts agree.
    unit: u64,
    /// Boundary suggested by the previous short response, not yet confirmed.
    candidate: u64,
}

impl PageBoundary {
    /// Whether a response was cut on a page boundary, which is no reason to
    /// shrink the window. The unit is the largest power of two dividing every cut.
    fn observe(
        &mut self,
        start: u64,
        served: u64,
        requested: u64,
        max_unit: u64,
        more_to_read: bool,
    ) -> bool {
        if served >= requested || !more_to_read {
            return false;
        }
        let cut = start + served;
        let unit = (cut & cut.wrapping_neg()).min(max_unit);
        if unit < MIN_PAGE_BOUNDARY {
            *self = Self::default();
            return false;
        }
        match (self.unit, self.candidate) {
            (0, 0) => self.candidate = unit,
            (0, candidate) => {
                self.unit = candidate.min(unit);
                self.candidate = 0;
            }
            (known, _) => self.unit = known.min(unit),
        }
        true
    }

    /// Last index of the request that starts at `start`.
    fn request_end(&self, start: u64, window: u64, last: u64) -> u64 {
        let end = (start + window - 1).min(last);
        match self.unit {
            0 => end,
            unit => end.min((start / unit + 1) * unit - 1),
        }
    }
}

pub struct LogHealth {
    inner: parking_lot::Mutex<LogHealthInner>,
    /// Mirrors `inner.circuit`; written under the inner lock, read atomically.
    circuit_fast: AtomicU8,
}

impl Default for LogHealth {
    fn default() -> Self {
        Self::new()
    }
}

impl LogHealth {
    const MIN_BACKOFF_MS: u64 = 1000;
    const MAX_BACKOFF_MS: u64 = 60000;
    const CIRCUIT_RESET_MS: u64 = 30000;
    pub const RATE_LIMIT_BACKOFF_MS: u64 = 5_000;

    pub fn new() -> Self {
        Self {
            inner: parking_lot::Mutex::new(LogHealthInner {
                consecutive_failures: 0,
                consecutive_successes: 0,
                total_errors: 0,
                status: HealthStatus::Healthy,
                circuit: CircuitState::Closed,
                circuit_opened_at: None,
                current_backoff_ms: Self::MIN_BACKOFF_MS,
            }),
            circuit_fast: AtomicU8::new(CIRCUIT_CLOSED),
        }
    }

    pub fn record_success(&self, healthy_threshold: u32) {
        let mut s = self.inner.lock();
        s.consecutive_failures = 0;
        s.current_backoff_ms = Self::MIN_BACKOFF_MS;
        s.consecutive_successes = s.consecutive_successes.saturating_add(1);

        if s.circuit == CircuitState::HalfOpen {
            s.circuit = CircuitState::Closed;
            s.circuit_opened_at = None;
            self.circuit_fast.store(CIRCUIT_CLOSED, Ordering::Release);
        }

        if s.consecutive_successes >= healthy_threshold {
            s.status = HealthStatus::Healthy;
        }
    }

    pub fn record_failure(&self, unhealthy_threshold: u32) {
        let mut s = self.inner.lock();
        s.consecutive_successes = 0;
        s.total_errors = s.total_errors.saturating_add(1);
        s.consecutive_failures = s.consecutive_failures.saturating_add(1);
        s.current_backoff_ms = (s.current_backoff_ms * 2).min(Self::MAX_BACKOFF_MS);

        // L-1 fix: integer division truncates 1/2=0; clamp to at least 1.
        let half_threshold = (unhealthy_threshold / 2).max(1);
        if s.consecutive_failures >= unhealthy_threshold {
            s.status = HealthStatus::Unhealthy;
            if s.circuit != CircuitState::Open {
                s.circuit = CircuitState::Open;
                s.circuit_opened_at = Some(Instant::now());
                self.circuit_fast.store(CIRCUIT_OPEN, Ordering::Release);
            }
        } else if s.consecutive_failures >= half_threshold {
            s.status = HealthStatus::Degraded;
        }
    }

    pub fn record_rate_limit(&self, unhealthy_threshold: u32) {
        let mut s = self.inner.lock();
        s.consecutive_successes = 0;
        s.total_errors = s.total_errors.saturating_add(1);
        s.consecutive_failures = s.consecutive_failures.saturating_add(1);
        s.current_backoff_ms = Self::RATE_LIMIT_BACKOFF_MS;

        let half_threshold = (unhealthy_threshold / 2).max(1);
        if s.consecutive_failures >= unhealthy_threshold {
            s.status = HealthStatus::Unhealthy;
            if s.circuit != CircuitState::Open {
                s.circuit = CircuitState::Open;
                s.circuit_opened_at = Some(Instant::now());
                self.circuit_fast.store(CIRCUIT_OPEN, Ordering::Release);
            }
        } else if s.consecutive_failures >= half_threshold {
            s.status = HealthStatus::Degraded;
        }
    }

    /// Record a 429/rate-limit using the backoff duration the server gave us in
    /// its `Retry-After` header (parsed + clamped by
    /// [`crate::ct::normalize::parse_retry_after`]). `backoff_ms` is already
    /// canonicalized; the caller passes `RATE_LIMIT_BACKOFF_MS` (5s) when the
    /// header is absent or unparseable.
    pub fn record_rate_limit_with_ms(&self, unhealthy_threshold: u32, backoff_ms: u64) {
        if backoff_ms == Self::RATE_LIMIT_BACKOFF_MS {
            self.record_rate_limit(unhealthy_threshold);
            return;
        }

        let mut s = self.inner.lock();
        s.consecutive_successes = 0;
        s.total_errors = s.total_errors.saturating_add(1);
        s.consecutive_failures = s.consecutive_failures.saturating_add(1);
        s.current_backoff_ms = backoff_ms;

        let half_threshold = (unhealthy_threshold / 2).max(1);
        if s.consecutive_failures >= unhealthy_threshold {
            s.status = HealthStatus::Unhealthy;
            if s.circuit != CircuitState::Open {
                s.circuit = CircuitState::Open;
                s.circuit_opened_at = Some(Instant::now());
                self.circuit_fast.store(CIRCUIT_OPEN, Ordering::Release);
            }
        } else if s.consecutive_failures >= half_threshold {
            s.status = HealthStatus::Degraded;
        }
    }

    pub fn is_healthy(&self) -> bool {
        self.inner.lock().status != HealthStatus::Unhealthy
    }

    pub fn total_errors(&self) -> u64 {
        self.inner.lock().total_errors
    }

    pub fn get_backoff(&self) -> Duration {
        Duration::from_millis(self.inner.lock().current_backoff_ms)
    }

    pub fn status(&self) -> HealthStatus {
        self.inner.lock().status
    }

    /// Test-only inspector. Production code observes circuit transitions via
    /// the `should_attempt()` fast path and the `LogHealth::status()` summary.
    #[cfg(test)]
    pub fn circuit_state(&self) -> CircuitState {
        self.inner.lock().circuit
    }

    /// Reads the mirrored state for the common Closed/HalfOpen case and takes
    /// the Mutex only when the circuit is Open, to check the timeout and
    /// possibly transition to HalfOpen.
    pub fn should_attempt(&self) -> bool {
        match self.circuit_fast.load(Ordering::Acquire) {
            CIRCUIT_CLOSED | CIRCUIT_HALF_OPEN => true, // ← ~1ns, no lock
            _ => {
                // Circuit is Open — check if reset timeout has elapsed.
                let mut s = self.inner.lock();
                // Re-check under lock; another thread may have already transitioned.
                if s.circuit != CircuitState::Open {
                    return true;
                }
                if let Some(opened_at) = s.circuit_opened_at
                    && opened_at.elapsed() > Duration::from_millis(Self::CIRCUIT_RESET_MS)
                {
                    s.circuit = CircuitState::HalfOpen;
                    self.circuit_fast
                        .store(CIRCUIT_HALF_OPEN, Ordering::Release);
                    return true;
                }
                false
            }
        }
    }

    /// Test-only helper to force the circuit into HalfOpen without waiting for
    /// the real CIRCUIT_RESET_MS timeout to elapse.
    #[cfg(test)]
    pub fn set_half_open_for_test(&self) {
        let mut s = self.inner.lock();
        s.circuit = CircuitState::HalfOpen;
        self.circuit_fast
            .store(CIRCUIT_HALF_OPEN, Ordering::Release);
    }
}

/// RFC 6962 CT log watcher — polls get-sth / get-entries in a loop.
#[allow(clippy::too_many_arguments)]
pub async fn run_watcher_with_cache(log: CtLog, ctx: WatcherContext) {
    let WatcherContext {
        client,
        tx,
        config,
        state_manager,
        cache,
        stats,
        tracker,
        shutdown,
        dedup,
        filters,
        nats,
        rate_limiter,
        streams,
        issuer_cache: _, // RFC6962 watcher doesn't use the issuer cache (no /issuer/ endpoint).
    } = ctx;
    use backon::{ExponentialBuilder, Retryable};
    use serde::Deserialize;
    use tokio::time::sleep;

    #[derive(Debug, Deserialize)]
    struct SthResponse {
        tree_size: u64,
    }

    #[derive(Debug, Deserialize)]
    struct EntriesResponse {
        entries: Vec<Entry>,
    }

    #[derive(Debug, Deserialize)]
    struct Entry {
        leaf_input: String,
        extra_data: String,
    }

    let base_url = log.normalized_url();
    let log_name = log.description.clone();
    let source_id = super::normalize::source_id(log.log_id.as_deref(), &base_url);
    let log_id_label = log.log_id.clone().unwrap_or_default();
    let nats_subject = nats.as_ref().map(|_| {
        format!(
            "certstream.{}.{}",
            crate::ct::static_ct::subject_token(&log.operator),
            crate::ct::static_ct::subject_token(&log.description)
        )
    });
    let log_id_for_msgs: Arc<str> = Arc::from(
        log.log_id
            .as_deref()
            .filter(|id| !id.is_empty())
            .unwrap_or(base_url.as_str()),
    );

    let source = Arc::new(Source {
        name: Arc::from(log.description.as_str()),
        url: Arc::from(base_url.as_str()),
        log_id: log.log_id.as_deref().map(Arc::from),
        operator: Arc::from(log.operator_name()),
        log_type: "rfc6962",
    });
    // RFC 6962 logs serve no checkpoint, so there is no checkpoint signature
    // to verify — that is a different answer from "we did not check".
    let verification = crate::models::Verification {
        checkpoint_signature: crate::models::VerificationState::NotApplicable,
        inclusion: crate::models::VerificationState::Unverified,
    };

    metrics::gauge!(
        "certstream_ct_runtime_log_info",
        "source_id" => source_id.clone(),
        "log_id" => log_id_label,
        "log" => log_name.clone(),
        "operator" => log.operator.clone(),
        "log_type" => "rfc6962"
    )
    .set(1.0);

    let health = Arc::new(LogHealth::new());
    let poll_interval = Duration::from_millis(config.poll_interval_ms);
    let mut unchanged_polls: u32 = 0;
    let timeout = Duration::from_secs(config.request_timeout_secs);
    let fetch_concurrency = config.fetch_concurrency.max(1) as usize;
    // Entries requested per get-entries call. Starts at the configured batch
    // size; follows the server's page size (see `adapt_window`).
    let mut effective_batch: u64 = config.batch_size.max(1);
    let mut full_streak: u32 = 0;
    let mut boundary = PageBoundary::default();

    // Per-watcher reusable JSON parse buffer. A fresh `to_vec()` per
    // get-entries response is a multi-hundred-KB allocation per poll; reusing
    // the buffer keeps the capacity stable after the first response and turns
    // the hottest transient
    // allocator (heap profile: ~16 MB across 30 watchers) into a one-time
    // amortised cost.
    #[cfg(feature = "simd")]
    let mut json_buf: Vec<u8> = Vec::new();
    // Cap on the capacity `json_buf` may keep between polls. Catch-up bursts
    // (256 entries × ~5-10 KB) still reuse the buffer within the drain loop;
    // anything larger is released afterwards instead of staying resident for
    // the life of the watcher (~35 watchers × up to ~3 MB was the single
    // biggest steady-state RSS contributor in the 1.5.3 memory audit).
    #[cfg(feature = "simd")]
    const JSON_BUF_RETAIN_MAX: usize = 512 * 1024;

    // Metric handles are registered once, with their labels, so the hot loop
    // does not allocate a label string per certificate.
    let counter_messages = metrics::counter!(
        "certstream_messages_sent",
        "log" => log_name.clone(),
        "source_id" => source_id.clone()
    );
    let counter_parse_failures = metrics::counter!(
        "certstream_parse_failures",
        "log" => log_name.clone(),
        "source_id" => source_id.clone()
    );

    // §1.5a: extension display strings are only consumed by the `full` and
    // `lite` streams; `domains_only` doesn't include them. When neither is
    // subscribed at the config level, skip the per-cert extension-string
    // work entirely (still populate all_domains for the DNS list).
    // `as_der` (base64 of the whole DER) is likewise only emitted by the
    // `full` stream — neither `lite`, `domains_only`, nor the REST cert
    // endpoint serve it.
    let parse_opts = ParseOptions {
        include_der: streams.full,
        parse_extensions: streams.full || streams.lite,
    };

    info!(log = %log_name, url = %base_url, "starting watcher");

    // Hoisted: the STH endpoint never changes; no need to re-format! it on
    // every poll / health check.
    let sth_url = format!("{}/ct/v1/get-sth", base_url);

    // Rollback guard, matching the static-CT watcher's. An RFC 6962 STH
    // tree_size is monotonically non-decreasing; a shrinking value means an
    // operator bug, an inconsistent replica, or a MITM. Re-seeded from
    // persisted state so the guard survives a restart.
    let mut high_water_tree_size: u64 = state_manager.get_tree_size(&base_url).unwrap_or(0);

    let mut current_index = if let Some(saved_index) = state_manager.get_index(&base_url) {
        info!(log = %log.description, saved_index = saved_index, "resuming from saved state");
        saved_index
    } else {
        let backoff = ExponentialBuilder::default()
            .with_min_delay(Duration::from_millis(config.retry_initial_delay_ms))
            .with_max_delay(Duration::from_millis(config.retry_max_delay_ms))
            .with_max_times(config.retry_max_attempts as usize);

        match (|| async {
            let response: SthResponse = client
                .get(&sth_url)
                .timeout(timeout)
                .send()
                .await?
                .json()
                .await?;
            Ok::<_, reqwest::Error>(response.tree_size)
        })
        .retry(backoff)
        .sleep(tokio::time::sleep)
        .await
        {
            Ok(size) => {
                let start = size.saturating_sub(1000);
                info!(log = %log.description, tree_size = size, starting_at = start, "starting fresh");
                start
            }
            // H-1 fix: do not silently start from 0 — let the supervisor restart us.
            Err(e) => {
                error!(log = %log.description, error = %e, "failed to get initial tree size after retries; the supervisor will start the watcher again");
                metrics::counter!("certstream_worker_init_failures").increment(1);
                return;
            }
        }
    };

    // The durable output's acknowledged position starts where this watcher
    // does, so the contiguous prefix has something to grow from.
    if let Some(sink) = &nats {
        sink.acks.resume_at(&base_url, current_index);
    }

    loop {
        if shutdown.is_cancelled() {
            info!(log = %log.description, "shutdown signal received");
            break;
        }

        if !health.should_attempt() {
            debug!(log = %log.description, "circuit breaker open, waiting");
            sleep(Duration::from_secs(config.health_check_interval_secs)).await;
            continue;
        }

        if !health.is_healthy() {
            // Upstream-transient state. Status is exposed via /health/deep and the
            // certstream_log_health_checks_failed counter; the per-iteration log
            // line only adds value to live debugging, so emit at debug.
            debug!(log = %log.description, errors = health.total_errors(), "log is unhealthy, waiting for recovery check");
            sleep(Duration::from_secs(config.health_check_interval_secs)).await;

            // The status has to be inspected, not just the transport result:
            // treating a 5xx or 429 as healthy sends the watcher straight back
            // into the get-entries loop, which fails again, and the log
            // oscillates between healthy and unhealthy without ever backing
            // off.
            match client.get(&sth_url).timeout(timeout).send().await {
                Ok(resp) if resp.status().is_success() => {
                    health.record_success(config.healthy_threshold);
                    info!(log = %log.description, "health check passed, resuming");
                }
                Ok(resp) => {
                    health.record_failure(config.unhealthy_threshold);
                    debug!(
                        log = %log.description,
                        status = %resp.status(),
                        "health check returned non-success, staying disabled"
                    );
                    metrics::counter!("certstream_log_health_checks_failed").increment(1);
                    continue;
                }
                Err(e) => {
                    health.record_failure(config.unhealthy_threshold);
                    debug!(log = %log.description, error = %e, "health check failed, staying disabled");
                    metrics::counter!("certstream_log_health_checks_failed").increment(1);
                    continue;
                }
            }
        }

        let tree_size = match client.get(&sth_url).timeout(timeout).send().await {
            Ok(resp) => {
                if !resp.status().is_success() {
                    let status = resp.status();
                    if status.as_u16() == 429 {
                        let retry_after_ms =
                            super::normalize::parse_retry_after(resp.headers(), &log.description);
                        health
                            .record_rate_limit_with_ms(config.unhealthy_threshold, retry_after_ms);
                        super::note_rate_limited(&rate_limiter);
                        metrics::counter!(
                            "certstream_ct_log_rate_limited_total",
                            "log" => log_name.clone(),
                            "source_id" => source_id.clone(),
                            "log_type" => "rfc6962"
                        )
                        .increment(1);
                        debug!(log = %log.description, retry_after_ms, "rate limited on get-sth, backing off");
                    } else {
                        health.record_failure(config.unhealthy_threshold);
                        debug!(log = %log.description, status = %status, "get-sth returned error");
                    }
                    sleep(health.get_backoff()).await;
                    continue;
                }
                match resp.json::<SthResponse>().await {
                    Ok(sth) => sth.tree_size,
                    Err(e) => {
                        health.record_failure(config.unhealthy_threshold);
                        debug!(log = %log.description, error = %e, "failed to parse tree size");
                        sleep(health.get_backoff()).await;
                        continue;
                    }
                }
            }
            Err(e) => {
                health.record_failure(config.unhealthy_threshold);
                debug!(log = %log.description, error = %e, "failed to get tree size");
                sleep(health.get_backoff()).await;
                continue;
            }
        };

        // RFC6962 rollback guard (parity with static_ct). Logged at debug —
        // some replicas flap between adjacent tree_size values, and the
        // certstream_rfc6962_tree_size_rollbacks metric already tracks each
        // occurrence for alerting.
        if tree_size < high_water_tree_size {
            debug!(
                log = %log.description,
                got = tree_size,
                high_water = high_water_tree_size,
                "tree_size went backwards; refusing to advance"
            );
            metrics::counter!(
                "certstream_rfc6962_tree_size_rollbacks",
                "log" => log_name.clone(),
                "source_id" => source_id.clone()
            )
            .increment(1);
            health.record_failure(config.unhealthy_threshold);
            sleep(health.get_backoff()).await;
            continue;
        }
        high_water_tree_size = tree_size;
        let head_polled = std::time::Instant::now();

        if current_index >= tree_size {
            // Caught up — idle point. If the last catch-up left a burst-sized
            // parse buffer behind, hand it back to the allocator now: within
            // the drain loop the capacity is reused batch-to-batch, but there
            // is no reason to keep multi-MB capacity resident while idle
            // (memory audit: ~35 watchers × up to ~3 MB retained forever was
            // the single biggest steady-state RSS contributor).
            #[cfg(feature = "simd")]
            if json_buf.capacity() > JSON_BUF_RETAIN_MAX {
                json_buf = Vec::new();
            }
            sleep(super::idle_poll_delay(poll_interval, unchanged_polls)).await;
            unchanged_polls = unchanged_polls.saturating_add(1);
            continue;
        }
        unchanged_polls = 0;

        // Drain every batch available under this STH before re-polling
        // get-sth — mirrors the static-CT tile loop. Fetches are pipelined
        // `fetch_concurrency`-deep (each still pays a token to the
        // per-operator bucket, so the sustained request rate is unchanged);
        // responses are processed strictly in order.
        'drain: while current_index < tree_size && !shutdown.is_cancelled() {
            use futures::StreamExt as _;

            // Defensive: tree_size > current_index ≥ 0 here, so tree_size ≥ 1 and
            // `tree_size - 1` never underflows. Use saturating_sub anyway so any
            // future regression saturates at 0 instead of wrapping to u64::MAX.
            let end_inclusive = tree_size.saturating_sub(1);
            let window = effective_batch.max(1);
            let drain_start = current_index;

            // Window starts are precomputed assuming full responses. If the
            // server returns fewer entries than requested (spec-legal — many
            // logs clamp), the remaining prefetched windows are misaligned;
            // the processing loop detects that, shrinks `effective_batch` to
            // what the server actually serves, and rebuilds the pipeline from
            // the true index.
            let page = boundary;
            let mut in_flight = futures::stream::iter(
                std::iter::successors(Some(drain_start), move |s| {
                    Some(page.request_end(*s, window, end_inclusive) + 1)
                })
                .take_while(move |s| *s <= end_inclusive)
                .map(move |s| (s, page.request_end(s, window, end_inclusive))),
            )
            .map(|(start, end)| {
                let client = client.clone();
                let limiter = rate_limiter.clone();
                let desc = log.description.clone();
                let url = format!("{}/ct/v1/get-entries?start={}&end={}", base_url, start, end);
                async move {
                    // Respect per-operator rate limit before making request
                    if let Some(ref l) = limiter {
                        l.tick().await;
                    }
                    let outcome = match client.get(&url).timeout(timeout).send().await {
                        Ok(resp) => {
                            let status = resp.status();
                            if status.is_success() {
                                match resp.bytes().await {
                                    Ok(b) => super::FetchOutcome::Body(b),
                                    Err(e) => super::FetchOutcome::Net(e.to_string()),
                                }
                            } else {
                                let retry_after_ms = (status.as_u16() == 429).then(|| {
                                    super::normalize::parse_retry_after(resp.headers(), &desc)
                                });
                                super::FetchOutcome::Http(status, retry_after_ms)
                            }
                        }
                        Err(e) => super::FetchOutcome::Net(e.to_string()),
                    };
                    (start, end, outcome)
                }
            })
            .buffered(fetch_concurrency);

            while let Some((batch_start, end, outcome)) = in_flight.next().await {
                if shutdown.is_cancelled() {
                    break 'drain;
                }
                // Windows are aligned as long as every prior response was
                // full; partial responses break out below before this runs.
                debug_assert_eq!(batch_start, current_index);

                let body = match outcome {
                    super::FetchOutcome::Body(b) => {
                        super::note_success(&rate_limiter);
                        b
                    }
                    super::FetchOutcome::Http(status, retry_after) => {
                        if let Some(retry_after_ms) = retry_after {
                            health.record_rate_limit_with_ms(
                                config.unhealthy_threshold,
                                retry_after_ms,
                            );
                            super::note_rate_limited(&rate_limiter);
                            metrics::counter!(
                                "certstream_ct_log_rate_limited_total",
                                "log" => log_name.clone(),
                                "source_id" => source_id.clone(),
                                "log_type" => "rfc6962"
                            )
                            .increment(1);
                            debug!(log = %log.description, retry_after_ms, "rate limited by CT log, backing off");
                        } else if status.as_u16() == 400 {
                            // Entries not yet available — skip ahead to tree_size
                            debug!(log = %log.description, start = batch_start, end = end,
                                "entries not available (400), skipping to tree head");
                            current_index = tree_size;
                            sleep(poll_interval).await;
                            break 'drain;
                        } else {
                            health.record_failure(config.unhealthy_threshold);
                            debug!(log = %log.description, status = %status, "CT log returned error");
                        }
                        sleep(health.get_backoff()).await;
                        break 'drain;
                    }
                    super::FetchOutcome::Net(e) => {
                        health.record_failure(config.unhealthy_threshold);
                        debug!(log = %log.description, error = %e, "failed to fetch entries");
                        sleep(health.get_backoff()).await;
                        break 'drain;
                    }
                };

                // simd-json for the entries response, the largest JSON payload
                // in the hot path. `simd_json::from_slice` requires `&mut [u8]`
                // (it rewrites the buffer in place for string escaping),
                // so we copy into the per-watcher reusable Vec (processing is
                // sequential even though fetching is pipelined, so one buffer
                // still suffices).
                #[cfg(feature = "simd")]
                let parse_result: Result<EntriesResponse, String> = {
                    json_buf.clear();
                    json_buf.extend_from_slice(&body);
                    simd_json::from_slice::<EntriesResponse>(&mut json_buf)
                        .map_err(|e| e.to_string())
                };
                #[cfg(not(feature = "simd"))]
                let parse_result: Result<EntriesResponse, String> =
                    serde_json::from_slice::<EntriesResponse>(&body).map_err(|e| e.to_string());

                match parse_result {
                    Ok(entries_resp) => {
                        health.record_success(config.healthy_threshold);
                        let count = entries_resp.entries.len();

                        // M-2 fix: an empty response must not advance the index —
                        // that would permanently skip one entry per occurrence.
                        if count == 0 {
                            // Empty response means the log has no new entries past current_index.
                            // Expected steady-state when a log is caught up; logged at debug to
                            // avoid drowning the warn channel during normal idle polling.
                            metrics::counter!(
                                "certstream_ct_log_empty_responses_total",
                                "log" => log_name.clone(),
                                "source_id" => source_id.clone(),
                                "log_type" => "rfc6962"
                            )
                            .increment(1);
                            debug!(log = %log_name, "CT log returned empty entries response, retrying");
                            sleep(poll_interval).await;
                            break 'drain;
                        }

                        // Base64 decode + X.509 parse + hashing for a whole
                        // batch is pure CPU with no yield points. Run it on the
                        // blocking pool so simultaneous catch-up across many
                        // watchers can't starve the small async runtime; one
                        // spawn_blocking hop amortised over up to `batch_size`
                        // certs.
                        let entries = entries_resp.entries;
                        let job_dedup = Arc::clone(&dedup);
                        let job_tx = tx.clone();
                        let job_cache = Arc::clone(&cache);
                        let job_stats = Arc::clone(&stats);
                        let job_streams = Arc::clone(&streams);
                        let job_retain_leaf = filters.active();
                        let job_durable = nats.is_some();
                        let job_nats_subject = nats_subject.clone().unwrap_or_default();
                        let job_log_url: Arc<str> = Arc::from(base_url.as_str());
                        let job_log_key = log_id_for_msgs.clone();
                        let job_verification = verification;
                        let job_source = Arc::clone(&source);
                        let job_counter_messages = counter_messages.clone();
                        let job_counter_parse_failures = counter_parse_failures.clone();
                        let job_log_name = log_name.clone();
                        let job_base_url = base_url.clone();
                        let job_state_manager = Arc::clone(&state_manager);
                        let job_tracker = Arc::clone(&tracker);
                        let job_health = Arc::clone(&health);
                        let full_stream_enabled = streams.full;
                        let join = tokio::task::spawn_blocking(move || {
                            let mut max_index_seen = batch_start;
                            let mut newest_submission = 0.0f64;
                            let mut durable: Vec<crate::nats::Record> = Vec::new();
                            let mut skipped: Vec<u64> = Vec::new();
                            let targets = crate::ct::BroadcastTargets {
                                tx: &job_tx,
                                cache: &job_cache,
                                stats: &job_stats,
                                messages_counter: &job_counter_messages,
                                streams: &job_streams,
                                retain_leaf: job_retain_leaf,
                            };
                            for (i, entry) in entries.into_iter().enumerate() {
                                let cert_index = batch_start + i as u64;
                                max_index_seen = max_index_seen.max(cert_index);
                                let parsed = match parse_leaf_input_with_options(
                                    &entry.leaf_input,
                                    &entry.extra_data,
                                    parse_opts,
                                ) {
                                    Some(p) => p,
                                    None => {
                                        debug!(log = %job_log_name, index = cert_index, "skipped unparseable cert");
                                        job_counter_parse_failures.increment(1);
                                        // Nothing will ever be published for
                                        // this index, so settle it or the
                                        // durable position stops here.
                                        skipped.push(cert_index);
                                        continue;
                                    }
                                };

                                let is_new = job_dedup.is_new(&parsed.leaf_cert.sha256_raw);
                                if !is_new && !job_durable {
                                    continue;
                                }

                                // Deferred chain parsing: only for entries that
                                // reach a subscriber, and only when the `full`
                                // stream — the sole consumer of `chain` — is
                                // enabled.
                                let chain =
                                    (is_new && full_stream_enabled).then(|| parsed.parse_chain());

                                let seen = chrono::Utc::now().timestamp_millis() as f64 / 1000.0;
                                newest_submission =
                                    newest_submission.max(parsed.submission_timestamp);
                                // Wrapped once and shared with the cache entry.
                                let leaf = Arc::new(parsed.leaf_cert);
                                let cached = build_cached_cert(
                                    Arc::clone(&leaf),
                                    seen,
                                    Arc::clone(&job_source),
                                    cert_index,
                                );
                                let cert_link = format!(
                                    "{}/ct/v1/get-entries?start={}&end={}",
                                    job_base_url, cert_index, cert_index
                                );
                                let msg = CertificateMessage {
                                    message_type: Cow::Borrowed("certificate_update"),
                                    data: CertificateData {
                                        update_type: parsed.update_type,
                                        leaf_cert: leaf,
                                        chain,
                                        cert_index,
                                        cert_link,
                                        seen,
                                        submission_timestamp: parsed.submission_timestamp,
                                        source: Arc::clone(&job_source),
                                        verification: job_verification,
                                    },
                                };
                                // Published before the live dedup is applied.
                                // Dedup collapses one certificate seen in
                                // several logs, but a durable record is
                                // addressed by (log_id, index) — each log's
                                // entry is a distinct record, and dropping the
                                // second one would leave a permanent hole in
                                // that log's position. JetStream deduplicates
                                // identical republishes by message id.
                                if job_durable {
                                    match msg.to_v2_json() {
                                        Ok(json) => durable.push(crate::nats::Record {
                                            log_url: Arc::clone(&job_log_url),
                                            msg_id: format!("{job_log_key}:{cert_index}"),
                                            index: cert_index,
                                            subject: job_nats_subject.clone(),
                                            payload: bytes::Bytes::from(json),
                                        }),
                                        Err(_) => skipped.push(cert_index),
                                    }
                                }

                                if is_new {
                                    broadcast_cert(msg, cached, &targets);
                                }
                            }

                            // Checkpoint INSIDE the job: if the supervisor's
                            // select! drops the watcher future at the
                            // `join.await` below (shutdown), the detached
                            // blocking task still runs to completion — the
                            // broadcasts above and this index persist stay
                            // atomic, so a restart doesn't replay the batch.
                            crate::ct::record_ingest_delay(
                                &job_log_name,
                                newest_submission,
                                chrono::Utc::now().timestamp_millis() as f64 / 1000.0,
                            );

                            let next_index = max_index_seen + 1;
                            job_state_manager.update_index(&job_base_url, next_index, tree_size);
                            job_tracker.update(
                                &job_base_url,
                                job_health.status(),
                                next_index,
                                tree_size,
                                job_health.total_errors(),
                            );
                            (max_index_seen, durable, skipped)
                        });
                        let (max_index_seen, durable, skipped) = match join.await {
                            Ok(v) => v,
                            // Re-raise worker panics so the supervisor's
                            // catch_unwind recovery path in main.rs still fires.
                            Err(e) if e.is_panic() => std::panic::resume_unwind(e.into_panic()),
                            // Cancelled (runtime shutdown) — bail out quietly.
                            Err(_) => break 'drain,
                        };

                        // Queued after the broadcast, awaited before the next
                        // window: under `on_full: block` this is where ingest
                        // slows to match durable storage.
                        if let Some(sink) = &nats {
                            let log_key: Arc<str> = Arc::from(base_url.as_str());
                            for index in skipped {
                                sink.acks.record_skipped(&log_key, index);
                            }
                            for record in durable {
                                sink.publish(record).await;
                            }
                        }

                        debug!(log = %log_name, count = count, "fetched entries");
                        current_index = max_index_seen + 1;

                        let requested = end - batch_start + 1;
                        let served = count as u64;
                        let before = effective_batch;
                        if boundary.observe(
                            batch_start,
                            served,
                            requested,
                            config.batch_size,
                            current_index < tree_size,
                        ) {
                            effective_batch = config.batch_size.max(1);
                            full_streak = 0;
                            break;
                        }
                        if adapt_window(
                            &mut effective_batch,
                            &mut full_streak,
                            served,
                            requested,
                            config.batch_size,
                            current_index < tree_size,
                        ) {
                            if served < requested && effective_batch != before {
                                debug!(
                                    log = %log_name,
                                    served,
                                    requested,
                                    "short get-entries response; realigning fetch window"
                                );
                            }
                            break;
                        }
                        if head_polled.elapsed() >= super::HEAD_REFRESH_EVERY {
                            break 'drain;
                        }
                    }
                    Err(ref e) => {
                        health.record_failure(config.unhealthy_threshold);
                        debug!(log = %log.description, error = %e, "failed to parse entries");
                        sleep(health.get_backoff()).await;
                        break 'drain;
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn window_follows_a_short_response_and_rebuilds() {
        let (mut window, mut streak) = (1024, 5);
        assert!(adapt_window(&mut window, &mut streak, 160, 1024, 1024, true));
        assert_eq!((window, streak), (160, 0));
    }

    #[test]
    fn window_is_kept_when_a_short_response_ends_the_log() {
        let (mut window, mut streak) = (160, 0);
        assert!(adapt_window(&mut window, &mut streak, 40, 160, 1024, false));
        assert_eq!(window, 160);
    }

    #[test]
    fn window_grows_after_a_run_of_full_responses() {
        let (mut window, mut streak) = (4, 0);
        for _ in 0..GROW_AFTER_FULL - 1 {
            assert!(!adapt_window(&mut window, &mut streak, 4, 4, 1024, true));
        }
        assert!(adapt_window(&mut window, &mut streak, 4, 4, 1024, true));
        assert_eq!((window, streak), (6, 0));
    }

    #[test]
    fn window_recovers_from_a_tiny_page_up_to_the_configured_size() {
        let (mut window, mut streak) = (4, 0);
        let mut rebuilds = 0;
        while window < 1024 {
            let asked = window;
            if adapt_window(&mut window, &mut streak, asked, asked, 1024, true) {
                rebuilds += 1;
            }
        }
        assert_eq!(window, 1024);
        assert!(rebuilds < 40, "{rebuilds} rebuilds");
        assert!(!adapt_window(&mut window, &mut streak, 1024, 1024, 1024, true));
    }

    /// Reads `from..to` the way the drain loop does, one request at a time,
    /// against a server whose page for a request is `serve(start, requested)`.
    fn read_all(serve: impl Fn(u64, u64) -> u64, from: u64, to: u64) -> (u64, PageBoundary) {
        let (mut window, mut streak, mut boundary) = (1024, 0, PageBoundary::default());
        let (mut index, mut requests) = (from, 0);
        while index < to {
            let end = boundary.request_end(index, window, to - 1);
            let requested = end - index + 1;
            let served = serve(index, requested);
            let more = index + served < to;
            if boundary.observe(index, served, requested, 1024, more) {
                (window, streak) = (1024, 0);
            } else {
                adapt_window(&mut window, &mut streak, served, requested, 1024, more);
            }
            index += served;
            requests += 1;
        }
        (requests, boundary)
    }

    fn paged_at(unit: u64) -> impl Fn(u64, u64) -> u64 {
        move |start, requested| requested.min(unit - start % unit)
    }

    #[test]
    fn a_256_page_log_is_read_a_page_per_request_from_any_start() {
        for from in [0, 64, 137, 255, 328_950_000] {
            let (requests, boundary) = read_all(paged_at(256), from, from + 100_000);
            assert_eq!(boundary.unit, 256);
            assert!(requests <= 100_000 / 256 + 4, "{requests} requests from {from}");
        }
    }

    #[test]
    fn a_32_page_log_is_read_a_page_per_request() {
        let (requests, boundary) = read_all(paged_at(32), 436_900_100, 436_900_100 + 50_000);
        assert_eq!(boundary.unit, 32);
        assert!(requests <= 50_000 / 32 + 4, "{requests} requests");
    }

    #[test]
    fn a_log_with_unaligned_pages_keeps_following_the_window() {
        let capped = |_, requested: u64| requested.min(15);
        let (requests, boundary) = read_all(capped, 1_000_003, 1_000_003 + 30_000);
        assert_eq!(boundary.unit, 0);
        assert!(requests < 30_000 / 15 + 100, "{requests} requests");
    }

    #[test]
    fn a_short_response_that_ends_the_log_teaches_nothing() {
        let mut boundary = PageBoundary::default();
        assert!(!boundary.observe(0, 64, 1024, 1024, false));
        assert_eq!((boundary.unit, boundary.candidate), (0, 0));
    }

    #[test]
    fn a_cut_off_the_boundary_forgets_what_was_learned() {
        let mut boundary = PageBoundary::default();
        assert!(boundary.observe(0, 256, 1024, 1024, true));
        assert!(boundary.observe(256, 256, 1024, 1024, true));
        assert_eq!(boundary.unit, 256);
        assert!(!boundary.observe(512, 15, 256, 1024, true));
        assert_eq!((boundary.unit, boundary.candidate), (0, 0));
    }

    #[test]
    fn requests_stop_at_the_boundary_and_at_the_head() {
        let page = PageBoundary { unit: 256, candidate: 0 };
        assert_eq!(page.request_end(240, 1024, 10_000), 255);
        assert_eq!(page.request_end(256, 1024, 10_000), 511);
        assert_eq!(page.request_end(256, 100, 10_000), 355);
        assert_eq!(page.request_end(256, 1024, 300), 300);
        assert_eq!(PageBoundary::default().request_end(240, 1024, 10_000), 1263);
    }

    #[test]
    fn test_log_health_initial_state() {
        let health = LogHealth::new();
        assert!(health.is_healthy());
        assert_eq!(health.total_errors(), 0);
        assert_eq!(health.circuit_state(), CircuitState::Closed);
        assert!(health.should_attempt());
    }

    #[test]
    fn test_record_success_resets_failures() {
        let health = LogHealth::new();
        health.record_failure(5);
        health.record_failure(5);
        assert_eq!(health.total_errors(), 2);

        health.record_success(2);
        assert_eq!(health.total_errors(), 2);
        assert!(health.is_healthy());
    }

    #[test]
    fn test_record_failure_transitions_to_degraded() {
        let health = LogHealth::new();
        health.record_failure(6);
        health.record_failure(6);
        assert_eq!(health.status(), HealthStatus::Healthy);

        health.record_failure(6); // 3rd failure = degraded (6/2 = 3)
        assert_eq!(health.status(), HealthStatus::Degraded);
    }

    #[test]
    fn test_record_failure_transitions_to_unhealthy() {
        let health = LogHealth::new();
        for _ in 0..5 {
            health.record_failure(5);
        }
        assert_eq!(health.status(), HealthStatus::Unhealthy);
        assert!(!health.is_healthy());
    }

    #[test]
    fn test_circuit_opens_on_unhealthy() {
        let health = LogHealth::new();
        for _ in 0..5 {
            health.record_failure(5);
        }
        assert_eq!(health.circuit_state(), CircuitState::Open);
        assert!(!health.should_attempt());
    }

    #[test]
    fn test_success_recovers_from_degraded() {
        let health = LogHealth::new();
        for _ in 0..3 {
            health.record_failure(6);
        }
        assert_eq!(health.status(), HealthStatus::Degraded);

        health.record_success(2);
        health.record_success(2);
        assert_eq!(health.status(), HealthStatus::Healthy);
    }

    #[test]
    fn test_backoff_increases_exponentially() {
        let health = LogHealth::new();
        assert_eq!(health.get_backoff(), Duration::from_millis(1000));

        health.record_failure(100);
        assert_eq!(health.get_backoff(), Duration::from_millis(2000));

        health.record_failure(100);
        assert_eq!(health.get_backoff(), Duration::from_millis(4000));

        health.record_failure(100);
        assert_eq!(health.get_backoff(), Duration::from_millis(8000));
    }

    #[test]
    fn test_backoff_caps_at_max() {
        let health = LogHealth::new();
        for _ in 0..20 {
            health.record_failure(100);
        }
        assert_eq!(health.get_backoff(), Duration::from_millis(60000));
    }

    #[test]
    fn test_success_resets_backoff() {
        let health = LogHealth::new();
        health.record_failure(100);
        health.record_failure(100);
        assert!(health.get_backoff() > Duration::from_millis(1000));

        health.record_success(1);
        assert_eq!(health.get_backoff(), Duration::from_millis(1000));
    }

    #[test]
    fn test_half_open_recovers_on_success() {
        let health = LogHealth::new();
        for _ in 0..5 {
            health.record_failure(5);
        }
        assert_eq!(health.circuit_state(), CircuitState::Open);

        // M-6 fix: use the test helper instead of directly writing the internal lock
        health.set_half_open_for_test();
        assert!(health.should_attempt());

        health.record_success(1);
        assert_eq!(health.circuit_state(), CircuitState::Closed);
    }

    #[test]
    fn test_total_errors_accumulate() {
        let health = LogHealth::new();
        health.record_failure(100);
        health.record_success(1);
        health.record_failure(100);
        health.record_failure(100);
        assert_eq!(health.total_errors(), 3);
    }

    #[test]
    fn test_unhealthy_threshold_1_degraded_at_1() {
        // L-1 fix: threshold=1 -> half=max(0,1)=1, so first failure → Degraded,
        // not immediately at 0 (which would fire even before any failure).
        let health = LogHealth::new();
        health.record_failure(1); // threshold=1: unhealthy immediately (failures>=1)
        // With threshold=1, the first failure should be Unhealthy (>=1), not just Degraded
        assert_eq!(health.status(), HealthStatus::Unhealthy);
    }
}
