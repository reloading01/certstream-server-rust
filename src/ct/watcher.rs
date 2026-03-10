use std::borrow::Cow;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tracing::{debug, error, info, warn};

use super::{broadcast_cert, build_cached_cert, parse_leaf_input, CtLog, WatcherContext};
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

/// Issue #9: AtomicU8 mirrors inner.circuit for a lock-free fast path in should_attempt().
/// The common case (Closed) reads one atomic without touching the Mutex at all.
const CIRCUIT_CLOSED: u8 = 0;
const CIRCUIT_OPEN: u8 = 1;
const CIRCUIT_HALF_OPEN: u8 = 2;

pub struct LogHealth {
    inner: parking_lot::Mutex<LogHealthInner>,
    /// Mirrors `inner.circuit`; written under the inner lock, read atomically.
    circuit_fast: AtomicU8,
}

impl LogHealth {
    const MIN_BACKOFF_MS: u64 = 1000;
    const MAX_BACKOFF_MS: u64 = 60000;
    const CIRCUIT_RESET_MS: u64 = 30000;
    pub const RATE_LIMIT_BACKOFF_MS: u64 = 30_000;

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

    /// Like [`record_rate_limit`], but uses the backoff duration provided by the server's
    /// `Retry-After` header instead of the hardcoded default. `backoff_ms` is the header
    /// value converted to milliseconds; falls back to `RATE_LIMIT_BACKOFF_MS` at the call
    /// site when the header is absent or unparseable.
    pub fn record_rate_limit_with_ms(&self, unhealthy_threshold: u32, backoff_ms: u64) {
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

    #[allow(dead_code)]
    pub fn circuit_state(&self) -> CircuitState {
        self.inner.lock().circuit
    }

    /// Issue #9: Lock-free fast path for the common Closed/HalfOpen case.
    /// Only acquires the Mutex when the circuit is Open (rare), to check the timeout
    /// and potentially transition to HalfOpen. The AtomicU8 is always kept in sync
    /// with `inner.circuit` under the lock.
    pub fn should_attempt(&self) -> bool {
        match self.circuit_fast.load(Ordering::Acquire) {
            CIRCUIT_CLOSED | CIRCUIT_HALF_OPEN => true,  // ← ~1ns, no lock
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
                    self.circuit_fast.store(CIRCUIT_HALF_OPEN, Ordering::Release);
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
        self.circuit_fast.store(CIRCUIT_HALF_OPEN, Ordering::Release);
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
        rate_limiter,
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
    let source = Arc::new(Source {
        name: Arc::from(log.description.as_str()),
        url: Arc::from(base_url.as_str()),
    });

    let health = Arc::new(LogHealth::new());
    let poll_interval = Duration::from_millis(config.poll_interval_ms);
    let timeout = Duration::from_secs(config.request_timeout_secs);

    // Issue #3: Pre-register metric counter handles — eliminates one String allocation
    // per certificate in the hot loop. The handle captures the label at startup time.
    let counter_messages = metrics::counter!("certstream_messages_sent", "log" => log_name.clone());
    let counter_parse_failures = metrics::counter!("certstream_parse_failures", "log" => log_name.clone());

    info!(log = %log_name, url = %base_url, "starting watcher");

    let mut current_index = if let Some(saved_index) = state_manager.get_index(&base_url) {
        info!(log = %log.description, saved_index = saved_index, "resuming from saved state");
        saved_index
    } else {
        let backoff = ExponentialBuilder::default()
            .with_min_delay(Duration::from_millis(config.retry_initial_delay_ms))
            .with_max_delay(Duration::from_millis(config.retry_max_delay_ms))
            .with_max_times(config.retry_max_attempts as usize);

        let url = format!("{}/ct/v1/get-sth", base_url);
        match (|| async {
            let response: SthResponse =
                client.get(&url).timeout(timeout).send().await?.json().await?;
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
                error!(log = %log.description, error = %e, "failed to get initial tree size after retries, exiting watcher");
                metrics::counter!("certstream_worker_init_failures").increment(1);
                return;
            }
        }
    };

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
            warn!(log = %log.description, errors = health.total_errors(), "log is unhealthy, waiting for recovery check");
            sleep(Duration::from_secs(config.health_check_interval_secs)).await;

            let url = format!("{}/ct/v1/get-sth", base_url);
            match client.get(&url).timeout(timeout).send().await {
                Ok(_) => {
                    health.record_success(config.healthy_threshold);
                    info!(log = %log.description, "health check passed, resuming");
                }
                Err(e) => {
                    health.record_failure(config.unhealthy_threshold);
                    warn!(log = %log.description, error = %e, "health check failed, staying disabled");
                    metrics::counter!("certstream_log_health_checks_failed").increment(1);
                    continue;
                }
            }
        }

        let sth_url = format!("{}/ct/v1/get-sth", base_url);
        let tree_size = match client.get(&sth_url).timeout(timeout).send().await {
            Ok(resp) => {
                if !resp.status().is_success() {
                    let status = resp.status();
                    if status.as_u16() == 429 {
                        health.record_rate_limit(config.unhealthy_threshold);
                        warn!(log = %log.description, "rate limited on get-sth, backing off");
                    } else {
                        health.record_failure(config.unhealthy_threshold);
                        warn!(log = %log.description, status = %status, "get-sth returned error");
                    }
                    sleep(health.get_backoff()).await;
                    continue;
                }
                match resp.json::<SthResponse>().await {
                    Ok(sth) => sth.tree_size,
                    Err(e) => {
                        health.record_failure(config.unhealthy_threshold);
                        warn!(log = %log.description, error = %e, "failed to parse tree size");
                        sleep(health.get_backoff()).await;
                        continue;
                    }
                }
            }
            Err(e) => {
                health.record_failure(config.unhealthy_threshold);
                warn!(log = %log.description, error = %e, "failed to get tree size");
                sleep(health.get_backoff()).await;
                continue;
            }
        };

        if current_index >= tree_size {
            sleep(poll_interval).await;
            continue;
        }

        let end = (current_index + config.batch_size).min(tree_size - 1);
        let entries_url = format!(
            "{}/ct/v1/get-entries?start={}&end={}",
            base_url, current_index, end
        );

        // Respect per-operator rate limit before making request
        if let Some(ref limiter) = rate_limiter {
            limiter.lock().await.tick().await;
        }

        match client.get(&entries_url).timeout(timeout).send().await {
            Ok(resp) => {
                if !resp.status().is_success() {
                    let status = resp.status();
                    if status.as_u16() == 429 {
                        health.record_rate_limit(config.unhealthy_threshold);
                        warn!(log = %log.description, "rate limited by CT log, backing off 30s");
                    } else if status.as_u16() == 400 {
                        // Entries not yet available — skip ahead to tree_size
                        debug!(log = %log.description, start = current_index, end = end,
                            "entries not available (400), skipping to tree head");
                        current_index = tree_size;
                        sleep(poll_interval).await;
                        continue;
                    } else {
                        health.record_failure(config.unhealthy_threshold);
                        warn!(log = %log.description, status = %status, "CT log returned error");
                    }
                    sleep(health.get_backoff()).await;
                    continue;
                }

                // Issue #14: simd-json for 2–4× faster deserialization of the entries
                // response — the largest JSON payload in the hot path. simd_json::from_slice
                // requires &mut [u8], so we collect bytes first then parse in-place.
                #[cfg(feature = "simd")]
                let parse_result: Result<EntriesResponse, String> = resp
                    .bytes()
                    .await
                    .map_err(|e| e.to_string())
                    .and_then(|b| {
                        let mut v = b.to_vec();
                        simd_json::from_slice::<EntriesResponse>(&mut v)
                            .map_err(|e| e.to_string())
                    });
                #[cfg(not(feature = "simd"))]
                let parse_result: Result<EntriesResponse, String> =
                    resp.json::<EntriesResponse>().await.map_err(|e| e.to_string());

                match parse_result {
                    Ok(entries_resp) => {
                        health.record_success(config.healthy_threshold);
                        let count = entries_resp.entries.len();

                        // M-2 fix: an empty response must not advance the index —
                        // that would permanently skip one entry per occurrence.
                        if count == 0 {
                            warn!(log = %log_name, "CT log returned empty entries response, retrying");
                            sleep(poll_interval).await;
                            continue;
                        }

                        let mut max_index_seen = current_index;

                        for (i, entry) in entries_resp.entries.into_iter().enumerate() {
                            let cert_index = current_index + i as u64;
                            max_index_seen = max_index_seen.max(cert_index);
                            let parsed =
                                match parse_leaf_input(&entry.leaf_input, &entry.extra_data) {
                                    Some(p) => p,
                                    None => {
                                        debug!(log = %log_name, index = cert_index, "skipped unparseable cert");
                                        counter_parse_failures.increment(1);
                                        continue;
                                    }
                                };

                            if !dedup.is_new(&parsed.leaf_cert.sha256_raw) {
                                continue;
                            }

                            let seen = chrono::Utc::now().timestamp_millis() as f64 / 1000.0;
                            // Issue #2: wrap in Arc once; share between CachedCert and CertificateData.
                            let leaf = Arc::new(parsed.leaf_cert);
                            let cached = build_cached_cert(
                                Arc::clone(&leaf),
                                seen,
                                &log.description,
                                &base_url,
                                cert_index,
                            );
                            let cert_link = format!(
                                "{}/ct/v1/get-entries?start={}&end={}",
                                base_url, cert_index, cert_index
                            );
                            let msg = CertificateMessage {
                                message_type: Cow::Borrowed("certificate_update"),
                                data: CertificateData {
                                    update_type: parsed.update_type,
                                    leaf_cert: leaf,
                                    chain: Some(parsed.chain),
                                    cert_index,
                                    cert_link,
                                    seen,
                                    source: Arc::clone(&source),
                                },
                            };
                            broadcast_cert(msg, &tx, &cache, cached, &stats, &counter_messages);
                        }

                        debug!(log = %log_name, count = count, "fetched entries");
                        current_index = max_index_seen + 1;
                        state_manager.update_index(&base_url, current_index, tree_size);

                        tracker.update(
                            &base_url,
                            health.status(),
                            current_index,
                            tree_size,
                            health.total_errors(),
                        );
                    }
                    Err(ref e) => {
                        health.record_failure(config.unhealthy_threshold);
                        warn!(log = %log.description, error = %e, "failed to parse entries");
                        sleep(health.get_backoff()).await;
                    }
                }
            }
            Err(e) => {
                health.record_failure(config.unhealthy_threshold);
                warn!(log = %log.description, error = %e, "failed to fetch entries");
                sleep(health.get_backoff()).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
