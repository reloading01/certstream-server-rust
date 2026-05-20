use dashmap::DashMap;
use parking_lot::Mutex;
use std::collections::VecDeque;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::config::RateLimitConfig;
use crate::hot_reload::HotReloadManager;

pub struct TokenBucket {
    tokens: f64,
    max_tokens: f64,
    refill_rate: f64,
    last_refill: Instant,
}

impl TokenBucket {
    fn new(max_tokens: f64, refill_rate: f64) -> Self {
        Self {
            tokens: max_tokens,
            max_tokens,
            refill_rate,
            last_refill: Instant::now(),
        }
    }

    fn try_consume(&mut self, tokens: f64) -> bool {
        self.refill();
        if self.tokens >= tokens {
            self.tokens -= tokens;
            true
        } else {
            false
        }
    }

    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.refill_rate).min(self.max_tokens);
        self.last_refill = now;
    }

    fn update_limits(&mut self, max_tokens: f64, refill_rate: f64) {
        self.max_tokens = max_tokens;
        self.refill_rate = refill_rate;
        self.tokens = self.tokens.min(max_tokens);
    }
}

/// L-5 fix: VecDeque allows O(1) amortised expiry of old timestamps from the
/// front rather than the O(n) shift-left that Vec::retain caused.
pub struct SlidingWindow {
    window_size: Duration,
    max_requests: u32,
    timestamps: VecDeque<Instant>,
}

impl SlidingWindow {
    fn new(window_size: Duration, max_requests: u32) -> Self {
        Self {
            window_size,
            max_requests,
            timestamps: VecDeque::with_capacity(max_requests as usize),
        }
    }

    fn try_acquire(&mut self) -> bool {
        let now = Instant::now();
        let cutoff = now - self.window_size;
        // Pop expired timestamps from the front (they are always in insertion order).
        while self.timestamps.front().is_some_and(|&t| t <= cutoff) {
            self.timestamps.pop_front();
        }
        if self.timestamps.len() < self.max_requests as usize {
            self.timestamps.push_back(now);
            true
        } else {
            false
        }
    }

    fn update_limits(&mut self, window_size: Duration, max_requests: u32) {
        self.window_size = window_size;
        self.max_requests = max_requests;
    }
}

struct ClientRateLimit {
    token_bucket: TokenBucket,
    sliding_window: SlidingWindow,
    burst_used: f64,
    burst_reset: Instant,
}

pub struct RateLimiter {
    hot_reload: Option<Arc<HotReloadManager>>,
    fallback_config: RateLimitConfig,
    /// H-2 fix: store Arc<Mutex<…>> so we can drop the DashMap shard lock
    /// before acquiring the inner mutex, eliminating shard-wide serialization.
    clients: DashMap<IpAddr, Arc<Mutex<ClientRateLimit>>>,
}

impl RateLimiter {
    pub fn new(
        config: RateLimitConfig,
        hot_reload: Option<Arc<HotReloadManager>>,
    ) -> Arc<Self> {
        Arc::new(Self {
            hot_reload,
            fallback_config: config,
            clients: DashMap::new(),
        })
    }

    fn get_config(&self) -> RateLimitConfig {
        self.hot_reload
            .as_ref()
            .map(|hr| hr.get().rate_limit.clone())
            .unwrap_or_else(|| self.fallback_config.clone())
    }

    /// Check whether `ip` may make another request right now. Single-tier:
    /// the limit applies to every IP equally, authenticated or not.
    pub fn check(&self, ip: IpAddr) -> RateLimitResult {
        let config = self.get_config();

        if !config.enabled {
            return RateLimitResult::Allowed;
        }

        // H-2 fix: extract the Arc<Mutex<…>>, then immediately drop the DashMap
        // RefMut (which held the shard write lock).  Only the inner Mutex is held
        // during the actual rate-limit computation, allowing other IPs in the same
        // shard to be checked concurrently.
        let client_mutex = {
            let entry = self.clients.entry(ip).or_insert_with(|| {
                Arc::new(Mutex::new(ClientRateLimit {
                    token_bucket: TokenBucket::new(config.max_tokens, config.refill_rate),
                    sliding_window: SlidingWindow::new(
                        Duration::from_secs(config.window_seconds),
                        config.window_max_requests,
                    ),
                    burst_used: 0.0,
                    burst_reset: Instant::now() + Duration::from_secs(config.burst_window_seconds),
                }))
            });
            Arc::clone(&*entry)
        }; // DashMap shard write lock released here

        let mut client = client_mutex.lock();
        client
            .token_bucket
            .update_limits(config.max_tokens, config.refill_rate);
        client.sliding_window.update_limits(
            Duration::from_secs(config.window_seconds),
            config.window_max_requests,
        );

        if !client.sliding_window.try_acquire() {
            metrics::counter!("certstream_rate_limit_rejected", "reason" => "sliding_window")
                .increment(1);
            return RateLimitResult::Rejected {
                retry_after_ms: config.window_seconds * 1000 / 2,
            };
        }

        if client.token_bucket.try_consume(1.0) {
            return RateLimitResult::Allowed;
        }

        let now = Instant::now();
        if now >= client.burst_reset {
            client.burst_used = 0.0;
            client.burst_reset = now + Duration::from_secs(config.burst_window_seconds);
        }

        if client.burst_used < config.burst {
            client.burst_used += 1.0;
            metrics::counter!("certstream_rate_limit_burst_used").increment(1);
            return RateLimitResult::Allowed;
        }

        metrics::counter!("certstream_rate_limit_rejected", "reason" => "token_bucket").increment(1);
        RateLimitResult::Rejected {
            retry_after_ms: (1000.0 / config.refill_rate.max(1.0)) as u64,
        }
    }

    pub fn cleanup_stale(&self, max_age: Duration) {
        // P1 fix: pre-1.5.0 ran a `retain` closure that took `v.lock()` while
        // holding the shard write lock. Request-path access from another IP
        // in the same shard had to wait for the shard write lock, even
        // though only one stale entry's inner mutex was being inspected.
        //
        // New approach: snapshot candidate keys with a quick shard READ
        // (only checks `last_refill` under inner lock, then releases), then
        // remove them one-by-one. Each remove takes the shard write lock
        // briefly, no nested inner-mutex hold.
        let cutoff = Instant::now() - max_age;
        let to_remove: Vec<IpAddr> = self
            .clients
            .iter()
            .filter_map(|entry| {
                let client = entry.value().lock();
                if client.token_bucket.last_refill <= cutoff {
                    Some(*entry.key())
                } else {
                    None
                }
            })
            .collect();
        for ip in to_remove {
            // Double-check under removal: another caller may have refreshed
            // the bucket between snapshot and removal.
            self.clients.remove_if(&ip, |_, v| {
                let c = v.lock();
                c.token_bucket.last_refill <= cutoff
            });
        }
    }
}

#[derive(Debug, Clone)]
pub enum RateLimitResult {
    Allowed,
    Rejected { retry_after_ms: u64 },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RateLimitConfig;
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;

    fn test_config(enabled: bool) -> RateLimitConfig {
        RateLimitConfig {
            enabled,
            window_seconds: 60,
            window_max_requests: 100,
            burst_window_seconds: 10,
            max_tokens: 5.0,
            refill_rate: 1.0,
            burst: 2.0,
        }
    }

    fn ip(last_octet: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, last_octet))
    }

    #[test]
    fn test_check_disabled_always_allowed() {
        let limiter = RateLimiter::new(test_config(false), None);
        let addr = ip(1);

        for _ in 0..500 {
            if let RateLimitResult::Rejected { .. } = limiter.check(addr) {
                panic!("should never reject when rate limiting is disabled");
            }
        }
    }

    #[test]
    fn test_check_first_request_allowed() {
        let limiter = RateLimiter::new(test_config(true), None);
        let addr = ip(2);

        if let RateLimitResult::Rejected { .. } = limiter.check(addr) {
            panic!("first request should always be allowed");
        }
    }

    #[test]
    fn test_check_eventually_rejected() {
        let limiter = RateLimiter::new(test_config(true), None);
        let addr = ip(3);

        let mut rejected = false;
        for _ in 0..50 {
            if let RateLimitResult::Rejected { retry_after_ms } = limiter.check(addr) {
                assert!(retry_after_ms > 0, "retry_after_ms should be positive");
                rejected = true;
                break;
            }
        }
        assert!(rejected, "limit should eventually trigger");
    }

    #[test]
    fn test_check_different_ips_independent() {
        let limiter = RateLimiter::new(test_config(true), None);
        let addr_a = ip(10);
        let addr_b = ip(11);

        for _ in 0..50 {
            let _ = limiter.check(addr_a);
        }

        if let RateLimitResult::Rejected { .. } = limiter.check(addr_b) {
            panic!("addr_b should not be affected by addr_a's exhaustion");
        }
    }

    #[test]
    fn test_cleanup_stale_removes_old_entries() {
        let limiter = RateLimiter::new(test_config(true), None);
        let addr = ip(40);

        let _ = limiter.check(addr);
        assert!(limiter.clients.contains_key(&addr));

        limiter.cleanup_stale(Duration::from_secs(0));
        assert!(!limiter.clients.contains_key(&addr));
    }

    #[test]
    fn test_cleanup_stale_keeps_fresh_entries() {
        let limiter = RateLimiter::new(test_config(true), None);
        let addr = ip(41);

        let _ = limiter.check(addr);

        limiter.cleanup_stale(Duration::from_secs(3600));
        assert!(limiter.clients.contains_key(&addr));
    }
}
