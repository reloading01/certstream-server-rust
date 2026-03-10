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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateLimitTier {
    Free,
    Standard,
    Premium,
}

impl RateLimitTier {
    pub fn from_token(token: Option<&str>, tier_tokens: &TierTokens) -> Self {
        match token {
            Some(t) => {
                let clean = t.strip_prefix("Bearer ").unwrap_or(t);
                if tier_tokens.premium.iter().any(|p| p == clean) {
                    RateLimitTier::Premium
                } else if tier_tokens.standard.iter().any(|s| s == clean) {
                    RateLimitTier::Standard
                } else {
                    RateLimitTier::Free
                }
            }
            None => RateLimitTier::Free,
        }
    }

    fn limits(&self, config: &RateLimitConfig) -> TierLimits {
        match self {
            RateLimitTier::Free => TierLimits {
                max_tokens: config.free_max_tokens,
                refill_rate: config.free_refill_rate,
                burst_allowance: config.free_burst,
            },
            RateLimitTier::Standard => TierLimits {
                max_tokens: config.standard_max_tokens,
                refill_rate: config.standard_refill_rate,
                burst_allowance: config.standard_burst,
            },
            RateLimitTier::Premium => TierLimits {
                max_tokens: config.premium_max_tokens,
                refill_rate: config.premium_refill_rate,
                burst_allowance: config.premium_burst,
            },
        }
    }
}

struct TierLimits {
    max_tokens: f64,
    refill_rate: f64,
    burst_allowance: f64,
}

pub struct TierTokens {
    pub standard: Vec<String>,
    pub premium: Vec<String>,
}

struct ClientRateLimit {
    token_bucket: TokenBucket,
    sliding_window: SlidingWindow,
    tier: RateLimitTier,
    burst_used: f64,
    burst_reset: Instant,
}

pub struct RateLimiter {
    hot_reload: Option<Arc<HotReloadManager>>,
    fallback_config: RateLimitConfig,
    /// H-2 fix: store Arc<Mutex<…>> so we can drop the DashMap shard lock
    /// before acquiring the inner mutex, eliminating shard-wide serialization.
    clients: DashMap<IpAddr, Arc<Mutex<ClientRateLimit>>>,
    tier_tokens: TierTokens,
}

impl RateLimiter {
    pub fn new(config: RateLimitConfig, tier_tokens: TierTokens, hot_reload: Option<Arc<HotReloadManager>>) -> Arc<Self> {
        Arc::new(Self {
            hot_reload,
            fallback_config: config,
            clients: DashMap::new(),
            tier_tokens,
        })
    }

    fn get_config(&self) -> RateLimitConfig {
        self.hot_reload
            .as_ref()
            .map(|hr| hr.get().rate_limit.clone())
            .unwrap_or_else(|| self.fallback_config.clone())
    }

    pub fn check(&self, ip: IpAddr, token: Option<&str>) -> RateLimitResult {
        let config = self.get_config();

        if !config.enabled {
            return RateLimitResult::Allowed;
        }

        let tier = RateLimitTier::from_token(token, &self.tier_tokens);
        let limits = tier.limits(&config);

        // H-2 fix: extract the Arc<Mutex<…>>, then immediately drop the DashMap
        // RefMut (which held the shard write lock).  Only the inner Mutex is held
        // during the actual rate-limit computation, allowing other IPs in the same
        // shard to be checked concurrently.
        let client_mutex = {
            let entry = self.clients.entry(ip).or_insert_with(|| {
                Arc::new(Mutex::new(ClientRateLimit {
                    token_bucket: TokenBucket::new(limits.max_tokens, limits.refill_rate),
                    sliding_window: SlidingWindow::new(
                        Duration::from_secs(config.window_seconds),
                        config.window_max_requests,
                    ),
                    tier,
                    burst_used: 0.0,
                    burst_reset: Instant::now() + Duration::from_secs(config.burst_window_seconds),
                }))
            });
            Arc::clone(&*entry)
        }; // DashMap shard write lock released here

        let mut client = client_mutex.lock();
        let current_limits = client.tier.limits(&config);
        client.token_bucket.update_limits(current_limits.max_tokens, current_limits.refill_rate);
        client.sliding_window.update_limits(
            Duration::from_secs(config.window_seconds),
            config.window_max_requests,
        );

        if client.tier != tier {
            let new_limits = tier.limits(&config);
            client.token_bucket = TokenBucket::new(new_limits.max_tokens, new_limits.refill_rate);
            client.tier = tier;
        }

        if !client.sliding_window.try_acquire() {
            metrics::counter!("certstream_rate_limit_rejected", "reason" => "sliding_window").increment(1);
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

        if client.burst_used < limits.burst_allowance {
            client.burst_used += 1.0;
            metrics::counter!("certstream_rate_limit_burst_used").increment(1);
            return RateLimitResult::Allowed;
        }

        metrics::counter!("certstream_rate_limit_rejected", "reason" => "token_bucket").increment(1);
        RateLimitResult::Rejected {
            retry_after_ms: (1000.0 / limits.refill_rate) as u64,
        }
    }

    pub fn cleanup_stale(&self, max_age: Duration) {
        let cutoff = Instant::now() - max_age;
        self.clients.retain(|_, v| {
            // During retain the shard write lock is held exclusively, so v.lock()
            // is uncontested — no other thread can hold shard write + inner mutex.
            let client = v.lock();
            client.token_bucket.last_refill > cutoff
        });
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
            free_max_tokens: 5.0,
            free_refill_rate: 1.0,
            free_burst: 2.0,
            standard_max_tokens: 50.0,
            standard_refill_rate: 10.0,
            standard_burst: 20.0,
            premium_max_tokens: 200.0,
            premium_refill_rate: 50.0,
            premium_burst: 100.0,
        }
    }

    fn test_tier_tokens() -> TierTokens {
        TierTokens {
            standard: vec!["std-token".to_string()],
            premium: vec!["premium-token".to_string()],
        }
    }

    fn ip(last_octet: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, last_octet))
    }

    #[test]
    fn test_tier_from_none_token_is_free() {
        let tokens = test_tier_tokens();
        let tier = RateLimitTier::from_token(None, &tokens);
        assert_eq!(tier, RateLimitTier::Free);
    }

    #[test]
    fn test_tier_from_unknown_token_is_free() {
        let tokens = test_tier_tokens();
        let tier = RateLimitTier::from_token(Some("unknown-garbage"), &tokens);
        assert_eq!(tier, RateLimitTier::Free);
    }

    #[test]
    fn test_tier_from_standard_token() {
        let tokens = test_tier_tokens();
        let tier = RateLimitTier::from_token(Some("std-token"), &tokens);
        assert_eq!(tier, RateLimitTier::Standard);
    }

    #[test]
    fn test_tier_from_premium_token() {
        let tokens = test_tier_tokens();
        let tier = RateLimitTier::from_token(Some("premium-token"), &tokens);
        assert_eq!(tier, RateLimitTier::Premium);
    }

    #[test]
    fn test_tier_strips_bearer_prefix() {
        let tokens = test_tier_tokens();

        let tier_std = RateLimitTier::from_token(Some("Bearer std-token"), &tokens);
        assert_eq!(tier_std, RateLimitTier::Standard);

        let tier_prem = RateLimitTier::from_token(Some("Bearer premium-token"), &tokens);
        assert_eq!(tier_prem, RateLimitTier::Premium);

        let tier_unknown = RateLimitTier::from_token(Some("Bearer nope"), &tokens);
        assert_eq!(tier_unknown, RateLimitTier::Free);
    }

    #[test]
    fn test_check_disabled_always_allowed() {
        let limiter = RateLimiter::new(test_config(false), test_tier_tokens(), None);
        let addr = ip(1);

        for _ in 0..500 {
            match limiter.check(addr, None) {
                RateLimitResult::Allowed => {}
                RateLimitResult::Rejected { .. } => {
                    panic!("should never reject when rate limiting is disabled");
                }
            }
        }
    }

    #[test]
    fn test_check_first_request_allowed() {
        let limiter = RateLimiter::new(test_config(true), test_tier_tokens(), None);
        let addr = ip(2);

        match limiter.check(addr, None) {
            RateLimitResult::Allowed => {}
            RateLimitResult::Rejected { .. } => {
                panic!("first request should always be allowed");
            }
        }
    }

    #[test]
    fn test_check_free_tier_eventually_rejected() {
        let limiter = RateLimiter::new(test_config(true), test_tier_tokens(), None);
        let addr = ip(3);

        let mut rejected = false;
        for _ in 0..50 {
            if let RateLimitResult::Rejected { retry_after_ms } = limiter.check(addr, None) {
                assert!(retry_after_ms > 0, "retry_after_ms should be positive");
                rejected = true;
                break;
            }
        }
        assert!(rejected, "free tier should eventually be rate limited");
    }

    #[test]
    fn test_check_different_ips_independent() {
        let limiter = RateLimiter::new(test_config(true), test_tier_tokens(), None);
        let addr_a = ip(10);
        let addr_b = ip(11);

        for _ in 0..50 {
            limiter.check(addr_a, None);
        }

        match limiter.check(addr_b, None) {
            RateLimitResult::Allowed => {}
            RateLimitResult::Rejected { .. } => {
                panic!("addr_b should not be affected by addr_a's exhaustion");
            }
        }
    }

    #[test]
    fn test_check_standard_tier_has_more_capacity() {
        let limiter = RateLimiter::new(test_config(true), test_tier_tokens(), None);
        let free_ip = ip(20);
        let std_ip = ip(21);

        let mut free_rejected = false;
        for _ in 0..8 {
            if let RateLimitResult::Rejected { .. } = limiter.check(free_ip, None) {
                free_rejected = true;
            }
        }

        let mut std_rejected = false;
        for _ in 0..8 {
            if let RateLimitResult::Rejected { .. } =
                limiter.check(std_ip, Some("std-token"))
            {
                std_rejected = true;
            }
        }

        assert!(free_rejected, "free tier should be rejected within 8 requests");
        assert!(!std_rejected, "standard tier should still be allowed after 8 requests");
    }

    #[test]
    fn test_check_premium_tier_has_most_capacity() {
        let limiter = RateLimiter::new(test_config(true), test_tier_tokens(), None);
        let premium_ip = ip(30);

        let mut any_rejected = false;
        for _ in 0..100 {
            if let RateLimitResult::Rejected { .. } =
                limiter.check(premium_ip, Some("premium-token"))
            {
                any_rejected = true;
                break;
            }
        }
        assert!(!any_rejected, "premium tier should handle 100 rapid requests without rejection");
    }

    #[test]
    fn test_cleanup_stale_removes_old_entries() {
        let limiter = RateLimiter::new(test_config(true), test_tier_tokens(), None);
        let addr = ip(40);

        limiter.check(addr, None);
        assert!(limiter.clients.contains_key(&addr), "client entry should exist after a request");

        limiter.cleanup_stale(Duration::from_secs(0));
        assert!(!limiter.clients.contains_key(&addr), "client entry should be removed after cleanup with zero max_age");
    }

    #[test]
    fn test_cleanup_stale_keeps_fresh_entries() {
        let limiter = RateLimiter::new(test_config(true), test_tier_tokens(), None);
        let addr = ip(41);

        limiter.check(addr, None);

        limiter.cleanup_stale(Duration::from_secs(3600));
        assert!(limiter.clients.contains_key(&addr), "fresh client entry should survive cleanup with large max_age");
    }
}
