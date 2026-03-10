use axum::{
    body::Body,
    extract::{ConnectInfo, Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};
use dashmap::DashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use subtle::ConstantTimeEq;

use crate::config::{AuthConfig, ConnectionLimitConfig};
use crate::hot_reload::HotReloadManager;
use crate::rate_limit::{RateLimitResult, RateLimiter};

pub struct ConnectionLimiter {
    hot_reload: Option<Arc<HotReloadManager>>,
    fallback_config: ConnectionLimitConfig,
    total_connections: AtomicU32,
    per_ip_connections: DashMap<IpAddr, u32>,
}

impl ConnectionLimiter {
    pub fn new(config: ConnectionLimitConfig, hot_reload: Option<Arc<HotReloadManager>>) -> Arc<Self> {
        Arc::new(Self {
            hot_reload,
            fallback_config: config,
            total_connections: AtomicU32::new(0),
            per_ip_connections: DashMap::new(),
        })
    }

    fn get_config(&self) -> ConnectionLimitConfig {
        self.hot_reload
            .as_ref()
            .map(|hr| hr.get().connection_limit.clone())
            .unwrap_or_else(|| self.fallback_config.clone())
    }

    pub fn try_acquire(&self, ip: IpAddr) -> bool {
        let config = self.get_config();

        if !config.enabled {
            return true;
        }

        loop {
            // L-7 fix: use Acquire for the load in the CAS loop
            let current_total = self.total_connections.load(Ordering::Acquire);
            if current_total >= config.max_connections {
                metrics::counter!("certstream_connection_limit_rejected").increment(1);
                return false;
            }

            if self
                .total_connections
                .compare_exchange(current_total, current_total + 1, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                break;
            }
        }

        if let Some(per_ip_limit) = config.per_ip_limit {
            let mut should_release = false;
            {
                let mut entry = self.per_ip_connections.entry(ip).or_insert(0);
                if *entry >= per_ip_limit {
                    should_release = true;
                } else {
                    *entry += 1;
                }
            }
            if should_release {
                // C-1 fix: use saturating_sub to prevent u32 underflow
                self.total_connections.fetch_update(
                    Ordering::AcqRel,
                    Ordering::Acquire,
                    |v| Some(v.saturating_sub(1)),
                ).ok();
                metrics::counter!("certstream_per_ip_limit_rejected").increment(1);
                return false;
            }
        } else {
            self.per_ip_connections
                .entry(ip)
                .and_modify(|v| *v += 1)
                .or_insert(1);
        }

        true
    }

    pub fn release(&self, ip: IpAddr) {
        let config = self.get_config();

        if !config.enabled {
            return;
        }

        // C-1 fix: use fetch_update with saturating_sub to prevent u32 underflow
        // if `enabled` flipped false→true between try_acquire and release due to
        // a hot-reload event (which would have left total_connections un-incremented).
        self.total_connections.fetch_update(
            Ordering::AcqRel,
            Ordering::Acquire,
            |v| Some(v.saturating_sub(1)),
        ).ok();

        if let Some(mut entry) = self.per_ip_connections.get_mut(&ip) {
            *entry = entry.saturating_sub(1);
            if *entry == 0 {
                drop(entry);
                self.per_ip_connections.remove(&ip);
            }
        }
    }

    pub fn current_connections(&self) -> u32 {
        self.total_connections.load(Ordering::Relaxed)
    }
}

#[derive(Clone)]
pub struct AuthMiddleware {
    hot_reload: Option<Arc<HotReloadManager>>,
    fallback_config: AuthConfig,
}

impl AuthMiddleware {
    pub fn new(config: &AuthConfig, hot_reload: Option<Arc<HotReloadManager>>) -> Self {
        Self {
            hot_reload,
            fallback_config: config.clone(),
        }
    }

    fn get_config(&self) -> AuthConfig {
        self.hot_reload
            .as_ref()
            .map(|hr| hr.get().auth.clone())
            .unwrap_or_else(|| self.fallback_config.clone())
    }

    pub fn validate(&self, token: Option<&str>) -> bool {
        let config = self.get_config();

        if !config.enabled {
            return true;
        }

        match token {
            Some(t) => {
                let token_value = t.strip_prefix("Bearer ").unwrap_or(t);
                let token_bytes = token_value.as_bytes();
                config.tokens.iter().any(|stored| {
                    let stored_bytes = stored.as_bytes();
                    stored_bytes.len() == token_bytes.len()
                        && stored_bytes.ct_eq(token_bytes).into()
                })
            }
            None => false,
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.get_config().enabled
    }

    pub fn header_name(&self) -> String {
        self.get_config().header_name
    }
}

pub async fn auth_middleware(
    State(auth): State<Arc<AuthMiddleware>>,
    request: Request<Body>,
    next: Next,
) -> Response {
    if !auth.is_enabled() {
        return next.run(request).await;
    }

    let header_name = auth.header_name();
    let token = request
        .headers()
        .get(&header_name)
        .and_then(|v| v.to_str().ok());

    if auth.validate(token) {
        next.run(request).await
    } else {
        metrics::counter!("certstream_auth_rejected").increment(1);
        (StatusCode::UNAUTHORIZED, "Unauthorized").into_response()
    }
}

pub async fn rate_limit_middleware(
    State(limiter): State<Arc<RateLimiter>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let token = request
        .headers()
        .get("Authorization")
        .and_then(|v| v.to_str().ok());

    match limiter.check(addr.ip(), token) {
        RateLimitResult::Allowed => next.run(request).await,
        RateLimitResult::Rejected { retry_after_ms } => {
            let mut response = (
                StatusCode::TOO_MANY_REQUESTS,
                format!("Rate limit exceeded. Retry after {}ms", retry_after_ms),
            )
                .into_response();
            response.headers_mut().insert(
                "Retry-After",
                ((retry_after_ms / 1000).max(1)).to_string().parse().unwrap(),
            );
            response
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AuthConfig, ConnectionLimitConfig};
    use std::net::{IpAddr, Ipv4Addr};

    fn test_ip(last_octet: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, last_octet))
    }

    fn limiter_config(enabled: bool, max: u32, per_ip: Option<u32>) -> ConnectionLimitConfig {
        ConnectionLimitConfig {
            enabled,
            max_connections: max,
            per_ip_limit: per_ip,
        }
    }

    fn auth_config(enabled: bool, tokens: Vec<&str>) -> AuthConfig {
        AuthConfig {
            enabled,
            tokens: tokens.into_iter().map(String::from).collect(),
            header_name: "Authorization".to_string(),
            standard_tokens: Vec::new(),
            premium_tokens: Vec::new(),
        }
    }

    #[test]
    fn limiter_disabled_always_allows() {
        let limiter = ConnectionLimiter::new(limiter_config(false, 1, Some(1)), None);
        let ip = test_ip(1);

        // Should succeed even though max_connections and per_ip_limit are 1
        assert!(limiter.try_acquire(ip));
        assert!(limiter.try_acquire(ip));
        assert!(limiter.try_acquire(ip));
    }

    #[test]
    fn limiter_acquire_within_limits() {
        let limiter = ConnectionLimiter::new(limiter_config(true, 3, None), None);

        assert!(limiter.try_acquire(test_ip(1)));
        assert!(limiter.try_acquire(test_ip(2)));
        assert!(limiter.try_acquire(test_ip(3)));
    }

    #[test]
    fn limiter_rejects_at_max_connections() {
        let limiter = ConnectionLimiter::new(limiter_config(true, 3, None), None);

        assert!(limiter.try_acquire(test_ip(1)));
        assert!(limiter.try_acquire(test_ip(2)));
        assert!(limiter.try_acquire(test_ip(3)));
        // 4th connection should be rejected
        assert!(!limiter.try_acquire(test_ip(4)));
    }

    #[test]
    fn limiter_per_ip_limit_enforcement() {
        let limiter = ConnectionLimiter::new(limiter_config(true, 10, Some(2)), None);
        let ip = test_ip(1);

        assert!(limiter.try_acquire(ip));
        assert!(limiter.try_acquire(ip));
        // 3rd from same IP should be rejected
        assert!(!limiter.try_acquire(ip));
        // Different IP should still work
        assert!(limiter.try_acquire(test_ip(2)));
    }

    #[test]
    fn limiter_release_decrements_and_reallows() {
        let limiter = ConnectionLimiter::new(limiter_config(true, 2, Some(1)), None);
        let ip = test_ip(1);

        assert!(limiter.try_acquire(ip));
        // Second from same IP blocked by per-IP limit
        assert!(!limiter.try_acquire(ip));

        limiter.release(ip);

        // After release, same IP can acquire again
        assert!(limiter.try_acquire(ip));
    }

    #[test]
    fn limiter_release_frees_total_slot() {
        let limiter = ConnectionLimiter::new(limiter_config(true, 2, None), None);

        assert!(limiter.try_acquire(test_ip(1)));
        assert!(limiter.try_acquire(test_ip(2)));
        assert!(!limiter.try_acquire(test_ip(3)));

        limiter.release(test_ip(1));

        // Slot freed, new IP can connect
        assert!(limiter.try_acquire(test_ip(3)));
    }

    #[test]
    fn limiter_current_connections_tracks_correctly() {
        let limiter = ConnectionLimiter::new(limiter_config(true, 10, None), None);

        assert_eq!(limiter.current_connections(), 0);

        limiter.try_acquire(test_ip(1));
        assert_eq!(limiter.current_connections(), 1);

        limiter.try_acquire(test_ip(2));
        limiter.try_acquire(test_ip(3));
        assert_eq!(limiter.current_connections(), 3);

        limiter.release(test_ip(2));
        assert_eq!(limiter.current_connections(), 2);
    }

    #[test]
    fn limiter_disabled_does_not_track_connections() {
        let limiter = ConnectionLimiter::new(limiter_config(false, 10, None), None);

        limiter.try_acquire(test_ip(1));
        limiter.try_acquire(test_ip(2));
        // When disabled, the atomic counter is never incremented
        assert_eq!(limiter.current_connections(), 0);
    }

    #[test]
    fn auth_disabled_always_validates() {
        let auth = AuthMiddleware::new(
            &auth_config(false, vec!["secret-token"]),
            None,
        );

        assert!(auth.validate(None));
        assert!(auth.validate(Some("wrong")));
        assert!(auth.validate(Some("")));
    }

    #[test]
    fn auth_valid_token_accepted() {
        let auth = AuthMiddleware::new(
            &auth_config(true, vec!["secret-token", "other-token"]),
            None,
        );

        assert!(auth.validate(Some("secret-token")));
        assert!(auth.validate(Some("other-token")));
    }

    #[test]
    fn auth_invalid_token_rejected() {
        let auth = AuthMiddleware::new(
            &auth_config(true, vec!["secret-token"]),
            None,
        );

        assert!(!auth.validate(Some("wrong-token")));
        assert!(!auth.validate(Some("SECRET-TOKEN"))); // case-sensitive
        assert!(!auth.validate(Some("secret-token "))); // trailing space
    }

    #[test]
    fn auth_none_token_rejected() {
        let auth = AuthMiddleware::new(
            &auth_config(true, vec!["secret-token"]),
            None,
        );

        assert!(!auth.validate(None));
    }

    #[test]
    fn auth_bearer_prefix_stripped() {
        let auth = AuthMiddleware::new(
            &auth_config(true, vec!["secret-token"]),
            None,
        );

        assert!(auth.validate(Some("Bearer secret-token")));
        // Without prefix also works
        assert!(auth.validate(Some("secret-token")));
        // Wrong prefix should fail (token becomes "bearer secret-token" != "secret-token")
        assert!(!auth.validate(Some("bearer secret-token")));
    }

    #[test]
    fn auth_is_enabled_returns_correct_value() {
        let enabled = AuthMiddleware::new(
            &auth_config(true, vec!["t"]),
            None,
        );
        let disabled = AuthMiddleware::new(
            &auth_config(false, vec![]),
            None,
        );

        assert!(enabled.is_enabled());
        assert!(!disabled.is_enabled());
    }
}
