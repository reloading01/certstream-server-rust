use axum::{
    body::Body,
    extract::{ConnectInfo, Request, State},
    http::{HeaderMap, StatusCode},
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

/// Proxies whose forwarding headers are believed. Behind a reverse proxy every
/// connection arrives from the proxy's address, so the per-IP connection and
/// request limits would treat all clients as one.
#[derive(Debug, Default, Clone)]
pub struct TrustedProxies(Vec<(IpAddr, u8)>);

impl TrustedProxies {
    /// Entries are single addresses or CIDR ranges, IPv4 or IPv6.
    pub fn parse(entries: &[String]) -> Result<Self, String> {
        entries
            .iter()
            .map(|entry| {
                let (addr, prefix) = match entry.split_once('/') {
                    Some((addr, prefix)) => (addr, Some(prefix)),
                    None => (entry.as_str(), None),
                };
                let addr: IpAddr = addr
                    .trim()
                    .parse()
                    .map_err(|_| format!("`{entry}` is not an IP address or CIDR range"))?;
                let max = if addr.is_ipv4() { 32 } else { 128 };
                let prefix = match prefix {
                    Some(p) => p
                        .trim()
                        .parse::<u8>()
                        .ok()
                        .filter(|p| *p <= max)
                        .ok_or_else(|| format!("`{entry}` has an invalid prefix length"))?,
                    None => max,
                };
                Ok((addr.to_canonical(), prefix))
            })
            .collect::<Result<_, _>>()
            .map(Self)
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    fn contains(&self, ip: IpAddr) -> bool {
        let ip = ip.to_canonical();
        self.0.iter().any(|(net, prefix)| match (net, ip) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                let mask = u32::MAX.checked_shl(32 - u32::from(*prefix)).unwrap_or(0);
                u32::from(*net) & mask == u32::from(ip) & mask
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                let mask = u128::MAX.checked_shl(128 - u32::from(*prefix)).unwrap_or(0);
                u128::from(*net) & mask == u128::from(ip) & mask
            }
            _ => false,
        })
    }

    /// The address a request should be attributed to.
    ///
    /// Headers are read only when the TCP peer is a trusted proxy. The
    /// `X-Forwarded-For` list is read from the right, skipping addresses that
    /// are trusted proxies themselves, and the first one that is not is the
    /// client: everything to its left was written by the client or by hops
    /// nobody here vouches for, and can be forged. If every entry is a trusted
    /// proxy the leftmost is used, then `X-Real-IP`, then the peer.
    pub fn client_ip(&self, peer: IpAddr, headers: &HeaderMap) -> IpAddr {
        if !self.contains(peer) {
            return peer;
        }
        let hops: Vec<&str> = headers
            .get_all("x-forwarded-for")
            .iter()
            .filter_map(|v| v.to_str().ok())
            .flat_map(|v| v.split(','))
            .map(str::trim)
            .collect();
        for hop in hops.iter().rev() {
            match hop.parse::<IpAddr>() {
                Ok(ip) if self.contains(ip) => continue,
                Ok(ip) => return ip,
                Err(_) => return peer,
            }
        }
        if let Some(ip) = hops.first().and_then(|hop| hop.parse::<IpAddr>().ok()) {
            return ip;
        }
        headers
            .get("x-real-ip")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.trim().parse().ok())
            .unwrap_or(peer)
    }
}

/// Replaces the connection's peer address with the client address behind a
/// trusted proxy, so everything downstream that reads `ConnectInfo` limits and
/// logs the real client without knowing about proxies.
pub async fn resolve_client_ip(
    State(trusted): State<Arc<TrustedProxies>>,
    mut req: Request,
    next: Next,
) -> Response {
    if let Some(ConnectInfo(peer)) = req.extensions().get::<ConnectInfo<SocketAddr>>().copied() {
        let ip = trusted.client_ip(peer.ip(), req.headers());
        if ip != peer.ip() {
            req.extensions_mut()
                .insert(ConnectInfo(SocketAddr::new(ip, peer.port())));
        }
    }
    next.run(req).await
}

pub struct ConnectionLimiter {
    hot_reload: Option<Arc<HotReloadManager>>,
    fallback_config: ConnectionLimitConfig,
    total_connections: AtomicU32,
    per_ip_connections: DashMap<IpAddr, u32>,
    per_account_connections: DashMap<String, u32>,
}

/// A cap on one account's open connections, attached by the proxy that
/// authenticated the request. It applies whether or not the server-wide
/// limits are enabled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountLimit {
    pub account: String,
    pub max: u32,
}

impl AccountLimit {
    pub const ACCOUNT_HEADER: &'static str = "x-certstream-account";
    pub const MAX_HEADER: &'static str = "x-certstream-account-limit";

    /// Both headers must be present and the limit a number; anything else
    /// means the request carries no account limit.
    pub fn from_headers(headers: &HeaderMap) -> Option<Self> {
        let account = headers.get(Self::ACCOUNT_HEADER)?.to_str().ok()?.trim();
        let max = headers.get(Self::MAX_HEADER)?.to_str().ok()?.trim().parse().ok()?;
        (!account.is_empty()).then(|| Self { account: account.to_owned(), max })
    }
}

/// Why [`ConnectionLimiter::acquire`] refused a connection.
#[derive(Debug, PartialEq, Eq)]
pub enum Rejection {
    Server,
    Account(u32),
}

impl IntoResponse for Rejection {
    fn into_response(self) -> Response {
        let body = match self {
            Self::Server => "Connection limit exceeded".to_owned(),
            Self::Account(max) => format!(
                "This account already has {max} open connections, the most its plan allows. \
                 Close one, or wait up to a minute for a dropped one to time out."
            ),
        };
        (StatusCode::TOO_MANY_REQUESTS, body).into_response()
    }
}

impl ConnectionLimiter {
    pub fn new(config: ConnectionLimitConfig, hot_reload: Option<Arc<HotReloadManager>>) -> Arc<Self> {
        Arc::new(Self {
            hot_reload,
            fallback_config: config,
            total_connections: AtomicU32::new(0),
            per_ip_connections: DashMap::new(),
            per_account_connections: DashMap::new(),
        })
    }

    fn get_config(&self) -> ConnectionLimitConfig {
        self.hot_reload
            .as_ref()
            .map(|hr| hr.get().connection_limit.clone())
            .unwrap_or_else(|| self.fallback_config.clone())
    }

    /// Take a slot and get back a handle that returns it on drop.
    ///
    /// The WebSocket handlers must acquire *before* `ws.on_upgrade`, but axum
    /// drops the upgrade callback without ever calling it when the handshake
    /// fails, so a slot released at the end of the connection task leaks on
    /// every failed upgrade. Moving this guard into the callback makes the
    /// release follow the callback's lifetime instead of its execution.
    pub fn acquire(
        self: &Arc<Self>,
        ip: IpAddr,
        account: Option<AccountLimit>,
    ) -> Result<ConnectionGuard, Rejection> {
        if let Some(limit) = &account {
            let mut open = self.per_account_connections.entry(limit.account.clone()).or_insert(0);
            if *open >= limit.max {
                drop(open);
                // A limit of 0 leaves the entry this call created at zero.
                self.per_account_connections.remove_if(&limit.account, |_, open| *open == 0);
                metrics::counter!("certstream_account_limit_rejected").increment(1);
                return Err(Rejection::Account(limit.max));
            }
            *open += 1;
        }
        let account = account.map(|limit| limit.account);
        if !self.try_acquire(ip) {
            if let Some(account) = &account {
                self.release_account(account);
            }
            return Err(Rejection::Server);
        }
        Ok(ConnectionGuard {
            limiter: Arc::clone(self),
            ip,
            account,
        })
    }

    /// Decrements an account's count and drops the entry at zero.
    fn release_account(&self, account: &str) {
        self.per_account_connections.remove_if_mut(account, |_, open| {
            *open = open.saturating_sub(1);
            *open == 0
        });
    }

    fn try_acquire(&self, ip: IpAddr) -> bool {
        let config = self.get_config();

        if !config.enabled {
            return true;
        }

        loop {
            // Acquire: the CAS below is only sound if this load cannot be
            // reordered past it.
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

    fn release(&self, ip: IpAddr) {
        let config = self.get_config();

        if !config.enabled {
            return;
        }

        // Saturating, because a hot reload can flip `enabled` from false to
        // true between acquire and release — the acquire never incremented,
        // and an unchecked decrement would underflow the counter.
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

    /// Sweep zero-count entries from `per_ip_connections`. `release()` already
    /// removes entries inline when their count hits zero, but error paths can
    /// leave zombies (entry decremented to zero by saturating_sub without the
    /// follow-up remove). This is a belt-and-braces sweep — cheap, idempotent,
    /// safe to run when the limiter is disabled.
    pub fn cleanup_stale(&self) {
        self.per_ip_connections.retain(|_, count| *count > 0);
    }
}

/// A slot held in [`ConnectionLimiter`], returned when this value drops.
///
/// Covers the paths a hand-written `release()` call misses: a failed
/// WebSocket upgrade (axum drops the callback uninvoked), a cancelled
/// connection task, and an early return between acquiring and streaming.
pub struct ConnectionGuard {
    limiter: Arc<ConnectionLimiter>,
    ip: IpAddr,
    account: Option<String>,
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.limiter.release(self.ip);
        if let Some(account) = &self.account {
            self.limiter.release_account(account);
        }
    }
}

/// Constant-time check that `target` matches some element of `list`.
/// Length mismatch short-circuits per entry (the length itself is not secret),
/// but byte comparison runs in fixed time so an attacker can't distinguish
/// near-matches via response timing.
fn ct_contains(list: &[String], target: &[u8]) -> bool {
    list.iter().any(|stored| {
        let sb = stored.as_bytes();
        sb.len() == target.len() && sb.ct_eq(target).into()
    })
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

    /// Runs `f` against the live config without cloning it: the hot-reload
    /// snapshot is an `ArcSwap` load, so a request that checks the enabled
    /// flag, the header name and the token list reads one consistent snapshot
    /// and copies none of it.
    fn with_config<R>(&self, f: impl FnOnce(&AuthConfig) -> R) -> R {
        match &self.hot_reload {
            Some(hr) => f(&hr.get().auth),
            None => f(&self.fallback_config),
        }
    }

    fn validate_against(config: &AuthConfig, token: Option<&str>) -> bool {
        if !config.enabled {
            return true;
        }
        let Some(t) = token else { return false };
        let token_value = t.strip_prefix("Bearer ").unwrap_or(t);
        ct_contains(&config.tokens, token_value.as_bytes())
    }

    /// Test-only inspectors — production traffic goes through `authorize`.
    #[cfg(test)]
    pub fn validate(&self, token: Option<&str>) -> bool {
        self.with_config(|config| Self::validate_against(config, token))
    }

    #[cfg(test)]
    pub fn is_enabled(&self) -> bool {
        self.with_config(|config| config.enabled)
    }

    /// Full request check with a single config snapshot: enabled flag, header
    /// lookup, and token validation all read the same consistent config.
    pub fn authorize(&self, headers: &axum::http::HeaderMap) -> bool {
        self.with_config(|config| {
            if !config.enabled {
                return true;
            }
            let token = headers
                .get(config.header_name.as_str())
                .and_then(|v| v.to_str().ok());
            Self::validate_against(config, token)
        })
    }
}

pub async fn auth_middleware(
    State(auth): State<Arc<AuthMiddleware>>,
    request: Request<Body>,
    next: Next,
) -> Response {
    if auth.authorize(request.headers()) {
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
    // Single-tier rate limit keyed by source IP. Auth status doesn't
    // influence this: a malicious authenticated client still hits the
    // same per-IP ceiling as anyone else. Tier-based throttling was
    // removed in 1.5.0 — it added complexity without a clear use case.
    match limiter.check(addr.ip()) {
        RateLimitResult::Allowed => next.run(request).await,
        RateLimitResult::Rejected { retry_after_ms } => {
            let mut response = (
                StatusCode::TOO_MANY_REQUESTS,
                format!("Rate limit exceeded. Retry after {}ms", retry_after_ms),
            )
                .into_response();
            let secs = (retry_after_ms / 1000).max(1).to_string();
            if let Ok(hv) = secs.parse() {
                response.headers_mut().insert("Retry-After", hv);
            }
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
        }
    }

    fn account(name: &str, max: u32) -> Option<AccountLimit> {
        Some(AccountLimit { account: name.to_owned(), max })
    }

    #[test]
    fn account_limit_spans_addresses_and_frees_on_drop() {
        let limiter = ConnectionLimiter::new(limiter_config(false, 0, None), None);

        let first = limiter.acquire(test_ip(1), account("a", 2)).unwrap();
        let _second = limiter.acquire(test_ip(2), account("a", 2)).unwrap();
        assert_eq!(
            limiter.acquire(test_ip(3), account("a", 2)).err(),
            Some(Rejection::Account(2))
        );
        assert!(limiter.acquire(test_ip(3), account("b", 2)).is_ok(), "accounts are counted apart");
        assert!(limiter.acquire(test_ip(3), None).is_ok(), "no account means no account limit");

        drop(first);
        assert!(limiter.acquire(test_ip(3), account("a", 2)).is_ok());
    }

    #[test]
    fn a_server_rejection_gives_the_account_slot_back() {
        let limiter = ConnectionLimiter::new(limiter_config(true, 10, Some(1)), None);
        let _held = limiter.acquire(test_ip(1), None).unwrap();

        assert_eq!(limiter.acquire(test_ip(1), account("a", 1)).err(), Some(Rejection::Server));
        assert!(limiter.acquire(test_ip(2), account("a", 1)).is_ok());
    }

    #[test]
    fn account_entries_are_removed_when_the_last_connection_closes() {
        let limiter = ConnectionLimiter::new(limiter_config(false, 0, None), None);
        drop(limiter.acquire(test_ip(1), account("a", 1)).unwrap());
        assert!(limiter.acquire(test_ip(1), account("z", 0)).is_err());
        assert!(limiter.per_account_connections.is_empty());
    }

    #[test]
    fn account_limit_needs_both_headers_and_a_number() {
        let mut headers = HeaderMap::new();
        headers.insert(AccountLimit::ACCOUNT_HEADER, "acct".parse().unwrap());
        assert_eq!(AccountLimit::from_headers(&headers), None);
        headers.insert(AccountLimit::MAX_HEADER, "two".parse().unwrap());
        assert_eq!(AccountLimit::from_headers(&headers), None);
        headers.insert(AccountLimit::MAX_HEADER, "2".parse().unwrap());
        assert_eq!(AccountLimit::from_headers(&headers), account("acct", 2));
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

    fn proxies(entries: &[&str]) -> TrustedProxies {
        let entries: Vec<String> = entries.iter().map(|e| e.to_string()).collect();
        TrustedProxies::parse(&entries).unwrap()
    }

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.append(
                axum::http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                value.parse().unwrap(),
            );
        }
        map
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn trusted_proxy_entries_are_validated() {
        assert!(TrustedProxies::parse(&["10.0.0.0/8".into(), "::1".into(), "2001:db8::/32".into()]).is_ok());
        for bad in ["nope", "10.0.0.0/33", "10.0.0.0/x", "2001:db8::/129"] {
            assert!(TrustedProxies::parse(&[bad.to_string()]).is_err(), "{bad}");
        }
    }

    #[test]
    fn without_a_trusted_proxy_the_peer_is_the_client() {
        let h = headers(&[("x-forwarded-for", "203.0.113.9")]);
        assert_eq!(TrustedProxies::default().client_ip(ip("198.51.100.7"), &h), ip("198.51.100.7"));
        // A peer that is not a proxy cannot vouch for a header, so it cannot
        // choose its own address.
        assert_eq!(proxies(&["10.0.0.0/8"]).client_ip(ip("198.51.100.7"), &h), ip("198.51.100.7"));
    }

    #[test]
    fn a_trusted_proxy_vouches_for_the_address_it_appended() {
        let p = proxies(&["10.0.0.0/8"]);
        let h = headers(&[("x-forwarded-for", "203.0.113.9")]);
        assert_eq!(p.client_ip(ip("10.0.0.1"), &h), ip("203.0.113.9"));
    }

    /// The client wrote the left of the list; only what the proxy appended can
    /// be trusted, so a forged leftmost address must not win.
    #[test]
    fn a_forged_leftmost_address_is_ignored() {
        let p = proxies(&["10.0.0.0/8"]);
        let h = headers(&[("x-forwarded-for", "192.0.2.66, 203.0.113.9, 10.0.0.2")]);
        assert_eq!(p.client_ip(ip("10.0.0.1"), &h), ip("203.0.113.9"));
        // Split over two header lines it reads the same.
        let h = headers(&[("x-forwarded-for", "192.0.2.66"), ("x-forwarded-for", "203.0.113.9")]);
        assert_eq!(p.client_ip(ip("10.0.0.1"), &h), ip("203.0.113.9"));
    }

    #[test]
    fn fallbacks_when_the_chain_names_no_outside_client() {
        let p = proxies(&["10.0.0.0/8"]);
        let all_proxies = headers(&[("x-forwarded-for", "10.1.1.1, 10.2.2.2")]);
        assert_eq!(p.client_ip(ip("10.0.0.1"), &all_proxies), ip("10.1.1.1"));
        let real = headers(&[("x-real-ip", "203.0.113.9")]);
        assert_eq!(p.client_ip(ip("10.0.0.1"), &real), ip("203.0.113.9"));
        assert_eq!(p.client_ip(ip("10.0.0.1"), &HeaderMap::new()), ip("10.0.0.1"));
        let junk = headers(&[("x-forwarded-for", "203.0.113.9, unknown")]);
        assert_eq!(p.client_ip(ip("10.0.0.1"), &junk), ip("10.0.0.1"));
    }

    #[test]
    fn an_ipv4_peer_mapped_into_ipv6_matches_its_ipv4_range() {
        let p = proxies(&["10.0.0.0/8"]);
        let h = headers(&[("x-forwarded-for", "203.0.113.9")]);
        assert_eq!(p.client_ip(ip("::ffff:10.0.0.1"), &h), ip("203.0.113.9"));
    }

    /// Through a real router: the limiter and the handlers downstream read
    /// `ConnectInfo`, so the replaced address is what they see.
    #[tokio::test]
    async fn the_middleware_rewrites_the_address_downstream_handlers_see() {
        use axum::{routing::get, Router};
        use tower::ServiceExt;

        let app = Router::new()
            .route("/", get(|ConnectInfo(addr): ConnectInfo<SocketAddr>| async move { addr.ip().to_string() }))
            .layer(axum::middleware::from_fn_with_state(
                Arc::new(proxies(&["10.0.0.0/8"])),
                resolve_client_ip,
            ));

        let ask = |peer: &str, forwarded: &str| {
            let mut req = axum::http::Request::builder()
                .uri("/")
                .header("x-forwarded-for", forwarded)
                .body(Body::empty())
                .unwrap();
            req.extensions_mut()
                .insert(ConnectInfo(SocketAddr::new(ip(peer), 4000)));
            req
        };
        let body = |resp: Response| async move {
            String::from_utf8(
                axum::body::to_bytes(resp.into_body(), 1024).await.unwrap().to_vec(),
            )
            .unwrap()
        };

        assert_eq!(body(app.clone().oneshot(ask("10.0.0.1", "203.0.113.9")).await.unwrap()).await, "203.0.113.9");
        assert_eq!(body(app.oneshot(ask("198.51.100.7", "203.0.113.9")).await.unwrap()).await, "198.51.100.7");
    }
}
