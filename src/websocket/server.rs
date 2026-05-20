use axum::{
    extract::{
        ws::{Message, Utf8Bytes, WebSocket, WebSocketUpgrade},
        ConnectInfo, State,
    },
    http::StatusCode,
    response::IntoResponse,
};
use std::net::{IpAddr, SocketAddr};
use futures_util::{SinkExt, StreamExt};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::broadcast;
use tokio::time::{interval, timeout};
use tracing::{debug, info};

use crate::config::StreamConfig;
use crate::middleware::ConnectionLimiter;
use crate::models::PreSerializedMessage;

static HEARTBEAT_JSON: &str = r#"{"message_type":"heartbeat"}"#;

/// Disconnect policy for persistently-lagging clients. Lives in a module so
/// the const is reachable from tests AND so a future tweak goes through a
/// single named symbol instead of a scattered literal.
pub mod lag_policy {
    /// Number of consecutive `broadcast::Receiver::Lagged` events tolerated
    /// before the WebSocket connection is forcibly closed. Pre-1.5.0 this
    /// was effectively infinite — slow clients held FDs and skewed metrics
    /// indefinitely.
    pub const MAX_CONSECUTIVE_LAGS: u32 = 5;
}

pub struct AppState {
    pub tx: broadcast::Sender<Arc<PreSerializedMessage>>,
    pub connections: ConnectionCounter,
    pub limiter: Arc<ConnectionLimiter>,
    pub streams: Arc<StreamConfig>,
}

#[derive(Default)]
pub struct ConnectionCounter {
    full: AtomicU64,
    lite: AtomicU64,
    domains: AtomicU64,
}

impl ConnectionCounter {
    pub fn new() -> Self {
        Self::default()
    }

    #[inline]
    fn increment(&self, stream_type: StreamType) {
        match stream_type {
            StreamType::Full => self.full.fetch_add(1, Ordering::Relaxed),
            StreamType::Lite => self.lite.fetch_add(1, Ordering::Relaxed),
            StreamType::DomainsOnly => self.domains.fetch_add(1, Ordering::Relaxed),
        };
        self.update_metrics();
    }

    #[inline]
    fn decrement(&self, stream_type: StreamType) {
        match stream_type {
            StreamType::Full => self.full.fetch_sub(1, Ordering::Relaxed),
            StreamType::Lite => self.lite.fetch_sub(1, Ordering::Relaxed),
            StreamType::DomainsOnly => self.domains.fetch_sub(1, Ordering::Relaxed),
        };
        self.update_metrics();
    }

    #[inline]
    fn update_metrics(&self) {
        let total = self.full.load(Ordering::Relaxed)
            + self.lite.load(Ordering::Relaxed)
            + self.domains.load(Ordering::Relaxed);
        metrics::gauge!("certstream_ws_connections_total").set(total as f64);
        metrics::gauge!("certstream_ws_connections_full").set(self.full.load(Ordering::Relaxed) as f64);
        metrics::gauge!("certstream_ws_connections_lite").set(self.lite.load(Ordering::Relaxed) as f64);
        metrics::gauge!("certstream_ws_connections_domains").set(self.domains.load(Ordering::Relaxed) as f64);
    }

    pub fn total(&self) -> u64 {
        self.full.load(Ordering::Relaxed)
            + self.lite.load(Ordering::Relaxed)
            + self.domains.load(Ordering::Relaxed)
    }
}

pub async fn handle_full_stream(
    ws: WebSocketUpgrade,
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> impl IntoResponse {
    let ip = addr.ip();
    if !state.limiter.try_acquire(ip) {
        return (StatusCode::TOO_MANY_REQUESTS, "Connection limit exceeded").into_response();
    }
    let rx = state.tx.subscribe();
    ws.on_upgrade(move |socket| handle_socket(socket, rx, StreamType::Full, state, ip))
        .into_response()
}

pub async fn handle_lite_stream(
    ws: WebSocketUpgrade,
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> impl IntoResponse {
    let ip = addr.ip();
    if !state.limiter.try_acquire(ip) {
        return (StatusCode::TOO_MANY_REQUESTS, "Connection limit exceeded").into_response();
    }
    let rx = state.tx.subscribe();
    ws.on_upgrade(move |socket| handle_socket(socket, rx, StreamType::Lite, state, ip))
        .into_response()
}

pub async fn handle_domains_only(
    ws: WebSocketUpgrade,
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> impl IntoResponse {
    let ip = addr.ip();
    if !state.limiter.try_acquire(ip) {
        return (StatusCode::TOO_MANY_REQUESTS, "Connection limit exceeded").into_response();
    }
    let rx = state.tx.subscribe();
    ws.on_upgrade(move |socket| handle_socket(socket, rx, StreamType::DomainsOnly, state, ip))
        .into_response()
}

#[derive(Clone, Copy)]
enum StreamType {
    Full,
    Lite,
    DomainsOnly,
}

async fn handle_socket(
    socket: WebSocket,
    mut rx: broadcast::Receiver<Arc<PreSerializedMessage>>,
    stream_type: StreamType,
    state: Arc<AppState>,
    client_ip: IpAddr,
) {
    let (mut sender, mut receiver) = socket.split();

    state.connections.increment(stream_type);
    let stream_name = match stream_type {
        StreamType::Full => "full",
        StreamType::Lite => "lite",
        StreamType::DomainsOnly => "domains",
    };

    info!(
        stream = stream_name,
        total = state.connections.total(),
        ip = %client_ip,
        "WS client connected"
    );

    let mut heartbeat_interval = interval(Duration::from_secs(30));
    let mut ping_interval = interval(Duration::from_secs(15));
    let mut last_pong = std::time::Instant::now();
    let pong_timeout = Duration::from_secs(45);

    // After this many *consecutive* Lagged events the client is hopeless —
    // it's burning channel capacity without ever catching up, so we cut it.
    // Reset on every successful send / receive. Constant lives in
    // `lag_policy` so the regression test can lock it down — accidentally
    // bumping it to u32::MAX would silently disable the disconnect path.
    const MAX_CONSECUTIVE_LAGS: u32 = lag_policy::MAX_CONSECUTIVE_LAGS;
    // Outbound write deadline. A client whose TCP send buffer is full will
    // back-pressure axum's Sink and `sender.send().await` blocks indefinitely.
    // While blocked, this task can't drain `rx` or service pongs — the
    // broadcast Receiver keeps growing (other clients lag), the FD stays
    // open, and the connection counter is poisoned. 10 s is a generous
    // upper bound: any healthy client drains tens of KB in <1 s.
    const WRITE_TIMEOUT: Duration = Duration::from_secs(10);
    let mut consecutive_lags: u32 = 0;

    // Helper: send with timeout. Returns false on send error OR timeout,
    // which the caller uses to break the loop.
    async fn send_with_deadline(
        sender: &mut futures_util::stream::SplitSink<WebSocket, Message>,
        msg: Message,
        deadline: Duration,
    ) -> bool {
        match timeout(deadline, sender.send(msg)).await {
            Ok(Ok(())) => true,
            Ok(Err(_)) => false,
            Err(_) => {
                // Write didn't complete within deadline → slow/dead client.
                metrics::counter!("certstream_ws_disconnect_write_timeout").increment(1);
                false
            }
        }
    }

    loop {
        tokio::select! {
            biased;

            msg = receiver.next() => {
                match msg {
                    Some(Ok(Message::Ping(data))) => {
                        if !send_with_deadline(&mut sender, Message::Pong(data), WRITE_TIMEOUT).await {
                            break;
                        }
                    }
                    Some(Ok(Message::Pong(_))) => {
                        last_pong = std::time::Instant::now();
                    }
                    Some(Ok(Message::Close(_))) | None => {
                        break;
                    }
                    _ => {}
                }
            }

            _ = ping_interval.tick() => {
                if last_pong.elapsed() > pong_timeout {
                    debug!(ip = %client_ip, "client pong timeout, disconnecting");
                    break;
                }
                if !send_with_deadline(&mut sender, Message::Ping(bytes::Bytes::new()), WRITE_TIMEOUT).await {
                    break;
                }
            }

            _ = heartbeat_interval.tick() => {
                // Text frame per certstream wire convention — JSON over WebSocket
                // is Text, not Binary. (Pre-1.5 sent this as Binary, which broke
                // strict clients that demuxed by frame type.)
                let hb = Message::Text(Utf8Bytes::from_static(HEARTBEAT_JSON));
                if !send_with_deadline(&mut sender, hb, WRITE_TIMEOUT).await {
                    break;
                }
            }

            result = rx.recv() => {
                match result {
                    Ok(msg) => {
                        let bytes = match stream_type {
                            StreamType::Full => msg.full.clone(),
                            StreamType::Lite => msg.lite.clone(),
                            StreamType::DomainsOnly => msg.domains_only.clone(),
                        };

                        // Pre-serialized JSON is guaranteed UTF-8 by serde_json,
                        // so `Utf8Bytes::try_from(bytes)` is a zero-copy ref-bump
                        // on the shared Bytes (no String allocation per client).
                        // Pre-1.5.0 did `from_utf8(&bytes).to_string()` here —
                        // one full copy per subscriber per message, defeating
                        // the whole point of pre-serializing into shared Bytes.
                        let frame = match Utf8Bytes::try_from(bytes.clone()) {
                            Ok(text) => Message::Text(text),
                            Err(_) => {
                                // serde_json must not produce invalid UTF-8;
                                // if it ever does, fall back to Binary rather
                                // than drop the message silently.
                                Message::Binary(bytes)
                            }
                        };
                        if !send_with_deadline(&mut sender, frame, WRITE_TIMEOUT).await {
                            break;
                        }
                        consecutive_lags = 0;
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        debug!(lagged = n, ip = %client_ip, "client lagged, skipping messages");
                        metrics::counter!("certstream_ws_messages_lagged").increment(n);
                        consecutive_lags = consecutive_lags.saturating_add(1);
                        if consecutive_lags >= MAX_CONSECUTIVE_LAGS {
                            debug!(
                                ip = %client_ip,
                                lags = consecutive_lags,
                                "client persistently lagged, disconnecting"
                            );
                            metrics::counter!("certstream_ws_disconnect_lag").increment(1);
                            break;
                        }
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        break;
                    }
                }
            }
        }
    }

    state.limiter.release(client_ip);
    state.connections.decrement(stream_type);
    info!(
        stream = stream_name,
        total = state.connections.total(),
        ip = %client_ip,
        "WS client disconnected"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::PreSerializedMessage;
    use bytes::Bytes;
    use std::sync::Arc;
    use tokio::sync::broadcast;

    /// Lock down MAX_CONSECUTIVE_LAGS: an accidental bump to a very large
    /// value would silently disable the lag-disconnect path (#10).
    /// `const { assert!(..) }` instead of a runtime assertion so any future
    /// change has to be deliberate at the const-eval boundary.
    #[test]
    fn lag_policy_disconnect_threshold_is_sane() {
        const _: () = assert!(
            lag_policy::MAX_CONSECUTIVE_LAGS >= 1 && lag_policy::MAX_CONSECUTIVE_LAGS <= 16,
            "MAX_CONSECUTIVE_LAGS outside sane window [1, 16]"
        );
        // Runtime touch so the test still produces a result in the output.
        assert_eq!(lag_policy::MAX_CONSECUTIVE_LAGS, 5);
    }

    /// Reproduces the wire-level Lagged event the handle_socket loop relies
    /// on: a sender that overruns the channel capacity while a receiver
    /// doesn't drain must surface `RecvError::Lagged(n)` (not silently drop
    /// messages, not `Closed`). This is the upstream behaviour the
    /// disconnect logic counts on; if tokio ever changed it, the disconnect
    /// path would never fire.
    #[tokio::test]
    async fn broadcast_emits_lagged_when_receiver_falls_behind() {
        let (tx, mut rx) = broadcast::channel::<Arc<PreSerializedMessage>>(4);

        let dummy = || {
            Arc::new(PreSerializedMessage {
                full: Bytes::from_static(b"f"),
                lite: Bytes::from_static(b"l"),
                domains_only: Bytes::from_static(b"d"),
            })
        };

        // Push 16 messages into a 4-cap channel. The receiver never drains;
        // its next `recv().await` must therefore be Lagged.
        for _ in 0..16 {
            let _ = tx.send(dummy());
        }

        let err = rx
            .recv()
            .await
            .expect_err("receiver should report lag after overrun");
        match err {
            broadcast::error::RecvError::Lagged(n) => {
                assert!(n > 0, "Lagged(n) must report n>0; got {n}");
            }
            other => panic!("expected Lagged, got {other:?}"),
        }
    }

    /// Simulate the handle_socket lag-counter logic in isolation: feed
    /// successive Lagged errors and assert the disconnect threshold fires
    /// at exactly MAX_CONSECUTIVE_LAGS. Mirrors the conditional at
    /// lines ~272-285 without spinning up an actual WebSocket.
    #[test]
    fn lag_counter_disconnects_at_threshold() {
        let mut consecutive_lags: u32 = 0;
        let mut disconnected = false;
        for _ in 0..(lag_policy::MAX_CONSECUTIVE_LAGS as usize + 5) {
            // Mirror the Err arm of `rx.recv()` in handle_socket.
            consecutive_lags = consecutive_lags.saturating_add(1);
            if consecutive_lags >= lag_policy::MAX_CONSECUTIVE_LAGS {
                disconnected = true;
                break;
            }
        }
        assert!(disconnected, "loop must break by MAX_CONSECUTIVE_LAGS");
        assert_eq!(consecutive_lags, lag_policy::MAX_CONSECUTIVE_LAGS);
    }
}
