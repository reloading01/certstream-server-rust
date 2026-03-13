use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
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
use tokio::time::interval;
use tracing::{debug, info};

use crate::config::StreamConfig;
use crate::middleware::ConnectionLimiter;
use crate::models::PreSerializedMessage;

static HEARTBEAT_JSON: &str = r#"{"message_type":"heartbeat"}"#;

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

    loop {
        tokio::select! {
            biased;

            msg = receiver.next() => {
                match msg {
                    Some(Ok(Message::Ping(data))) => {
                        if sender.send(Message::Pong(data)).await.is_err() {
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
                if sender.send(Message::Ping(bytes::Bytes::new())).await.is_err() {
                    break;
                }
            }

            _ = heartbeat_interval.tick() => {
                if sender.send(Message::Binary(bytes::Bytes::from_static(HEARTBEAT_JSON.as_bytes()))).await.is_err() {
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

                        if sender.send(Message::Binary(bytes)).await.is_err() {
                            break;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        debug!(lagged = n, "client lagged, skipping messages");
                        metrics::counter!("certstream_ws_messages_lagged").increment(n);
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
