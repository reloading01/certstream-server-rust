use axum::{
    extract::{ConnectInfo, Query, Request, State},
    http::{header, HeaderMap, HeaderValue, Method, StatusCode},
    response::{IntoResponse, Response},
};
use bytes::Bytes;
use hyper_util::rt::TokioIo;
use serde::Deserialize;
use std::net::{IpAddr, SocketAddr};
use futures_util::{SinkExt, StreamExt};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::broadcast;
use tokio::time::{interval, timeout};
use tokio_tungstenite::tungstenite::{
    handshake::derive_accept_key,
    protocol::{
        frame::{
            coding::{CloseCode, Data, OpCode},
            Frame,
        },
        CloseFrame, Role,
    },
    Message, Utf8Bytes,
};
use tokio_tungstenite::WebSocketStream;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info};

use crate::config::StreamConfig;
use crate::deflate::{self, DeflateHub};
use crate::filter::{Filter, FilterHub};
use crate::lag_policy::LagWindow;
use crate::middleware::{ConnectionGuard, ConnectionLimiter};
use crate::models::PreSerializedMessage;

static HEARTBEAT_JSON: &str = r#"{"message_type":"heartbeat"}"#;

pub struct AppState {
    pub tx: broadcast::Sender<Arc<PreSerializedMessage>>,
    pub connections: ConnectionCounter,
    pub limiter: Arc<ConnectionLimiter>,
    pub streams: Arc<StreamConfig>,
    pub stats: Arc<crate::api::ServerStats>,
    pub filters: Arc<FilterHub>,
    /// Shared-context permessage-deflate. Dormant until a client negotiates it.
    pub deflate: Arc<DeflateHub>,
    /// Cancelled when the server is asked to stop. Streams never finish on
    /// their own, so each one ends itself on this; otherwise graceful
    /// shutdown waits for the last client to leave.
    pub shutdown: CancellationToken,
}

/// What a streaming endpoint reads from.
///
/// The two differ in more than the channel: a filtered subscriber can also
/// lose messages *upstream*, in the dispatcher, before anything was matched
/// against its filter. Only it needs to ask about that.
pub enum Subscription {
    Firehose(broadcast::Receiver<Arc<PreSerializedMessage>>),
    Filtered(crate::filter::Subscription),
}

impl Subscription {
    pub fn into_receiver(self) -> (broadcast::Receiver<Arc<PreSerializedMessage>>, Option<crate::filter::Subscription>) {
        match self {
            Self::Firehose(rx) => (rx, None),
            Self::Filtered(mut sub) => {
                let rx = std::mem::replace(&mut sub.rx, broadcast::channel(1).1);
                (rx, Some(sub))
            }
        }
    }
}

/// Optional server-side filter, shared by every streaming endpoint.
#[derive(Debug, Deserialize, Default)]
pub struct FilterParams {
    #[serde(default)]
    pub domain: Option<String>,
    #[serde(default)]
    pub issuer: Option<String>,
}

impl AppState {
    /// Resolve the query into a subscription: the unfiltered firehose when no
    /// filter terms were given, otherwise a seat in that filter's group.
    pub fn subscribe_filtered(
        &self,
        params: &FilterParams,
    ) -> Result<Subscription, crate::filter::FilterError> {
        match Filter::parse(params.domain.as_deref(), params.issuer.as_deref())? {
            Some(filter) => self.filters.subscribe(filter).map(Subscription::Filtered),
            None => Ok(Subscription::Firehose(self.tx.subscribe())),
        }
    }
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
            StreamType::DomainsOnly | StreamType::V2 => self.domains.fetch_add(1, Ordering::Relaxed),
        };
        self.update_metrics();
    }

    #[inline]
    fn decrement(&self, stream_type: StreamType) {
        match stream_type {
            StreamType::Full => self.full.fetch_sub(1, Ordering::Relaxed),
            StreamType::Lite => self.lite.fetch_sub(1, Ordering::Relaxed),
            StreamType::DomainsOnly | StreamType::V2 => self.domains.fetch_sub(1, Ordering::Relaxed),
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
    Query(params): Query<FilterParams>,
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    req: Request,
) -> Response {
    upgrade(req, state, addr, StreamType::Full, &params)
}

pub async fn handle_lite_stream(
    Query(params): Query<FilterParams>,
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    req: Request,
) -> Response {
    upgrade(req, state, addr, StreamType::Lite, &params)
}

pub async fn handle_domains_only(
    Query(params): Query<FilterParams>,
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    req: Request,
) -> Response {
    upgrade(req, state, addr, StreamType::DomainsOnly, &params)
}

pub async fn handle_v2_stream(
    Query(params): Query<FilterParams>,
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    req: Request,
) -> Response {
    upgrade(req, state, addr, StreamType::V2, &params)
}

/// Checks an HTTP/1.1 WebSocket upgrade request (RFC 6455 §4.2.1) and returns
/// its `Sec-WebSocket-Key`.
fn handshake_key(req: &Request) -> Result<&HeaderValue, (StatusCode, &'static str)> {
    fn has_token(headers: &HeaderMap, name: header::HeaderName, token: &str) -> bool {
        headers
            .get_all(name)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .flat_map(|v| v.split(','))
            .any(|t| t.trim().eq_ignore_ascii_case(token))
    }

    if req.method() != Method::GET {
        return Err((StatusCode::METHOD_NOT_ALLOWED, "WebSocket upgrade requires GET"));
    }
    let headers = req.headers();
    if !has_token(headers, header::CONNECTION, "upgrade") {
        return Err((StatusCode::BAD_REQUEST, "Connection header did not include 'upgrade'"));
    }
    if !has_token(headers, header::UPGRADE, "websocket") {
        return Err((StatusCode::BAD_REQUEST, "`Upgrade` header did not include 'websocket'"));
    }
    if headers.get(header::SEC_WEBSOCKET_VERSION).map(HeaderValue::as_bytes) != Some(b"13") {
        return Err((StatusCode::BAD_REQUEST, "`Sec-WebSocket-Version` header did not include '13'"));
    }
    if req.extensions().get::<hyper::upgrade::OnUpgrade>().is_none() {
        return Err((StatusCode::UPGRADE_REQUIRED, "connection cannot be upgraded"));
    }
    headers
        .get(header::SEC_WEBSOCKET_KEY)
        .ok_or((StatusCode::BAD_REQUEST, "`Sec-WebSocket-Key` header missing"))
}

fn upgrade(
    mut req: Request,
    state: Arc<AppState>,
    addr: SocketAddr,
    stream_type: StreamType,
    params: &FilterParams,
) -> Response {
    let accept = match handshake_key(&req) {
        Ok(key) => derive_accept_key(key.as_bytes()),
        Err(rejection) => return rejection.into_response(),
    };
    let ip = addr.ip();
    let Some(guard) = state.limiter.acquire(ip) else {
        return (StatusCode::TOO_MANY_REQUESTS, "Connection limit exceeded").into_response();
    };
    // Before the upgrade, so a rejected filter is an HTTP error the client
    // can read rather than an immediately-closed WebSocket.
    let feed = match state.subscribe_filtered(params) {
        // A filtered stream is a subset of the broadcast, so it cannot share
        // the compressed one.
        Ok(Subscription::Firehose(rx))
            if deflate::negotiate(
                req.headers()
                    .get_all(header::SEC_WEBSOCKET_EXTENSIONS)
                    .iter()
                    .filter_map(|v| v.to_str().ok()),
            ) =>
        {
            drop(rx);
            Feed::Deflate {
                seat: state.deflate.subscribe(stream_type.format()),
                synced: false,
            }
        }
        Ok(sub) => {
            let (rx, filtered) = sub.into_receiver();
            Feed::Raw { rx, filtered }
        }
        Err(e) => return (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    };
    let compressed = matches!(feed, Feed::Deflate { .. });

    let on_upgrade = hyper::upgrade::on(&mut req);
    // `guard` rides into the task rather than being released at the end of
    // `handle_socket`: when the handshake never completes the task returns
    // early, and that path has to give the slot back too.
    tokio::spawn(async move {
        let Ok(upgraded) = on_upgrade.await else {
            return;
        };
        let socket = WebSocketStream::from_raw_socket(TokioIo::new(upgraded), Role::Server, None).await;
        handle_socket(socket, feed, stream_type, state, ip, guard).await;
    });

    let mut response = Response::builder()
        .status(StatusCode::SWITCHING_PROTOCOLS)
        .header(header::CONNECTION, "upgrade")
        .header(header::UPGRADE, "websocket")
        .header(header::SEC_WEBSOCKET_ACCEPT, accept);
    if compressed {
        response = response.header(header::SEC_WEBSOCKET_EXTENSIONS, deflate::EXTENSION_RESPONSE);
    }
    response
        .body(axum::body::Body::empty())
        .expect("static upgrade response is valid")
}

#[derive(Clone, Copy)]
enum StreamType {
    Full,
    Lite,
    DomainsOnly,
    V2,
}

impl StreamType {
    fn format(self) -> deflate::Format {
        match self {
            Self::Full => deflate::Format::Full,
            Self::Lite => deflate::Format::Lite,
            Self::DomainsOnly => deflate::Format::DomainsOnly,
            Self::V2 => deflate::Format::V2,
        }
    }

    fn payload(self, msg: &PreSerializedMessage) -> &Utf8Bytes {
        match self {
            Self::Full => &msg.full,
            Self::Lite => &msg.lite,
            Self::DomainsOnly => &msg.domains_only,
            Self::V2 => &msg.v2,
        }
    }
}

/// Where a connection's messages come from.
enum Feed {
    Raw {
        rx: broadcast::Receiver<Arc<PreSerializedMessage>>,
        filtered: Option<crate::filter::Subscription>,
    },
    /// The shared compressed stream. `synced` is false until the connection
    /// reaches a compressor reset, and again after it loses a message.
    Deflate { seat: deflate::Seat, synced: bool },
}

/// The outcome of waiting on a [`Feed`].
struct Step {
    send: Option<Message>,
    /// Messages this connection will never see.
    lost: u64,
    closed: bool,
}

impl Feed {
    /// Cancel-safe: the only await is the channel receive.
    async fn next(&mut self, stream_type: StreamType) -> Step {
        let mut step = Step { send: None, lost: 0, closed: false };
        match self {
            Self::Raw { rx, filtered } => {
                let result = rx.recv().await;
                if let Some(sub) = filtered.as_mut() {
                    step.lost += sub.take_upstream_gap();
                }
                match result {
                    Ok(msg) => {
                        // Pre-validated Utf8Bytes: cloning is a refcount bump
                        // on the shared Bytes, no per-client copy or UTF-8 scan.
                        let text = stream_type.payload(&msg);
                        if !text.is_empty() {
                            step.send = Some(Message::Text(text.clone()));
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => step.lost += n,
                    Err(broadcast::error::RecvError::Closed) => step.closed = true,
                }
            }
            Self::Deflate { seat, synced } => match seat.rx.recv().await {
                Ok(msg) => {
                    *synced |= msg.boundary;
                    let payload = msg.payload(stream_type.format());
                    if *synced && !payload.is_empty() {
                        step.send = Some(compressed_text(payload.clone()));
                    }
                }
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    *synced = false;
                    step.lost = n;
                }
                Err(broadcast::error::RecvError::Closed) => step.closed = true,
            },
        }
        step
    }
}

/// A text frame whose payload is already permessage-deflate compressed.
fn compressed_text(payload: Bytes) -> Message {
    let mut frame = Frame::message(payload, OpCode::Data(Data::Text), true);
    frame.header_mut().rsv1 = true;
    Message::Frame(frame)
}

type Socket = WebSocketStream<TokioIo<hyper::upgrade::Upgraded>>;

async fn handle_socket(
    socket: Socket,
    mut feed: Feed,
    stream_type: StreamType,
    state: Arc<AppState>,
    client_ip: IpAddr,
    _slot: ConnectionGuard,
) {
    let (mut sender, mut receiver) = socket.split();

    state.connections.increment(stream_type);
    let stream_name = match stream_type {
        StreamType::Full => "full",
        StreamType::Lite => "lite",
        StreamType::DomainsOnly => "domains",
        StreamType::V2 => "v2",
    };
    let compressed = matches!(feed, Feed::Deflate { .. });

    info!(
        stream = stream_name,
        compressed,
        total = state.connections.total(),
        ip = %client_ip,
        "WS client connected"
    );

    // Outbound bytes are accumulated per connection and pushed to the shared
    // counter in batches. Doing it per frame would turn one broadcast into one
    // atomic write per subscriber, which is the one thing the pre-serialized
    // fan-out path is built to avoid.
    let mut pending_bytes: u64 = 0;
    let mut pending_frames: u32 = 0;
    const BYTES_FLUSH_FRAMES: u32 = 256;

    let mut heartbeat_interval = interval(Duration::from_secs(30));
    let mut ping_interval = interval(Duration::from_secs(15));
    let mut last_pong = std::time::Instant::now();
    let pong_timeout = Duration::from_secs(45);

    // Outbound write deadline. A client whose TCP send buffer is full will
    // back-pressure the Sink and `sender.send().await` blocks indefinitely.
    // While blocked, this task can't drain its feed or service pongs — the
    // broadcast Receiver keeps growing (other clients lag), the FD stays
    // open, and the connection counter is poisoned. 10 s is a generous
    // upper bound: any healthy client drains tens of KB in <1 s.
    const WRITE_TIMEOUT: Duration = Duration::from_secs(10);
    let mut lag_window = LagWindow::new(std::time::Instant::now());

    // Helper: send with timeout. Returns false on send error OR timeout,
    // which the caller uses to break the loop.
    async fn send_with_deadline(
        sender: &mut futures_util::stream::SplitSink<Socket, Message>,
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

            _ = state.shutdown.cancelled() => {
                let going_away = Message::Close(Some(CloseFrame {
                    code: CloseCode::Away,
                    reason: Utf8Bytes::from_static("server shutting down"),
                }));
                send_with_deadline(&mut sender, going_away, WRITE_TIMEOUT).await;
                break;
            }

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
                    Some(Ok(Message::Close(_))) | Some(Err(_)) | None => {
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
                if !send_with_deadline(&mut sender, Message::Ping(Bytes::new()), WRITE_TIMEOUT).await {
                    break;
                }
            }

            _ = heartbeat_interval.tick() => {
                // Text frame per certstream wire convention — JSON over WebSocket
                // is Text, not Binary — a client that demuxes by frame type
                // reads a Binary heartbeat as a protocol error. Sent
                // uncompressed even on a compressed connection, which RFC 7692
                // allows and which leaves the decompressor's window untouched.
                let hb = Message::Text(Utf8Bytes::from_static(HEARTBEAT_JSON));
                if !send_with_deadline(&mut sender, hb, WRITE_TIMEOUT).await {
                    break;
                }
            }

            step = feed.next(stream_type) => {
                if step.lost > 0 {
                    debug!(lagged = step.lost, ip = %client_ip, "client lagged, skipping messages");
                    metrics::counter!("certstream_ws_messages_lagged").increment(step.lost);
                    if lag_window.record(std::time::Instant::now(), step.lost) {
                        debug!(
                            ip = %client_ip,
                            dropped = lag_window.dropped_in_window(),
                            "client exceeded its drop budget, disconnecting"
                        );
                        metrics::counter!("certstream_ws_disconnect_lag").increment(1);
                        break;
                    }
                }
                if step.closed {
                    break;
                }
                if let Some(frame) = step.send {
                    let frame_len = frame.len() as u64;
                    if !send_with_deadline(&mut sender, frame, WRITE_TIMEOUT).await {
                        break;
                    }
                    pending_bytes += frame_len;
                    pending_frames += 1;
                    if pending_frames >= BYTES_FLUSH_FRAMES {
                        flush_bytes_sent(&state, &mut pending_bytes, &mut pending_frames);
                    }
                }
            }
        }
    }

    flush_bytes_sent(&state, &mut pending_bytes, &mut pending_frames);
    state.connections.decrement(stream_type);
    info!(
        stream = stream_name,
        total = state.connections.total(),
        ip = %client_ip,
        "WS client disconnected"
    );
}

/// Push a connection's accumulated outbound bytes to the shared counter.
fn flush_bytes_sent(state: &AppState, pending_bytes: &mut u64, pending_frames: &mut u32) {
    if *pending_bytes == 0 {
        return;
    }
    state
        .stats
        .bytes_sent
        .fetch_add(*pending_bytes, Ordering::Relaxed);
    metrics::counter!("certstream_bytes_sent_total", "protocol" => "websocket")
        .increment(*pending_bytes);
    *pending_bytes = 0;
    *pending_frames = 0;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::PreSerializedMessage;
    use std::sync::Arc;
    use tokio::sync::broadcast;

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
                full: Utf8Bytes::from_static("f"),
                lite: Utf8Bytes::from_static("l"),
                domains_only: Utf8Bytes::from_static("d"),
                v2: Utf8Bytes::from_static("2"),
                leaf: None,
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

    /// The failed-upgrade path. axum's `on_upgrade` drops the callback
    /// without calling it when the handshake never completes, so a slot
    /// released inside `handle_socket` is a slot leaked on every aborted
    /// WebSocket. Build the same callback `upgrade()` builds, drop it
    /// uninvoked, and assert the limiter got its slot back.
    #[test]
    fn dropping_the_upgrade_callback_returns_the_slot() {
        let limiter = ConnectionLimiter::new(
            crate::config::ConnectionLimitConfig {
                enabled: true,
                max_connections: 1,
                per_ip_limit: Some(1),
            },
            None,
        );
        let ip: IpAddr = "127.0.0.1".parse().unwrap();

        let guard = limiter.acquire(ip).expect("first slot");
        assert_eq!(limiter.current_connections(), 1);
        assert!(limiter.acquire(ip).is_none(), "limit of 1 must be enforced");

        // What axum does to the callback when the upgrade fails.
        let callback = move |_socket: ()| async move {
            let _slot = guard;
        };
        drop(callback);

        assert_eq!(
            limiter.current_connections(),
            0,
            "an upgrade that never ran must not hold the slot"
        );
        assert!(limiter.acquire(ip).is_some(), "slot must be reusable");
    }
}
