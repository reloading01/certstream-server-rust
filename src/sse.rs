use axum::{
    extract::{ConnectInfo, Query, State},
    http::StatusCode,
    response::{
        sse::{Event, KeepAlive, Sse},
        IntoResponse,
    },
};
use futures_util::StreamExt;
use serde::Deserialize;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio_stream::wrappers::BroadcastStream;
use tracing::info;

use crate::middleware::ConnectionLimiter;
use crate::models::PreSerializedMessage;

static SSE_CONNECTION_COUNT: AtomicU64 = AtomicU64::new(0);

/// Issue #13: Copy enum — no heap allocation, no clone per message.
/// Previously `stream_type: String` was cloned into the closure on every received message.
#[derive(Clone, Copy)]
enum SseStreamType {
    Full,
    Lite,
    DomainsOnly,
}

impl SseStreamType {
    fn from_str(s: &str) -> Self {
        match s {
            "full" => Self::Full,
            "domains" | "domains-only" => Self::DomainsOnly,
            _ => Self::Lite,
        }
    }
}

#[derive(Debug, Deserialize, Default)]
pub struct SseQueryParams {
    #[serde(default)]
    pub stream: Option<String>,
}

pub async fn handle_sse_stream(
    Query(params): Query<SseQueryParams>,
    State(state): State<Arc<crate::websocket::AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> impl IntoResponse {
    let ip = addr.ip();

    if !state.limiter.try_acquire(ip) {
        return (StatusCode::TOO_MANY_REQUESTS, "Connection limit exceeded").into_response();
    }

    let stream_type = SseStreamType::from_str(params.stream.as_deref().unwrap_or("lite"));

    let stream_enabled = match stream_type {
        SseStreamType::Full => state.streams.full,
        SseStreamType::Lite => state.streams.lite,
        SseStreamType::DomainsOnly => state.streams.domains_only,
    };
    if !stream_enabled {
        state.limiter.release(ip);
        return (StatusCode::NOT_FOUND, "Stream type not available").into_response();
    }

    let rx = state.tx.subscribe();

    SSE_CONNECTION_COUNT.fetch_add(1, Ordering::Relaxed);
    update_sse_metrics();

    info!(
        stream = params.stream.as_deref().unwrap_or("lite"),
        total = SSE_CONNECTION_COUNT.load(Ordering::Relaxed),
        ip = %ip,
        "SSE client connected"
    );

    let stream = BroadcastStream::new(rx).filter_map(move |result| {
        // stream_type is Copy — captured by value, zero allocation per message.
        std::future::ready(match result {
            Ok(msg) => process_message(msg, stream_type),
            Err(_) => None,
        })
    });

    let stream = SseStreamWrapper {
        inner: Box::pin(stream),
        limiter: state.limiter.clone(),
        client_ip: ip,
    };

    Sse::new(stream).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(15))
            .text("heartbeat"),
    ).into_response()
}

fn process_message(
    msg: Arc<PreSerializedMessage>,
    stream_type: SseStreamType,
) -> Option<Result<Event, std::convert::Infallible>> {
    let bytes = match stream_type {
        SseStreamType::Full => &msg.full,
        SseStreamType::DomainsOnly => &msg.domains_only,
        SseStreamType::Lite => &msg.lite,
    };

    std::str::from_utf8(bytes)
        .ok()
        .map(|json_str| Ok(Event::default().data(json_str)))
}

struct SseStreamWrapper<S> {
    inner: std::pin::Pin<Box<S>>,
    limiter: Arc<ConnectionLimiter>,
    client_ip: IpAddr,
}

impl<S> Drop for SseStreamWrapper<S> {
    fn drop(&mut self) {
        self.limiter.release(self.client_ip);
        SSE_CONNECTION_COUNT.fetch_sub(1, Ordering::Relaxed);
        update_sse_metrics();
        info!(
            total = SSE_CONNECTION_COUNT.load(Ordering::Relaxed),
            ip = %self.client_ip,
            "SSE client disconnected"
        );
    }
}

impl<S> futures_util::Stream for SseStreamWrapper<S>
where
    S: futures_util::Stream<Item = Result<Event, std::convert::Infallible>>,
{
    type Item = Result<Event, std::convert::Infallible>;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        self.inner.as_mut().poll_next(cx)
    }
}

fn update_sse_metrics() {
    metrics::gauge!("certstream_sse_connections")
        .set(SSE_CONNECTION_COUNT.load(Ordering::Relaxed) as f64);
}

pub fn sse_connection_count() -> u64 {
    SSE_CONNECTION_COUNT.load(Ordering::Relaxed)
}
