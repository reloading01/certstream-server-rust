use axum::{
    extract::{ConnectInfo, Query, State},
    http::{HeaderMap, StatusCode},
    response::{
        sse::{Event, KeepAlive, Sse},
        IntoResponse,
    },
};
use serde::Deserialize;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio_stream::wrappers::{errors::BroadcastStreamRecvError, BroadcastStream};
use tokio_util::sync::WaitForCancellationFutureOwned;
use tracing::{debug, info};

use crate::lag_policy::LagWindow;
use crate::middleware::{AccountLimit, ConnectionGuard};
use crate::models::PreSerializedMessage;

static SSE_CONNECTION_COUNT: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy)]
enum SseStreamType {
    Full,
    Lite,
    DomainsOnly,
    V2,
}

impl SseStreamType {
    fn from_str(s: &str) -> Self {
        match s {
            "full" => Self::Full,
            "domains" | "domains-only" => Self::DomainsOnly,
            "v2" => Self::V2,
            _ => Self::Lite,
        }
    }
}

#[derive(Debug, Deserialize, Default)]
pub struct SseQueryParams {
    #[serde(default)]
    pub stream: Option<String>,
    #[serde(flatten)]
    pub filter: crate::websocket::FilterParams,
}

pub async fn handle_sse_stream(
    Query(params): Query<SseQueryParams>,
    State(state): State<Arc<crate::websocket::AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let ip = addr.ip();

    let slot = match state.limiter.acquire(ip, AccountLimit::from_headers(&headers)) {
        Ok(slot) => slot,
        Err(rejection) => return rejection.into_response(),
    };

    let stream_type = SseStreamType::from_str(params.stream.as_deref().unwrap_or("lite"));

    let stream_enabled = match stream_type {
        SseStreamType::Full => state.streams.full,
        SseStreamType::Lite => state.streams.lite,
        SseStreamType::DomainsOnly => state.streams.domains_only,
        SseStreamType::V2 => state.streams.v2,
    };
    if !stream_enabled {
        return (StatusCode::NOT_FOUND, "Stream type not available").into_response();
    }

    let (rx, filtered) = match state.subscribe_filtered(&params.filter) {
        Ok(sub) => sub.into_receiver(),
        Err(e) => return (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    };

    SSE_CONNECTION_COUNT.fetch_add(1, Ordering::Relaxed);
    update_sse_metrics();

    info!(
        stream = params.stream.as_deref().unwrap_or("lite"),
        total = SSE_CONNECTION_COUNT.load(Ordering::Relaxed),
        ip = %ip,
        "SSE client connected"
    );

    let stream = SseStreamWrapper {
        inner: BroadcastStream::new(rx),
        filtered,
        stream_type,
        client_ip: ip,
        stats: state.stats.clone(),
        pending_bytes: 0,
        lag: LagWindow::new(Instant::now()),
        closing: false,
        shutdown: Box::pin(state.shutdown.clone().cancelled_owned()),
        _slot: slot,
    };

    Sse::new(stream)
        .keep_alive(
            KeepAlive::new()
                .interval(Duration::from_secs(15))
                .text("heartbeat"),
        )
        .into_response()
}

/// Told to a consumer that just lost messages, so a gap in the stream is a
/// visible event rather than a silent renumbering.
///
/// Sent as a *named* event: `EventSource.onmessage` only fires for the
/// default (unnamed) event type, so a client that parses every payload as a
/// certificate is unaffected, while one that cares registers
/// `addEventListener("gap", …)`.
fn gap_event(dropped: u64, disconnecting: bool) -> Event {
    Event::default().event("gap").data(format!(
        r#"{{"message_type":"gap","dropped":{dropped},"disconnecting":{disconnecting}}}"#
    ))
}

struct SseStreamWrapper {
    inner: BroadcastStream<Arc<PreSerializedMessage>>,
    /// Present only for a filtered subscription, which can also lose messages
    /// in the dispatcher before anything is matched against its filter.
    filtered: Option<crate::filter::Subscription>,
    stream_type: SseStreamType,
    client_ip: IpAddr,
    stats: Arc<crate::api::ServerStats>,
    /// Outbound bytes for this connection, pushed to the shared counter in
    /// batches. Per-message writes to the global counter would put every
    /// subscriber on the same cache line.
    pending_bytes: u64,
    lag: LagWindow,
    /// Set once the drop budget is spent; the next poll ends the stream.
    closing: bool,
    /// Ends the stream when the server is stopping, so graceful shutdown does
    /// not wait for a client that would otherwise stay connected indefinitely.
    shutdown: std::pin::Pin<Box<WaitForCancellationFutureOwned>>,
    _slot: ConnectionGuard,
}

impl SseStreamWrapper {
    /// Move this connection's accumulated bytes into the shared counter.
    fn flush_bytes(&mut self) {
        let n = std::mem::take(&mut self.pending_bytes);
        if n > 0 {
            self.stats.bytes_sent.fetch_add(n, Ordering::Relaxed);
            metrics::counter!("certstream_bytes_sent_total", "protocol" => "sse").increment(n);
        }
    }
}

impl Drop for SseStreamWrapper {
    fn drop(&mut self) {
        self.flush_bytes();
        SSE_CONNECTION_COUNT.fetch_sub(1, Ordering::Relaxed);
        update_sse_metrics();
        info!(
            total = SSE_CONNECTION_COUNT.load(Ordering::Relaxed),
            ip = %self.client_ip,
            "SSE client disconnected"
        );
    }
}

impl futures_util::Stream for SseStreamWrapper {
    type Item = Result<Event, std::convert::Infallible>;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        use std::future::Future;
        use std::task::Poll;

        if self.closing || self.shutdown.as_mut().poll(cx).is_ready() {
            return Poll::Ready(None);
        }

        // Reported ahead of the channel's own loss, and counted the same way:
        // from the consumer's side a message the dispatcher never matched and
        // one this connection could not keep up with are both gaps.
        if let Some(sub) = self.filtered.as_mut()
            && let dropped = sub.take_upstream_gap()
            && dropped > 0
        {
            metrics::counter!("certstream_sse_messages_lagged").increment(dropped);
            let over_budget = self.lag.record(Instant::now(), dropped);
            if over_budget {
                self.closing = true;
                metrics::counter!("certstream_sse_disconnect_lag").increment(1);
            }
            return Poll::Ready(Some(Ok(gap_event(dropped, over_budget))));
        }

        match std::pin::Pin::new(&mut self.inner).poll_next(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Ready(Some(Ok(msg))) => {
                let text = match self.stream_type {
                    SseStreamType::Full => &msg.full,
                    SseStreamType::DomainsOnly => &msg.domains_only,
                    SseStreamType::Lite => &msg.lite,
                    SseStreamType::V2 => &msg.v2,
                };
                if text.is_empty() {
                    // Nothing to send for this stream; poll again for the next
                    // message instead of emitting an empty event.
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
                // Payloads are pre-validated Utf8Bytes — no per-client UTF-8
                // scan here. (Event::data still copies into the event's own
                // buffer; that copy is inherent to axum's SSE Event API.)
                let event = Event::default().data(text.as_str());
                self.pending_bytes += text.len() as u64;

                // Long-lived connections would otherwise only report their
                // bytes on disconnect, which for SSE can be hours.
                const FLUSH_THRESHOLD_BYTES: u64 = 256 * 1024;
                if self.pending_bytes >= FLUSH_THRESHOLD_BYTES {
                    self.flush_bytes();
                }
                Poll::Ready(Some(Ok(event)))
            }
            Poll::Ready(Some(Err(BroadcastStreamRecvError::Lagged(dropped)))) => {
                metrics::counter!("certstream_sse_messages_lagged").increment(dropped);
                let over_budget = self.lag.record(Instant::now(), dropped);
                if over_budget {
                    self.closing = true;
                    metrics::counter!("certstream_sse_disconnect_lag").increment(1);
                    info!(
                        ip = %self.client_ip,
                        dropped = self.lag.dropped_in_window(),
                        "SSE client exceeded its drop budget, disconnecting"
                    );
                } else {
                    debug!(dropped, ip = %self.client_ip, "SSE client lagged, skipping messages");
                }
                Poll::Ready(Some(Ok(gap_event(dropped, over_budget))))
            }
        }
    }
}

fn update_sse_metrics() {
    metrics::gauge!("certstream_sse_connections")
        .set(SSE_CONNECTION_COUNT.load(Ordering::Relaxed) as f64);
}

pub fn sse_connection_count() -> u64 {
    SSE_CONNECTION_COUNT.load(Ordering::Relaxed)
}
