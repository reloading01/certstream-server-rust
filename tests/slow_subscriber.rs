//! Drives the real WebSocket and SSE fan-out loops against a subscriber that
//! falls behind, over a real socket.
//!
//! The unit tests around the drop budget check the arithmetic; these check
//! that the arithmetic is wired to the send loop — that a subscriber which
//! misses more than its budget is actually cut, that SSE tells the consumer
//! about the gap instead of renumbering silently, and that neither path
//! leaks the connection slot it took.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio_tungstenite::tungstenite::Utf8Bytes;
use axum::routing::get;
use axum::Router;
use certstream_server_rust::api::ServerStats;
use certstream_server_rust::config::{ConnectionLimitConfig, StreamConfig};
use certstream_server_rust::filter::FilterHub;
use certstream_server_rust::deflate::DeflateHub;
use certstream_server_rust::middleware::ConnectionLimiter;
use certstream_server_rust::models::PreSerializedMessage;
use certstream_server_rust::sse::handle_sse_stream;
use certstream_server_rust::websocket::{handle_lite_stream, AppState, ConnectionCounter};
use tokio::sync::broadcast;
use tokio_util::sync::CancellationToken;

/// Smaller than any real deployment so a burst overruns it immediately —
/// what matters is that the receiver falls behind, not by how much.
const CHANNEL_CAPACITY: usize = 4;

/// Comfortably over `lag_policy::MAX_DROPPED_PER_WINDOW`, so the very first
/// `Lagged` the fan-out loop sees already spends the whole budget.
const HOPELESS_BURST: usize = 1200;

/// Well under the budget: a gap the subscriber should be told about and
/// survive.
const SURVIVABLE_BURST: usize = 100;

struct Harness {
    addr: SocketAddr,
    tx: broadcast::Sender<Arc<PreSerializedMessage>>,
    limiter: Arc<ConnectionLimiter>,
    shutdown: CancellationToken,
    server: tokio::task::JoinHandle<()>,
}

impl Harness {
    async fn start() -> Self {
        let (tx, _) = broadcast::channel(CHANNEL_CAPACITY);
        // Limits on, and generous: the point is to watch the slot come back,
        // not to test rejection.
        let limiter = ConnectionLimiter::new(
            ConnectionLimitConfig {
                enabled: true,
                max_connections: 64,
                per_ip_limit: Some(64),
            },
            None,
        );

        let shutdown = CancellationToken::new();
        let state = Arc::new(AppState {
            shutdown: shutdown.clone(),
            tx: tx.clone(),
            connections: ConnectionCounter::new(),
            limiter: Arc::clone(&limiter),
            streams: Arc::new(StreamConfig::default()),
            stats: Arc::new(ServerStats::new()),
            filters: FilterHub::new(tx.clone()),
            deflate: DeflateHub::new(tx.clone(), 1024),
        });

        let app = Router::new()
            .route("/", get(handle_lite_stream))
            .route("/sse", get(handle_sse_stream))
            .with_state(state);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let stop = shutdown.clone();
        let server = tokio::spawn(async move {
            let _ = axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .with_graceful_shutdown(async move { stop.cancelled().await })
            .await;
        });

        Self {
            addr,
            tx,
            limiter,
            shutdown,
            server,
        }
    }

    /// `broadcast::Sender::send` is synchronous and non-blocking, so this
    /// loop outruns any subscriber task: the channel wraps long before the
    /// fan-out loop has written the first message to its socket. That is the
    /// same shape as a real slow client, minus the wall-clock wait.
    fn burst(&self, count: usize) {
        let msg = Arc::new(PreSerializedMessage {
            full: Utf8Bytes::from_static(r#"{"message_type":"certificate_update"}"#),
            lite: Utf8Bytes::from_static(r#"{"message_type":"certificate_update"}"#),
            domains_only: Utf8Bytes::from_static(r#"{"message_type":"dns_entries"}"#),
            v2: Utf8Bytes::from_static(r#"{"message_type":"certificate_update","version":2}"#),
            leaf: None,
        });
        for _ in 0..count {
            let _ = self.tx.send(Arc::clone(&msg));
        }
    }

    /// Poll until every slot has been handed back, or give up. Release is
    /// driven by the connection task noticing the socket is gone, so it is
    /// not instantaneous.
    async fn await_no_connections(&self) -> u32 {
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if self.limiter.current_connections() == 0 {
                return 0;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        self.limiter.current_connections()
    }
}

/// Terminating chunk of an HTTP/1.1 chunked body. An SSE stream that ends
/// server-side finishes the response here; hyper then keeps the connection
/// alive for a further request, so waiting for a TCP EOF would hang.
const LAST_CHUNK: &[u8] = b"\r\n0\r\n\r\n";

/// Read from `sock` until the response ends or `deadline` passes. Returns
/// everything read plus whether the server actually ended the stream — by
/// closing the connection (WebSocket) or terminating the chunked body (SSE).
fn read_until_end(sock: &mut TcpStream, deadline: Duration) -> (Vec<u8>, bool) {
    sock.set_read_timeout(Some(Duration::from_millis(250)))
        .unwrap();
    let stop = Instant::now() + deadline;
    let mut out = Vec::new();
    let mut buf = [0u8; 8192];
    while Instant::now() < stop {
        match sock.read(&mut buf) {
            Ok(0) => return (out, true),
            Ok(n) => {
                out.extend_from_slice(&buf[..n]);
                if out.ends_with(LAST_CHUNK) {
                    return (out, true);
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => continue,
            Err(_) => return (out, true),
        }
    }
    (out, false)
}

fn connect(addr: SocketAddr, request: &str) -> TcpStream {
    let mut sock = TcpStream::connect(addr).unwrap();
    sock.write_all(request.as_bytes()).unwrap();
    sock.flush().unwrap();
    sock
}

/// Wait for the response head so the handler has definitely subscribed
/// before the burst starts.
fn read_response_head(sock: &mut TcpStream) -> String {
    sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        match sock.read(&mut byte) {
            Ok(0) => break,
            Ok(_) => head.push(byte[0]),
            Err(e) => panic!("reading response head: {e}"),
        }
    }
    String::from_utf8_lossy(&head).into_owned()
}

fn ws_request(addr: SocketAddr) -> String {
    format!(
        "GET / HTTP/1.1\r\n\
         Host: {addr}\r\n\
         Connection: Upgrade\r\n\
         Upgrade: websocket\r\n\
         Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
         Sec-WebSocket-Version: 13\r\n\
         \r\n"
    )
}

fn sse_request(addr: SocketAddr, stream: &str) -> String {
    format!(
        "GET /sse?stream={stream} HTTP/1.1\r\n\
         Host: {addr}\r\n\
         Accept: text/event-stream\r\n\
         \r\n"
    )
}

/// The regression the windowed policy exists for, exercised through the real
/// `handle_socket` select loop: a subscriber that misses more than its budget
/// gets disconnected instead of holding a slot and a file descriptor forever.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn websocket_subscriber_over_its_drop_budget_is_disconnected() {
    let h = Harness::start().await;

    let mut sock = connect(h.addr, &ws_request(h.addr));
    let head = read_response_head(&mut sock);
    assert!(
        head.starts_with("HTTP/1.1 101"),
        "expected a websocket upgrade, got:\n{head}"
    );

    // Give the upgraded connection task a moment to reach its select loop.
    tokio::time::sleep(Duration::from_millis(200)).await;
    h.burst(HOPELESS_BURST);

    // The client keeps reading throughout, so writes never stall: the only
    // thing that can end this connection is the drop budget.
    let (_read, closed) = tokio::task::spawn_blocking(move || {
        let out = read_until_end(&mut sock, Duration::from_secs(15));
        drop(sock);
        out
    })
    .await
    .unwrap();

    assert!(
        closed,
        "a subscriber past its drop budget must be disconnected"
    );
    assert_eq!(
        h.await_no_connections().await,
        0,
        "the disconnected subscriber must give its slot back"
    );
}

/// SSE's counterpart, plus the part a consumer can actually see: the gap is
/// announced on the wire before the stream ends.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sse_subscriber_is_told_about_the_gap_and_then_cut() {
    let h = Harness::start().await;

    let mut sock = connect(h.addr, &sse_request(h.addr, "lite"));
    let head = read_response_head(&mut sock);
    assert!(
        head.starts_with("HTTP/1.1 200"),
        "expected an SSE response, got:\n{head}"
    );
    assert!(
        head.to_ascii_lowercase().contains("text/event-stream"),
        "expected an event-stream content type, got:\n{head}"
    );

    tokio::time::sleep(Duration::from_millis(200)).await;
    h.burst(HOPELESS_BURST);

    let (body, closed) = tokio::task::spawn_blocking(move || {
        let out = read_until_end(&mut sock, Duration::from_secs(15));
        drop(sock);
        out
    })
    .await
    .unwrap();
    let body = String::from_utf8_lossy(&body);

    assert!(
        body.contains("event: gap"),
        "dropped messages must reach the consumer as a named `gap` event, got:\n{body}"
    );
    assert!(
        body.contains(r#""message_type":"gap""#),
        "gap payload must be self-describing JSON, got:\n{body}"
    );
    assert!(
        body.contains(r#""disconnecting":true"#),
        "the final gap must say the connection is being cut, got:\n{body}"
    );
    assert!(
        closed,
        "the SSE response must end once the drop budget is spent, got:\n{body}"
    );
    assert_eq!(
        h.await_no_connections().await,
        0,
        "the disconnected subscriber must give its slot back"
    );
}

/// A gap inside the budget is reported and survived. Without this the first
/// test would also pass on a build that cut every lagging client instantly.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sse_survives_a_gap_inside_its_budget() {
    let h = Harness::start().await;

    let mut sock = connect(h.addr, &sse_request(h.addr, "lite"));
    let head = read_response_head(&mut sock);
    assert!(head.starts_with("HTTP/1.1 200"), "got:\n{head}");

    tokio::time::sleep(Duration::from_millis(200)).await;
    h.burst(SURVIVABLE_BURST);

    // Keep feeding it so there is something to read after the gap.
    for _ in 0..20 {
        tokio::time::sleep(Duration::from_millis(50)).await;
        h.burst(1);
    }

    let body = tokio::task::spawn_blocking(move || {
        let (out, _) = read_until_end(&mut sock, Duration::from_secs(3));
        drop(sock);
        out
    })
    .await
    .unwrap();
    let body = String::from_utf8_lossy(&body);

    assert!(
        body.contains("event: gap"),
        "a gap inside the budget must still be announced, got:\n{body}"
    );
    assert!(
        body.contains(r#""disconnecting":false"#),
        "a survivable gap must not claim the connection is ending, got:\n{body}"
    );
    assert!(
        body.contains("certificate_update"),
        "the stream must keep delivering after a survivable gap, got:\n{body}"
    );
}

/// The connection slot is taken before the WebSocket handshake and released
/// by a guard that rides into the upgrade callback. A client that vanishes
/// mid-handshake exercises the path where axum drops that callback without
/// ever calling it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn aborted_websocket_handshake_does_not_leak_a_slot() {
    let h = Harness::start().await;

    for _ in 0..32 {
        let sock = connect(h.addr, &ws_request(h.addr));
        // Gone before the upgrade can complete. Whether hyper fails the
        // upgrade or completes it onto a dead socket is a race we do not
        // control — the slot has to come back either way.
        let _ = sock.shutdown(std::net::Shutdown::Both);
        drop(sock);
    }

    assert_eq!(
        h.await_no_connections().await,
        0,
        "aborted handshakes must not accumulate connection slots"
    );
}

/// SIGTERM with clients attached: axum's graceful shutdown waits for every
/// connection to finish, and a WebSocket or SSE stream never does on its own,
/// so the process used to sit there until the clients went away (observed:
/// more than four minutes). Both stream kinds must end when the server is told
/// to stop.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn open_streams_end_when_the_server_shuts_down() {
    let h = Harness::start().await;

    let mut ws = connect(h.addr, &ws_request(h.addr));
    assert!(read_response_head(&mut ws).starts_with("HTTP/1.1 101"));
    let mut sse = connect(h.addr, &sse_request(h.addr, "lite"));
    assert!(read_response_head(&mut sse).starts_with("HTTP/1.1 200"));
    tokio::time::sleep(Duration::from_millis(200)).await;

    h.shutdown.cancel();

    let (ws_closed, sse_closed) = tokio::task::spawn_blocking(move || {
        let (_, ws_closed) = read_until_end(&mut ws, Duration::from_secs(5));
        let (_, sse_closed) = read_until_end(&mut sse, Duration::from_secs(5));
        (ws_closed, sse_closed)
    })
    .await
    .unwrap();

    assert!(ws_closed, "the WebSocket must be closed on shutdown");
    assert!(sse_closed, "the SSE response must end on shutdown");
    tokio::time::timeout(Duration::from_secs(5), h.server)
        .await
        .expect("the server must finish shutting down with clients attached")
        .unwrap();
}

/// A certificate with no DNS names (an IP address certificate) has nothing to
/// say on the domains-only stream. Its payload is empty and every send path
/// must skip it instead of putting an empty frame or event on the wire.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_empty_payload_is_skipped_not_sent() {
    let h = Harness::start().await;

    let mut ws = connect(h.addr, &ws_request(h.addr));
    assert!(read_response_head(&mut ws).starts_with("HTTP/1.1 101"));
    let mut sse = connect(h.addr, &sse_request(h.addr, "lite"));
    assert!(read_response_head(&mut sse).starts_with("HTTP/1.1 200"));
    tokio::time::sleep(Duration::from_millis(200)).await;

    let message = |lite: &'static str| {
        Arc::new(PreSerializedMessage {
            full: Utf8Bytes::from_static(""),
            lite: Utf8Bytes::from_static(lite),
            domains_only: Utf8Bytes::from_static(""),
            v2: Utf8Bytes::from_static(""),
            leaf: None,
        })
    };
    h.tx.send(message("")).unwrap();
    h.tx.send(message(r#"{"message_type":"after_the_empty_one"}"#))
        .unwrap();

    let (ws_bytes, sse_bytes) = tokio::task::spawn_blocking(move || {
        let (ws_bytes, _) = read_until_end(&mut ws, Duration::from_secs(2));
        let (sse_bytes, _) = read_until_end(&mut sse, Duration::from_secs(2));
        (ws_bytes, sse_bytes)
    })
    .await
    .unwrap();

    assert!(
        String::from_utf8_lossy(&ws_bytes).contains("after_the_empty_one"),
        "the message after the empty one must still arrive"
    );
    assert!(
        !ws_bytes.windows(2).any(|w| w == [0x81, 0x00]),
        "an empty text frame must not be sent"
    );
    let sse_body = String::from_utf8_lossy(&sse_bytes);
    assert!(sse_body.contains("after_the_empty_one"));
    assert!(
        !sse_body.contains("data: \n\n"),
        "an empty SSE event must not be sent, got:\n{sse_body}"
    );
}
