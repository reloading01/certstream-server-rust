//! Server-side subscription filters, over a real socket.
//!
//! The unit tests in `filter` cover the matching rules. This covers the
//! wiring: that a filtered subscriber gets only its matches, that the
//! unfiltered stream is unaffected, and that a rejected filter is an HTTP
//! error rather than a stream that opens and immediately dies.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::routing::get;
use axum::Router;
use certstream_server_rust::api::ServerStats;
use certstream_server_rust::config::{ConnectionLimitConfig, StreamConfig};
use certstream_server_rust::deflate::DeflateHub;
use certstream_server_rust::filter::FilterHub;
use certstream_server_rust::middleware::ConnectionLimiter;
use certstream_server_rust::models::{Extensions, LeafCert, PreSerializedMessage, Subject};
use certstream_server_rust::sse::handle_sse_stream;
use certstream_server_rust::websocket::{AppState, ConnectionCounter};
use smallvec::SmallVec;
use tokio_tungstenite::tungstenite::Utf8Bytes;
use tokio::sync::broadcast;

struct Harness {
    addr: SocketAddr,
    tx: broadcast::Sender<Arc<PreSerializedMessage>>,
    filters: Arc<FilterHub>,
}

async fn start() -> Harness {
    let (tx, _) = broadcast::channel(1024);
    let filters = FilterHub::new(tx.clone());
    let state = Arc::new(AppState {
        tx: tx.clone(),
        connections: ConnectionCounter::new(),
        limiter: ConnectionLimiter::new(
            ConnectionLimitConfig {
                enabled: false,
                max_connections: 1000,
                per_ip_limit: None,
            },
            None,
        ),
        streams: Arc::new(StreamConfig::default()),
        stats: Arc::new(ServerStats::new()),
        filters: Arc::clone(&filters),
        deflate: DeflateHub::new(tx.clone(), 1024),
        shutdown: tokio_util::sync::CancellationToken::new(),
    });

    let app = Router::new()
        .route("/sse", get(handle_sse_stream))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await;
    });

    Harness { addr, tx, filters }
}

/// A message carrying both the payload a subscriber would see and the leaf
/// the filters match on, exactly as the ingest path builds it.
fn message(domain: &str, issuer_o: &str) -> Arc<PreSerializedMessage> {
    let mut all_domains: SmallVec<[String; 4]> = SmallVec::new();
    all_domains.push(domain.to_string());

    let payload = Utf8Bytes::from(format!(
        r#"{{"message_type":"certificate_update","domain":"{domain}"}}"#
    ));
    Arc::new(PreSerializedMessage {
        full: payload.clone(),
        lite: payload.clone(),
        domains_only: payload.clone(),
        v2: payload,
        leaf: Some(Arc::new(LeafCert {
            subject: Subject::default(),
            issuer: Subject {
                cn: Some("R10".to_string()),
                o: Some(issuer_o.to_string()),
                ..Default::default()
            },
            serial_number: String::new(),
            not_before: 0,
            not_after: 0,
            fingerprint: Arc::from(""),
            sha1: String::new(),
            sha256: String::new(),
            sha256_raw: [0u8; 32],
            signature_algorithm: std::borrow::Cow::Borrowed("test"),
            is_ca: false,
            all_domains,
            as_der: None,
            extensions: Extensions::default(),
        })),
    })
}

fn open_sse(addr: SocketAddr, query: &str) -> TcpStream {
    let mut sock = TcpStream::connect(addr).unwrap();
    sock.write_all(
        format!(
            "GET /sse?{query} HTTP/1.1\r\nHost: {addr}\r\nAccept: text/event-stream\r\n\r\n"
        )
        .as_bytes(),
    )
    .unwrap();
    sock.flush().unwrap();
    sock
}

fn read_head(sock: &mut TcpStream) -> String {
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

fn drain(mut sock: TcpStream, window: Duration) -> String {
    sock.set_read_timeout(Some(Duration::from_millis(200)))
        .unwrap();
    let stop = Instant::now() + window;
    let mut out = Vec::new();
    let mut buf = [0u8; 8192];
    while Instant::now() < stop {
        match sock.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => out.extend_from_slice(&buf[..n]),
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut => {}
            Err(_) => break,
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_filtered_subscriber_receives_only_its_matches() {
    let h = start().await;

    let mut filtered = open_sse(h.addr, "stream=lite&domain=example.com");
    assert!(read_head(&mut filtered).starts_with("HTTP/1.1 200"));
    let mut unfiltered = open_sse(h.addr, "stream=lite");
    assert!(read_head(&mut unfiltered).starts_with("HTTP/1.1 200"));

    // Let the filter dispatcher subscribe before anything is published.
    tokio::time::sleep(Duration::from_millis(300)).await;

    for msg in [
        message("www.example.com", "Let's Encrypt"),
        message("notexample.com", "Let's Encrypt"),
        message("other.org", "Let's Encrypt"),
        message("deep.sub.example.com", "Let's Encrypt"),
    ] {
        let _ = h.tx.send(msg);
        tokio::time::sleep(Duration::from_millis(30)).await;
    }

    let filtered_body =
        tokio::task::spawn_blocking(move || drain(filtered, Duration::from_secs(2)))
            .await
            .unwrap();
    let unfiltered_body =
        tokio::task::spawn_blocking(move || drain(unfiltered, Duration::from_secs(2)))
            .await
            .unwrap();

    assert!(filtered_body.contains("www.example.com"), "{filtered_body}");
    assert!(
        filtered_body.contains("deep.sub.example.com"),
        "{filtered_body}"
    );
    assert!(
        !filtered_body.contains("notexample.com"),
        "label-boundary violation reached a subscriber:\n{filtered_body}"
    );
    assert!(!filtered_body.contains("other.org"), "{filtered_body}");

    // The unfiltered stream is untouched by anyone else's filter.
    for name in ["www.example.com", "notexample.com", "other.org"] {
        assert!(unfiltered_body.contains(name), "{unfiltered_body}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn domain_and_issuer_narrow_together() {
    let h = start().await;

    let mut sock = open_sse(h.addr, "stream=lite&domain=example.com&issuer=let%27s%20encrypt");
    assert!(read_head(&mut sock).starts_with("HTTP/1.1 200"));
    tokio::time::sleep(Duration::from_millis(300)).await;

    for msg in [
        message("a.example.com", "Let's Encrypt"),
        message("b.example.com", "Google Trust Services"),
    ] {
        let _ = h.tx.send(msg);
        tokio::time::sleep(Duration::from_millis(30)).await;
    }

    let body = tokio::task::spawn_blocking(move || drain(sock, Duration::from_secs(2)))
        .await
        .unwrap();

    assert!(body.contains("a.example.com"), "{body}");
    assert!(!body.contains("b.example.com"), "{body}");
}

/// A filter the server will not evaluate has to fail loudly at subscribe
/// time, not open a stream that silently delivers nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_rejected_filter_is_an_http_error() {
    let h = start().await;

    let too_many: Vec<String> = (0..30).map(|i| format!("d{i}.com")).collect();
    let mut sock = open_sse(h.addr, &format!("domain={}", too_many.join(",")));
    let head = read_head(&mut sock);
    assert!(head.starts_with("HTTP/1.1 400"), "got:\n{head}");

    let mut sock = open_sse(h.addr, "domain=a.com,,b.com");
    let head = read_head(&mut sock);
    assert!(head.starts_with("HTTP/1.1 400"), "got:\n{head}");
}

/// The dispatcher only exists while a filter group does. If it outlived the
/// last filtered subscriber it would hold a permanent subscription to the
/// main channel and defeat the guard that skips serialization on an idle
/// server.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn filters_leave_no_subscriber_behind() {
    let h = start().await;
    assert!(!h.filters.active());
    assert_eq!(h.tx.receiver_count(), 0);

    {
        let mut sock = open_sse(h.addr, "stream=lite&domain=example.com");
        assert!(read_head(&mut sock).starts_with("HTTP/1.1 200"));
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(h.filters.active(), "a filtered subscriber must arm the hub");
        assert!(
            h.tx.receiver_count() >= 1,
            "the dispatcher must be reading the main channel"
        );
    }

    // The dispatcher notices on its next message that the group is empty.
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        let _ = h.tx.send(message("anything.example", "X"));
        if h.tx.receiver_count() == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    assert_eq!(
        h.tx.receiver_count(),
        0,
        "the dispatcher must release the main channel once no filters remain"
    );
    assert!(!h.filters.active());
}
