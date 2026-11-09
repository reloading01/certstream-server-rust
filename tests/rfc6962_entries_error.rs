//! An RFC 6962 log that rejects a get-entries range below its STH once must
//! have that range requested again, not skipped.

use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::Json;
use axum::Router;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::routing::get;
use certstream_server_rust::api::{CertificateCache, LogTracker, ServerStats};
use certstream_server_rust::config::{CtLogConfig, CustomCtLog, StateRecovery, StreamConfig};
use certstream_server_rust::ct::static_ct::IssuerCache;
use certstream_server_rust::ct::watcher::run_watcher_with_cache;
use certstream_server_rust::ct::{CtLog, WatcherContext};
use certstream_server_rust::dedup::DedupFilter;
use certstream_server_rust::filter::FilterHub;
use certstream_server_rust::state::StateManager;
use parking_lot::Mutex;
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::sync::broadcast;
use tokio_util::sync::CancellationToken;

type Requests = Arc<Mutex<Vec<(u64, u64)>>>;

#[derive(Deserialize)]
struct Range {
    start: u64,
    end: u64,
}

async fn get_sth(State(requests): State<Requests>) -> Json<Value> {
    let grown = !requests.lock().is_empty();
    Json(json!({ "tree_size": 1024 + u64::from(grown) }))
}

async fn get_entries(
    State(requests): State<Requests>,
    Query(range): Query<Range>,
) -> (StatusCode, Json<Value>) {
    let mut requests = requests.lock();
    requests.push((range.start, range.end));
    if requests.len() == 1 {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "temporary failure" })),
        )
    } else {
        (StatusCode::OK, Json(json!({ "entries": [] })))
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_rejected_range_below_the_head_is_requested_again() {
    let requests = Requests::default();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = Router::new()
        .route("/ct/v1/get-sth", get(get_sth))
        .route("/ct/v1/get-entries", get(get_entries))
        .with_state(requests.clone());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let log = CtLog::from(CustomCtLog {
        name: "fake rfc6962 log".into(),
        url: format!("http://{addr}"),
        expected_log_id: None,
        batch_size: None,
        poll_interval_ms: None,
    });

    let (tx, _) = broadcast::channel(16);
    let shutdown = CancellationToken::new();
    let ctx = WatcherContext {
        client: reqwest::Client::new(),
        tx: tx.clone(),
        config: Arc::new(CtLogConfig {
            batch_size: 1024,
            fetch_concurrency: 1,
            poll_interval_ms: 100,
            max_catchup_lag_entries: 0,
            max_catchup_lag_secs: 0,
            ..CtLogConfig::default()
        }),
        state_manager: StateManager::new(None, StateRecovery::default()).unwrap(),
        cache: Arc::new(CertificateCache::new(16)),
        stats: Arc::new(ServerStats::new()),
        tracker: Arc::new(LogTracker::new()),
        shutdown: shutdown.clone(),
        dedup: Arc::new(DedupFilter::new()),
        rate_limiter: None,
        streams: Arc::new(StreamConfig::default()),
        filters: FilterHub::new(tx),
        nats: None,
        issuer_cache: Arc::new(IssuerCache::new()),
    };
    let watcher = tokio::spawn(run_watcher_with_cache(log, ctx));

    let deadline = Instant::now() + Duration::from_secs(15);
    while requests.lock().len() < 2 {
        assert!(
            Instant::now() < deadline,
            "no retry; requests: {:?}",
            requests.lock()
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    shutdown.cancel();
    watcher.await.unwrap();

    let requests = requests.lock();
    assert_eq!(requests[0].0, 24);
    assert_eq!(
        requests[1].0, requests[0].0,
        "rejected range was skipped: {requests:?}"
    );
}
