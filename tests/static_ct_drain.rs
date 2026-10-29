//! A static-CT drain against a slow log, over a real socket.
//!
//! The watcher re-polls the checkpoint every 30 seconds during a long drain.
//! Tiles already requested when that happens are below the old head and still
//! valid, so each one must be fetched once; refetching them is what held slow
//! origins to a tile or two per refresh. The drain has to outlast the refresh,
//! so this test takes about 40 seconds.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::Router;
use axum::extract::{Path, State};
use axum::routing::get;
use certstream_server_rust::api::{CertificateCache, LogTracker, ServerStats};
use certstream_server_rust::config::{
    CtLogConfig, NamesTiles, StateRecovery, StaticCtLog, StreamConfig,
};
use certstream_server_rust::ct::static_ct::{IssuerCache, run_static_ct_watcher};
use certstream_server_rust::ct::{CtLog, WatcherContext};
use certstream_server_rust::dedup::DedupFilter;
use certstream_server_rust::filter::FilterHub;
use certstream_server_rust::state::StateManager;
use parking_lot::Mutex;
use tokio::sync::broadcast;
use tokio_util::sync::CancellationToken;

const TILES: u64 = 72;
const TILE_DELAY: Duration = Duration::from_secs(2);

#[derive(Clone)]
struct FakeLog {
    origin: String,
    requests: Arc<Mutex<HashMap<u64, u32>>>,
}

async fn checkpoint(State(log): State<FakeLog>) -> String {
    format!(
        "{}\n{}\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n\n— fake sig\n",
        log.origin,
        TILES * 256
    )
}

async fn names_tile(State(log): State<FakeLog>, Path(path): Path<String>) -> String {
    let index: u64 = path
        .split('/')
        .map(|part| part.trim_start_matches('x'))
        .collect::<String>()
        .parse()
        .unwrap();
    *log.requests.lock().entry(index).or_default() += 1;
    tokio::time::sleep(TILE_DELAY).await;
    (0..256)
        .map(|i| format!("{{\"Timestamp\":1,\"DNS\":[\"e{i}.t{index}.example\"]}}\n"))
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn in_flight_tiles_survive_the_head_refresh() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let fake = FakeLog {
        origin: addr.to_string(),
        requests: Arc::default(),
    };
    let app = Router::new()
        .route("/checkpoint", get(checkpoint))
        .route("/tile/names/{*path}", get(names_tile))
        .with_state(fake.clone());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let url = format!("http://{addr}");
    let log: CtLog = serde_json::from_value::<StaticCtLog>(serde_json::json!({
        "name": "fake slow log",
        "url": url,
    }))
    .unwrap()
    .into();

    let config = CtLogConfig {
        names_tiles: NamesTiles::Prefer,
        poll_interval_ms: 100,
        ..CtLogConfig::default()
    };
    let state_manager = StateManager::new(None, StateRecovery::default()).unwrap();
    state_manager.update_index(&url, 0, TILES * 256);

    let (tx, _) = broadcast::channel(1024);
    let shutdown = CancellationToken::new();
    let ctx = WatcherContext {
        client: reqwest::Client::new(),
        tx: tx.clone(),
        config: Arc::new(config),
        state_manager: state_manager.clone(),
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
    let watcher = tokio::spawn(run_static_ct_watcher(log, ctx));

    let deadline = Instant::now() + Duration::from_secs(90);
    while state_manager.get_index(&url) < Some(TILES * 256) {
        assert!(
            Instant::now() < deadline,
            "drain did not finish; reached {:?}",
            state_manager.get_index(&url)
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    shutdown.cancel();
    watcher.await.unwrap();

    let requests = fake.requests.lock();
    let refetched: Vec<_> = requests.iter().filter(|(_, n)| **n > 1).collect();
    assert_eq!(requests.len() as u64, TILES);
    assert!(
        refetched.is_empty(),
        "tiles fetched more than once: {refetched:?}"
    );
}
