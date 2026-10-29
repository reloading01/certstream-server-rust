//! Static-CT drains against slow logs, over a real socket.
//!
//! The watcher re-polls the checkpoint every 30 seconds during a long drain.
//! Tiles already requested when that happens are below the old head and still
//! valid, so each one must be fetched once and keep downloading while the
//! checkpoint is polled; stopping for the poll is what held slow origins to a
//! tile or two per refresh. A log that splits its bandwidth across concurrent
//! downloads must not turn timeouts into refetching every tile in flight.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
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

#[derive(Clone)]
struct FakeLog {
    origin: String,
    tiles: u64,
    /// Added to every checkpoint poll during the drain after the first.
    checkpoint_delay: Duration,
    tile_delay: Duration,
    /// Added to a tile's delay for every download in progress, itself
    /// included: a log whose bandwidth is shared by its concurrent requests.
    delay_per_download: Duration,
    requests: Arc<Mutex<HashMap<u64, u32>>>,
    tiles_downloading: Arc<AtomicUsize>,
    checkpoint_polls: Arc<AtomicUsize>,
    /// Tile downloads in progress halfway through each checkpoint poll during the drain.
    downloading_during_poll: Arc<Mutex<Vec<usize>>>,
}

async fn checkpoint(State(log): State<FakeLog>) -> String {
    let first_poll = log.checkpoint_polls.fetch_add(1, Ordering::SeqCst) == 0;
    // Polls once every tile has been requested are the idle ones after the drain.
    let drain_unfinished = (log.requests.lock().len() as u64) < log.tiles;
    if !first_poll && drain_unfinished && !log.checkpoint_delay.is_zero() {
        tokio::time::sleep(log.checkpoint_delay / 2).await;
        let downloading = log.tiles_downloading.load(Ordering::SeqCst);
        log.downloading_during_poll.lock().push(downloading);
        tokio::time::sleep(log.checkpoint_delay / 2).await;
    }
    format!(
        "{}\n{}\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n\n— fake sig\n",
        log.origin,
        log.tiles * 256
    )
}

/// Counts a download in progress until dropped, which is also what happens
/// when the client gives up and the handler is cancelled.
struct Download<'a> {
    counter: &'a AtomicUsize,
    concurrent: usize,
}

impl<'a> Download<'a> {
    fn start(counter: &'a AtomicUsize) -> Self {
        let concurrent = counter.fetch_add(1, Ordering::SeqCst) + 1;
        Self {
            counter,
            concurrent,
        }
    }
}

impl Drop for Download<'_> {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, Ordering::SeqCst);
    }
}

async fn names_tile(State(log): State<FakeLog>, Path(path): Path<String>) -> String {
    let index: u64 = path
        .split('/')
        .map(|part| part.trim_start_matches('x'))
        .collect::<String>()
        .parse()
        .unwrap();
    *log.requests.lock().entry(index).or_default() += 1;
    let download = Download::start(&log.tiles_downloading);
    tokio::time::sleep(log.tile_delay + log.delay_per_download * download.concurrent as u32).await;
    drop(download);
    (0..256)
        .map(|i| format!("{{\"Timestamp\":1,\"DNS\":[\"e{i}.t{index}.example\"]}}\n"))
        .collect()
}

/// Drain a fake log from index 0 to its head and return it once done.
async fn drain(fake: FakeLog, config: CtLogConfig, deadline: Duration) -> FakeLog {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let fake = FakeLog {
        origin: addr.to_string(),
        ..fake
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

    let head = fake.tiles * 256;
    let state_manager = StateManager::new(None, StateRecovery::default()).unwrap();
    state_manager.update_index(&url, 0, head);

    let (tx, _) = broadcast::channel(1024);
    let shutdown = CancellationToken::new();
    let ctx = WatcherContext {
        client: reqwest::Client::new(),
        tx: tx.clone(),
        config: Arc::new(CtLogConfig {
            names_tiles: NamesTiles::Prefer,
            poll_interval_ms: 100,
            ..config
        }),
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

    let deadline = Instant::now() + deadline;
    while state_manager.get_index(&url) < Some(head) {
        assert!(
            Instant::now() < deadline,
            "drain did not finish; reached {:?}",
            state_manager.get_index(&url)
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    shutdown.cancel();
    watcher.await.unwrap();
    fake
}

fn fake_log(
    tiles: u64,
    checkpoint_delay: Duration,
    tile_delay: Duration,
    delay_per_download: Duration,
) -> FakeLog {
    FakeLog {
        origin: String::new(),
        tiles,
        checkpoint_delay,
        tile_delay,
        delay_per_download,
        requests: Arc::default(),
        tiles_downloading: Arc::default(),
        checkpoint_polls: Arc::default(),
        downloading_during_poll: Arc::default(),
    }
}

/// Outlasts the 30 second head refresh, so this test takes about 40 seconds.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tiles_keep_downloading_across_the_head_refresh() {
    let fake = drain(
        fake_log(
            72,
            Duration::from_secs(2),
            Duration::from_secs(2),
            Duration::ZERO,
        ),
        CtLogConfig::default(),
        Duration::from_secs(90),
    )
    .await;

    let requests = fake.requests.lock();
    let refetched: Vec<_> = requests.iter().filter(|(_, n)| **n > 1).collect();
    assert_eq!(requests.len() as u64, fake.tiles);
    assert!(
        refetched.is_empty(),
        "tiles fetched more than once: {refetched:?}"
    );
    let during_poll = fake.downloading_during_poll.lock();
    assert!(
        !during_poll.is_empty(),
        "the drain never refreshed the head"
    );
    assert!(
        during_poll.iter().all(|n| *n > 0),
        "tile downloads stopped while the checkpoint was polled: {during_poll:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_log_too_slow_for_the_full_depth_is_drained_at_a_lower_one() {
    // At 16 deep each tile takes about 5 s against a 2 s timeout; at 4 deep, 1.2 s.
    let fake = drain(
        fake_log(
            40,
            Duration::ZERO,
            Duration::ZERO,
            Duration::from_millis(300),
        ),
        CtLogConfig {
            fetch_concurrency: 16,
            request_timeout_secs: 2,
            ..CtLogConfig::default()
        },
        Duration::from_secs(60),
    )
    .await;

    let requests: u32 = fake.requests.lock().values().sum();
    assert!(
        u64::from(requests) <= fake.tiles * 2,
        "{requests} tile requests to drain {} tiles",
        fake.tiles
    );
}
