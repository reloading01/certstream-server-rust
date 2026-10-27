mod api;
mod backfill;
mod cli;
mod config;
mod ct;
mod dedup;
mod deflate;
mod filter;
mod health;
mod hot_reload;
mod lag_policy;
mod memstats;
mod middleware;
mod nats;
mod models;
mod rate_limit;
mod sse;
mod state;
mod tls;
mod websocket;

use axum::{http::header, middleware as axum_middleware, response::IntoResponse, routing::get, Router};
use metrics_exporter_prometheus::PrometheusBuilder;
use reqwest::Client;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::broadcast;
use tokio_util::sync::CancellationToken;
use tower_http::cors::{Any as CorsAny, CorsLayer};
use tracing::{debug, error, info, warn};
use tracing_subscriber::EnvFilter;

use api::{ApiState, CertificateCache, LogTracker, ServerStats};
use cli::{CliArgs, DEFAULT_USER_AGENT, VERSION};
use config::{Config, CtLogConfig};
use ct::{fetch_log_list, WatcherContext};
use dedup::DedupFilter;
use health::{deep_health, example_json, health, HealthState};
use hot_reload::{HotReloadManager, HotReloadableConfig};
use middleware::{
    auth_middleware, rate_limit_middleware, resolve_client_ip, AuthMiddleware, ConnectionLimiter,
    TrustedProxies,
};
use models::PreSerializedMessage;
use rate_limit::RateLimiter;
use sse::handle_sse_stream;
use state::StateManager;
use websocket::{
    handle_domains_only, handle_full_stream, handle_lite_stream, handle_v2_stream, AppState,
    ConnectionCounter,
};

// The workload alloc/frees multi-MB tile and batch buffers across ~100 watcher
// tasks every poll. The system allocator (macOS malloc / glibc) keeps those
// freed pages in per-thread arenas, so RSS settles near the transient
// high-water mark (~400 MB observed) instead of the ~100-150 MB live heap.
// jemalloc returns dirty pages to the OS on a decay timer, keeping RSS close
// to actual usage, but only once configured. See below.
#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

// jemalloc defaults, read before main() runs. Every one of these was measured
// on the live ingest workload (45 CT logs, ~420 certs/s, one subscriber);
// stock defaults gave 358 MiB RSS against a 52 MiB live heap, these give
// ~85 MiB. The allocator cache and decay settings below, with the compact
// dedup set, bring the idle container to 43 MiB at 1,600 entries/s.
//
//   thp:never
//     The big one. With transparent huge pages in `always` mode (the default
//     inside Docker Desktop's VM and on several distros) the kernel promotes
//     jemalloc's 4 KiB pages into 2 MiB ones. jemalloc frees at 4 KiB
//     granularity, and a partially-free huge page cannot be returned, so RSS
//     parks at a multiple of the live heap. Of that 358 MiB, 206 MiB was
//     AnonHugePages. Hosts running THP in `madvise` mode never saw this,
//     which is why it went unnoticed.
//
//   narenas:4
//     jemalloc defaults to 4 × logical CPUs, and in a container that reads
//     the *host* CPU count: 72 arenas on an 18-core machine, each with its
//     own dirty-page pool and decay clock, for a runtime that only has 4
//     worker threads. Matching the worker count also halved arena metadata
//     (11.8 MiB -> 4.8 MiB).
//
//   background_thread:true
//     Decay only advances when an arena is touched. Watcher tasks are bursty,
//     so idle arenas held dirty pages indefinitely. This gives them a purger
//     that runs regardless.
//
//   dirty_decay_ms / muzzy_decay_ms:1000
//     Catch-up bursts free multi-MB buffers all at once. Returning them within
//     a second, with the background purger doing the work, took about 3 MiB
//     off the idle size at no measurable CPU. Returning them at once took
//     another 9 MiB but cost about 0.01 core, which was not worth it.
//
//   tcache:false
//     jemalloc keeps freed objects in a cache per thread, and with the
//     runtime's workers plus its blocking pool that was 20 to 25 MiB of idle
//     memory. Measured on the live workload, same logs, seven minutes, no
//     subscribers: 73 MiB with it, 46 MiB without, at the same CPU.
//
// These are defaults, not policy: jemalloc applies `_RJEM_MALLOC_CONF` from
// the environment after this symbol, so operators can still override any of
// it (or all of it) without rebuilding.
// `#[used]` because nothing in this crate reads the symbol (jemalloc looks it
// up at startup) and fat LTO would otherwise be free to drop it.
// `thp` and `background_thread` are Linux-only in jemalloc: macOS has no
// transparent huge pages at all, and the background purger is documented as
// pthread-only. Passing them anyway is harmless but makes jemalloc print
// "No THP support" and "supports pthread only" to stderr on every start,
// which is noise for anyone running the binary outside a container.
#[cfg(all(not(target_env = "msvc"), target_os = "linux"))]
#[used]
#[allow(non_upper_case_globals)]
#[unsafe(export_name = "_rjem_malloc_conf")]
pub static MALLOC_CONF: &[u8] =
    b"thp:never,narenas:4,background_thread:true,tcache:false,dirty_decay_ms:1000,muzzy_decay_ms:1000\0";

#[cfg(all(not(target_env = "msvc"), not(target_os = "linux")))]
#[used]
#[allow(non_upper_case_globals)]
#[unsafe(export_name = "_rjem_malloc_conf")]
pub static MALLOC_CONF: &[u8] = b"narenas:4,tcache:false,dirty_decay_ms:1000,muzzy_decay_ms:1000\0";

// CT polling + WS broadcast are heavily I/O-bound; CPU work is bursty (JSON
// parse + cert deserialise) and cheap relative to the network wait. 4 worker
// threads is plenty in practice and saves ~8 MiB of resident memory vs the
// runtime default (= number of logical CPUs, often 8 on modern hosts).
// Operators with extreme load can override via TOKIO_WORKER_THREADS env var.
#[tokio::main(worker_threads = 4)]
async fn main() {
    // Two rustls providers are compiled in (the NATS client brings ring), and
    // rustls refuses to pick one itself, which made enabling TLS panic.
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("no rustls crypto provider is installed before startup");

    let cli_args = CliArgs::parse();

    if cli_args.show_help {
        CliArgs::print_help();
        return;
    }

    if cli_args.show_version {
        CliArgs::print_version();
        return;
    }

    let config = Config::load();

    if cli_args.validate_config {
        print_config_validation(&config);
        return;
    }

    // Always validate on normal startup too — `--validate-config` is opt-in
    // and most operators don't run it. Without this, an invalid `buffer_size:
    // 0` would reach `broadcast::channel(0)` and panic on a fresh boot.
    // `--export-metrics` and `--dry-run` are still allowed to skip
    // because they're operator probes, not real servers.
    if !cli_args.export_metrics && let Err(errors) = config.validate() {
        eprintln!("Configuration validation failed:");
        for err in errors {
            eprintln!("  - {}: {}", err.field, err.message);
        }
        std::process::exit(1);
    }

    if cli_args.export_metrics {
        let prometheus_handle = PrometheusBuilder::new()
            .install_recorder()
            .expect("failed to install prometheus recorder");
        // Initialize all tracked counters to 0 so they appear in the snapshot
        // even before the first real event fires.
        metrics::counter!("certstream_worker_panics").increment(0);
        metrics::counter!("certstream_connection_limit_rejected").increment(0);
        metrics::counter!("certstream_per_ip_limit_rejected").increment(0);
        metrics::counter!("certstream_log_health_checks_failed").increment(0);
        metrics::counter!("certstream_duplicates_filtered").increment(0);
        metrics::counter!("certstream_static_ct_checkpoint_errors").increment(0);
        metrics::counter!("certstream_ws_messages_lagged").increment(0);
        metrics::counter!("certstream_ws_disconnect_lag").increment(0);
        metrics::counter!("certstream_sse_messages_lagged").increment(0);
        metrics::counter!("certstream_sse_disconnect_lag").increment(0);
        println!("{}", prometheus_handle.render());
        return;
    }

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new(&config.log_level)),
        )
        .init();

    info!("starting certstream-server-rust v{}", VERSION);

    let shutdown_token = CancellationToken::new();
    let started_at = std::time::Instant::now();

    spawn_signal_handler(shutdown_token.clone());

    let prometheus_handle = PrometheusBuilder::new()
        .install_recorder()
        .expect("failed to install prometheus recorder");

    // Initialize counters to 0 so they appear in /metrics before the first event.
    // Without this, Prometheus rate() and increase() queries return no data until
    // the counter fires at least once.
    metrics::counter!("certstream_worker_panics").increment(0);
    metrics::counter!("certstream_connection_limit_rejected").increment(0);
    metrics::counter!("certstream_per_ip_limit_rejected").increment(0);
    metrics::counter!("certstream_log_health_checks_failed").increment(0);
    metrics::counter!("certstream_duplicates_filtered").increment(0);
    metrics::counter!("certstream_static_ct_checkpoint_errors").increment(0);
    // Subscriber-side losses. Zero here is a real answer ("nobody missed
    // anything"), and without the pre-init it is indistinguishable from
    // "this build never reports it".
    metrics::counter!("certstream_ws_messages_lagged").increment(0);
    metrics::counter!("certstream_ws_disconnect_lag").increment(0);
    metrics::counter!("certstream_sse_messages_lagged").increment(0);
    metrics::counter!("certstream_sse_disconnect_lag").increment(0);

    // The receiver is dropped deliberately. Holding one for the process
    // lifetime would keep `tx.receiver_count()` above zero forever and defeat
    // the guard that skips serialization when nobody is listening. `send()`
    // returning `Err(SendError)` with no subscribers is already ignored
    // downstream, so nothing needs the placeholder.
    let tx: broadcast::Sender<Arc<PreSerializedMessage>> =
        broadcast::channel(config.buffer_size).0;

    // Server-side subscription filters. Dormant — and free — until the first
    // filtered subscriber connects.
    let filter_hub = filter::FilterHub::new(tx.clone());

    if let Some(request) = cli_args.backfill.clone() {
        run_backfill(request, &config).await;
        return;
    }

    let user_agent = match config.ct_log.user_agent_override() {
        Some(ua) => {
            info!(user_agent = ua, "using configured User-Agent");
            ua.to_string()
        }
        None => {
            if config.ct_log.user_agent.is_some() {
                warn!("configured User-Agent is blank; falling back to the default");
            }
            DEFAULT_USER_AGENT.to_string()
        }
    };

    let client = build_ct_client(&config.ct_log, &user_agent, false)
        .expect("failed to build http client");
    let transport = OperatorTransport::new(&config.ct_log, &user_agent);

    let state_manager = match StateManager::new(
        config.ct_log.state_file.clone(),
        config.ct_log.state_recovery,
    ) {
        Ok(m) => m,
        Err(e) => {
            error!(error = %e, "refusing to start with an unusable state file");
            eprintln!("State recovery failed: {e}");
            eprintln!("Set ct_log.state_recovery: fresh to start from the log head instead.");
            std::process::exit(1);
        }
    };
    if config.ct_log.state_file.is_some() {
        state_manager
            .clone()
            .start_periodic_save(Duration::from_secs(30), shutdown_token.clone());
        info!("state persistence enabled");
    }

    // Durable output. Started before the watchers so a broker that is down at
    // boot is a startup failure the operator sees, not a silent fallback to a
    // non-durable server.
    let nats_sink = if config.nats.enabled {
        match nats::start(&config.nats, shutdown_token.clone()).await {
            Ok(sink) => {
                state_manager.gate_saves_on_acks(sink.acks.clone());
                info!("state saves now follow NATS acknowledgements");
                Some(sink)
            }
            Err(e) => {
                nats::report_start_failure(&e);
                eprintln!("NATS JetStream output is enabled but could not be started: {e}");
                std::process::exit(1);
            }
        }
    } else {
        None
    };

    let hot_reload_manager = if config.hot_reload.enabled {
        let initial_hot_config = HotReloadableConfig {
            connection_limit: config.connection_limit.clone(),
            rate_limit: config.rate_limit.clone(),
            auth: config.auth.clone(),
        };
        let manager = HotReloadManager::new(initial_hot_config);
        let watch_path = config
            .hot_reload
            .watch_path
            .clone()
            .or(config.config_path.clone());
        manager.clone().start_watching(watch_path, shutdown_token.clone());
        info!("hot reload enabled");
        Some(manager)
    } else {
        None
    };

    let dedup_filter = Arc::new(DedupFilter::with_config(
        config.dedup.capacity,
        Duration::from_secs(config.dedup.ttl_secs),
    ));
    dedup_filter.clone().start_cleanup_task(shutdown_token.clone());
    info!(
        capacity = config.dedup.capacity,
        ttl_secs = config.dedup.ttl_secs,
        "cross-log dedup filter enabled"
    );

    let ct_log_config = Arc::new(config.ct_log.clone());
    let log_tracker = Arc::new(LogTracker::new());
    let server_stats = Arc::new(ServerStats::new());
    let cert_cache = Arc::new(CertificateCache::new(config.api.cache_capacity));

    let rate_limiter = RateLimiter::new(config.rate_limit.clone(), hot_reload_manager.clone());

    info!(
        catalog_sources = ?ct::catalog::CATALOG_SOURCE_IDS,
        "fetching CT log lists from signed-catalog registry"
    );

    if !config.custom_logs.is_empty() {
        info!(count = config.custom_logs.len(), "adding custom CT logs");
    }
    if !config.static_logs.is_empty() {
        info!(count = config.static_logs.len(), "adding static CT logs");
    }

    let host = config.host;
    let port = config.port;
    let has_tls = config.has_tls();
    let tls_cert = config.tls_cert.clone();
    let tls_key = config.tls_key.clone();
    let protocols = config.protocols.clone();
    let streams = Arc::new(config.streams.clone());

    if !config.streams.full {
        info!("full stream disabled by config");
    }
    if !config.streams.lite {
        info!("lite stream disabled by config");
    }
    if !config.streams.domains_only {
        info!("domains-only stream disabled by config");
    }
    if config.streams.v2 {
        info!("v2 stream enabled");
    }

    // Single issuer cache shared across all static-CT watchers.
    let issuer_cache = Arc::new(ct::static_ct::IssuerCache::new());

    if !cli_args.dry_run {
        let watcher_ctx = WatcherContext {
            client: client.clone(),
            tx: tx.clone(),
            config: ct_log_config.clone(),
            state_manager: state_manager.clone(),
            cache: cert_cache.clone(),
            stats: server_stats.clone(),
            tracker: log_tracker.clone(),
            shutdown: shutdown_token.clone(),
            dedup: dedup_filter.clone(),
            filters: filter_hub.clone(),
            nats: nats_sink.clone(),
            rate_limiter: None,
            streams: streams.clone(),
            issuer_cache: issuer_cache.clone(),
        };

        let pool = Arc::new(parking_lot::Mutex::new(WatcherPool::default()));
        let (rfc_count, static_count) =
            discover_and_spawn(&config, &log_tracker, &watcher_ctx, &transport, &pool).await;

        if rfc_count == 0 && static_count == 0 {
            error!("no CT log watchers were started — refusing to run with zero sources");
            std::process::exit(1);
        }
        info!(rfc6962 = rfc_count, static_ct = static_count, "CT watcher pool started");

        let refresh_secs = config.ct_log.log_refresh_interval_secs;
        if refresh_secs == 0 {
            info!("periodic log list refresh disabled");
        } else {
            info!(interval_secs = refresh_secs, "periodic log list refresh enabled");
            spawn_log_refresh(
                Arc::new(config.clone()),
                log_tracker.clone(),
                watcher_ctx.clone(),
                transport.clone(),
                pool,
                Duration::from_secs(refresh_secs),
            );
        }
    } else {
        info!("dry-run mode: skipping CT log connections");
    }

    // Heartbeat: periodic throughput summary at INFO. Without this the log
    // looks frozen after startup since all per-iteration transient events are
    // debug-level — operators couldn't tell the difference between "healthy
    // and busy" and "stuck". The tick interval is wide enough not to spam.
    {
        use std::sync::atomic::Ordering;
        let stats = server_stats.clone();
        let dedup = dedup_filter.clone();
        let heartbeat_cancel = shutdown_token.clone();
        tokio::spawn(async move {
            const INTERVAL: Duration = Duration::from_secs(30);
            let mut interval = tokio::time::interval(INTERVAL);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            interval.tick().await; // skip the immediate fire-on-start
            let mut last_processed: u64 = 0;
            let mut last_sent: u64 = 0;
            loop {
                tokio::select! {
                    _ = heartbeat_cancel.cancelled() => break,
                    _ = interval.tick() => {
                        let heap = memstats::record();
                        let processed = stats.certificates_processed.load(Ordering::Relaxed);
                        let sent = stats.messages_sent.load(Ordering::Relaxed);
                        let d_processed = processed.saturating_sub(last_processed);
                        let d_sent = sent.saturating_sub(last_sent);
                        let rate = d_processed as f64 / INTERVAL.as_secs() as f64;
                        info!(
                            certs_total = processed,
                            certs_delta = d_processed,
                            certs_per_sec = format!("{rate:.0}"),
                            broadcast_total = sent,
                            broadcast_delta = d_sent,
                            dedup_cache = dedup.len(),
                            heap_allocated_mib = heap.map(|h| h.allocated / 1_048_576),
                            heap_resident_mib = heap.map(|h| h.resident / 1_048_576),
                            "heartbeat"
                        );
                        last_processed = processed;
                        last_sent = sent;
                    }
                }
            }
        });
    }

    let connection_limiter =
        ConnectionLimiter::new(config.connection_limit.clone(), hot_reload_manager.clone());

    let app = build_router(
        &protocols,
        &config,
        RouterDeps {
            tx: tx.clone(),
            filter_hub: filter_hub.clone(),
            connection_limiter: connection_limiter.clone(),
            server_stats: server_stats.clone(),
            cert_cache: cert_cache.clone(),
            log_tracker: log_tracker.clone(),
            rate_limiter,
            hot_reload_manager: hot_reload_manager.clone(),
            prometheus_handle,
            started_at,
            shutdown_token: shutdown_token.clone(),
        },
    );

    let addr = SocketAddr::from((host, port));
    info!(address = %addr, "starting server");

    if has_tls {
        run_tls_server(addr, app, &tls_cert, &tls_key, shutdown_token.clone()).await;
    } else {
        run_plain_server(addr, app, shutdown_token.clone()).await;
    }

    info!("flushing state before exit...");
    state_manager.save_if_dirty().await;
    info!("server stopped");
}

fn spawn_signal_handler(shutdown_token: CancellationToken) {
    tokio::spawn(async move {
        #[cfg(unix)]
        {
            // Set up both signals before selecting; if either fails, log and
            // cancel immediately so the server shuts down rather than running
            // silently un-stoppable.
            let mut sigterm = match tokio::signal::unix::signal(
                tokio::signal::unix::SignalKind::terminate(),
            ) {
                Ok(s) => s,
                Err(e) => {
                    error!(error = %e, "failed to register SIGTERM handler, shutting down");
                    shutdown_token.cancel();
                    return;
                }
            };

            tokio::select! {
                result = tokio::signal::ctrl_c() => {
                    if let Err(e) = result {
                        error!(error = %e, "ctrl-c handler error");
                    } else {
                        info!("received SIGINT");
                    }
                }
                _ = sigterm.recv() => {
                    info!("received SIGTERM");
                }
            }
        }

        #[cfg(not(unix))]
        {
            if let Err(e) = tokio::signal::ctrl_c().await {
                error!(error = %e, "failed to listen for ctrl+c, shutting down");
            } else {
                info!("received SIGINT");
            }
        }

        info!("initiating graceful shutdown...");
        shutdown_token.cancel();
    });
}

/// Build a CT-fetch HTTP client. `http1_only` yields the transport used by the
/// operators listed in `ct_log.force_http1_operators`.
fn build_ct_client(
    ct_log: &CtLogConfig,
    user_agent: &str,
    http1_only: bool,
) -> reqwest::Result<Client> {
    let builder = Client::builder()
        .user_agent(user_agent)
        // Sized to what a watcher actually pipelines: it keeps up to
        // `fetch_concurrency` range/tile fetches in flight during catch-up.
        // reqwest's default of 20 per host across ~55 hosts would hold an
        // order of magnitude more idle sockets, with their kernel and TLS
        // state, than any of them use. Matters most for HTTP/1.1 hosts;
        // HTTP/2 multiplexes over fewer connections anyway.
        .pool_max_idle_per_host((ct_log.fetch_concurrency as usize).max(2))
        .pool_idle_timeout(Duration::from_secs(30))
        // Global timeout for catalog list/signature fetches. Watcher fetches
        // also set per-request bounds; this backstops shared-client requests.
        .timeout(Duration::from_secs(ct_log.request_timeout_secs))
        .tcp_nodelay(true);
    if http1_only {
        builder.http1_only().build()
    } else {
        builder.build()
    }
}

/// Per-operator transport selection.
///
/// DigiCert throttles per TCP connection rather than per IP. Under HTTP/2
/// reqwest multiplexes every watcher's request for a host onto one connection,
/// so that per-connection quota caps the whole process — and DigiCert serves
/// several logs from one host, so their watchers all land on it. HTTP/1.1 needs
/// a connection per in-flight request, so each concurrent fetch carries its own
/// quota (`pool_max_idle_per_host` only decides how many stay warm between
/// polls). The per-operator token bucket still gates every fetch, so this
/// redistributes our request rate across connections rather than raising it.
/// Same observation as certspotter's `digicerthack` branch
/// (<https://github.com/SSLMate/certspotter/issues/126>), which drops
/// keep-alives outright instead.
#[derive(Clone)]
struct OperatorTransport {
    /// `None` when no operator is listed, or when the client failed to build.
    client: Option<Client>,
    /// Canonicalized operator names that should use `client`.
    operators: std::collections::HashSet<String>,
}

impl OperatorTransport {
    fn new(ct_log: &CtLogConfig, user_agent: &str) -> Self {
        let operators: std::collections::HashSet<String> = ct_log
            .force_http1_operators
            .iter()
            .map(|op| ct::normalize_operator(op))
            .collect();
        if operators.is_empty() {
            return Self {
                client: None,
                operators,
            };
        }
        let client = match build_ct_client(ct_log, user_agent, true) {
            Ok(c) => {
                let mut names: Vec<&str> = operators.iter().map(String::as_str).collect();
                names.sort_unstable();
                info!(operators = ?names, "forcing HTTP/1.1 transport");
                Some(c)
            }
            Err(e) => {
                error!(error = %e, "failed to build the HTTP/1.1 client; listed operators stay on the shared client");
                None
            }
        };
        Self { client, operators }
    }

    fn uses_http1(&self, operator_key: &str) -> bool {
        self.client.is_some() && self.operators.contains(operator_key)
    }

    /// Resolve the client for an already-canonicalized operator name.
    fn client_for<'a>(&'a self, operator_key: &str, shared: &'a Client) -> &'a Client {
        match &self.client {
            Some(client) if self.uses_http1(operator_key) => client,
            _ => shared,
        }
    }
}

/// Configured operator names that match none of the discovered logs. Both
/// `operator_rate_limits` and `force_http1_operators` are looked up by
/// canonicalized name, so a key that never matches is silently inert — which
/// from the outside looks exactly like a working config.
fn unmatched_operator_keys<'a>(
    configured: impl IntoIterator<Item = &'a String>,
    known: &std::collections::HashSet<String>,
) -> Vec<String> {
    let mut missing: Vec<String> = configured
        .into_iter()
        .filter(|key| !known.contains(&ct::normalize_operator(key)))
        .cloned()
        .collect();
    missing.sort();
    missing.dedup();
    missing
}

/// Discovery + spawn pipeline. Returns `(rfc6962_count, static_ct_count)`.
/// Identity a refreshed log list is diffed against the running watchers by.
///
/// `log_id` is the SHA-256 of the log's public key, so it survives a URL
/// change and is the same across every catalog that lists the log. A log
/// whose list entry carries no id can only be matched on its URL.
fn watcher_key(log: &ct::CtLog) -> String {
    match log.log_id.as_deref().filter(|id| !id.is_empty()) {
        Some(id) => format!("id:{id}"),
        None => format!("url:{}", log.normalized_url()),
    }
}

struct RunningWatcher {
    /// Child of the process shutdown token, so cancelling this stops one
    /// watcher and cancelling the parent still stops them all.
    cancel: CancellationToken,
    name: String,
    url: String,
    local: bool,
}

/// The set of watchers currently running, and the per-operator limiters they
/// share. Refresh diffs a freshly resolved log list against `running`.
#[derive(Default)]
struct WatcherPool {
    running: std::collections::HashMap<String, RunningWatcher>,
    operator_limiters: std::collections::HashMap<String, ct::OperatorRateLimiter>,
}

/// Fetch the catalogs and merge in the locally configured logs.
///
/// Returns an error where startup would refuse to run, instead of exiting:
/// this also runs on a live server, where a bad refresh must leave the
/// existing watchers alone rather than take the process down.
/// A resolved log set, and which of its entries came from this server's own
/// config rather than from a catalog. Always produced and consumed together.
struct ResolvedLogs {
    logs: Vec<ct::CtLog>,
    local_keys: std::collections::HashSet<String>,
    /// Catalog logs that did not answer the availability probe. No watcher is
    /// started for them, but they are still listed, so one that is already
    /// running is not mistaken for a delisted log.
    unreachable_keys: std::collections::HashSet<String>,
}

impl ResolvedLogs {
    /// Every log the catalog currently lists, answering or not.
    fn listed_keys(&self) -> std::collections::HashSet<String> {
        self.logs
            .iter()
            .map(watcher_key)
            .chain(self.unreachable_keys.iter().cloned())
            .collect()
    }
}

async fn resolve_logs(config: &Config, ctx: &WatcherContext) -> Result<ResolvedLogs, String> {
    use ct::LogType;

    // Drive the signed-catalog registry. Per-source authority comes from
    // ct_log.catalog_authority_overrides; signature verification gates auto-spawn.
    let discovered = fetch_log_list(
        &ctx.client,
        &ct::catalog::catalog_registry(),
        &config.ct_log.catalog_authority_overrides,
        config.custom_logs.clone(),
        Duration::from_secs(config.ct_log.request_timeout_secs),
        ctx.config.user_agent_override().unwrap_or(DEFAULT_USER_AGENT),
        &ct::LogExclusions::new(
            &config.ct_log.excluded_operators,
            &config.ct_log.excluded_logs,
        ),
    )
    .await
    .map_err(|e| format!("failed to fetch any CT log list: {e}"))?;
    let unreachable_keys: std::collections::HashSet<String> =
        discovered.unreachable.iter().map(watcher_key).collect();
    let mut all_logs = discovered.reachable;

    // Splice in configured static logs by expected CT log ID when provided.
    // A configured static log with the same CT log ID as a discovered log
    // replaces it only if non-replaceable identity fields still agree.
    let mut static_overrides: Vec<ct::CtLog> =
        config.static_logs.iter().cloned().map(ct::CtLog::from).collect();

    // Rate limits are keyed by operator, so an override has to carry the
    // operator name of the log it replaces rather than the generic one
    // `From<StaticCtLog>` stamps on every local entry.
    ct::inherit_operators(&all_logs, &mut static_overrides);

    let conflicts = ct::local_override_conflicts(&all_logs, &static_overrides);
    if !conflicts.is_empty() {
        for conflict in &conflicts {
            error!("{conflict}");
        }
        return Err("static log override conflicts with discovered CT log identity".to_string());
    }
    let override_ids: std::collections::HashSet<String> = static_overrides
        .iter()
        .filter_map(|log| log.log_id.as_deref().filter(|id| !id.is_empty()))
        .map(str::to_string)
        .collect();
    let override_urls_without_id: std::collections::HashSet<String> = static_overrides
        .iter()
        .filter(|log| log.log_id.as_deref().filter(|id| !id.is_empty()).is_none())
        .map(|log| log.normalized_url())
        .collect();
    all_logs.retain(|l| {
        let replaced_by_id = l
            .log_id
            .as_ref()
            .map(|id| override_ids.contains(id))
            .unwrap_or(false);
        let replaced_by_url = l.log_type == LogType::StaticCt
            && override_urls_without_id.contains(&l.normalized_url());
        !(replaced_by_id || replaced_by_url)
    });

    // Everything the operator configured by hand. A catalog that stops
    // listing one of these says nothing about it, so refresh never retires it.
    let mut local_keys: std::collections::HashSet<String> =
        static_overrides.iter().map(watcher_key).collect();
    for custom in &config.custom_logs {
        local_keys.insert(watcher_key(&ct::CtLog::from(custom.clone())));
    }

    all_logs.extend(static_overrides);

    {
        let mut seen = std::collections::HashSet::new();
        let duplicates: Vec<String> = all_logs
            .iter()
            .filter_map(|log| log.log_id.clone())
            .filter(|id| !seen.insert(id.clone()))
            .collect();
        if !duplicates.is_empty() {
            error!(duplicate_log_ids = ?duplicates, "multiple CT watchers resolved to the same log_id");
            return Err("multiple CT watchers resolved to the same log_id".to_string());
        }
    }

    Ok(ResolvedLogs {
        logs: all_logs,
        local_keys,
        unreachable_keys,
    })
}

fn warn_unmatched_operators(config: &Config, all_logs: &[ct::CtLog]) {
    let known_operators: std::collections::HashSet<String> = all_logs
        .iter()
        .map(|log| ct::normalize_operator(&log.operator))
        .collect();
    for (field, unmatched) in [
        (
            "ct_log.operator_rate_limits",
            unmatched_operator_keys(config.ct_log.operator_rate_limits.keys(), &known_operators),
        ),
        (
            "ct_log.force_http1_operators",
            unmatched_operator_keys(&config.ct_log.force_http1_operators, &known_operators),
        ),
    ] {
        if !unmatched.is_empty() {
            warn!(
                field,
                unmatched = ?unmatched,
                "configured operator names match no discovered CT log operator and have no effect"
            );
        }
    }
}

/// Bring the running watcher set in line with `all_logs`: start one for every
/// log that has none, and apply the removal policy to the rest.
/// Returns (rfc6962 running, static-ct running, started, stopped).
fn reconcile_pool(
    pool: &mut WatcherPool,
    resolved: ResolvedLogs,
    config: &Config,
    log_tracker: &Arc<LogTracker>,
    ctx: &WatcherContext,
    transport: &OperatorTransport,
    stagger: bool,
) -> (usize, usize, usize, usize) {
    use ct::LogType;

    let present = resolved.listed_keys();
    let ResolvedLogs { logs, local_keys, .. } = resolved;
    let local_keys = &local_keys;

    // Partition by type — the two watcher pools differ in protocol.
    let (rfc_logs, static_logs): (Vec<_>, Vec<_>) =
        logs.into_iter().partition(|l| l.log_type == LogType::Rfc6962);

    let rfc_total = rfc_logs.len();
    let static_total = static_logs.len();

    let rfc_started = spawn_pool(
        "RFC 6962",
        config.ct_log.rfc6962_enabled,
        rfc_logs,
        log_tracker,
        ctx,
        transport,
        pool,
        local_keys,
        "certstream_ct_logs_count",
        if stagger { 50 } else { 0 },
        WorkerKind::Rfc6962,
    );

    let static_started = spawn_pool(
        "static-ct-api",
        config.ct_log.static_ct_enabled,
        static_logs,
        log_tracker,
        ctx,
        transport,
        pool,
        local_keys,
        "certstream_static_ct_logs_count",
        if stagger { 100 } else { 0 },
        WorkerKind::StaticCt,
    );

    let stopped = retire_absent(
        pool,
        &present,
        config.ct_log.removed_log_policy,
        log_tracker,
    );

    (
        if config.ct_log.rfc6962_enabled { rfc_total } else { 0 },
        if config.ct_log.static_ct_enabled { static_total } else { 0 },
        rfc_started + static_started,
        stopped,
    )
}

/// Stop the watchers whose logs the refreshed list no longer carries.
fn retire_absent(
    pool: &mut WatcherPool,
    present: &std::collections::HashSet<String>,
    policy: config::RemovedLogPolicy,
    log_tracker: &LogTracker,
) -> usize {
    let mut stopped = 0;
    pool.running.retain(|key, watcher| {
        if present.contains(key) || watcher.local {
            return true;
        }
        if policy == config::RemovedLogPolicy::Keep {
            debug!(log = %watcher.name, "log delisted; keeping the watcher per policy");
            return true;
        }
        info!(log = %watcher.name, "log delisted from the catalog, stopping its watcher");
        watcher.cancel.cancel();
        log_tracker.deregister(&watcher.url);
        stopped += 1;
        false
    });
    if stopped > 0 {
        metrics::counter!("certstream_log_refresh_removed_total").increment(stopped as u64);
    }
    stopped
}

async fn discover_and_spawn(
    config: &Config,
    log_tracker: &Arc<LogTracker>,
    ctx: &WatcherContext,
    transport: &OperatorTransport,
    pool: &parking_lot::Mutex<WatcherPool>,
) -> (usize, usize) {
    // Resolved before the lock is taken: the pool guard must never be held
    // across an await.
    let resolved = match resolve_logs(config, ctx).await {
        Ok(v) => v,
        Err(e) => {
            error!(error = %e, "CT log discovery failed");
            // Startup keeps its old contract: a resolvable-identity conflict
            // is fatal, an empty list falls through to the zero-sources check.
            if e.contains("conflicts") || e.contains("same log_id") {
                std::process::exit(1);
            }
            ResolvedLogs {
                logs: Vec::new(),
                local_keys: std::collections::HashSet::new(),
                unreachable_keys: std::collections::HashSet::new(),
            }
        }
    };

    warn_unmatched_operators(config, &resolved.logs);
    let (rfc, static_ct, _, _) = reconcile_pool(
        &mut pool.lock(),
        resolved,
        config,
        log_tracker,
        ctx,
        transport,
        true,
    );
    (rfc, static_ct)
}

/// Re-resolve the log list on an interval and reconcile the watcher pool
/// against it, so a log added to the catalog is picked up by a server that
/// has been up for months.
///
/// A refresh that cannot resolve a list changes nothing: the running watchers
/// are the last known-good set, and losing the catalog for an hour is not a
/// reason to stop reading the logs it named.
fn spawn_log_refresh(
    config: Arc<Config>,
    log_tracker: Arc<LogTracker>,
    ctx: WatcherContext,
    transport: OperatorTransport,
    pool: Arc<parking_lot::Mutex<WatcherPool>>,
    interval: Duration,
) {
    let cancel = ctx.shutdown.clone();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(interval);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        tick.tick().await; // the first tick fires immediately; discovery just ran
        loop {
            tokio::select! {
                _ = cancel.cancelled() => break,
                _ = tick.tick() => {}
            }

            metrics::counter!("certstream_log_refresh_total").increment(1);
            let resolved = match resolve_logs(&config, &ctx).await {
                Ok(v) => v,
                Err(e) => {
                    warn!(error = %e, "log list refresh failed; keeping the running watchers");
                    metrics::counter!("certstream_log_refresh_failures_total").increment(1);
                    continue;
                }
            };

            // A resolve that yields nothing is a broken catalog, not an
            // ecosystem with no CT logs. Retiring every watcher on it would
            // turn a transient fetch problem into an outage.
            if resolved.logs.is_empty() {
                warn!("log list refresh resolved zero logs; keeping the running watchers");
                metrics::counter!("certstream_log_refresh_failures_total").increment(1);
                continue;
            }

            let (rfc, static_ct, started, stopped) = reconcile_pool(
                &mut pool.lock(),
                resolved,
                &config,
                &log_tracker,
                &ctx,
                &transport,
                false,
            );

            metrics::gauge!("certstream_log_refresh_last_success_timestamp")
                .set(chrono::Utc::now().timestamp() as f64);
            if started > 0 || stopped > 0 {
                info!(
                    added = started,
                    removed = stopped,
                    rfc6962 = rfc,
                    static_ct,
                    "log list refreshed"
                );
            } else {
                debug!(rfc6962 = rfc, static_ct, "log list refreshed, no changes");
            }
        }
        info!("log refresh task stopping");
    });
}

/// `--backfill`: replay one log's index range to JSONL and exit.
///
/// Runs the same discovery the server does, so a log can be named the way an
/// operator knows it, then hands off to the batch reader. It builds no
/// watchers, opens no channel, and never writes the live state file.
async fn run_backfill(request: Result<cli::BackfillArgs, String>, config: &Config) {
    let args = match request {
        Ok(a) => a,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(2);
        }
    };

    let user_agent = config
        .ct_log
        .user_agent_override()
        .unwrap_or(DEFAULT_USER_AGENT)
        .to_string();
    let client = match build_ct_client(&config.ct_log, &user_agent, false) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("failed to build http client: {e}");
            std::process::exit(1);
        }
    };

    let logs = match fetch_log_list(
        &client,
        &ct::catalog::catalog_registry(),
        &config.ct_log.catalog_authority_overrides,
        config.custom_logs.clone(),
        Duration::from_secs(config.ct_log.request_timeout_secs),
        &user_agent,
        &ct::LogExclusions::default(),
    )
    .await
    {
        Ok(discovered) => {
            let mut logs = discovered.reachable;
            logs.extend(config.static_logs.iter().cloned().map(ct::CtLog::from));
            logs
        }
        Err(e) => {
            eprintln!("failed to fetch the CT log list: {e}");
            std::process::exit(1);
        }
    };

    let target = match backfill::resolve_target(&logs, &args.log) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(2);
        }
    };

    let report = backfill::run(
        backfill::BackfillRequest {
            start: args.start,
            end: args.end,
            out: args.out.map(std::path::PathBuf::from),
        },
        target,
        &config.ct_log,
        &client,
    )
    .await;

    match report {
        Ok(r) => {
            eprintln!(
                "backfill complete: {} of {} entries written, {} unparseable, {} fetch failures",
                r.written, r.requested, r.unparseable, r.fetch_failures
            );
            if r.fetch_failures > 0 {
                std::process::exit(1);
            }
        }
        Err(e) => {
            eprintln!("backfill failed: {e}");
            std::process::exit(1);
        }
    }
}

#[derive(Clone, Copy)]
enum WorkerKind {
    Rfc6962,
    StaticCt,
}

impl WorkerKind {
    fn label(self) -> &'static str {
        match self {
            WorkerKind::Rfc6962 => "worker",
            WorkerKind::StaticCt => "static CT worker",
        }
    }
}

/// Start a watcher for every log in `logs` that has none yet, attaching the
/// per-operator rate limiter it shares with the other logs of its operator.
/// Logs already running are left untouched — that is what preserves their
/// position across a refresh. Returns the number newly started.
#[allow(clippy::too_many_arguments)]
fn spawn_pool(
    family: &'static str,
    enabled: bool,
    logs: Vec<ct::CtLog>,
    log_tracker: &Arc<LogTracker>,
    ctx: &WatcherContext,
    transport: &OperatorTransport,
    pool: &mut WatcherPool,
    local_keys: &std::collections::HashSet<String>,
    count_gauge: &'static str,
    startup_stagger_ms: u64,
    kind: WorkerKind,
) -> usize {
    if !enabled {
        info!(family, "watchers disabled by config");
        metrics::gauge!(count_gauge).set(0.0);
        return 0;
    }

    metrics::gauge!(count_gauge).set(logs.len() as f64);

    let fresh: Vec<ct::CtLog> = logs
        .into_iter()
        .filter(|log| !pool.running.contains_key(&watcher_key(log)))
        .collect();
    if fresh.is_empty() {
        return 0;
    }
    info!(count = fresh.len(), family, "starting CT log watchers");

    for log in &fresh {
        // Key by canonical operator name and resolve the interval from config
        // instead of a hardcoded shared default.
        let op = ct::normalize_operator(&log.operator);
        pool.operator_limiters.entry(op.clone()).or_insert_with(|| {
            let ms = ctx
                .config
                .operator_rate_limits
                .get(&op)
                .copied()
                .unwrap_or(ctx.config.default_operator_rate_limit_ms);
            // Burst = fetch_concurrency so a watcher can pipeline its
            // catch-up fetches; sustained rate stays 1 per `ms`.
            Arc::new(ct::OperatorLimiter::adaptive(
                op.clone(),
                Duration::from_millis(ms),
                ctx.config.fetch_concurrency.min(4),
            ))
        });
        log_tracker.register(
            log.description.clone(),
            log.normalized_url(),
            log.operator_name().to_string(),
        );
    }

    let count = fresh.len();
    for (index, log) in fresh.into_iter().enumerate() {
        let key = watcher_key(&log);
        let mut wctx = ctx.clone();
        let operator_key = ct::normalize_operator(&log.operator);
        wctx.rate_limiter = pool.operator_limiters.get(&operator_key).cloned();
        wctx.client = transport.client_for(&operator_key, &ctx.client).clone();
        // Catalog-discovered logs share the global config. Local custom/static
        // entries with per-log overrides get their own resolved config.
        if log.batch_size.is_some() || log.poll_interval_ms.is_some() {
            let mut cfg = (*ctx.config).clone();
            if let Some(bs) = log.batch_size {
                cfg.batch_size = bs;
            }
            if let Some(pi) = log.poll_interval_ms {
                cfg.poll_interval_ms = pi;
            }
            wctx.config = Arc::new(cfg);
        }
        // A child token so a refresh can retire this one watcher, while the
        // process shutdown token still stops every watcher at once.
        let cancel = ctx.shutdown.child_token();
        wctx.shutdown = cancel.clone();

        pool.running.insert(
            key.clone(),
            RunningWatcher {
                cancel,
                name: log.description.clone(),
                url: log.normalized_url(),
                local: local_keys.contains(&key),
            },
        );
        spawn_worker_loop(log, wctx, startup_stagger_ms * index as u64, kind);
    }
    count
}

/// How long a watcher that gave up waits before it is started again: first
/// this, doubling up to the cap. A watcher that ran for `WATCHER_HEALTHY_AFTER`
/// before giving up starts over from the first wait.
const WATCHER_RESTART_INITIAL: Duration = Duration::from_secs(30);
const WATCHER_RESTART_MAX: Duration = Duration::from_secs(15 * 60);
const WATCHER_HEALTHY_AFTER: Duration = Duration::from_secs(10 * 60);

fn restart_wait(previous: Option<Duration>, ran_for: Duration) -> Duration {
    match previous {
        Some(wait) if ran_for < WATCHER_HEALTHY_AFTER => (wait * 2).min(WATCHER_RESTART_MAX),
        _ => WATCHER_RESTART_INITIAL,
    }
}

/// Supervisor that keeps a watcher running. On panic it logs the failure,
/// bumps the `certstream_worker_panics` counter, sleeps 5s, and restarts. A
/// watcher that returns on its own gave up, usually because the log refused
/// its first checkpoint, and is restarted after a growing wait: without that a
/// log that is rate limiting at startup stays dead until the process restarts.
/// Exits cleanly on shutdown cancellation.
fn spawn_worker_loop(log: ct::CtLog, ctx: WatcherContext, startup_delay_ms: u64, kind: WorkerKind) {
    let cancel = ctx.shutdown.clone();
    tokio::spawn(async move {
        if startup_delay_ms > 0 {
            tokio::time::sleep(Duration::from_millis(startup_delay_ms)).await;
        }
        let log_name = log.description.clone();
        let label = kind.label();
        let mut last_wait: Option<Duration> = None;
        loop {
            let started = std::time::Instant::now();
            let fut = std::panic::AssertUnwindSafe(async {
                match kind {
                    WorkerKind::Rfc6962 => {
                        ct::watcher::run_watcher_with_cache(log.clone(), ctx.clone()).await
                    }
                    WorkerKind::StaticCt => {
                        ct::static_ct::run_static_ct_watcher(log.clone(), ctx.clone()).await
                    }
                }
            });

            tokio::select! {
                _ = cancel.cancelled() => {
                    info!(log = %log_name, kind = %label, "worker stopped by shutdown signal");
                    break;
                }
                res = futures::FutureExt::catch_unwind(fut) => {
                    match res {
                        Ok(_) if cancel.is_cancelled() => break,
                        Ok(_) => {
                            let wait = restart_wait(last_wait, started.elapsed());
                            last_wait = Some(wait);
                            warn!(log = %log_name, kind = %label, wait_secs = wait.as_secs(), "worker stopped on its own, restarting");
                            tokio::select! {
                                _ = cancel.cancelled() => break,
                                _ = tokio::time::sleep(wait) => {}
                            }
                        }
                        Err(_) => {
                            error!(log = %log_name, kind = %label, "worker panicked, restarting in 5s");
                            metrics::counter!("certstream_worker_panics").increment(1);
                            tokio::time::sleep(Duration::from_secs(5)).await;
                        }
                    }
                }
            }
        }
    });
}

/// Dependencies needed to build the HTTP router.
struct RouterDeps {
    tx: broadcast::Sender<Arc<PreSerializedMessage>>,
    filter_hub: Arc<filter::FilterHub>,
    connection_limiter: Arc<ConnectionLimiter>,
    server_stats: Arc<ServerStats>,
    cert_cache: Arc<CertificateCache>,
    log_tracker: Arc<LogTracker>,
    rate_limiter: Arc<RateLimiter>,
    hot_reload_manager: Option<Arc<HotReloadManager>>,
    prometheus_handle: metrics_exporter_prometheus::PrometheusHandle,
    started_at: std::time::Instant,
    shutdown_token: CancellationToken,
}

fn build_router(protocols: &config::ProtocolConfig, config: &Config, deps: RouterDeps) -> Router {
    let RouterDeps {
        tx,
        filter_hub,
        connection_limiter,
        server_stats,
        cert_cache,
        log_tracker,
        rate_limiter,
        hot_reload_manager,
        prometheus_handle,
        started_at,
        shutdown_token,
    } = deps;
    let streams = Arc::new(config.streams.clone());
    let state = Arc::new(AppState {
        filters: filter_hub,
        deflate: deflate::DeflateHub::new(tx.clone(), config.buffer_size),
        tx: tx.clone(),
        connections: ConnectionCounter::new(),
        limiter: connection_limiter.clone(),
        streams: streams.clone(),
        stats: server_stats.clone(),
        shutdown: shutdown_token.clone(),
    });
    let auth_middleware_state = Arc::new(AuthMiddleware::new(
        &config.auth,
        hot_reload_manager.clone(),
    ));
    let api_state = Arc::new(ApiState {
        stats: server_stats.clone(),
        cache: cert_cache.clone(),
        log_tracker: log_tracker.clone(),
        ws_state: state.clone(),
    });

    // Public routes: always accessible, never behind auth or rate limiting.
    // Kubernetes probes and Prometheus scrapers must reach these without tokens.
    let mut public_app = Router::new();

    if protocols.health {
        let health_state = Arc::new(HealthState {
            log_tracker: log_tracker.clone(),
            limiter: connection_limiter.clone(),
            started_at,
        });
        public_app = public_app
            .route("/health", get(health))
            .route("/health/deep", get(deep_health).with_state(health_state));
    }

    if protocols.metrics {
        public_app = public_app.route(
            "/metrics",
            get(move || async move { prometheus_handle.render() }),
        );
    }

    if protocols.example_json {
        public_app = public_app.route("/example.json", get(example_json));
    }

    // Protected routes: subject to auth and rate limiting when enabled.
    let mut protected_app = Router::new();

    if protocols.api {
        let api_router = Router::new()
            .route("/api/stats", get(api::handle_stats))
            .route("/api/logs", get(api::handle_logs))
            .route("/api/cert/{hash}", get(api::handle_cert))
            .with_state(api_state);
        protected_app = protected_app.merge(api_router);
        info!("REST API enabled");
    }

    if protocols.websocket {
        let mut ws_router = Router::new();
        if streams.lite {
            ws_router = ws_router.route("/", get(handle_lite_stream));
        }
        if streams.full {
            ws_router = ws_router.route("/full-stream", get(handle_full_stream));
        }
        if streams.domains_only {
            ws_router = ws_router.route("/domains-only", get(handle_domains_only));
        }
        if streams.v2 {
            ws_router = ws_router.route("/v2", get(handle_v2_stream));
        }
        let ws_router = ws_router.with_state(state.clone());
        protected_app = protected_app.merge(ws_router);
        info!("WebSocket protocol enabled");
    }

    if protocols.sse {
        let sse_router = Router::new()
            .route("/sse", get(handle_sse_stream))
            .with_state(state.clone());
        protected_app = protected_app.merge(sse_router);
        info!("SSE protocol enabled");
    }

    let protected_app = if config.auth.enabled {
        info!("token authentication enabled");
        protected_app.layer(axum_middleware::from_fn_with_state(
            auth_middleware_state,
            auth_middleware,
        ))
    } else {
        protected_app
    };

    if config.connection_limit.enabled {
        let conn_limiter = connection_limiter.clone();
        let cl_cancel = shutdown_token.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(300));
            loop {
                tokio::select! {
                    _ = cl_cancel.cancelled() => break,
                    _ = interval.tick() => conn_limiter.cleanup_stale(),
                }
            }
        });
    }

    let protected_app = if config.rate_limit.enabled {
        info!("rate limiting enabled (token bucket + sliding window)");
        let limiter = rate_limiter.clone();
        let rate_limit_cancel = shutdown_token.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(300));
            loop {
                tokio::select! {
                    _ = rate_limit_cancel.cancelled() => break,
                    _ = interval.tick() => limiter.cleanup_stale(Duration::from_secs(600)),
                }
            }
        });
        protected_app.layer(axum_middleware::from_fn_with_state(
            rate_limiter.clone(),
            rate_limit_middleware,
        ))
    } else {
        protected_app
    };

    if config.connection_limit.enabled {
        info!(
            max_connections = config.connection_limit.max_connections,
            per_ip_limit = ?config.connection_limit.per_ip_limit,
            "connection limiting enabled"
        );
    }

    // CORS policy:
    //   * `public_app` (/health, /metrics, /example.json) is operator-facing —
    //     intended for Kubernetes probes and Prometheus scrapers, NOT for
    //     cross-origin browser fetches. We don't add CORS headers; a malicious
    //     web page cannot read /metrics from a victim's browser.
    //   * `protected_app` (WS, SSE, /api/cert/{hash}) is the public data
    //     surface — browser CT viewers consume it cross-origin, so it gets a
    //     permissive (any origin, GET only) CORS layer. Auth tokens, when
    //     enabled, are sent via header so credentials=false is fine.
    let protected_app = protected_app.layer(
        CorsLayer::new()
            .allow_origin(CorsAny)
            .allow_methods([axum::http::Method::GET, axum::http::Method::HEAD])
            .allow_headers(CorsAny),
    );

    let router = Router::new()
        .merge(public_app)
        .merge(protected_app)
        .fallback(handler_404);

    let trusted_proxies = TrustedProxies::parse(&config.trusted_proxies)
        .expect("trusted_proxies was checked when the configuration was validated");
    if trusted_proxies.is_empty() {
        return router;
    }
    // Outermost, so the limiters and handlers all see the resolved client.
    router.layer(axum_middleware::from_fn_with_state(
        Arc::new(trusted_proxies),
        resolve_client_ip,
    ))
}

async fn run_tls_server(
    addr: SocketAddr,
    app: Router,
    tls_cert: &Option<String>,
    tls_key: &Option<String>,
    shutdown_token: CancellationToken,
) {
    let cert_path = match tls_cert.as_ref() {
        Some(p) => p,
        None => {
            error!("TLS mode requested but tls_cert is missing");
            shutdown_token.cancel();
            return;
        }
    };
    let key_path = match tls_key.as_ref() {
        Some(p) => p,
        None => {
            error!("TLS mode requested but tls_key is missing");
            shutdown_token.cancel();
            return;
        }
    };

    let tls_config =
        match axum_server::tls_rustls::RustlsConfig::from_pem_file(cert_path, key_path).await {
            Ok(c) => c,
            Err(e) => {
                error!(cert = %cert_path, key = %key_path, error = %e, "failed to load TLS config");
                shutdown_token.cancel();
                return;
            }
        };

    tokio::spawn(tls::reload_when_files_change(
        tls_config.clone(),
        cert_path.clone(),
        key_path.clone(),
        Duration::from_secs(60),
        shutdown_token.clone(),
    ));

    let handle = axum_server::Handle::new();
    let shutdown_handle = handle.clone();
    let cancel_for_signal = shutdown_token.clone();
    tokio::spawn(async move {
        cancel_for_signal.cancelled().await;
        info!("shutting down TLS server");
        shutdown_handle.graceful_shutdown(Some(Duration::from_secs(30)));
    });

    if let Err(e) = axum_server::bind_rustls(addr, tls_config)
        .handle(handle)
        .serve(app.into_make_service_with_connect_info::<SocketAddr>())
        .await
    {
        error!(error = %e, "TLS server exited with error");
        shutdown_token.cancel();
    }
}

async fn run_plain_server(addr: SocketAddr, app: Router, shutdown_token: CancellationToken) {
    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            error!(address = %addr, error = %e, "failed to bind listener");
            shutdown_token.cancel();
            return;
        }
    };

    let cancel_for_graceful = shutdown_token.clone();
    if let Err(e) = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(async move {
        cancel_for_graceful.cancelled().await;
        info!("shutting down HTTP server");
    })
    .await
    {
        error!(error = %e, "HTTP server exited with error");
        shutdown_token.cancel();
    }
}

async fn handler_404() -> impl IntoResponse {
    (
        axum::http::StatusCode::NOT_FOUND,
        [(header::CONTENT_TYPE, "application/json")],
        r#"{"error":"Not Found"}"#,
    )
}

fn print_config_validation(config: &Config) {
    println!("Validating configuration...");
    match config.validate() {
        Ok(()) => {
            println!("Configuration is valid.");
            if let Some(ref path) = config.config_path {
                println!("Config file: {}", path);
            }
            println!("Host: {}", config.host);
            println!("Port: {}", config.port);
            println!("Log level: {}", config.log_level);
            println!("Buffer size: {}", config.buffer_size);
            println!("WebSocket: {}", config.protocols.websocket);
            println!("SSE: {}", config.protocols.sse);
            println!("API: {}", config.protocols.api);
            println!("Metrics: {}", config.protocols.metrics);
            println!("Connection limit enabled: {}", config.connection_limit.enabled);
            println!("Rate limit enabled: {}", config.rate_limit.enabled);
            println!("Auth enabled: {}", config.auth.enabled);
            println!("Hot reload enabled: {}", config.hot_reload.enabled);
        }
        Err(errors) => {
            eprintln!("Configuration validation failed:");
            for err in errors {
                eprintln!("  - {}: {}", err.field, err.message);
            }
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use config::RemovedLogPolicy;
    use std::collections::{HashMap, HashSet};

    fn test_log(description: &str, url: &str, log_id: Option<&str>) -> ct::CtLog {
        ct::CtLog::from(config::CustomCtLog {
            name: description.to_string(),
            url: url.to_string(),
            expected_log_id: log_id.map(str::to_string),
            batch_size: None,
            poll_interval_ms: None,
        })
    }

    fn running(pool: &mut WatcherPool, key: &str, url: &str, local: bool) -> CancellationToken {
        let cancel = CancellationToken::new();
        pool.running.insert(
            key.to_string(),
            RunningWatcher {
                cancel: cancel.clone(),
                name: key.to_string(),
                url: url.to_string(),
                local,
            },
        );
        cancel
    }

    /// A log's identity across refreshes is its key hash, not its URL: an
    /// operator that moves a log to a new hostname must not look like one log
    /// leaving and a different one arriving.
    #[test]
    fn watcher_key_prefers_the_log_id_over_the_url() {
        let before = test_log("Argon", "https://ct.example.com/2026h1/", Some("abc123="));
        let after = test_log("Argon", "https://ct2.example.com/2026h1/", Some("abc123="));
        assert_eq!(watcher_key(&before), watcher_key(&after));
        assert_eq!(watcher_key(&before), "id:abc123=");
    }

    #[test]
    fn watcher_key_falls_back_to_the_normalized_url() {
        let no_id = test_log("Local", "ct.example.com/log/", None);
        let empty_id = test_log("Local", "https://ct.example.com/log", Some(""));
        assert_eq!(watcher_key(&no_id), "url:https://ct.example.com/log");
        assert_eq!(watcher_key(&no_id), watcher_key(&empty_id));
    }

    #[test]
    fn retire_absent_stops_only_delisted_catalog_logs() {
        let tracker = LogTracker::new();
        let mut pool = WatcherPool::default();
        let kept = running(&mut pool, "id:still-listed", "https://a.example", false);
        let gone = running(&mut pool, "id:delisted", "https://b.example", false);

        let present = HashSet::from(["id:still-listed".to_string()]);
        let stopped = retire_absent(&mut pool, &present, RemovedLogPolicy::Stop, &tracker);

        assert_eq!(stopped, 1);
        assert!(gone.is_cancelled(), "the delisted watcher must be cancelled");
        assert!(!kept.is_cancelled(), "a listed watcher must keep running");
        assert!(pool.running.contains_key("id:still-listed"));
        assert!(!pool.running.contains_key("id:delisted"));
    }

    /// A log the operator put in `custom_logs` / `static_logs` is not the
    /// catalog's to remove.
    #[test]
    fn retire_absent_never_stops_a_locally_configured_log() {
        let tracker = LogTracker::new();
        let mut pool = WatcherPool::default();
        let local = running(&mut pool, "url:https://mine.example", "https://mine.example", true);

        let stopped = retire_absent(&mut pool, &HashSet::new(), RemovedLogPolicy::Stop, &tracker);

        assert_eq!(stopped, 0);
        assert!(!local.is_cancelled());
        assert!(pool.running.contains_key("url:https://mine.example"));
    }

    #[test]
    fn keep_policy_leaves_delisted_watchers_running() {
        let tracker = LogTracker::new();
        let mut pool = WatcherPool::default();
        let delisted = running(&mut pool, "id:delisted", "https://b.example", false);

        let stopped = retire_absent(&mut pool, &HashSet::new(), RemovedLogPolicy::Keep, &tracker);

        assert_eq!(stopped, 0);
        assert!(!delisted.is_cancelled());
    }

    /// A watcher that returns without being cancelled gave up, usually because
    /// the log refused its first checkpoint. It is restarted after a wait that
    /// doubles up to a cap, and starts over once it has run for a while.
    #[test]
    fn a_giving_up_watcher_backs_off_and_resets_after_running() {
        let quick = Duration::from_secs(1);
        let first = restart_wait(None, quick);
        assert_eq!(first, WATCHER_RESTART_INITIAL);
        assert_eq!(restart_wait(Some(first), quick), first * 2);

        let mut wait = first;
        for _ in 0..20 {
            wait = restart_wait(Some(wait), quick);
        }
        assert_eq!(wait, WATCHER_RESTART_MAX, "the wait must stop growing");

        assert_eq!(
            restart_wait(Some(WATCHER_RESTART_MAX), WATCHER_HEALTHY_AFTER),
            WATCHER_RESTART_INITIAL,
            "a watcher that ran for a while starts over"
        );
    }

    /// A log the catalog still lists but that failed this cycle's availability
    /// probe is slow or throttling us, not delisted. Stopping its watcher
    /// would lose the log until the next restart.
    #[test]
    fn a_listed_log_that_failed_the_probe_keeps_its_watcher() {
        let tracker = LogTracker::new();
        let mut pool = WatcherPool::default();
        let throttled = test_log("Eszigno", "https://eszigno.example/2026h2/", Some("abc="));
        let watcher = running(
            &mut pool,
            &watcher_key(&throttled),
            &throttled.normalized_url(),
            false,
        );
        let resolved = ResolvedLogs {
            logs: Vec::new(),
            local_keys: HashSet::new(),
            unreachable_keys: HashSet::from([watcher_key(&throttled)]),
        };

        let stopped = retire_absent(
            &mut pool,
            &resolved.listed_keys(),
            RemovedLogPolicy::Stop,
            &tracker,
        );

        assert_eq!(stopped, 0);
        assert!(!watcher.is_cancelled());
    }

    /// Retiring a watcher has to take the log out of the tracker too, or
    /// `/api/logs` and the health rollup keep counting a watcher that is gone.
    #[test]
    fn retiring_a_watcher_deregisters_it_from_the_tracker() {
        let tracker = LogTracker::new();
        tracker.register(
            "Delisted".to_string(),
            "https://b.example".to_string(),
            "Test".to_string(),
        );
        assert_eq!(tracker.get_all().len(), 1);

        let mut pool = WatcherPool::default();
        running(&mut pool, "id:delisted", "https://b.example", false);
        retire_absent(&mut pool, &HashSet::new(), RemovedLogPolicy::Stop, &tracker);

        assert!(tracker.get_all().is_empty());
    }

    /// The point of keying the pool: a refresh that re-lists a running log
    /// must not spawn a second watcher for it, because restarting one would
    /// throw away its in-memory position.
    #[test]
    fn a_relisted_log_is_not_spawned_again() {
        let mut pool = WatcherPool::default();
        let log = test_log("Argon", "https://ct.example.com/2026h1/", Some("abc123="));
        running(&mut pool, &watcher_key(&log), &log.normalized_url(), false);

        let fresh: Vec<&ct::CtLog> = [&log]
            .into_iter()
            .filter(|l| !pool.running.contains_key(&watcher_key(l)))
            .collect();

        assert!(fresh.is_empty(), "an already-running log must be skipped");
    }

    /// Cancelling the process token must still stop watchers whose own token
    /// is a child of it.
    #[test]
    fn a_child_token_is_cancelled_by_the_process_token() {
        let process = CancellationToken::new();
        let watcher = process.child_token();
        assert!(!watcher.is_cancelled());
        process.cancel();
        assert!(watcher.is_cancelled());
    }

    /// …and cancelling one watcher must not touch its siblings or the parent.
    #[test]
    fn cancelling_one_child_token_leaves_the_others_alone() {
        let process = CancellationToken::new();
        let a = process.child_token();
        let b = process.child_token();
        a.cancel();
        assert!(a.is_cancelled());
        assert!(!b.is_cancelled());
        assert!(!process.is_cancelled());
    }

    /// `operator_limiters` is shared across refreshes so a log added later
    /// lands in the same token bucket as its operator's existing logs —
    /// otherwise a refresh would quietly double that operator's request rate.
    #[test]
    fn operator_limiters_are_reused_across_reconciles() {
        let mut limiters: HashMap<String, ct::OperatorRateLimiter> = HashMap::new();
        let make = || {
            Arc::new(ct::OperatorLimiter::with_burst(
                Duration::from_millis(500),
                4,
            ))
        };
        let first = limiters.entry("digicert".into()).or_insert_with(make).clone();
        let second = limiters.entry("digicert".into()).or_insert_with(make).clone();
        assert!(Arc::ptr_eq(&first, &second));
    }

    fn transport_with(operators: &[&str]) -> OperatorTransport {
        let ct_log = CtLogConfig {
            force_http1_operators: operators.iter().map(|s| s.to_string()).collect(),
            ..CtLogConfig::default()
        };
        OperatorTransport::new(&ct_log, DEFAULT_USER_AGENT)
    }

    #[test]
    fn transport_matches_operators_by_canonical_name() {
        let transport = transport_with(&["DigiCert, Inc."]);
        assert!(transport.uses_http1(&ct::normalize_operator("digicert inc")));
        assert!(transport.uses_http1(&ct::normalize_operator("  DigiCert  Inc  ")));
        // The catalog-emitted "DigiCert" is a different canonical name than
        // "DigiCert, Inc." — punctuation collapses, the suffix does not.
        assert!(!transport.uses_http1(&ct::normalize_operator("DigiCert")));
        assert!(!transport.uses_http1(&ct::normalize_operator("Google")));
    }

    #[test]
    fn transport_without_listed_operators_builds_no_client() {
        let transport = transport_with(&[]);
        assert!(transport.client.is_none());
        assert!(!transport.uses_http1("digicert"));
    }

    #[test]
    fn transport_returns_shared_client_for_unlisted_operators() {
        let transport = transport_with(&["DigiCert"]);
        let shared = Client::new();
        assert!(!std::ptr::eq(
            transport.client_for("digicert", &shared),
            &shared
        ));
        assert!(std::ptr::eq(transport.client_for("google", &shared), &shared));
    }

    #[test]
    fn unmatched_operator_keys_reports_only_misses() {
        let known: std::collections::HashSet<String> =
            ["digicert", "google"].iter().map(|s| s.to_string()).collect();
        let configured = vec![
            "DigiCert".to_string(),
            "Geomys".to_string(),
            "sectigo".to_string(),
        ];
        assert_eq!(
            unmatched_operator_keys(&configured, &known),
            vec!["Geomys".to_string(), "sectigo".to_string()]
        );
        assert!(unmatched_operator_keys(std::iter::empty(), &known).is_empty());
    }
}
