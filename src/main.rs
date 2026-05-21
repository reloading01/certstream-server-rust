mod api;
mod cli;
mod config;
mod ct;
mod dedup;
mod health;
mod hot_reload;
mod middleware;
mod models;
mod rate_limit;
mod sse;
mod state;
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
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

use api::{ApiState, CertificateCache, LogTracker, ServerStats};
use cli::{CliArgs, VERSION};
use config::Config;
use ct::{fetch_log_list, WatcherContext};
use dedup::DedupFilter;
use health::{deep_health, example_json, health, HealthState};
use hot_reload::{HotReloadManager, HotReloadableConfig};
use middleware::{auth_middleware, rate_limit_middleware, AuthMiddleware, ConnectionLimiter};
use models::PreSerializedMessage;
use rate_limit::RateLimiter;
use sse::handle_sse_stream;
use state::StateManager;
use websocket::{handle_domains_only, handle_full_stream, handle_lite_stream, AppState, ConnectionCounter};

// CT polling + WS broadcast are heavily I/O-bound; CPU work is bursty (JSON
// parse + cert deserialise) and cheap relative to the network wait. 4 worker
// threads is plenty in practice and saves ~8 MiB of resident memory vs the
// runtime default (= number of logical CPUs, often 8 on modern hosts).
// Operators with extreme load can override via TOKIO_WORKER_THREADS env var.
#[tokio::main(worker_threads = 4)]
async fn main() {
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
    // (P0 fix.) `--export-metrics` and `--dry-run` are still allowed to skip
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

    // No placeholder Receiver here. The pre-1.5.0 version bound `_rx` which
    // stayed alive for the whole process — that kept `tx.receiver_count()` at
    // ≥1 forever and silently defeated the idle-server pre-serialize guard
    // (#13). `tx.send()` returning `Err(SendError)` on zero subscribers is
    // already ignored downstream (`let _ = tx.send(...)`), so no placeholder
    // is needed for correctness.
    let tx: broadcast::Sender<Arc<PreSerializedMessage>> =
        broadcast::channel(config.buffer_size).0;

    let client = Client::builder()
        .user_agent(format!("certstream-server-rust/{}", VERSION))
        // Pre-1.5.0 kept 20 idle connections per host × 55 hosts = 1100
        // hot TCP sockets, ~40-55 MiB of kernel + TLS state per process.
        // CT log polls are sequential per watcher (rate-limited at the
        // OperatorLimiter); 4 idle per host is enough for retry overlap.
        .pool_max_idle_per_host(2)
        .pool_idle_timeout(Duration::from_secs(30))
        .tcp_nodelay(true)
        .build()
        .expect("failed to build http client");

    let state_manager = StateManager::new(config.ct_log.state_file.clone());
    if config.ct_log.state_file.is_some() {
        state_manager
            .clone()
            .start_periodic_save(Duration::from_secs(30), shutdown_token.clone());
        info!("state persistence enabled");
    }

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

    info!(url = %config.ct_logs_url, "fetching CT log list");

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
            rate_limiter: None,
            streams: streams.clone(),
            issuer_cache: issuer_cache.clone(),
        };

        let (rfc_count, static_count) =
            discover_and_spawn(&config, &log_tracker, &watcher_ctx).await;

        if rfc_count == 0 && static_count == 0 {
            error!("no CT log watchers were started — refusing to run with zero sources");
            std::process::exit(1);
        }
        info!(rfc6962 = rfc_count, static_ct = static_count, "CT watcher pool started");
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

/// Build a fresh `OperatorRateLimiter` capped at 2 req/s, shared across all
/// logs of the same operator so a single CDN host doesn't see a thundering
/// herd from per-shard watchers.
fn make_operator_limiter() -> ct::OperatorRateLimiter {
    Arc::new(ct::OperatorLimiter::new(Duration::from_millis(500)))
}

/// Discovery + spawn pipeline. Returns `(rfc6962_count, static_ct_count)`.
async fn discover_and_spawn(
    config: &Config,
    log_tracker: &Arc<LogTracker>,
    ctx: &WatcherContext,
) -> (usize, usize) {
    use std::collections::HashMap;
    use ct::{LogType, OperatorRateLimiter};

    let discovered = fetch_log_list(
        &ctx.client,
        &config.ct_logs_url,
        &config.additional_log_lists,
        config.custom_logs.clone(),
    )
    .await;

    let mut all_logs = match discovered {
        Ok(v) => v,
        Err(e) => {
            error!(error = %e, "failed to fetch any CT log list");
            Vec::new()
        }
    };

    // Splice in the user's static_logs from config. We dedupe by URL so a
    // user-provided override (e.g. with a custom log_origin) takes precedence
    // over discovery for the same monitoring URL.
    let config_static_urls: std::collections::HashSet<String> = config
        .static_logs
        .iter()
        .map(|sl| sl.url.trim_end_matches('/').to_string())
        .collect();
    all_logs.retain(|l| {
        l.log_type != LogType::StaticCt
            || !config_static_urls.contains(l.url.trim_end_matches('/'))
    });
    for sl in &config.static_logs {
        all_logs.push(ct::CtLog::from(sl.clone()));
    }

    // Partition by type — the two watcher pools differ in protocol.
    let (rfc_logs, static_logs): (Vec<_>, Vec<_>) =
        all_logs.into_iter().partition(|l| l.log_type == LogType::Rfc6962);

    let mut operator_limiters: HashMap<String, OperatorRateLimiter> = HashMap::new();

    let rfc_count = spawn_pool(
        "RFC 6962",
        config.ct_log.rfc6962_enabled,
        rfc_logs,
        log_tracker,
        ctx,
        &mut operator_limiters,
        "certstream_ct_logs_count",
        50,
        WorkerKind::Rfc6962,
    );

    let static_count = spawn_pool(
        "static-ct-api",
        config.ct_log.static_ct_enabled,
        static_logs,
        log_tracker,
        ctx,
        &mut operator_limiters,
        "certstream_static_ct_logs_count",
        100,
        WorkerKind::StaticCt,
    );

    (rfc_count, static_count)
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

/// Register a pool of watchers, attach per-operator rate limiters, and spawn
/// each worker behind a restart-on-panic supervisor. Returns the number of
/// workers actually spawned (0 if the pool is disabled by config).
#[allow(clippy::too_many_arguments)]
fn spawn_pool(
    family: &'static str,
    enabled: bool,
    logs: Vec<ct::CtLog>,
    log_tracker: &Arc<LogTracker>,
    ctx: &WatcherContext,
    operator_limiters: &mut std::collections::HashMap<String, ct::OperatorRateLimiter>,
    count_gauge: &'static str,
    startup_stagger_ms: u64,
    kind: WorkerKind,
) -> usize {
    if !enabled {
        info!(family, "watchers disabled by config");
        metrics::gauge!(count_gauge).set(0.0);
        return 0;
    }

    info!(count = logs.len(), family, "found CT logs");
    metrics::gauge!(count_gauge).set(logs.len() as f64);

    for log in &logs {
        operator_limiters
            .entry(log.operator.to_lowercase())
            .or_insert_with(make_operator_limiter);
        log_tracker.register(
            log.description.clone(),
            log.normalized_url(),
            log.operator.clone(),
        );
    }

    let count = logs.len();
    for (index, log) in logs.into_iter().enumerate() {
        let mut wctx = ctx.clone();
        wctx.rate_limiter = operator_limiters
            .get(&log.operator.to_lowercase())
            .cloned();
        spawn_worker_loop(log, wctx, startup_stagger_ms * index as u64, kind);
    }
    count
}

/// Supervisor that runs a watcher in a panic-resilient loop. On panic, logs
/// the failure, bumps the `certstream_worker_panics` counter, sleeps 5s, and
/// restarts. Exits cleanly on shutdown cancellation.
fn spawn_worker_loop(log: ct::CtLog, ctx: WatcherContext, startup_delay_ms: u64, kind: WorkerKind) {
    let cancel = ctx.shutdown.clone();
    tokio::spawn(async move {
        if startup_delay_ms > 0 {
            tokio::time::sleep(Duration::from_millis(startup_delay_ms)).await;
        }
        let log_name = log.description.clone();
        let label = kind.label();
        loop {
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
                        Ok(_) => break,
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
        tx: tx.clone(),
        connections: ConnectionCounter::new(),
        limiter: connection_limiter.clone(),
        streams: streams.clone(),
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

    Router::new()
        .merge(public_app)
        .merge(protected_app)
        .fallback(handler_404)
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
