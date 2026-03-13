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
use tower_http::cors::CorsLayer;
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
use rate_limit::{RateLimiter, TierTokens};
use sse::handle_sse_stream;
use state::StateManager;
use websocket::{handle_domains_only, handle_full_stream, handle_lite_stream, AppState, ConnectionCounter};

#[tokio::main]
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

    let (tx, _rx) = broadcast::channel::<Arc<PreSerializedMessage>>(config.buffer_size);

    let client = Client::builder()
        .user_agent(format!("certstream-server-rust/{}", VERSION))
        .pool_max_idle_per_host(20)
        .pool_idle_timeout(Duration::from_secs(90))
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

    let dedup_filter = Arc::new(DedupFilter::new());
    dedup_filter.clone().start_cleanup_task(shutdown_token.clone());
    info!("cross-log dedup filter enabled");

    let ct_log_config = Arc::new(config.ct_log.clone());
    let log_tracker = Arc::new(LogTracker::new());
    let server_stats = Arc::new(ServerStats::new());
    let cert_cache = Arc::new(CertificateCache::new(config.api.cache_capacity));

    let tier_tokens = TierTokens {
        standard: config.auth.standard_tokens.clone(),
        premium: config.auth.premium_tokens.clone(),
    };
    let rate_limiter = RateLimiter::new(
        config.rate_limit.clone(),
        tier_tokens,
        hot_reload_manager.clone(),
    );

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
        };

        spawn_rfc6962_watchers(&config, &log_tracker, &watcher_ctx).await;
        spawn_static_ct_watchers(&config, &log_tracker, &watcher_ctx);
    } else {
        info!("dry-run mode: skipping CT log connections");
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

async fn spawn_rfc6962_watchers(
    config: &Config,
    log_tracker: &Arc<LogTracker>,
    ctx: &WatcherContext,
) {
    use std::collections::HashMap;
    use ct::OperatorRateLimiter;

    match fetch_log_list(&ctx.client, &config.ct_logs_url, config.custom_logs.clone()).await {
        Ok(logs) => {
            info!(count = logs.len(), "found CT logs");
            metrics::gauge!("certstream_ct_logs_count").set(logs.len() as f64);

            // Build per-operator rate limiters (500ms = 2 req/s shared across all logs of same operator)
            let mut operator_limiters: HashMap<String, OperatorRateLimiter> = HashMap::new();
            for log in &logs {
                let op = log.operator.to_lowercase();
                operator_limiters.entry(op).or_insert_with(|| {
                    let interval = tokio::time::interval(Duration::from_millis(500));
                    Arc::new(tokio::sync::Mutex::new(interval))
                });
            }

            for log in &logs {
                log_tracker.register(
                    log.description.clone(),
                    log.normalized_url(),
                    log.operator.clone(),
                );
            }

            for (index, log) in logs.into_iter().enumerate() {
                let mut ctx = ctx.clone();
                let op = log.operator.to_lowercase();
                ctx.rate_limiter = operator_limiters.get(&op).cloned();
                let cancel = ctx.shutdown.clone();

                tokio::spawn(async move {
                    tokio::time::sleep(Duration::from_millis(50 * index as u64)).await;

                    let log_name = log.description.clone();
                    loop {
                        let result = std::panic::AssertUnwindSafe(
                            ct::watcher::run_watcher_with_cache(log.clone(), ctx.clone()),
                        );

                        tokio::select! {
                            _ = cancel.cancelled() => {
                                info!(log = %log_name, "worker stopped by shutdown signal");
                                break;
                            }
                            res = futures::FutureExt::catch_unwind(result) => {
                                match res {
                                    Ok(_) => break,
                                    Err(_) => {
                                        error!(log = %log_name, "worker panicked, restarting in 5s");
                                        metrics::counter!("certstream_worker_panics").increment(1);
                                        tokio::time::sleep(Duration::from_secs(5)).await;
                                    }
                                }
                            }
                        }
                    }
                });
            }
        }
        Err(e) => {
            error!(error = %e, "failed to fetch CT log list");
            std::process::exit(1);
        }
    }
}

fn spawn_static_ct_watchers(
    config: &Config,
    log_tracker: &Arc<LogTracker>,
    ctx: &WatcherContext,
) {
    if config.static_logs.is_empty() {
        return;
    }

    metrics::gauge!("certstream_static_ct_logs_count").set(config.static_logs.len() as f64);

    for (index, static_log) in config.static_logs.iter().enumerate() {
        let ct_log = ct::CtLog::from(static_log.clone());
        log_tracker.register(
            ct_log.description.clone(),
            ct_log.normalized_url(),
            ct_log.operator.clone(),
        );

        let ctx = ctx.clone();
        let cancel = ctx.shutdown.clone();

        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(100 * index as u64)).await;

            let log_name = ct_log.description.clone();
            loop {
                let result = std::panic::AssertUnwindSafe(
                    ct::static_ct::run_static_ct_watcher(ct_log.clone(), ctx.clone()),
                );

                tokio::select! {
                    _ = cancel.cancelled() => {
                        info!(log = %log_name, "static CT worker stopped by shutdown signal");
                        break;
                    }
                    res = futures::FutureExt::catch_unwind(result) => {
                        match res {
                            Ok(_) => break,
                            Err(_) => {
                                error!(log = %log_name, "static CT worker panicked, restarting in 5s");
                                metrics::counter!("certstream_worker_panics").increment(1);
                                tokio::time::sleep(Duration::from_secs(5)).await;
                            }
                        }
                    }
                }
            }
        });
    }

    info!(count = config.static_logs.len(), "static CT log watchers started");
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

    let protected_app = if config.rate_limit.enabled {
        info!("rate limiting enabled (token bucket + sliding window)");
        let limiter = rate_limiter.clone();
        let rate_limit_cancel = shutdown_token.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(300));
            loop {
                tokio::select! {
                    _ = rate_limit_cancel.cancelled() => break,
                    _ = interval.tick() => {
                        limiter.cleanup_stale(Duration::from_secs(600));
                    }
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

    Router::new()
        .merge(public_app)
        .merge(protected_app)
        .layer(CorsLayer::permissive())
        .fallback(handler_404)
}

async fn run_tls_server(
    addr: SocketAddr,
    app: Router,
    tls_cert: &Option<String>,
    tls_key: &Option<String>,
    shutdown_token: CancellationToken,
) {
    let tls_config = axum_server::tls_rustls::RustlsConfig::from_pem_file(
        tls_cert.as_ref().unwrap(),
        tls_key.as_ref().unwrap(),
    )
    .await
    .expect("failed to load TLS config");

    let handle = axum_server::Handle::new();
    let shutdown_handle = handle.clone();
    tokio::spawn(async move {
        shutdown_token.cancelled().await;
        info!("shutting down TLS server");
        shutdown_handle.graceful_shutdown(Some(Duration::from_secs(30)));
    });

    axum_server::bind_rustls(addr, tls_config)
        .handle(handle)
        .serve(app.into_make_service_with_connect_info::<SocketAddr>())
        .await
        .expect("server error");
}

async fn run_plain_server(addr: SocketAddr, app: Router, shutdown_token: CancellationToken) {
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("failed to bind");
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(async move {
        shutdown_token.cancelled().await;
        info!("shutting down HTTP server");
    })
    .await
    .expect("server error");
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
