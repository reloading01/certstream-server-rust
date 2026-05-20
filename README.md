# certstream-server-rust

A high-performance **certstream server** written in Rust. Monitors Certificate Transparency logs and streams newly issued SSL/TLS certificates in real-time via WebSocket and SSE. 

[![GHCR](https://img.shields.io/badge/ghcr.io-reloading01%2Fcertstream--server--rust-blue?logo=github)](https://github.com/reloading01/certstream-server-rust/pkgs/container/certstream-server-rust)
[![Rust](https://img.shields.io/badge/rust-edition%202024-orange.svg)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Sponsor](https://img.shields.io/badge/sponsor-%E2%9D%A4-ff69b4?logo=githubsponsors)](https://github.com/sponsors/reloading01)

## What is Certstream?

Certstream aggregates certificates from Certificate Transparency (CT) logs and streams them in real-time. It provides a firehose of newly issued SSL/TLS certificates that you can filter and process for your own purposes.

This Rust implementation delivers better performance than certstream-server-go while maintaining full compatibility with existing certstream clients.

### Why Rust?

- ~118 MiB stable RSS under load (default config + 100 WS clients, 10-min plateau); plateau within ~5 minutes of startup, no growth over time
- Single shared issuer cache across all static-CT watchers (1.5.0) — no per-log cache duplication
- Pre-serialized broadcast via `Arc<PreSerializedMessage>` with zero-copy `Utf8Bytes` Text frames (1.5.0) — no per-subscriber JSON re-encoding
- Idle-server pre-serialize guard (1.5.0) — JSON serialization skipped entirely when `receiver_count() == 0`
- ~1,000 msg/s sustained CT ingest rate; tens of MB/s WS broadcast headroom
- SIMD-accelerated JSON via `simd-json` (enabled by default)
- Single binary, no runtime dependencies

## Features

- WebSocket and Server-Sent Events (SSE)
- Pre-serialized messages for efficient broadcasting
- 80+ Certificate Transparency logs monitored across both Google and Apple log lists (Google, Cloudflare, DigiCert, Sectigo, Let's Encrypt, Geomys, IPng Networks, TrustAsia, …)
- **Static-CT-API v1.0.0-rc.1 support** — checkpoint + tile protocol used by Let's Encrypt's Sycamore/Willow, Cloudflare Raio, IPng Halloumi/Gouda, Geomys Tuscolo, TrustAsia Luoshu and other 2026 logs
- **Tiled-log discovery** — `operators[].tiled_logs[]` auto-merged from Apple + Google lists, deduped by `log_id`
- Cross-log dedup with tunable capacity/TTL (defaults 1M entries / 15-minute window)
- Runtime kill switches per protocol family: `CERTSTREAM_RFC6962_ENABLED`, `CERTSTREAM_STATIC_CT_ENABLED`
- State persistence - resume from last position after restart
- Connection limiting - protect against abuse with per-IP and total limits
- Token authentication - Bearer token based API access control
- Hot reload - config changes apply without restart
- Rate limiting - token bucket + sliding window algorithm
- Circuit breaker - automatic isolation of failing CT logs with exponential backoff
- Prometheus metrics endpoint (/metrics)
- Health check endpoint (/health)
- REST API for server stats and CT log health
- Certificate lookup by SHA256, SHA1, or fingerprint

## Documentation

Visit **[certstream.dev](https://certstream.dev/)** for:
- Detailed API documentation
- Client examples and integration guides
- Self-hosting guide

## Quick Start

```bash
docker run -d -p 8080:8080 ghcr.io/reloading01/certstream-server-rust:latest

docker run -d \
  --name certstream \
  --restart unless-stopped \
  -p 8080:8080 \
  -v certstream-state:/data \
  -e CERTSTREAM_CT_LOG_STATE_FILE=/data/state.json \
  -e CERTSTREAM_CONNECTION_LIMIT_ENABLED=true \
  ghcr.io/reloading01/certstream-server-rust:latest
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `CERTSTREAM_HOST` | 0.0.0.0 | Bind address |
| `CERTSTREAM_PORT` | 8080 | HTTP/WebSocket port |
| `CERTSTREAM_LOG_LEVEL` | info | debug, info, warn, error |
| `CERTSTREAM_BUFFER_SIZE` | 1000 | Broadcast buffer |

**Protocols**

| Variable | Default | Description |
|----------|---------|-------------|
| `CERTSTREAM_WS_ENABLED` | true | Enable WebSocket |
| `CERTSTREAM_SSE_ENABLED` | true | Enable SSE |
| `CERTSTREAM_METRICS_ENABLED` | true | Enable /metrics endpoint |
| `CERTSTREAM_HEALTH_ENABLED` | true | Enable /health endpoint |
| `CERTSTREAM_EXAMPLE_JSON_ENABLED` | true | Enable /example.json endpoint |
| `CERTSTREAM_API_ENABLED` | false | Enable REST API endpoints |

**Stream Types**

| Variable | Default | Description |
|----------|---------|-------------|
| `CERTSTREAM_STREAM_FULL_ENABLED` | true | Enable full stream (DER + chain, ~4-5 KB/cert) |
| `CERTSTREAM_STREAM_LITE_ENABLED` | true | Enable lite stream (~1 KB/cert) |
| `CERTSTREAM_STREAM_DOMAINS_ONLY_ENABLED` | true | Enable domains-only stream (~200 B/cert) |

Disabling a stream type removes its WebSocket/SSE route and skips JSON serialization entirely, saving CPU and outbound bandwidth.

**Connection Limiting**

| Variable | Default | Description |
|----------|---------|-------------|
| `CERTSTREAM_CONNECTION_LIMIT_ENABLED` | false | Enable connection limits |
| `CERTSTREAM_CONNECTION_LIMIT_MAX_CONNECTIONS` | 10000 | Max total connections |
| `CERTSTREAM_CONNECTION_LIMIT_PER_IP_LIMIT` | 100 | Max per IP |

**Authentication**

| Variable | Default | Description |
|----------|---------|-------------|
| `CERTSTREAM_AUTH_ENABLED` | false | Enable token auth |
| `CERTSTREAM_AUTH_TOKENS` | - | Comma-separated tokens |
| `CERTSTREAM_AUTH_HEADER_NAME` | Authorization | Auth header |

**Rate Limiting**

| Variable | Default | Description |
|----------|---------|-------------|
| `CERTSTREAM_RATE_LIMIT_ENABLED` | false | Enable rate limiting |

Single-tier per-IP rate limit (token bucket + sliding window). Authenticated and unauthenticated clients hit the same per-source-IP ceiling — auth gates *who* may connect, rate-limit gates *how often*. YAML config:

```yaml
rate_limit:
  enabled: true
  max_tokens: 100         # bucket capacity per IP
  refill_rate: 10         # tokens/second
  burst: 20               # extra credits per burst_window
  window_seconds: 60
  window_max_requests: 1000
  burst_window_seconds: 10
```

Legacy `free_max_tokens` / `free_refill_rate` / `free_burst` keys still parse via aliases for v1.4.x config compatibility — multi-tier (`standard_*` / `premium_*`) keys were removed in 1.5.0.

**CT Log Settings**

| Variable | Default | Description |
|----------|---------|-------------|
| `CERTSTREAM_CT_LOG_STATE_FILE` | certstream_state.json | State file path |
| `CERTSTREAM_CT_LOG_RETRY_MAX_ATTEMPTS` | 3 | Max retry attempts |
| `CERTSTREAM_CT_LOG_REQUEST_TIMEOUT_SECS` | 30 | Request timeout |
| `CERTSTREAM_CT_LOG_BATCH_SIZE` | 256 | Entries per batch |

**Hot Reload**

| Variable | Default | Description |
|----------|---------|-------------|
| `CERTSTREAM_HOT_RELOAD_ENABLED` | false | Enable hot reload |
| `CERTSTREAM_HOT_RELOAD_WATCH_PATH` | - | Config file to watch |

### Build from Source

```bash
# Docker Compose
docker compose up -d
```

## API

### WebSocket

| Endpoint | Description |
|----------|-------------|
| `ws://host:8080/` | Lite stream (no DER/chain) |
| `ws://host:8080/full-stream` | Full data with DER and chain |
| `ws://host:8080/domains-only` | Just domain names (`message_type: "dns_entries"`, `data` is a bare string array) |

### SSE

| Endpoint | Description |
|----------|-------------|
| `http://host:8080/sse` | Lite (default) |
| `http://host:8080/sse?stream=full` | Full |
| `http://host:8080/sse?stream=domains` | Domains only |

### HTTP

| Endpoint | Description |
|----------|-------------|
| `/health` | Basic health check (returns "OK") |
| `/health/deep` | Detailed health with log status, connections, uptime (JSON) |
| `/metrics` | Prometheus metrics |
| `/example.json` | Example message |

### REST API

Enable with `CERTSTREAM_API_ENABLED=true`.

| Endpoint | Description |
|----------|-------------|
| `GET /api/stats` | Server statistics (uptime, connections, throughput, cache) |
| `GET /api/logs` | CT log health status (healthy, degraded, unhealthy counts) |
| `GET /api/cert/{hash}` | Lookup certificate by SHA256, SHA1, or fingerprint |

Example:
```bash
# Get server stats
curl http://localhost:8080/api/stats

# Get CT log health
curl http://localhost:8080/api/logs

# Lookup certificate by SHA256 hash
curl http://localhost:8080/api/cert/F0E2023BCAACBF9D40A4E2C767E77B46BA96AE81240EBC525FA43C0A50BFACDE

# Deep health check (returns JSON with detailed status)
curl http://localhost:8080/health/deep
# {"status":"healthy","logs_healthy":27,"logs_degraded":0,"logs_unhealthy":0,"logs_total":27,"active_connections":0,"uptime_secs":3600}
```

## Performance Comparison

Benchmarked with 100 concurrent WebSocket clients pulling the lite stream against the same Docker host, default config on both sides:

| Metric | Rust (1.5.0) | Go (0rickyy0) | Notes |
|--------|-------------:|--------------:|-------|
| Memory (steady, no clients) | **113-118 MiB** | n/a | 10-min plateau, default config, 55 CT watchers |
| Memory (avg, 100 clients) | **117 MiB** | ~100 MiB | both broadcasting at full CT rate |
| Memory (peak, 100 clients) | **118 MiB** | **161 MiB** | Go GC pressure causes burstier RSS |
| CPU (avg, 100 clients) | **13 %** | 38 % | one core, single host |
| Memory salınımı | ±5 MiB | ±66 MiB | Rust plateau çok daha sıkı |
| Cold start to first cert | <2 s | <2 s | both pull Apple + Google log list at boot |

What we genuinely beat Go on right now:
- **~3× lower CPU** at the same load (no GC, no per-message JSON re-encoding)
- **Tight memory plateau** (±5 MiB vs Go's ±66 MiB swing)
- **Lower peak RSS** under load (118 vs 161 MiB)
- **Static-CT-API v1.0.0-rc.1 conformance** (checkpoint, tile, leaf_index extension, tree-size monotonicity) — 0rickyy0/certstream-server-go is RFC6962-only at the time of writing
- **Tunable issuer + dedup caches** shared across all watchers (1.5.0)

What's still close:
- **Average memory** is within ~15 % of Go's average. The price of holding a 1M-entry cross-log dedup window (~30-40 MiB) for the multi-log dedup quality guarantee — tunable down via `CERTSTREAM_DEDUP_CAPACITY` if you don't need it.

Elixir comparison was dropped — the upstream calidog/certstream-server image isn't published, so any number we quoted would be from an unbuildable reference. Numbers above are reproducible with the scripts in `soak/` (run `bash soak/monitor-3way.sh` against your own two containers).

## Certificate Transparency Logs

Certstream monitors 50+ CT logs from all Chrome-trusted providers:

| Provider | Logs |
|----------|------|
| Google | Argon, Xenon |
| Cloudflare | Nimbus |
| DigiCert | Wyvern, Sphinx |
| Sectigo | Elephant, Tiger, Mammoth, Sabre |
| Let's Encrypt | Willow, Sycamore (Static CT — 2025h2/2026h1) |
| TrustAsia | HETU, Luoshu |
| Geomys | Tuscolo |
| IPng Networks | Halloumi, Gouda |

## Release Notes

See [RELEASE_NOTES.md](RELEASE_NOTES.md) for version history.

## Support

I work on this in my free time. If you find it useful, just using it, starring the repo, or sharing it with someone who needs it already means a lot to me that's the kind of thing that keeps me going.

If you'd like to go a step further, you can also [sponsor me on GitHub](https://github.com/sponsors/reloading01). No pressure though, every form of support is appreciated.

## License

MIT - see [LICENSE](LICENSE)
