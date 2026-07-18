# certstream-server-rust

A high-performance **certstream server** written in Rust. Monitors Certificate Transparency logs and streams newly issued SSL/TLS certificates in real-time via WebSocket and SSE. 

[![GHCR](https://img.shields.io/badge/ghcr.io-reloading01%2Fcertstream--server--rust-blue?logo=github)](https://github.com/reloading01/certstream-server-rust/pkgs/container/certstream-server-rust)
[![Rust](https://img.shields.io/badge/rust-edition%202024-orange.svg)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Sponsor](https://img.shields.io/badge/sponsor-%E2%9D%A4-ff69b4?logo=githubsponsors)](https://github.com/sponsors/reloading01)

## What is Certstream?

Certstream aggregates certificates from Certificate Transparency (CT) logs and streams them in real-time. It provides a firehose of newly issued SSL/TLS certificates that you can filter and process for your own purposes.

This Rust implementation is a drop-in replacement that maintains full compatibility with existing certstream clients.

### Why Rust?

- Flat resident memory that tracks live usage (jemalloc allocator) — catch-up bursts don't park RSS at the high-water mark, no growth over time
- Keeps pace with live CT issuance: pipelined catch-up fetches with an unchanged per-operator request rate
- Single shared issuer cache (pre-parsed certs) across all static-CT watchers — no per-log cache duplication, no re-parsing shared intermediates
- Pre-serialized broadcast via `Arc<PreSerializedMessage>` with zero-copy `Utf8Bytes` Text frames — no per-subscriber JSON re-encoding, no per-subscriber UTF-8 validation
- Idle-server pre-serialize guard — JSON serialization skipped entirely when `receiver_count() == 0`
- SIMD-accelerated JSON via `simd-json` (enabled by default)
- Single binary, no runtime dependencies

## Features

- WebSocket and Server-Sent Events (SSE)
- Pre-serialized messages for efficient broadcasting
- Every Chrome- and Apple-trusted Certificate Transparency log monitored across both Google and Apple log lists (Google, Cloudflare, DigiCert, Sectigo, Let's Encrypt, Geomys, IPng Networks, TrustAsia, …)
- **Static-CT-API support** — checkpoint + tile protocol used by Let's Encrypt's Sycamore/Willow, Cloudflare Raio, IPng Halloumi/Gouda, Geomys Tuscolo, TrustAsia Luoshu and other tiled logs
- **Tiled-log discovery** — `operators[].tiled_logs[]` auto-merged from Apple + Google lists, deduped by `log_id`
- Cross-log dedup with tunable capacity/TTL (defaults 200K entries / 15-minute window)
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

**CT Log Settings**

| Variable | Default | Description |
|----------|---------|-------------|
| `CERTSTREAM_CT_LOG_STATE_FILE` | certstream_state.json | State file path |
| `CERTSTREAM_CT_LOG_RETRY_MAX_ATTEMPTS` | 3 | Max retry attempts |
| `CERTSTREAM_CT_LOG_REQUEST_TIMEOUT_SECS` | 30 | Request timeout |
| `CERTSTREAM_CT_LOG_BATCH_SIZE` | 1024 | Entries requested per get-entries call (servers clamp to their own max) |
| `CERTSTREAM_CT_LOG_FETCH_CONCURRENCY` | 4 | Concurrent range/tile fetches per watcher during catch-up (1-16) |

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

## Performance

Benchmarked against v1.5.2 on the same host — default config, 100 concurrent WebSocket clients pulling the lite stream, 10-minute plateau window:

| Metric (vs v1.5.2, identical conditions) | Change |
|------------------------------------------|-------:|
| Sustained delivered throughput | ~+70% |
| CPU per delivered message | ~−50% |
| RSS after catch-up bursts | returns to idle baseline (previously parked at peak) |
| Cold start to first cert | seconds |

Every certificate is serialized once and broadcast to all subscribers via an `Arc<PreSerializedMessage>` with zero-copy text frames; when no clients are connected, serialization is skipped entirely. Catch-up fetches are pipelined per watcher while the per-operator request rate stays within the same politeness budget as sequential fetching. Memory stays flat over time — jemalloc returns burst allocations to the OS instead of parking RSS at the high-water mark. The default 200K-entry cross-log dedup window costs only a few MiB and is tunable via `CERTSTREAM_DEDUP_CAPACITY`.

## Certificate Transparency Logs

Certstream monitors every Chrome- and Apple-trusted CT log. A sample of operators:

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
