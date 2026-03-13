# certstream-server-rust

A high-performance **certstream server** written in Rust. Monitors Certificate Transparency logs and streams newly issued SSL/TLS certificates in real-time via WebSocket and SSE. 

[![GHCR](https://img.shields.io/badge/ghcr.io-reloading01%2Fcertstream--server--rust-blue?logo=github)](https://github.com/reloading01/certstream-server-rust/pkgs/container/certstream-server-rust)
[![Rust](https://img.shields.io/badge/rust-1.88%2B-orange.svg)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Docs](https://img.shields.io/badge/docs-certstream.dev-blue.svg)](https://certstream.dev/)

## What is Certstream?

Certstream aggregates certificates from Certificate Transparency (CT) logs and streams them in real-time. It provides a firehose of newly issued SSL/TLS certificates that you can filter and process for your own purposes.

This Rust implementation delivers better performance than certstream-server-go while maintaining full compatibility with existing certstream clients.

### Why Rust?

- 27 MB memory idle, ~150 MB stable RSS under load (flat — no growth over time)
- ~1,000 msg/s sustained CT ingest rate; zero-copy broadcast via `Arc<PreSerializedMessage>`
- 8.4 ms average latency
- 23% CPU with 500 clients
- SIMD-accelerated JSON via `simd-json` (enabled by default)
- Single binary, no dependencies

## Features

- WebSocket and Server-Sent Events (SSE)
- Pre-serialized messages for efficient broadcasting
- 60+ Certificate Transparency logs monitored (Google, Cloudflare, DigiCert, Sectigo, Let's Encrypt)
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

## Public API

A free community endpoint is available at **`api.certstream.dev`**. Check **[certstream.instatus.com](https://certstream.instatus.com)** for current status.

| Endpoint | Description |
|----------|-------------|
| `wss://api.certstream.dev/` | Lite WebSocket stream |
| `wss://api.certstream.dev/full-stream` | Full stream (with DER and chain) |
| `wss://api.certstream.dev/domains-only` | Domains only |
| `https://api.certstream.dev/sse` | SSE stream |
| `https://api.certstream.dev/api/stats` | Server statistics |
| `https://api.certstream.dev/health` | Health check |
| `https://certstream.instatus.com` | Status page (uptime, incidents) |

```bash
# Quick test
websocat wss://api.certstream.dev/
curl -N https://api.certstream.dev/sse
```

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

Rate limiting uses a hybrid token bucket + sliding window algorithm with tier-based limits (Free, Standard, Premium).

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

Benchmarked with 500 concurrent WebSocket clients, 60 seconds, identical conditions (2 CPU cores, 2GB RAM per container):

| Metric | Rust | Go | Elixir |
|--------|------|-----|--------|
| Memory (idle) | 27 MB | 49 MB | 230 MB |
| Memory (under load, stable) | ~150 MB | 309 MB | 649 MB |
| CPU (idle) | 5% | 36% | 172% |
| CPU (under load) | 23% | 72% | 206% |
| Throughput | 48.6K msg/s | 27K msg/s | 19K msg/s |
| Avg Latency | 8.4 ms | 9.2 ms | 26.8 ms |
| P99 Latency | 172 ms | 187 ms | 297 ms |
| Connect Time | 162 ms | 156 ms | 784 ms |

**Rust vs Elixir**: ~4x less memory under load (flat ~150MB RSS), 2.5x higher throughput, 3.2x lower latency
**Rust vs Go**: ~2x less memory under load, 3x lower CPU, 1.8x higher throughput

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

## License

MIT - see [LICENSE](LICENSE)
