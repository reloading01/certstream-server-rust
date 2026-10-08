# certstream-server-rust

A Certstream server written in Rust. It monitors Certificate Transparency (CT) logs and streams newly issued SSL/TLS certificates over WebSocket and Server-Sent Events (SSE).

[![GHCR](https://img.shields.io/badge/ghcr.io-reloading01%2Fcertstream--server--rust-blue?logo=github)](https://github.com/reloading01/certstream-server-rust/pkgs/container/certstream-server-rust)
[![Docker Hub](https://img.shields.io/badge/docker%20hub-reloading01%2Fcertstream--server--rust-blue?logo=docker)](https://hub.docker.com/r/reloading01/certstream-server-rust)
[![Rust](https://img.shields.io/badge/rust-edition%202024-orange.svg)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Sponsor](https://img.shields.io/badge/sponsor-%E2%9D%A4-ff69b4?logo=githubsponsors)](https://github.com/sponsors/reloading01)

## Overview

Certstream aggregates certificates from Certificate Transparency logs and streams them in real time. This implementation is compatible with existing Certstream clients and supports both RFC 6962 and static-CT logs.

Key features:

- WebSocket and SSE streaming
- Full, lite, and domains-only streams
- Chrome- and Apple-trusted CT log discovery
- Static-CT checkpoint and tile support
- Cross-log certificate deduplication
- Persistent CT log positions across restarts
- Per-IP connection and request limiting
- Bearer-token authentication
- Hot-reloadable configuration
- Circuit breakers and retry handling for CT logs
- Prometheus metrics and health endpoints
- Optional REST API with certificate lookup
- Pre-serialized broadcast payloads and SIMD JSON
- Single binary with no runtime dependencies

## Documentation

Full API documentation, client examples, integration guides, and self-hosting notes are available at [certstream.dev](https://certstream.dev/).

## Installation

Prebuilt Linux binaries use static musl builds and do not depend on the host glibc version. Release archives include SHA-256 checksums.

### Install script

Linux and macOS, x86_64 and arm64:

```bash
curl -fsSL https://raw.githubusercontent.com/reloading01/certstream-server-rust/main/install.sh | sh
```

The installer verifies the published checksum and refuses to install if one is unavailable.

Use a custom prefix to avoid installing under `/usr/local`:

```bash
curl -fsSL https://raw.githubusercontent.com/reloading01/certstream-server-rust/main/install.sh | PREFIX="$HOME/.local" sh
```

Pin a release with `VERSION`, for example `VERSION=v1.6.0`.

### Homebrew

```bash
brew install reloading01/tap/certstream-server-rust
```

### Debian / Ubuntu

```bash
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://reloading01.github.io/packages/key.gpg | sudo tee /etc/apt/keyrings/certstream.asc > /dev/null

echo "deb [signed-by=/etc/apt/keyrings/certstream.asc] https://reloading01.github.io/packages/apt stable main" \
  | sudo tee /etc/apt/sources.list.d/certstream.list

sudo apt update
sudo apt install certstream-server-rust
sudo systemctl enable --now certstream-server-rust
```

### Fedora / RHEL / openSUSE

```bash
sudo rpm --import https://reloading01.github.io/packages/key.gpg

sudo tee /etc/yum.repos.d/certstream.repo > /dev/null <<'REPO'
[certstream]
name=certstream-server-rust
baseurl=https://reloading01.github.io/packages/rpm
enabled=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=https://reloading01.github.io/packages/key.gpg
REPO

sudo dnf install certstream-server-rust
sudo systemctl enable --now certstream-server-rust
```

Both package repositories are signed. `.deb` and `.rpm` files are also attached to each [GitHub release](https://github.com/reloading01/certstream-server-rust/releases/latest).

The packaged systemd unit runs under `DynamicUser`, stores CT log positions in `/var/lib/certstream`, and reads settings from `/etc/default/certstream-server-rust`.

### Cargo

```bash
cargo install certstream-server-rust
```

### Docker

Minimal:

```bash
docker run -d -p 8080:8080 ghcr.io/reloading01/certstream-server-rust:latest
```

The same image is on Docker Hub as `reloading01/certstream-server-rust`.

With persistent state and connection limits:

```bash
docker run -d \
  --name certstream \
  --restart unless-stopped \
  -p 8080:8080 \
  -v certstream-state:/data \
  -e CERTSTREAM_CT_LOG_STATE_FILE=/data/state.json \
  -e CERTSTREAM_CONNECTION_LIMIT_ENABLED=true \
  ghcr.io/reloading01/certstream-server-rust:latest
```

No configuration is required for a basic deployment. The server discovers CT logs automatically, serves WebSocket on port `8080`, and persists its position so restarts resume instead of replaying log history.

### Docker Compose

```bash
docker compose up -d
```

## Configuration

All settings are optional. Environment variables override YAML values, and YAML values override built-in defaults.

### General

| Variable | Default | Description |
| --- | --- | --- |
| `CERTSTREAM_HOST` | `0.0.0.0` | Bind address |
| `CERTSTREAM_PORT` | `8080` | HTTP/WebSocket port |
| `CERTSTREAM_LOG_LEVEL` | `info` | `debug`, `info`, `warn`, or `error` |
| `CERTSTREAM_BUFFER_SIZE` | `1000` | Broadcast buffer size |

### Protocols

| Variable | Default | Description |
| --- | --- | --- |
| `CERTSTREAM_WS_ENABLED` | `true` | Enable WebSocket |
| `CERTSTREAM_SSE_ENABLED` | `false` | Enable SSE |
| `CERTSTREAM_METRICS_ENABLED` | `true` | Enable `/metrics` |
| `CERTSTREAM_HEALTH_ENABLED` | `true` | Enable `/health` |
| `CERTSTREAM_EXAMPLE_JSON_ENABLED` | `true` | Enable `/example.json` |
| `CERTSTREAM_API_ENABLED` | `false` | Enable REST API endpoints |

### Stream types

| Variable | Default | Description |
| --- | --- | --- |
| `CERTSTREAM_STREAM_FULL_ENABLED` | `true` | Full stream with DER and chain, ~4-5 KB/cert |
| `CERTSTREAM_STREAM_LITE_ENABLED` | `true` | Lite stream, ~1 KB/cert |
| `CERTSTREAM_STREAM_DOMAINS_ONLY_ENABLED` | `true` | Domains-only stream, ~200 B/cert |

Disabling a stream removes its WebSocket/SSE route and skips serialization for that format.

### Connection limiting

| Variable | Default | Description |
| --- | --- | --- |
| `CERTSTREAM_CONNECTION_LIMIT_ENABLED` | `false` | Enable connection limits |
| `CERTSTREAM_CONNECTION_LIMIT_MAX_CONNECTIONS` | `10000` | Maximum total connections |
| `CERTSTREAM_CONNECTION_LIMIT_PER_IP_LIMIT` | `100` | Maximum connections per IP |

### Authentication

| Variable | Default | Description |
| --- | --- | --- |
| `CERTSTREAM_AUTH_ENABLED` | `false` | Enable token authentication |
| `CERTSTREAM_AUTH_TOKENS` | none | Comma-separated tokens |
| `CERTSTREAM_AUTH_HEADER_NAME` | `Authorization` | Authentication header |

### Rate limiting

| Variable | Default | Description |
| --- | --- | --- |
| `CERTSTREAM_RATE_LIMIT_ENABLED` | `false` | Enable request rate limiting |

Rate limiting is per source IP. Authentication controls who may connect; rate limiting controls request frequency.

```yaml
rate_limit:
  enabled: true
  max_tokens: 100
  refill_rate: 10
  burst: 20
  window_seconds: 60
  window_max_requests: 1000
  burst_window_seconds: 10
```

### CT log settings

| Variable | Default | Description |
| --- | --- | --- |
| `CERTSTREAM_CT_LOG_STATE_FILE` | `certstream_state.json` | State file path |
| `CERTSTREAM_CT_LOG_STATE_RECOVERY` | `fresh` | Behaviour on an unreadable state file: `fresh` or `fail` |
| `CERTSTREAM_CT_LOG_REFRESH_INTERVAL_SECS` | `3600` | Log-list refresh interval while running; `0` disables it |
| `CERTSTREAM_CT_LOG_REMOVED_POLICY` | `stop` | What a refresh does with a delisted log: `stop` or `keep` |
| `CERTSTREAM_STATIC_CT_MERKLE_VERIFICATION` | `off` | Merkle verification depth: `off`, `consistency`, `full` |
| `CERTSTREAM_STATIC_CT_NAMES_TILES` | `off` | Read names tiles where served: `off` or `prefer` |
| `CERTSTREAM_NATS_ENABLED` | `false` | Durable output to NATS JetStream |
| `CERTSTREAM_CT_LOG_RETRY_MAX_ATTEMPTS` | `3` | Maximum retry attempts |
| `CERTSTREAM_CT_LOG_REQUEST_TIMEOUT_SECS` | `30` | Request timeout |
| `CERTSTREAM_CT_LOG_BATCH_SIZE` | `1024` | Requested entries per `get-entries` call; servers may clamp it |
| `CERTSTREAM_CT_LOG_FETCH_CONCURRENCY` | `4` | Concurrent range/tile fetches per watcher during catch-up, 1-16 |
| `CERTSTREAM_CT_LOG_PARTIAL_TILE_WAIT_SECS` | `60` | Seconds a caught-up static-CT watcher waits for the newest partial tile to fill before fetching it; `0` fetches at once |
| `CERTSTREAM_CT_LOG_MAX_CATCHUP_LAG_ENTRIES` | `0` | A watcher more than this many entries behind its log skips ahead to near the head; `0` never skips, minimum 10000 |
| `CERTSTREAM_CT_LOG_MAX_CATCHUP_LAG_SECS` | `0` | The same bound as the age of the newest entry read, applied only to a watcher that did not reach the previous tree head; `0` never skips, minimum 300 |
| `CERTSTREAM_USER_AGENT` | `certstream-server-rust/{VERSION} (+https://github.com/reloading01/certstream-server-rust)` | User-Agent for CT log and catalog requests |
| `CERTSTREAM_CT_LOG_FORCE_HTTP1_OPERATORS` | none | Comma-separated operators that should use HTTP/1.1 |
| `CERTSTREAM_CT_LOG_OPERATOR_RATE_LIMITS` | none | Comma-separated `operator=milliseconds` floors on the request interval, for example `trustasia=10,digicert=40`; replaces `ct_log.operator_rate_limits` |

RFC 6962 and static-CT watchers can also be disabled independently with `CERTSTREAM_RFC6962_ENABLED` and `CERTSTREAM_STATIC_CT_ENABLED`.

A blank `CERTSTREAM_USER_AGENT` falls back to the default. Some operators may apply different rate limits to clients that include contact information in the User-Agent.

### Hot reload

| Variable | Default | Description |
| --- | --- | --- |
| `CERTSTREAM_HOT_RELOAD_ENABLED` | `false` | Enable hot reload |
| `CERTSTREAM_HOT_RELOAD_WATCH_PATH` | none | Configuration file to watch |

## Advanced CT log configuration

### Hybrid tile fetching without checkpoints

Some RFC 6962 logs expose static-CT tile data but do not publish `/checkpoint`. For those logs, `tree_size_source: get_sth` can use `/ct/v1/get-sth` for the tree size while fetching entries from `/tile/data`.

```yaml
static_logs:
  - name: "TrustAsia log2026a"
    url: "https://ct2026-a.trustasia.com/log2026a"
    expected_log_id: "dNudWPfUfp39eHoWKpkcGM9pjafHKZGMmhiwRQ26RLw="
    tree_size_source: get_sth
```

The override replaces the catalog-discovered RFC 6962 watcher for the same `log_id`, so the log is fetched only once.

There are two operational trade-offs:

- Without a checkpoint, the server cannot verify the log on its side and logs a warning at startup.
- The watcher stops at the last full tile. The newest 0-255 entries wait until the tile is complete when partial tiles are unavailable.

Busy tiled logs may also need more fetch concurrency. In the measured TrustAsia case, increasing `fetch_concurrency` from `4` to `16` raised aggregate throughput from roughly 50 entries/s to roughly 276 entries/s.

```yaml
ct_log:
  fetch_concurrency: 16
```

An override for a catalog-discovered log inherits its operator name. For a local log that is not present in a catalog, set `operator` explicitly if it should use a specific operator rate-limit bucket.

### Forcing HTTP/1.1 for an operator

Some CT operators apply limits per TCP connection. With HTTP/2, several watchers on the same host can share one connection and therefore one connection-level quota.

Operators listed under `force_http1_operators` use a dedicated HTTP/1.1 client:

```yaml
ct_log:
  force_http1_operators:
    - DigiCert
```

This does not increase the configured outbound request rate. The per-operator token bucket still gates requests; HTTP/1.1 only spreads them across separate connections. Operator matching is case-insensitive and ignores punctuation. Unmatched names are reported at startup.

## API

### WebSocket

| Endpoint | Stream |
| --- | --- |
| `ws://host:8080/` | Lite |
| `ws://host:8080/full-stream` | Full data with DER and chain |
| `ws://host:8080/domains-only` | Domain names only |
| `ws://host:8080/v2` | Version 2 output; off by default |

The domains-only stream uses `message_type: "dns_entries"` and returns `data` as a string array.

All streaming endpoints accept `domain` and `issuer` query parameters for server-side filtering. Version 2 adds an explicit source address and a record of what was verified. `--backfill` replays a fixed index range to JSONL. See the [documentation](https://certstream.dev/docs.html) for all of it.

### SSE

SSE is disabled by default. Enable it with `CERTSTREAM_SSE_ENABLED=true`.

| Endpoint | Stream |
| --- | --- |
| `http://host:8080/sse` | Lite |
| `http://host:8080/sse?stream=full` | Full |
| `http://host:8080/sse?stream=domains` | Domains only |
| `http://host:8080/sse?stream=v2` | Version 2 output; off by default |

### HTTP endpoints

| Endpoint | Description |
| --- | --- |
| `/health` | Basic health check; returns `OK` |
| `/health/deep` | Detailed log health, connection count, and uptime |
| `/metrics` | Prometheus metrics |
| `/example.json` | Example certificate message |

### REST API

The REST API is disabled by default. Enable it with `CERTSTREAM_API_ENABLED=true`.

| Endpoint | Description |
| --- | --- |
| `GET /api/stats` | Uptime, connections, throughput, and cache statistics |
| `GET /api/logs` | CT log health and position information |
| `GET /api/cert/{hash}` | Lookup by SHA-256, SHA-1, or fingerprint |

Examples:

```bash
curl http://localhost:8080/api/stats
curl http://localhost:8080/api/logs
curl http://localhost:8080/api/cert/F0E2023BCAACBF9D40A4E2C767E77B46BA96AE81240EBC525FA43C0A50BFACDE
curl http://localhost:8080/health/deep
```

## Memory

At the measured workload of roughly 420 certs/s across 45 trusted logs, steady-state resident memory is about 85 MB with a live heap of about 50 MB.

The binary ships with jemalloc defaults tuned for this workload:

```text
thp:never,narenas:4,background_thread:true,dirty_decay_ms:5000,muzzy_decay_ms:5000
```

`thp:never` avoids resident-memory inflation on hosts with transparent huge pages set to `always`. Check the host setting with:

```bash
cat /sys/kernel/mm/transparent_hugepage/enabled
```

jemalloc settings can be overridden without rebuilding:

```bash
docker run \
  -e _RJEM_MALLOC_CONF=dirty_decay_ms:30000,muzzy_decay_ms:30000 \
  ghcr.io/reloading01/certstream-server-rust:latest
```

Useful allocator metrics include:

- `certstream_jemalloc_allocated_bytes`: live heap
- `certstream_jemalloc_resident_bytes`: allocator estimate of resident pages

A widening gap between the two points to allocator behavior; growth in `allocated` means the application itself is retaining more live data.

Dedup memory scales with ingest rate and TTL, bounded by `dedup.capacity`. At 420 certs/s, a 15-minute window would require roughly 354K entries, so the default 200K capacity shortens the effective window. `certstream_dedup_effective_ttl_seconds` reports the active window.

## Performance

Measured against v1.5.2 on the same host with the default configuration, 100 concurrent WebSocket clients on the lite stream, and a 10-minute plateau window:

| Metric | Result |
| --- | ---: |
| Sustained delivered throughput | ~70% higher |
| CPU per delivered message | ~50% lower |
| RSS after catch-up | Returns to the idle baseline |

Certificate payloads are serialized once and shared across subscribers. Serialization is skipped when there are no subscribers. Catch-up fetches are pipelined per watcher without increasing the configured per-operator request rate.

## Certificate Transparency logs

The server monitors Chrome- and Apple-trusted CT logs. Examples include:

| Provider | Logs |
| --- | --- |
| Google | Argon, Xenon |
| Cloudflare | Nimbus |
| DigiCert | Wyvern, Sphinx |
| Sectigo | Elephant, Tiger, Mammoth, Sabre |
| Let's Encrypt | Willow, Sycamore |
| TrustAsia | HETU, Luoshu |
| Geomys | Tuscolo |
| IPng Networks | Halloumi, Gouda |

## Release notes

See [RELEASE_NOTES.md](RELEASE_NOTES.md) for version history.

## Support

If the project is useful to you, starring the repository or sharing it with others is appreciated. You can also [sponsor the project on GitHub](https://github.com/sponsors/reloading01).

## License

MIT. See [LICENSE](LICENSE).
