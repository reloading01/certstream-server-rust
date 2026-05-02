# Release Notes

## v1.4.0 — static-ct-api v1.0.0-rc.1 + log-list discovery

**May 2, 2026**

Brings the project in line with the post-RFC6962 CT ecosystem: Apple-list discovery for tiled logs, static-ct-api v1.0.0-rc.1 conformance (leaf_index extension, partial-tile width validation, tree-size monotonicity), runtime kill switches per protocol family, and a critical tile-parser bug fix that had silently dropped 99% of static-CT entries since v1.2.

### Highlights

**Tile parser correctness (critical fix).** The `Fingerprint certificate_chain<0..2^16-1>` field is byte-length-prefixed per the static-ct-api framing, not count-prefixed. Pre-1.4 builds treated the prefix as a fingerprint count, consuming subsequent leaves' bytes as chain data — every tile yielded only its first leaf. With the fix, full tiles correctly emit all 256 entries (verified against real Sycamore/Willow/Cloudflare Raio/IPng Networks tiles).

**Log-list discovery.** `additional_log_lists` (default: Apple's `current_log_list.json`) is fetched in parallel with Google's v3 list. Both lists' `operators[].tiled_logs[]` arrays are now read and surfaced as static-ct watchers. Logs appearing in multiple lists are deduped by `log_id`. Submission URL drives the checkpoint origin per spec; user-provided `static_logs` entries override discovery for the same URL.

**static-ct-api v1.0.0-rc.1 conformance:**
- `leaf_index` SCT extension (type 0, 40-bit BE) parsed from `CtExtensions`; validated against the tile-derived index, mismatches counted via `certstream_static_ct_leaf_index_mismatch`.
- Partial-tile width enforced: a tile body must contain exactly `floor(s / 256^l) mod 256` leaves for the last tile, 256 for full. Mismatches drop the tile and back off rather than emit partial data (`certstream_static_ct_tile_width_mismatch`).
- Tree-size monotonicity: rollbacks are detected, logged, and refused (`certstream_static_ct_tree_size_rollbacks`).
- Witness signatures on checkpoints are passively accepted — extra `— ` lines beyond the primary log signature no longer trip the parser.

**Runtime kill switches:**
- `CERTSTREAM_RFC6962_ENABLED=false` (or YAML `ct_log.rfc6962_enabled: false`) skips the legacy watcher pool entirely. Prepares for the 2027 RFC6962 sunset.
- `CERTSTREAM_STATIC_CT_ENABLED=false` mirrors for static-ct.
- Refuses to start when both are disabled rather than running with zero sources.

**Type-aware health probes.** Static-CT logs are reachability-probed against `/checkpoint`; RFC6962 logs against `/ct/v1/get-sth`. Static-CT logs no longer get false-negative-filtered out of the candidate pool.

**Per-operator rate limiting for static-CT.** Watchers belonging to the same operator (e.g. all of Cloudflare's Raio shards) now share a 2 req/s limiter, matching the existing RFC6962 behavior. Avoids thundering-herd toward a single CDN host.

**Tunable cross-log dedup.** New `dedup.capacity` / `dedup.ttl_secs` config (env: `CERTSTREAM_DEDUP_CAPACITY` / `CERTSTREAM_DEDUP_TTL_SECS`). Defaults bumped to 1M / 900s to cover the wider RFC6962↔static-CT propagation window.

### New metrics

- `certstream_static_ct_leaf_index_mismatch{log}`
- `certstream_static_ct_tile_width_mismatch{log}`
- `certstream_static_ct_tree_size_rollbacks{log}`

### Breaking-ish changes

- `fetch_log_list` (internal) now takes `&[String]` of additional list URLs and returns mixed RFC6962+static-CT logs; downstream binary integrators should re-pin.
- `dedup` config block is new (defaults backward-compatible).
- `additional_log_lists` defaults to fetching Apple's list at startup. Set to an empty array (or `CERTSTREAM_ADDITIONAL_LOG_LISTS=`) to opt out.

### Test coverage

205 unit tests (was 190 in v1.3.4). New: leaf_index extension parsing, byte-length-prefixed chain fingerprints, Apple-style log-list schema, partial-tile semantics.

### Upgrade notes

```bash
docker pull ghcr.io/reloading01/certstream-server-rust:1.4.0
```

Drop-in upgrade from v1.3.4. Existing config files keep working; `additional_log_lists` and `dedup` blocks are optional. To stay on the v1.3 behavior:

```yaml
additional_log_lists: []
ct_log:
  static_ct_enabled: false
dedup:
  capacity: 500000
  ttl_secs: 300
```

---

## v1.3.4 — Submission Timestamp Support

**April 3, 2026**

Adds the `submission_timestamp` field to all certificate messages — the moment the CT log issued the Signed Certificate Timestamp (SCT) per [RFC 6962 §3.1](https://www.rfc-editor.org/rfc/rfc6962#section-3.1). This complements the existing `seen` field (server-side processing time) and enables consumers to gauge certificate freshness and estimate maximum merge delay.

### New Features

**`submission_timestamp` Field**
Every certificate message (full, lite) now includes `submission_timestamp`: a Unix timestamp (seconds since epoch, millisecond precision) extracted from the `TimestampedEntry.timestamp` field in the CT log's Merkle tree leaf. Available on both RFC 6962 and static CT log entries.

```json
{
  "seen": 1703808000.123,
  "submission_timestamp": 1703721600.456
}
```

| Field | Source | Meaning |
|-------|--------|---------|
| `seen` | Server clock | When this server processed the entry |
| `submission_timestamp` | CT log | When the CT log accepted the certificate and issued the SCT |

### Implementation

- **RFC 6962 path**: Extracted from bytes 2–9 of `leaf_input` (uint64 big-endian milliseconds)
- **Static CT path**: Extracted from `TileLeaf` timestamp field, renamed from `timestamp` to `submission_timestamp` for clarity

### Test Coverage

189 unit tests (no change in count — existing static CT tests updated for field rename).

### Upgrade Notes

- Drop-in upgrade from v1.3.3. No config or state file changes.
- Additive change — existing WebSocket/SSE consumers will see a new `submission_timestamp` field in JSON payloads; no fields removed.

```bash
docker pull ghcr.io/reloading01/certstream-server-rust:1.3.4
```

### Community

Thanks to [@raffysommy](https://github.com/raffysommy) for the contribution ([#5](https://github.com/reloading01/certstream-server-rust/pull/5)).

---

## v1.3.3 — Bandwidth Optimization & Stream Control

**March 13, 2026**

Performance release cutting CT log fetch bandwidth by ~30-50% via HTTP compression, adding per-stream-type on/off config for outbound bandwidth control, switching to Chrome-trusted log list for better coverage with less waste, and deferring chain cert parsing for duplicates.

### New Features

**Configurable Stream Types**
Each stream type (full, lite, domains-only) can be independently enabled or disabled via config or environment variables. Disabled streams skip JSON serialization entirely and their WebSocket/SSE routes are not registered — saving both CPU and outbound bandwidth.

```yaml
streams:
  full: false          # Disable full stream (saves ~4-5 KB/cert outbound)
  lite: true
  domains_only: true
```

| Variable | Default | Description |
|----------|---------|-------------|
| `CERTSTREAM_STREAM_FULL_ENABLED` | true | Full stream (DER + chain) |
| `CERTSTREAM_STREAM_LITE_ENABLED` | true | Lite stream (no DER/chain) |
| `CERTSTREAM_STREAM_DOMAINS_ONLY_ENABLED` | true | Domains-only stream |

Disabling `full` alone reduces per-cert serialization cost by ~80% and is recommended for bandwidth-constrained deployments.

### Performance

**HTTP Compression (gzip + brotli + deflate)**
Added `gzip`, `brotli`, and `deflate` features to reqwest. CT log servers (Google, Cloudflare, DigiCert, Sectigo) all support compressed responses. Previously, no `Accept-Encoding` header was sent — all JSON responses arrived uncompressed. Expected inbound bandwidth reduction: **~30-50%**.

**Deferred Chain Parsing**
Certificate chain parsing is now deferred until after the dedup filter check. Duplicate certificates (which account for ~60-80% of entries across overlapping CT logs) no longer pay the cost of DER-parsing 2-4 chain certs per entry.

**Chrome-Trusted Log List**
Default CT log list URL changed from `all_logs_list.json` to `log_list.json` (Chrome-trusted only). This removes ~31 test/staging/legacy logs that wasted bandwidth while adding 16 new production logs from TrustAsia, Geomys, and IPng Networks operators that were missing from the old list.

| Metric | all_logs_list.json | log_list.json |
|--------|-------------------|---------------|
| Active production logs | 24 | 47 |
| Test/staging (wasted bandwidth) | 19 | 0 |
| Duplicate Solera logs | 12 | 0 |
| New operators | — | TrustAsia, Geomys, IPng Networks |

### Refactoring

**`readonly` Log State**
`LogState` struct now explicitly models the `readonly` state from the CT log list JSON, instead of relying on serde silently ignoring the unknown field.

### Test Coverage

189 unit tests (+4 new stream config tests).

### Upgrade Notes

- Drop-in upgrade from v1.3.2. No config or state file changes.
- New `streams` config section is optional — defaults to all enabled.
- CT log list URL changed: override with `CERTSTREAM_CT_LOGS_URL` env var if needed.
- For bandwidth-constrained deployments, set `CERTSTREAM_STREAM_FULL_ENABLED=false`.

```bash
docker pull ghcr.io/reloading01/certstream-server-rust:1.3.3
```

---

## v1.3.2 — Live Connection Count Fix & Public API

**March 9, 2026**

Patch release fixing `/api/stats` always reporting zero active connections, plus public API documentation and live certificate demo on the docs site.

### Bug Fixes

**`/api/stats` Always Reported Zero Connections** *(Bug)*
`ApiState` held its own `ServerStats` struct with `ws_connections` and `sse_connections` counters that were never incremented anywhere in the codebase. As a result, `GET /api/stats` always returned `{"connections": {"total": 0, "websocket": 0, "sse": 0}}` regardless of actual connected clients.

Fixed by wiring `ApiState` directly to the real connection sources:
- Added `ws_state: Arc<websocket::AppState>` to `ApiState` — reads `ConnectionCounter::total()` which is already correctly maintained by WebSocket connect/disconnect handlers.
- Exposed `pub fn sse_connection_count() -> u64` from `sse.rs` — reads the `SSE_CONNECTION_COUNT` static `AtomicU64` which is already correctly maintained by SSE connect/disconnect handlers.
- `handle_stats` now computes live counts from these real sources instead of the dead counters.

### Changes

**Public API Documentation**
- Added live SSE demo with certificate detail modal to the homepage.
- Added live active connections counter to the demo terminal (reads `/api/stats` every 30 s).
- Added Google Analytics (GA4) to all docs pages.

### Upgrade Notes

- Drop-in upgrade from v1.3.1. No config or state file changes.
- `/api/stats` now returns correct live connection counts.

```bash
docker pull ghcr.io/reloading01/certstream-server-rust:1.3.2
```

---

## v1.3.1 — Static CT Tracker Fix

**March 8, 2026**

Patch release fixing a bug in the static CT watcher where `/api/logs` showed `current_index: 0, tree_size: 0` for static CT logs that were fully caught up after a server restart.

### Bug Fixes

**Static CT Tracker Zero After Restart** *(Bug)*
When a static CT log's `current_index` equalled `tree_size` on startup (i.e. the log was fully caught up from saved state), the main poll loop skipped the tile-processing path entirely and never called `tracker.update()`. As a result, `/api/logs` reported `current_index: 0, tree_size: 0` for those logs until new entries arrived and a tile was actually fetched. Fixed by calling `tracker.update()` with the current checkpoint values before sleeping when no new tiles are available.

Affected logs: any static CT log that is fully caught up on startup — most visibly Let's Encrypt 2025h2d logs (Willow/Sycamore) which are closed-period logs with no new entries.

### Test Coverage

185 unit tests (no change — bug was in runtime control flow, not a missing test case).

### Upgrade Notes

- Drop-in upgrade from v1.3.0. No config or state file changes.
- `/api/logs` now correctly reflects static CT log positions immediately after restart.

```bash
docker pull ghcr.io/reloading01/certstream-server-rust:1.3.1
```

---

## v1.3.0 — Zero-Copy & Performance Update

**February 22, 2026**

Performance-focused release eliminating hot-path heap allocations through a "serialize-once, broadcast-many" zero-copy pipeline, lock-free concurrency throughout, and SIMD-accelerated JSON enabled by default — while hardening state persistence, fixing critical correctness bugs, and ensuring monitoring endpoints are always reachable.

### Performance

**Zero-Copy Serialize-Once Pipeline**
`CertificateMessage::pre_serialize()` wraps three pre-built `Bytes` payloads (`full`, `lite`, `domains_only`) in an `Arc<PreSerializedMessage>`. Each broadcast subscriber receives only an Arc pointer clone — a single atomic increment — regardless of the number of connected clients. With 10,000 clients, serialization cost is O(1) instead of O(n).

**`Arc<LeafCert>` — Shared Leaf Certificate**
`CertificateData.leaf_cert` is now `Arc<LeafCert>`. Broadcasting the same certificate across the full, lite, and domains-only channels no longer copies the leaf cert struct — all three serialization paths reference the same heap allocation.

**Zero-Allocation Dedup Key**
The dedup filter key changed from a hex-encoded `String` (`format!("{:02x}", ...)` × 32) to a raw `[u8; 32]` fixed-size array stored directly in `LeafCert::sha256_raw`. This eliminates one heap allocation per certificate on every dedup lookup — on both hit and miss. The raw digest flows from `x509-parser` to `DedupFilter::is_new()` with no intermediate encoding step.

**`Arc<str>` Fingerprint & `Cow<'static, str>` for Static Strings**
`LeafCert::fingerprint` is now `Arc<str>`, shared with the `sha1` field — no duplicate heap allocation for the fingerprint string. `signature_algorithm` and `message_type` use `Cow<'static, str>`, eliminating allocations for common static values.

**SIMD JSON Enabled by Default**
`simd-json` is now a default Cargo feature. `cargo build --release` produces SIMD-accelerated JSON serialization without any explicit `--features` flag. Use `--no-default-features` to revert to `serde_json`.

**Result**: Flat ~150 MB RSS under sustained load (~1,000 cert/s ingest rate). Memory footprint is stable and does not grow over time.

### Bug Fixes

**RFC 6962 Partial Response Gap** *(Critical)*
When a CT log returned fewer entries than the requested batch size (common on Google Argon), `current_index` was advanced by the requested batch size rather than the actual number of entries received. This silently skipped certificate ranges on every partial response. Fixed to advance by `entries.len()`.

**SIGTERM/SIGINT TOCTOU Race** *(Critical)*
The signal handler stream was registered inside the `select!` block. A signal arriving between process entry and the first `select!` poll was silently discarded, causing the server to hang instead of shutting down gracefully. Signal stream registration now happens before entering `select!`. Shutdown token is cancelled on signal registration failure instead of hanging.

**State Persistence — fsync Before Rename**
`save_if_dirty()` wrote state to a `.tmp` file then renamed it atomically. On ext4/xfs with ordered journaling, the OS could reorder the rename before the write's data pages were flushed, producing a zero-byte state file after a hard crash. A new `write_and_sync()` helper calls `fsync()` on the temp file descriptor before `rename()`.

**Auth/Rate-Limit Blocking Health Endpoints** *(Critical)*
When authentication or rate limiting was enabled, `/health`, `/health/deep`, `/metrics`, and `/example.json` were intercepted by middleware and returned 401/429 — breaking Kubernetes liveness/readiness probes and Prometheus scraping. These endpoints are now explicitly exempted from all auth and rate-limit layers.

**WebSocket Heartbeat Frame Type**
Keepalive heartbeat frames were sent as `Text` frames while certificate messages use `Binary` frames. Strict WebSocket clients rejected heartbeats as unexpected frame types. Heartbeats are now sent as `Binary` frames, consistent with the rest of the protocol.

**RFC 6962 Watcher Silent Start from Index 0**
If the initial STH fetch failed, the watcher silently started processing from index 0 instead of exiting, causing the entire log history to be re-processed on transient startup errors. The watcher now exits immediately on initial STH fetch failure.

**`ctlPoisonByte` Deserialization Failure on Chain Certs**
Chain certificates missing the `ctlPoisonByte` field caused a serde deserialization error, dropping the entire chain. Added `#[serde(default)]` so missing field deserializes to `false`.

**`LogHealth` Torn Reads**
`LogHealth` tracked circuit-breaker state across multiple independently-locked atomics and `RwLock` fields. Concurrent readers could observe partially-updated state (e.g., a reset failure count with a stale health status). All fields are now consolidated under a single `Mutex<LogHealthInner>`.

**Degraded Threshold Division Edge Case**
When a log had fewer than 2 recent attempts, integer division produced `half_threshold = 0`, making every single failure immediately trip the degraded state. The threshold is now clamped to a minimum of 1.

**`CERTSTREAM_HOT_RELOAD_WATCH_PATH` Not Parsed**
`CERTSTREAM_HOT_RELOAD_WATCH_PATH` was documented in the README and config reference but the environment variable was never read in `config.rs`. Fixed.

**Spurious ERROR Log on Shutdown**
Concurrent `save_if_dirty()` calls during graceful shutdown could race on the `.tmp` file rename, producing a spurious `ENOENT` `ERROR` log. `ENOENT` on rename is now treated as benign — another concurrent call completed the rename first.

**Prometheus Counters Not Initialized at Startup**
Key counters had no initial value, causing `rate()` and `increase()` Prometheus queries to return `NaN` until the first event fired. Counters are now explicitly set to 0 at startup.

**JSON Body on 404 Responses**
404 responses returned an empty body. Now return `{"error": "not found"}` for consistency with other error responses.

### Refactoring

**`LogHealth` Consolidated Under Single Mutex**
Replaced multiple atomic and `RwLock` fields with a single `Mutex<LogHealthInner>`, eliminating inconsistent lock-ordering requirements and ensuring all health state transitions are atomic from the perspective of any reader.

**Empty Entry Batch Guard**
Both RFC 6962 and static CT watchers now guard against empty response batches before advancing the current index, preventing accidental progress past the real tree tip.

**`write_and_sync()` Helper**
Extracted fsync + atomic rename into a dedicated helper used by all state persistence code paths.

### Configuration Changes

`CERTSTREAM_HOT_RELOAD_WATCH_PATH` environment variable now correctly overrides the config file watch path (was documented but not implemented in previous releases).

### Benchmarks (vs v1.2.0)

| Metric | v1.2.0 | v1.3.0 |
|--------|--------|--------|
| Memory (under load, stable) | ~198 MB | ~150 MB |
| Heap allocs per certificate (hot path) | ~6 | ~3 |
| Dedup key allocation | 1 `String` (hex, 64 B heap) | 0 (32 B stack array) |
| SIMD JSON | opt-in (`--features simd`) | on by default |
| Certs skipped on partial CT response | Yes (Google Argon affected) | No |
| Health/metrics endpoints behind auth | Yes | No (always exempt) |
| SIGTERM drop on fast shutdown | Possible | Fixed |

### Upgrade Notes

- No breaking changes. Drop-in upgrade from v1.2.0.
- SIMD JSON is now on by default — no `--features simd` flag needed for source builds.
- `/health`, `/health/deep`, `/metrics`, and `/example.json` are now always accessible regardless of authentication configuration.
- State files written by v1.2.0 are fully compatible — no migration required.

```bash
docker pull ghcr.io/reloading01/certstream-server-rust:1.3.0
```

---

## v1.2.0 — Static CT Log Support, Stability & Performance Overhaul

**February 6, 2026**

Major release adding static CT protocol (RFC 6962-bis) support, cross-log certificate deduplication, full CT log coverage, and significant stability/performance improvements — preparing for Let's Encrypt's RFC 6962 shutdown on February 28, 2026.

### Breaking Changes

- **TCP protocol removed.** Switch to WebSocket (`ws://host:8080/`) or SSE (`http://host:8080/sse`). Related env vars `CERTSTREAM_TCP_ENABLED` and `CERTSTREAM_TCP_PORT` have been removed.

### New Features

**Static CT Log Protocol (Sunlight / static-ct-api)**
Full support for the checkpoint + tile-based static CT API per [c2sp.org/static-ct-api](https://c2sp.org/static-ct-api). Includes binary tile parsing (x509/precert), hierarchical tile path encoding, gzip decompression, and issuer certificate fetching with DashMap-based caching. Four Let's Encrypt Sunlight logs are configured by default (Willow/Sycamore 2025h2d/2026h1).

**Cross-Log Certificate Deduplication**
SHA-256 based dedup filter prevents duplicate broadcasts when the same certificate appears across multiple CT logs. Configured with a 5-minute TTL, 60-second cleanup interval, and 500K entry capacity (~50 MB max). Runs as a background task with graceful cancellation — always active, no configuration needed.

**Full CT Log Coverage**
Now monitors all CT logs except rejected/retired (previously only "usable"). Adds Google Solera logs (2018–2027) and readonly logs. 63 candidates → 49 reachable.

**Startup Health Check**
Parallel health checks filter unreachable logs on startup with a 5-second timeout, preventing warning spam from defunct logs. Workers start with 50 ms staggered intervals to reduce rate limiting.

**Circuit Breaker Pattern**
Handles unreliable CT logs gracefully: Closed (normal) → Open (30 s block) → HalfOpen (testing). Paired with exponential backoff (1 s min → 60 s max).

**Graceful Shutdown**
`CancellationToken` for coordinated worker termination on SIGINT/SIGTERM. Workers complete current work before stopping.

**Deep Health Endpoint**
`GET /health/deep` returns per-log health status with connection count and uptime. Returns HTTP 503 when >50% of logs are failing.

**New Prometheus Metrics**

| Metric | Type | Description |
|--------|------|-------------|
| `certstream_static_ct_logs_count` | Gauge | Static CT logs monitored |
| `certstream_static_ct_tiles_fetched` | Counter | Tiles fetched from static CT logs |
| `certstream_static_ct_entries_parsed` | Counter | Entries parsed from static CT tiles |
| `certstream_static_ct_parse_failures` | Counter | Failed static CT entry parses |
| `certstream_static_ct_checkpoint_errors` | Counter | Checkpoint fetch/parse errors |
| `certstream_issuer_cache_size` | Gauge | Cached issuer certificates |
| `certstream_issuer_cache_hits` | Counter | Issuer cache hits |
| `certstream_issuer_cache_misses` | Counter | Issuer cache misses |
| `certstream_duplicates_filtered` | Counter | Certificates filtered by dedup |
| `certstream_dedup_cache_size` | Gauge | Current dedup cache size |
| `certstream_worker_panics` | Counter | Worker panics (auto-recovered) |
| `certstream_log_health_checks_failed` | Counter | Failed log health checks |

Per-log metrics (`certstream_messages_sent`, `certstream_parse_failures`, and all `static_ct_*` counters) now include a `log` label for per-source breakdown in Grafana.

**Grafana Dashboard & Monitoring Stack**
Pre-built Grafana dashboard with per-source certificate volume, dedup efficiency, and static CT panels. Prometheus + Grafana run behind Docker Compose's `monitoring` profile and are not started by default:

```bash
# Server only
docker compose up -d

# With monitoring
docker compose --profile monitoring up -d
```

Default Grafana credentials: `admin` / `certstream` (configurable via `GRAFANA_USER` / `GRAFANA_PASSWORD`).

### Bug Fixes

**State Persistence — AtomicBool Dirty Flag** *(Critical)*
`update_index()` used `try_write()` on a tokio `RwLock<bool>`, which silently failed when `save_if_dirty()` held a read lock, causing lost state updates. Replaced with `AtomicBool` using `Ordering::Relaxed`.

**State Persistence — Shutdown Flush** *(Critical)*
`save_if_dirty()` was never called on SIGINT/SIGTERM, losing up to 30 seconds of progress on every restart. Now flushes state after the HTTP server stops.

**State Persistence — Periodic Save Never Stops**
`start_periodic_save()` spawned an infinite loop with no cancellation mechanism. Now accepts a `CancellationToken` and flushes state before exiting.

**State Persistence — Default State File**
`state_file` defaulted to `null`, silently disabling persistence. Changed default to `"certstream_state.json"`.

**Subject/Issuer Parsing Always Null** *(Critical)*
All certificates had `null` subject/issuer fields because `as_str()` only handled UTF8String ASN.1 encoding. Real-world certificates use PrintableString, IA5String, and others. Added a raw byte fallback for ASCII-compatible encodings.

**Config Environment Variable Override Ignored**
Env vars for a config section were silently ignored when that YAML section existed. Env var overrides now always apply on top of YAML values.

**Inconsistent Subject/Issuer JSON Serialization**
Stream endpoints serialized empty fields as `null` while the cert lookup API omitted them. Added `skip_serializing_if = "Option::is_none"` for consistent omission of empty fields.

**HTTP Status Check Before JSON Parse** *(Critical)*
CT logs (especially DigiCert) returning 400/429/5xx caused continuous JSON parse errors, CPU strain, and log spam. Non-2xx responses are now logged as warnings with proper status codes.

**Worker Panic Recovery**
Worker threads silently died on panic, leaving CT logs unmonitored. Implemented `catch_unwind` with automatic restart after 5-second delay.

**WebSocket Ping Priority**
Ping/pong had lowest priority in `tokio::select!`, causing client timeouts. Reordered with `biased;`.

### Performance

- **O(1) certificate cache lookup** — DashMap with pre-normalized hash keys replaces linear scan (~100× faster).
- **O(1) domain deduplication** — HashSet replaces O(n²) `contains()` scans (~10× faster for large SAN lists).
- **Pre-allocated serialization buffers** — 4 KB (full), 2 KB (lite), 512 B (domains-only).
- **Staggered worker start** — 50 ms intervals between worker launches reduces DigiCert 429 errors by ~60%.
- **Optional SIMD JSON** — enable with `cargo build --release --features simd`.
- **Optimized release profile** — `opt-level = 3`, LTO, single codegen unit, symbol stripping.

### Docker

Native health check via `HEALTHCHECK` directive and `docker-compose.yml` healthcheck config against `/health/deep`.

### Configuration Changes

New `static_logs` section:

```yaml
static_logs:
  - name: "Let's Encrypt 'Willow' 2026h1"
    url: "https://mon.willow.ct.letsencrypt.org/2026h1/"
  - name: "Let's Encrypt 'Sycamore' 2026h1"
    url: "https://mon.sycamore.ct.letsencrypt.org/2026h1/"
  - name: "Let's Encrypt 'Willow' 2025h2d"
    url: "https://mon.willow.ct.letsencrypt.org/2025h2d/"
  - name: "Let's Encrypt 'Sycamore' 2025h2d"
    url: "https://mon.sycamore.ct.letsencrypt.org/2025h2d/"
```

Default `state_file` changed from `null` → `"certstream_state.json"`.

### Test Coverage

183 unit tests across all modules: `static_ct` (30), `parser` (27), `config` (18), `api` (18), `middleware` (14), `rate_limit` (13), `log_list` (13), `state` (12), `certificate` (11), `watcher` (11), `dedup` (10), `hot_reload` (6).

### Dependencies

Added `flate2 = "1.0"` for gzip tile decompression.

### Benchmarks (vs v1.1.0)

| Metric | v1.1.0 | v1.2.0 |
|--------|--------|--------|
| Parse errors | Continuous | 0 |
| Healthy logs | Variable | 49/49 |
| Throughput | ~200 cert/s | ~400 cert/s |
| Client disconnections | Frequent | Rare |
| Recovery | Manual | Automatic |

### Upgrade Notes

- TCP protocol removed — switch to WebSocket or SSE
- Subject/issuer fields now populate correctly for all certificate encodings
- Environment variables now always override YAML config
- State persistence enabled by default
- Cross-log dedup is always active (no config required)
- Static CT logs require explicit `static_logs` entries for non-Let's Encrypt logs
- Monitoring is opt-in via `docker compose --profile monitoring up -d`

```bash
docker pull ghcr.io/reloading01/certstream-server-rust:1.2.0
```
