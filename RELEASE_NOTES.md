# Release Notes — v1.5.3

**Release date:** July 18, 2026

v1.5.3 is a throughput and memory release, plus one new security feature: static-CT checkpoint signature verification. No wire-format changes — the JSON payloads are byte-identical to v1.5.2 (locked by snapshot tests).

## Performance

Measured on the same host, same config, 100 WebSocket clients on the lite stream, against v1.5.2 under identical conditions:

* **~70% higher sustained throughput.** v1.5.2's sequential fetching couldn't keep pace with live CT issuance on the test host; v1.5.3 does, with headroom.
* **CPU per delivered message roughly halved.** Total CPU is lower even while doing ~1.7× the work.
* **RSS now tracks live usage.** Catch-up bursts no longer park resident memory at the high-water mark — after a burst, RSS returns to its idle baseline within seconds. Long-running deployments that previously plateaued at several times their live heap should see the difference immediately.

### What changed

**Ingest pipeline.**

* get-entries / tile fetches are now pipelined `fetch_concurrency`-deep per watcher (default 4). The per-operator rate limiter became a token bucket with a burst of the same size, so the **sustained request rate toward log operators is unchanged** — concurrency only hides latency.
* RFC 6962 watchers drain the whole backlog under one STH instead of re-fetching `get-sth` per batch (the static-CT tile loop already worked this way).
* Default `batch_size` raised 256 → 1024. Servers clamp to their own maximum (spec-legal); the watcher adapts its window to whatever page size the server actually serves, so pipelined windows stay aligned.
* All CPU-heavy work — base64, X.509 parsing, hashing, tile decompression — moved off the async runtime onto the blocking pool. Catch-up storms across many watchers no longer starve polling, broadcasting, or health checks.

**Per-certificate CPU.**

* The shared issuer cache stores **parsed** `Arc<ChainCert>`s instead of raw DER. A tile whose 256 leaves chain to the same intermediate now pays one parse instead of 256. Unparseable issuers are negative-cached (fetched at most once).
* `as_der` (base64 of the full DER), chain building, and issuer prefetching are skipped entirely when the `full` stream is disabled — they have no other consumer.
* Pre-serialized payloads carry the UTF-8 invariant (`Utf8Bytes`), removing the per-client-per-message UTF-8 scan on both WebSocket and SSE fan-out.
* The dedup map hashes its SHA-256 keys with ahash instead of SipHash (the key is already uniformly distributed).
* Auth middleware reads one config snapshot per request instead of cloning the token list up to three times.

**Memory.**

* jemalloc (`tikv-jemallocator`) is the global allocator on non-MSVC targets. The ingest workload churns multi-MB transient buffers across ~100 tasks; system allocators retain those freed pages in arenas, which is exactly the "RSS parked at peak" behavior this replaces.
* The per-watcher JSON parse buffer hands burst-sized capacity back once a log is caught up instead of retaining its catch-up peak forever — previously the single biggest steady-state RSS contributor.
* Static-CT tile leaves are zero-copy `Bytes` slices of the shared tile buffer (was: one heap copy per leaf, ~256 allocations per tile).
* The REST cache shares the message's `Arc<Source>` instead of allocating two `String`s per certificate; `domains_only` serialization no longer clones the domain list.

## Static-CT checkpoint signature verification

Checkpoints are now verified against the log's ECDSA P-256 key from the signed catalog (signed-note `TreeHeadSignature`, per c2sp.org/static-ct-api):

* `ct_log.checkpoint_signature_mode: warn` (default) verifies and counts failures but never blocks ingest; `enforce` rejects checkpoints whose signature is present but fails. Checkpoints that *cannot* be verified (no usable P-256 key) are accepted in both modes — inability to verify is not proof of forgery.
* `static_logs` entries accept an optional `key` (base64 SPKI DER) for logs outside the catalog.
* Env override: `CERTSTREAM_STATIC_CT_CHECKPOINT_SIGNATURE`.

New metrics: `certstream_static_ct_checkpoint_sig_verified`, `..._sig_failed`, `..._sig_unverifiable`.

## Reliability

**Shutdown atomicity.** Batch processing and the state checkpoint now run as one detached unit: a shutdown arriving mid-batch can no longer broadcast entries without persisting the index, which previously caused those entries to be re-broadcast after a restart.

## Configuration

| Setting | Old | New |
| ------- | --: | --: |
| `ct_log.batch_size` | 256 | 1024 |
| `ct_log.fetch_concurrency` | — | 4 (new, 1-16; env `CERTSTREAM_CT_LOG_FETCH_CONCURRENCY`) |
| `ct_log.checkpoint_signature_mode` | — | `warn` (new) |

Setting `fetch_concurrency: 1` restores the v1.5.2 sequential fetch behavior.

## New dependencies

`tikv-jemallocator` (global allocator, non-MSVC), `static_ct_api` + `signed_note` + `p256` (checkpoint signature verification).

## Tests

251 unit tests (was 249) plus the integration/snapshot suites. Snapshot tests confirm the serialized JSON output is unchanged.

## Upgrade

```bash
docker pull ghcr.io/reloading01/certstream-server-rust:1.5.3
```

Drop-in upgrade from v1.5.2. Existing configs keep working; the new keys are optional.

---

# Release Notes — v1.5.2

**Release date:** June 16, 2026

v1.5.2 replaces URL-configured CT log discovery with a code-owned, signature-verified catalog registry, and adds the runtime controls to operate it safely.

## Trusted CT source discovery

CT log sources now come from a compile-time registry instead of operator-supplied URLs:

* **google_v3_usable** — verified against a pinned RSA-SHA256 trust anchor; authoritative by default.
* **google_v3_all** — same pinned key; non-authoritative until opted in via `ct_log.catalog_authority_overrides`.
* **apple** — TLS-authenticated via issuer-CA SPKI pinning (Apple publishes no detached signature); permanently non-authoritative.

Trust model: a source that does not verify can never auto-spawn watchers. An authority override can only *grant* authority to a source that currently verifies — it can never promote an unverified source such as Apple. A signature failure forces the source non-authoritative for that cycle while still exposing the raw bytes for audit (`certstream_ct_catalog_source_verified=0`).

## Operational controls

* Per-operator outbound rate limits: `ct_log.default_operator_rate_limit_ms` + `ct_log.operator_rate_limits`.
* Per-log overrides: `batch_size` and `poll_interval_ms` on `custom_logs` / `static_logs`.
* `expected_log_id` guards configured static-CT overrides against the discovered catalog identity (transport, fetch URL, and an explicitly declared checkpoint origin). The server refuses to start if a configured override contradicts the signed catalog, or if multiple resolved watchers would share a CT log ID.

## Breaking change

The `ct_logs_url` and `additional_log_lists` config keys — and the `CERTSTREAM_CT_LOGS_URL` / `CERTSTREAM_ADDITIONAL_LOG_LISTS` env vars — are removed. CT sources are now the code-owned registry. Apple-only or otherwise non-authoritative logs are ingested by declaring them under `static_logs` / `custom_logs`. Existing configs that still set the removed keys are ignored, not rejected.

## New dependencies

`rsa` (catalog signature verification), `rustls` + `rustls-native-certs` (pinned Apple TLS client); `reqwest` gains the `rustls` feature.

---

# Release Notes — v1.5.1

**Release date:** June 15, 2026

A small, focused patch release. Two operational improvements, no breaking changes, fully backward-compatible with v1.5.0 configs and Prometheus queries.

## Configurable static-CT tail overlap

Fresh static-CT watchers previously started at a fixed `tree_size - 256`. The overlap is now tunable:

* `ct_log.start_overlap_leaves` (default `256` — existing behavior preserved)
* env override `CERTSTREAM_CT_LOG_START_OVERLAP_LEAVES`
* validated with an upper bound of 100,000 leaves

## CT source observability & retry attribution

* new `certstream_ct_runtime_log_info` gauge (`source_id`, `log_id`, `log`, `operator`, `log_type`)
* existing per-log metrics gain a stable `source_id` label (`ctlog:<log_id>`, or `url:<...>` for id-less sources) alongside the existing human-readable `log` label — old selectors keep working
* new `certstream_ct_log_rate_limited_total` (labeled by `log_type`) and `certstream_ct_log_empty_responses_total` counters
* RFC6962 watchers now honor the `Retry-After` header on 429s (clamped to 250 ms–10 min), matching the static-CT path

---

# Release Notes — v1.5.0

**Release date:** May 19, 2026

v1.5.0 is focused on one thing: making the server behave like production software under real load.

This release fixes multiple race conditions, removes several failure paths, hardens the networking layer, reduces memory usage, and significantly improves long-term runtime stability.

The old multi-tier rate limiting system has been removed completely. In practice it added complexity without delivering meaningful operational value.

The Rust toolchain is now pinned to **Edition 2024**.

This is a strongly recommended upgrade for all deployments.

---

# TL;DR

### Major improvements

* Fixed multiple P0 race conditions and state consistency bugs
* Eliminated duplicate broadcast edge cases
* Reduced idle and loaded CPU usage dramatically
* Lowered default memory footprint by ~22%
* Added rollback protection for RFC6962 logs
* Improved WebSocket reliability under slow/stalled clients
* Hardened gzip parsing and chain parsing logic
* Removed startup panic paths
* Shared issuer cache across watchers
* Added proper idle-server optimization
* Simplified rate limiting model

### Breaking change

WebSocket messages now use **Text frames** instead of binary frames.

Most existing clients already support this automatically.

---

# Performance

After tuning and long-duration soak testing:

| Metric     |  Before |   After |
| ---------- | ------: | ------: |
| Idle RSS   | 223 MiB | 174 MiB |
| Loaded RSS | 253 MiB | 198 MiB |
| Loaded CPU |     49% |     25% |

12-hour soak testing results:

* 0 panics
* 0 restarts
* 0 healthcheck failures
* 38.3M duplicates filtered
* stable RSS plateau

Compared against the Go implementation (`0rickyy0/certstream-server-go`) with 100 WebSocket clients:

| Metric       | Rust v1.5.0 |      Go |
| ------------ | ----------: | ------: |
| Avg CPU      |         13% |     38% |
| Peak RSS     |     118 MiB | 161 MiB |
| Memory swing |      ±5 MiB | ±66 MiB |

The Rust implementation consistently maintained:

* lower CPU usage
* tighter memory stability
* lower peak RSS
* full static-CT support

---

# Data Integrity

## Dedup race condition fixed

`DedupFilter::is_new` previously allowed concurrent inserts for the same SHA-256 hash under load, which could broadcast duplicate certificates.

The implementation now uses `DashMap::entry`, ensuring atomic check-and-insert behavior.

A regression test with:

* 32 threads
* 1000 calls each

now guarantees exactly one successful insertion.

---

## Dedup cache wipe removed

Previously, reaching the 1M-entry dedup capacity triggered a full cache clear.

That caused immediate duplicate storms.

The cache now performs targeted expiration instead of catastrophic wipes.

---

## State persistence race fixed

`save_if_dirty` previously cleared the dirty flag after disk writes, creating a TOCTOU window where updates could be lost.

The dirty flag is now cleared before snapshot generation using atomic swap semantics.

Failed saves automatically re-arm persistence.

---

## RFC6962 rollback protection added

Rollback protection now exists for both:

* static-CT
* RFC6962 watchers

Logs returning smaller `tree_size` values than previously observed are now rejected safely.

Additional bounds protection was added around `tree_size - 1`.

---

## Certificate cache eviction race fixed

TTL eviction could previously invalidate the API index for newer copies of the same certificate, causing false `404` responses.

Eviction now validates pointer identity before removing index entries.

---

# Reliability & Stability

## Startup panics removed

Critical startup paths no longer rely on `.expect()`.

Graceful shutdown handling now covers:

* invalid TLS files
* occupied ports
* malformed YAML configs

All failures are logged properly through the cancellation token system.

---

## Config validation now runs on normal startup

Invalid configs such as:

```yaml
buffer_size: 0
```

previously reached runtime and panicked immediately.

Validation now runs during all startup paths.

---

## Slow WebSocket client protection

Outbound WebSocket writes now enforce:

```rust
WRITE_TIMEOUT = 10s
```

Stalled clients are disconnected automatically instead of permanently blocking connection tasks.

New metric:

```text
certstream_ws_disconnect_write_timeout
```

---

## Per-client lag disconnects

Clients that fall behind for 5 consecutive lag events are now disconnected automatically.

Threshold:

```rust
lag_policy::MAX_CONSECUTIVE_LAGS
```

---

## Idle-server CPU optimization

JSON serialization is now skipped entirely when no subscribers are connected.

This significantly reduces idle CPU usage on ingest-only deployments.

---

# Memory & Resource Usage

## Shared issuer cache

Issuer caches are now shared globally across watchers instead of allocating separate caches per CT log.

Benefits:

* lower RAM usage
* improved issuer reuse
* faster issuer prewarm behavior

---

## Issuer prewarm concurrency capped

Large tiles previously triggered unbounded issuer fetch fan-out.

Prewarm now uses bounded concurrency:

```rust
MAX_INFLIGHT_ISSUER_FETCHES = 16
```

and skips already-cached fingerprints.

---

## Gzip bomb protection

Tile decompression is now capped at:

```rust
MAX_DECOMPRESSED_TILE_BYTES = 16 MiB
```

Oversized payloads are rejected safely.

Metric added:

```text
certstream_static_ct_decompress_oversize
```

---

# Protocol Changes

## WebSocket frames now use Text

Certificate updates and heartbeat messages now use:

```rust
Message::Text
```

instead of binary frames.

Most clients already support this automatically, including:

* browser WebSocket APIs
* certstream-python
* standard websocket libraries

---

## Zero-copy WebSocket text path

The initial Text-frame migration introduced unnecessary per-message string allocations.

The implementation now uses:

```rust
Utf8Bytes::try_from(bytes)
```

allowing shared-buffer reuse without additional allocations.

---

# Security & Hardening

## Hot reload authentication bypass fixed

Before v1.5.0, partial hot reload configs could unintentionally disable authentication because omitted sections were replaced with defaults.

Authentication state is now preserved correctly during reloads.

Regression tests added for:

* empty YAML reloads
* partial config overrides

---

## CORS scoping tightened

Permissive CORS headers now apply only to public endpoints:

* WebSocket
* SSE
* `/api/cert/{hash}`

Operator-only routes such as:

* `/metrics`
* `/health`
* `/example.json`

no longer expose permissive CORS behavior.

---

## RFC6962 parser bounds enforced

Certificate chain parsing now strictly respects declared chain lengths.

Trailing bytes beyond the declared length are rejected.

---

## Constant-time auth preserved

Authentication token comparison still uses:

```rust
subtle::ct_eq
```

to avoid timing attacks.

---

# Runtime Tuning

Default settings were tightened after profiling and soak testing.

### Updated defaults

| Setting              | Old |  New |
| -------------------- | --: | ---: |
| reqwest idle pool    |  20 |    4 |
| dedup capacity       |  1M | 200K |
| API cache            | 10K |   1K |
| tokio worker threads |   8 |    4 |

These changes reduce:

* idle CPU usage
* long-term memory drift
* RSS footprint

while maintaining compatibility.

---

# Major CPU Fix

## Dedup hot-path thrash removed

`DedupFilter::is_new` previously triggered inline expiration scans whenever capacity was reached.

Under real-world ingest this caused repeated O(n) scans inside the hot path.

Observed behavior before the fix:

| Scenario          | CPU Usage |
| ----------------- | --------: |
| Idle containers   |      211% |
| Loaded containers |      268% |

Expiration now happens only inside the periodic cleanup task.

Post-fix:

| Scenario          | CPU Usage |
| ----------------- | --------: |
| Idle containers   |        5% |
| Loaded containers |       16% |

---

# Dependency Updates

Core stack updated to current stable releases:

* tokio 1.52
* reqwest 0.13
* axum-server 0.8
* simd-json 0.17
* x509-parser 0.18
* notify 8

Builder image updated to:

```dockerfile
rust:1.95-alpine
```

---

# Removed

The following features no longer exist:

* `RateLimitTier::{Free, Standard, Premium}`
* tier token tables
* standard/premium throughput configs

Rate limiting is now unified and based solely on source IP.

Authentication controls access.

Rate limiting controls throughput.

Legacy YAML keys still deserialize through compatibility aliases.

---

# Testing

Total test count:

```text
425 passing tests
```

Coverage includes:

* unit tests
* integration tests
* fuzz targets
* graceful failure tests
* soak validation

No panics were found during fuzzing.

---

# Upgrade

```bash
docker pull ghcr.io/reloading01/certstream-server-rust:1.5.0
```

## Compatibility Notes

### For v1.4.x users

* old standard/premium rate-limit fields are ignored
* move legacy tier tokens into unified `auth.tokens`
* WebSocket clients must support Text frames instead of binary-only handling

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
