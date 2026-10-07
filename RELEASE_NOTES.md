# Release Notes

## v1.6.3: Catch-up speed and bounded delay

Logs that fell hours behind in v1.6.2 were behind because of how the watcher asked for entries, not because of the operators' limits. Every number below comes from 30 to 60 second runs against the live logs from a seeded position, one log operator at a time, compared with the v1.6.2 binary.

### get-entries pages

Sectigo, DigiCert and Cloudflare never serve a get-entries page across a multiple of 256, Google and TrustAsia across a multiple of 32, so a request that starts mid-page gets only the rest of it: 256 minus the index modulo 256 entries for the first three. The window followed those short tails down to 4 to 18 entries per request and climbed back a quarter at a time until the next tail. The watcher now learns the boundary from two short responses that stop on a multiple of 32 or more and ends each request on it, so every response is a full page and the fetch pipeline is no longer rebuilt.

| Log | Produced entries/s | Read before | Read after | Average page before, after |
| --- | --- | --- | --- | --- |
| Sectigo Elephant2027h1, Tiger2027h1 | 111, 109 | 79, 181 | 4,633, 5,009 | 9 and 8, 256 |
| DigiCert Wyvern2027h1, sphinx2027h1 | 54, 51 | 30, 9 | 113, 105 | 61 and 20, 250 |
| Cloudflare Nimbus2026 | 20 | 43 | 827 | 12, 256 |
| TrustAsia HETU2027, log2026a (RFC 6962) | 80, 72 | 0, 3 | 470, 261 | 1 to 3, 32 |
| Google Argon2027h1 | 156 | 52 | 114 | 12, 32 |

Produced is the growth of each log's tree size over 53 minutes, sampled from `get-sth`; over a minute it is steppier, because logs publish a new head every so often. Read is entries per second over a 30 to 60 s run started 40,000 to 300,000 entries behind, two logs of one operator at a time. TrustAsia's get-entries answered 429 to the stream of tiny requests the old window produced, so HETU2027 read nothing; with full pages it did not, and the hybrid `tree_size_source: get_sth` configuration was not needed to keep up in a 60 s run.

### Rate limits no longer idle a watcher

Five 429 answers in a row marked a log unhealthy and opened its circuit: the watcher then slept 60 s, again before the health probe, and needed a second success to count as healthy. In the v1.6.2 container logs TrustAsia HETU2027 logged "health check passed, resuming" 45 times in 39 minutes. A 429 now only sets the backoff, the `Retry-After` value or 5 s without one, and counts in the error total. Against a local fake log that answered 429 with `Retry-After: 0` for its first 12 s, a 40 s run read 0 entries before (circuit still open) and 56,152 after.

### Polling

An RFC 6962 watcher that caught up went straight back to the log for the head: DigiCert signs a fresh tree head for every request, so every round trip found a few new entries. It now waits one poll interval after catching up. Two DigiCert logs already caught up, 40 s: 233 requests and 2 429s before, 101 requests and none after, at the same lag of 0.

A caught-up static-CT watcher no longer fetches the newest partial tile at once. `ct_log.partial_tile_wait_secs` (default 60, `0` restores the old behaviour, `CERTSTREAM_CT_LOG_PARTIAL_TILE_WAIT_SECS`) holds it back until it is full or has stayed partial that long. Idle checkpoint polling now backs off from `poll_interval_ms` to 15 s (it was 4 s), and returns to the interval when a poll finds a tile to read. The last 0 to 255 entries of a slow log are delivered up to the wait plus one idle poll later. Sixteen Geomys and Let's Encrypt logs, 60 s from a fresh start: 1,007 requests before, 597 after, tiles fetched 365 and 102. That run is shorter than the wait, so it shows the saving while the first partial tiles are held, not a steady-state rate.

### Bounded delay (opt-in)

`ct_log.max_catchup_lag_entries` and `ct_log.max_catchup_lag_secs` (`CERTSTREAM_CT_LOG_MAX_CATCHUP_LAG_ENTRIES`, `CERTSTREAM_CT_LOG_MAX_CATCHUP_LAG_SECS`) are off by default, which reads every entry however long it takes. When set, a watcher further behind than either limit at a head refresh, which happens at least every 30 s, resumes where a fresh watcher would start, logs the range and adds its size to `certstream_ct_log_skipped_entries_total`. The seconds limit is the age of the newest entry read, so it includes the age of the log's own tree head: 8 to 230 s for the RFC 6962 logs sampled, and 34 minutes for Cloudflare Nimbus2026 at one sample. Minimums are 10,000 entries and 300 s. A log that was offline for longer than the limit skips the gap on restart.

With `nats.enabled` the skipped range is settled in the acknowledged position as one range. The saved position stays below records that were read before the jump and are not stored yet, and moves over the range once they are; nothing in it is published. A restart before that re-reads the range and the same limit makes the watcher jump again.

In a run against a local fake log 3,000,000 entries behind with a limit of 100,000 entries, the watcher skipped 2,999,143 entries in its first poll. Sectigo Elephant2027h1 300,000 entries behind with the 300 s limit read 210,706 entries in 50 s, skipped 89,294 at the 30 s refresh and ended at lag 0.

### Recommended settings

- `ct_log.max_catchup_lag_secs: 900` for a hard bound of about 15 minutes plus the age of each log's tree head. The entries limit does not scale across logs that grow from 15 to 400 entries per second.
- `ct_log.force_http1_operators: [digicert]`. DigiCert answered 429 to a single HTTP/2 connection above about 2 to 3 requests per second (12 of 12 requests succeeded at 2 per second, 6 of 20 failed at 5). Two logs 120,000 entries behind, 40 s: 218 entries/s over HTTP/2, 1,310 over HTTP/1.1.
- `ct_log.fetch_concurrency: 12` for Google. Argon2027h1 serves 32 entries per request at about a second each, so 4 requests in flight read 114 entries/s against 156 produced; 12 read 256 (8 was not measured). The operator limiter still bounds the request rate, and caught-up logs keep one request in flight.
- No per-operator interval is needed for Sectigo any more: at 256 entries per request its roughly 400 entries per second need under 2 requests per second.

### Metrics

`certstream_operator_requests_total{operator}` counts the get-entries and tile requests started for each operator, so request rates can be read from `rate()` without the operator's own statistics. Tree head and checkpoint polls are not included.

### Not fixed

- A watcher reads only up to the log's latest tree head, so its delay never falls below the head's age. Sectigo, Cloudflare, TrustAsia and Google heads were 8 to 230 s old when sampled. Cloudflare Nimbus2026 had a head 34 minutes old at one sample and the tree size of Nimbus2027 did not change over 40 minutes. That is why such logs show tens of minutes of delay in `certstream_ct_log_ingest_delay_seconds` while their entries are read as they are published. The logs serve entries past the head (49 past Elephant2027h1's, 23 past log2026a's), but those are not covered by a signed tree size.
- TrustAsia static-CT and hybrid tiles that miss the cache can take about 20 s each, which caps a watcher at about 50 entries/s with the default `fetch_concurrency` (45 entries/s measured on Luoshu2027); the README reports 276 across three logs at 16.
- Each head refresh, every 30 s, tears the fetch pipeline down: at most three requests in flight are discarded, and the next fills after one round trip, which should cost a log with 1.7 s answers (DigiCert) about 6% of its throughput. This is arithmetic, not a measurement.

## v1.6.2: TLS fix, memory and catch-up speed

**Release date:** October 5, 2026

### TLS listener

With `tls.enabled` the server panicked on the first connection, because two rustls crypto providers were linked and none was installed. This affects v1.6.0 and v1.6.1. The provider is now installed at startup and a test covers the TLS path.

### Memory

Idle resident memory is 43 MB at a read rate of about 1,600 entries per second, against 70 to 80 MB for v1.6.1 under the same load (8 minute runs against the live logs, no subscribers, cgroup `anon` memory). It was 53 to 58 MB in later runs that read 2,000 or more entries per second. Two changes account for it. The duplicate filter held every key for the whole window in a map with about 160 bytes per entry; it now keeps a 128 bit fingerprint per key in time slices, under 40 bytes per entry (the window and capacity settings are unchanged). jemalloc also keeps no per-thread cache, which removed about 30 MB (78 to 46 MB in 7 minute idle runs) with no change in CPU, and returns freed pages within a second instead of five. Returning them at once saved another 9 MB but cost 0.01 core, so it is not the default.

### Catch-up speed

The share of new entries read, measured against each log's own checkpoint in 8 minute runs from a clean state, rose from 0.27 to 0.45 in v1.6.1 to 0.67 to 0.78.

- `default_operator_rate_limit_ms` is 25 ms, the fastest an operator is asked, and the interval follows the operator. Every 20 requests it is slowed by a quarter, up to one second, if a quarter or more were answered with 429, and it speeds up by a tenth each second after five seconds without a 429. Answers older than a minute are not counted, and a log that receives a `Retry-After` waits it out on its own while the other logs of the operator keep their pace. `certstream_operator_request_interval_ms` reports the value in force. The burst per operator is at most four requests instead of `fetch_concurrency`.
- A `Retry-After` given as an HTTP date was treated as unparseable, and a 429 without the header waited 30 seconds. Dates are now read, and a 429 with no hint waits 5 seconds. DigiCert answers 429 without the header, and Geomys sends a date.
- The default User-Agent is now `certstream-server-rust/{version} (+https://github.com/reloading01/certstream-server-rust)`. Geomys applies a global limit of 75 requests per second to clients that give neither an email nor a URL. Twenty-five consecutive tile requests succeeded 12 times with the old agent and 25 times with a URL in it, and Geomys went from 0.01 to 1.00 of its entries read. Set `CERTSTREAM_USER_AGENT` to use your own contact.

DigiCert, Sectigo and TrustAsia are still read at 0.4 to 0.6 of what they produce in most runs. Set `ct_log.operator_rate_limits` for a gentler pace.

### Log exclusion

`ct_log.excluded_operators` and `ct_log.excluded_logs` (`CERTSTREAM_CT_LOG_EXCLUDED_OPERATORS`, `CERTSTREAM_CT_LOG_EXCLUDED_LOGS`) drop catalog logs before any watcher starts. Entries that match nothing are logged at startup.

### Reverse proxies

`trusted_proxies` (`CERTSTREAM_TRUSTED_PROXIES`) lists the proxy addresses or networks whose `X-Forwarded-For` is believed. The client address used for connection limits and rate limits is the first address that is not a trusted proxy, counting from the right of the chain, so a forged leftmost entry is ignored.

### Certificate reload

The TLS certificate and key files are checked every 60 seconds and reloaded when they change, without dropping connections. A pair that cannot be loaded, for instance one caught half written, leaves the old certificate in use and is tried again at the next check.

### Docker Hub

Images are also published to Docker Hub, with the repository description taken from the README.

### Idle polling

A caught-up watcher asked for the checkpoint, or the RFC 6962 tree head, once per `poll_interval_ms` whether or not the log had grown. The delay now doubles for each poll that finds the head unmoved, up to four times the interval, and returns to the interval as soon as the head moves. In one operator's client statistics checkpoint requests were 92% of this project's requests, and on one install 18 of 38 static-CT logs were idle. The drop in requests was not measured.

## v1.6.1: Shutdown, catalog refresh and verification fixes

**Release date:** October 4, 2026

Fixes found by running v1.6.0 for almost four hours against the live logs with every feature enabled.

### Shutdown

SIGTERM with a WebSocket or SSE client connected left the process running until the client went away. In the test run it needed SIGKILL after 247 seconds, and Docker stops a container after 10. Open streams now end when the server is told to stop: WebSocket clients receive a going away close frame, SSE responses end. With both kinds connected the process exits in about 0.1 seconds.

### Log list refresh

The hourly refresh probes every catalog log and dropped the ones that did not answer, so a log that was slow or rate limiting looked delisted and its watcher was stopped for good. Five Microsec logs and Argon2026h2 were lost this way while the catalog still listed them. A log that fails the probe is now kept in the listed set: it blocks starting a new watcher, and it never stops a running one.

Google's `all_logs_list.json` omits `description` on test and pending logs, and one such entry made the whole list fail to parse (147 entries). Entries without a description are now named by their URL. The list is informational and was never authoritative, so watchers were not affected.

### Watchers that give up

A watcher that could not read its log's first checkpoint exited for good, and the refresh did not start it again because the key was still in the pool, so a log that was rate limiting at startup stayed dead until the process restarted. The supervisor now starts such a watcher again after 30 seconds, doubling up to 15 minutes, and starting over once it has run for ten. A refused checkpoint is reported as its HTTP status instead of as a malformed checkpoint.

GoDaddy's limit is keyed on the start of the User-Agent. In a test, `certstream-server-rust/1.6.0` was refused with a 429 whether or not text followed it, while any other name was accepted. The default is shared by every install, so set `CERTSTREAM_USER_AGENT` to a name of your own for GoDaddy's logs.

### Static-CT inclusion verification

A log may delete a partial hash tile once the full tile exists, and the verifier turned every 404 on a partial tile into `inclusion: unverified`. A 404 on a partial tile now falls back to the full tile. Over six minutes with full verification, Google tiles reported as unverifiable went from 81 to 0. A 429 or a timeout still reads as unverifiable, which is what remains for Geomys, Microsec and GoDaddy.

### Domains-only stream

Certificates that carry only IP address SANs, which Let's Encrypt now issues, have no DNS names. The domains-only stream sent them as `dns_entries` with an empty array, about 1.2% of its messages. They are no longer sent there. The lite and full streams are unchanged.

### Dependencies

`h2` 0.4.14 (RUSTSEC-2026-0258) and `rustls` 0.23.40 (RUSTSEC-2026-0285) are updated, along with `crossbeam-epoch` and two lockfile-only entries. `paste` and `rsa` remain flagged by advisory databases and have no fixed release; `rsa` is used only to verify signatures.

### Documentation

The list of monitored logs is current, and the performance page now measures how the per-operator request budget limits catch-up speed and what full verification costs.

## v1.6.0: Verification, filtering, and durable output

**Release date:** September 5, 2026

This release adds server-side stream filtering, optional Merkle verification for static-CT logs, versioned v2 output, live CT log-list refresh, JetStream output, names-tile support, historical backfill, and improved subscriber-loss and freshness reporting.

### Server-side subscription filters

WebSocket and SSE endpoints now accept `domain` and `issuer` query parameters.

Domain matching respects DNS label boundaries. For example, `example.com` matches `example.com`, `www.example.com`, and `*.example.com`, but not `notexample.com`.

Subscribers with identical filters share a subscription group. Filters are evaluated once per certificate for the group, and the serialized payload is reused across its subscribers. When there are no filtered subscribers, no filtering work is performed.

### Static-CT Merkle verification

`CERTSTREAM_STATIC_CT_MERKLE_VERIFICATION` enables Merkle verification against static-CT hash tiles.

Available modes:

* `consistency`: verifies that each new checkpoint extends the previous tree.
* `full`: additionally verifies inclusion of each ingested entry in the signed tree.

Verification is disabled by default.

Unavailable or incomplete tiles are treated as unverifiable rather than invalid. HTTP 429 responses and partial tiles that are no longer served result in `inclusion: unverified`; delivery continues. Entries are rejected only when a returned hash conflicts with the expected tree.

Verification requests use the existing per-operator rate limiter.

### Version 2 output

A versioned output format is available through:

* WebSocket: `/v2`
* SSE: `/sse?stream=v2`

The v2 stream is disabled by default and includes:

* CT log ID
* entry index
* entry type
* observation time
* verification status

`(log_id, index)` identifies the record at its source. The certificate SHA-256 fingerprint identifies the certificate itself.

Existing v1 output formats are unchanged.

### Live log-list refresh

The CT log catalog is now refreshed hourly.

New logs can be discovered without restarting the server. Existing watchers are matched by CT log ID, so their state is preserved if a catalog entry changes URL.

A failed refresh, or one that resolves no logs, leaves the current watcher set unchanged.

User-defined `custom_logs` and `static_logs` are never removed by catalog refresh.

### NATS JetStream output

`CERTSTREAM_NATS_ENABLED=true` enables publishing to NATS JetStream.

Watcher state advances according to acknowledged JetStream writes rather than completed reads. After a restart, entries that were read but not durably acknowledged are replayed.

Records use:

```text
Nats-Msg-Id: <log_id>:<index>
```

This allows JetStream to deduplicate replayed entries.

The stream uses `discard: new`, so a full stream rejects new writes instead of deleting existing unread records.

### Names tiles

`CERTSTREAM_STATIC_CT_NAMES_TILES=prefer` enables the Sunlight names-tiles extension on compatible static-CT logs.

Names tiles are significantly smaller than the corresponding data tiles and do not require X.509 parsing.

Because names-tile data is unauthenticated and cannot be verified for inclusion, entries produced from this path are published as:

```text
dns_entries_unauthenticated
```

### Historical backfill

A fixed CT log index range can now be replayed to JSONL:

```bash
certstream-server-rust --backfill --log <id> --start N --end M --out file.jsonl
```

The requested range is fixed before fetching begins. Backfill does not read or modify the live watcher state file.

### Subscriber loss reporting

SSE no longer drops lagged messages silently.

Message gaps are emitted as named `gap` events, and both WebSocket and SSE track subscriber losses.

The slow-client policy now uses a rolling window. A subscriber may miss up to 1000 messages within 60 seconds before being disconnected.

This replaces the previous consecutive-lag counter, which reset after every successful send and could allow continuously lagging clients to remain connected.

### Freshness metrics

Added:

```text
certstream_ct_log_ingest_delay_seconds
```

This reports the age of the newest entry delivered by each watcher, providing a measure of ingest freshness in addition to entry-count lag.

`soak/measure.sh` now samples this metric alongside CPU, RSS, and subscriber-loss metrics.

### Fixes

* Failed WebSocket handshakes no longer leak connection-limit slots. The slot is released if the upgrade does not complete.

* `ct_log.state_recovery: fail` now refuses startup when the state file is unreadable instead of restarting watchers from the current log head. The default `fresh` behavior is unchanged.


## v1.5.6: Distribution

**Release date:** August 25, 2026

This release changes distribution only. The server binary is identical to v1.5.5.

### Prebuilt binaries and install script

Prebuilt binaries are now available for Linux and macOS:

- Linux: `x86_64` and `aarch64`, statically linked with musl
- macOS: Intel and Apple Silicon

Install with:

```bash
curl -fsSL https://raw.githubusercontent.com/reloading01/certstream-server-rust/main/install.sh | sh
```

The script selects the correct build, verifies the published SHA-256 checksum, and aborts if a checksum is missing. Use `PREFIX=$HOME/.local` to install outside `/usr/local` without root.

Downloaded binaries do not use `target-cpu` tuning so they remain portable across supported CPUs. The container image keeps its existing build tuning.

### apt and dnf repositories

Signed package repositories are available for system-managed upgrades.

For apt:

```bash
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://reloading01.github.io/packages/key.gpg | sudo tee /etc/apt/keyrings/certstream.asc > /dev/null
echo "deb [signed-by=/etc/apt/keyrings/certstream.asc] https://reloading01.github.io/packages/apt stable main" | sudo tee /etc/apt/sources.list.d/certstream.list
sudo apt update && sudo apt install certstream-server-rust
```

The dnf instructions are on the [package repository page](https://reloading01.github.io/packages/). Both repositories are signed with:

```text
C5D7 B0D1 42A6 1EF0 FB1A BE95 462A 111C FD91 20EE
```

Packages include a systemd unit with `DynamicUser`, `StateDirectory=/var/lib/certstream`, `ProtectSystem=strict`, `NoNewPrivileges`, and a syscall filter. Configuration is read from `/etc/default/certstream-server-rust`.

A commented `MemoryMax` setting is included. Steady-state RSS is around 80 MB, but catch-up after downtime needs additional headroom.

### Homebrew and crates.io

```bash
brew install reloading01/tap/certstream-server-rust
```

```bash
cargo install certstream-server-rust
```

The Homebrew formula is updated automatically by the release workflow for each tag.

### Upgrade

No server-side migration is required. The binary is unchanged from v1.5.5.

```bash
docker pull ghcr.io/reloading01/certstream-server-rust:1.5.6
```

---

## v1.5.5: Memory, observability, and hybrid tile fetching

**Release date:** August 25, 2026

This release fixes excessive resident memory on hosts using transparent huge pages in `always` mode, adds allocator and CT lag metrics, and supports tile fetching for logs that expose `/tile/data` but no checkpoint. There are no wire-format changes. `/api/stats` gains one field.

### jemalloc defaults

v1.5.3 switched the process to jemalloc but kept its defaults. Three defaults were a poor fit for this workload: transparent huge pages, arena count, and decay behavior.

On a host with THP set to `always`, a two-hour run against all 45 Chrome- and Apple-trusted logs at about 420 certs/s measured 358 MB RSS, including 206 MB of `AnonHugePages`, while the live heap was 52 MB. Hosts using THP `madvise`, including the Debian and Ubuntu defaults, did not show the same behavior.

jemalloc also sized arenas from the host CPU count. On an 18-core host this produced 72 arenas for a runtime using four worker threads, leaving more dirty-page pools and metadata than the process needed. Bursty watcher arenas could also retain dirty pages because decay advances when an arena is touched.

The binary now embeds:

```text
thp:never,narenas:4,background_thread:true,dirty_decay_ms:5000,muzzy_decay_ms:5000
```

Measured on the same workload:

| Metric | v1.5.4 | v1.5.5 |
| --- | ---: | ---: |
| RSS, THP `always` host | 358 MB | 85 MB |
| RSS, THP `madvise` host | 88 MB | 76 MB |
| `AnonHugePages` | 206 MB | 6 MB |
| jemalloc `retained` | 116 MB | 34 MB |
| Arena metadata | 11.8 MB | 4.8 MB |
| Live heap (`allocated`) | 52 MB | 49 MB |

The live heap is effectively unchanged; the difference is allocator residency rather than application-held data.

These are defaults, not hard policy. Override them without rebuilding through `_RJEM_MALLOC_CONF`:

```bash
docker run -e _RJEM_MALLOC_CONF=narenas:8,dirty_decay_ms:20000 ghcr.io/reloading01/certstream-server-rust:1.5.5
```

`thp` and `background_thread` are Linux-only. Non-Linux builds use the arena and decay settings without those options.

### Allocator metrics

Six jemalloc gauges are now exported:

| Metric | Meaning |
| --- | --- |
| `certstream_jemalloc_allocated_bytes` | Live heap |
| `certstream_jemalloc_resident_bytes` | Physically resident allocator pages |
| `certstream_jemalloc_active_bytes` | Active pages |
| `certstream_jemalloc_mapped_bytes` | Mapped address space |
| `certstream_jemalloc_retained_bytes` | Virtual mappings retained after pages are returned |
| `certstream_jemalloc_metadata_bytes` | Allocator bookkeeping |

`allocated` versus `resident` is the useful diagnostic pair: growth in `allocated` points to live application data, while a large resident gap points to allocator behavior. The heartbeat log also reports `heap_allocated_mib` and `heap_resident_mib`.

### Hybrid tile fetching

`static_logs[].tree_size_source: get_sth` allows a static-CT watcher to read tree size from RFC 6962 `/ct/v1/get-sth` while reading entries from `/tile/data`.

This is intended for logs such as TrustAsia `log2026a`, `log2026b`, and `hetu2027`, which serve tile data but return 404 for `/checkpoint`.

```yaml
static_logs:
  - name: "TrustAsia log2026a"
    url: "https://ct2026-a.trustasia.com/log2026a"
    expected_log_id: "dNudWPfUfp39eHoWKpkcGM9pjafHKZGMmhiwRQ26RLw="
    tree_size_source: get_sth
```

A comparison near the head of `log2026a`, measured on 2026-08-25 for the same 256 entries:

| Path | Size | Time |
| --- | ---: | ---: |
| `/tile/data/x010/x076/918` | 189 KB | 5.96s cold, 0.36s warm |
| `get-entries?start=…&end=…` | 696 KB | 30.4s / 30.7s / 25.2s |

Over a two-hour run against all 45 trusted logs with `total_errors = 0` and no operator rate limiting, the RFC 6962 path left `log2026b` 278,890 entries behind, `log2026a` 79,392 behind, and `hetu2027` 37,898 behind. TrustAsia Luoshu2027, which publishes a checkpoint and is fetched over tiles, was 1,310 entries behind.

There are two trade-offs:

- Without a checkpoint, the server cannot verify these logs locally. A warning is emitted at startup. This mode favors receiving certificate data over cryptographic log monitoring.
- The watcher stops at the last full tile. Without a published checkpoint, the static-ct-api does not require partial tiles, and these TrustAsia logs do not serve them. The newest 0-255 entries wait until the tile fills.

An override with `tree_size_source: get_sth` may replace a catalog-discovered RFC 6962 watcher for the same `log_id`. Other silent protocol switches remain rejected, and the exemption does not work in reverse.

Overrides now inherit the operator name of the log they replace. `static_logs[].operator` can set the operator for logs not present in a catalog. This keeps operator rate limits grouped correctly.

Busy tiled logs may also need higher `fetch_concurrency`. Near the head, cache misses can make each tile request take several seconds; four in-flight requests capped one watcher near 50 entries/s. Across the three TrustAsia logs, 16 in flight measured about 276 entries/s, enough for two logs to catch up and remain current.

Reported and measured by Effy Elden (@ineffyble) in #14, including the related ct-policy discussion.

### Dedup capacity is now enforced

`dedup.capacity` previously did not bound the map; only TTL expiry did. At about 420 certs/s with a 900-second TTL, the steady-state map was roughly 354K entries even when capacity was set to 200K.

Cleanup now shortens the effective TTL window when the map exceeds capacity. The adjustment happens during the existing sweep instead of on the insert path. If capacity is binding, deduplication may cover a shorter history, but correctness is unchanged.

New metrics:

- `certstream_dedup_effective_ttl_seconds`
- `certstream_dedup_capacity_trims`

### `bytes_sent` now reports transmitted bytes

`throughput.bytes_sent` previously counted all three serialized formats for every certificate, whether or not anyone subscribed to them. In a two-hour run with one domains-only subscriber, it reported 26.8 GB while actual container egress was 555 MB.

It now counts bytes sent to WebSocket and SSE subscribers. The old value is available as `throughput.bytes_serialized`.

Prometheus exports both:

- `certstream_bytes_sent_total{protocol}`
- `certstream_bytes_serialized_total`

Subscriber byte counts are accumulated locally and flushed in batches to avoid an atomic write for every client on every broadcast.

### CT log lag metric

`certstream_ct_log_lag_entries{log}` reports `tree_size - current_index` per log. This catches logs that remain request-healthy while steadily falling behind.

In one two-hour run, 19 of 45 logs were healthy but more than 5K entries behind; one was 1.3M entries behind.

### Issuer cache metrics

Issuer cache hit/miss accounting now happens inside `IssuerCache::get`, so tile pre-warm hits are counted correctly. Network fetch attempts are tracked separately as:

```text
certstream_issuer_fetch_attempts
```

### SSE documentation

`protocols.sse` still defaults to `false`, matching `protocols.api`. The README, example config, and docs previously listed SSE as enabled. The documentation is corrected and a test now pins the serde field default to `ProtocolConfig::default()`.

### Configuration

| Setting | Old | New |
| --- | --- | --- |
| `static_logs[].tree_size_source` | none | `checkpoint` by default; `get_sth` enables hybrid tile fetching |
| `static_logs[].operator` | none | Inherited from the replaced log; configurable for uncatalogued logs |
| `dedup.capacity` | Advisory only | Enforced during cleanup |

### API

`/api/stats` adds `throughput.bytes_serialized`. `throughput.bytes_sent` keeps its name but now reports actual transmitted bytes.

### Tests

269 unit tests, up from 262, plus integration and snapshot suites.

### Upgrade

Drop-in upgrade. Configuration defaults are unchanged.

```bash
docker pull ghcr.io/reloading01/certstream-server-rust:1.5.5
```

---

## v1.5.4: Outbound HTTP controls

**Release date:** August 22, 2026

Adds two controls for deployments that run into CT operator rate limits. No wire-format or API changes.

### Configurable User-Agent

`ct_log.user_agent` (env `CERTSTREAM_USER_AGENT`) sets the User-Agent for CT log and catalog requests. Some operators, including Geomys, provide a more permissive tier when the client includes a contact address.

```yaml
ct_log:
  user_agent: "certstream-server-rust (security@example.com)"
```

Unset or blank values fall back to `certstream-server-rust/{VERSION}`. A blank environment value is logged, and invalid HTTP header content fails configuration validation before bind.

Contributed by Effy Elden (@ineffyble) in #12.

### Per-operator HTTP/1.1

DigiCert applies rate limits per TCP connection rather than per IP. Under HTTP/2, reqwest multiplexes requests for a host over one connection; several DigiCert logs can therefore share a single connection quota.

Operators listed in `force_http1_operators` use a dedicated HTTP/1.1 client so concurrent requests can use separate connections:

```yaml
ct_log:
  force_http1_operators:
    - DigiCert
```

Environment form:

```text
CERTSTREAM_CT_LOG_FORCE_HTTP1_OPERATORS=DigiCert,Geomys
```

This does not increase the configured request rate. The per-operator token bucket still gates every fetch using `default_operator_rate_limit_ms` (500 ms by default). `fetch_concurrency` controls how many connections can remain active.

The behavior was also observed in certspotter's `digicerthack` branch: [SSLMate/certspotter#126](https://github.com/SSLMate/certspotter/issues/126).

### Operator name matching

`operator_rate_limits` and `force_http1_operators` both use canonicalized operator names, with case, whitespace, and punctuation normalized.

Startup now warns when a configured name matches no discovered operator:

```text
WARN configured operator names match no discovered CT log operator and have no effect field="ct_log.operator_rate_limits" unmatched=["digicert inc"]
```

### Configuration

| Setting | Old | New |
| --- | --- | --- |
| `ct_log.user_agent` | none | `null` (env `CERTSTREAM_USER_AGENT`) |
| `ct_log.force_http1_operators` | none | `[]` (env `CERTSTREAM_CT_LOG_FORCE_HTTP1_OPERATORS`) |

### Tests

262 unit tests, up from 251, plus the existing integration and snapshot suites.

### Upgrade

Drop-in upgrade. Both settings default to v1.5.3 behavior.

```bash
docker pull ghcr.io/reloading01/certstream-server-rust:1.5.4
```

---

## v1.5.3: Throughput, memory, and checkpoint verification

**Release date:** July 18, 2026

This release improves ingest throughput and memory behavior and adds static-CT checkpoint signature verification. JSON payloads are byte-identical to v1.5.2, verified by snapshot tests.

### Performance

Measured against v1.5.2 on the same host and configuration with 100 WebSocket clients on the lite stream:

- Sustained throughput increased by about 70%.
- CPU per delivered message was roughly halved.
- RSS returns toward idle baseline after catch-up bursts instead of remaining at the high-water mark.

The main changes are:

- Fetches are pipelined up to `fetch_concurrency` per watcher, default 4. The per-operator limiter uses a token bucket with the same burst size; sustained request rate is unchanged.
- RFC 6962 watchers drain the backlog under one STH instead of fetching `get-sth` for every batch.
- Default `batch_size` increased from 256 to 1024. Watchers adapt to smaller server-side page limits.
- Base64, X.509 parsing, hashing, and tile decompression run on the blocking pool instead of the async runtime.
- The issuer cache stores parsed `Arc<ChainCert>` values and negative-caches unparseable issuers.
- Full DER base64, chain building, and issuer prefetch are skipped when the `full` stream is disabled.
- Pre-serialized payloads carry the UTF-8 invariant through `Utf8Bytes`, avoiding per-client UTF-8 validation.
- The dedup map uses ahash for SHA-256 keys instead of SipHash.
- Auth middleware reads one config snapshot per request instead of cloning the token list repeatedly.
- jemalloc (`tikv-jemallocator`) is the global allocator on non-MSVC targets.
- Per-watcher JSON buffers release burst-sized capacity after catch-up.
- Static-CT leaves are zero-copy `Bytes` slices of the shared tile buffer.
- The REST cache shares `Arc<Source>`, and domains-only serialization no longer clones the domain list.

### Static-CT checkpoint signature verification

Static-CT checkpoints are now verified against the log's ECDSA P-256 key from the signed catalog, using signed-note `TreeHeadSignature` semantics.

- `ct_log.checkpoint_signature_mode: warn` is the default. Failures are counted and logged but do not block ingest.
- `enforce` rejects checkpoints whose signature is present but invalid.
- Checkpoints that cannot be verified because no usable P-256 key is available are accepted in both modes.
- `static_logs` can provide an optional `key` containing base64 SPKI DER for logs outside the catalog.
- Environment override: `CERTSTREAM_STATIC_CT_CHECKPOINT_SIGNATURE`.

New metrics:

- `certstream_static_ct_checkpoint_sig_verified`
- `certstream_static_ct_checkpoint_sig_failed`
- `certstream_static_ct_checkpoint_sig_unverifiable`

### Shutdown consistency

Batch processing and state checkpointing now complete as one detached unit. A shutdown in the middle of a batch can no longer broadcast entries without persisting the corresponding index, which previously caused those entries to be replayed after restart.

### Configuration

| Setting | Old | New |
| --- | ---: | ---: |
| `ct_log.batch_size` | 256 | 1024 |
| `ct_log.fetch_concurrency` | none | 4 (1-16; env `CERTSTREAM_CT_LOG_FETCH_CONCURRENCY`) |
| `ct_log.checkpoint_signature_mode` | none | `warn` |

Set `fetch_concurrency: 1` to restore the v1.5.2 sequential fetch behavior.

### Dependencies

Added `tikv-jemallocator`, `static_ct_api`, `signed_note`, and `p256` for allocator and checkpoint verification support.

### Tests

251 unit tests, up from 249, plus integration and snapshot suites.

### Upgrade

Drop-in upgrade from v1.5.2. New configuration keys are optional.

```bash
docker pull ghcr.io/reloading01/certstream-server-rust:1.5.3
```

---

## v1.5.2: Verified CT catalog registry

**Release date:** June 16, 2026

CT source discovery now uses a code-owned registry with source verification instead of operator-configured log-list URLs.

### Trusted CT sources

The built-in registry contains:

- `google_v3_usable`: verified with a pinned RSA-SHA256 trust anchor and authoritative by default.
- `google_v3_all`: verified with the same key but non-authoritative unless enabled through `ct_log.catalog_authority_overrides`.
- `apple`: TLS-authenticated through issuer-CA SPKI pinning. Apple does not publish a detached signature, so this source is permanently non-authoritative.

A source that fails verification cannot auto-spawn watchers. Authority overrides only apply to sources that currently verify; they cannot promote an unverified source. On signature failure, a source becomes non-authoritative for that cycle while its raw bytes remain available for audit through `certstream_ct_catalog_source_verified=0`.

### Operational controls

- Per-operator outbound rate limits: `ct_log.default_operator_rate_limit_ms` and `ct_log.operator_rate_limits`.
- Per-log `batch_size` and `poll_interval_ms` overrides on `custom_logs` and `static_logs`.
- `expected_log_id` validates static-CT overrides against discovered catalog identity, including transport, fetch URL, and an explicitly declared checkpoint origin.

Startup fails if an override contradicts the signed catalog or if multiple resolved watchers would use the same CT log ID.

### Breaking change

The following settings are removed:

- `ct_logs_url`
- `additional_log_lists`
- `CERTSTREAM_CT_LOGS_URL`
- `CERTSTREAM_ADDITIONAL_LOG_LISTS`

CT sources now come from the built-in registry. Apple-only or otherwise non-authoritative logs must be declared under `static_logs` or `custom_logs`.

Existing configurations that still contain the removed keys are ignored rather than rejected.

### Dependencies

Added `rsa` for catalog signature verification and `rustls` plus `rustls-native-certs` for the pinned Apple TLS client. `reqwest` now uses its `rustls` feature.

---

## v1.5.1: Static-CT overlap and source metrics

**Release date:** June 15, 2026

Two operational changes, with no breaking changes for v1.5.0 configuration or existing Prometheus queries.

### Configurable static-CT tail overlap

Fresh static-CT watchers previously started at a fixed `tree_size - 256`. The overlap is now configurable:

- `ct_log.start_overlap_leaves`, default `256`
- `CERTSTREAM_CT_LOG_START_OVERLAP_LEAVES`
- Valid range up to 100,000 leaves

### CT source observability and retries

- Added `certstream_ct_runtime_log_info` with `source_id`, `log_id`, `log`, `operator`, and `log_type` labels.
- Existing per-log metrics now include a stable `source_id` label such as `ctlog:<log_id>` or `url:<...>` while keeping the existing `log` label.
- Added `certstream_ct_log_rate_limited_total{log_type}` and `certstream_ct_log_empty_responses_total`.
- RFC 6962 watchers now honor `Retry-After` on HTTP 429 responses, clamped to 250 ms to 10 min, matching the static-CT path.

---

## v1.5.0: Production hardening

**Release date:** May 19, 2026

v1.5.0 focuses on correctness and long-running behavior under load: race fixes, safer shutdown and parsing, lower resource usage, more reliable WebSocket handling, and a simpler rate-limiting model.

The project now targets Rust 2024 Edition.

### Breaking change

WebSocket certificate and heartbeat messages now use text frames instead of binary frames. Clients that only accept binary frames must be updated.

The old Free/Standard/Premium rate-limit tiers are also removed. Authentication now controls access and a single source-IP rate limiter controls throughput.

### Performance

After tuning and soak testing:

| Metric | Before | After |
| --- | ---: | ---: |
| Idle RSS | 223 MiB | 174 MiB |
| Loaded RSS | 253 MiB | 198 MiB |
| Loaded CPU | 49% | 25% |

A 12-hour soak test completed with zero panics, restarts, or health-check failures, filtered 38.3M duplicates, and maintained a stable RSS plateau.

### Data integrity

- **Dedup race:** `DedupFilter::is_new` now uses `DashMap::entry` for atomic check-and-insert. A regression test with 32 threads × 1000 calls confirms one successful insertion.
- **Dedup cache wipe:** reaching capacity no longer clears the entire map. Expired entries are removed selectively.
- **State persistence race:** `save_if_dirty` clears the dirty flag with an atomic swap before snapshot generation. Failed saves re-arm persistence.
- **RFC 6962 rollback protection:** both static-CT and RFC 6962 watchers reject a `tree_size` smaller than the previously observed value. Bounds around `tree_size - 1` are also checked.
- **Certificate cache eviction:** TTL eviction verifies pointer identity before deleting the API index, preventing stale copies from removing newer entries.

### Reliability

- Startup paths no longer depend on `.expect()` for invalid TLS files, occupied ports, or malformed YAML.
- Configuration validation now runs on normal startup, so invalid values such as `buffer_size: 0` fail before runtime.
- WebSocket writes have a 10-second timeout; stalled clients are disconnected and counted by `certstream_ws_disconnect_write_timeout`.
- Clients are disconnected after five consecutive lag events (`lag_policy::MAX_CONSECUTIVE_LAGS`).
- JSON serialization is skipped when there are no subscribers.

### Memory and resource use

- Issuer caches are shared across watchers instead of allocated per CT log.
- Issuer pre-warming is capped at `MAX_INFLIGHT_ISSUER_FETCHES = 16` and skips cached fingerprints.
- Static-CT tile decompression is capped at `MAX_DECOMPRESSED_TILE_BYTES = 16 MiB`; oversize payloads increment `certstream_static_ct_decompress_oversize`.

### Protocol and security

- WebSocket certificate and heartbeat messages now use `Message::Text`.
- The zero-copy text path uses `Utf8Bytes::try_from(bytes)` to avoid per-message string allocation.
- Partial hot reloads no longer reset omitted authentication sections to defaults.
- Permissive CORS applies only to public WebSocket, SSE, and `/api/cert/{hash}` routes. `/metrics`, `/health`, and `/example.json` are excluded.
- RFC 6962 chain parsing now rejects bytes beyond the declared chain length.
- Authentication token comparison remains constant-time through `subtle::ct_eq`.

### Runtime defaults

| Setting | Old | New |
| --- | ---: | ---: |
| reqwest idle pool | 20 | 4 |
| dedup capacity | 1M | 200K |
| API cache | 10K | 1K |
| tokio worker threads | 8 | 4 |

These defaults reduce idle CPU, memory drift, and RSS without changing external behavior.

### Dedup hot-path CPU fix

`DedupFilter::is_new` previously ran O(n) expiration scans inline after capacity was reached. Expiration now runs only in the periodic cleanup task.

Measured before the fix:

| Scenario | CPU |
| --- | ---: |
| Idle containers | 211% |
| Loaded containers | 268% |

After the fix:

| Scenario | CPU |
| --- | ---: |
| Idle containers | 5% |
| Loaded containers | 16% |

### Dependency updates

- tokio 1.52
- reqwest 0.13
- axum-server 0.8
- simd-json 0.17
- x509-parser 0.18
- notify 8

Builder image:

```dockerfile
rust:1.95-alpine
```

### Removed

The following rate-limit tier features are removed:

- `RateLimitTier::{Free, Standard, Premium}`
- tier token tables
- standard/premium throughput configuration

Legacy YAML keys still deserialize through compatibility aliases.

### Tests

425 tests pass across unit, integration, fuzz, graceful-failure, and soak coverage. No panics were found during fuzzing.

### Upgrade

```bash
docker pull ghcr.io/reloading01/certstream-server-rust:1.5.0
```

For v1.4.x deployments:

- old standard/premium rate-limit fields are ignored
- move legacy tier tokens to `auth.tokens`
- WebSocket clients must accept text frames

---

## v1.4.0: static-ct-api v1.0.0-rc.1 and log-list discovery

**Release date:** May 2, 2026

This release updates static-CT handling to static-ct-api v1.0.0-rc.1, adds Apple tiled-log discovery, introduces per-protocol runtime switches, and fixes a tile-parser bug that caused pre-v1.4 builds to emit only the first entry from each static-CT tile.

### Tile parser fix

`Fingerprint certificate_chain<0..2^16-1>` is byte-length-prefixed, not count-prefixed. Earlier versions interpreted the prefix as a fingerprint count and consumed bytes from following leaves as chain data.

Full tiles now emit all 256 entries. The fix was verified against Sycamore, Willow, Cloudflare Raio, and IPng Networks tiles.

### Log-list discovery

`additional_log_lists` defaults to Apple's `current_log_list.json` and is fetched alongside Google's v3 list. `operators[].tiled_logs[]` from both sources are exposed as static-CT watchers.

- Logs are deduplicated by `log_id`.
- The submission URL determines checkpoint origin.
- User-defined `static_logs` override discovery for the same URL.

### static-ct-api v1.0.0-rc.1 conformance

- Parses the `leaf_index` SCT extension (type 0, 40-bit big-endian) and validates it against the tile-derived index. Mismatches increment `certstream_static_ct_leaf_index_mismatch`.
- Enforces partial-tile width: the final tile must contain `floor(s / 256^l) mod 256` leaves, while full tiles contain 256. Invalid widths are rejected and counted by `certstream_static_ct_tile_width_mismatch`.
- Detects and rejects tree-size rollback through `certstream_static_ct_tree_size_rollbacks`.
- Accepts additional witness signature lines after the primary checkpoint signature.

### Runtime protocol switches

- `CERTSTREAM_RFC6962_ENABLED=false` or `ct_log.rfc6962_enabled: false` disables the RFC 6962 watcher pool.
- `CERTSTREAM_STATIC_CT_ENABLED=false` disables static-CT watchers.
- Startup fails if both protocol families are disabled.

### Health checks and rate limiting

Static-CT logs are probed through `/checkpoint`; RFC 6962 logs use `/ct/v1/get-sth`.

Static-CT watchers from the same operator now share a 2 req/s limiter, matching the existing RFC 6962 behavior.

### Dedup configuration

Added:

- `dedup.capacity`
- `dedup.ttl_secs`
- `CERTSTREAM_DEDUP_CAPACITY`
- `CERTSTREAM_DEDUP_TTL_SECS`

Defaults are 1M entries and 900 seconds to cover the wider RFC 6962/static-CT propagation window.

### New metrics

- `certstream_static_ct_leaf_index_mismatch{log}`
- `certstream_static_ct_tile_width_mismatch{log}`
- `certstream_static_ct_tree_size_rollbacks{log}`

### Compatibility notes

- Internal `fetch_log_list` now takes `&[String]` for additional list URLs and returns mixed RFC 6962 and static-CT logs. Downstream binary integrators should re-pin.
- The `dedup` block is new but optional.
- `additional_log_lists` now fetches Apple's list by default. Set it to an empty array, or `CERTSTREAM_ADDITIONAL_LOG_LISTS=`, to opt out.

### Tests

205 unit tests, up from 190 in v1.3.4, covering `leaf_index`, chain fingerprint framing, Apple-style lists, and partial-tile behavior.

### Upgrade

```bash
docker pull ghcr.io/reloading01/certstream-server-rust:1.4.0
```

Existing v1.3.4 configurations remain valid. To retain v1.3-style behavior:

```yaml
additional_log_lists: []
ct_log:
  static_ct_enabled: false
dedup:
  capacity: 500000
  ttl_secs: 300
```

---

## v1.3.4: Submission timestamp support

**Release date:** April 3, 2026

Adds `submission_timestamp` to certificate messages. The value is the SCT timestamp from the CT log, as defined in [RFC 6962 §3.1](https://www.rfc-editor.org/rfc/rfc6962#section-3.1), complementing `seen`, which records when this server processed the entry.

```json
{
  "seen": 1703808000.123,
  "submission_timestamp": 1703721600.456
}
```

| Field | Source | Meaning |
| --- | --- | --- |
| `seen` | Server clock | When this server processed the entry |
| `submission_timestamp` | CT log | When the CT log accepted the certificate and issued the SCT |

The field uses Unix seconds with millisecond precision and is available on full and lite messages for both RFC 6962 and static-CT entries.

Implementation details:

- RFC 6962: extracted from bytes 2-9 of `leaf_input` as a big-endian `uint64` millisecond value.
- Static CT: sourced from the `TileLeaf` timestamp and renamed to `submission_timestamp`.

### Tests

189 unit tests. Existing static-CT tests were updated for the field rename.

### Upgrade

Drop-in upgrade from v1.3.3. There are no config or state-file changes. The JSON change is additive; consumers will see the new field but no existing fields are removed.

```bash
docker pull ghcr.io/reloading01/certstream-server-rust:1.3.4
```

Thanks to [@raffysommy](https://github.com/raffysommy) for the contribution in [#5](https://github.com/reloading01/certstream-server-rust/pull/5).

---

## v1.3.3: Bandwidth and stream controls

**Release date:** March 13, 2026

This release reduces CT fetch bandwidth through HTTP compression, adds per-stream enable/disable controls, switches the default Google list to Chrome-trusted logs, and avoids parsing certificate chains for duplicate entries.

### Stream controls

Each output stream can be enabled independently. Disabled streams are not serialized and their WebSocket/SSE routes are not registered.

```yaml
streams:
  full: false
  lite: true
  domains_only: true
```

| Variable | Default | Description |
| --- | --- | --- |
| `CERTSTREAM_STREAM_FULL_ENABLED` | `true` | Full stream, including DER and chain |
| `CERTSTREAM_STREAM_LITE_ENABLED` | `true` | Lite stream without DER/chain |
| `CERTSTREAM_STREAM_DOMAINS_ONLY_ENABLED` | `true` | Domains-only stream |

Disabling the full stream avoids its DER/chain serialization cost and can reduce per-certificate serialization work by about 80%.

### HTTP compression

reqwest now enables gzip, brotli, and deflate. Previously no `Accept-Encoding` header was sent, so CT JSON responses were uncompressed.

Measured/expected inbound bandwidth reduction for supporting operators is about 30-50%.

### Deferred chain parsing

Chain certificates are now parsed after the cross-log dedup check. Duplicate entries, estimated at roughly 60-80% across overlapping logs in the tested workload, no longer pay the cost of parsing 2-4 chain certificates.

### Chrome-trusted log list

The default Google list changes from `all_logs_list.json` to `log_list.json`.

| Metric | `all_logs_list.json` | `log_list.json` |
| --- | ---: | ---: |
| Active production logs | 24 | 47 |
| Test/staging logs | 19 | 0 |
| Duplicate Solera logs | 12 | 0 |
| New operators | none | TrustAsia, Geomys, IPng Networks |

`LogState` now models the `readonly` field explicitly instead of relying on serde to ignore it.

### Tests

189 unit tests, including four new stream configuration tests.

### Upgrade

Drop-in upgrade from v1.3.2. The `streams` section is optional and all streams remain enabled by default.

The default log-list URL changes; override it with `CERTSTREAM_CT_LOGS_URL` if needed. For bandwidth-constrained deployments, set `CERTSTREAM_STREAM_FULL_ENABLED=false`.

```bash
docker pull ghcr.io/reloading01/certstream-server-rust:1.3.3
```

---

## v1.3.2: Live connection counts and public API docs

**Release date:** March 9, 2026

Fixes `/api/stats` reporting zero active connections and adds public API documentation and a live certificate demo to the docs site.

### `/api/stats` connection counts

`ApiState` previously owned unused `ws_connections` and `sse_connections` counters, so `/api/stats` always returned zero active connections.

The endpoint now reads the actual connection sources:

- `ws_state: Arc<websocket::AppState>` uses `ConnectionCounter::total()`.
- `sse_connection_count()` reads the `SSE_CONNECTION_COUNT` `AtomicU64`.
- `handle_stats` calculates totals from those live values.

### Documentation

- Added a live SSE certificate demo with detail modal.
- Added a live active-connection counter that reads `/api/stats` every 30 seconds.
- Added Google Analytics (GA4) to the docs pages.

### Upgrade

Drop-in upgrade from v1.3.1. No configuration or state-file changes.

```bash
docker pull ghcr.io/reloading01/certstream-server-rust:1.3.2
```

---

## v1.3.1: Static-CT tracker restart fix

**Release date:** March 8, 2026

Fixes `/api/logs` showing `current_index: 0, tree_size: 0` for static-CT logs that were already caught up when the server restarted.

When `current_index == tree_size` at startup, the poll loop skipped tile processing and never called `tracker.update()`. The tracker is now updated with the current checkpoint values before the watcher sleeps.

This mainly affected closed-period static-CT logs, including Let's Encrypt Willow/Sycamore 2025h2d, because no new entries arrived to refresh the tracker later.

### Tests

185 unit tests. The test count is unchanged because the bug was in runtime control flow.

### Upgrade

Drop-in upgrade from v1.3.0. No configuration or state-file changes.

```bash
docker pull ghcr.io/reloading01/certstream-server-rust:1.3.1
```

---

## v1.3.0: Zero-copy pipeline and correctness fixes

**Release date:** February 22, 2026

This release reduces hot-path allocation, enables SIMD JSON by default, hardens state persistence, and fixes several correctness and shutdown bugs.

### Performance and allocation

- `CertificateMessage::pre_serialize()` builds `full`, `lite`, and `domains_only` `Bytes` payloads once and shares them through `Arc<PreSerializedMessage>`.
- `CertificateData.leaf_cert` is now `Arc<LeafCert>` so output formats share one leaf-certificate allocation.
- Dedup keys use raw `[u8; 32]` SHA-256 digests instead of heap-allocated 64-byte hex strings.
- `LeafCert::fingerprint` uses `Arc<str>` and shares storage with `sha1`.
- Static values such as `signature_algorithm` and `message_type` use `Cow<'static, str>`.
- `simd-json` is now a default Cargo feature. Use `--no-default-features` to fall back to `serde_json`.

Under a sustained ingest rate of about 1,000 certs/s, measured RSS stayed around 150 MB without long-term growth.

### Correctness and reliability

- **RFC 6962 partial responses:** `current_index` now advances by the number of entries actually received rather than the requested batch size, preventing skipped ranges.
- **SIGTERM/SIGINT registration:** signal streams are registered before entering `select!`, preventing a fast shutdown signal from being lost. Signal registration failure now cancels the shutdown token.
- **State durability:** state temp files are `fsync()`ed before atomic rename through `write_and_sync()`.
- **Health endpoints:** `/health`, `/health/deep`, `/metrics`, and `/example.json` bypass auth and rate limiting so probes and Prometheus scraping continue to work.
- **WebSocket heartbeat type:** heartbeat frames now use the same binary frame type as certificate messages in this release.
- **Initial STH failure:** RFC 6962 watchers exit instead of silently starting from index 0.
- **Missing `ctlPoisonByte`:** chain certificates now deserialize missing values as `false` through `#[serde(default)]`.
- **`LogHealth` consistency:** circuit-breaker state moved under one `Mutex<LogHealthInner>` to prevent torn reads.
- **Degraded threshold:** the half-threshold is clamped to at least 1 for low sample counts.
- **Hot reload path env:** `CERTSTREAM_HOT_RELOAD_WATCH_PATH` is now parsed correctly.
- **Shutdown rename race:** `ENOENT` from a concurrent temp-file rename is treated as benign.
- **Prometheus startup values:** key counters are initialized to zero so `rate()` and `increase()` do not return `NaN` before the first event.
- **404 responses:** missing routes now return `{"error": "not found"}`.
- **Empty batches:** RFC 6962 and static-CT watchers do not advance on empty response batches.

### Benchmarks vs v1.2.0

| Metric | v1.2.0 | v1.3.0 |
| --- | --- | --- |
| Memory under load | ~198 MB | ~150 MB |
| Hot-path heap allocations per certificate | ~6 | ~3 |
| Dedup key allocation | 1 heap `String` | 0; 32-byte stack array |
| SIMD JSON | Opt-in | Default |
| Partial-response certificate skips | Possible | Fixed |
| Health/metrics behind auth | Yes | No |
| Fast SIGTERM loss | Possible | Fixed |

### Upgrade

Drop-in upgrade from v1.2.0. Existing state files remain compatible.

SIMD JSON no longer requires `--features simd`, and monitoring endpoints are always reachable regardless of authentication settings.

```bash
docker pull ghcr.io/reloading01/certstream-server-rust:1.3.0
```

---

## v1.2.0: Static CT support and stability overhaul

**Release date:** February 6, 2026

Adds static-CT support, cross-log certificate deduplication, broader log coverage, graceful worker recovery, and a monitoring stack. It also removes the legacy TCP output protocol.

### Breaking change

TCP output is removed. Use WebSocket (`ws://host:8080/`) or SSE (`http://host:8080/sse`).

The following environment variables are removed:

- `CERTSTREAM_TCP_ENABLED`
- `CERTSTREAM_TCP_PORT`

### Static CT support

The server now supports checkpoint- and tile-based static CT according to [c2sp.org/static-ct-api](https://c2sp.org/static-ct-api), including:

- x509/precert tile parsing
- hierarchical tile paths
- gzip decompression
- issuer certificate fetching with a DashMap-backed cache

Four Let's Encrypt Sunlight logs are configured by default: Willow and Sycamore for 2025h2d and 2026h1.

### Cross-log deduplication

A SHA-256 dedup filter prevents the same certificate from being broadcast repeatedly when it appears in multiple CT logs.

Initial defaults in this release:

- TTL: 5 minutes
- cleanup interval: 60 seconds
- capacity: 500K entries, approximately 50 MB

The filter runs as a background task and shuts down through the shared cancellation token.

### CT log coverage and health

- Monitors all logs except rejected/retired, rather than only `usable` logs.
- Adds Google Solera and readonly logs.
- Startup health checks run in parallel with a 5-second timeout; 63 candidates produced 49 reachable logs in the tested set.
- Worker startup is staggered by 50 ms to reduce rate-limit bursts.
- Per-log circuit breakers use Closed → Open → HalfOpen transitions with 30-second open state and exponential backoff from 1 to 60 seconds.
- `CancellationToken` coordinates SIGINT/SIGTERM shutdown.
- `GET /health/deep` reports per-log health, connection count, and uptime, and returns HTTP 503 when more than half of logs are failing.

### Prometheus metrics

| Metric | Type | Description |
| --- | --- | --- |
| `certstream_static_ct_logs_count` | Gauge | Static CT logs monitored |
| `certstream_static_ct_tiles_fetched` | Counter | Static CT tiles fetched |
| `certstream_static_ct_entries_parsed` | Counter | Static CT entries parsed |
| `certstream_static_ct_parse_failures` | Counter | Static CT parse failures |
| `certstream_static_ct_checkpoint_errors` | Counter | Checkpoint fetch/parse errors |
| `certstream_issuer_cache_size` | Gauge | Cached issuer certificates |
| `certstream_issuer_cache_hits` | Counter | Issuer cache hits |
| `certstream_issuer_cache_misses` | Counter | Issuer cache misses |
| `certstream_duplicates_filtered` | Counter | Duplicate certificates filtered |
| `certstream_dedup_cache_size` | Gauge | Current dedup cache size |
| `certstream_worker_panics` | Counter | Worker panics recovered |
| `certstream_log_health_checks_failed` | Counter | Failed log health checks |

Per-log metrics such as `certstream_messages_sent`, `certstream_parse_failures`, and static-CT counters now include a `log` label.

### Grafana and Prometheus

A Grafana dashboard is included for source volume, dedup efficiency, and static-CT metrics. Prometheus and Grafana are behind the Docker Compose `monitoring` profile and are not started by default.

```bash
# Server only
docker compose up -d

# Server + monitoring
docker compose --profile monitoring up -d
```

Default Grafana credentials are `admin` / `certstream` and can be changed through `GRAFANA_USER` and `GRAFANA_PASSWORD`.

### Bug fixes

- **Dirty state updates:** `update_index()` now uses `AtomicBool` instead of `try_write()` on a tokio `RwLock<bool>`, preventing lost dirty-state updates.
- **Shutdown state flush:** state is saved after the HTTP server stops, avoiding up to 30 seconds of lost progress.
- **Periodic save shutdown:** the periodic save task now accepts a `CancellationToken` and flushes before exit.
- **Default state file:** `state_file` now defaults to `"certstream_state.json"` instead of `null`.
- **Subject/issuer parsing:** non-UTF8String ASN.1 encodings now fall back to raw ASCII-compatible bytes instead of producing `null`.
- **Environment overrides:** environment values now apply on top of YAML even when the YAML section already exists.
- **JSON consistency:** absent subject/issuer fields are omitted consistently through `skip_serializing_if = "Option::is_none"`.
- **HTTP status handling:** non-2xx CT responses are handled before JSON parsing, reducing parse-error loops on 400/429/5xx responses.
- **Worker panic recovery:** watcher panics are caught and restarted after five seconds.
- **WebSocket ping priority:** ping/pong handling gets priority through `biased;` in `tokio::select!`.

### Performance

- O(1) certificate cache lookup using DashMap and normalized hash keys.
- O(1) domain deduplication using HashSet instead of repeated linear `contains()` scans.
- Preallocated serialization buffers: 4 KB full, 2 KB lite, 512 B domains-only.
- 50 ms staggered worker startup reduced DigiCert 429 responses by about 60% in testing.
- Optional SIMD JSON through `cargo build --release --features simd`.
- Release profile uses `opt-level = 3`, LTO, one codegen unit, and symbol stripping.

### Docker

The image and Compose setup now include a native health check against `/health/deep`.

### Configuration

Static CT logs can be configured with:

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

Default `state_file` changes from `null` to `"certstream_state.json"`.

### Tests

183 unit tests across the codebase:

- `static_ct` 30
- `parser` 27
- `config` 18
- `api` 18
- `middleware` 14
- `rate_limit` 13
- `log_list` 13
- `state` 12
- `certificate` 11
- `watcher` 11
- `dedup` 10
- `hot_reload` 6

Added `flate2 = "1.0"` for gzip tile decompression.

### Benchmarks vs v1.1.0

| Metric | v1.1.0 | v1.2.0 |
| --- | --- | --- |
| Parse errors | Continuous | 0 |
| Healthy logs | Variable | 49/49 |
| Throughput | ~200 cert/s | ~400 cert/s |
| Client disconnections | Frequent | Rare |
| Recovery | Manual | Automatic |

### Upgrade

- Switch TCP clients to WebSocket or SSE.
- Subject/issuer fields now populate across supported certificate encodings.
- Environment variables now override YAML consistently.
- State persistence is enabled by default.
- Cross-log deduplication is always active.
- Non-Let's Encrypt static-CT logs require explicit `static_logs` entries.
- Monitoring remains opt-in through the Compose `monitoring` profile.

```bash
docker pull ghcr.io/reloading01/certstream-server-rust:1.2.0
```
