# benchmarks/

Measurement harness for v1.6.0 release validation. Three things to measure,
three scripts to run them, one to summarise:

| Script | What it does | Output |
|---|---|---|
| `run_comparison.sh` | Side-by-side v1.5.x vs v1.6.0 RSS + CPU under identical load | `results/comparison_<ts>.json` |
| `run_soak.sh` | Single binary, long run, samples VmRSS for drift analysis | `results/soak_<ts>.csv` |
| `measure_latency.sh` | WebSocket client, records broadcast latency, emits percentiles | `results/latency_<ts>.json` |
| `summarize.sh` | Reads any result file and prints a paste-ready text summary | stdout |

Everything writes under `benchmarks/results/` (gitignored). Only the scripts
themselves are committed.

---

## Prereqs

| Tool | Required for | Install |
|---|---|---|
| `bash` | all scripts | (every distro) |
| `jq` | comparison + latency summaries | `apt install jq` / `brew install jq` |
| `curl` | `/health` readiness probe | (every distro) |
| `awk` | summarize.sh math + /proc parsing | (every distro) |
| `python3` | latency + dummy_subscriber | (every distro) |
| `python3 -m pip install websockets` | latency + dummy_subscriber | once, user-level fine |
| `pidstat` (sysstat) | preferred CPU sampler | `apt install sysstat` (**optional** — falls back to `/proc/<pid>/stat` ticks if missing) |

The scripts check for each dep at startup and exit non-zero with a clear
install hint when something is missing.

---

## Recommended order of operations

Assuming you've built both binaries:

```
TARGET=~/builds
mkdir -p $TARGET

# v1.5.x — from the tag
git worktree add /tmp/v15 v1.5.0
(cd /tmp/v15 && cargo build --release)
cp /tmp/v15/target/release/certstream-server-rust $TARGET/certstream-v1.5.x

# v1.6.0 — from release/v1.6.0 HEAD
cargo build --release
cp target/release/certstream-server-rust $TARGET/certstream-v1.6.0
```

Then, from the repo root:

```
cd benchmarks

# 1. Idle-mode comparison (no subscribers; pure runtime + CT polling)
./run_comparison.sh \
    --v15-bin $TARGET/certstream-v1.5.x \
    --v16-bin $TARGET/certstream-v1.6.0 \
    --mode idle --duration 30m

# 2. Loaded-mode comparison (10 dummy WS subs per binary)
./run_comparison.sh \
    --v15-bin $TARGET/certstream-v1.5.x \
    --v16-bin $TARGET/certstream-v1.6.0 \
    --mode loaded --duration 30m

# 3. Broadcast latency on v1.6.0
./run_comparison.sh --v15-bin ... --v16-bin ... --mode loaded --duration 10s  # warmup, optional
# (the latency script connects to a server you've already started; the
#  simplest is to start a v1.6.0 binary by hand in another terminal:)
$TARGET/certstream-v1.6.0 &     # listens on default port 8080
./measure_latency.sh --url ws://localhost:8080/full-stream --duration 30m

# 4. 24h soak on v1.6.0 (drift verdict)
./run_soak.sh --bin $TARGET/certstream-v1.6.0 --duration 24h \
              --label "v1.6.0-mimalloc"

# 5. Final paste-ready summary across everything
./summarize.sh results/*
```

---

## What "healthy" looks like

### Comparison (`comparison_*.json`)

- **avg RSS**: v1.6.0 should be lower than v1.5.x. Magnitude depends on
  workload — for idle, expect tens of MiB lower; for loaded, similar or
  slightly lower at peak but **much** lower on the long tail (drift).
- **peak RSS**: not the most interesting metric on its own; useful for
  catching short-lived bursts that average-only would miss.
- **avg CPU**: v1.6.0 should be at or below v1.5.x. Allocator + parser
  optimisations shouldn't make CPU worse; if they have, that's a regression.

### Soak (`soak_*.csv`)

- The summary prints a `drift` value in **MiB/hour** (computed as a linear
  regression of RSS vs elapsed seconds).
- **`FLAT (pass)`**: `|drift| < 0.1 MiB/h`. This is the v1.6.0 target —
  mimalloc returns pages aggressively, RSS curve tracks workload jitter
  rather than climbing.
- **`drifting up (borderline)`**: `0.1 < drift < 0.5 MiB/h`. Plausible but
  worth investigating; might be the issuer cache filling, might be real.
- **`RISING (investigate)`**: `drift > 0.5 MiB/h`. Something is leaking or
  the allocator isn't being asked to release pages. Pre-1.6.0 baseline.
- **`FALLING`**: `drift < -0.5 MiB/h`. Means the allocator is returning
  memory faster than workload is allocating — fine, but worth noting in
  case it indicates a one-shot cleanup event biasing the slope.

### Latency (`latency_*.json`)

- `data.seen` is set after dedup + cache push, before serialisation. So
  the measured latency is `serialise + tx queue + network + recv`.
- On localhost: expect single-digit milliseconds for p50, p99 typically
  under 50ms. Anything in the hundreds means slow consumer / GC-style stalls
  / OS scheduling pressure.
- The "dropped" counts in the summary are sanity backstops:
  - `dropped_negative`: clock skew (server `seen` is ahead of client clock).
    On a single host this should be zero.
  - `dropped_above_30s`: outliers, usually from a long reconnect window
    where backed-up messages flush as soon as the WS comes back up.
  - `dropped_no_seen_field`: domains-only frames have no `seen` field;
    these are silently skipped.

---

## Output formats (for downstream tooling)

### `comparison_*.json`

```json
{
  "kind": "comparison",
  "mode": "loaded",
  "started_at": "...",
  "duration_seconds": 1800,
  "sample_interval_seconds": 60,
  "subscribers_per_binary": 10,
  "v1_5": {
    "samples": [{"t": 0, "rss_kib": 178432, "cpu_pct": 12.3}, ...],
    "summary": {
      "n": 30, "avg_rss_mib": 174.2, "peak_rss_mib": 192.1,
      "avg_cpu_pct": 14.8, "peak_cpu_pct": 28.0
    }
  },
  "v1_6": { ... },
  "deltas": { "rss_mib_change": -23.4, "rss_mib_pct": -13.4, "cpu_pct_change": -2.1 }
}
```

### `soak_*.csv`

```
# kind=soak
# binary=/path/to/binary
# label=v1.6.0-mimalloc
# started_at=...
# target_duration_seconds=86400
# sample_interval_seconds=300
iso_timestamp,seconds_elapsed,rss_kib
2026-05-21T12:00:00Z,0,178432
2026-05-21T12:05:00Z,300,178640
...
# stopped_at=...
```

CSV is append-only; each row is a complete record. Killing the script
mid-run leaves a valid partial time-series. The trailing `# stopped_at`
line is written by the EXIT trap.

### `latency_*.json`

```json
{
  "kind": "latency",
  "url": "ws://localhost:8080/full-stream",
  "started_at": "...",
  "duration_seconds": 1800,
  "samples": 47832,
  "dropped_negative": 0,
  "dropped_above_30s": 4,
  "dropped_no_seen_field": 0,
  "min_ms": 0.412, "max_ms": 1832.0, "mean_ms": 4.7,
  "p50_ms": 2.8, "p95_ms": 12.3, "p99_ms": 47.1
}
```

---

## Early-exit behaviour

All three runners trap `EXIT INT TERM` and finalise their output before the
shell returns. Specifically:

- **`run_comparison.sh`**: collects samples into two `.partial_*.jsonl`
  files as they happen. On exit, the JSONL files are folded into the final
  `comparison_*.json` with the deltas section computed against whatever
  samples were captured. A Ctrl-C at minute 17 of a 30-minute run produces
  a valid 17-minute comparison file.
- **`run_soak.sh`**: every sample is appended to the CSV in-place. The
  exit trap appends a `# stopped_at=` metadata line and runs
  `summarize.sh` inline. Killing it at hour 6 leaves a 6-hour soak file
  with a correct verdict line.
- **`measure_latency.sh`**: signals are forwarded to the Python helper,
  which has its own SIGINT handler that writes the JSON summary before
  returning 0.

In all three cases: **interrupted output is real output, treat it the
same as a completed run**. The summary scripts don't distinguish.

---

## Notes on what the harness deliberately does not do

- **No automated v1.5.x build.** You're expected to point `--v15-bin` at
  a binary you've already built. Avoids hiding which exact commit was
  measured.
- **No automated upload of results.** Results stay local; `summarize.sh`
  output is the artifact you paste into the release notes.
- **No subscriber count auto-tuning.** Default `--subscribers 10` is what
  the release notes table is based on. Override if your environment
  needs different load.
- **No CT log mocking.** Both binaries talk to the real CT log network.
  This means runs aren't perfectly deterministic, but the alternative is
  building a fake log harness that wouldn't capture real-world fanout
  patterns. Run for ≥30 minutes to amortise log-side noise.
