#!/usr/bin/env bash
# Run two certstream-server binaries side-by-side under identical load and
# sample VmRSS + CPU% on each every minute. Writes a single JSON document
# under benchmarks/results/comparison_<timestamp>.json.
#
# Usage:
#   ./run_comparison.sh \
#       --v15-bin /path/to/v1.5.x/certstream-server-rust \
#       --v16-bin /path/to/v1.6.0/certstream-server-rust \
#       --mode {idle|loaded} \
#       --duration 30m
#
# Modes:
#   idle    — no subscribers; measures resident overhead of the runtime +
#             CT log polling alone. Loaded CPU should be small and dominated
#             by JSON-skipped CT ingest.
#   loaded  — spawns N=10 dummy WebSocket subscribers per binary, so the
#             full broadcast fanout path is exercised.
#
# Early exit (Ctrl-C): the JSONL accumulator is finalized into the final
# JSON with whatever samples were collected before the signal.

set -uo pipefail

# Resolve script dir & source the shared helpers.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
. "$SCRIPT_DIR/lib.sh"

# --- Defaults --------------------------------------------------------------
MODE="loaded"
DURATION="30m"
SAMPLE_INTERVAL_SEC=60
SUBSCRIBERS_PER_BINARY=10
V15_PORT=18080
V16_PORT=18081
WS_PATH="/full-stream"
HOST="127.0.0.1"
V15_BIN=""
V16_BIN=""

usage() {
    cat <<EOF
Usage: $0 --v15-bin PATH --v16-bin PATH [options]

Options:
  --v15-bin PATH         path to v1.5.x binary (required)
  --v16-bin PATH         path to v1.6.0 binary (required)
  --mode {idle|loaded}   default: loaded
  --duration DURATION    default: 30m   (suffixes: s/m/h, e.g. 90s, 30m, 1h)
  --sample-interval SECS default: 60
  --subscribers N        per binary, loaded mode only. default: 10
  --v15-port PORT        default: 18080
  --v16-port PORT        default: 18081
  --ws-path PATH         default: /full-stream
  -h, --help             show this help and exit

Output: benchmarks/results/comparison_<UTC-timestamp>.json
EOF
}

# --- Argument parsing ------------------------------------------------------
while [ $# -gt 0 ]; do
    case "$1" in
        --v15-bin)         V15_BIN=$2; shift 2 ;;
        --v16-bin)         V16_BIN=$2; shift 2 ;;
        --mode)            MODE=$2; shift 2 ;;
        --duration)        DURATION=$2; shift 2 ;;
        --sample-interval) SAMPLE_INTERVAL_SEC=$2; shift 2 ;;
        --subscribers)     SUBSCRIBERS_PER_BINARY=$2; shift 2 ;;
        --v15-port)        V15_PORT=$2; shift 2 ;;
        --v16-port)        V16_PORT=$2; shift 2 ;;
        --ws-path)         WS_PATH=$2; shift 2 ;;
        -h|--help)         usage; exit 0 ;;
        *)                 err "unknown arg: $1"; usage; exit 2 ;;
    esac
done

[ -z "$V15_BIN" ] && { err "--v15-bin is required"; exit 2; }
[ -z "$V16_BIN" ] && { err "--v16-bin is required"; exit 2; }
[ -x "$V15_BIN" ] || { err "$V15_BIN is not executable"; exit 2; }
[ -x "$V16_BIN" ] || { err "$V16_BIN is not executable"; exit 2; }
case "$MODE" in idle|loaded) ;; *) err "--mode must be idle or loaded"; exit 2 ;; esac

# Parse DURATION (e.g. 90s, 30m, 1h) into seconds.
duration_to_secs() {
    local s=$1
    case "$s" in
        *s) echo "${s%s}" ;;
        *m) echo "$(( ${s%m} * 60 ))" ;;
        *h) echo "$(( ${s%h} * 3600 ))" ;;
        *)  echo "$s" ;;
    esac
}
DURATION_SECS=$(duration_to_secs "$DURATION")
[ "$DURATION_SECS" -gt 0 ] || { err "invalid duration: $DURATION"; exit 2; }

require_cmds bash jq curl awk sed || exit 1
if [ "$MODE" = "loaded" ]; then
    require_cmds python3 || exit 1
    require_python_websockets || exit 1
fi
if ! optional_dep pidstat; then
    warn "pidstat not found — falling back to /proc/<pid>/stat ticks (less precise)"
fi

# --- Setup paths -----------------------------------------------------------
RESULTS=$(results_dir)
mkdir -p "$RESULTS"
TAG=$(now_tag)
RESULT_PATH="$RESULTS/comparison_${TAG}.json"
JSONL_V15="$RESULTS/.partial_${TAG}_v15.jsonl"
JSONL_V16="$RESULTS/.partial_${TAG}_v16.jsonl"
WORK=$(mktemp -d)
V15_DIR="$WORK/v15"
V16_DIR="$WORK/v16"
mkdir -p "$V15_DIR" "$V16_DIR"

log "mode=$MODE duration=${DURATION_SECS}s interval=${SAMPLE_INTERVAL_SEC}s"
log "v1.5 bin: $V15_BIN (port $V15_PORT)"
log "v1.6 bin: $V16_BIN (port $V16_PORT)"
log "result:   $RESULT_PATH"

# --- PID tracking + cleanup ------------------------------------------------
V15_PID=""; V16_PID=""
V15_SUB_PID=""; V16_SUB_PID=""

cleanup() {
    log "cleaning up..."
    [ -n "$V15_SUB_PID" ] && stop_pid "$V15_SUB_PID"
    [ -n "$V16_SUB_PID" ] && stop_pid "$V16_SUB_PID"
    [ -n "$V15_PID" ]     && stop_pid "$V15_PID"
    [ -n "$V16_PID" ]     && stop_pid "$V16_PID"
    finalize
    rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

# --- Start binaries --------------------------------------------------------
start_binary() {
    # Run in a subshell so the cd doesn't leak into the parent. Each binary
    # gets its own cwd; the relative default state_file landing in that dir
    # keeps the two instances isolated without a config file.
    local bin=$1 port=$2 workdir=$3 log_path=$4
    log "starting $(basename "$bin") on port $port (cwd $workdir)..."
    (
        cd "$workdir" || exit 1
        CERTSTREAM_HOST="$HOST" \
        CERTSTREAM_PORT="$port" \
        CERTSTREAM_LOG_LEVEL="warn" \
        exec "$bin" > "$log_path" 2>&1
    ) &
    echo "$!"
}

V15_LOG="$WORK/v15.log"
V16_LOG="$WORK/v16.log"
V15_PID=$(start_binary "$V15_BIN" "$V15_PORT" "$V15_DIR" "$V15_LOG")
V16_PID=$(start_binary "$V16_BIN" "$V16_PORT" "$V16_DIR" "$V16_LOG")

if ! wait_for_health "$HOST" "$V15_PORT" 60; then
    err "v1.5 failed to come up"; tail -20 "$V15_LOG" >&2; exit 1
fi
if ! wait_for_health "$HOST" "$V16_PORT" 60; then
    err "v1.6 failed to come up"; tail -20 "$V16_LOG" >&2; exit 1
fi
ok "both binaries healthy (v1.5 pid=$V15_PID, v1.6 pid=$V16_PID)"

# --- Optional: start subscribers (loaded mode only) ------------------------
if [ "$MODE" = "loaded" ]; then
    V15_URL="ws://${HOST}:${V15_PORT}${WS_PATH}"
    V16_URL="ws://${HOST}:${V16_PORT}${WS_PATH}"
    log "spawning $SUBSCRIBERS_PER_BINARY subs per binary..."
    python3 "$SCRIPT_DIR/dummy_subscriber.py" \
        --url "$V15_URL" --count "$SUBSCRIBERS_PER_BINARY" \
        2> "$WORK/sub-v15.log" &
    V15_SUB_PID=$!
    python3 "$SCRIPT_DIR/dummy_subscriber.py" \
        --url "$V16_URL" --count "$SUBSCRIBERS_PER_BINARY" \
        2> "$WORK/sub-v16.log" &
    V16_SUB_PID=$!
    # Brief warm-up so the connections settle before the first sample.
    sleep 5
fi

# --- Sampling loop ---------------------------------------------------------
START_EPOCH=$(date +%s)
log "sampling for ${DURATION_SECS}s (Ctrl-C to stop early; partial results will be finalized)"
sample_once() {
    local pid=$1 jsonl=$2 elapsed=$3
    local rss cpu
    rss=$(sample_rss_kib "$pid" 2>/dev/null || echo 0)
    cpu=$(sample_cpu_pct "$pid" 2>/dev/null || echo 0)
    jsonl_append "$jsonl" "$(jq -nc \
        --argjson t "$elapsed" --argjson rss "$rss" --argjson cpu "$cpu" \
        '{t:$t, rss_kib:$rss, cpu_pct:$cpu}')"
}

format_last() {
    # Pretty-print the most recent JSONL line as "rss=X MiB cpu=Y%".
    local jsonl=$1
    tail -n1 "$jsonl" 2>/dev/null \
        | jq -r '"rss=" + (((.rss_kib // 0)/1024)|tostring|.[0:6]) + " MiB cpu=" + ((.cpu_pct // 0)|tostring|.[0:5]) + "%"' \
        2>/dev/null || echo "rss=? cpu=?"
}

: > "$JSONL_V15"; : > "$JSONL_V16"
NEXT_TS=$START_EPOCH
while :; do
    NOW=$(date +%s)
    ELAPSED=$((NOW - START_EPOCH))
    [ "$ELAPSED" -ge "$DURATION_SECS" ] && break
    if [ "$NOW" -ge "$NEXT_TS" ]; then
        # sample_cpu_pct sleeps ~1s internally — run them sequentially so
        # the two measurements aren't fighting for the same CPU.
        sample_once "$V15_PID" "$JSONL_V15" "$ELAPSED"
        sample_once "$V16_PID" "$JSONL_V16" "$ELAPSED"
        log "  t=${ELAPSED}s   v1.5: $(format_last "$JSONL_V15")   v1.6: $(format_last "$JSONL_V16")"
        NEXT_TS=$((NEXT_TS + SAMPLE_INTERVAL_SEC))
    fi
    sleep 1
done

# --- Finalize: collapse JSONL into a single result JSON --------------------
finalize() {
    [ -f "$JSONL_V15" ] || return 0
    local v15_samples v16_samples
    v15_samples=$(jq -s '.' "$JSONL_V15" 2>/dev/null || echo "[]")
    v16_samples=$(jq -s '.' "$JSONL_V16" 2>/dev/null || echo "[]")
    local v15_summary v16_summary
    v15_summary=$(jq -n --argjson s "$v15_samples" '
        {
          n: ($s|length),
          avg_rss_mib: (if ($s|length)>0 then ([$s[].rss_kib]|add/length/1024) else null end),
          peak_rss_mib: (if ($s|length)>0 then ([$s[].rss_kib]|max/1024) else null end),
          avg_cpu_pct: (if ($s|length)>0 then ([$s[].cpu_pct]|add/length) else null end),
          peak_cpu_pct: (if ($s|length)>0 then ([$s[].cpu_pct]|max) else null end)
        }')
    v16_summary=$(jq -n --argjson s "$v16_samples" '
        {
          n: ($s|length),
          avg_rss_mib: (if ($s|length)>0 then ([$s[].rss_kib]|add/length/1024) else null end),
          peak_rss_mib: (if ($s|length)>0 then ([$s[].rss_kib]|max/1024) else null end),
          avg_cpu_pct: (if ($s|length)>0 then ([$s[].cpu_pct]|add/length) else null end),
          peak_cpu_pct: (if ($s|length)>0 then ([$s[].cpu_pct]|max) else null end)
        }')
    local deltas
    deltas=$(jq -n --argjson a "$v15_summary" --argjson b "$v16_summary" '
        {
          rss_mib_change:  (if $a.avg_rss_mib and $b.avg_rss_mib then ($b.avg_rss_mib - $a.avg_rss_mib) else null end),
          rss_mib_pct:     (if $a.avg_rss_mib and $b.avg_rss_mib and $a.avg_rss_mib>0
                              then (($b.avg_rss_mib - $a.avg_rss_mib) / $a.avg_rss_mib * 100) else null end),
          cpu_pct_change:  (if $a.avg_cpu_pct and $b.avg_cpu_pct then ($b.avg_cpu_pct - $a.avg_cpu_pct) else null end)
        }')
    jq -n \
        --arg kind "comparison" \
        --arg mode "$MODE" \
        --arg started_at "$(date -u -d "@$START_EPOCH" +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || date -u -r "$START_EPOCH" +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null)" \
        --argjson duration_seconds "$DURATION_SECS" \
        --argjson sample_interval "$SAMPLE_INTERVAL_SEC" \
        --argjson subs "$SUBSCRIBERS_PER_BINARY" \
        --argjson v15 "$v15_samples" \
        --argjson v16 "$v16_samples" \
        --argjson v15_summary "$v15_summary" \
        --argjson v16_summary "$v16_summary" \
        --argjson deltas "$deltas" \
        '{
          kind: $kind,
          mode: $mode,
          started_at: $started_at,
          duration_seconds: $duration_seconds,
          sample_interval_seconds: $sample_interval,
          subscribers_per_binary: (if $mode == "loaded" then $subs else 0 end),
          v1_5: { samples: $v15, summary: $v15_summary },
          v1_6: { samples: $v16, summary: $v16_summary },
          deltas: $deltas
        }' > "$RESULT_PATH"
    rm -f "$JSONL_V15" "$JSONL_V16"
    ok "result: $RESULT_PATH"
}

# Cleanup trap will call finalize, but call it explicitly here in the
# normal-exit path so the cleanup trap's call becomes a no-op.
finalize
