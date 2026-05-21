#!/usr/bin/env bash
# Docker variant of run_comparison.sh. Runs two pre-built certstream-server
# images side-by-side under identical load and samples VmRSS + CPU% on each.
# Output format is identical to the host-binary variant, so summarize.sh
# reads the resulting JSON without modification.
#
# Usage:
#   ./run_comparison_docker.sh \
#       --v15-image certstream:v1.5.0 \
#       --v16-image certstream:v1.6.0 \
#       --mode {idle|loaded} \
#       --duration 30m
#
# Caveat (macOS Docker Desktop): containers run inside a Linux VM. Absolute
# RSS/CPU numbers carry VM overhead; v1.5↔v1.6 deltas are still meaningful
# because both binaries share the same VM. For absolute production figures,
# rerun on a Linux host.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
. "$SCRIPT_DIR/lib.sh"
# shellcheck source=lib_docker.sh
. "$SCRIPT_DIR/lib_docker.sh"

# --- Defaults --------------------------------------------------------------
MODE="loaded"
DURATION="30m"
SAMPLE_INTERVAL_SEC=60
SUBSCRIBERS_PER_BINARY=10
V15_PORT=18080
V16_PORT=18081
WS_PATH="/full-stream"
HOST="127.0.0.1"
V15_IMAGE=""
V16_IMAGE=""
V15_NAME="certstream-bench-v15"
V16_NAME="certstream-bench-v16"

usage() {
    cat <<EOF
Usage: $0 --v15-image IMAGE --v16-image IMAGE [options]

Options:
  --v15-image IMAGE      v1.5.x docker image tag (required)
  --v16-image IMAGE      v1.6.0 docker image tag (required)
  --mode {idle|loaded}   default: loaded
  --duration DURATION    default: 30m   (suffixes: s/m/h, e.g. 90s, 30m, 1h)
  --sample-interval SECS default: 60
  --subscribers N        per binary, loaded mode only. default: 10
  --v15-port PORT        host-side port mapped to v1.5 container. default: 18080
  --v16-port PORT        host-side port mapped to v1.6 container. default: 18081
  --ws-path PATH         default: /full-stream
  -h, --help             show this help and exit

Output: benchmarks/results/comparison_<UTC-timestamp>.json
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --v15-image)       V15_IMAGE=$2; shift 2 ;;
        --v16-image)       V16_IMAGE=$2; shift 2 ;;
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

[ -z "$V15_IMAGE" ] && { err "--v15-image is required"; exit 2; }
[ -z "$V16_IMAGE" ] && { err "--v16-image is required"; exit 2; }
case "$MODE" in idle|loaded) ;; *) err "--mode must be idle or loaded"; exit 2 ;; esac

duration_to_secs() {
    case "$1" in
        *s) echo "${1%s}" ;;
        *m) echo "$(( ${1%m} * 60 ))" ;;
        *h) echo "$(( ${1%h} * 3600 ))" ;;
        *)  echo "$1" ;;
    esac
}
DURATION_SECS=$(duration_to_secs "$DURATION")
[ "$DURATION_SECS" -gt 0 ] || { err "invalid duration: $DURATION"; exit 2; }

require_cmds bash jq curl awk sed docker || exit 1
if [ "$MODE" = "loaded" ]; then
    require_cmds python3 || exit 1
    require_python_websockets || exit 1
fi

# Verify images exist locally so we fail fast rather than after starting one.
for img in "$V15_IMAGE" "$V16_IMAGE"; do
    if ! docker image inspect "$img" >/dev/null 2>&1; then
        err "docker image not found locally: $img"
        err "  build it first, e.g.: docker build -t $img ."
        exit 1
    fi
done

# --- Setup paths -----------------------------------------------------------
RESULTS=$(results_dir)
mkdir -p "$RESULTS"
TAG=$(now_tag)
RESULT_PATH="$RESULTS/comparison_${TAG}.json"
JSONL_V15="$RESULTS/.partial_${TAG}_v15.jsonl"
JSONL_V16="$RESULTS/.partial_${TAG}_v16.jsonl"
WORK=$(mktemp -d)

log "mode=$MODE duration=${DURATION_SECS}s interval=${SAMPLE_INTERVAL_SEC}s"
log "v1.5 image: $V15_IMAGE (host port $V15_PORT)"
log "v1.6 image: $V16_IMAGE (host port $V16_PORT)"
log "result:     $RESULT_PATH"

V15_CONT=""; V16_CONT=""
V15_SUB_PID=""; V16_SUB_PID=""

cleanup() {
    log "cleaning up..."
    [ -n "$V15_SUB_PID" ] && stop_pid "$V15_SUB_PID"
    [ -n "$V16_SUB_PID" ] && stop_pid "$V16_SUB_PID"
    [ -n "$V15_CONT" ]    && stop_container "$V15_CONT"
    [ -n "$V16_CONT" ]    && stop_container "$V16_CONT"
    finalize
    rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

# --- Start containers ------------------------------------------------------
log "starting $V15_IMAGE as $V15_NAME on host port $V15_PORT..."
V15_CONT=$(start_container "$V15_IMAGE" "$V15_NAME" "$V15_PORT")
log "starting $V16_IMAGE as $V16_NAME on host port $V16_PORT..."
V16_CONT=$(start_container "$V16_IMAGE" "$V16_NAME" "$V16_PORT")

# Containers need a moment for the port forwarder + binary startup. The
# CT log list fetch can be slow on first run, so allow a generous timeout.
if ! wait_for_health "$HOST" "$V15_PORT" 120; then
    err "v1.5 container failed to come up"; dump_container_log "$V15_CONT"; exit 1
fi
if ! wait_for_health "$HOST" "$V16_PORT" 120; then
    err "v1.6 container failed to come up"; dump_container_log "$V16_CONT"; exit 1
fi
ok "both containers healthy"

# --- Optional: start subscribers (loaded mode only) ------------------------
if [ "$MODE" = "loaded" ]; then
    V15_URL="ws://${HOST}:${V15_PORT}${WS_PATH}"
    V16_URL="ws://${HOST}:${V16_PORT}${WS_PATH}"
    log "spawning $SUBSCRIBERS_PER_BINARY subs per container..."
    python3 "$SCRIPT_DIR/dummy_subscriber.py" \
        --url "$V15_URL" --count "$SUBSCRIBERS_PER_BINARY" \
        2> "$WORK/sub-v15.log" &
    V15_SUB_PID=$!
    python3 "$SCRIPT_DIR/dummy_subscriber.py" \
        --url "$V16_URL" --count "$SUBSCRIBERS_PER_BINARY" \
        2> "$WORK/sub-v16.log" &
    V16_SUB_PID=$!
    sleep 5
fi

# --- Sampling loop ---------------------------------------------------------
START_EPOCH=$(date +%s)
log "sampling for ${DURATION_SECS}s (Ctrl-C to stop early; partial results will be finalized)"

sample_once_docker() {
    local container=$1 jsonl=$2 elapsed=$3
    local rss cpu
    rss=$(sample_rss_kib_docker "$container" 2>/dev/null || echo 0)
    cpu=$(sample_cpu_pct_docker "$container" 2>/dev/null || echo 0)
    jsonl_append "$jsonl" "$(jq -nc \
        --argjson t "$elapsed" --argjson rss "$rss" --argjson cpu "$cpu" \
        '{t:$t, rss_kib:$rss, cpu_pct:$cpu}')"
}

format_last() {
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
        sample_once_docker "$V15_CONT" "$JSONL_V15" "$ELAPSED"
        sample_once_docker "$V16_CONT" "$JSONL_V16" "$ELAPSED"
        log "  t=${ELAPSED}s   v1.5: $(format_last "$JSONL_V15")   v1.6: $(format_last "$JSONL_V16")"
        NEXT_TS=$((NEXT_TS + SAMPLE_INTERVAL_SEC))
    fi
    sleep 1
done

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
          runtime: "docker",
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

finalize
