#!/usr/bin/env bash
# Run a single certstream-server binary for a configurable duration and
# sample VmRSS every N minutes. Writes a time-series CSV to
# benchmarks/results/soak_<timestamp>.csv that the summarize.sh script
# can read.
#
# Usage:
#   ./run_soak.sh --bin /path/to/certstream-server-rust --duration 24h
#
# Early exit (Ctrl-C / SIGTERM): the CSV is append-only and each row is a
# complete record, so killing the script at hour 6 leaves a valid 6-hour
# time-series on disk. The trap finalizes the metadata header and runs
# summarize.sh inline.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
. "$SCRIPT_DIR/lib.sh"

# --- Defaults --------------------------------------------------------------
BIN=""
DURATION="24h"
SAMPLE_INTERVAL_SEC=300        # 5 minutes
PORT=18080
HOST="127.0.0.1"
LABEL=""                        # informational tag, e.g. "v1.6.0-mimalloc"

usage() {
    cat <<EOF
Usage: $0 --bin PATH [options]

Options:
  --bin PATH             path to the binary under test (required)
  --duration DURATION    default: 24h    (suffixes: s/m/h, e.g. 90s, 30m, 24h)
  --sample-interval SECS default: 300 (= 5 min)
  --port PORT            default: 18080
  --label STRING         informational tag included in the CSV header
  -h, --help             show this help and exit

Output: benchmarks/results/soak_<UTC-timestamp>.csv (CSV with header)
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --bin)             BIN=$2; shift 2 ;;
        --duration)        DURATION=$2; shift 2 ;;
        --sample-interval) SAMPLE_INTERVAL_SEC=$2; shift 2 ;;
        --port)            PORT=$2; shift 2 ;;
        --label)           LABEL=$2; shift 2 ;;
        -h|--help)         usage; exit 0 ;;
        *)                 err "unknown arg: $1"; usage; exit 2 ;;
    esac
done

[ -z "$BIN" ] && { err "--bin is required"; exit 2; }
[ -x "$BIN" ] || { err "$BIN is not executable"; exit 2; }

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

require_cmds bash curl awk || exit 1

# --- Output paths ----------------------------------------------------------
RESULTS=$(results_dir)
mkdir -p "$RESULTS"
TAG=$(now_tag)
CSV_PATH="$RESULTS/soak_${TAG}.csv"
WORK=$(mktemp -d)
LOG_FILE="$WORK/binary.log"
# Binary runs cwd=$WORK so its relative default state_file lands inside the
# temp dir and gets cleaned up with the rest of WORK.

# --- Header ----------------------------------------------------------------
{
    echo "# kind=soak"
    echo "# binary=$BIN"
    echo "# label=$LABEL"
    echo "# started_at=$(now_iso)"
    echo "# target_duration_seconds=$DURATION_SECS"
    echo "# sample_interval_seconds=$SAMPLE_INTERVAL_SEC"
    echo "iso_timestamp,seconds_elapsed,rss_kib"
} > "$CSV_PATH"

log "binary:   $BIN"
log "duration: ${DURATION_SECS}s    interval: ${SAMPLE_INTERVAL_SEC}s"
log "output:   $CSV_PATH"

# --- Start binary ----------------------------------------------------------
PID=""
finalize() {
    [ -z "$PID" ] && return 0
    if kill -0 "$PID" 2>/dev/null; then
        log "stopping binary (pid=$PID)..."
        stop_pid "$PID"
    fi
    echo "# stopped_at=$(now_iso)" >> "$CSV_PATH"
    ok "soak data: $CSV_PATH"
    log "summary:"
    bash "$SCRIPT_DIR/summarize.sh" "$CSV_PATH" || true
    rm -rf "$WORK"
}
trap finalize EXIT INT TERM

(
    cd "$WORK" || exit 1
    CERTSTREAM_HOST="$HOST" \
    CERTSTREAM_PORT="$PORT" \
    CERTSTREAM_LOG_LEVEL="warn" \
    exec "$BIN" > "$LOG_FILE" 2>&1
) &
PID=$!

if ! wait_for_health "$HOST" "$PORT" 60; then
    err "binary failed to come up"
    tail -20 "$LOG_FILE" >&2
    exit 1
fi
ok "binary healthy (pid=$PID)"

# --- Sampling loop ---------------------------------------------------------
START_EPOCH=$(date +%s)
NEXT_TS=$START_EPOCH
while :; do
    NOW=$(date +%s)
    ELAPSED=$((NOW - START_EPOCH))
    [ "$ELAPSED" -ge "$DURATION_SECS" ] && break
    if ! kill -0 "$PID" 2>/dev/null; then
        err "binary died after ${ELAPSED}s — see $LOG_FILE"
        exit 1
    fi
    if [ "$NOW" -ge "$NEXT_TS" ]; then
        RSS=$(sample_rss_kib "$PID" 2>/dev/null || echo 0)
        printf '%s,%d,%d\n' "$(now_iso)" "$ELAPSED" "$RSS" >> "$CSV_PATH"
        # Compact progress line; full data is in the CSV.
        printf '%s  t=%6ds  rss=%8s MiB\n' \
            "$(date '+%H:%M:%S')" "$ELAPSED" \
            "$(awk -v k="$RSS" 'BEGIN { printf "%.1f", k/1024 }')" >&2
        NEXT_TS=$((NEXT_TS + SAMPLE_INTERVAL_SEC))
    fi
    sleep 5
done
