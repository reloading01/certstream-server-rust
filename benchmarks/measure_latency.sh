#!/usr/bin/env bash
# Thin wrapper around measure_latency.py that handles dep-checks, output
# pathing, and SIGINT-safe early exit. The actual WS work + percentile
# math live in the Python helper.
#
# Usage:
#   ./measure_latency.sh --url ws://localhost:18080/full-stream --duration 30m
#
# Early exit: SIGINT/SIGTERM is forwarded to the Python process, which
# writes whatever samples it has into the output JSON before exiting 0.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
. "$SCRIPT_DIR/lib.sh"

URL=""
DURATION="30m"
OUTPUT=""

usage() {
    cat <<EOF
Usage: $0 --url WS_URL [options]

Options:
  --url URL              ws:// URL (required, e.g. ws://localhost:18080/full-stream)
  --duration DURATION    default: 30m   (suffixes: s/m/h)
  --output PATH          default: benchmarks/results/latency_<UTC-timestamp>.json
  -h, --help             show this help and exit

Output: JSON document with min/mean/p50/p95/p99/max latency in ms.
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --url)      URL=$2; shift 2 ;;
        --duration) DURATION=$2; shift 2 ;;
        --output)   OUTPUT=$2; shift 2 ;;
        -h|--help)  usage; exit 0 ;;
        *)          err "unknown arg: $1"; usage; exit 2 ;;
    esac
done

[ -z "$URL" ] && { err "--url is required"; exit 2; }

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

require_cmds python3 || exit 1
require_python_websockets || exit 1

RESULTS=$(results_dir)
mkdir -p "$RESULTS"
if [ -z "$OUTPUT" ]; then
    OUTPUT="$RESULTS/latency_$(now_tag).json"
fi

log "url:      $URL"
log "duration: ${DURATION_SECS}s"
log "output:   $OUTPUT"

# Forward signals to the Python process so its own SIGINT handler fires
# and writes the partial summary.
exec python3 "$SCRIPT_DIR/measure_latency.py" \
    --url "$URL" \
    --duration "$DURATION_SECS" \
    --output "$OUTPUT"
