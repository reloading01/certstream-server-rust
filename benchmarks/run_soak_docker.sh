#!/usr/bin/env bash
# Docker variant of run_soak.sh. Long-running single-container RSS sampler
# for drift analysis. CSV format is identical to the host-binary variant.
#
# Usage:
#   ./run_soak_docker.sh --image certstream:v1.6.0 --duration 24h \
#                        --label "v1.6.0-mimalloc"
#
# macOS Docker Desktop caveat applies — see run_comparison_docker.sh.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
. "$SCRIPT_DIR/lib.sh"
# shellcheck source=lib_docker.sh
. "$SCRIPT_DIR/lib_docker.sh"

IMAGE=""
DURATION="24h"
SAMPLE_INTERVAL_SEC=300
PORT=18080
HOST="127.0.0.1"
LABEL=""
CONTAINER_NAME="certstream-bench-soak"

usage() {
    cat <<EOF
Usage: $0 --image IMAGE [options]

Options:
  --image IMAGE          docker image under test (required)
  --duration DURATION    default: 24h    (suffixes: s/m/h)
  --sample-interval SECS default: 300 (= 5 min)
  --port PORT            host-side port mapped to the container. default: 18080
  --label STRING         informational tag included in the CSV header
  -h, --help             show this help and exit

Output: benchmarks/results/soak_<UTC-timestamp>.csv
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --image)           IMAGE=$2; shift 2 ;;
        --duration)        DURATION=$2; shift 2 ;;
        --sample-interval) SAMPLE_INTERVAL_SEC=$2; shift 2 ;;
        --port)            PORT=$2; shift 2 ;;
        --label)           LABEL=$2; shift 2 ;;
        -h|--help)         usage; exit 0 ;;
        *)                 err "unknown arg: $1"; usage; exit 2 ;;
    esac
done

[ -z "$IMAGE" ] && { err "--image is required"; exit 2; }

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

require_cmds bash curl awk docker || exit 1
if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    err "docker image not found locally: $IMAGE"
    exit 1
fi

RESULTS=$(results_dir)
mkdir -p "$RESULTS"
TAG=$(now_tag)
CSV_PATH="$RESULTS/soak_${TAG}.csv"

{
    echo "# kind=soak"
    echo "# runtime=docker"
    echo "# image=$IMAGE"
    echo "# label=$LABEL"
    echo "# started_at=$(now_iso)"
    echo "# target_duration_seconds=$DURATION_SECS"
    echo "# sample_interval_seconds=$SAMPLE_INTERVAL_SEC"
    echo "iso_timestamp,seconds_elapsed,rss_kib"
} > "$CSV_PATH"

log "image:    $IMAGE"
log "duration: ${DURATION_SECS}s    interval: ${SAMPLE_INTERVAL_SEC}s"
log "output:   $CSV_PATH"

CONT=""
finalize() {
    [ -z "$CONT" ] && return 0
    if docker ps --filter "name=^${CONTAINER_NAME}$" --format '{{.ID}}' | grep -q .; then
        log "stopping container..."
        stop_container "$CONT"
    fi
    echo "# stopped_at=$(now_iso)" >> "$CSV_PATH"
    ok "soak data: $CSV_PATH"
    log "summary:"
    bash "$SCRIPT_DIR/summarize.sh" "$CSV_PATH" || true
}
trap finalize EXIT INT TERM

CONT=$(start_container "$IMAGE" "$CONTAINER_NAME" "$PORT")
if ! wait_for_health "$HOST" "$PORT" 120; then
    err "container failed to come up"
    dump_container_log "$CONT"
    exit 1
fi
ok "container healthy"

START_EPOCH=$(date +%s)
NEXT_TS=$START_EPOCH
while :; do
    NOW=$(date +%s)
    ELAPSED=$((NOW - START_EPOCH))
    [ "$ELAPSED" -ge "$DURATION_SECS" ] && break
    if ! docker ps --filter "name=^${CONTAINER_NAME}$" --format '{{.ID}}' | grep -q .; then
        err "container died after ${ELAPSED}s"
        docker logs --tail 30 "$CONT" 2>&1 | sed 's/^/  /' >&2
        exit 1
    fi
    if [ "$NOW" -ge "$NEXT_TS" ]; then
        RSS=$(sample_rss_kib_docker "$CONT" 2>/dev/null || echo 0)
        printf '%s,%d,%d\n' "$(now_iso)" "$ELAPSED" "$RSS" >> "$CSV_PATH"
        printf '%s  t=%6ds  rss=%8s MiB\n' \
            "$(date '+%H:%M:%S')" "$ELAPSED" \
            "$(awk -v k="$RSS" 'BEGIN { printf "%.1f", k/1024 }')" >&2
        NEXT_TS=$((NEXT_TS + SAMPLE_INTERVAL_SEC))
    fi
    sleep 5
done
