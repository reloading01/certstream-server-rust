#!/usr/bin/env bash
# Shared helpers for the benchmarks/ harness.
# Sourced by the run_*.sh / measure_*.sh / summarize.sh scripts.
# Pure POSIX-ish bash + standard /proc inspection. Python3 + websockets are
# only required by measure_latency.{sh,py} and dummy_subscriber.py.

set -uo pipefail

# Color helpers (auto-disabled when stdout is not a TTY).
if [ -t 1 ]; then
    C_BOLD=$'\033[1m'; C_RED=$'\033[31m'; C_GRN=$'\033[32m'; C_YEL=$'\033[33m'; C_DIM=$'\033[2m'; C_RST=$'\033[0m'
else
    C_BOLD=""; C_RED=""; C_GRN=""; C_YEL=""; C_DIM=""; C_RST=""
fi

log()  { printf '%s[%s]%s %s\n' "$C_DIM" "$(date '+%H:%M:%S')" "$C_RST" "$*" >&2; }
warn() { printf '%s[%s]%s %swarn:%s %s\n' "$C_DIM" "$(date '+%H:%M:%S')" "$C_RST" "$C_YEL" "$C_RST" "$*" >&2; }
err()  { printf '%s[%s]%s %serror:%s %s\n' "$C_DIM" "$(date '+%H:%M:%S')" "$C_RST" "$C_RED" "$C_RST" "$*" >&2; }
ok()   { printf '%s[%s]%s %sok:%s %s\n' "$C_DIM" "$(date '+%H:%M:%S')" "$C_RST" "$C_GRN" "$C_RST" "$*" >&2; }

# --- Dep checks ------------------------------------------------------------

# Verify every named command is on PATH; bail with a one-line install hint
# for the ones that are missing. Optional deps go through `optional_dep`.
require_cmds() {
    local missing=()
    for cmd in "$@"; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            missing+=("$cmd")
        fi
    done
    if [ ${#missing[@]} -gt 0 ]; then
        err "missing required commands: ${missing[*]}"
        err "  install hints:"
        for m in "${missing[@]}"; do
            case "$m" in
                jq)       err "    jq        : apt install jq      | brew install jq" ;;
                python3)  err "    python3   : apt install python3 | brew install python3" ;;
                curl)     err "    curl      : apt install curl    | brew install curl" ;;
                *)        err "    $m" ;;
            esac
        done
        return 1
    fi
}

# Optional deps: warn-and-continue. Return 0 if present, 1 if missing.
optional_dep() {
    local cmd=$1
    if command -v "$cmd" >/dev/null 2>&1; then return 0; fi
    return 1
}

# Verify python3 has the `websockets` module importable. Used by latency
# and dummy-subscriber scripts.
require_python_websockets() {
    if ! python3 -c 'import websockets' >/dev/null 2>&1; then
        err "python3 module 'websockets' missing"
        err "  install: python3 -m pip install --user websockets"
        return 1
    fi
}

# --- Sampling --------------------------------------------------------------

# Read VmRSS in KiB from /proc/<pid>/status. Returns 0 (and exits the
# function with status 1) if the process is gone — callers should treat
# that as a missing sample, not a hard error.
sample_rss_kib() {
    local pid=$1
    if [ ! -r "/proc/$pid/status" ]; then
        echo 0
        return 1
    fi
    awk '/^VmRSS:/ { print $2; exit }' "/proc/$pid/status"
}

# Time-averaged CPU% over a 1s window. Prefers pidstat (sysstat) when
# present because it handles the math identically across kernel versions;
# falls back to a /proc/<pid>/stat tick diff otherwise.
#
# Multi-core processes can legitimately exceed 100% — that's not a bug.
sample_cpu_pct() {
    local pid=$1
    if command -v pidstat >/dev/null 2>&1; then
        # pidstat -u: %CPU is the column right before Command.
        # The "Average:" row is what we want with a 1-sample run.
        local val
        val=$(pidstat -u -p "$pid" 1 1 2>/dev/null \
            | awk '/Average:/ && /[0-9]/ { for (i=NF; i>=1; i--) if ($i ~ /^[0-9.]+$/) { print $i; exit } }')
        echo "${val:-0}"
    else
        sample_cpu_proc_fallback "$pid"
    fi
}

# /proc/<pid>/stat fallback. Field 14 = utime, field 15 = stime, both in
# clock ticks. We diff over a 1s wall-clock window and convert via
# CLK_TCK (typically 100 Hz on Linux).
sample_cpu_proc_fallback() {
    local pid=$1
    local hertz
    hertz=$(getconf CLK_TCK 2>/dev/null || echo 100)
    if [ ! -r "/proc/$pid/stat" ]; then
        echo 0
        return 1
    fi
    local s1 t1 s2 t2
    s1=$(awk '{ print $14 + $15 }' "/proc/$pid/stat")
    t1=$(awk '{ print $1 }' /proc/uptime)
    sleep 1
    if [ ! -r "/proc/$pid/stat" ]; then
        echo 0
        return 1
    fi
    s2=$(awk '{ print $14 + $15 }' "/proc/$pid/stat")
    t2=$(awk '{ print $1 }' /proc/uptime)
    awk -v s1="$s1" -v s2="$s2" -v t1="$t1" -v t2="$t2" -v hertz="$hertz" '
        BEGIN {
            dt = t2 - t1
            if (dt <= 0) { print 0; exit }
            printf "%.2f\n", ((s2 - s1) / hertz / dt) * 100
        }'
}

# --- Process orchestration -------------------------------------------------

# Poll /health on the given port until it responds 200 or we time out.
# Default timeout is 30s — increase for cold-start scenarios where the CT
# log list fetch dominates startup.
wait_for_health() {
    local host=$1 port=$2 timeout=${3:-30}
    local elapsed=0
    while ! curl -sfm 1 "http://$host:$port/health" >/dev/null 2>&1; do
        elapsed=$((elapsed + 1))
        if [ "$elapsed" -ge "$timeout" ]; then
            err "$host:$port did not become healthy within ${timeout}s"
            return 1
        fi
        sleep 1
    done
    return 0
}

# Send SIGTERM, wait up to 10s for graceful exit, then SIGKILL.
stop_pid() {
    local pid=$1
    if [ -z "$pid" ] || ! kill -0 "$pid" 2>/dev/null; then return 0; fi
    kill -TERM "$pid" 2>/dev/null || true
    for _ in 1 2 3 4 5 6 7 8 9 10; do
        if ! kill -0 "$pid" 2>/dev/null; then return 0; fi
        sleep 1
    done
    kill -KILL "$pid" 2>/dev/null || true
}

# --- JSONL → final JSON helpers -------------------------------------------

# Append a JSON object (single line) to a JSONL file. Atomic w.r.t. line
# boundary because we redirect a single `printf` rather than building up.
jsonl_append() {
    local file=$1 obj=$2
    printf '%s\n' "$obj" >> "$file"
}

# Compute simple stats (n, mean, min, max) over a list of numbers piped on
# stdin. Used by summarize.sh and the comparison finalizer.
stats_summary() {
    awk '
        BEGIN { n = 0; sum = 0; mn = 1e300; mx = -1e300 }
        {
            v = $1 + 0
            n++; sum += v
            if (v < mn) mn = v
            if (v > mx) mx = v
        }
        END {
            if (n == 0) {
                printf "{\"n\":0,\"mean\":null,\"min\":null,\"max\":null}\n"
            } else {
                printf "{\"n\":%d,\"mean\":%.3f,\"min\":%.3f,\"max\":%.3f}\n",
                       n, sum / n, mn, mx
            }
        }'
}

# Default results directory (always relative to the harness root). Callers
# may override by exporting RESULTS_DIR.
results_dir() {
    local script_dir
    script_dir=$(cd "$(dirname "${BASH_SOURCE[1]}")" && pwd)
    echo "${RESULTS_DIR:-$script_dir/results}"
}

now_iso() { date -u +"%Y-%m-%dT%H:%M:%SZ"; }
now_tag() { date -u +"%Y%m%dT%H%M%SZ"; }
