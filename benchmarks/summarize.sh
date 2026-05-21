#!/usr/bin/env bash
# Read any benchmarks/results/ output file and emit a human-readable
# summary suitable for pasting into the RELEASE_NOTES.md performance
# table.
#
# Accepts:
#   comparison_*.json   — side-by-side v1.5 vs v1.6 with deltas
#   soak_*.csv          — 24h-style RSS time-series with drift verdict
#   latency_*.json      — p50/p95/p99 broadcast latency
#
# Usage:
#   ./summarize.sh <file>...
#   ./summarize.sh benchmarks/results/*
#
# Multiple files are processed in sequence; each gets its own block.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
. "$SCRIPT_DIR/lib.sh"

if [ $# -eq 0 ] || [ "$1" = "-h" ] || [ "$1" = "--help" ]; then
    cat <<EOF
Usage: $0 <result-file>...

Recognises comparison_*.json, soak_*.csv, and latency_*.json files in
benchmarks/results/. Output is plain text, paste-ready.

Examples:
  $0 results/comparison_20260521T120000Z.json
  $0 results/soak_20260521T120000Z.csv
  $0 results/*
EOF
    [ $# -eq 0 ] && exit 2 || exit 0
fi

require_cmds awk jq || exit 1

# --- Helpers ---------------------------------------------------------------

mib() { awk -v k="$1" 'BEGIN { if (k+0 == 0) print "?"; else printf "%.1f", k/1024 }'; }
fmt() { awk -v v="$1" -v fmt="${2:-%.1f}" 'BEGIN { if (v == "null" || v == "") print "?"; else printf fmt, v }'; }

summarize_comparison() {
    local path=$1
    local mode duration started subs
    mode=$(jq -r '.mode' "$path")
    duration=$(jq -r '.duration_seconds' "$path")
    started=$(jq -r '.started_at' "$path")
    subs=$(jq -r '.subscribers_per_binary' "$path")

    local v15_rss v16_rss v15_cpu v16_cpu v15_peak v16_peak
    v15_rss=$(jq -r '.v1_5.summary.avg_rss_mib' "$path")
    v16_rss=$(jq -r '.v1_6.summary.avg_rss_mib' "$path")
    v15_cpu=$(jq -r '.v1_5.summary.avg_cpu_pct' "$path")
    v16_cpu=$(jq -r '.v1_6.summary.avg_cpu_pct' "$path")
    v15_peak=$(jq -r '.v1_5.summary.peak_rss_mib' "$path")
    v16_peak=$(jq -r '.v1_6.summary.peak_rss_mib' "$path")

    local rss_change rss_pct cpu_change
    rss_change=$(jq -r '.deltas.rss_mib_change' "$path")
    rss_pct=$(jq -r '.deltas.rss_mib_pct' "$path")
    cpu_change=$(jq -r '.deltas.cpu_pct_change' "$path")

    cat <<EOF
${C_BOLD}=== comparison ($mode) ===${C_RST}
file:     $path
started:  $started
duration: ${duration}s    subscribers/binary: $subs

                   v1.5.x          v1.6.0
  avg RSS         $(fmt "$v15_rss") MiB     $(fmt "$v16_rss") MiB
  peak RSS        $(fmt "$v15_peak") MiB     $(fmt "$v16_peak") MiB
  avg CPU         $(fmt "$v15_cpu" "%.1f")%           $(fmt "$v16_cpu" "%.1f")%

  delta RSS       $(fmt "$rss_change" "%+.1f") MiB ($(fmt "$rss_pct" "%+.1f")%)
  delta CPU       $(fmt "$cpu_change" "%+.1f") pp

EOF
}

summarize_soak() {
    local path=$1
    awk -F',' '
        BEGIN { n = 0 }
        /^#/ {
            # metadata lines, keep verbatim
            print "  " $0
            next
        }
        /^iso_timestamp/ { next }
        NF >= 3 {
            t = $2 + 0
            rss = $3 + 0
            samples[n++] = rss
            ts[n-1] = t
            if (n == 1) { mn_rss = rss; mx_rss = rss; first_t = t }
            if (rss < mn_rss) mn_rss = rss
            if (rss > mx_rss) mx_rss = rss
            last_rss = rss
            last_t = t
        }
        END {
            if (n == 0) { print "  (no samples yet)"; exit }
            # Linear regression slope across samples (rss vs elapsed seconds)
            # gives MiB / hour drift (negative = trending down).
            sum_t = 0; sum_rss = 0
            for (i = 0; i < n; i++) { sum_t += ts[i]; sum_rss += samples[i] }
            mean_t = sum_t / n; mean_rss = sum_rss / n
            num = 0; den = 0
            for (i = 0; i < n; i++) {
                num += (ts[i] - mean_t) * (samples[i] - mean_rss)
                den += (ts[i] - mean_t) ^ 2
            }
            slope = (den > 0) ? num / den : 0
            slope_mib_per_hour = slope / 1024 * 3600

            print ""
            printf "  samples:        %d\n", n
            printf "  elapsed:        %.1fh\n", (last_t - first_t) / 3600
            printf "  first RSS:      %.1f MiB\n", samples[0] / 1024
            printf "  last  RSS:      %.1f MiB\n", last_rss / 1024
            printf "  min   RSS:      %.1f MiB\n", mn_rss / 1024
            printf "  max   RSS:      %.1f MiB\n", mx_rss / 1024
            printf "  drift:          %+.2f MiB/hour", slope_mib_per_hour
            # Verdict: flat = |slope| < 0.1 MiB/h; rising = > +0.5 MiB/h.
            verdict = "FLAT (pass)"
            if (slope_mib_per_hour > 0.5)  verdict = "RISING (investigate)"
            else if (slope_mib_per_hour > 0.1) verdict = "drifting up (borderline)"
            else if (slope_mib_per_hour < -0.5) verdict = "FALLING (allocator returning memory)"
            printf "   verdict: %s\n", verdict
        }
    ' "$path"
    echo ""
}

summarize_latency() {
    local path=$1
    local url duration samples n
    url=$(jq -r '.url' "$path")
    duration=$(jq -r '.duration_seconds' "$path")
    samples=$(jq -r '.samples' "$path")
    local p50 p95 p99 mn mx mean
    p50=$(jq -r '.p50_ms' "$path")
    p95=$(jq -r '.p95_ms' "$path")
    p99=$(jq -r '.p99_ms' "$path")
    mn=$(jq -r '.min_ms' "$path")
    mx=$(jq -r '.max_ms' "$path")
    mean=$(jq -r '.mean_ms' "$path")
    local dn dh dn_no
    dn=$(jq -r '.dropped_negative' "$path")
    dh=$(jq -r '.dropped_above_30s' "$path")
    dn_no=$(jq -r '.dropped_no_seen_field' "$path")
    cat <<EOF
${C_BOLD}=== latency ===${C_RST}
file:     $path
url:      $url
duration: ${duration}s   samples: $samples
  min:    $(fmt "$mn" "%.2f") ms
  mean:   $(fmt "$mean" "%.2f") ms
  p50:    $(fmt "$p50" "%.2f") ms
  p95:    $(fmt "$p95" "%.2f") ms
  p99:    $(fmt "$p99" "%.2f") ms
  max:    $(fmt "$mx" "%.2f") ms
  dropped: $dn negative, $dh >30s, $dn_no missing-seen

EOF
}

# --- Dispatch --------------------------------------------------------------

for f in "$@"; do
    if [ ! -r "$f" ]; then
        err "cannot read $f"
        continue
    fi
    case "$f" in
        *comparison_*.json) summarize_comparison "$f" ;;
        *soak_*.csv)        printf '%s=== soak ===%s\nfile: %s\n' "$C_BOLD" "$C_RST" "$f"; summarize_soak "$f" ;;
        *latency_*.json)    summarize_latency "$f" ;;
        *)
            # Best-effort: peek at content to decide.
            if head -c 1 "$f" | grep -q '{'; then
                if jq -e '.kind == "comparison"' "$f" >/dev/null 2>&1; then
                    summarize_comparison "$f"
                elif jq -e '.kind == "latency"' "$f" >/dev/null 2>&1; then
                    summarize_latency "$f"
                else
                    warn "unknown JSON shape: $f"
                fi
            elif head -1 "$f" | grep -q 'kind=soak'; then
                printf '%s=== soak ===%s\nfile: %s\n' "$C_BOLD" "$C_RST" "$f"
                summarize_soak "$f"
            else
                warn "unrecognised result file: $f"
            fi
            ;;
    esac
done
