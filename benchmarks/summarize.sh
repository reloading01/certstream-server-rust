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
    local mode duration started subs interval
    mode=$(jq -r '.mode' "$path")
    duration=$(jq -r '.duration_seconds' "$path")
    started=$(jq -r '.started_at' "$path")
    subs=$(jq -r '.subscribers_per_binary' "$path")
    interval=$(jq -r '.sample_interval_seconds // 60' "$path")

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
duration: ${duration}s   interval: ${interval}s   subscribers/binary: $subs

                   v1.5.x          v1.6.0
  avg RSS         $(fmt "$v15_rss") MiB     $(fmt "$v16_rss") MiB
  peak RSS        $(fmt "$v15_peak") MiB     $(fmt "$v16_peak") MiB
  avg CPU         $(fmt "$v15_cpu" "%.1f")%           $(fmt "$v16_cpu" "%.1f")%

  delta RSS       $(fmt "$rss_change" "%+.1f") MiB ($(fmt "$rss_pct" "%+.1f")%)
  delta CPU       $(fmt "$cpu_change" "%+.1f") pp

EOF

    # ── Per-time-point drift curve + slope ─────────────────────────────────
    #
    # The whole point of a long side-by-side: see WHETHER v1.5.x drifts up
    # while v1.6.0 stays flat (validates the mimalloc story), or whether
    # both stay flat (mimalloc wasn't the differentiator).
    #
    # Aggregates collapse that signal. The table + slope estimates surface it.
    local merged
    merged=$(jq -c '
        # Zip the two sample arrays by index (they share the same t indices
        # because the harness samples them in lockstep each interval).
        .v1_5.samples as $a |
        .v1_6.samples as $b |
        [range(0; ([($a|length), ($b|length)]|min))]
          | map(. as $i | {
              t:       ($a[$i].t      // 0),
              v15_rss: ($a[$i].rss_kib // 0),
              v15_cpu: ($a[$i].cpu_pct // 0),
              v16_rss: ($b[$i].rss_kib // 0),
              v16_cpu: ($b[$i].cpu_pct // 0)
            })
    ' "$path" 2>/dev/null)

    if [ -z "$merged" ] || [ "$merged" = "[]" ] || [ "$merged" = "null" ]; then
        printf '  (no per-sample data in this result file)\n\n'
        return 0
    fi

    printf '%sdrift curve%s (rss in MiB, cpu in %%)\n\n' "$C_BOLD" "$C_RST"
    printf '  %-9s  %-13s  %-13s\n' "t" "v1.5.x" "v1.6.0"
    printf '  %-9s  %-13s  %-13s\n' "-------" "-------------" "-------------"
    echo "$merged" | jq -r '
        .[] | [
            (.t | tostring + "s"),
            ((.v15_rss / 1024) | tostring | .[0:6]) + " MiB " + ((.v15_cpu | tostring | .[0:5]) + "%"),
            ((.v16_rss / 1024) | tostring | .[0:6]) + " MiB " + ((.v16_cpu | tostring | .[0:5]) + "%")
        ] | @tsv
    ' | awk -F'\t' '{ printf "  %-9s  %-13s  %-13s\n", $1, $2, $3 }'

    # ── Slope (linear regression of rss_kib vs t_seconds) ──────────────────
    echo
    printf '%sslopes%s (linear regression of RSS over the full window)\n\n' \
        "$C_BOLD" "$C_RST"

    echo "$merged" | jq -r '
        # Extract two parallel series: t (seconds) and rss (kib), for each binary.
        [.[] | {t, v15_rss, v16_rss}]
          | { t:[.[].t], v15:[.[].v15_rss], v16:[.[].v16_rss] }
          | "\(.t|join(","))|\(.v15|join(","))|\(.v16|join(","))"
    ' | awk -F'|' '
        function slope_per_hour(t_csv, rss_csv,    n, i, ts, rs, sum_t, sum_r, mean_t, mean_r, num, den, s_kib_s) {
            n = split(t_csv, ts, ",")
            split(rss_csv, rs, ",")
            if (n < 2) return "n/a"
            sum_t = 0; sum_r = 0
            for (i = 1; i <= n; i++) { sum_t += ts[i]; sum_r += rs[i] }
            mean_t = sum_t / n; mean_r = sum_r / n
            num = 0; den = 0
            for (i = 1; i <= n; i++) {
                num += (ts[i] - mean_t) * (rs[i] - mean_r)
                den += (ts[i] - mean_t) ^ 2
            }
            if (den == 0) return "n/a"
            s_kib_s = num / den               # KiB per second
            return sprintf("%+.2f MiB/h", s_kib_s / 1024 * 3600)
        }
        function verdict(s,    v) {
            # Strip the unit so we can numeric-compare.
            v = s + 0
            if (s == "n/a") return ""
            if (v >  0.5)  return "RISING (investigate)"
            if (v >  0.1)  return "drifting up (borderline)"
            if (v < -0.5)  return "FALLING (allocator returning memory)"
            return "FLAT (pass)"
        }
        {
            v15 = slope_per_hour($1, $2)
            v16 = slope_per_hour($1, $3)
            printf "  v1.5.x:  %-14s   %s\n", v15, verdict(v15)
            printf "  v1.6.0:  %-14s   %s\n", v16, verdict(v16)
        }
    '
    echo
    # ── Joint verdict for the comparison thesis ────────────────────────────
    # Read both slopes back from the JSON one more time so the joint line
    # is computed in a single awk pass with consistent rounding.
    echo "$merged" | jq -r '
        [.[] | {t, v15_rss, v16_rss}]
          | { t:[.[].t], v15:[.[].v15_rss], v16:[.[].v16_rss] }
          | "\(.t|join(","))|\(.v15|join(","))|\(.v16|join(","))"
    ' | awk -F'|' '
        function slope_mh(t_csv, rss_csv,    n, i, ts, rs, sum_t, sum_r, mean_t, mean_r, num, den, s_kib_s) {
            n = split(t_csv, ts, ",")
            split(rss_csv, rs, ",")
            if (n < 2) return 0
            sum_t = 0; sum_r = 0
            for (i = 1; i <= n; i++) { sum_t += ts[i]; sum_r += rs[i] }
            mean_t = sum_t / n; mean_r = sum_r / n
            num = 0; den = 0
            for (i = 1; i <= n; i++) {
                num += (ts[i] - mean_t) * (rs[i] - mean_r)
                den += (ts[i] - mean_t) ^ 2
            }
            return (den == 0) ? 0 : num / den / 1024 * 3600
        }
        {
            v15 = slope_mh($1, $2); v16 = slope_mh($1, $3)
            printf "  joint:   "
            if (v15 > 0.5 && v16 < 0.1)
                printf "v1.5.x drifts up, v1.6.0 stays flat — mimalloc thesis VALIDATED\n"
            else if (v15 < 0.1 && v16 < 0.1)
                printf "both flat — mimalloc not the differentiator at this load/duration\n"
            else if (v15 > 0.5 && v16 > 0.5)
                printf "both drifting up — investigate independently of allocator choice\n"
            else
                printf "mixed signal — inspect the curve directly before drawing conclusions\n"
        }
    '
    echo
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
