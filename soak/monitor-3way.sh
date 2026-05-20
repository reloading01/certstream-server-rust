#!/usr/bin/env bash
# 3-way an-be-an monitor (macOS bash 3.2-compatible):
#   - certstream-load    (Rust, 18080, IDLE — no WS clients)
#   - certstream-loaded  (Rust, 18081, LOADED — 100 WS clients)
#   - certstream-go      (Go,   18082, LOADED — 100 WS clients)
set -u
PATH=/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin
DURATION=${DURATION:-600}
INTERVAL=${INTERVAL:-5}

OUT=/tmp/realtime.tsv
echo -e "t\trust_idle_mem\trust_idle_cpu\trust_load_mem\trust_load_cpu\tgo_load_mem\tgo_load_cpu" > "$OUT"

# Peak trackers (plain vars, MiB stripped + as float)
PEAK_RIM=0; PEAK_RIC=0; PEAK_RLM=0; PEAK_RLC=0; PEAK_GLM=0; PEAK_GLC=0

# Parse MiB / GiB → MiB float
mem_to_mib() {
    local raw=$1
    if [[ $raw == *GiB ]]; then
        awk -v v="${raw%GiB}" 'BEGIN { printf "%.1f", v * 1024 }'
    elif [[ $raw == *MiB ]]; then
        echo "${raw%MiB}"
    else
        echo 0
    fi
}
strip_pct() { echo "${1%\%}"; }
max() { awk -v a="$1" -v b="$2" 'BEGIN { print (a+0 > b+0) ? a : b }'; }

START=$(date +%s)
printf "%-8s %-22s %-22s %-22s\n" "elapsed" "rust idle (18080)" "rust loaded (18081)" "go loaded (18082)"
printf "%-8s %-22s %-22s %-22s\n" "-------" "-----------------" "-------------------" "-----------------"

while [[ $(($(date +%s) - START)) -lt $DURATION ]]; do
    SAMPLE=$(docker stats --no-stream --format '{{.Name}}|{{.MemUsage}}|{{.CPUPerc}}' \
        certstream-load certstream-loaded certstream-go 2>/dev/null)

    R_I_M=$(echo "$SAMPLE" | awk -F'|' '$1=="certstream-load"  {print $2}' | awk -F' / ' '{print $1}')
    R_I_C=$(echo "$SAMPLE" | awk -F'|' '$1=="certstream-load"  {print $3}')
    R_L_M=$(echo "$SAMPLE" | awk -F'|' '$1=="certstream-loaded"{print $2}' | awk -F' / ' '{print $1}')
    R_L_C=$(echo "$SAMPLE" | awk -F'|' '$1=="certstream-loaded"{print $3}')
    G_L_M=$(echo "$SAMPLE" | awk -F'|' '$1=="certstream-go"    {print $2}' | awk -F' / ' '{print $1}')
    G_L_C=$(echo "$SAMPLE" | awk -F'|' '$1=="certstream-go"    {print $3}')

    PEAK_RIM=$(max "$(mem_to_mib "$R_I_M")" "$PEAK_RIM")
    PEAK_RIC=$(max "$(strip_pct "$R_I_C")"   "$PEAK_RIC")
    PEAK_RLM=$(max "$(mem_to_mib "$R_L_M")" "$PEAK_RLM")
    PEAK_RLC=$(max "$(strip_pct "$R_L_C")"   "$PEAK_RLC")
    PEAK_GLM=$(max "$(mem_to_mib "$G_L_M")" "$PEAK_GLM")
    PEAK_GLC=$(max "$(strip_pct "$G_L_C")"   "$PEAK_GLC")

    ELAPSED=$(($(date +%s) - START))
    printf "%-8s %-10s %-10s %-10s %-10s %-10s %-10s\n" \
        "T+${ELAPSED}s" "$R_I_M" "$R_I_C" "$R_L_M" "$R_L_C" "$G_L_M" "$G_L_C"

    echo -e "$ELAPSED\t$R_I_M\t$R_I_C\t$R_L_M\t$R_L_C\t$G_L_M\t$G_L_C" >> "$OUT"

    sleep $INTERVAL
done

echo
echo "=================================================="
echo "                  PEAKS (over ${DURATION}s)"
echo "=================================================="
printf "%-22s %-15s %-15s\n" "container" "peak mem (MiB)" "peak cpu (%)"
printf "%-22s %-15s %-15s\n" "------------------" "--------------" "------------"
printf "%-22s %-15s %-15s\n" "rust  idle  (18080)" "$PEAK_RIM" "$PEAK_RIC"
printf "%-22s %-15s %-15s\n" "rust  loaded(18081)" "$PEAK_RLM" "$PEAK_RLC"
printf "%-22s %-15s %-15s\n" "go    loaded(18082)" "$PEAK_GLM" "$PEAK_GLC"
echo
echo "Raw TSV: $OUT  ($(wc -l < $OUT) samples)"
