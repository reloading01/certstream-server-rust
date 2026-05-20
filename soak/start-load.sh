#!/usr/bin/env bash
# Spawn the persistent 100-WS-client load against certstream-loaded.
# Self-restarts the client if it disconnects (Python WS client tends to drop
# after ~50s on macOS due to local socket pressure — restart loop keeps
# 100-ish clients live for the full soak duration).
set -u
PATH=/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin

PORT=${PORT:-18081}
CLIENTS=${CLIENTS:-100}
DURATION_PER_RUN=${DURATION_PER_RUN:-300}  # 5 min per client batch; restart automatically
TOTAL_SECONDS=${TOTAL_SECONDS:-43200}      # 12 h

LOG=/tmp/dual-soak-load.log
echo "=== load harness started at $(date -u +%Y-%m-%dT%H:%M:%SZ) ===" > "$LOG"

end=$(( $(date +%s) + TOTAL_SECONDS ))
i=0
while [[ $(date +%s) -lt $end ]]; do
    i=$((i+1))
    echo "--- batch $i @ $(date -u +%H:%M:%SZ) ---" >> "$LOG"
    python3 soak/ws-load.py --port "$PORT" --path / \
        --clients "$CLIENTS" --duration "$DURATION_PER_RUN" >> "$LOG" 2>&1 || true
done
echo "=== load harness done at $(date -u +%Y-%m-%dT%H:%M:%SZ) ===" >> "$LOG"
