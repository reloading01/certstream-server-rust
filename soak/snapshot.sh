#!/usr/bin/env bash
# Hourly soak snapshot — capture metrics, log tail, health, container stats.
# Output goes to soak-state/observations.md (append-only journal).
set -u
OUT=soak-state/observations.md
mkdir -p soak-state
ts=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
{
    echo
    echo "## $ts"
    echo
    if ! docker ps --format '{{.Names}}' | grep -q '^certstream-soak$'; then
        echo "❌ container NOT running"
        exit 0
    fi
    echo "### health"
    curl -s http://localhost:8080/health/deep | python3 -m json.tool 2>/dev/null | head -10
    echo
    echo "### container stats"
    docker stats --no-stream --format 'cpu={{.CPUPerc}} mem={{.MemUsage}} net={{.NetIO}} block={{.BlockIO}} pids={{.PIDs}}' certstream-soak
    echo
    echo "### healthcheck status"
    docker inspect certstream-soak --format '{{.State.Health.Status}} (failing={{.State.Health.FailingStreak}})'
    echo
    echo "### key metrics"
    curl -s http://localhost:8080/metrics \
        | grep -E '^certstream_(worker_panics|duplicates_filtered|dedup_cache_size|dedup_cache_clears|messages_sent_total|ws_connections_total|ws_messages_lagged|ws_disconnect_lag|connection_limit_rejected|per_ip_limit_rejected|static_ct_(tile_width_mismatch|tree_size_rollbacks|leaf_index_mismatch|checkpoint_errors)|log_health_checks_failed|issuer_cache_(hits|misses|size)) ' \
        | sort
    echo
    SENT=$(curl -s http://localhost:8080/metrics | grep -E '^certstream_messages_sent\{' | awk '{s+=$2} END {print s+0}')
    echo "### aggregate"
    echo "total messages_sent (sum over logs): $SENT"
    echo
    echo "### log scan (errors/warns/panics in last 5 min)"
    docker logs --since 5m certstream-soak 2>&1 | grep -iE 'panic|fatal|error' | head -20 || echo "(none)"
    echo
} >> "$OUT"
echo "snapshot appended to $OUT"
