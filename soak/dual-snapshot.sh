#!/usr/bin/env bash
# Hourly snapshot for the dual soak: capture per-container RSS, CPU, key
# metrics, log scan, healthcheck. Appends to soak-state/dual-observations.md.
set -u
PATH=/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin
OUT=soak-state/dual-observations.md
mkdir -p soak-state

ts=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
{
    echo
    echo "## $ts"
    echo
    for name in certstream-idle certstream-loaded; do
        port=$([[ "$name" == "certstream-idle" ]] && echo 18080 || echo 18081)
        if ! docker ps --format '{{.Names}}' | grep -q "^${name}$"; then
            echo "### $name (port $port) — NOT RUNNING"
            continue
        fi
        echo "### $name (port $port)"
        echo
        echo "**health/deep:**"
        curl -s "http://localhost:$port/health/deep" | python3 -m json.tool 2>/dev/null | head -10
        echo
        echo "**stats:** $(docker stats --no-stream --format 'cpu={{.CPUPerc}} mem={{.MemUsage}} net={{.NetIO}}' $name)"
        echo
        echo "**healthcheck:** $(docker inspect $name --format '{{.State.Health.Status}} (failing={{.State.Health.FailingStreak}})')"
        echo
        echo "**key metrics:**"
        curl -s "http://localhost:$port/metrics" \
            | grep -E '^certstream_(worker_panics|duplicates_filtered|dedup_cache_size|messages_sent_total|ws_connections_total|ws_messages_lagged|ws_disconnect_lag|ws_disconnect_write_timeout|connection_limit_rejected|log_health_checks_failed|static_ct_(checkpoint_errors|tree_size_rollbacks|leaf_index_mismatch|tile_width_mismatch|decompress_oversize)|rfc6962_tree_size_rollbacks|issuer_cache_(hits|misses|size)) ' \
            | sort
        SENT=$(curl -s "http://localhost:$port/metrics" | awk '/^certstream_messages_sent\{/{s+=$NF} END{print s+0}')
        WS=$(curl -s "http://localhost:$port/metrics" | awk '/^certstream_ws_connections_total /{print $2}')
        echo
        echo "**aggregate:** messages_sent=$SENT ws_connections=${WS:-0}"
        echo
        echo "**panic/fatal scan (last 1h):**"
        docker logs --since 1h "$name" 2>&1 | grep -iE 'panic|fatal|FATAL' | head -10 || echo "(none)"
        echo
    done
} >> "$OUT"
echo "snapshot appended to $OUT"
