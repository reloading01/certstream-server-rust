#!/usr/bin/env bash
# Shared helpers for the docker-based benchmark variants.
# Sourced after lib.sh. Provides docker-equivalents of sample_rss_kib /
# sample_cpu_pct / wait_for_health that target a running container.
#
# Sampling strategy: docker exec into the container and read /proc/1/* —
# the certstream binary is PID 1 inside the container, so VmRSS and the
# stat-tick CPU diff are byte-identical to the host-side measurements.
# Avoids parsing the human-formatted "178.4MiB" output of `docker stats`.

# Sample VmRSS (KiB) of PID 1 inside a container. Same semantics as
# lib.sh:sample_rss_kib but addresses a container instead of a host pid.
sample_rss_kib_docker() {
    local container=$1
    local out
    out=$(docker exec "$container" awk '/^VmRSS:/ { print $2; exit }' /proc/1/status 2>/dev/null)
    if [ -z "$out" ]; then
        echo 0
        return 1
    fi
    echo "$out"
}

# Time-averaged CPU% over a 1s window for PID 1 in the container.
# Pure /proc/<pid>/stat tick diff — pidstat isn't installed in the alpine
# runtime image and we don't want to bloat it just for benchmarking.
sample_cpu_pct_docker() {
    local container=$1
    # Single docker exec that captures (utime+stime, uptime) twice with a
    # 1s sleep between, then computes the percentage. Doing it in one
    # invocation avoids paying docker exec startup cost twice.
    docker exec "$container" sh -c '
        hertz=$(getconf CLK_TCK 2>/dev/null || echo 100)
        s1=$(awk "{ print \$14 + \$15 }" /proc/1/stat)
        t1=$(awk "{ print \$1 }" /proc/uptime)
        sleep 1
        s2=$(awk "{ print \$14 + \$15 }" /proc/1/stat)
        t2=$(awk "{ print \$1 }" /proc/uptime)
        awk -v s1="$s1" -v s2="$s2" -v t1="$t1" -v t2="$t2" -v hz="$hertz" "
            BEGIN {
                dt = t2 - t1
                if (dt <= 0) { print 0; exit }
                printf \"%.2f\n\", ((s2 - s1) / hz / dt) * 100
            }"
    ' 2>/dev/null || echo 0
}

# Poll /health via the host-side mapped port. Identical to wait_for_health
# in lib.sh — kept as a separate name only for symmetry with the other
# docker helpers.
wait_for_health_docker() {
    wait_for_health "$@"
}

# Start a container in detached mode, returning the container ID on stdout.
# Caller is responsible for cleanup. Port mapping is host:container —
# container always listens on 8080.
start_container() {
    local image=$1 name=$2 host_port=$3
    # Remove any stale container of the same name (defensive — should not
    # happen during a normal run, but interrupted prior runs can leave
    # stopped containers around).
    docker rm -f "$name" >/dev/null 2>&1 || true
    docker run -d \
        --name "$name" \
        -p "${host_port}:8080" \
        -e CERTSTREAM_LOG_LEVEL=warn \
        "$image" >/dev/null
    echo "$name"
}

# Stop and remove a container. Idempotent — safe to call on a name that
# never started or that already exited.
stop_container() {
    local container=$1
    [ -z "$container" ] && return 0
    docker stop -t 10 "$container" >/dev/null 2>&1 || true
    docker rm -f "$container" >/dev/null 2>&1 || true
}

# Dump the last 20 log lines from a container to stderr. Used on startup
# failure to surface the cause without spamming.
dump_container_log() {
    local container=$1
    docker logs --tail 20 "$container" 2>&1 | sed 's/^/  /' >&2
}
