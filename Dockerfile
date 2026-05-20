# syntax=docker/dockerfile:1.7
FROM rust:1.95-alpine AS builder
ARG TARGETPLATFORM

RUN apk add --no-cache musl-dev pkgconf openssl-dev openssl-libs-static

WORKDIR /app
COPY Cargo.toml Cargo.lock* ./
COPY src ./src

ENV OPENSSL_STATIC=1
# target-cpu=x86-64-v3 unlocks AVX2/BMI2 on Haswell+ / Zen+ hosts. Applied only
# to linux/amd64; arm64 builds use their default target-cpu.
#
# BuildKit cache mounts persist the cargo registry and target dir between
# builds. First build pays the full cost; rebuilds reuse compiled deps. The
# final binary is copied out before the cache mount is torn down at RUN-end.
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/app/target,sharing=locked \
    case "$TARGETPLATFORM" in \
      "linux/amd64"|"") export RUSTFLAGS="-C target-cpu=x86-64-v3" ;; \
    esac && \
    cargo build --release && \
    cp target/release/certstream-server-rust /usr/local/bin/certstream-server-rust

FROM alpine:3.21

RUN apk add --no-cache ca-certificates curl

COPY --from=builder /usr/local/bin/certstream-server-rust /usr/local/bin/

# jemalloc tuning. No-op under musl's default allocator; activates once the
# jemalloc feature ships in v1.6.0 PR2. Values follow database production
# norms: background_thread returns pages asynchronously, dirty/muzzy decay
# 5000ms (vs jemalloc default 10000ms) for an RSS-sensitive monitoring
# service, narenas:4 caps per-arena retention on high-core hosts.
ENV MALLOC_CONF=background_thread:true,dirty_decay_ms:5000,muzzy_decay_ms:5000,narenas:4

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -sf http://localhost:8080/health/deep | grep -q '"status":"healthy"' || exit 1

CMD ["certstream-server-rust"]
