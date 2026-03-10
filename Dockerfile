FROM rust:1.88-alpine AS builder

RUN apk add --no-cache musl-dev pkgconf openssl-dev openssl-libs-static

WORKDIR /app
COPY Cargo.toml Cargo.lock* ./
COPY src ./src

ENV OPENSSL_STATIC=1
RUN cargo build --release

FROM alpine:3.21

RUN apk add --no-cache ca-certificates curl

COPY --from=builder /app/target/release/certstream-server-rust /usr/local/bin/

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -sf http://localhost:8080/health/deep | grep -q '"status":"healthy"' || exit 1

CMD ["certstream-server-rust"]
