# certstream-server-rust

A Certstream server written in Rust. It monitors Certificate Transparency (CT) logs and streams newly issued SSL/TLS certificates over WebSocket and Server-Sent Events (SSE).

[![GHCR](https://img.shields.io/badge/ghcr.io-reloading01%2Fcertstream--server--rust-blue?logo=github)](https://github.com/reloading01/certstream-server-rust/pkgs/container/certstream-server-rust)
[![Docker Hub](https://img.shields.io/badge/docker%20hub-reloading01%2Fcertstream--server--rust-blue?logo=docker)](https://hub.docker.com/r/reloading01/certstream-server-rust)
[![Rust](https://img.shields.io/badge/rust-edition%202024-orange.svg)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Sponsor](https://img.shields.io/badge/sponsor-%E2%9D%A4-ff69b4?logo=githubsponsors)](https://github.com/sponsors/reloading01)

## Overview

Certstream aggregates certificates from Certificate Transparency logs and streams them in real time. This implementation is compatible with existing Certstream clients and supports both RFC 6962 and static-CT logs.

Key features:

- WebSocket and SSE streaming
- Full, lite, and domains-only streams
- Chrome- and Apple-trusted CT log discovery
- Static-CT checkpoint and tile support
- Cross-log certificate deduplication
- Persistent CT log positions across restarts
- Per-IP connection and request limiting
- Bearer-token authentication
- Hot-reloadable configuration
- Circuit breakers and retry handling for CT logs
- Prometheus metrics and health endpoints
- Optional REST API with certificate lookup
- Pre-serialized broadcast payloads and SIMD JSON
- Single binary with no runtime dependencies

## Documentation

Full API documentation, client examples, configuration reference, and self-hosting notes are at [certstream.dev](https://certstream.dev/docs.html).

## Installation

Prebuilt Linux binaries are static musl builds. Release archives include SHA-256 checksums.

```bash
# Linux and macOS, x86_64 and arm64; verifies the checksum before installing
curl -fsSL https://raw.githubusercontent.com/reloading01/certstream-server-rust/main/install.sh | sh

# Homebrew
brew install reloading01/tap/certstream-server-rust

# Cargo
cargo install certstream-server-rust

# Docker
docker run -d -p 8080:8080 ghcr.io/reloading01/certstream-server-rust:latest
```

Signed apt and rpm repositories, Docker Compose, and installer options are covered in the [self-hosting docs](https://certstream.dev/docs.html#run-your-own-instance).

No configuration is required. The server discovers CT logs automatically, serves WebSocket on port `8080`, and persists its position so restarts resume instead of replaying log history.

## Configuration

All settings are optional. Environment variables override YAML values, and YAML values override built-in defaults. Every variable and YAML key is listed in the [configuration reference](https://certstream.dev/docs.html#environment-variables).

| Variable | Default | Description |
| --- | --- | --- |
| `CERTSTREAM_PORT` | `8080` | HTTP/WebSocket port |
| `CERTSTREAM_SSE_ENABLED` | `false` | Enable SSE |
| `CERTSTREAM_API_ENABLED` | `false` | Enable the REST API |
| `CERTSTREAM_AUTH_ENABLED` | `false` | Require bearer tokens (`CERTSTREAM_AUTH_TOKENS`) |
| `CERTSTREAM_CONNECTION_LIMIT_ENABLED` | `false` | Enable global and per-IP connection limits |
| `CERTSTREAM_CT_LOG_STATE_FILE` | `certstream_state.json` | CT log position file |

## Endpoints

| Endpoint | Stream |
| --- | --- |
| `ws://host:8080/` | Lite |
| `ws://host:8080/full-stream` | Full data with DER and chain |
| `ws://host:8080/domains-only` | Domain names only |
| `http://host:8080/sse` | SSE, when enabled (`?stream=full` or `?stream=domains`) |
| `/health`, `/health/deep`, `/metrics` | Health checks and Prometheus metrics |
| `/api/stats`, `/api/logs`, `/api/cert/{hash}` | REST API, when enabled |

Streaming endpoints accept `domain` and `issuer` query parameters for server-side filtering. See the [documentation](https://certstream.dev/docs.html) for message formats, version 2 output, and range export.

## Release notes

See [RELEASE_NOTES.md](RELEASE_NOTES.md) for version history.

## Contributing

Bug reports, CT log quirks, and pull requests are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for how to build, test, and send a change.

## Support

Starring the repository or sharing it helps the project get found. You can also [sponsor it on GitHub](https://github.com/sponsors/reloading01).

## License

MIT. See [LICENSE](LICENSE).
