//! Library façade for the certstream-server-rust binary.
//!
//! The runtime entry point lives in `src/main.rs`. This file exposes the
//! parser/model surface needed by `fuzz/` targets and external integration
//! tests. Modules tagged `#[doc(hidden)]` are runtime internals — they're
//! declared here because the public modules reference them transitively, but
//! they're not part of the stable API.

pub mod ct;
pub mod models;

#[doc(hidden)]
pub mod api;
#[doc(hidden)]
pub mod config;
#[doc(hidden)]
pub mod dedup;
#[doc(hidden)]
pub mod state;
#[doc(hidden)]
pub mod websocket;
#[doc(hidden)]
pub mod middleware;
#[doc(hidden)]
pub mod hot_reload;
#[doc(hidden)]
pub mod rate_limit;
#[doc(hidden)]
pub mod sse;
