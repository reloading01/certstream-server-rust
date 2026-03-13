mod log_list;
mod parser;
pub mod static_ct;
pub mod watcher;

pub use log_list::*;
pub use parser::*;

use std::sync::atomic::Ordering;
use std::sync::Arc;
use tokio::sync::broadcast;
use tokio_util::sync::CancellationToken;

/// Per-operator rate limiter to avoid hitting CT log rate limits.
/// Wraps a tokio Interval so all watchers sharing it are serialized.
pub type OperatorRateLimiter = Arc<tokio::sync::Mutex<tokio::time::Interval>>;

use crate::api::{CachedCert, CertificateCache, LogTracker, ServerStats};
use crate::config::{CtLogConfig, StreamConfig};
use crate::dedup::DedupFilter;
use crate::models::{CertificateMessage, LeafCert, PreSerializedMessage};
use crate::state::StateManager;

/// Shared context for CT log watcher tasks.
#[derive(Clone)]
pub struct WatcherContext {
    pub client: reqwest::Client,
    pub tx: broadcast::Sender<Arc<PreSerializedMessage>>,
    pub config: Arc<CtLogConfig>,
    pub state_manager: Arc<StateManager>,
    pub cache: Arc<CertificateCache>,
    pub stats: Arc<ServerStats>,
    pub tracker: Arc<LogTracker>,
    pub shutdown: CancellationToken,
    pub dedup: Arc<DedupFilter>,
    pub rate_limiter: Option<OperatorRateLimiter>,
    pub streams: Arc<StreamConfig>,
}

/// Issue #2: Build a CachedCert sharing the Arc<LeafCert> — zero field clones.
pub fn build_cached_cert(
    leaf: Arc<LeafCert>,
    seen: f64,
    source_name: &str,
    source_url: &str,
    cert_index: u64,
) -> CachedCert {
    CachedCert {
        leaf,
        seen,
        source_name: source_name.to_string(),
        source_url: source_url.to_string(),
        cert_index,
    }
}

/// Serialize and broadcast a certificate message to all subscribers.
/// Issue #3: `messages_counter` is pre-registered outside the hot loop — no label allocation.
pub fn broadcast_cert(
    msg: CertificateMessage,
    tx: &broadcast::Sender<Arc<PreSerializedMessage>>,
    cache: &CertificateCache,
    cached: CachedCert,
    stats: &ServerStats,
    messages_counter: &metrics::Counter,
    streams: &StreamConfig,
) {
    cache.push(cached);
    if let Some(serialized) = msg.pre_serialize(streams) {
        let msg_size =
            serialized.full.len() + serialized.lite.len() + serialized.domains_only.len();
        let _ = tx.send(serialized);
        stats.messages_sent.fetch_add(1, Ordering::Relaxed);
        stats
            .certificates_processed
            .fetch_add(1, Ordering::Relaxed);
        stats
            .bytes_sent
            .fetch_add(msg_size as u64, Ordering::Relaxed);
        messages_counter.increment(1);
    }
}
