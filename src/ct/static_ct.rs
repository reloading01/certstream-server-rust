use bytes::Bytes;
use moka::sync::Cache;
use flate2::read::GzDecoder;
use reqwest::Client;
use std::borrow::Cow;
use std::fmt::Write;
use std::io::Read;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, error, info, warn};

use super::watcher::LogHealth;
use super::{broadcast_cert, build_cached_cert, parse_certificate, CtLog, WatcherContext};
use crate::models::{CertificateData, CertificateMessage, ChainCert, Source};

/// A parsed static CT checkpoint.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct Checkpoint {
    pub origin: String,
    pub tree_size: u64,
    pub root_hash: String,
}

/// A single entry parsed from a tile/data tile.
#[derive(Debug)]
#[allow(dead_code)]
pub struct TileLeaf {
    pub timestamp: u64,
    pub entry_type: u16,
    pub cert_der: Vec<u8>,
    pub is_precert: bool,
    pub chain_fingerprints: Vec<[u8; 32]>,
}

const MAX_ISSUER_CACHE_SIZE: u64 = 10_000;

/// Concurrent LRU cache backed by `moka` — automatically evicts the least-recently-used
/// entry once `MAX_ISSUER_CACHE_SIZE` is reached, replacing the old DashMap that silently
/// dropped inserts when full.
pub struct IssuerCache {
    cache: Cache<[u8; 32], Bytes>,
}

impl IssuerCache {
    pub fn new() -> Self {
        Self {
            cache: Cache::builder()
                .max_capacity(MAX_ISSUER_CACHE_SIZE)
                .build(),
        }
    }

    pub fn get(&self, fingerprint: &[u8; 32]) -> Option<Bytes> {
        self.cache.get(fingerprint)
    }

    pub fn insert(&self, fingerprint: [u8; 32], data: Bytes) {
        self.cache.insert(fingerprint, data);
    }

    pub fn len(&self) -> usize {
        self.cache.run_pending_tasks();
        self.cache.entry_count() as usize
    }
}

impl Default for IssuerCache {
    fn default() -> Self {
        Self::new()
    }
}

/// Parse a checkpoint text response.
///
/// Format:
/// ```text
/// <origin>\n
/// <tree_size>\n
/// <base64_root_hash>\n
/// \n
/// — <signature line(s)>
/// ```
pub fn parse_checkpoint(text: &str, expected_origin: &str) -> Option<Checkpoint> {
    let lines: Vec<&str> = text.lines().collect();
    if lines.len() < 3 {
        return None;
    }

    let origin = lines[0].to_string();
    if origin != expected_origin {
        warn!(
            got = %origin,
            expected = %expected_origin,
            "checkpoint origin mismatch — possible misconfiguration or MITM"
        );
        return None;
    }

    let tree_size: u64 = lines[1].parse().ok()?;
    let root_hash = lines[2].to_string();

    Some(Checkpoint {
        origin,
        tree_size,
        root_hash,
    })
}

/// Encode a tile index into a hierarchical path (groups of 3 digits, "x" prefix for dirs).
///
/// Examples: 0→"000", 999→"999", 1234→"x001/234", 1234567→"x001/x234/567"
pub fn encode_tile_path(n: u64) -> String {
    if n < 1000 {
        return format!("{:03}", n);
    }

    // u64 max (~1.8e19) needs at most 7 groups of 3 digits — no heap alloc needed
    let mut groups = [0u16; 7];
    let mut count = 0;
    let mut remaining = n;
    while remaining > 0 {
        groups[count] = (remaining % 1000) as u16;
        count += 1;
        remaining /= 1000;
    }
    groups[..count].reverse();

    let mut result = String::with_capacity(count * 5);
    for (i, group) in groups.iter().enumerate().take(count) {
        if i > 0 {
            result.push('/');
        }
        if i < count - 1 {
            result.push('x');
        }
        let _ = write!(result, "{:03}", group);
    }

    result
}

/// Build the URL for a data tile fetch.
///
/// `tile_index` is the 0-based index of the 256-leaf tile.
/// `partial_width` is the number of leaves in a partial tile (0 means full 256-leaf tile).
///
/// Per the static-ct-api spec, data tile URLs do NOT include a level parameter:
/// `<prefix>/tile/data/<N>[.p/<W>]`
pub fn tile_url(base_url: &str, _level: u8, tile_index: u64, partial_width: u64) -> String {
    let base = base_url.trim_end_matches('/');
    let path = encode_tile_path(tile_index);
    if partial_width > 0 && partial_width < 256 {
        format!("{}/tile/data/{}.p/{}", base, path, partial_width)
    } else {
        format!("{}/tile/data/{}", base, path)
    }
}

/// Parse binary tile leaf entries. Each entry: 8B timestamp + 2B type (0=x509, 1=precert),
/// followed by type-specific cert data, extensions, and chain fingerprints.
pub fn parse_tile_leaves(data: &[u8]) -> Vec<TileLeaf> {
    let mut leaves = Vec::new();
    let mut offset = 0;

    while offset < data.len() {
        match parse_one_leaf(data, &mut offset) {
            Some(leaf) => leaves.push(leaf),
            None => break,
        }
    }

    leaves
}

fn parse_one_leaf(data: &[u8], offset: &mut usize) -> Option<TileLeaf> {
    // Need at least 10 bytes for timestamp + entry_type
    if *offset + 10 > data.len() {
        return None;
    }

    let timestamp = u64::from_be_bytes(data[*offset..*offset + 8].try_into().ok()?);
    *offset += 8;

    let entry_type = u16::from_be_bytes(data[*offset..*offset + 2].try_into().ok()?);
    *offset += 2;

    let is_precert = entry_type == 1;

    let cert_der;

    if entry_type == 0 {
        // x509 entry
        if *offset + 3 > data.len() {
            return None;
        }
        let cert_len = read_u24(data, *offset)?;
        *offset += 3;

        if *offset + cert_len > data.len() {
            return None;
        }
        cert_der = data[*offset..*offset + cert_len].to_vec();
        *offset += cert_len;
    } else if entry_type == 1 {
        if *offset + 32 > data.len() {
            return None;
        }
        *offset += 32; // issuer_key_hash

        if *offset + 3 > data.len() {
            return None;
        }
        let tbs_len = read_u24(data, *offset)?;
        *offset += 3;

        if *offset + tbs_len > data.len() {
            return None;
        }
        *offset += tbs_len;

        if *offset + 2 > data.len() {
            return None;
        }
        let ext_len = u16::from_be_bytes(data[*offset..*offset + 2].try_into().ok()?) as usize;
        *offset += 2;
        if *offset + ext_len > data.len() {
            return None;
        }
        *offset += ext_len;

        if *offset + 3 > data.len() {
            return None;
        }
        let precert_len = read_u24(data, *offset)?;
        *offset += 3;

        if *offset + precert_len > data.len() {
            return None;
        }
        cert_der = data[*offset..*offset + precert_len].to_vec();
        *offset += precert_len;

        if *offset + 2 > data.len() {
            return None;
        }
        let chain_count = u16::from_be_bytes(data[*offset..*offset + 2].try_into().ok()?) as usize;
        *offset += 2;

        let mut chain_fingerprints = Vec::with_capacity(chain_count);
        for _ in 0..chain_count {
            if *offset + 32 > data.len() {
                return None;
            }
            let mut fp = [0u8; 32];
            fp.copy_from_slice(&data[*offset..*offset + 32]);
            chain_fingerprints.push(fp);
            *offset += 32;
        }

        return Some(TileLeaf {
            timestamp,
            entry_type,
            cert_der,
            is_precert,
            chain_fingerprints,
        });
    } else {
        return None;
    }

    if *offset + 2 > data.len() {
        return None;
    }
    let ext_len = u16::from_be_bytes(data[*offset..*offset + 2].try_into().ok()?) as usize;
    *offset += 2;
    if *offset + ext_len > data.len() {
        return None;
    }
    *offset += ext_len;

    if *offset + 2 > data.len() {
        return None;
    }
    let chain_count = u16::from_be_bytes(data[*offset..*offset + 2].try_into().ok()?) as usize;
    *offset += 2;

    let mut chain_fingerprints = Vec::with_capacity(chain_count);
    for _ in 0..chain_count {
        if *offset + 32 > data.len() {
            return None;
        }
        let mut fp = [0u8; 32];
        fp.copy_from_slice(&data[*offset..*offset + 32]);
        chain_fingerprints.push(fp);
        *offset += 32;
    }

    Some(TileLeaf {
        timestamp,
        entry_type,
        cert_der,
        is_precert,
        chain_fingerprints,
    })
}

fn read_u24(data: &[u8], offset: usize) -> Option<usize> {
    if offset + 3 > data.len() {
        return None;
    }
    Some(u32::from_be_bytes([0, data[offset], data[offset + 1], data[offset + 2]]) as usize)
}

/// Format a 32-byte fingerprint as lowercase hex.
pub fn fingerprint_hex(fp: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for b in fp {
        let _ = write!(s, "{:02x}", b);
    }
    s
}

/// Issue #10: `fingerprint` is used directly as the cache key — no hex String on cache hit.
/// Only on a cache miss do we compute the hex string for the HTTP URL.
pub async fn fetch_issuer(
    client: &Client,
    base_url: &str,
    fingerprint: &[u8; 32],
    cache: &IssuerCache,
    timeout: Duration,
) -> Option<Bytes> {
    // Zero-alloc cache hit path: [u8; 32] key copied directly from stack.
    if let Some(cached) = cache.get(fingerprint) {
        metrics::counter!("certstream_issuer_cache_hits").increment(1);
        return Some(cached);
    }

    metrics::counter!("certstream_issuer_cache_misses").increment(1);

    // Cache miss: only now do we pay for the hex string (needed for the URL).
    let hex = fingerprint_hex(fingerprint);
    let base = base_url.trim_end_matches('/');
    let url = format!("{}/issuer/{}", base, hex);

    match client.get(&url).timeout(timeout).send().await {
        Ok(resp) if resp.status().is_success() => match resp.bytes().await {
            Ok(bytes) => {
                cache.insert(*fingerprint, bytes.clone());
                metrics::gauge!("certstream_issuer_cache_size").set(cache.len() as f64);
                Some(bytes)
            }
            Err(e) => {
                warn!(url = %url, error = %e, "failed to read issuer response body");
                None
            }
        },
        Ok(resp) => {
            debug!(url = %url, status = %resp.status(), "issuer fetch returned non-success");
            None
        }
        Err(e) => {
            debug!(url = %url, error = %e, "failed to fetch issuer");
            None
        }
    }
}

/// Decompress gzipped tile data. Returns borrowed data if not gzipped.
pub fn decompress_tile(data: &[u8]) -> Cow<'_, [u8]> {
    if data.len() >= 2 && data[0] == 0x1f && data[1] == 0x8b {
        let mut decoder = GzDecoder::new(data);
        let mut decompressed = Vec::new();
        match decoder.read_to_end(&mut decompressed) {
            Ok(_) => Cow::Owned(decompressed),
            Err(_) => Cow::Borrowed(data),
        }
    } else {
        Cow::Borrowed(data)
    }
}

/// Static CT (checkpoint + tile protocol) watcher loop.
#[allow(clippy::too_many_arguments)]
pub async fn run_static_ct_watcher(log: CtLog, ctx: WatcherContext) {
    let WatcherContext {
        client,
        tx,
        config,
        state_manager,
        cache,
        stats,
        tracker,
        shutdown,
        dedup,
        rate_limiter,
        streams,
    } = ctx;
    use tokio::time::sleep;

    let base_url = log.normalized_url();
    // Use the explicit `log_origin` from config when the fetch URL (e.g. mon.*) differs from
    // the origin embedded in the checkpoint (e.g. log.*). Fall back to deriving it from the URL.
    let expected_origin = log.log_origin.clone().unwrap_or_else(|| {
        base_url
            .trim_start_matches("https://")
            .trim_start_matches("http://")
            .trim_end_matches('/')
            .to_string()
    });
    let log_name = log.description.clone();
    let source = Arc::new(Source {
        name: Arc::from(log.description.as_str()),
        url: Arc::from(base_url.as_str()),
    });

    let health = Arc::new(LogHealth::new());
    let issuer_cache = Arc::new(IssuerCache::new());
    let poll_interval = Duration::from_millis(config.poll_interval_ms);
    let timeout = Duration::from_secs(config.request_timeout_secs);

    // Issue #3: Pre-register metric handles — no String allocation per certificate.
    let counter_tiles = metrics::counter!("certstream_static_ct_tiles_fetched", "log" => log_name.clone());
    let counter_parse_failures = metrics::counter!("certstream_static_ct_parse_failures", "log" => log_name.clone());
    let counter_entries_parsed = metrics::counter!("certstream_static_ct_entries_parsed", "log" => log_name.clone());
    let counter_messages = metrics::counter!("certstream_messages_sent", "log" => log_name.clone());

    info!(log = %log_name, url = %base_url, "starting static CT watcher");

    let checkpoint_url = format!("{}/checkpoint", base_url);

    let mut current_index = if let Some(saved_index) = state_manager.get_index(&base_url) {
        info!(log = %log.description, saved_index = saved_index, "resuming from saved state");
        saved_index
    } else {
        match client.get(&checkpoint_url).timeout(timeout).send().await {
            Ok(resp) => match resp.text().await {
                Ok(text) => match parse_checkpoint(&text, &expected_origin) {
                    Some(cp) => {
                        let start = cp.tree_size.saturating_sub(256);
                        info!(log = %log.description, tree_size = cp.tree_size, starting_at = start, "starting fresh (static CT)");
                        start
                    }
                    None => {
                        error!(log = %log.description, "failed to parse initial checkpoint, exiting watcher");
                        metrics::counter!("certstream_static_ct_checkpoint_errors").increment(1);
                        metrics::counter!("certstream_worker_init_failures").increment(1);
                        return;
                    }
                },
                Err(e) => {
                    error!(log = %log.description, error = %e, "failed to read initial checkpoint response, exiting watcher");
                    metrics::counter!("certstream_static_ct_checkpoint_errors").increment(1);
                    metrics::counter!("certstream_worker_init_failures").increment(1);
                    return;
                }
            },
            Err(e) => {
                error!(log = %log.description, error = %e, "failed to fetch initial checkpoint, exiting watcher");
                metrics::counter!("certstream_static_ct_checkpoint_errors").increment(1);
                metrics::counter!("certstream_worker_init_failures").increment(1);
                return;
            }
        }
    };

    loop {
        if shutdown.is_cancelled() {
            info!(log = %log.description, "shutdown signal received (static CT)");
            break;
        }

        if !health.should_attempt() {
            debug!(log = %log.description, "circuit breaker open, waiting (static CT)");
            sleep(Duration::from_secs(config.health_check_interval_secs)).await;
            continue;
        }

        // Unified checkpoint fetch — serves both the health-check path (when the log was
        // previously unhealthy) and the normal polling path in a single HTTP request,
        // eliminating the previous double-fetch on recovery.
        let was_unhealthy = !health.is_healthy();
        if was_unhealthy {
            warn!(log = %log.description, errors = health.total_errors(), "static CT log is unhealthy, waiting for recovery");
            sleep(Duration::from_secs(config.health_check_interval_secs)).await;
        }

        let tree_size = match client.get(&checkpoint_url).timeout(timeout).send().await {
            Ok(resp) => {
                let status = resp.status();
                if status.as_u16() == 429 {
                    let retry_after_ms = resp
                        .headers()
                        .get("retry-after")
                        .and_then(|v| v.to_str().ok())
                        .and_then(|s| s.parse::<u64>().ok())
                        .map(|secs| secs.saturating_mul(1_000))
                        .unwrap_or(LogHealth::RATE_LIMIT_BACKOFF_MS);
                    health.record_rate_limit_with_ms(config.unhealthy_threshold, retry_after_ms);
                    warn!(log = %log.description, retry_after_ms, "rate limited on checkpoint fetch, backing off");
                    metrics::counter!("certstream_static_ct_checkpoint_errors").increment(1);
                    sleep(health.get_backoff()).await;
                    continue;
                }
                if !status.is_success() {
                    if was_unhealthy {
                        metrics::counter!("certstream_log_health_checks_failed").increment(1);
                    }
                    health.record_failure(config.unhealthy_threshold);
                    warn!(log = %log.description, %status, "checkpoint fetch returned non-success");
                    metrics::counter!("certstream_static_ct_checkpoint_errors").increment(1);
                    sleep(health.get_backoff()).await;
                    continue;
                }
                match resp.text().await {
                    Ok(text) => match parse_checkpoint(&text, &expected_origin) {
                        Some(cp) => {
                            if was_unhealthy {
                                info!(log = %log.description, "health check passed (static CT), resuming");
                            }
                            health.record_success(config.healthy_threshold);
                            cp.tree_size
                        }
                        None => {
                            health.record_failure(config.unhealthy_threshold);
                            warn!(log = %log.description, "failed to parse checkpoint");
                            metrics::counter!("certstream_static_ct_checkpoint_errors").increment(1);
                            sleep(health.get_backoff()).await;
                            continue;
                        }
                    },
                    Err(e) => {
                        health.record_failure(config.unhealthy_threshold);
                        warn!(log = %log.description, error = %e, "failed to read checkpoint");
                        metrics::counter!("certstream_static_ct_checkpoint_errors").increment(1);
                        sleep(health.get_backoff()).await;
                        continue;
                    }
                }
            }
            Err(e) => {
                if was_unhealthy {
                    metrics::counter!("certstream_log_health_checks_failed").increment(1);
                }
                health.record_failure(config.unhealthy_threshold);
                warn!(log = %log.description, error = %e, "failed to fetch checkpoint");
                metrics::counter!("certstream_static_ct_checkpoint_errors").increment(1);
                sleep(health.get_backoff()).await;
                continue;
            }
        };

        if current_index >= tree_size {
            // Keep the tracker current even when fully caught up so that /api/logs
            // shows the correct index/tree_size instead of 0/0 after a restart.
            tracker.update(
                &base_url,
                health.status(),
                current_index,
                tree_size,
                health.total_errors(),
            );
            sleep(poll_interval).await;
            continue;
        }

        // Inner while loop: drain all available tiles before re-polling the checkpoint.
        // This replaces the original one-tile-per-checkpoint-fetch pattern, allowing
        // fast catch-up without repeatedly paying checkpoint fetch latency.
        'tile_loop: while current_index < tree_size {
            let tile_index = current_index / 256;
            let end_tile = (tree_size.saturating_sub(1)) / 256;

            let is_last_tile = tile_index == end_tile;
            let entries_in_tile = if is_last_tile {
                let remainder = tree_size % 256;
                if remainder == 0 { 256 } else { remainder }
            } else {
                256
            };

            let partial_width = if is_last_tile && entries_in_tile < 256 {
                entries_in_tile
            } else {
                0
            };

            let url = tile_url(&base_url, 0, tile_index, partial_width);

            // Respect per-operator rate limit before making request
            if let Some(ref limiter) = rate_limiter {
                limiter.lock().await.tick().await;
            }

            match client.get(&url).timeout(timeout).send().await {
                Ok(resp) => {
                    if !resp.status().is_success() {
                        let status = resp.status();
                        if status.as_u16() == 429 {
                            let retry_after_ms = resp
                                .headers()
                                .get("retry-after")
                                .and_then(|v| v.to_str().ok())
                                .and_then(|s| s.parse::<u64>().ok())
                                .map(|secs| secs.saturating_mul(1_000))
                                .unwrap_or(LogHealth::RATE_LIMIT_BACKOFF_MS);
                            health.record_rate_limit_with_ms(config.unhealthy_threshold, retry_after_ms);
                            warn!(log = %log.description, retry_after_ms, "rate limited by static CT log, backing off");
                        } else {
                            health.record_failure(config.unhealthy_threshold);
                            warn!(log = %log.description, url = %url, status = %status, "tile fetch failed");
                        }
                        sleep(health.get_backoff()).await;
                        break 'tile_loop;
                    }

                    match resp.bytes().await {
                        Ok(raw_data) => {
                            health.record_success(config.healthy_threshold);
                            counter_tiles.increment(1);

                            let data = decompress_tile(&raw_data);
                            let leaves = parse_tile_leaves(&data);

                            let tile_start_index = tile_index * 256;
                            let offset_in_tile = if current_index > tile_start_index {
                                (current_index - tile_start_index) as usize
                            } else {
                                0
                            };

                            // H-3 fix: collect all unique fingerprints across the tile slice and
                            // pre-warm the issuer cache with a single concurrent fetch round,
                            // replacing the original O(n*m) sequential-await pattern.
                            {
                                use std::collections::HashSet;
                                let unique_fps: HashSet<&[u8; 32]> = leaves
                                    .iter()
                                    .skip(offset_in_tile)
                                    .flat_map(|l| l.chain_fingerprints.iter())
                                    .collect();
                                if !unique_fps.is_empty() {
                                    let fetch_futs: Vec<_> = unique_fps
                                        .into_iter()
                                        .map(|fp| fetch_issuer(&client, &base_url, fp, &issuer_cache, timeout))
                                        .collect();
                                    futures::future::join_all(fetch_futs).await;
                                }
                            }

                            for (i, leaf) in leaves.iter().enumerate().skip(offset_in_tile) {
                                let cert_index = tile_start_index + i as u64;

                                let parsed = match parse_certificate(&leaf.cert_der, true) {
                                    Some(p) => p,
                                    None => {
                                        debug!(log = %log_name, index = cert_index, "skipped unparseable cert (static CT)");
                                        counter_parse_failures.increment(1);
                                        continue;
                                    }
                                };

                                counter_entries_parsed.increment(1);

                                if !dedup.is_new(&parsed.sha256_raw) {
                                    continue;
                                }

                                let seen = chrono::Utc::now().timestamp_millis() as f64 / 1000.0;
                                let mut chain = Vec::new();
                                for fp in &leaf.chain_fingerprints {
                                    if let Some(issuer_der) =
                                        fetch_issuer(&client, &base_url, fp, &issuer_cache, timeout)
                                            .await
                                        && let Some(issuer_cert) = parse_certificate(&issuer_der, false)
                                    {
                                        chain.push(ChainCert {
                                            subject: issuer_cert.subject,
                                            issuer: issuer_cert.issuer,
                                            serial_number: issuer_cert.serial_number,
                                            not_before: issuer_cert.not_before,
                                            not_after: issuer_cert.not_after,
                                            fingerprint: issuer_cert.fingerprint,
                                            sha1: issuer_cert.sha1,
                                            sha256: issuer_cert.sha256,
                                            signature_algorithm: issuer_cert.signature_algorithm,
                                            is_ca: issuer_cert.is_ca,
                                            as_der: issuer_cert.as_der,
                                            extensions: issuer_cert.extensions,
                                        });
                                    }
                                }

                                let update_type = if leaf.is_precert {
                                    Cow::Borrowed("PrecertLogEntry")
                                } else {
                                    Cow::Borrowed("X509LogEntry")
                                };

                                // Issue #2: wrap in Arc once; share between CachedCert and CertificateData.
                                let leaf_arc = Arc::new(parsed);
                                let cached = build_cached_cert(
                                    Arc::clone(&leaf_arc),
                                    seen,
                                    &log.description,
                                    &base_url,
                                    cert_index,
                                );
                                let cert_link = format!(
                                    "{}/tile/data/{}",
                                    base_url,
                                    encode_tile_path(tile_index)
                                );
                                let msg = CertificateMessage {
                                    message_type: Cow::Borrowed("certificate_update"),
                                    data: CertificateData {
                                        update_type,
                                        leaf_cert: leaf_arc,
                                        chain: if chain.is_empty() {
                                            None
                                        } else {
                                            Some(chain)
                                        },
                                        cert_index,
                                        cert_link,
                                        seen,
                                        source: Arc::clone(&source),
                                    },
                                };
                                broadcast_cert(msg, &tx, &cache, cached, &stats, &counter_messages, &streams);
                            }

                            let next_index = ((tile_index + 1) * 256).min(tree_size);
                            current_index = next_index;
                            state_manager.update_index(&base_url, current_index, tree_size);

                            tracker.update(
                                &base_url,
                                health.status(),
                                current_index,
                                tree_size,
                                health.total_errors(),
                            );

                            debug!(log = %log.description, tile = tile_index, leaves = leaves.len(), "processed static CT tile");
                        }
                        Err(e) => {
                            health.record_failure(config.unhealthy_threshold);
                            warn!(log = %log.description, error = %e, "failed to read tile response body");
                            sleep(health.get_backoff()).await;
                            break 'tile_loop;
                        }
                    }
                }
                Err(e) => {
                    health.record_failure(config.unhealthy_threshold);
                    warn!(log = %log.description, error = %e, "failed to fetch tile");
                    sleep(health.get_backoff()).await;
                    break 'tile_loop;
                }
            }
        }

        if current_index >= tree_size {
            sleep(poll_interval).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_checkpoint() {
        let text = "example.com/log\n12345\nABCDEF==\n\n— signature";
        let cp = parse_checkpoint(text, "example.com/log").unwrap();
        assert_eq!(cp.origin, "example.com/log");
        assert_eq!(cp.tree_size, 12345);
        assert_eq!(cp.root_hash, "ABCDEF==");
    }

    #[test]
    fn test_parse_checkpoint_invalid() {
        assert!(parse_checkpoint("too\nshort", "too").is_none());
        assert!(parse_checkpoint("origin\nnot_a_number\nhash", "origin").is_none());
    }

    #[test]
    fn test_parse_checkpoint_origin_mismatch() {
        let text = "actual.origin/log\n12345\nABCDEF==\n\n— signature";
        // Wrong expected origin must be rejected.
        assert!(parse_checkpoint(text, "expected.origin/log").is_none());
        // Exact match succeeds.
        assert!(parse_checkpoint(text, "actual.origin/log").is_some());
    }

    #[test]
    fn test_encode_tile_path() {
        assert_eq!(encode_tile_path(0), "000");
        assert_eq!(encode_tile_path(5), "005");
        assert_eq!(encode_tile_path(999), "999");
        assert_eq!(encode_tile_path(1000), "x001/000");
        assert_eq!(encode_tile_path(1234), "x001/234");
        assert_eq!(encode_tile_path(123456), "x123/456");
        assert_eq!(encode_tile_path(1234567), "x001/x234/567");
    }

    #[test]
    fn test_tile_url_full() {
        let url = tile_url("https://example.com/log/", 0, 5, 0);
        assert_eq!(url, "https://example.com/log/tile/data/005");
    }

    #[test]
    fn test_tile_url_partial() {
        let url = tile_url("https://example.com/log", 0, 5, 100);
        assert_eq!(url, "https://example.com/log/tile/data/005.p/100");
    }

    #[test]
    fn test_fingerprint_hex() {
        let fp = [0xab; 32];
        let hex = fingerprint_hex(&fp);
        assert_eq!(hex.len(), 64);
        assert!(hex.chars().all(|c| c == 'a' || c == 'b'));
    }

    #[test]
    fn test_decompress_tile_passthrough() {
        let data = b"not gzipped data";
        let result = decompress_tile(data);
        assert_eq!(&*result, &data[..]);
    }

    #[test]
    fn test_decompress_tile_gzip() {
        use flate2::write::GzEncoder;
        use flate2::Compression;
        use std::io::Write;

        let original = b"hello, this is tile data that should be compressed";
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(original).unwrap();
        let compressed = encoder.finish().unwrap();

        assert_eq!(compressed[0], 0x1f);
        assert_eq!(compressed[1], 0x8b);

        let decompressed = decompress_tile(&compressed);
        assert_eq!(&*decompressed, &original[..]);
    }

    #[test]
    fn test_decompress_tile_corrupt_gzip() {
        let data = vec![0x1f, 0x8b, 0x08, 0x00, 0xff, 0xff];
        let result = decompress_tile(&data);
        assert_eq!(&*result, &data[..]);
    }

    #[test]
    fn test_issuer_cache_new() {
        let cache = IssuerCache::new();
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn test_issuer_cache_insert_and_get() {
        let cache = IssuerCache::new();
        let data = Bytes::from(vec![1, 2, 3, 4]);
        let fp = [0xabu8; 32];

        cache.insert(fp, data.clone());
        assert_eq!(cache.len(), 1);

        let retrieved = cache.get(&fp).unwrap();
        assert_eq!(&retrieved[..], &[1, 2, 3, 4]);
    }

    #[test]
    fn test_issuer_cache_get_missing() {
        let cache = IssuerCache::new();
        assert!(cache.get(&[0u8; 32]).is_none());
    }

    #[test]
    fn test_issuer_cache_overwrite() {
        let cache = IssuerCache::new();
        let fp = [0x01u8; 32];
        cache.insert(fp, Bytes::from(vec![1, 2, 3]));
        cache.insert(fp, Bytes::from(vec![4, 5, 6]));
        assert_eq!(cache.len(), 1);
        assert_eq!(&cache.get(&fp).unwrap()[..], &[4, 5, 6]);
    }

    #[test]
    fn test_issuer_cache_multiple_entries() {
        let cache = IssuerCache::new();
        for i in 0u8..100 {
            let mut fp = [0u8; 32];
            fp[0] = i;
            cache.insert(fp, Bytes::from(vec![i]));
        }
        assert_eq!(cache.len(), 100);
        let fp0 = [0u8; 32];
        assert_eq!(&cache.get(&fp0).unwrap()[..], &[0]);
        let mut fp99 = [0u8; 32];
        fp99[0] = 99;
        assert_eq!(&cache.get(&fp99).unwrap()[..], &[99]);
    }

    /// Build a synthetic x509 tile entry.
    fn build_x509_entry(timestamp: u64, cert_der: &[u8], chain_fps: &[[u8; 32]]) -> Vec<u8> {
        let mut data = Vec::new();
        // 8 bytes timestamp
        data.extend_from_slice(&timestamp.to_be_bytes());
        // 2 bytes entry_type = 0 (x509)
        data.extend_from_slice(&0u16.to_be_bytes());
        // 3 bytes cert length
        let cert_len = cert_der.len() as u32;
        data.push((cert_len >> 16) as u8);
        data.push((cert_len >> 8) as u8);
        data.push(cert_len as u8);
        // cert DER
        data.extend_from_slice(cert_der);
        // 2 bytes extensions length = 0
        data.extend_from_slice(&0u16.to_be_bytes());
        // 2 bytes chain count
        data.extend_from_slice(&(chain_fps.len() as u16).to_be_bytes());
        // chain fingerprints
        for fp in chain_fps {
            data.extend_from_slice(fp);
        }
        data
    }

    /// Build a synthetic precert tile entry.
    fn build_precert_entry(
        timestamp: u64,
        issuer_key_hash: &[u8; 32],
        tbs_cert: &[u8],
        precert_der: &[u8],
        chain_fps: &[[u8; 32]],
    ) -> Vec<u8> {
        let mut data = Vec::new();
        // 8 bytes timestamp
        data.extend_from_slice(&timestamp.to_be_bytes());
        // 2 bytes entry_type = 1 (precert)
        data.extend_from_slice(&1u16.to_be_bytes());
        // 32 bytes issuer_key_hash
        data.extend_from_slice(issuer_key_hash);
        // 3 bytes TBS cert length
        let tbs_len = tbs_cert.len() as u32;
        data.push((tbs_len >> 16) as u8);
        data.push((tbs_len >> 8) as u8);
        data.push(tbs_len as u8);
        // TBS cert
        data.extend_from_slice(tbs_cert);
        // 2 bytes extensions length = 0
        data.extend_from_slice(&0u16.to_be_bytes());
        // 3 bytes pre-certificate DER length
        let precert_len = precert_der.len() as u32;
        data.push((precert_len >> 16) as u8);
        data.push((precert_len >> 8) as u8);
        data.push(precert_len as u8);
        // pre-certificate DER
        data.extend_from_slice(precert_der);
        // 2 bytes chain count
        data.extend_from_slice(&(chain_fps.len() as u16).to_be_bytes());
        // chain fingerprints
        for fp in chain_fps {
            data.extend_from_slice(fp);
        }
        data
    }

    #[test]
    fn test_parse_tile_leaves_single_x509() {
        let cert = b"fake_cert_der_data";
        let fp1 = [0xaa; 32];
        let data = build_x509_entry(1700000000000, cert, &[fp1]);

        let leaves = parse_tile_leaves(&data);
        assert_eq!(leaves.len(), 1);
        assert_eq!(leaves[0].timestamp, 1700000000000);
        assert_eq!(leaves[0].entry_type, 0);
        assert!(!leaves[0].is_precert);
        assert_eq!(leaves[0].cert_der, cert);
        assert_eq!(leaves[0].chain_fingerprints.len(), 1);
        assert_eq!(leaves[0].chain_fingerprints[0], fp1);
    }

    #[test]
    fn test_parse_tile_leaves_single_precert() {
        let issuer_hash = [0xbb; 32];
        let tbs = b"fake_tbs_cert";
        let precert = b"fake_precert_der";
        let fp1 = [0xcc; 32];
        let fp2 = [0xdd; 32];
        let data = build_precert_entry(1700000001000, &issuer_hash, tbs, precert, &[fp1, fp2]);

        let leaves = parse_tile_leaves(&data);
        assert_eq!(leaves.len(), 1);
        assert_eq!(leaves[0].timestamp, 1700000001000);
        assert_eq!(leaves[0].entry_type, 1);
        assert!(leaves[0].is_precert);
        assert_eq!(leaves[0].cert_der, precert);
        assert_eq!(leaves[0].chain_fingerprints.len(), 2);
        assert_eq!(leaves[0].chain_fingerprints[0], fp1);
        assert_eq!(leaves[0].chain_fingerprints[1], fp2);
    }

    #[test]
    fn test_parse_tile_leaves_multiple_entries() {
        let mut data = Vec::new();
        data.extend_from_slice(&build_x509_entry(1000, b"cert1", &[]));
        data.extend_from_slice(&build_x509_entry(2000, b"cert2", &[[0xee; 32]]));

        let issuer_hash = [0xff; 32];
        data.extend_from_slice(&build_precert_entry(3000, &issuer_hash, b"tbs", b"precert", &[]));

        let leaves = parse_tile_leaves(&data);
        assert_eq!(leaves.len(), 3);

        assert_eq!(leaves[0].timestamp, 1000);
        assert!(!leaves[0].is_precert);
        assert_eq!(leaves[0].cert_der, b"cert1");

        assert_eq!(leaves[1].timestamp, 2000);
        assert!(!leaves[1].is_precert);
        assert_eq!(leaves[1].cert_der, b"cert2");
        assert_eq!(leaves[1].chain_fingerprints.len(), 1);

        assert_eq!(leaves[2].timestamp, 3000);
        assert!(leaves[2].is_precert);
        assert_eq!(leaves[2].cert_der, b"precert");
    }

    #[test]
    fn test_parse_tile_leaves_empty() {
        let data: &[u8] = &[];
        let leaves = parse_tile_leaves(data);
        assert!(leaves.is_empty());
    }

    #[test]
    fn test_parse_tile_leaves_truncated() {
        // Only 5 bytes (needs at least 10 for timestamp + entry_type)
        let data = [0u8; 5];
        let leaves = parse_tile_leaves(&data);
        assert!(leaves.is_empty());
    }

    #[test]
    fn test_parse_tile_leaves_x509_no_chain() {
        let cert = b"test";
        let data = build_x509_entry(5000, cert, &[]);

        let leaves = parse_tile_leaves(&data);
        assert_eq!(leaves.len(), 1);
        assert!(leaves[0].chain_fingerprints.is_empty());
    }

    #[test]
    fn test_parse_tile_leaves_precert_no_chain() {
        let data = build_precert_entry(6000, &[0; 32], b"tbs", b"precert", &[]);
        let leaves = parse_tile_leaves(&data);
        assert_eq!(leaves.len(), 1);
        assert!(leaves[0].chain_fingerprints.is_empty());
    }

    #[test]
    fn test_read_u24() {
        assert_eq!(read_u24(&[0, 0, 5], 0), Some(5));
        assert_eq!(read_u24(&[0, 1, 0], 0), Some(256));
        assert_eq!(read_u24(&[1, 0, 0], 0), Some(65536));
        assert_eq!(read_u24(&[0xff, 0xff, 0xff], 0), Some(16777215));
        // With offset
        assert_eq!(read_u24(&[0x99, 0, 0, 10], 1), Some(10));
        // Too short
        assert_eq!(read_u24(&[0, 0], 0), None);
    }

    #[test]
    fn test_parse_checkpoint_large_tree_size() {
        let text = "origin\n999999999999\nhash\n\nsig";
        let cp = parse_checkpoint(text, "origin").unwrap();
        assert_eq!(cp.tree_size, 999999999999);
    }

    #[test]
    fn test_parse_checkpoint_zero_tree_size() {
        let text = "origin\n0\nhash";
        let cp = parse_checkpoint(text, "origin").unwrap();
        assert_eq!(cp.tree_size, 0);
    }

    #[test]
    fn test_parse_checkpoint_empty_string() {
        assert!(parse_checkpoint("", "origin").is_none());
    }

    #[test]
    fn test_tile_url_large_index() {
        let url = tile_url("https://example.com", 0, 1234567, 0);
        assert_eq!(url, "https://example.com/tile/data/x001/x234/567");
    }

    #[test]
    fn test_tile_url_full_256_is_not_partial() {
        // partial_width=256 should be treated as full tile
        let url = tile_url("https://example.com", 0, 0, 256);
        assert_eq!(url, "https://example.com/tile/data/000");
    }

    #[test]
    fn test_fingerprint_hex_zeros() {
        let fp = [0u8; 32];
        let hex = fingerprint_hex(&fp);
        assert_eq!(hex, "0000000000000000000000000000000000000000000000000000000000000000");
    }

    #[test]
    fn test_fingerprint_hex_all_ff() {
        let fp = [0xff; 32];
        let hex = fingerprint_hex(&fp);
        assert_eq!(hex, "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    }

    #[test]
    fn test_fingerprint_hex_mixed() {
        let mut fp = [0u8; 32];
        fp[0] = 0xde;
        fp[1] = 0xad;
        fp[2] = 0xbe;
        fp[3] = 0xef;
        let hex = fingerprint_hex(&fp);
        assert!(hex.starts_with("deadbeef"));
        assert_eq!(hex.len(), 64);
    }
}
