use base64::{Engine, engine::general_purpose::STANDARD};
use bytes::Bytes;
use flate2::read::GzDecoder;
use p256::ecdsa::VerifyingKey as EcdsaVerifyingKey;
use p256::pkcs8::DecodePublicKey;
use quick_cache::sync::Cache;
use reqwest::Client;
use signed_note::{Note, Verifier as NoteVerifier, VerifierList};
use static_ct_api::RFC6962Verifier;
use std::borrow::Cow;
use std::fmt::Write;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, error, info, warn};

use super::watcher::LogHealth;
use super::{
    CtLog, ParseOptions, WatcherContext, broadcast_cert, build_cached_cert,
    parse_certificate_with_options,
};
use crate::config::CheckpointSignatureMode;
use crate::models::{CertificateData, CertificateMessage, ChainCert, Source};

/// A parsed static CT checkpoint.
///
/// `origin` and `root_hash` are populated by the parser and asserted in tests.
/// Production consumes only `tree_size` for catch-up; signature verification
/// re-parses the raw checkpoint text through the signed-note verifier (see
/// `verify_checkpoint_signature`) rather than these fields, so `origin` and
/// `root_hash` are retained for tests and forensics but unused at runtime.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct Checkpoint {
    pub origin: String,
    pub tree_size: u64,
    pub root_hash: String,
}

/// A single entry parsed from a tile/data tile.
///
/// `entry_type` (0=x509, 1=precert) is the raw wire value. Hot path uses the
/// derived `is_precert` boolean, but `entry_type` is exposed so callers /
/// tests can detect spec-forward values (>1) the day the static-ct-api adds
/// new entry kinds, without a parser change.
#[derive(Debug)]
#[allow(dead_code)]
pub struct TileLeaf {
    pub submission_timestamp: u64,
    pub entry_type: u16,
    /// Zero-copy slice of the shared decompressed tile buffer. Pre-1.5.3 this
    /// was a per-leaf `Vec<u8>` copy — 256 allocations + ~2-3 MiB of memcpy
    /// per tile.
    pub cert_der: Bytes,
    pub is_precert: bool,
    pub chain_fingerprints: Vec<[u8; 32]>,
    /// `leaf_index` extension from `CtExtensions` (static-ct-api v1.0.0-rc.1).
    /// 0-based log index of this entry. `None` if the log hasn't populated the
    /// extension yet (older logs / draft conformance). When present, it must
    /// match `tile_start_index + offset_in_tile`; a mismatch is logged as an
    /// integrity warning.
    pub leaf_index: Option<u64>,
}

/// Parse a `CtExtensions` blob and return the `leaf_index` value (extension
/// type 0, big-endian unsigned 40-bit) when present. The extensions vector is
/// `Extension*` where each `Extension` is `1B type + 2B len + len bytes data`.
/// Unknown extensions are skipped to remain forward-compatible.
fn parse_leaf_index_ext(ext_bytes: &[u8]) -> Option<u64> {
    let mut i = 0;
    while i + 3 <= ext_bytes.len() {
        let ext_type = ext_bytes[i];
        let data_len = u16::from_be_bytes([ext_bytes[i + 1], ext_bytes[i + 2]]) as usize;
        i += 3;
        if i + data_len > ext_bytes.len() {
            return None;
        }
        if ext_type == 0 && data_len == 5 {
            // 40-bit big-endian unsigned integer
            let mut acc: u64 = 0;
            for &b in &ext_bytes[i..i + 5] {
                acc = (acc << 8) | b as u64;
            }
            return Some(acc);
        }
        i += data_len;
    }
    None
}

const MAX_ISSUER_CACHE_SIZE: usize = 10_000;

/// Concurrent bounded cache for chain-issuer certs. Switched from `moka`
/// to `quick_cache` in v1.6.0: identical get/insert semantics for our use
/// case (bounded fingerprint → issuer map), but ~100B/entry less overhead and
/// no async housekeeping task — eviction is synchronous on insert, so
/// `len()` is accurate without a `run_pending_tasks` round-trip.
///
/// Values are **parsed** `Arc<ChainCert>`s, not raw DER. A tile of 256 leaves
/// typically chains to a handful of shared intermediates; caching the parse
/// result turns the per-leaf chain build into an Arc clone instead of a full
/// X.509 parse + SHA-1/SHA-256 of the same DER thousands of times.
///
/// A stored `None` is a negative entry: the endpoint served the blob but it
/// failed to parse. Caching that verdict stops every subsequent tile from
/// re-fetching a deterministically broken issuer over the network.
pub struct IssuerCache {
    cache: Cache<[u8; 32], Option<Arc<ChainCert>>>,
}

impl IssuerCache {
    pub fn new() -> Self {
        Self {
            cache: Cache::new(MAX_ISSUER_CACHE_SIZE),
        }
    }

    /// Outer `None` = never fetched (caller should fetch); `Some(None)` =
    /// fetched but unparseable (negative-cached, skip).
    pub fn get(&self, fingerprint: &[u8; 32]) -> Option<Option<Arc<ChainCert>>> {
        self.cache.get(fingerprint)
    }

    pub fn insert(&self, fingerprint: [u8; 32], cert: Arc<ChainCert>) {
        self.cache.insert(fingerprint, Some(cert));
    }

    pub fn insert_unparseable(&self, fingerprint: [u8; 32]) {
        self.cache.insert(fingerprint, None);
    }

    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn len(&self) -> usize {
        self.cache.len()
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

/// Outcome of verifying the log's signature on a static-CT checkpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SigCheck {
    /// The log's signature is present and cryptographically valid.
    Verified,
    /// A usable key was available but the checkpoint carries no valid signature
    /// under it (missing or cryptographically wrong). The strong failure signal;
    /// rejected in `enforce` mode.
    Failed(&'static str),
    /// No cryptographic check was possible (no key in the list, a non-ECDSA-P256
    /// key, or a malformed key/origin). Never rejects — inability to verify is
    /// not proof of forgery.
    Unverifiable(&'static str),
}

/// Verify the RFC 6962 `TreeHeadSignature` a static-CT log embeds in its
/// checkpoint (signed-note signature type `0x05`, ECDSA P-256), per
/// c2sp.org/static-ct-api.
///
/// `key_b64` is the base64 SubjectPublicKeyInfo (DER) from the CT log list.
/// Only ECDSA P-256 log keys can be verified; RSA / P-384 logs yield
/// `Unverifiable` (the underlying verifier supports only ECDSA-SHA256).
pub fn verify_checkpoint_signature(
    checkpoint_text: &str,
    expected_origin: &str,
    key_b64: Option<&str>,
) -> SigCheck {
    let Some(key_b64) = key_b64 else {
        return SigCheck::Unverifiable("no log key in list");
    };
    let Ok(der) = STANDARD.decode(key_b64) else {
        return SigCheck::Unverifiable("log key not valid base64");
    };
    let Ok(vkey) = EcdsaVerifyingKey::from_public_key_der(&der) else {
        return SigCheck::Unverifiable("log key not ECDSA P-256 SPKI");
    };
    let Ok(verifier) = RFC6962Verifier::new(expected_origin, &vkey) else {
        return SigCheck::Unverifiable("verifier init failed");
    };
    let Ok(note) = Note::from_bytes(checkpoint_text.as_bytes()) else {
        // parse_checkpoint already validated the checkpoint body, so a signed-note
        // parse mismatch is a format quirk, not proof of forgery — don't reject.
        return SigCheck::Unverifiable("could not parse signed note");
    };
    // A single-verifier list: `verify` returns Ok only when our key signed and
    // the signature verified; a present-but-wrong signature under our key is an
    // Err, and our key being absent entirely is an Err too. Both are failures.
    let verifiers: VerifierList =
        VerifierList::new(vec![Box::new(verifier) as Box<dyn NoteVerifier>]);
    match note.verify(&verifiers) {
        Ok((verified, _)) if !verified.is_empty() => SigCheck::Verified,
        Ok(_) => SigCheck::Failed("log signature not present"),
        Err(_) => SigCheck::Failed("log signature invalid"),
    }
}

/// Apply the configured checkpoint-signature policy after a checkpoint parses.
/// Returns `true` if the checkpoint should be accepted; only `enforce` mode on
/// a `Failed` outcome returns `false`.
#[allow(clippy::too_many_arguments)]
fn accept_checkpoint_signature(
    checkpoint_text: &str,
    expected_origin: &str,
    key_b64: Option<&str>,
    mode: CheckpointSignatureMode,
    log_desc: &str,
    log_name: &str,
    source_id: &str,
) -> bool {
    match verify_checkpoint_signature(checkpoint_text, expected_origin, key_b64) {
        SigCheck::Verified => {
            metrics::counter!(
                "certstream_static_ct_checkpoint_sig_verified",
                "log" => log_name.to_string(),
                "source_id" => source_id.to_string()
            )
            .increment(1);
            true
        }
        SigCheck::Unverifiable(reason) => {
            metrics::counter!(
                "certstream_static_ct_checkpoint_sig_unverifiable",
                "log" => log_name.to_string(),
                "source_id" => source_id.to_string()
            )
            .increment(1);
            debug!(log = %log_desc, reason, "checkpoint signature not verifiable; accepting");
            true
        }
        SigCheck::Failed(reason) => {
            metrics::counter!(
                "certstream_static_ct_checkpoint_sig_failed",
                "log" => log_name.to_string(),
                "source_id" => source_id.to_string()
            )
            .increment(1);
            match mode {
                CheckpointSignatureMode::Enforce => {
                    warn!(log = %log_desc, reason, "checkpoint signature verification failed; rejecting (enforce mode)");
                    false
                }
                CheckpointSignatureMode::Warn => {
                    warn!(log = %log_desc, reason, "checkpoint signature verification failed; accepting (warn mode)");
                    true
                }
            }
        }
    }
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
///
/// Takes the buffer as `Bytes` so each leaf's `cert_der` is a refcounted
/// sub-slice of it instead of an owned copy.
pub fn parse_tile_leaves(data: Bytes) -> Vec<TileLeaf> {
    let mut leaves = Vec::new();
    let mut offset = 0;

    while offset < data.len() {
        match parse_one_leaf(&data, &mut offset) {
            Some(leaf) => leaves.push(leaf),
            None => break,
        }
    }

    leaves
}

fn parse_one_leaf(data: &Bytes, offset: &mut usize) -> Option<TileLeaf> {
    // Need at least 10 bytes for timestamp + entry_type
    if *offset + 10 > data.len() {
        return None;
    }

    let submission_timestamp = u64::from_be_bytes(data[*offset..*offset + 8].try_into().ok()?);
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
        cert_der = data.slice(*offset..*offset + cert_len);
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
        let leaf_index = parse_leaf_index_ext(&data[*offset..*offset + ext_len]);
        *offset += ext_len;

        if *offset + 3 > data.len() {
            return None;
        }
        let precert_len = read_u24(data, *offset)?;
        *offset += 3;

        if *offset + precert_len > data.len() {
            return None;
        }
        cert_der = data.slice(*offset..*offset + precert_len);
        *offset += precert_len;

        let chain_fingerprints = read_chain_fingerprints(data, offset)?;

        return Some(TileLeaf {
            submission_timestamp,
            entry_type,
            cert_der,
            is_precert,
            chain_fingerprints,
            leaf_index,
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
    let leaf_index = parse_leaf_index_ext(&data[*offset..*offset + ext_len]);
    *offset += ext_len;

    let chain_fingerprints = read_chain_fingerprints(data, offset)?;

    Some(TileLeaf {
        submission_timestamp,
        entry_type,
        cert_der,
        is_precert,
        chain_fingerprints,
        leaf_index,
    })
}

/// Read a static-ct-api `Fingerprint certificate_chain<0..2^16-1>` field.
///
/// Spec note: the 2-byte prefix is the **byte length** of the chain blob, not
/// a fingerprint count (TLS presentation language `<lo..hi>` denotes byte
/// extents). The body is therefore exactly `byte_len / 32` consecutive 32-byte
/// fingerprints; a non-multiple-of-32 length is malformed.
fn read_chain_fingerprints(data: &[u8], offset: &mut usize) -> Option<Vec<[u8; 32]>> {
    if *offset + 2 > data.len() {
        return None;
    }
    let byte_len = u16::from_be_bytes(data[*offset..*offset + 2].try_into().ok()?) as usize;
    *offset += 2;
    if !byte_len.is_multiple_of(32) {
        return None;
    }
    if *offset + byte_len > data.len() {
        return None;
    }
    let count = byte_len / 32;
    let mut fingerprints = Vec::with_capacity(count);
    for _ in 0..count {
        let mut fp = [0u8; 32];
        fp.copy_from_slice(&data[*offset..*offset + 32]);
        fingerprints.push(fp);
        *offset += 32;
    }
    Some(fingerprints)
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
///
/// The fetched DER is parsed once here and cached as `Arc<ChainCert>`;
/// unparseable issuer blobs are not cached (and yield `None`).
pub async fn fetch_issuer(
    client: &Client,
    base_url: &str,
    fingerprint: &[u8; 32],
    cache: &IssuerCache,
    timeout: Duration,
    parse_opts: ParseOptions,
) -> Option<Arc<ChainCert>> {
    // Zero-alloc cache hit path: [u8; 32] key copied directly from stack.
    // A negative entry (Some(None)) is also a hit — known-unparseable.
    if let Some(cached) = cache.get(fingerprint) {
        metrics::counter!("certstream_issuer_cache_hits").increment(1);
        return cached;
    }

    metrics::counter!("certstream_issuer_cache_misses").increment(1);

    // Cache miss: only now do we pay for the hex string (needed for the URL).
    let hex = fingerprint_hex(fingerprint);
    let base = base_url.trim_end_matches('/');
    let url = format!("{}/issuer/{}", base, hex);

    match client.get(&url).timeout(timeout).send().await {
        Ok(resp) if resp.status().is_success() => match resp.bytes().await {
            Ok(bytes) => match parse_certificate_with_options(&bytes, parse_opts) {
                Some(leaf) => {
                    let cert = Arc::new(ChainCert::from(leaf));
                    cache.insert(*fingerprint, Arc::clone(&cert));
                    metrics::gauge!("certstream_issuer_cache_size").set(cache.len() as f64);
                    Some(cert)
                }
                None => {
                    // Negative-cache the verdict: the endpoint answered 200 but
                    // the DER is broken — refetching won't change that.
                    cache.insert_unparseable(*fingerprint);
                    debug!(url = %url, "issuer DER failed to parse");
                    None
                }
            },
            Err(e) => {
                debug!(url = %url, error = %e, "failed to read issuer response body");
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

/// Hard ceiling on a single decompressed tile. A static-CT tile is at most
/// 256 entries × ~(8 KB cert + small chain) ≈ 2-3 MiB in normal traffic.
/// 16 MiB gives ~5× headroom for chain-heavy precerts; anything larger is
/// either a misconfigured operator or a gzip bomb. We refuse it.
const MAX_DECOMPRESSED_TILE_BYTES: u64 = 16 * 1024 * 1024;

/// Decompress gzipped tile data, capped at [`MAX_DECOMPRESSED_TILE_BYTES`].
/// Returns borrowed data if not gzipped, or `Cow::Borrowed(&[])` if the
/// decompressed stream would exceed the cap (caller must check the slice's
/// length against the original `data.len()` if it wants to discriminate).
///
/// Pre-1.5.0 used `read_to_end` with no cap — a hostile or buggy CDN could
/// serve a small gzip stream that expanded to gigabytes and OOM'd the
/// process.
pub fn decompress_tile(data: &[u8]) -> Cow<'_, [u8]> {
    use std::io::Read as _;
    if data.len() >= 2 && data[0] == 0x1f && data[1] == 0x8b {
        let decoder = GzDecoder::new(data);
        let mut bounded = decoder.take(MAX_DECOMPRESSED_TILE_BYTES + 1);
        let mut decompressed = Vec::new();
        match bounded.read_to_end(&mut decompressed) {
            Ok(_) => {
                if decompressed.len() as u64 > MAX_DECOMPRESSED_TILE_BYTES {
                    warn!(
                        decompressed_size = decompressed.len(),
                        cap = MAX_DECOMPRESSED_TILE_BYTES,
                        "decompressed tile exceeds cap; rejecting"
                    );
                    metrics::counter!("certstream_static_ct_decompress_oversize").increment(1);
                    // Empty Cow makes parse_tile_leaves return [] and the
                    // caller treats it as a fetch failure → backoff.
                    Cow::Owned(Vec::new())
                } else {
                    Cow::Owned(decompressed)
                }
            }
            Err(_) => Cow::Borrowed(data),
        }
    } else {
        Cow::Borrowed(data)
    }
}

fn tail_start(tree_size: u64, overlap: u64) -> u64 {
    tree_size.saturating_sub(overlap)
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
        issuer_cache: shared_issuer_cache,
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
    let source_id = super::normalize::source_id(log.log_id.as_deref(), &base_url);
    let log_id_label = log.log_id.clone().unwrap_or_default();
    let source = Arc::new(Source {
        name: Arc::from(log.description.as_str()),
        url: Arc::from(base_url.as_str()),
    });

    metrics::gauge!(
        "certstream_ct_runtime_log_info",
        "source_id" => source_id.clone(),
        "log_id" => log_id_label,
        "log" => log_name.clone(),
        "operator" => log.operator.clone(),
        "log_type" => "static_ct"
    )
    .set(1.0);

    let health = Arc::new(LogHealth::new());
    // P1 fix: use the SHARED issuer cache from WatcherContext instead of
    // allocating a fresh per-watcher cache. With 55 static-CT logs this
    // was up to 55 × 10K entries (~500 MiB worst case); now a single
    // 10K-entry cache amortises issuer DERs across all logs of the same
    // operator (and across different operators sharing a root).
    let issuer_cache: Arc<IssuerCache> = shared_issuer_cache;
    let poll_interval = Duration::from_millis(config.poll_interval_ms);
    let timeout = Duration::from_secs(config.request_timeout_secs);
    let fetch_concurrency = config.fetch_concurrency.max(1) as usize;

    // Issue #3: Pre-register metric handles — no String allocation per certificate.
    let counter_tiles = metrics::counter!(
        "certstream_static_ct_tiles_fetched",
        "log" => log_name.clone(),
        "source_id" => source_id.clone()
    );
    let counter_parse_failures = metrics::counter!(
        "certstream_static_ct_parse_failures",
        "log" => log_name.clone(),
        "source_id" => source_id.clone()
    );
    let counter_entries_parsed = metrics::counter!(
        "certstream_static_ct_entries_parsed",
        "log" => log_name.clone(),
        "source_id" => source_id.clone()
    );
    let counter_messages = metrics::counter!(
        "certstream_messages_sent",
        "log" => log_name.clone(),
        "source_id" => source_id.clone()
    );
    let counter_checkpoint_errors = metrics::counter!(
        "certstream_static_ct_checkpoint_errors",
        "log" => log_name.clone(),
        "source_id" => source_id.clone()
    );
    counter_checkpoint_errors.increment(0);
    let counter_leaf_index_mismatch = metrics::counter!(
        "certstream_static_ct_leaf_index_mismatch",
        "log" => log_name.clone(),
        "source_id" => source_id.clone()
    );

    // §1.5a: skip extension display-string parsing when neither full nor lite
    // is subscribed at the config level. all_domains still populates from SAN.
    // `as_der` is only emitted by the `full` stream, so skip the per-cert
    // base64 encode of the whole DER unless full is enabled.
    let leaf_parse_opts = ParseOptions {
        include_der: streams.full,
        parse_extensions: streams.full || streams.lite,
    };
    // Chain certs are only serialized by the `full` stream, so their
    // extension strings are irrelevant elsewhere.
    let issuer_parse_opts = ParseOptions {
        include_der: false,
        parse_extensions: streams.full,
    };

    info!(log = %log_name, url = %base_url, "starting static CT watcher");

    let checkpoint_url = format!("{}/checkpoint", base_url);

    // Tracks the highest tree_size we've observed for rollback detection.
    // A static-CT log's tree_size must be monotonically non-decreasing; if the
    // server returns a smaller value we assume an operator bug or transient
    // serving inconsistency, log it, and refuse to advance.
    //
    // Seed from persisted state on resume so the rollback guard survives
    // restarts — otherwise the first poll after a restart would silently
    // accept any tree_size, including one smaller than what we had before.
    let mut high_water_tree_size: u64 = state_manager.get_tree_size(&base_url).unwrap_or(0);

    let mut current_index = if let Some(saved_index) = state_manager.get_index(&base_url) {
        info!(log = %log.description, saved_index = saved_index, "resuming from saved state");
        saved_index
    } else {
        // Bounded exponential retry on the initial checkpoint fetch. A brand-new
        // log can return malformed data on first contact (e.g. an empty body
        // before the operator finishes initialization); a single-shot failure
        // would have killed the watcher permanently for the lifetime of the
        // process. Mirror the retry semantics that watcher.rs uses for get-sth.
        let mut attempt: u32 = 0;
        let max_attempts = config.retry_max_attempts.max(1);
        let mut delay_ms = config.retry_initial_delay_ms;
        let max_delay_ms = config.retry_max_delay_ms;
        let initial = loop {
            attempt += 1;
            let outcome: Result<u64, String> =
                match client.get(&checkpoint_url).timeout(timeout).send().await {
                    Ok(resp) => match resp.text().await {
                        Ok(text) => match parse_checkpoint(&text, &expected_origin) {
                            Some(cp) => {
                                if accept_checkpoint_signature(
                                    &text,
                                    &expected_origin,
                                    log.key.as_deref(),
                                    config.checkpoint_signature_mode,
                                    &log.description,
                                    &log_name,
                                    &source_id,
                                ) {
                                    Ok(cp.tree_size)
                                } else {
                                    Err("checkpoint signature rejected".to_string())
                                }
                            }
                            None => Err("malformed checkpoint".to_string()),
                        },
                        Err(e) => Err(format!("read body: {e}")),
                    },
                    Err(e) => Err(format!("send: {e}")),
                };
            match outcome {
                Ok(size) => break Some(size),
                Err(reason) => {
                    if attempt >= max_attempts {
                        error!(
                            log = %log.description,
                            attempts = attempt,
                            error = %reason,
                            "initial checkpoint fetch failed after retries, exiting watcher"
                        );
                        counter_checkpoint_errors.increment(1);
                        metrics::counter!("certstream_worker_init_failures").increment(1);
                        break None;
                    }
                    debug!(
                        log = %log.description,
                        attempt,
                        max_attempts,
                        error = %reason,
                        "initial checkpoint fetch failed, retrying"
                    );
                    sleep(Duration::from_millis(delay_ms)).await;
                    delay_ms = (delay_ms * 2).min(max_delay_ms);
                }
            }
        };
        let Some(tree_size) = initial else { return };
        let start = tail_start(tree_size, config.start_overlap_leaves);
        info!(
            log = %log.description,
            tree_size,
            overlap = config.start_overlap_leaves,
            starting_at = start,
            "starting fresh (static CT)"
        );
        start
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
            // Status surfaced via /health/deep + the certstream_log_health_*
            // counters; the per-iteration log line is debug-only.
            debug!(log = %log.description, errors = health.total_errors(), "static CT log is unhealthy, waiting for recovery");
            sleep(Duration::from_secs(config.health_check_interval_secs)).await;
        }

        let raw_tree_size = match client.get(&checkpoint_url).timeout(timeout).send().await {
            Ok(resp) => {
                let status = resp.status();
                if status.as_u16() == 429 {
                    let retry_after_ms =
                        super::normalize::parse_retry_after(resp.headers(), &log.description);
                    health.record_rate_limit_with_ms(config.unhealthy_threshold, retry_after_ms);
                    metrics::counter!(
                        "certstream_ct_log_rate_limited_total",
                        "log" => log_name.clone(),
                        "source_id" => source_id.clone(),
                        "log_type" => "static_ct"
                    )
                    .increment(1);
                    debug!(log = %log.description, retry_after_ms, "rate limited on checkpoint fetch, backing off");
                    counter_checkpoint_errors.increment(1);
                    sleep(health.get_backoff()).await;
                    continue;
                }
                if !status.is_success() {
                    if was_unhealthy {
                        metrics::counter!("certstream_log_health_checks_failed").increment(1);
                    }
                    health.record_failure(config.unhealthy_threshold);
                    debug!(log = %log.description, %status, "checkpoint fetch returned non-success");
                    counter_checkpoint_errors.increment(1);
                    sleep(health.get_backoff()).await;
                    continue;
                }
                match resp.text().await {
                    Ok(text) => match parse_checkpoint(&text, &expected_origin) {
                        Some(cp) => {
                            if !accept_checkpoint_signature(
                                &text,
                                &expected_origin,
                                log.key.as_deref(),
                                config.checkpoint_signature_mode,
                                &log.description,
                                &log_name,
                                &source_id,
                            ) {
                                health.record_failure(config.unhealthy_threshold);
                                counter_checkpoint_errors.increment(1);
                                sleep(health.get_backoff()).await;
                                continue;
                            }
                            if was_unhealthy {
                                info!(log = %log.description, "health check passed (static CT), resuming");
                            }
                            health.record_success(config.healthy_threshold);
                            cp.tree_size
                        }
                        None => {
                            health.record_failure(config.unhealthy_threshold);
                            debug!(log = %log.description, "failed to parse checkpoint");
                            counter_checkpoint_errors.increment(1);
                            sleep(health.get_backoff()).await;
                            continue;
                        }
                    },
                    Err(e) => {
                        health.record_failure(config.unhealthy_threshold);
                        debug!(log = %log.description, error = %e, "failed to read checkpoint");
                        counter_checkpoint_errors.increment(1);
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
                debug!(log = %log.description, error = %e, "failed to fetch checkpoint");
                counter_checkpoint_errors.increment(1);
                sleep(health.get_backoff()).await;
                continue;
            }
        };

        // Tree-size monotonicity check: a static-CT log's tree_size never
        // shrinks. A regression indicates an operator bug, an incomplete
        // checkpoint replica, or a partial deployment — back off and retry
        // rather than reading stale tiles.
        if raw_tree_size < high_water_tree_size {
            debug!(
                log = %log.description,
                got = raw_tree_size,
                high_water = high_water_tree_size,
                "tree_size went backwards; refusing to advance"
            );
            metrics::counter!(
                "certstream_static_ct_tree_size_rollbacks",
                "log" => log_name.clone(),
                "source_id" => source_id.clone()
            )
            .increment(1);
            health.record_failure(config.unhealthy_threshold);
            sleep(health.get_backoff()).await;
            continue;
        }
        high_water_tree_size = raw_tree_size;
        let tree_size = raw_tree_size;

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

        // Inner drain: fetch all available tiles before re-polling the
        // checkpoint, pipelined `fetch_concurrency`-deep (each fetch still
        // pays a token to the per-operator bucket, so the sustained request
        // rate is unchanged). Tile geometry is deterministic from `tree_size`,
        // so unlike get-entries there is no partial-response realignment —
        // responses are simply processed in order.
        'tile_loop: while current_index < tree_size && !shutdown.is_cancelled() {
            use futures::StreamExt as _;

            let end_tile = (tree_size.saturating_sub(1)) / 256;
            let first_tile = current_index / 256;

            let mut in_flight = futures::stream::iter((first_tile..=end_tile).map(|tile_index| {
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
                (tile_index, entries_in_tile, partial_width)
            }))
            .map(|(tile_index, entries_in_tile, partial_width)| {
                let client = client.clone();
                let limiter = rate_limiter.clone();
                let desc = log.description.clone();
                let url = tile_url(&base_url, 0, tile_index, partial_width);
                async move {
                    // Respect per-operator rate limit before making request
                    if let Some(ref l) = limiter {
                        l.tick().await;
                    }
                    let outcome = match client.get(&url).timeout(timeout).send().await {
                        Ok(resp) => {
                            let status = resp.status();
                            if status.is_success() {
                                match resp.bytes().await {
                                    Ok(b) => super::FetchOutcome::Body(b),
                                    Err(e) => super::FetchOutcome::Net(e.to_string()),
                                }
                            } else {
                                let retry_after_ms = (status.as_u16() == 429).then(|| {
                                    super::normalize::parse_retry_after(resp.headers(), &desc)
                                });
                                super::FetchOutcome::Http(status, retry_after_ms)
                            }
                        }
                        Err(e) => super::FetchOutcome::Net(e.to_string()),
                    };
                    (tile_index, entries_in_tile, url, outcome)
                }
            })
            .buffered(fetch_concurrency);

            while let Some((tile_index, entries_in_tile, url, outcome)) = in_flight.next().await {
                if shutdown.is_cancelled() {
                    break 'tile_loop;
                }
                let is_last_tile = tile_index == end_tile;

                let raw_data = match outcome {
                    super::FetchOutcome::Body(b) => b,
                    super::FetchOutcome::Http(status, retry_after) => {
                        if let Some(retry_after_ms) = retry_after {
                            health.record_rate_limit_with_ms(
                                config.unhealthy_threshold,
                                retry_after_ms,
                            );
                            metrics::counter!(
                                "certstream_ct_log_rate_limited_total",
                                "log" => log_name.clone(),
                                "source_id" => source_id.clone(),
                                "log_type" => "static_ct"
                            )
                            .increment(1);
                            debug!(log = %log.description, retry_after_ms, "rate limited by static CT log, backing off");
                        } else {
                            health.record_failure(config.unhealthy_threshold);
                            debug!(log = %log.description, url = %url, status = %status, "tile fetch failed");
                        }
                        sleep(health.get_backoff()).await;
                        break 'tile_loop;
                    }
                    super::FetchOutcome::Net(e) => {
                        health.record_failure(config.unhealthy_threshold);
                        debug!(log = %log.description, url = %url, error = %e, "failed to fetch tile");
                        sleep(health.get_backoff()).await;
                        break 'tile_loop;
                    }
                };

                health.record_success(config.healthy_threshold);
                counter_tiles.increment(1);

                // Decompression (up to 16 MiB) + tile parsing is
                // pure CPU with no yield points — run it on the
                // blocking pool so concurrent catch-up across many
                // watchers doesn't starve the async runtime.
                let leaves = match tokio::task::spawn_blocking(move || {
                    let data: Bytes = match decompress_tile(&raw_data) {
                        // Not gzip (or decode failure): content is
                        // the response body as-is — reuse it.
                        Cow::Borrowed(_) => raw_data,
                        Cow::Owned(v) => Bytes::from(v),
                    };
                    parse_tile_leaves(data)
                })
                .await
                {
                    Ok(v) => v,
                    // Re-raise worker panics so the supervisor's
                    // catch_unwind recovery path still fires.
                    Err(e) if e.is_panic() => std::panic::resume_unwind(e.into_panic()),
                    // Cancelled (runtime shutdown) — bail out quietly.
                    Err(_) => break 'tile_loop,
                };

                // Static-CT-API rc.1: a tile must contain exactly
                // `entries_in_tile` leaves (256 for full, partial
                // width for the last). Mismatches indicate either
                // a corrupt fetch (truncated body) or a server
                // serving stale partials — drop the tile and
                // retry rather than emitting partial data.
                if (leaves.len() as u64) != entries_in_tile {
                    warn!(
                        log = %log.description,
                        tile = tile_index,
                        got = leaves.len(),
                        expected = entries_in_tile,
                        partial = is_last_tile && entries_in_tile < 256,
                        "tile leaf count mismatch; skipping"
                    );
                    metrics::counter!(
                        "certstream_static_ct_tile_width_mismatch",
                        "log" => log_name.clone(),
                        "source_id" => source_id.clone()
                    )
                    .increment(1);
                    health.record_failure(config.unhealthy_threshold);
                    sleep(health.get_backoff()).await;
                    break 'tile_loop;
                }

                let tile_start_index = tile_index * 256;
                let offset_in_tile = if current_index > tile_start_index {
                    (current_index - tile_start_index) as usize
                } else {
                    0
                };

                // Pre-warm the issuer cache for unique chain fingerprints
                // across this tile slice. Two safeties on top of the H-3 fix:
                //   1. Concurrency cap (`MAX_INFLIGHT_ISSUER_FETCHES`) so a
                //      tile with a huge chain count can't fan out into 65K
                //      concurrent HTTP requests to the operator's /issuer/
                //      endpoint — that bypasses the per-operator rate limiter
                //      and triggers IP bans / 429-storms.
                //   2. Per-fingerprint cache skip: only fetch what we don't
                //      already have, since the cache is now shared across
                //      all watchers and common roots (R10, ISRG X1) cache
                //      across logs.
                //
                // Chain certs are only consumed by the `full` stream, so
                // skip the issuer fetches entirely when it's disabled.
                if streams.full {
                    use futures::stream::{self, StreamExt};
                    use std::collections::HashSet;
                    const MAX_INFLIGHT_ISSUER_FETCHES: usize = 16;

                    let unique_fps: HashSet<[u8; 32]> = leaves
                        .iter()
                        .skip(offset_in_tile)
                        .flat_map(|l| l.chain_fingerprints.iter().copied())
                        .filter(|fp| issuer_cache.get(fp).is_none())
                        .collect();
                    if !unique_fps.is_empty() {
                        stream::iter(unique_fps)
                            .for_each_concurrent(MAX_INFLIGHT_ISSUER_FETCHES, |fp| {
                                let client = client.clone();
                                let base_url = base_url.clone();
                                let issuer_cache = issuer_cache.clone();
                                async move {
                                    let _ = fetch_issuer(
                                        &client,
                                        &base_url,
                                        &fp,
                                        &issuer_cache,
                                        timeout,
                                        issuer_parse_opts,
                                    )
                                    .await;
                                }
                            })
                            .await;
                    }
                }

                let leaf_count = leaves.len();

                // X.509 parse + hashing for a whole tile slice is
                // pure CPU — run it on the blocking pool (same
                // rationale as the decompress hop above). One hop
                // amortised over up to 256 leaves.
                let job_dedup = Arc::clone(&dedup);
                let job_tx = tx.clone();
                let job_cache = Arc::clone(&cache);
                let job_stats = Arc::clone(&stats);
                let job_streams = Arc::clone(&streams);
                let job_source = Arc::clone(&source);
                let job_issuer_cache = Arc::clone(&issuer_cache);
                let job_counter_messages = counter_messages.clone();
                let job_counter_parse_failures = counter_parse_failures.clone();
                let job_counter_entries_parsed = counter_entries_parsed.clone();
                let job_counter_leaf_index_mismatch = counter_leaf_index_mismatch.clone();
                let job_log_name = log_name.clone();
                let job_base_url = base_url.clone();
                let job_state_manager = Arc::clone(&state_manager);
                let job_tracker = Arc::clone(&tracker);
                let job_health = Arc::clone(&health);
                let full_stream_enabled = streams.full;
                // Identical for every leaf in the tile — format once.
                let tile_cert_link =
                    format!("{}/tile/data/{}", base_url, encode_tile_path(tile_index));
                let join = tokio::task::spawn_blocking(move || {
                    for (i, leaf) in leaves.into_iter().enumerate().skip(offset_in_tile) {
                        let cert_index = tile_start_index + i as u64;

                        // Static-CT-API rc.1: when the log populates
                        // the leaf_index SCT extension, it must equal
                        // the entry's tile-derived index. Mismatches
                        // are integrity violations (or operator bugs)
                        // — count them but continue with our index,
                        // which is grounded in tile coordinates.
                        if let Some(li) = leaf.leaf_index
                            && li != cert_index
                        {
                            warn!(
                                log = %job_log_name,
                                expected = cert_index,
                                got = li,
                                "leaf_index extension disagrees with tile-derived index"
                            );
                            job_counter_leaf_index_mismatch.increment(1);
                        }

                        let parsed = match parse_certificate_with_options(
                            &leaf.cert_der,
                            leaf_parse_opts,
                        ) {
                            Some(p) => p,
                            None => {
                                debug!(log = %job_log_name, index = cert_index, "skipped unparseable cert (static CT)");
                                job_counter_parse_failures.increment(1);
                                continue;
                            }
                        };

                        job_counter_entries_parsed.increment(1);

                        if !job_dedup.is_new(&parsed.sha256_raw) {
                            continue;
                        }

                        let seen = chrono::Utc::now().timestamp_millis() as f64 / 1000.0;
                        // Chain certs are only serialized by the `full`
                        // stream; the cache hands back pre-parsed
                        // Arc<ChainCert>s, so this is a refcount bump
                        // per issuer instead of a re-parse per leaf.
                        let chain: Vec<Arc<ChainCert>> = if full_stream_enabled {
                            leaf.chain_fingerprints
                                .iter()
                                // Pre-warm above already issued a concurrent
                                // fetch round populating the cache; here we
                                // just read it. If the pre-warm failed for
                                // this fp, skip rather than re-issuing a
                                // serial network round-trip on the hot path.
                                .filter_map(|fp| job_issuer_cache.get(fp).flatten())
                                .collect()
                        } else {
                            Vec::new()
                        };

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
                            Arc::clone(&job_source),
                            cert_index,
                        );
                        let msg = CertificateMessage {
                            message_type: Cow::Borrowed("certificate_update"),
                            data: CertificateData {
                                update_type,
                                leaf_cert: leaf_arc,
                                chain: if chain.is_empty() { None } else { Some(chain) },
                                cert_index,
                                cert_link: tile_cert_link.clone(),
                                seen,
                                submission_timestamp: leaf.submission_timestamp as f64 / 1000.0,
                                source: Arc::clone(&job_source),
                            },
                        };
                        broadcast_cert(
                            msg,
                            &job_tx,
                            &job_cache,
                            cached,
                            &job_stats,
                            &job_counter_messages,
                            &job_streams,
                        );
                    }

                    // Checkpoint INSIDE the job: if the supervisor's
                    // select! drops the watcher future at the
                    // `join.await` below (shutdown), the detached
                    // blocking task still runs to completion — the
                    // broadcasts above and this index persist stay
                    // atomic, so a restart doesn't replay the tile.
                    let next_index = ((tile_index + 1) * 256).min(tree_size);
                    job_state_manager.update_index(&job_base_url, next_index, tree_size);
                    job_tracker.update(
                        &job_base_url,
                        job_health.status(),
                        next_index,
                        tree_size,
                        job_health.total_errors(),
                    );
                });
                match join.await {
                    Ok(()) => {}
                    Err(e) if e.is_panic() => std::panic::resume_unwind(e.into_panic()),
                    Err(_) => break 'tile_loop,
                }

                current_index = ((tile_index + 1) * 256).min(tree_size);

                debug!(log = %log.description, tile = tile_index, leaves = leaf_count, "processed static CT tile");
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
    fn test_tail_start_seeds_overlap_behind_head() {
        assert_eq!(tail_start(1_000_000, 256), 999_744);
        assert_eq!(tail_start(1_000_000, 0), 1_000_000);
    }

    #[test]
    fn test_tail_start_small_log_floors_at_zero() {
        assert_eq!(tail_start(100, 256), 0);
        assert_eq!(tail_start(0, 256), 0);
    }

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
        use flate2::Compression;
        use flate2::write::GzEncoder;
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

    fn dummy_chain_cert(serial: &str) -> Arc<ChainCert> {
        Arc::new(ChainCert {
            subject: Default::default(),
            issuer: Default::default(),
            serial_number: serial.to_string(),
            not_before: 0,
            not_after: 0,
            fingerprint: Arc::from(""),
            sha1: String::new(),
            sha256: String::new(),
            signature_algorithm: Cow::Borrowed("test"),
            is_ca: true,
            as_der: None,
            extensions: Default::default(),
        })
    }

    #[test]
    fn test_issuer_cache_new() {
        let cache = IssuerCache::new();
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn test_issuer_cache_insert_and_get() {
        let cache = IssuerCache::new();
        let fp = [0xabu8; 32];

        cache.insert(fp, dummy_chain_cert("1234"));
        assert_eq!(cache.len(), 1);

        let retrieved = cache.get(&fp).unwrap().unwrap();
        assert_eq!(retrieved.serial_number, "1234");
    }

    #[test]
    fn test_issuer_cache_get_missing() {
        let cache = IssuerCache::new();
        assert!(cache.get(&[0u8; 32]).is_none());
    }

    #[test]
    fn test_issuer_cache_negative_entry() {
        let cache = IssuerCache::new();
        let fp = [0x42u8; 32];
        cache.insert_unparseable(fp);
        // Present (no refetch) but resolves to no cert (skipped in chains).
        let entry = cache.get(&fp);
        assert!(entry.is_some(), "negative entry must be present");
        assert!(
            entry.unwrap().is_none(),
            "negative entry must resolve to no cert"
        );
    }

    #[test]
    fn test_issuer_cache_overwrite() {
        let cache = IssuerCache::new();
        let fp = [0x01u8; 32];
        cache.insert(fp, dummy_chain_cert("old"));
        cache.insert(fp, dummy_chain_cert("new"));
        assert_eq!(cache.len(), 1);
        assert_eq!(cache.get(&fp).unwrap().unwrap().serial_number, "new");
    }

    /// Regression for #6: pre-1.5.0 each leaf in the per-tile loop went
    /// through `fetch_issuer(...).await` even after the pre-warm `join_all`
    /// populated the cache. The per-leaf path now reads
    /// `issuer_cache.get(fp)` directly, so for any one fingerprint we hit
    /// the network *at most once* per cache lifetime.
    #[tokio::test]
    async fn issuer_fetch_hits_network_at_most_once_per_fingerprint() {
        use std::net::SocketAddr;
        use std::sync::atomic::{AtomicU32, Ordering};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr: SocketAddr = listener.local_addr().unwrap();
        let counter = Arc::new(AtomicU32::new(0));
        let counter_clone = counter.clone();
        // fetch_issuer now parses the DER before caching, so serve a real
        // certificate instead of garbage bytes.
        let issuer_der: Arc<Vec<u8>> = Arc::new(
            rcgen::generate_simple_self_signed(vec!["issuer.test".to_string()])
                .unwrap()
                .cert
                .der()
                .to_vec(),
        );
        let issuer_der_srv = Arc::clone(&issuer_der);
        let server = tokio::spawn(async move {
            loop {
                let (mut sock, _) = match listener.accept().await {
                    Ok(p) => p,
                    Err(_) => break,
                };
                let counter = counter_clone.clone();
                let body = Arc::clone(&issuer_der_srv);
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    let _ = sock.read(&mut buf).await;
                    counter.fetch_add(1, Ordering::SeqCst);
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    );
                    let _ = sock.write_all(resp.as_bytes()).await;
                    let _ = sock.write_all(&body).await;
                    let _ = sock.shutdown().await;
                });
            }
        });

        let base = format!("http://{addr}");
        let client = reqwest::Client::new();
        let cache = Arc::new(IssuerCache::new());
        let fp = [0xab; 32];
        let opts = ParseOptions {
            include_der: false,
            parse_extensions: false,
        };

        let v1 = fetch_issuer(
            &client,
            &base,
            &fp,
            &cache,
            std::time::Duration::from_secs(2),
            opts,
        )
        .await;
        assert!(v1.is_some(), "first fetch should succeed");
        assert_eq!(
            counter.load(Ordering::SeqCst),
            1,
            "exactly one HTTP hit so far"
        );

        let v2 = fetch_issuer(
            &client,
            &base,
            &fp,
            &cache,
            std::time::Duration::from_secs(2),
            opts,
        )
        .await;
        assert!(v2.is_some(), "cached fetch must return Some");
        assert_eq!(
            counter.load(Ordering::SeqCst),
            1,
            "second fetch_issuer with cached fp must NOT hit the network — \
             pre-1.5.0 the per-leaf hot loop burned an HTTP request per chain \
             entry per leaf even when the cache had the value"
        );

        let fp2 = [0xcd; 32];
        let _ = fetch_issuer(
            &client,
            &base,
            &fp2,
            &cache,
            std::time::Duration::from_secs(2),
            opts,
        )
        .await;
        assert_eq!(
            counter.load(Ordering::SeqCst),
            2,
            "new fingerprint must hit the network exactly once"
        );

        server.abort();
    }

    #[test]
    fn test_issuer_cache_multiple_entries() {
        let cache = IssuerCache::new();
        for i in 0u8..100 {
            let mut fp = [0u8; 32];
            fp[0] = i;
            cache.insert(fp, dummy_chain_cert(&i.to_string()));
        }
        assert_eq!(cache.len(), 100);
        let fp0 = [0u8; 32];
        assert_eq!(cache.get(&fp0).unwrap().unwrap().serial_number, "0");
        let mut fp99 = [0u8; 32];
        fp99[0] = 99;
        assert_eq!(cache.get(&fp99).unwrap().unwrap().serial_number, "99");
    }

    /// Build a synthetic x509 tile entry. `extensions` is the raw `CtExtensions`
    /// body (without the 2-byte length prefix); pass `&[]` for legacy-empty.
    fn build_x509_entry_with_ext(
        timestamp: u64,
        cert_der: &[u8],
        chain_fps: &[[u8; 32]],
        extensions: &[u8],
    ) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&timestamp.to_be_bytes());
        data.extend_from_slice(&0u16.to_be_bytes());
        let cert_len = cert_der.len() as u32;
        data.push((cert_len >> 16) as u8);
        data.push((cert_len >> 8) as u8);
        data.push(cert_len as u8);
        data.extend_from_slice(cert_der);
        data.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        data.extend_from_slice(extensions);
        // 2-byte BYTE-length prefix per static-ct-api `<0..2^16-1>` framing.
        data.extend_from_slice(&((chain_fps.len() * 32) as u16).to_be_bytes());
        for fp in chain_fps {
            data.extend_from_slice(fp);
        }
        data
    }

    fn build_x509_entry(timestamp: u64, cert_der: &[u8], chain_fps: &[[u8; 32]]) -> Vec<u8> {
        build_x509_entry_with_ext(timestamp, cert_der, chain_fps, &[])
    }

    /// Build a `leaf_index` extension blob suitable for `extensions` in
    /// `build_x509_entry_with_ext`. `index` is encoded as a 5-byte big-endian
    /// unsigned integer per static-ct-api v1.0.0-rc.1.
    fn build_leaf_index_ext(index: u64) -> Vec<u8> {
        let mut v = Vec::with_capacity(8);
        v.push(0); // extension_type = leaf_index(0)
        v.extend_from_slice(&5u16.to_be_bytes()); // extension_data length
        v.push((index >> 32) as u8);
        v.push((index >> 24) as u8);
        v.push((index >> 16) as u8);
        v.push((index >> 8) as u8);
        v.push(index as u8);
        v
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
        // 2-byte BYTE-length prefix per static-ct-api `<0..2^16-1>` framing.
        data.extend_from_slice(&((chain_fps.len() * 32) as u16).to_be_bytes());
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

        let leaves = parse_tile_leaves(Bytes::from(data));
        assert_eq!(leaves.len(), 1);
        assert_eq!(leaves[0].submission_timestamp, 1700000000000);
        assert_eq!(leaves[0].entry_type, 0);
        assert!(!leaves[0].is_precert);
        assert_eq!(&leaves[0].cert_der[..], &cert[..]);
        assert_eq!(leaves[0].chain_fingerprints.len(), 1);
        assert_eq!(leaves[0].chain_fingerprints[0], fp1);
        assert_eq!(leaves[0].leaf_index, None);
    }

    #[test]
    fn test_parse_leaf_index_ext_present() {
        let ext = build_leaf_index_ext(0x123456789a);
        assert_eq!(parse_leaf_index_ext(&ext), Some(0x123456789a));
    }

    #[test]
    fn test_parse_leaf_index_ext_zero() {
        let ext = build_leaf_index_ext(0);
        assert_eq!(parse_leaf_index_ext(&ext), Some(0));
    }

    #[test]
    fn test_parse_leaf_index_ext_max_40bit() {
        // (1 << 40) - 1 fills all 5 bytes.
        let ext = build_leaf_index_ext((1u64 << 40) - 1);
        assert_eq!(parse_leaf_index_ext(&ext), Some((1u64 << 40) - 1));
    }

    #[test]
    fn test_parse_leaf_index_ext_empty() {
        assert_eq!(parse_leaf_index_ext(&[]), None);
    }

    #[test]
    fn test_parse_leaf_index_ext_unknown_only() {
        // type=42, len=3, data=[1,2,3]. No leaf_index → None.
        let blob = vec![42, 0, 3, 1, 2, 3];
        assert_eq!(parse_leaf_index_ext(&blob), None);
    }

    #[test]
    fn test_parse_leaf_index_ext_skip_unknown_then_match() {
        // unknown ext (type=10, 2-byte payload) followed by leaf_index.
        let mut blob = vec![10, 0, 2, 0xaa, 0xbb];
        blob.extend_from_slice(&build_leaf_index_ext(7));
        assert_eq!(parse_leaf_index_ext(&blob), Some(7));
    }

    #[test]
    fn test_parse_tile_leaves_x509_with_leaf_index() {
        let ext = build_leaf_index_ext(42);
        let data = build_x509_entry_with_ext(1_700_000_000_000, b"cert", &[], &ext);
        let leaves = parse_tile_leaves(Bytes::from(data));
        assert_eq!(leaves.len(), 1);
        assert_eq!(leaves[0].leaf_index, Some(42));
    }

    #[test]
    fn test_parse_tile_leaves_truncated_ext_data_returns_none() {
        // ext type=0, declared len=5, but only 4 data bytes present.
        let bad_ext = vec![0, 0, 5, 1, 2, 3, 4];
        assert_eq!(parse_leaf_index_ext(&bad_ext), None);
    }

    #[test]
    fn test_parse_tile_leaves_single_precert() {
        let issuer_hash = [0xbb; 32];
        let tbs = b"fake_tbs_cert";
        let precert = b"fake_precert_der";
        let fp1 = [0xcc; 32];
        let fp2 = [0xdd; 32];
        let data = build_precert_entry(1700000001000, &issuer_hash, tbs, precert, &[fp1, fp2]);

        let leaves = parse_tile_leaves(Bytes::from(data));
        assert_eq!(leaves.len(), 1);
        assert_eq!(leaves[0].submission_timestamp, 1700000001000);
        assert_eq!(leaves[0].entry_type, 1);
        assert!(leaves[0].is_precert);
        assert_eq!(&leaves[0].cert_der[..], &precert[..]);
        assert_eq!(leaves[0].chain_fingerprints.len(), 2);
        assert_eq!(leaves[0].chain_fingerprints[0], fp1);
        assert_eq!(leaves[0].chain_fingerprints[1], fp2);
    }

    #[test]
    fn test_parse_tile_leaves_long_chain_recovers_full_count() {
        // Regression: the chain field is `Fingerprint<0..2^16-1>` — a byte-length
        // prefix, not a fingerprint count. A pre-1.4 bug treated the prefix as
        // a count, consuming subsequent leaves' bytes as fingerprint data.
        let chain: Vec<[u8; 32]> = (0..64).map(|i| [i as u8; 32]).collect();
        let mut data = Vec::new();
        data.extend_from_slice(&build_x509_entry(1, b"a", &chain));
        data.extend_from_slice(&build_x509_entry(2, b"b", &chain));
        data.extend_from_slice(&build_x509_entry(3, b"c", &chain));
        let leaves = parse_tile_leaves(Bytes::from(data));
        assert_eq!(leaves.len(), 3);
        assert_eq!(leaves[1].chain_fingerprints.len(), 64);
        assert_eq!(leaves[2].submission_timestamp, 3);
    }

    #[test]
    fn test_read_chain_fingerprints_rejects_non_aligned_length() {
        // 2-byte length = 33 (not a multiple of 32) → malformed, parser
        // refuses to advance.
        let data: Vec<u8> = vec![0x00, 0x21, 0u8, 0u8, 0u8];
        let mut offset = 0;
        assert!(read_chain_fingerprints(&data, &mut offset).is_none());
    }

    #[test]
    fn test_parse_tile_leaves_multiple_entries() {
        let mut data = Vec::new();
        data.extend_from_slice(&build_x509_entry(1000, b"cert1", &[]));
        data.extend_from_slice(&build_x509_entry(2000, b"cert2", &[[0xee; 32]]));

        let issuer_hash = [0xff; 32];
        data.extend_from_slice(&build_precert_entry(
            3000,
            &issuer_hash,
            b"tbs",
            b"precert",
            &[],
        ));

        let leaves = parse_tile_leaves(Bytes::from(data));
        assert_eq!(leaves.len(), 3);

        assert_eq!(leaves[0].submission_timestamp, 1000);
        assert!(!leaves[0].is_precert);
        assert_eq!(&leaves[0].cert_der[..], b"cert1");

        assert_eq!(leaves[1].submission_timestamp, 2000);
        assert!(!leaves[1].is_precert);
        assert_eq!(&leaves[1].cert_der[..], b"cert2");
        assert_eq!(leaves[1].chain_fingerprints.len(), 1);

        assert_eq!(leaves[2].submission_timestamp, 3000);
        assert!(leaves[2].is_precert);
        assert_eq!(&leaves[2].cert_der[..], b"precert");
    }

    #[test]
    fn test_parse_tile_leaves_empty() {
        let leaves = parse_tile_leaves(Bytes::new());
        assert!(leaves.is_empty());
    }

    #[test]
    fn test_parse_tile_leaves_truncated() {
        // Only 5 bytes (needs at least 10 for timestamp + entry_type)
        let data = [0u8; 5];
        let leaves = parse_tile_leaves(Bytes::copy_from_slice(&data));
        assert!(leaves.is_empty());
    }

    #[test]
    fn test_parse_tile_leaves_x509_no_chain() {
        let cert = b"test";
        let data = build_x509_entry(5000, cert, &[]);

        let leaves = parse_tile_leaves(Bytes::from(data));
        assert_eq!(leaves.len(), 1);
        assert!(leaves[0].chain_fingerprints.is_empty());
    }

    #[test]
    fn test_parse_tile_leaves_precert_no_chain() {
        let data = build_precert_entry(6000, &[0; 32], b"tbs", b"precert", &[]);
        let leaves = parse_tile_leaves(Bytes::from(data));
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
        assert_eq!(
            hex,
            "0000000000000000000000000000000000000000000000000000000000000000"
        );
    }

    #[test]
    fn test_fingerprint_hex_all_ff() {
        let fp = [0xff; 32];
        let hex = fingerprint_hex(&fp);
        assert_eq!(
            hex,
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        );
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

    // Real Let's Encrypt Willow 2025h1b checkpoint + log key, from the
    // static_ct_api crate's own doc vector. The log key is ECDSA P-256.
    const WILLOW_ORIGIN: &str = "willow.ct.letsencrypt.org/2025h1b";
    const WILLOW_KEY_B64: &str = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEbNmWXyYsF2pohGOAiNELea6UL4/XioI3w6ChE5Udlos0HUqM7KOHIP9qBuWCVs6VAdtDXrvanmxKq52Whh2+2w==";
    const WILLOW_CHECKPOINT: &str = concat!(
        "willow.ct.letsencrypt.org/2025h1b\n",
        "1237717073\n",
        "pT/KC9MSHoRK2rHkeyfTSXfxolR2ja4JqhdymK9pnlo=\n",
        "\n",
        "— grease.invalid 6PiRCcvuZmG719Q08yWtEVT7C6ncT1s8R1xtzvX/reoSPKtuXROhW7Se59Kiwa7i98c/AM8tH4EElmqOQnJcF4cxRlbI9FY=\n",
        "— willow.ct.letsencrypt.org/2025h1b kgUpF33pGg==\n",
        "— willow.ct.letsencrypt.org/2025h1b ilIWIZPYgLHq/TqbHb14ff7ydbJ3VTODZcRE5VVYXTc3RduKQdVTwHV+Uv6NAEq9qBmjeXXw5QePKXNfDK747p2VOgo=\n",
        "— willow.ct.letsencrypt.org/2025h1b GYcbuAAAAZSU2PMJBAMASDBGAiEAhNc5t31Sx4HmBDN4bh366ApPb1Ag1S1zn1XN02ibJNYCIQCKGun1fU1tcgMpWPu3918Rk6OBuoSjt7wdBag1cKsQ+g==\n",
    );
    // A different valid ECDSA P-256 SPKI (Cloudflare static-ct-dev log key).
    const OTHER_P256_KEY_B64: &str = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAES4yrL7jarwxEdSWrJp35uef789UYLma/F0x7bfBpW2KWnN5yuDE5XgeOAKeWM3RpycCZF2xRGAp2iHFCa4PtqA==";
    // A valid Ed25519 SPKI (a witness key) — not ECDSA, must be unverifiable.
    const ED25519_KEY_B64: &str = "MCowBQYDK2VwAyEARN4KXLGKQrfUUGU1zwbFvEN1AckVY76d4CnuNRc20vI=";

    #[test]
    fn verify_checkpoint_signature_valid() {
        let outcome =
            verify_checkpoint_signature(WILLOW_CHECKPOINT, WILLOW_ORIGIN, Some(WILLOW_KEY_B64));
        assert_eq!(outcome, SigCheck::Verified);
    }

    #[test]
    fn verify_checkpoint_signature_tampered_tree_size_fails() {
        // Flip the tree size; the signed body no longer matches the log signature.
        let tampered = WILLOW_CHECKPOINT.replace("1237717073", "1237717074");
        assert!(matches!(
            verify_checkpoint_signature(&tampered, WILLOW_ORIGIN, Some(WILLOW_KEY_B64)),
            SigCheck::Failed(_)
        ));
    }

    #[test]
    fn verify_checkpoint_signature_wrong_key_fails() {
        // A different (valid P-256) key never matches the checkpoint's signature id.
        assert!(matches!(
            verify_checkpoint_signature(WILLOW_CHECKPOINT, WILLOW_ORIGIN, Some(OTHER_P256_KEY_B64)),
            SigCheck::Failed(_)
        ));
    }

    #[test]
    fn verify_checkpoint_signature_no_key_unverifiable() {
        assert!(matches!(
            verify_checkpoint_signature(WILLOW_CHECKPOINT, WILLOW_ORIGIN, None),
            SigCheck::Unverifiable(_)
        ));
    }

    #[test]
    fn verify_checkpoint_signature_non_p256_key_unverifiable() {
        // Ed25519 key can't be parsed as an ECDSA P-256 verifying key.
        assert!(matches!(
            verify_checkpoint_signature(WILLOW_CHECKPOINT, WILLOW_ORIGIN, Some(ED25519_KEY_B64)),
            SigCheck::Unverifiable(_)
        ));
    }

    #[test]
    fn verify_checkpoint_signature_bad_base64_unverifiable() {
        assert!(matches!(
            verify_checkpoint_signature(WILLOW_CHECKPOINT, WILLOW_ORIGIN, Some("not@@base64!!")),
            SigCheck::Unverifiable(_)
        ));
    }

    #[test]
    fn verify_checkpoint_signature_wrong_origin_fails() {
        // The origin is folded into the key id; a mismatched origin can't match.
        assert!(matches!(
            verify_checkpoint_signature(
                WILLOW_CHECKPOINT,
                "wrong.example.com/2025h1b",
                Some(WILLOW_KEY_B64)
            ),
            SigCheck::Failed(_)
        ));
    }

    #[test]
    fn accept_enforce_rejects_failed_signature() {
        let tampered = WILLOW_CHECKPOINT.replace("1237717073", "1237717074");
        let accepted = accept_checkpoint_signature(
            &tampered,
            WILLOW_ORIGIN,
            Some(WILLOW_KEY_B64),
            CheckpointSignatureMode::Enforce,
            "test-log",
            "test-log",
            "src-1",
        );
        assert!(!accepted, "enforce mode must reject an invalid signature");
    }

    #[test]
    fn accept_warn_accepts_failed_signature() {
        let tampered = WILLOW_CHECKPOINT.replace("1237717073", "1237717074");
        let accepted = accept_checkpoint_signature(
            &tampered,
            WILLOW_ORIGIN,
            Some(WILLOW_KEY_B64),
            CheckpointSignatureMode::Warn,
            "test-log",
            "test-log",
            "src-1",
        );
        assert!(accepted, "warn mode must accept even an invalid signature");
    }

    #[test]
    fn accept_enforce_accepts_unverifiable() {
        // No key → unverifiable → accepted even under enforce (can't verify is not forgery).
        let accepted = accept_checkpoint_signature(
            WILLOW_CHECKPOINT,
            WILLOW_ORIGIN,
            None,
            CheckpointSignatureMode::Enforce,
            "test-log",
            "test-log",
            "src-1",
        );
        assert!(
            accepted,
            "enforce must still accept an unverifiable checkpoint"
        );
    }

    #[test]
    fn accept_verified_signature() {
        let accepted = accept_checkpoint_signature(
            WILLOW_CHECKPOINT,
            WILLOW_ORIGIN,
            Some(WILLOW_KEY_B64),
            CheckpointSignatureMode::Enforce,
            "test-log",
            "test-log",
            "src-1",
        );
        assert!(accepted, "a valid signature must be accepted");
    }
}
