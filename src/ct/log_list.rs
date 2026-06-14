use crate::config::{CustomCtLog, StaticCtLog};
use crate::ct::catalog::{self, CatalogFetch, SignedCatalog};
use crate::ct::normalize::{normalize_log_origin, normalize_operator, normalize_url};
use futures::future::join_all;
use reqwest::Client;
use serde::Deserialize;
use std::collections::HashMap;
use std::time::Duration;
use thiserror::Error;
use tracing::{debug, info, warn};

#[derive(Error, Debug)]
pub enum LogListError {
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("No usable logs found")]
    NoLogs,
}

#[derive(Debug, Deserialize)]
struct LogListResponse {
    operators: Vec<Operator>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct Operator {
    name: String,
    #[serde(default)]
    logs: Vec<RawCtLog>,
    /// Apple's log list (and Google's v3 starting in 2026) carry static-ct-api endpoints
    /// here. Older Google lists omit the field, hence the default. Operators that only
    /// run tiled logs may also have an empty `logs` array.
    #[serde(default)]
    tiled_logs: Vec<RawTiledLog>,
    /// Recognized-but-unused v3 fields. Captured explicitly so they do not trip
    /// the unknown-field counter.
    #[serde(default)]
    email: Option<serde_json::Value>,
    /// Genuinely unknown operator-level keys are captured and counted, never a
    /// parse crash.
    #[serde(flatten)]
    _other: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct RawCtLog {
    description: String,
    url: String,
    #[serde(default)]
    log_id: Option<String>,
    #[serde(default)]
    state: Option<LogState>,
    /// Recognized v3 fields not consumed by the runtime. Captured so they do
    /// not trip unknown-field metrics.
    /// `log_type` is Google's "prod"/"test" marker.
    #[serde(default)]
    key: Option<String>,
    #[serde(default)]
    mmd: Option<u64>,
    #[serde(default)]
    temporal_interval: Option<serde_json::Value>,
    #[serde(default)]
    previous_operators: Option<serde_json::Value>,
    #[serde(default)]
    log_type: Option<String>,
    #[serde(flatten)]
    _other: HashMap<String, serde_json::Value>,
}

/// Schema for a static-ct-api / Sunlight log entry as it appears in Apple's
/// `current_log_list.json` and Google's v3 list. The submission URL doubles as
/// the checkpoint origin (schema-less, trailing-slash-stripped).
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct RawTiledLog {
    description: String,
    monitoring_url: String,
    submission_url: String,
    #[serde(default)]
    log_id: Option<String>,
    #[serde(default)]
    state: Option<LogState>,
    /// Recognized v3 fields (see `RawCtLog`). `tls_only` is the tiled-log marker
    /// for submission over a TLS-authenticated connection.
    #[serde(default)]
    key: Option<String>,
    #[serde(default)]
    mmd: Option<u64>,
    #[serde(default)]
    temporal_interval: Option<serde_json::Value>,
    #[serde(default)]
    previous_operators: Option<serde_json::Value>,
    #[serde(default)]
    log_type: Option<String>,
    #[serde(default)]
    tls_only: Option<bool>,
    #[serde(flatten)]
    _other: HashMap<String, serde_json::Value>,
}

/// Mirror of the v3 log-list `state` object. Prod code only branches on
/// `rejected`/`retired` today; `pending`/`qualified`/`usable`/`readonly` are
/// declared so serde recognizes the full lifecycle (B2b's spawn allowlist uses
/// them). Unknown state keys are captured in `_other` and counted as an unknown
/// enum rather than silently dropped.
#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
struct LogState {
    #[serde(default)]
    pending: Option<StateInfo>,
    #[serde(default)]
    qualified: Option<StateInfo>,
    #[serde(default)]
    usable: Option<StateInfo>,
    #[serde(default)]
    readonly: Option<StateInfo>,
    #[serde(default)]
    retired: Option<StateInfo>,
    #[serde(default)]
    rejected: Option<StateInfo>,
    #[serde(flatten)]
    _other: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Deserialize)]
struct StateInfo {
    #[serde(rename = "timestamp")]
    _timestamp: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LogType {
    Rfc6962,
    StaticCt,
}

#[derive(Debug, Clone)]
pub struct CtLog {
    pub description: String,
    pub url: String,
    pub operator: String,
    pub log_type: LogType,
    /// Explicit checkpoint origin override (see `StaticCtLog::log_origin`).
    pub log_origin: Option<String>,
    /// Base64-encoded log ID (SHA-256 of the log's public key). Used to dedupe
    /// logs that appear in multiple log lists (e.g. Google + Apple).
    pub log_id: Option<String>,
    /// Optional per-log override; `None` means use the global CT config.
    pub batch_size: Option<u64>,
    /// Optional per-log override; `None` means use the global CT config.
    pub poll_interval_ms: Option<u64>,
    state: Option<LogState>,
}

impl CtLog {
    pub fn is_usable(&self) -> bool {
        match &self.state {
            Some(state) => {
                // Include all logs except rejected and retired
                state.rejected.is_none() && state.retired.is_none()
            }
            // state: null - include these too (e.g., Solera logs that work but aren't marked usable yet)
            None => true,
        }
    }

    pub fn normalized_url(&self) -> String {
        let url = self.url.trim_end_matches('/');
        if url.starts_with("https://") || url.starts_with("http://") {
            url.to_string()
        } else {
            format!("https://{}", url)
        }
    }
}

impl From<CustomCtLog> for CtLog {
    fn from(custom: CustomCtLog) -> Self {
        Self {
            description: custom.name,
            url: custom.url,
            operator: "Custom".to_string(),
            log_type: LogType::Rfc6962,
            log_origin: None,
            log_id: None,
            batch_size: custom.batch_size,
            poll_interval_ms: custom.poll_interval_ms,
            state: None,
        }
    }
}

impl From<StaticCtLog> for CtLog {
    fn from(static_log: StaticCtLog) -> Self {
        Self {
            description: static_log.name,
            url: static_log.url,
            operator: "Static CT".to_string(),
            log_type: LogType::StaticCt,
            log_origin: static_log.log_origin,
            log_id: None,
            batch_size: static_log.batch_size,
            poll_interval_ms: static_log.poll_interval_ms,
            state: None,
        }
    }
}

#[cfg(test)]
fn make_test_log(description: &str, url: &str, state: Option<LogState>) -> CtLog {
    CtLog {
        description: description.to_string(),
        url: url.to_string(),
        operator: "TestOp".to_string(),
        log_type: LogType::Rfc6962,
        log_origin: None,
        log_id: None,
        batch_size: None,
        poll_interval_ms: None,
        state,
    }
}

/// Probe a log for reachability. Dispatches by `LogType`:
/// - `Rfc6962` logs respond on `/ct/v1/get-sth`.
/// - `StaticCt` logs respond on `/checkpoint`.
///
/// Static-CT logs do not implement `get-sth`, so attempting it produces false
/// negatives. When the spec evolves and a log temporarily exposes both, either
/// endpoint is sufficient — we treat any `200` on the type-appropriate URL as
/// reachable.
async fn probe_log(client: &Client, log: &CtLog) -> bool {
    let url = match log.log_type {
        LogType::Rfc6962 => format!("{}/ct/v1/get-sth", log.normalized_url()),
        LogType::StaticCt => format!("{}/checkpoint", log.normalized_url()),
    };
    match client
        .get(&url)
        .timeout(Duration::from_secs(5))
        .send()
        .await
    {
        Ok(resp) if resp.status().is_success() => true,
        Ok(resp) => {
            debug!(log = %log.description, status = %resp.status(), kind = ?log.log_type, "log not reachable");
            false
        }
        Err(_) => {
            debug!(log = %log.description, kind = ?log.log_type, "log not reachable");
            false
        }
    }
}

/// Parse already-fetched catalog JSON bytes into `CtLog` candidates. Unknown
/// operator/log keys are counted, never a parse crash; malformed catalog JSON
/// yields zero entries and a counted skip rather than aborting the whole
/// refresh.
///
/// `source_name` is the `catalog_source` metric label. Operator names are
/// canonicalized via `normalize_operator`; static-ct origins via
/// `normalize_log_origin`. RFC-6962 entries come from `operators[].logs`,
/// static-CT entries from `operators[].tiled_logs`.
fn parse_list(bytes: &[u8], source_name: &str) -> Vec<CtLog> {
    let response: LogListResponse = match serde_json::from_slice(bytes) {
        Ok(r) => r,
        Err(e) => {
            metrics::counter!(
                "certstream_catalog_entry_skipped_total",
                "catalog_source" => source_name.to_string(),
                "reason" => "list_parse_error"
            )
            .increment(1);
            warn!(catalog_source = source_name, error = %e, "catalog list failed to parse; skipping source this cycle");
            return Vec::new();
        }
    };

    let mut out = Vec::new();
    for op in response.operators {
        count_unknown_fields(source_name, &op._other);
        let operator = normalize_operator(&op.name);
        for raw in op.logs {
            count_unknown_fields(source_name, &raw._other);
            count_unknown_state_enum(source_name, raw.state.as_ref());
            out.push(CtLog {
                description: raw.description,
                url: normalize_url(&raw.url),
                operator: operator.clone(),
                log_type: LogType::Rfc6962,
                log_origin: None,
                log_id: raw.log_id,
                batch_size: None,
                poll_interval_ms: None,
                state: raw.state,
            });
        }
        for raw in op.tiled_logs {
            count_unknown_fields(source_name, &raw._other);
            count_unknown_state_enum(source_name, raw.state.as_ref());
            out.push(CtLog {
                description: raw.description,
                url: normalize_url(&raw.monitoring_url),
                operator: operator.clone(),
                log_type: LogType::StaticCt,
                log_origin: Some(normalize_log_origin(&raw.submission_url)),
                log_id: raw.log_id,
                batch_size: None,
                poll_interval_ms: None,
                state: raw.state,
            });
        }
    }
    out
}

/// Count each unknown top-level key once, with the raw name in a WARN log (the
/// forensic surface) but NEVER as a metric label (unbounded by construction).
fn count_unknown_fields(source_name: &str, other: &HashMap<String, serde_json::Value>) {
    for key in other.keys() {
        metrics::counter!(
            "certstream_catalog_unknown_field_total",
            "catalog_source" => source_name.to_string()
        )
        .increment(1);
        warn!(catalog_source = source_name, field = %key, "unknown catalog field (ignored)");
    }
}

/// Count unknown `state` object keys (a future lifecycle state) as an unknown
/// enum. The raw key goes to a WARN log, not a label (`field="state"` is the
/// only label — a known field name, bounded).
fn count_unknown_state_enum(source_name: &str, state: Option<&LogState>) {
    if let Some(s) = state {
        for key in s._other.keys() {
            metrics::counter!(
                "certstream_catalog_unknown_enum_total",
                "catalog_source" => source_name.to_string(),
                "field" => "state"
            )
            .increment(1);
            warn!(catalog_source = source_name, state_value = %key, "unknown catalog state enum (treated as inert)");
        }
    }
}

/// Discover CT logs from the signed catalog registry and append the operator's
/// `custom_logs`. Each catalog is fetched and signature-verified; only entries
/// whose source resolves to runtime-authoritative drive auto-spawn.
///
/// Logs appearing in multiple catalogs are deduped by `log_id`; authority is the
/// OR across sources (any authoritative source that lists a log makes it
/// spawn-eligible). Authoritative discovered logs are then health-probed in
/// parallel. Custom logs are explicit operator intent and always included
/// without probing.
pub async fn fetch_log_list(
    client: &Client,
    catalogs: &[Box<dyn SignedCatalog>],
    authority_overrides: &HashMap<String, bool>,
    custom_logs: Vec<CustomCtLog>,
) -> Result<Vec<CtLog>, LogListError> {
    // Fetch + verify every catalog concurrently.
    let fetches = catalogs.iter().map(|cat| {
        let client = client.clone();
        async move { (cat, catalog::fetch_and_verify(&client, cat.as_ref()).await) }
    });
    let results = join_all(fetches).await;

    // Merge by log_id. Value: (CtLog, runtime_authoritative). Authority is OR'd
    // across sources; the first-seen CtLog data wins (identity is stable by id).
    let mut merged: HashMap<String, (CtLog, bool)> = HashMap::new();
    let mut had_success = false;
    for (cat, res) in results {
        let fetch: CatalogFetch = match res {
            Ok(f) => f,
            Err(e) => {
                warn!(catalog_source = cat.name(), error = %e, "catalog fetch failed; continuing with remaining sources");
                continue;
            }
        };
        had_success = true;
        let authoritative =
            catalog::effective_runtime_authoritative(cat.as_ref(), &fetch, authority_overrides);
        let parsed = parse_list(&fetch.raw_bytes, cat.name());
        let parsed_count = parsed.len();
        for log in parsed {
            let Some(id) = log.log_id.clone().filter(|s| !s.is_empty()) else {
                // No usable identity — can't dedup or carry provenance. Count + skip.
                metrics::counter!(
                    "certstream_catalog_entry_skipped_total",
                    "catalog_source" => cat.name().to_string(),
                    "reason" => "missing_log_id"
                )
                .increment(1);
                continue;
            };
            merged
                .entry(id)
                .and_modify(|(_, auth)| *auth |= authoritative)
                .or_insert((log, authoritative));
        }
        info!(
            catalog_source = cat.name(),
            verified = fetch.verified,
            verifier_present = fetch.verifier_present,
            runtime_authoritative = authoritative,
            entries = parsed_count,
            "processed catalog source"
        );
    }
    if !had_success {
        return Err(LogListError::NoLogs);
    }

    // Spawn candidates: runtime-authoritative AND usable (B2a keeps upstream's
    // rejected/retired denylist; B2b tightens this to the positive allowlist).
    let candidate_logs: Vec<CtLog> = merged
        .into_values()
        .filter(|(_, authoritative)| *authoritative)
        .map(|(log, _)| log)
        .filter(|l| l.is_usable())
        .collect();
    info!(count = candidate_logs.len(), "checking CT log availability (authoritative set)");

    let health_checks: Vec<_> = candidate_logs
        .into_iter()
        .map(|log| {
            let client = client.clone();
            async move {
                if probe_log(&client, &log).await {
                    Some(log)
                } else {
                    None
                }
            }
        })
        .collect();

    let results = join_all(health_checks).await;
    let mut logs: Vec<CtLog> = results.into_iter().flatten().collect();

    let filtered_count = logs.len();
    info!(reachable = filtered_count, "CT log availability check complete");

    for custom_log in custom_logs {
        logs.push(CtLog::from(custom_log));
    }

    if logs.is_empty() {
        return Err(LogListError::NoLogs);
    }

    Ok(logs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_usable_no_state() {
        let log = make_test_log("test", "https://ct.example.com", None);
        assert!(log.is_usable());
    }

    /// Build a `LogState` with the named lifecycle keys present (others absent).
    fn mk_state(usable: bool, readonly: bool, retired: bool, rejected: bool) -> LogState {
        let si = || {
            Some(StateInfo {
                _timestamp: "2024-01-01T00:00:00Z".to_string(),
            })
        };
        LogState {
            pending: None,
            qualified: None,
            usable: if usable { si() } else { None },
            readonly: if readonly { si() } else { None },
            retired: if retired { si() } else { None },
            rejected: if rejected { si() } else { None },
            _other: HashMap::new(),
        }
    }

    #[test]
    fn test_is_usable_usable_state() {
        let log = make_test_log("test", "https://ct.example.com", Some(mk_state(true, false, false, false)));
        assert!(log.is_usable());
    }

    #[test]
    fn test_is_usable_retired() {
        let log = make_test_log("test", "https://ct.example.com", Some(mk_state(false, false, true, false)));
        assert!(!log.is_usable());
    }

    #[test]
    fn test_is_usable_rejected() {
        let log = make_test_log("test", "https://ct.example.com", Some(mk_state(false, false, false, true)));
        assert!(!log.is_usable());
    }

    #[test]
    fn test_is_usable_both_retired_and_rejected() {
        let log = make_test_log("test", "https://ct.example.com", Some(mk_state(true, false, true, true)));
        assert!(!log.is_usable());
    }

    #[test]
    fn test_normalized_url_with_https() {
        let log = make_test_log("test", "https://ct.example.com/log", None);
        assert_eq!(log.normalized_url(), "https://ct.example.com/log");
    }

    #[test]
    fn test_normalized_url_with_trailing_slash() {
        let log = make_test_log("test", "https://ct.example.com/log/", None);
        assert_eq!(log.normalized_url(), "https://ct.example.com/log");
    }

    #[test]
    fn test_normalized_url_without_scheme() {
        let log = make_test_log("test", "ct.example.com/log", None);
        assert_eq!(log.normalized_url(), "https://ct.example.com/log");
    }

    #[test]
    fn test_normalized_url_without_scheme_trailing_slash() {
        let log = make_test_log("test", "ct.example.com/log/", None);
        assert_eq!(log.normalized_url(), "https://ct.example.com/log");
    }

    #[test]
    fn test_normalized_url_http() {
        let log = make_test_log("test", "http://ct.example.com/log", None);
        assert_eq!(log.normalized_url(), "http://ct.example.com/log");
    }

    #[test]
    fn test_from_custom_ct_log() {
        let custom = CustomCtLog {
            name: "My Custom Log".to_string(),
            url: "https://custom.example.com/ct".to_string(),
            batch_size: None,
            poll_interval_ms: None,
        };
        let ct_log = CtLog::from(custom);
        assert_eq!(ct_log.description, "My Custom Log");
        assert_eq!(ct_log.url, "https://custom.example.com/ct");
        assert_eq!(ct_log.operator, "Custom");
        assert_eq!(ct_log.log_type, LogType::Rfc6962);
        assert!(ct_log.state.is_none());
    }

    #[test]
    fn test_from_static_ct_log() {
        let static_log = StaticCtLog {
            name: "LE Willow 2025h2".to_string(),
            url: "https://mon.willow.ct.letsencrypt.org/2025h2d/".to_string(),
            log_origin: Some("log.willow.ct.letsencrypt.org/2025h2d".to_string()),
            batch_size: None,
            poll_interval_ms: None,
        };
        let ct_log = CtLog::from(static_log);
        assert_eq!(ct_log.description, "LE Willow 2025h2");
        assert_eq!(
            ct_log.url,
            "https://mon.willow.ct.letsencrypt.org/2025h2d/"
        );
        assert_eq!(ct_log.operator, "Static CT");
        assert_eq!(ct_log.log_type, LogType::StaticCt);
        assert_eq!(
            ct_log.log_origin.as_deref(),
            Some("log.willow.ct.letsencrypt.org/2025h2d")
        );
        assert!(ct_log.state.is_none());
    }

    #[test]
    fn test_log_type_equality() {
        assert_eq!(LogType::Rfc6962, LogType::Rfc6962);
        assert_eq!(LogType::StaticCt, LogType::StaticCt);
        assert_ne!(LogType::Rfc6962, LogType::StaticCt);
    }

    // The static-ct origin derivation moved to `normalize::normalize_log_origin`
    // and its behavior is covered by `normalize::tests`.

    /// Apple's log list adds `assetVersionV2` and `tiled_logs` and may include
    /// operators with empty (or missing) `logs` arrays. The parser must accept
    /// all of these.
    #[test]
    fn test_parse_apple_style_log_list() {
        let json = r#"{
            "$schema": "https://example.com/schema.json",
            "assetVersion": 32,
            "assetVersionV2": 1013,
            "operators": [
                {
                    "name": "Cloudflare",
                    "email": ["ct-logs@cloudflare.com"],
                    "logs": [],
                    "tiled_logs": [
                        {
                            "description": "Cloudflare 'Raio2025h2b' log",
                            "key": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAESwiXfU4...",
                            "log_id": "Tw05u8NV28wWJ5ZuVAUVfMr3Lj90j0f+ewSeWlkVXL0=",
                            "mmd": 60,
                            "monitoring_url": "https://raio2025h2b.ct.cloudflare.com/",
                            "submission_url": "https://ct.cloudflare.com/logs/raio2025h2b/",
                            "state": {"usable": {"timestamp": "2025-07-01T00:00:00Z"}},
                            "tls_only": true
                        }
                    ]
                },
                {
                    "name": "Old Operator",
                    "logs": [
                        {
                            "description": "Old RFC6962 log",
                            "url": "https://old.example.com/ct",
                            "log_id": "abcdef==",
                            "state": {"usable": {"timestamp": "2024-01-01T00:00:00Z"}}
                        }
                    ]
                }
            ]
        }"#;
        let parsed: LogListResponse = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.operators.len(), 2);
        assert_eq!(parsed.operators[0].name, "Cloudflare");
        assert!(parsed.operators[0].logs.is_empty());
        assert_eq!(parsed.operators[0].tiled_logs.len(), 1);
        let tiled = &parsed.operators[0].tiled_logs[0];
        assert_eq!(tiled.monitoring_url, "https://raio2025h2b.ct.cloudflare.com/");
        assert_eq!(tiled.submission_url, "https://ct.cloudflare.com/logs/raio2025h2b/");
        assert_eq!(tiled.log_id.as_deref(), Some("Tw05u8NV28wWJ5ZuVAUVfMr3Lj90j0f+ewSeWlkVXL0="));

        assert_eq!(parsed.operators[1].name, "Old Operator");
        assert_eq!(parsed.operators[1].logs.len(), 1);
        assert!(parsed.operators[1].tiled_logs.is_empty());
    }

    #[test]
    fn test_parse_legacy_google_v3_no_tiled_logs() {
        // Older Google v3 responses (and minimal test fixtures) have no
        // `tiled_logs` field at all — the default must populate an empty Vec.
        let json = r#"{
            "operators": [
                {"name": "Google", "logs": [
                    {"description": "Argon2026", "url": "https://ct.googleapis.com/logs/argon2026/"}
                ]}
            ]
        }"#;
        let parsed: LogListResponse = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.operators[0].logs.len(), 1);
        assert!(parsed.operators[0].tiled_logs.is_empty());
    }

    /// parse_list: normalizes operator + origin, tolerates unknown operator/log
    /// fields and an unknown `state` enum key without crashing, and emits both
    /// an RFC-6962 and a static-CT entry.
    #[test]
    fn parse_list_normalizes_and_tolerates_unknown() {
        let json = br#"{
            "future_top_level_key": 1,
            "operators": [
                {
                    "name": "DigiCert, Inc.",
                    "some_unknown_operator_field": true,
                    "logs": [
                        {
                            "description": "DigiCert RFC6962 log",
                            "url": "ct.digicert.com/log/",
                            "log_id": "rfc-id-1",
                            "state": {"usable": {"timestamp": "2024-01-01T00:00:00Z"}},
                            "unknown_log_field": "x"
                        }
                    ],
                    "tiled_logs": [
                        {
                            "description": "DigiCert tiled log",
                            "monitoring_url": "https://mon.example.com/tiled/",
                            "submission_url": "https://ct.example.com/tiled/",
                            "log_id": "tiled-id-1",
                            "state": {"some_future_state": {"timestamp": "2024-01-01T00:00:00Z"}}
                        }
                    ]
                }
            ]
        }"#;
        let logs = parse_list(json, "test_source");
        assert_eq!(logs.len(), 2, "one RFC6962 + one static-CT entry");

        let rfc = logs.iter().find(|l| l.log_type == LogType::Rfc6962).unwrap();
        assert_eq!(rfc.operator, "digicert inc", "operator canonicalized");
        assert_eq!(rfc.url, "https://ct.digicert.com/log", "url normalized (scheme + no trailing slash)");
        assert_eq!(rfc.log_id.as_deref(), Some("rfc-id-1"));

        let tiled = logs.iter().find(|l| l.log_type == LogType::StaticCt).unwrap();
        assert_eq!(tiled.operator, "digicert inc");
        assert_eq!(tiled.url, "https://mon.example.com/tiled");
        assert_eq!(tiled.log_origin.as_deref(), Some("ct.example.com/tiled"), "origin normalized");
        // The unknown `state` enum key did not crash the parse.
    }

    /// Malformed (non-JSON) bytes yield zero entries, not a panic/abort.
    #[test]
    fn parse_list_malformed_yields_empty() {
        assert!(parse_list(b"not json at all", "test_source").is_empty());
    }
}
