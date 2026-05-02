use crate::config::{CustomCtLog, StaticCtLog};
use futures::future::join_all;
use reqwest::Client;
use serde::Deserialize;
use std::collections::HashSet;
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
struct Operator {
    name: String,
    #[serde(default)]
    logs: Vec<RawCtLog>,
    /// Apple's log list (and Google's v3 starting in 2026) carry static-ct-api endpoints
    /// here. Older Google lists omit the field, hence the default. Operators that only
    /// run tiled logs may also have an empty `logs` array.
    #[serde(default)]
    tiled_logs: Vec<RawTiledLog>,
}

#[derive(Debug, Deserialize)]
struct RawCtLog {
    description: String,
    url: String,
    #[serde(default)]
    log_id: Option<String>,
    #[serde(default)]
    state: Option<LogState>,
}

/// Schema for a static-ct-api / Sunlight log entry as it appears in Apple's
/// `current_log_list.json` and Google's v3 list. The submission URL doubles as
/// the checkpoint origin (schema-less, trailing-slash-stripped).
#[derive(Debug, Deserialize)]
struct RawTiledLog {
    description: String,
    monitoring_url: String,
    submission_url: String,
    #[serde(default)]
    log_id: Option<String>,
    #[serde(default)]
    state: Option<LogState>,
}

#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
struct LogState {
    #[serde(default)]
    usable: Option<StateInfo>,
    #[serde(default)]
    readonly: Option<StateInfo>,
    #[serde(default)]
    retired: Option<StateInfo>,
    #[serde(default)]
    rejected: Option<StateInfo>,
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
#[allow(dead_code)]
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
            state: None,
        }
    }
}

/// Strip scheme and trailing slash to produce the static-ct-api checkpoint origin
/// (matches the spec's "submission prefix as schema-less URL with no trailing slashes").
fn submission_url_to_origin(submission_url: &str) -> String {
    submission_url
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .trim_end_matches('/')
        .to_string()
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

/// Fetch a log list URL and parse it into raw `CtLog` candidates (no health
/// check applied — caller is responsible for probing). The resulting vector
/// contains both RFC 6962 entries (from `operators[].logs`) and static-CT
/// entries (from `operators[].tiled_logs`), each tagged with their operator.
async fn fetch_one_list(client: &Client, url: &str) -> Result<Vec<CtLog>, LogListError> {
    let response: LogListResponse = client.get(url).send().await?.json().await?;
    let mut out = Vec::new();
    for op in response.operators {
        let operator_name = op.name;
        for raw in op.logs {
            out.push(CtLog {
                description: raw.description,
                url: raw.url,
                operator: operator_name.clone(),
                log_type: LogType::Rfc6962,
                log_origin: None,
                log_id: raw.log_id,
                state: raw.state,
            });
        }
        for raw in op.tiled_logs {
            let origin = submission_url_to_origin(&raw.submission_url);
            out.push(CtLog {
                description: raw.description,
                url: raw.monitoring_url,
                operator: operator_name.clone(),
                log_type: LogType::StaticCt,
                log_origin: Some(origin),
                log_id: raw.log_id,
                state: raw.state,
            });
        }
    }
    Ok(out)
}

/// Discover CT logs from one or more log-list URLs and append the user's custom
/// and static logs. Logs appearing in multiple lists are deduped by `log_id`
/// (first occurrence wins). All discovered logs are health-probed in parallel;
/// custom and static logs are appended without probing on the assumption they
/// were configured intentionally.
pub async fn fetch_log_list(
    client: &Client,
    primary_url: &str,
    additional_urls: &[String],
    custom_logs: Vec<CustomCtLog>,
) -> Result<Vec<CtLog>, LogListError> {
    // Issue all list fetches concurrently — Apple and Google can be served at
    // once instead of sequentially, halving startup latency on a warm cache.
    let mut all_urls: Vec<String> = vec![primary_url.to_string()];
    all_urls.extend(additional_urls.iter().cloned());
    let fetches = all_urls.iter().map(|u| {
        let c = client.clone();
        let url = u.clone();
        async move { (url.clone(), fetch_one_list(&c, &url).await) }
    });
    let results = join_all(fetches).await;

    let mut candidates: Vec<CtLog> = Vec::new();
    let mut seen_ids: HashSet<String> = HashSet::new();
    let mut had_success = false;
    for (url, res) in results {
        match res {
            Ok(logs) => {
                had_success = true;
                let raw_count = logs.len();
                let mut added = 0usize;
                for log in logs {
                    if let Some(ref id) = log.log_id
                        && !seen_ids.insert(id.clone())
                    {
                        continue;
                    }
                    candidates.push(log);
                    added += 1;
                }
                info!(url = %url, total = raw_count, deduped = added, "fetched log list");
            }
            Err(e) => {
                warn!(url = %url, error = %e, "failed to fetch log list, continuing with remaining sources");
            }
        }
    }
    if !had_success {
        return Err(LogListError::NoLogs);
    }

    let candidate_logs: Vec<CtLog> = candidates.into_iter().filter(|l| l.is_usable()).collect();
    info!(count = candidate_logs.len(), "checking CT log availability");

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

    #[test]
    fn test_is_usable_usable_state() {
        let state = LogState {
            usable: Some(StateInfo {
                _timestamp: "2024-01-01T00:00:00Z".to_string(),
            }),
            readonly: None,
            retired: None,
            rejected: None,
        };
        let log = make_test_log("test", "https://ct.example.com", Some(state));
        assert!(log.is_usable());
    }

    #[test]
    fn test_is_usable_retired() {
        let state = LogState {
            usable: None,
            readonly: None,
            retired: Some(StateInfo {
                _timestamp: "2024-01-01T00:00:00Z".to_string(),
            }),
            rejected: None,
        };
        let log = make_test_log("test", "https://ct.example.com", Some(state));
        assert!(!log.is_usable());
    }

    #[test]
    fn test_is_usable_rejected() {
        let state = LogState {
            usable: None,
            readonly: None,
            retired: None,
            rejected: Some(StateInfo {
                _timestamp: "2024-01-01T00:00:00Z".to_string(),
            }),
        };
        let log = make_test_log("test", "https://ct.example.com", Some(state));
        assert!(!log.is_usable());
    }

    #[test]
    fn test_is_usable_both_retired_and_rejected() {
        let state = LogState {
            usable: Some(StateInfo {
                _timestamp: "2023-01-01T00:00:00Z".to_string(),
            }),
            readonly: None,
            retired: Some(StateInfo {
                _timestamp: "2024-01-01T00:00:00Z".to_string(),
            }),
            rejected: Some(StateInfo {
                _timestamp: "2024-06-01T00:00:00Z".to_string(),
            }),
        };
        let log = make_test_log("test", "https://ct.example.com", Some(state));
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

    #[test]
    fn test_submission_url_to_origin_strips_https_and_slash() {
        assert_eq!(
            submission_url_to_origin("https://ct.cloudflare.com/logs/raio2025h2b/"),
            "ct.cloudflare.com/logs/raio2025h2b"
        );
    }

    #[test]
    fn test_submission_url_to_origin_no_trailing() {
        assert_eq!(
            submission_url_to_origin("https://log.sycamore.ct.letsencrypt.org/2026h1"),
            "log.sycamore.ct.letsencrypt.org/2026h1"
        );
    }

    #[test]
    fn test_submission_url_to_origin_http() {
        assert_eq!(
            submission_url_to_origin("http://example.test/foo/"),
            "example.test/foo"
        );
    }

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
}
