use crate::config::{CustomCtLog, StaticCtLog};
use futures::future::join_all;
use reqwest::Client;
use serde::Deserialize;
use std::time::Duration;
use thiserror::Error;
use tracing::{debug, info};

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
    logs: Vec<RawCtLog>,
}

#[derive(Debug, Deserialize)]
struct RawCtLog {
    description: String,
    url: String,
    #[serde(default)]
    state: Option<LogState>,
}

#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
struct LogState {
    #[serde(default)]
    usable: Option<StateInfo>,
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
        state,
    }
}

pub async fn fetch_log_list(
    client: &Client,
    url: &str,
    custom_logs: Vec<CustomCtLog>,
) -> Result<Vec<CtLog>, LogListError> {
    let response: LogListResponse = client.get(url).send().await?.json().await?;

    let candidate_logs: Vec<CtLog> = response
        .operators
        .into_iter()
        .flat_map(|op| {
            let operator_name = op.name;
            op.logs.into_iter().map(move |log| CtLog {
                description: log.description,
                url: log.url,
                operator: operator_name.clone(),
                log_type: LogType::Rfc6962,
                log_origin: None,
                state: log.state,
            })
        })
        .filter(|log| log.is_usable())
        .collect();

    info!(count = candidate_logs.len(), "checking CT log availability");

    let health_checks: Vec<_> = candidate_logs
        .into_iter()
        .map(|log| {
            let client = client.clone();
            async move {
                let sth_url = format!("{}/ct/v1/get-sth", log.normalized_url());
                match client
                    .get(&sth_url)
                    .timeout(Duration::from_secs(5))
                    .send()
                    .await
                {
                    Ok(resp) if resp.status().is_success() => Some(log),
                    Ok(resp) => {
                        debug!(log = %log.description, status = %resp.status(), "log not reachable");
                        None
                    }
                    Err(_) => {
                        debug!(log = %log.description, "log not reachable");
                        None
                    }
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
}
