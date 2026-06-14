use reqwest::header::HeaderMap;
use tracing::warn;

use super::watcher::LogHealth;

const MIN_RETRY_AFTER_MS: u64 = 250;
const MAX_RETRY_AFTER_MS: u64 = 10 * 60 * 1000;

pub(super) fn source_id(log_id: Option<&str>, normalized_url: &str) -> String {
    match log_id.filter(|id| !id.is_empty()) {
        Some(id) => format!("ctlog:{id}"),
        None => format!("url:{normalized_url}"),
    }
}

pub(super) fn parse_retry_after(headers: &HeaderMap, log_description: &str) -> u64 {
    let Some(header) = headers.get("retry-after") else {
        return LogHealth::RATE_LIMIT_BACKOFF_MS;
    };

    let Some(requested_ms) = header
        .to_str()
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .map(|secs| secs.saturating_mul(1_000))
    else {
        metrics::counter!(
            "certstream_input_parse_rejected_total",
            "field" => "retry_after",
            "reason" => "unparseable"
        )
        .increment(1);
        return LogHealth::RATE_LIMIT_BACKOFF_MS;
    };

    if requested_ms > MAX_RETRY_AFTER_MS {
        metrics::counter!(
            "certstream_input_clamp_total",
            "field" => "retry_after",
            "direction" => "max"
        )
        .increment(1);
        warn!(
            log = %log_description,
            requested_ms,
            clamped_ms = MAX_RETRY_AFTER_MS,
            "Retry-After exceeds cap, clamping"
        );
        MAX_RETRY_AFTER_MS
    } else if requested_ms < MIN_RETRY_AFTER_MS {
        metrics::counter!(
            "certstream_input_clamp_total",
            "field" => "retry_after",
            "direction" => "min"
        )
        .increment(1);
        warn!(
            log = %log_description,
            requested_ms,
            clamped_ms = MIN_RETRY_AFTER_MS,
            "Retry-After below floor, clamping"
        );
        MIN_RETRY_AFTER_MS
    } else {
        requested_ms
    }
}

/// Canonicalize a CT Log Provider operator name for keying. Lowercases, trims,
/// collapses internal whitespace to a single space, and drops punctuation. So
/// `"DigiCert, Inc."` and `"DigiCert Inc"` resolve to the same operator slot.
pub fn normalize_operator(operator: &str) -> String {
    let mut out = String::with_capacity(operator.len());
    let mut pending_space = false;
    for c in operator.chars() {
        if c.is_whitespace() {
            // Defer the separator so leading/trailing/internal runs collapse.
            if !out.is_empty() {
                pending_space = true;
            }
        } else if c.is_alphanumeric() {
            if pending_space {
                out.push(' ');
                pending_space = false;
            }
            out.extend(c.to_lowercase());
        }
        // Punctuation (',', '.', '(', ')', '\'', …) is dropped, NOT treated as
        // a separator — "DigiCert, Inc" and "DigiCert Inc" must coincide.
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::header::{HeaderMap, HeaderValue};

    fn header(value: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert("retry-after", HeaderValue::from_str(value).unwrap());
        h
    }

    #[test]
    fn absent_header_uses_default_rate_limit_backoff() {
        assert_eq!(
            parse_retry_after(&HeaderMap::new(), "test-log"),
            LogHealth::RATE_LIMIT_BACKOFF_MS
        );
    }

    #[test]
    fn valid_integer_seconds_converted_to_milliseconds() {
        assert_eq!(parse_retry_after(&header("5"), "test-log"), 5_000);
    }

    #[test]
    fn value_over_cap_clamps_to_maximum() {
        assert_eq!(
            parse_retry_after(&header("86400"), "test-log"),
            MAX_RETRY_AFTER_MS
        );
    }

    #[test]
    fn zero_clamps_to_minimum_floor() {
        assert_eq!(
            parse_retry_after(&header("0"), "test-log"),
            MIN_RETRY_AFTER_MS
        );
    }

    #[test]
    fn http_date_form_uses_default_rate_limit_backoff() {
        assert_eq!(
            parse_retry_after(&header("Wed, 21 Oct 2026 07:28:00 GMT"), "test-log"),
            LogHealth::RATE_LIMIT_BACKOFF_MS
        );
    }

    #[test]
    fn source_id_prefers_non_empty_log_id() {
        assert_eq!(
            source_id(Some("abc123"), "https://ct.example.com/log"),
            "ctlog:abc123"
        );
    }

    #[test]
    fn source_id_falls_back_to_url_when_log_id_absent_or_empty() {
        assert_eq!(
            source_id(None, "https://ct.example.com/log"),
            "url:https://ct.example.com/log"
        );
        assert_eq!(
            source_id(Some(""), "https://ct.example.com/log"),
            "url:https://ct.example.com/log"
        );
    }

    #[test]
    fn normalize_operator_collapses_case_whitespace_punctuation() {
        assert_eq!(normalize_operator("DigiCert, Inc."), "digicert inc");
        assert_eq!(normalize_operator("digicert inc"), "digicert inc");
        assert_eq!(normalize_operator("  DigiCert   Inc  "), "digicert inc");
        assert_eq!(normalize_operator("Let's Encrypt"), "lets encrypt");
    }
}
