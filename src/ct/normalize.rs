use reqwest::header::HeaderMap;
use tracing::warn;

use super::watcher::LogHealth;

const MIN_RETRY_AFTER_MS: u64 = 250;
const MAX_RETRY_AFTER_MS: u64 = 10 * 60 * 1000;

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
}
