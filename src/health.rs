use axum::{extract::State, http::StatusCode, Json};
use serde::Serialize;
use smallvec::smallvec;
use std::borrow::Cow;
use std::sync::Arc;

use crate::api::LogTracker;
use crate::middleware::ConnectionLimiter;
use crate::models::{
    CertificateData, CertificateMessage, ChainCert, Extensions, LeafCert, Source, Subject,
};

pub struct HealthState {
    pub log_tracker: Arc<LogTracker>,
    pub limiter: Arc<ConnectionLimiter>,
    pub started_at: std::time::Instant,
}

#[derive(Serialize)]
pub struct DeepHealthResponse {
    status: &'static str,
    logs_healthy: usize,
    logs_degraded: usize,
    logs_unhealthy: usize,
    logs_total: usize,
    active_connections: u64,
    uptime_secs: u64,
}

pub async fn health() -> &'static str {
    "OK"
}

pub async fn deep_health(
    State(state): State<Arc<HealthState>>,
) -> (StatusCode, Json<DeepHealthResponse>) {
    let (healthy, degraded, unhealthy) = state.log_tracker.count_by_status();
    let total = healthy + degraded + unhealthy;
    let connections = state.limiter.current_connections() as u64;
    let uptime = state.started_at.elapsed().as_secs();

    let status = if unhealthy > total / 2 {
        "unhealthy"
    } else if degraded > 0 || unhealthy > 0 {
        "degraded"
    } else {
        "healthy"
    };

    let code = if status == "unhealthy" {
        StatusCode::SERVICE_UNAVAILABLE
    } else {
        StatusCode::OK
    };

    (
        code,
        Json(DeepHealthResponse {
            status,
            logs_healthy: healthy,
            logs_degraded: degraded,
            logs_unhealthy: unhealthy,
            logs_total: total,
            active_connections: connections,
            uptime_secs: uptime,
        }),
    )
}

/// Returns an example certificate JSON for API documentation.
pub async fn example_json() -> Json<CertificateMessage> {
    let mut subject = Subject {
        cn: Some("example.com".to_string()),
        o: Some("Example Organization".to_string()),
        c: Some("US".to_string()),
        ..Default::default()
    };
    subject.build_aggregated();

    let mut issuer = Subject {
        cn: Some("Example CA".to_string()),
        o: Some("Example Certificate Authority".to_string()),
        c: Some("US".to_string()),
        ..Default::default()
    };
    issuer.build_aggregated();

    let mut chain_issuer = Subject {
        cn: Some("Root CA".to_string()),
        o: Some("Example Root Authority".to_string()),
        ..Default::default()
    };
    chain_issuer.build_aggregated();

    let extensions = Extensions {
        key_usage: Some("Digital Signature, Key Encipherment".to_string()),
        extended_key_usage: Some("serverAuth, clientAuth".to_string()),
        basic_constraints: Some("CA:FALSE".to_string()),
        subject_alt_name: Some(
            "DNS:example.com, DNS:www.example.com, DNS:*.example.com".to_string(),
        ),
        ..Default::default()
    };

    let chain_extensions = Extensions {
        key_usage: Some("Certificate Signing, CRL Signing".to_string()),
        basic_constraints: Some("CA:TRUE".to_string()),
        ..Default::default()
    };

    let example = CertificateMessage {
        message_type: Cow::Borrowed("certificate_update"),
        data: CertificateData {
            update_type: Cow::Borrowed("X509LogEntry"),
            leaf_cert: Arc::new(LeafCert {
                subject: subject.clone(),
                issuer: issuer.clone(),
                serial_number: "0123456789ABCDEF".to_string(),
                not_before: 1704067200,
                not_after: 1735689600,
                fingerprint: Arc::from("AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01"),
                sha1: "AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01".to_string(),
                sha256: "AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89".to_string(),
                sha256_raw: [0u8; 32],
                signature_algorithm: Cow::Borrowed("sha256, rsa"),
                is_ca: false,
                all_domains: smallvec![
                    "example.com".to_string(),
                    "www.example.com".to_string(),
                    "*.example.com".to_string(),
                ],
                as_der: Some("BASE64_ENCODED_DER_DATA".to_string()),
                extensions,
            }),
            chain: Some(vec![ChainCert {
                subject: issuer,
                issuer: chain_issuer,
                serial_number: "00112233445566".to_string(),
                not_before: 1672531200,
                not_after: 1767225600,
                fingerprint: Arc::from("11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44"),
                sha1: "11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44".to_string(),
                sha256: "11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00".to_string(),
                signature_algorithm: Cow::Borrowed("sha256, rsa"),
                is_ca: true,
                as_der: Some("BASE64_ENCODED_CA_DER".to_string()),
                extensions: chain_extensions,
            }]),
            cert_index: 123456789,
            cert_link: "https://ct.googleapis.com/logs/us1/argon2025h2/ct/v1/get-entries?start=123456789&end=123456789".to_string(),
            seen: 1704067200.123,
            submission_timestamp: 1704000000.0,
            source: Arc::new(Source {
                name: Arc::from("Google 'Argon2024' log"),
                url: Arc::from("https://ct.googleapis.com/logs/argon2024"),
            }),
        },
    };

    Json(example)
}
