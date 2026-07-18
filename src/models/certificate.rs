use axum::extract::ws::Utf8Bytes;
use serde::{Deserialize, Serialize};
use smallvec::SmallVec;
use std::borrow::Cow;
use std::sync::Arc;

use crate::config::StreamConfig;

pub type DomainList = SmallVec<[String; 4]>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateMessage {
    pub message_type: Cow<'static, str>,
    pub data: CertificateData,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateData {
    pub update_type: Cow<'static, str>,
    pub leaf_cert: Arc<LeafCert>,
    /// Chain certs are `Arc`-shared: static-CT watchers reuse one parsed
    /// issuer across every leaf that chains to it (serde's `rc` feature
    /// serializes through the Arc transparently).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub chain: Option<Vec<Arc<ChainCert>>>,
    pub cert_index: u64,
    pub cert_link: String,
    pub seen: f64,
    /// Submission timestamp: the moment the CT log issued the SCT for this entry
    /// (RFC 6962 §3.1), in seconds since Unix epoch with millisecond precision.
    pub submission_timestamp: f64,
    pub source: Arc<Source>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Subject {
    #[serde(rename = "C", skip_serializing_if = "Option::is_none")]
    pub c: Option<String>,
    #[serde(rename = "CN", skip_serializing_if = "Option::is_none")]
    pub cn: Option<String>,
    #[serde(rename = "L", skip_serializing_if = "Option::is_none")]
    pub l: Option<String>,
    #[serde(rename = "O", skip_serializing_if = "Option::is_none")]
    pub o: Option<String>,
    #[serde(rename = "OU", skip_serializing_if = "Option::is_none")]
    pub ou: Option<String>,
    #[serde(rename = "ST", skip_serializing_if = "Option::is_none")]
    pub st: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aggregated: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_address: Option<String>,
}

impl Subject {
    pub fn build_aggregated(&mut self) {
        let mut agg = String::new();
        if let Some(ref c) = self.c {
            agg.push_str("/C=");
            agg.push_str(c);
        }
        if let Some(ref cn) = self.cn {
            agg.push_str("/CN=");
            agg.push_str(cn);
        }
        if let Some(ref l) = self.l {
            agg.push_str("/L=");
            agg.push_str(l);
        }
        if let Some(ref o) = self.o {
            agg.push_str("/O=");
            agg.push_str(o);
        }
        if let Some(ref ou) = self.ou {
            agg.push_str("/OU=");
            agg.push_str(ou);
        }
        if let Some(ref st) = self.st {
            agg.push_str("/ST=");
            agg.push_str(st);
        }
        self.aggregated = Some(agg);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Extensions {
    #[serde(rename = "authorityInfoAccess", skip_serializing_if = "Option::is_none")]
    pub authority_info_access: Option<String>,
    #[serde(rename = "authorityKeyIdentifier", skip_serializing_if = "Option::is_none")]
    pub authority_key_identifier: Option<String>,
    #[serde(rename = "basicConstraints", skip_serializing_if = "Option::is_none")]
    pub basic_constraints: Option<String>,
    #[serde(rename = "certificatePolicies", skip_serializing_if = "Option::is_none")]
    pub certificate_policies: Option<String>,
    #[serde(rename = "ctlSignedCertificateTimestamp", skip_serializing_if = "Option::is_none")]
    pub ctl_signed_certificate_timestamp: Option<String>,
    #[serde(rename = "extendedKeyUsage", skip_serializing_if = "Option::is_none")]
    pub extended_key_usage: Option<String>,
    #[serde(rename = "keyUsage", skip_serializing_if = "Option::is_none")]
    pub key_usage: Option<String>,
    #[serde(rename = "subjectAltName", skip_serializing_if = "Option::is_none")]
    pub subject_alt_name: Option<String>,
    #[serde(rename = "subjectKeyIdentifier", skip_serializing_if = "Option::is_none")]
    pub subject_key_identifier: Option<String>,
    #[serde(rename = "ctlPoisonByte", skip_serializing_if = "is_false", default)]
    pub ctl_poison_byte: bool,
}

fn is_false(b: &bool) -> bool {
    !*b
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeafCert {
    pub subject: Subject,
    pub issuer: Subject,
    pub serial_number: String,
    pub not_before: i64,
    pub not_after: i64,
    /// Issue #12: Arc<str> shared with `sha1` — fingerprint IS sha1; no duplicate heap allocation.
    pub fingerprint: Arc<str>,
    pub sha1: String,
    pub sha256: String,
    /// Raw SHA-256 bytes — used as the zero-alloc dedup key. Skipped in JSON.
    #[serde(skip)]
    pub sha256_raw: [u8; 32],
    pub signature_algorithm: Cow<'static, str>,
    pub is_ca: bool,
    pub all_domains: DomainList,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub as_der: Option<String>,
    pub extensions: Extensions,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainCert {
    pub subject: Subject,
    pub issuer: Subject,
    pub serial_number: String,
    pub not_before: i64,
    pub not_after: i64,
    pub fingerprint: Arc<str>,
    pub sha1: String,
    pub sha256: String,
    pub signature_algorithm: Cow<'static, str>,
    pub is_ca: bool,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub as_der: Option<String>,
    pub extensions: Extensions,
}

impl From<LeafCert> for ChainCert {
    /// A chain cert is a leaf-cert parse minus the leaf-only fields
    /// (`all_domains`, `sha256_raw`). Shared by the RFC 6962 chain parser and
    /// the static-CT issuer cache so the field mapping lives in one place.
    fn from(leaf: LeafCert) -> Self {
        ChainCert {
            subject: leaf.subject,
            issuer: leaf.issuer,
            serial_number: leaf.serial_number,
            not_before: leaf.not_before,
            not_after: leaf.not_after,
            fingerprint: leaf.fingerprint,
            sha1: leaf.sha1,
            sha256: leaf.sha256,
            signature_algorithm: leaf.signature_algorithm,
            is_ca: leaf.is_ca,
            as_der: leaf.as_der,
            extensions: leaf.extensions,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Source {
    pub name: Arc<str>,
    pub url: Arc<str>,
}

/// Borrow-based like `LiteMessage` — serializing the domains_only stream
/// must not clone every domain String per certificate.
#[derive(Debug, Clone, Serialize)]
pub struct DomainsOnlyMessage<'a> {
    pub message_type: Cow<'static, str>,
    pub data: &'a DomainList,
}

/// Payloads carry the UTF-8 invariant (`Utf8Bytes` wraps shared `Bytes`), so
/// WS/SSE fan-out is a pure refcount bump per client — the O(n) UTF-8 scan
/// happens once here at serialize time, not once per subscriber per message.
#[derive(Debug, Clone)]
pub struct PreSerializedMessage {
    pub full: Utf8Bytes,
    pub lite: Utf8Bytes,
    pub domains_only: Utf8Bytes,
}

/// Serialize any `Serialize` value to JSON bytes.
///
/// Backend precedence (each gated by Cargo feature):
///   1. `sonic` → cloudwego/sonic-rs (fastest; subtly different edge-case
///      semantics — see the `sonic` feature comment in Cargo.toml for the
///      full list, but tl;dr: NaN/Infinity emitted as non-standard tokens,
///      some Unicode escaping differences. Default OFF.)
///   2. `simd` → simd-json (default ON).
///   3. neither → serde_json (always-available fallback; required when both
///      `simd` and `sonic` are disabled).
///
/// All three produce identical JSON bytes for the payloads this crate emits
/// (cert metadata: integers, monotonic timestamps as f64, ASCII/UTF-8 strings).
/// The differences only surface for edge-case values that certstream-server
/// never constructs.
#[inline]
fn serialize_json<T: Serialize>(value: &T, _capacity_hint: usize) -> Option<Vec<u8>> {
    #[cfg(feature = "sonic")]
    {
        sonic_rs::to_vec(value).ok()
    }
    #[cfg(all(feature = "simd", not(feature = "sonic")))]
    {
        simd_json::to_vec(value).ok()
    }
    #[cfg(not(any(feature = "simd", feature = "sonic")))]
    {
        let mut buf = Vec::with_capacity(_capacity_hint);
        serde_json::to_writer(&mut buf, value).ok()?;
        Some(buf)
    }
}

/// Serialize to a `Utf8Bytes`, validating UTF-8 exactly once. Serde output is
/// always valid UTF-8, so the validation cannot fail in practice; `None` on
/// the impossible path keeps the caller's existing skip semantics.
#[inline]
fn serialize_utf8<T: Serialize>(value: &T, capacity_hint: usize) -> Option<Utf8Bytes> {
    let s = String::from_utf8(serialize_json(value, capacity_hint)?).ok()?;
    Some(Utf8Bytes::from(s))
}

impl PreSerializedMessage {
    pub fn from_certificate(msg: &CertificateMessage, streams: &StreamConfig) -> Option<Self> {
        let full = if streams.full {
            serialize_utf8(msg, 4096)?
        } else {
            Utf8Bytes::from_static("")
        };

        let lite = if streams.lite {
            serialize_utf8(&msg.to_lite(), 2048)?
        } else {
            Utf8Bytes::from_static("")
        };

        let domains_only = if streams.domains_only {
            serialize_utf8(&msg.to_domains_only(), 512)?
        } else {
            Utf8Bytes::from_static("")
        };

        Some(Self {
            full,
            lite,
            domains_only,
        })
    }
}

#[derive(Debug, Clone, Serialize)]
struct LiteMessage<'a> {
    message_type: &'a Cow<'static, str>,
    data: LiteData<'a>,
}

#[derive(Debug, Clone, Serialize)]
struct LiteData<'a> {
    update_type: &'a Cow<'static, str>,
    leaf_cert: LiteLeafCert<'a>,
    cert_index: u64,
    cert_link: &'a str,
    seen: f64,
    submission_timestamp: f64,
    source: &'a Arc<Source>,
}

#[derive(Debug, Clone, Serialize)]
struct LiteLeafCert<'a> {
    subject: &'a Subject,
    issuer: &'a Subject,
    serial_number: &'a str,
    not_before: i64,
    not_after: i64,
    fingerprint: &'a str,
    sha1: &'a str,
    sha256: &'a str,
    signature_algorithm: &'a str,
    is_ca: bool,
    all_domains: &'a DomainList,
    extensions: &'a Extensions,
}

impl CertificateMessage {
    pub fn to_domains_only(&self) -> DomainsOnlyMessage<'_> {
        DomainsOnlyMessage {
            message_type: Cow::Borrowed("dns_entries"),
            data: &self.data.leaf_cert.all_domains,
        }
    }

    fn to_lite(&self) -> LiteMessage<'_> {
        LiteMessage {
            message_type: &self.message_type,
            data: LiteData {
                update_type: &self.data.update_type,
                leaf_cert: LiteLeafCert {
                    subject: &self.data.leaf_cert.subject,
                    issuer: &self.data.leaf_cert.issuer,
                    serial_number: &self.data.leaf_cert.serial_number,
                    not_before: self.data.leaf_cert.not_before,
                    not_after: self.data.leaf_cert.not_after,
                    fingerprint: &self.data.leaf_cert.fingerprint,
                    sha1: &self.data.leaf_cert.sha1,
                    sha256: &self.data.leaf_cert.sha256,
                    signature_algorithm: self.data.leaf_cert.signature_algorithm.as_ref(),
                    is_ca: self.data.leaf_cert.is_ca,
                    all_domains: &self.data.leaf_cert.all_domains,
                    extensions: &self.data.leaf_cert.extensions,
                },
                cert_index: self.data.cert_index,
                cert_link: &self.data.cert_link,
                seen: self.data.seen,
                submission_timestamp: self.data.submission_timestamp,
                source: &self.data.source,
            },
        }
    }

    #[inline]
    pub fn pre_serialize(self, streams: &StreamConfig) -> Option<Arc<PreSerializedMessage>> {
        PreSerializedMessage::from_certificate(&self, streams).map(Arc::new)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use smallvec::smallvec;
    use std::borrow::Cow;
    use std::sync::Arc;

    fn make_test_message() -> CertificateMessage {
        CertificateMessage {
            message_type: Cow::Borrowed("certificate_update"),
            data: CertificateData {
                update_type: Cow::Borrowed("X509LogEntry"),
                leaf_cert: Arc::new(LeafCert {
                    subject: Subject {
                        cn: Some("example.com".into()),
                        ..Default::default()
                    },
                    issuer: Subject {
                        cn: Some("Test CA".into()),
                        ..Default::default()
                    },
                    serial_number: "01".into(),
                    not_before: 1700000000,
                    not_after: 1730000000,
                    fingerprint: "AA:BB".into(),
                    sha1: "CC:DD".into(),
                    sha256: "EE:FF".into(),
                    sha256_raw: [0u8; 32],
                    signature_algorithm: Cow::Borrowed("sha256, rsa"),
                    is_ca: false,
                    all_domains: smallvec!["example.com".into(), "www.example.com".into()],
                    as_der: None,
                    extensions: Extensions::default(),
                }),
                chain: None,
                cert_index: 12345,
                cert_link: "https://ct.example.com/entry/12345".into(),
                seen: 1700000000.0,
                submission_timestamp: 1700000000.0,
                source: Arc::new(Source {
                    name: Arc::from("Test Log"),
                    url: Arc::from("https://ct.example.com/"),
                }),
            },
        }
    }

    #[test]
    fn test_build_aggregated_all_fields() {
        let mut subject = Subject {
            c: Some("US".into()),
            cn: Some("example.com".into()),
            l: Some("City".into()),
            o: Some("Org".into()),
            ou: Some("Unit".into()),
            st: Some("State".into()),
            aggregated: None,
            email_address: None,
        };
        subject.build_aggregated();
        assert_eq!(
            subject.aggregated.as_deref(),
            Some("/C=US/CN=example.com/L=City/O=Org/OU=Unit/ST=State")
        );
    }

    #[test]
    fn test_build_aggregated_only_cn() {
        let mut subject = Subject {
            cn: Some("example.com".into()),
            ..Default::default()
        };
        subject.build_aggregated();
        assert_eq!(subject.aggregated.as_deref(), Some("/CN=example.com"));
    }

    #[test]
    fn test_build_aggregated_empty_subject() {
        let mut subject = Subject::default();
        subject.build_aggregated();
        assert_eq!(subject.aggregated.as_deref(), Some(""));
    }

    #[test]
    fn test_to_domains_only_message_type() {
        let msg = make_test_message();
        let domains_msg = msg.to_domains_only();
        assert_eq!(domains_msg.message_type, "dns_entries");
    }

    #[test]
    fn test_to_domains_only_contains_correct_domains() {
        let msg = make_test_message();
        let domains_msg = msg.to_domains_only();
        assert_eq!(domains_msg.data.len(), 2);
        assert_eq!(domains_msg.data[0], "example.com");
        assert_eq!(domains_msg.data[1], "www.example.com");
    }

    #[test]
    fn test_pre_serialize_returns_some() {
        let msg = make_test_message();
        let result = msg.pre_serialize(&StreamConfig::default());
        assert!(result.is_some());
    }

    #[test]
    fn test_pre_serialize_full_contains_certificate_update() {
        let msg = make_test_message();
        let pre = msg.pre_serialize(&StreamConfig::default()).unwrap();
        let full_str = pre.full.as_str();
        assert!(full_str.contains("certificate_update"));
    }

    #[test]
    fn test_pre_serialize_lite_does_not_contain_chain() {
        let msg = make_test_message();
        let pre = msg.pre_serialize(&StreamConfig::default()).unwrap();
        let lite_str = pre.lite.as_str();
        assert!(!lite_str.contains("\"chain\""));
    }

    #[test]
    fn test_pre_serialize_domains_contains_dns_entries() {
        let msg = make_test_message();
        let pre = msg.pre_serialize(&StreamConfig::default()).unwrap();
        let domains_str = pre.domains_only.as_str();
        assert!(domains_str.contains("dns_entries"));
    }

    #[test]
    fn test_is_false_with_true_value() {
        assert!(!is_false(&true));
    }

    #[test]
    fn test_is_false_with_false_value() {
        assert!(is_false(&false));
    }
}
