use ahash::AHashSet;
use base64::{engine::general_purpose::STANDARD, Engine};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::borrow::Cow;
use std::fmt::Write;
use std::net::IpAddr;
use std::sync::Arc;
use x509_parser::der_parser::oid;
use x509_parser::extensions::ParsedExtension;
use x509_parser::oid_registry::Oid;
use x509_parser::prelude::*;

use crate::models::{ChainCert, DomainList, Extensions, LeafCert, Subject};

// Issue #6: OID constants for DN attributes — compared directly, no string allocation.
const OID_CN: Oid<'static> = oid!(2.5.4.3);
const OID_C: Oid<'static> = oid!(2.5.4.6);
const OID_L: Oid<'static> = oid!(2.5.4.7);
const OID_ST: Oid<'static> = oid!(2.5.4.8);
const OID_O: Oid<'static> = oid!(2.5.4.10);
const OID_OU: Oid<'static> = oid!(2.5.4.11);
const OID_EMAIL: Oid<'static> = oid!(1.2.840.113549.1.9.1);

// Issue #7: OID constants for signature algorithms.
const OID_MD2_RSA: Oid<'static> = oid!(1.2.840.113549.1.1.2);
const OID_MD5_RSA: Oid<'static> = oid!(1.2.840.113549.1.1.4);
const OID_SHA1_RSA: Oid<'static> = oid!(1.2.840.113549.1.1.5);
const OID_SHA256_RSA: Oid<'static> = oid!(1.2.840.113549.1.1.11);
const OID_SHA384_RSA: Oid<'static> = oid!(1.2.840.113549.1.1.12);
const OID_SHA512_RSA: Oid<'static> = oid!(1.2.840.113549.1.1.13);
const OID_SHA256_RSA_PSS: Oid<'static> = oid!(1.2.840.113549.1.1.10);
const OID_DSA_SHA1: Oid<'static> = oid!(1.2.840.10040.4.3);
const OID_DSA_SHA256: Oid<'static> = oid!(2.16.840.1.101.3.4.3.2);
const OID_ECDSA_SHA1: Oid<'static> = oid!(1.2.840.10045.4.1);
const OID_ECDSA_SHA256: Oid<'static> = oid!(1.2.840.10045.4.3.2);
const OID_ECDSA_SHA384: Oid<'static> = oid!(1.2.840.10045.4.3.3);
const OID_ECDSA_SHA512: Oid<'static> = oid!(1.2.840.10045.4.3.4);
const OID_ED25519: Oid<'static> = oid!(1.3.101.112);

pub struct ParsedEntry {
    pub update_type: Cow<'static, str>,
    pub leaf_cert: LeafCert,
    /// CT log timestamp from the leaf_input MerkleTreeLeaf structure (RFC 6962).
    /// Bytes 2–9 of the decoded leaf_input, interpreted as a uint64 big-endian
    /// milliseconds value, converted to seconds with millisecond precision.
    pub timestamp: f64,
    /// Raw extra_data bytes and the offset where chain parsing should begin.
    /// Chain parsing is deferred so that duplicate certificates (caught by the
    /// dedup filter) never pay the cost of DER-parsing 2-4 chain certs.
    chain_extra_bytes: Vec<u8>,
    chain_offset: usize,
}

impl ParsedEntry {
    /// Parse the certificate chain from the stored extra_data.
    /// Call this only after confirming the leaf cert passes dedup filtering.
    pub fn parse_chain(&self) -> Vec<ChainCert> {
        parse_chain_from_bytes(&self.chain_extra_bytes, self.chain_offset)
    }
}

pub fn parse_leaf_input(leaf_input: &str, extra_data: &str) -> Option<ParsedEntry> {
    let leaf_bytes = STANDARD.decode(leaf_input).ok()?;
    let extra_bytes = STANDARD.decode(extra_data).ok()?;

    if leaf_bytes.len() < 15 {
        return None;
    }

    // The length check above (< 15) guarantees at least 15 bytes, so indexing
    // into [2..10] (the 8-byte timestamp) and [10..12] (the entry type) is safe.
    // RFC 6962 MerkleTreeLeaf: byte 0 = version, byte 1 = leaf_type,
    // bytes 2–9 = uint64 big-endian timestamp (milliseconds since Unix epoch).
    let ts_ms = u64::from_be_bytes([
        leaf_bytes[2],
        leaf_bytes[3],
        leaf_bytes[4],
        leaf_bytes[5],
        leaf_bytes[6],
        leaf_bytes[7],
        leaf_bytes[8],
        leaf_bytes[9],
    ]);
    let timestamp = ts_ms as f64 / 1000.0;

    let entry_type = u16::from_be_bytes([leaf_bytes[10], leaf_bytes[11]]);

    match entry_type {
        0 => parse_x509_entry(&leaf_bytes, extra_bytes, timestamp),
        1 => parse_precert_entry(extra_bytes, timestamp),
        _ => None,
    }
}

fn parse_x509_entry(leaf_bytes: &[u8], extra_bytes: Vec<u8>, timestamp: f64) -> Option<ParsedEntry> {
    if leaf_bytes.len() < 15 {
        return None;
    }

    let cert_data = &leaf_bytes[12..];
    if cert_data.len() < 3 {
        return None;
    }

    let cert_len = u32::from_be_bytes([0, cert_data[0], cert_data[1], cert_data[2]]) as usize;
    if cert_data.len() < 3 + cert_len {
        return None;
    }

    let cert_bytes = &cert_data[3..3 + cert_len];
    let leaf_cert = parse_certificate(cert_bytes, true)?;

    Some(ParsedEntry {
        update_type: Cow::Borrowed("X509LogEntry"),
        leaf_cert,
        timestamp,
        chain_extra_bytes: extra_bytes,
        chain_offset: 0,
    })
}

fn parse_precert_entry(extra_bytes: Vec<u8>, timestamp: f64) -> Option<ParsedEntry> {
    // RFC 6962: extra_data for precert contains:
    // - 3 bytes: pre-certificate length
    // - pre-certificate (full X509 with CT poison extension)
    // - 3 bytes: certificate chain length
    // - certificate chain
    if extra_bytes.len() < 3 {
        return None;
    }

    let precert_len =
        u32::from_be_bytes([0, extra_bytes[0], extra_bytes[1], extra_bytes[2]]) as usize;

    if extra_bytes.len() < 3 + precert_len {
        return None;
    }

    let precert_bytes = &extra_bytes[3..3 + precert_len];
    let mut leaf_cert = parse_certificate(precert_bytes, true)?;
    leaf_cert.extensions.ctl_poison_byte = true;

    let chain_offset = 3 + precert_len;

    Some(ParsedEntry {
        update_type: Cow::Borrowed("PrecertLogEntry"),
        leaf_cert,
        timestamp,
        chain_extra_bytes: extra_bytes,
        chain_offset,
    })
}

pub fn parse_certificate(der_bytes: &[u8], include_der: bool) -> Option<LeafCert> {
    let (_, cert) = X509Certificate::from_der(der_bytes).ok()?;

    let mut subject = extract_name(cert.subject());
    let mut issuer = extract_name(cert.issuer());
    subject.build_aggregated();
    issuer.build_aggregated();

    let serial_number = format_serial_number(cert.serial.to_bytes_be());

    let sha1_hash = calculate_sha1(der_bytes);
    let (sha256_raw, sha256_hash) = calculate_sha256(der_bytes);
    // Issue #12: fingerprint == sha1. Build Arc<str> from sha1 first, then move sha1 into the
    // struct — zero clone, zero extra heap allocation vs the previous sha1_hash.clone().
    let fingerprint: Arc<str> = Arc::from(sha1_hash.as_str());

    // Issue #7: returns &'static str — no OID string allocation, no result string allocation.
    let signature_algorithm = parse_signature_algorithm(&cert);
    let is_ca = cert.is_ca();

    let mut all_domains = DomainList::new();
    // Issue #8: AHashSet<&str> — borrows rather than owns; AHash is ~4× faster than SipHash.
    // Pre-sized to expected domain count (most certs have < 16 SANs).
    let mut seen_domains: AHashSet<&str> = AHashSet::with_capacity(8);

    if let Some(ref cn) = subject.cn
        && !cn.is_empty() && !is_ca
    {
        // Issue #8: borrow cn into the set (no clone); one clone only for all_domains.
        seen_domains.insert(cn.as_str());
        all_domains.push(cn.clone());
    }

    let extensions = parse_extensions(&cert, &mut all_domains, &mut seen_domains);

    let as_der = if include_der {
        Some(STANDARD.encode(der_bytes))
    } else {
        None
    };

    Some(LeafCert {
        subject,
        issuer,
        serial_number,
        not_before: cert.validity().not_before.timestamp(),
        not_after: cert.validity().not_after.timestamp(),
        fingerprint,
        sha1: sha1_hash,
        sha256: sha256_hash,
        sha256_raw,
        signature_algorithm: Cow::Borrowed(signature_algorithm),
        is_ca,
        all_domains,
        as_der,
        extensions,
    })
}

fn parse_chain_from_bytes(bytes: &[u8], start_offset: usize) -> Vec<ChainCert> {
    let mut chain = Vec::with_capacity(4);

    if bytes.len() <= start_offset + 3 {
        return chain;
    }

    // Skip the 3-byte chain length prefix
    let mut offset = start_offset + 3;

    while offset + 3 < bytes.len() {
        let cert_len =
            u32::from_be_bytes([0, bytes[offset], bytes[offset + 1], bytes[offset + 2]]) as usize;
        offset += 3;

        if offset + cert_len > bytes.len() {
            break;
        }

        let cert_bytes = &bytes[offset..offset + cert_len];
        if let Some(leaf) = parse_certificate(cert_bytes, false) {
            chain.push(ChainCert {
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
            });
        }

        offset += cert_len;
    }

    chain
}

/// Issue #6: Compare OIDs directly — eliminates per-attribute string allocation.
fn extract_name(name: &X509Name) -> Subject {
    let mut subject = Subject::default();

    for rdn in name.iter() {
        for attr in rdn.iter() {
            let oid = attr.attr_type();
            let value = attr.attr_value();
            let value_str = value
                .as_str()
                .ok()
                .or_else(|| std::str::from_utf8(value.data).ok());
            if let Some(value) = value_str {
                if oid == &OID_CN {
                    subject.cn = Some(value.to_string());
                } else if oid == &OID_C {
                    subject.c = Some(value.to_string());
                } else if oid == &OID_L {
                    subject.l = Some(value.to_string());
                } else if oid == &OID_ST {
                    subject.st = Some(value.to_string());
                } else if oid == &OID_O {
                    subject.o = Some(value.to_string());
                } else if oid == &OID_OU {
                    subject.ou = Some(value.to_string());
                } else if oid == &OID_EMAIL {
                    subject.email_address = Some(value.to_string());
                }
            }
        }
    }

    subject
}

/// Issue #8: AHashSet<&str> — borrows &str from the parsed cert directly.
/// On new SAN entry: one allocation (dns.to_string() into all_domains only).
/// On duplicate: zero allocations (insert returns false, nothing pushed).
fn parse_extensions<'cert>(
    cert: &'cert X509Certificate,
    all_domains: &mut DomainList,
    seen_domains: &mut AHashSet<&'cert str>,
) -> Extensions {
    let mut ext = Extensions::default();
    let mut san_parts: Vec<String> = Vec::new();

    for extension in cert.extensions() {
        match extension.parsed_extension() {
            ParsedExtension::AuthorityKeyIdentifier(aki) => {
                if let Some(key_id) = &aki.key_identifier {
                    ext.authority_key_identifier = Some(format_key_id(key_id.0));
                }
            }
            ParsedExtension::SubjectKeyIdentifier(ski) => {
                ext.subject_key_identifier = Some(format_key_id(ski.0));
            }
            ParsedExtension::KeyUsage(ku) => {
                ext.key_usage = Some(key_usage_to_string(ku));
            }
            ParsedExtension::ExtendedKeyUsage(eku) => {
                ext.extended_key_usage = Some(extended_key_usage_to_string(eku));
            }
            ParsedExtension::BasicConstraints(bc) => {
                let ca_str = if bc.ca {
                    "CA:TRUE".to_string()
                } else {
                    "CA:FALSE".to_string()
                };
                ext.basic_constraints = Some(ca_str);
            }
            ParsedExtension::SubjectAlternativeName(san) => {
                for name in &san.general_names {
                    match name {
                        GeneralName::DNSName(dns) => {
                            san_parts.push(format!("DNS:{}", dns));
                            // Issue #8: insert borrows &str directly — no allocation on hit.
                            // Single dns.to_string() alloc only on new (non-duplicate) entry.
                            if seen_domains.insert(*dns) {
                                all_domains.push(dns.to_string());
                            }
                        }
                        GeneralName::RFC822Name(email) => {
                            san_parts.push(format!("email:{}", email));
                        }
                        GeneralName::IPAddress(ip_bytes) => {
                            if let Some(ip) = parse_ip_address(ip_bytes) {
                                san_parts.push(format!("IP Address:{}", ip));
                            }
                        }
                        _ => {}
                    }
                }
            }
            ParsedExtension::AuthorityInfoAccess(aia) => {
                let mut aia_parts: Vec<String> = Vec::new();
                for desc in &aia.accessdescs {
                    if let GeneralName::URI(uri) = &desc.access_location {
                        aia_parts.push(format!("URI:{}", uri));
                    }
                }
                if !aia_parts.is_empty() {
                    ext.authority_info_access = Some(aia_parts.join(", "));
                }
            }
            ParsedExtension::CertificatePolicies(policies) => {
                let mut policy_strs: Vec<String> = Vec::new();
                for policy in policies.iter() {
                    policy_strs.push(format!("Policy: {}\n", policy.policy_id));
                }
                if !policy_strs.is_empty() {
                    ext.certificate_policies = Some(policy_strs.concat());
                }
            }
            ParsedExtension::Unparsed => {
                if extension.oid == OID_X509_EXT_CT_POISON {
                    ext.ctl_poison_byte = true;
                }
            }
            _ => {}
        }
    }

    if !san_parts.is_empty() {
        ext.subject_alt_name = Some(san_parts.join(", "));
    }

    ext
}

fn parse_ip_address(bytes: &[u8]) -> Option<String> {
    match bytes.len() {
        4 => {
            let ip: IpAddr = std::net::Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]).into();
            Some(ip.to_string())
        }
        16 => {
            let arr: [u8; 16] = bytes.try_into().ok()?;
            let ip: IpAddr = std::net::Ipv6Addr::from(arr).into();
            Some(ip.to_string())
        }
        _ => None,
    }
}

fn format_key_id(key_id: &[u8]) -> String {
    let mut result = String::with_capacity(6 + key_id.len() * 3);
    result.push_str("keyid:");
    for (i, b) in key_id.iter().enumerate() {
        if i > 0 {
            result.push(':');
        }
        let _ = write!(result, "{:02x}", b);
    }
    result
}

fn format_serial_number(bytes: impl AsRef<[u8]>) -> String {
    let bytes = bytes.as_ref();
    let mut serial_number = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(serial_number, "{:02X}", b);
    }
    serial_number
}

fn calculate_sha1(data: &[u8]) -> String {
    let mut hasher = Sha1::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut hash = String::with_capacity(32 * 3);
    for (i, b) in result.iter().enumerate() {
        if i > 0 {
            hash.push(':');
        }
        let _ = write!(hash, "{:02X}", b);
    }
    hash
}

/// Issue #1 (partial) + #7: Returns both raw bytes ([u8; 32]) and the colon-hex string.
/// The raw bytes serve as a zero-alloc key in DedupFilter.
fn calculate_sha256(data: &[u8]) -> ([u8; 32], String) {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let raw: [u8; 32] = result.into();
    let mut hash = String::with_capacity(32 * 3);
    for (i, b) in raw.iter().enumerate() {
        if i > 0 {
            hash.push(':');
        }
        let _ = write!(hash, "{:02X}", b);
    }
    (raw, hash)
}

/// Issue #7: Returns &'static str — eliminates OID-to-string allocation AND result-string
/// allocation. The Cow::Borrowed wrapper in LeafCert carries zero allocation cost.
fn parse_signature_algorithm(cert: &X509Certificate) -> &'static str {
    let oid = &cert.signature_algorithm.algorithm;
    if oid == &OID_SHA256_RSA {
        "sha256, rsa"
    } else if oid == &OID_ECDSA_SHA256 {
        "ecdsa, sha256"
    } else if oid == &OID_SHA384_RSA {
        "sha384, rsa"
    } else if oid == &OID_SHA512_RSA {
        "sha512, rsa"
    } else if oid == &OID_SHA1_RSA {
        "sha1, rsa"
    } else if oid == &OID_SHA256_RSA_PSS {
        "sha256, rsa-pss"
    } else if oid == &OID_ECDSA_SHA384 {
        "ecdsa, sha384"
    } else if oid == &OID_ECDSA_SHA512 {
        "ecdsa, sha512"
    } else if oid == &OID_ECDSA_SHA1 {
        "ecdsa, sha1"
    } else if oid == &OID_MD5_RSA {
        "md5, rsa"
    } else if oid == &OID_MD2_RSA {
        "md2, rsa"
    } else if oid == &OID_DSA_SHA1 {
        "dsa, sha1"
    } else if oid == &OID_DSA_SHA256 {
        "dsa, sha256"
    } else if oid == &OID_ED25519 {
        "ed25519"
    } else {
        "unknown"
    }
}

fn key_usage_to_string(ku: &KeyUsage) -> String {
    let mut parts: Vec<&str> = Vec::new();
    if ku.digital_signature() {
        parts.push("Digital Signature");
    }
    if ku.non_repudiation() {
        parts.push("Content Commitment");
    }
    if ku.key_encipherment() {
        parts.push("Key Encipherment");
    }
    if ku.data_encipherment() {
        parts.push("Data Encipherment");
    }
    if ku.key_agreement() {
        parts.push("Key Agreement");
    }
    if ku.key_cert_sign() {
        parts.push("Certificate Signing");
    }
    if ku.crl_sign() {
        parts.push("CRL Signing");
    }
    if ku.encipher_only() {
        parts.push("Encipher Only");
    }
    if ku.decipher_only() {
        parts.push("Decipher Only");
    }
    parts.join(", ")
}

fn extended_key_usage_to_string(eku: &ExtendedKeyUsage) -> String {
    let mut parts: Vec<&str> = Vec::new();
    if eku.server_auth {
        parts.push("serverAuth");
    }
    if eku.client_auth {
        parts.push("clientAuth");
    }
    if eku.code_signing {
        parts.push("codeSigning");
    }
    if eku.email_protection {
        parts.push("emailProtection");
    }
    if eku.time_stamping {
        parts.push("timeStamping");
    }
    if eku.ocsp_signing {
        parts.push("OCSPSigning");
    }
    if eku.any {
        parts.push("anyExtendedKeyUsage");
    }
    parts.join(", ")
}

const OID_X509_EXT_CT_POISON: Oid<'static> = oid!(1.3.6 .1 .4 .1 .11129 .2 .4 .3);

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD, Engine};

    fn generate_self_signed_der(cn: &str) -> Vec<u8> {
        let mut params = rcgen::CertificateParams::new(vec![]).unwrap();
        params.distinguished_name = rcgen::DistinguishedName::new();
        params.distinguished_name.push(rcgen::DnType::CommonName, cn);
        params.distinguished_name.push(rcgen::DnType::OrganizationName, "Test Org");
        params.distinguished_name.push(rcgen::DnType::CountryName, "US");
        params.distinguished_name.push(rcgen::DnType::LocalityName, "San Francisco");
        params.distinguished_name.push(rcgen::DnType::StateOrProvinceName, "California");
        params.is_ca = rcgen::IsCa::NoCa;
        let cert = params.self_signed(&rcgen::KeyPair::generate().unwrap()).unwrap();
        cert.der().to_vec()
    }

    fn generate_cert_with_sans(cn: &str, sans: &[&str]) -> Vec<u8> {
        let san_strings: Vec<String> = sans.iter().map(|s| s.to_string()).collect();
        let mut params = rcgen::CertificateParams::new(san_strings).unwrap();
        params.distinguished_name = rcgen::DistinguishedName::new();
        params.distinguished_name.push(rcgen::DnType::CommonName, cn);
        params.is_ca = rcgen::IsCa::NoCa;
        let cert = params.self_signed(&rcgen::KeyPair::generate().unwrap()).unwrap();
        cert.der().to_vec()
    }

    fn generate_ca_cert_der(cn: &str) -> Vec<u8> {
        let mut params = rcgen::CertificateParams::new(vec![]).unwrap();
        params.distinguished_name = rcgen::DistinguishedName::new();
        params.distinguished_name.push(rcgen::DnType::CommonName, cn);
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let cert = params.self_signed(&rcgen::KeyPair::generate().unwrap()).unwrap();
        cert.der().to_vec()
    }

    #[test]
    fn test_format_key_id_empty() {
        assert_eq!(format_key_id(&[]), "keyid:");
    }

    #[test]
    fn test_format_key_id_single_byte() {
        assert_eq!(format_key_id(&[0xAB]), "keyid:ab");
    }

    #[test]
    fn test_format_key_id_multiple_bytes() {
        assert_eq!(
            format_key_id(&[0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF]),
            "keyid:01:23:45:67:89:ab:cd:ef"
        );
    }

    #[test]
    fn test_format_serial_number_basic() {
        assert_eq!(format_serial_number([0x00, 0xFF, 0x10]), "00FF10");
    }

    #[test]
    fn test_format_serial_number_empty() {
        let empty: &[u8] = &[];
        assert_eq!(format_serial_number(empty), "");
    }

    #[test]
    fn test_format_serial_number_single_byte() {
        assert_eq!(format_serial_number([0x0A]), "0A");
    }

    #[test]
    fn test_calculate_sha1_known_value() {
        // SHA1("") = da39a3ee5e6b4b0d3255bfef95601890afd80709
        let hash = calculate_sha1(b"");
        assert_eq!(
            hash,
            "DA:39:A3:EE:5E:6B:4B:0D:32:55:BF:EF:95:60:18:90:AF:D8:07:09"
        );
    }

    #[test]
    fn test_calculate_sha256_known_value() {
        // SHA256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        let (raw, hash) = calculate_sha256(b"");
        assert_eq!(
            hash,
            "E3:B0:C4:42:98:FC:1C:14:9A:FB:F4:C8:99:6F:B9:24:27:AE:41:E4:64:9B:93:4C:A4:95:99:1B:78:52:B8:55"
        );
        assert_eq!(raw[0], 0xe3);
        assert_eq!(raw[1], 0xb0);
    }

    #[test]
    fn test_calculate_sha1_nonempty() {
        // SHA1("abc") = a9993e364706816aba3e25717850c26c9cd0d89d
        let hash = calculate_sha1(b"abc");
        assert_eq!(
            hash,
            "A9:99:3E:36:47:06:81:6A:BA:3E:25:71:78:50:C2:6C:9C:D0:D8:9D"
        );
    }

    #[test]
    fn test_parse_ip_address_ipv4() {
        let result = parse_ip_address(&[192, 168, 1, 1]);
        assert_eq!(result, Some("192.168.1.1".to_string()));
    }

    #[test]
    fn test_parse_ip_address_ipv6() {
        // ::1 (loopback)
        let mut bytes = [0u8; 16];
        bytes[15] = 1;
        let result = parse_ip_address(&bytes);
        assert_eq!(result, Some("::1".to_string()));
    }

    #[test]
    fn test_parse_ip_address_invalid_length() {
        // 5 bytes is neither IPv4 nor IPv6
        assert!(parse_ip_address(&[1, 2, 3, 4, 5]).is_none());
    }

    #[test]
    fn test_parse_ip_address_empty() {
        assert!(parse_ip_address(&[]).is_none());
    }

    #[test]
    fn test_parse_leaf_input_too_short() {
        let short = STANDARD.encode([0u8; 10]);
        let extra = STANDARD.encode([0u8; 0]);
        assert!(parse_leaf_input(&short, &extra).is_none());
    }

    #[test]
    fn test_parse_leaf_input_invalid_base64() {
        assert!(parse_leaf_input("not-valid-b64!!!", "also-bad!!!").is_none());
    }

    #[test]
    fn test_parse_leaf_input_unknown_entry_type() {
        // Entry type at bytes 10-11, set to 99 (unknown)
        let mut leaf = vec![0u8; 15];
        leaf[10] = 0;
        leaf[11] = 99;
        let encoded = STANDARD.encode(&leaf);
        let extra = STANDARD.encode([0u8; 0]);
        assert!(parse_leaf_input(&encoded, &extra).is_none());
    }

    #[test]
    fn test_parse_leaf_input_x509_entry_type_invalid_cert() {
        // Entry type 0 (x509) but the certificate data is garbage
        let mut leaf = vec![0u8; 20];
        leaf[10] = 0;
        leaf[11] = 0; // entry type = 0 (x509)
        // bytes 12..15 encode the cert length as 3 bytes: length = 2
        leaf[12] = 0;
        leaf[13] = 0;
        leaf[14] = 2;
        // 2 bytes of garbage cert data
        leaf[15] = 0xFF;
        leaf[16] = 0xFF;
        let encoded = STANDARD.encode(&leaf);
        let extra = STANDARD.encode([0u8; 4]);
        // Should return None because the cert bytes are not valid DER
        assert!(parse_leaf_input(&encoded, &extra).is_none());
    }

    #[test]
    fn test_parse_certificate_empty_bytes() {
        assert!(parse_certificate(&[], true).is_none());
    }

    #[test]
    fn test_parse_certificate_garbage() {
        assert!(parse_certificate(&[0, 1, 2, 3, 4], true).is_none());
    }

    #[test]
    fn test_parse_certificate_valid_der() {
        let der = generate_self_signed_der("test.com");
        let result = parse_certificate(&der, true);
        assert!(result.is_some(), "parse_certificate should succeed for a valid DER cert");

        let leaf = result.unwrap();

        // Subject CN should be test.com
        assert_eq!(leaf.subject.cn.as_deref(), Some("test.com"));

        // Self-signed: issuer CN should also be test.com
        assert_eq!(leaf.issuer.cn.as_deref(), Some("test.com"));

        // Subject should contain O, C, L, ST from the generated cert
        assert_eq!(leaf.subject.o.as_deref(), Some("Test Org"));
        assert_eq!(leaf.subject.c.as_deref(), Some("US"));
        assert_eq!(leaf.subject.l.as_deref(), Some("San Francisco"));
        assert_eq!(leaf.subject.st.as_deref(), Some("California"));

        // Serial number should be non-empty hex
        assert!(!leaf.serial_number.is_empty());
        assert!(
            leaf.serial_number.chars().all(|c| c.is_ascii_hexdigit()),
            "serial number should be hex: {}",
            leaf.serial_number
        );

        // Signature algorithm: rcgen uses ECDSA P-256 by default
        assert_eq!(leaf.signature_algorithm.as_ref(), "ecdsa, sha256");

        // is_ca should be false (we set IsCa::NoCa)
        assert!(!leaf.is_ca);

        // SHA1 and SHA256 fingerprints should be colon-separated hex
        assert!(leaf.sha1.contains(':'), "sha1 should be colon-separated");
        assert!(leaf.sha256.contains(':'), "sha256 should be colon-separated");

        // sha256_raw should be non-zero for a real cert
        assert_ne!(leaf.sha256_raw, [0u8; 32], "sha256_raw should not be all zeros");

        // fingerprint == sha1
        assert_eq!(&*leaf.fingerprint, leaf.sha1.as_str());

        // as_der should be present when include_der=true
        assert!(leaf.as_der.is_some());
        // Round-trip: as_der should decode back to the original DER
        let decoded = STANDARD.decode(leaf.as_der.as_ref().unwrap()).unwrap();
        assert_eq!(decoded, der);

        // Validity: not_before and not_after should be nonzero timestamps
        assert!(leaf.not_before != 0);
        assert!(leaf.not_after != 0);
        assert!(leaf.not_after > leaf.not_before);

        // Subject aggregated field should contain /CN=test.com
        let agg = leaf.subject.aggregated.as_ref().unwrap();
        assert!(agg.contains("/CN=test.com"), "aggregated should contain /CN=test.com, got: {}", agg);
        assert!(agg.contains("/O=Test Org"), "aggregated should contain /O=Test Org, got: {}", agg);
        assert!(agg.contains("/C=US"), "aggregated should contain /C=US, got: {}", agg);

        // all_domains should include "test.com" from the CN (no SANs in this cert)
        assert!(
            leaf.all_domains.iter().any(|d| d == "test.com"),
            "all_domains should include test.com from CN"
        );

        // Extensions: rcgen with IsCa::NoCa omits BasicConstraints entirely,
        // which is valid per X.509 (absence means not a CA).
        // basic_constraints may be None or Some("CA:FALSE") depending on the generator.
        if let Some(ref bc) = leaf.extensions.basic_constraints {
            assert_eq!(bc, "CA:FALSE");
        }

        // subject_key_identifier may or may not be present depending on rcgen version.
        // If present, it should start with "keyid:"
        if let Some(ref ski) = leaf.extensions.subject_key_identifier {
            assert!(ski.starts_with("keyid:"), "SKI should start with keyid:, got: {}", ski);
        }
    }

    #[test]
    fn test_parse_certificate_no_der() {
        let der = generate_self_signed_der("example.org");
        let result = parse_certificate(&der, false);
        assert!(result.is_some());
        let leaf = result.unwrap();
        assert!(leaf.as_der.is_none(), "as_der should be None when include_der=false");
    }

    #[test]
    fn test_parse_certificate_hashes_deterministic() {
        let der = generate_self_signed_der("deterministic.test");
        let a = parse_certificate(&der, true).unwrap();
        let b = parse_certificate(&der, true).unwrap();
        assert_eq!(a.sha1, b.sha1);
        assert_eq!(a.sha256, b.sha256);
        assert_eq!(a.sha256_raw, b.sha256_raw);
        assert_eq!(a.serial_number, b.serial_number);
    }

    #[test]
    fn test_parse_certificate_with_sans() {
        let der = generate_cert_with_sans("primary.com", &["alt1.com", "alt2.com", "*.wildcard.com"]);
        let leaf = parse_certificate(&der, true).unwrap();

        assert_eq!(leaf.subject.cn.as_deref(), Some("primary.com"));

        // all_domains should contain the CN plus all SANs (deduplicated)
        assert!(leaf.all_domains.iter().any(|d| d == "primary.com"), "should contain CN");
        assert!(leaf.all_domains.iter().any(|d| d == "alt1.com"), "should contain alt1.com SAN");
        assert!(leaf.all_domains.iter().any(|d| d == "alt2.com"), "should contain alt2.com SAN");
        assert!(leaf.all_domains.iter().any(|d| d == "*.wildcard.com"), "should contain wildcard SAN");

        // SAN extension should be present
        let san = leaf.extensions.subject_alt_name.as_ref().unwrap();
        assert!(san.contains("DNS:alt1.com"), "SAN should contain DNS:alt1.com, got: {}", san);
        assert!(san.contains("DNS:alt2.com"), "SAN should contain DNS:alt2.com, got: {}", san);
        assert!(san.contains("DNS:*.wildcard.com"), "SAN should contain DNS:*.wildcard.com, got: {}", san);
    }

    #[test]
    fn test_parse_certificate_ca_cert() {
        let der = generate_ca_cert_der("My Root CA");
        let leaf = parse_certificate(&der, true).unwrap();

        assert_eq!(leaf.subject.cn.as_deref(), Some("My Root CA"));
        assert!(leaf.is_ca, "CA cert should have is_ca=true");
        assert_eq!(leaf.extensions.basic_constraints.as_deref(), Some("CA:TRUE"));

        // CA certs should NOT add the CN to all_domains
        assert!(
            !leaf.all_domains.iter().any(|d| d == "My Root CA"),
            "CA cert CN should not be added to all_domains"
        );
    }

    #[test]
    fn test_parse_chain_from_bytes_empty() {
        let chain = parse_chain_from_bytes(&[], 0);
        assert!(chain.is_empty());
    }

    #[test]
    fn test_parse_chain_from_bytes_too_short() {
        // Only 3 bytes (the chain-length prefix) with zero length, no certs
        let chain = parse_chain_from_bytes(&[0, 0, 0], 0);
        assert!(chain.is_empty());
    }

    #[test]
    fn test_parse_chain_from_bytes_with_one_cert() {
        let cert_der = generate_self_signed_der("chain-test.com");
        let cert_len = cert_der.len();

        // Build extra_bytes: 3-byte chain length + 3-byte cert length + cert DER
        let chain_total_len = 3 + cert_len;
        // 3-byte chain length (big-endian u24) + 3-byte cert length
        let mut extra = vec![
            ((chain_total_len >> 16) & 0xFF) as u8,
            ((chain_total_len >> 8) & 0xFF) as u8,
            (chain_total_len & 0xFF) as u8,
            ((cert_len >> 16) & 0xFF) as u8,
            ((cert_len >> 8) & 0xFF) as u8,
            (cert_len & 0xFF) as u8,
        ];
        // cert DER bytes
        extra.extend_from_slice(&cert_der);

        let chain = parse_chain_from_bytes(&extra, 0);
        assert_eq!(chain.len(), 1, "should parse exactly one chain cert");
        assert_eq!(chain[0].subject.cn.as_deref(), Some("chain-test.com"));
    }
}
