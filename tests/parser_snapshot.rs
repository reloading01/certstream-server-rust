//! Parser snapshot tests — byte-equivalence regression suite for the JSON
//! output of the CT parsing + serialization pipeline. Gates the parser
//! optimization work (v1.6.0 items 7/8/9) by failing on any change to the
//! emitted JSON for a fixed corpus.
//!
//! Corpus:
//!   * ~10 synthetic certs (rcgen) covering common shapes — RSA/ECDSA, varied
//!     SAN types (DNS, wildcard, IDN, IP, email), CA vs leaf, multi-attribute
//!     subject, no-SAN CN-only.
//!   * ~50 sampled from live CT logs (three operators: Let's Encrypt, Google,
//!     Cloudflare) for real-world diversity.
//!
//! Fixtures are committed to `tests/fixtures/parser_snapshots/` so CI doesn't
//! depend on network. The committed JSON bytes ARE the v1.5.x→v1.6.0 baseline.
//!
//! To regenerate after an intentional, reviewed output change:
//!   cargo test --release --test parser_snapshot regenerate_synthetic_fixtures \
//!     -- --ignored --nocapture
//!   cargo test --release --test parser_snapshot regenerate_live_ct_fixtures \
//!     -- --ignored --nocapture
//!
//! Caveats:
//!   * Synthetic fixtures embed a freshly-generated key pair on every regen
//!     (rcgen has no fixed-seed knob), so synthetic.json will diff in full on
//!     each regen. Live CT fixtures are stable across regens iff the CT logs
//!     still hold the same entries (they do for at least their MMD).

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use certstream_server_rust::config::StreamConfig;
use certstream_server_rust::ct::{
    parse_certificate, parse_certificate_with_options, parse_leaf_input,
    parse_leaf_input_with_options, ParseOptions,
};
use certstream_server_rust::models::{
    CertificateData, CertificateMessage, ChainCert, LeafCert, PreSerializedMessage, Source,
};
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::path::PathBuf;
use std::sync::Arc;

const FIXTURE_DIR: &str = "tests/fixtures/parser_snapshots";

// Fixed values used to build deterministic CertificateMessages from raw
// parser output. Snapshot tests need stable input across runs, so we
// override every clock-derived or context-derived field.
const FIXED_SEEN: f64 = 1_700_000_000.0;
const FIXED_CERT_INDEX: u64 = 42;
const FIXED_CERT_LINK: &str = "https://test.example/entry/42";
const FIXED_SOURCE_NAME: &str = "Snapshot Test Log";
const FIXED_SOURCE_URL: &str = "https://test.example/";

fn stream_all() -> StreamConfig {
    StreamConfig {
        full: true,
        lite: true,
        domains_only: true,
    }
}

// ----- fixture types -----

#[derive(Debug, Serialize, Deserialize)]
struct SyntheticFixture {
    name: String,
    der_b64: String,
    submission_timestamp: f64,
    expected_full: String,
    expected_lite: String,
    expected_domains_only: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct LiveCtFixture {
    name: String,
    log_name: String,
    log_url: String,
    cert_index: u64,
    leaf_input: String,
    extra_data: String,
    expected_full: String,
    expected_lite: String,
    expected_domains_only: String,
}

// ----- message builders -----

fn build_msg(
    leaf_cert: LeafCert,
    chain: Option<Vec<Arc<ChainCert>>>,
    update_type: Cow<'static, str>,
    sub_ts: f64,
    cert_index: u64,
    cert_link: String,
    source: Arc<Source>,
) -> CertificateMessage {
    CertificateMessage {
        message_type: Cow::Borrowed("certificate_update"),
        data: CertificateData {
            update_type,
            leaf_cert: Arc::new(leaf_cert),
            chain,
            cert_index,
            cert_link,
            seen: FIXED_SEEN,
            submission_timestamp: sub_ts,
            source,
        },
    }
}

fn test_source() -> Arc<Source> {
    Arc::new(Source {
        name: Arc::from(FIXED_SOURCE_NAME),
        url: Arc::from(FIXED_SOURCE_URL),
    })
}

fn serialize_all(msg: &CertificateMessage) -> (String, String, String) {
    let pre = PreSerializedMessage::from_certificate(msg, &stream_all())
        .expect("pre-serialize must succeed");
    (
        pre.full.as_str().to_string(),
        pre.lite.as_str().to_string(),
        pre.domains_only.as_str().to_string(),
    )
}

// ----- snapshot assertions -----

#[test]
fn snapshot_synthetic_corpus_matches() {
    let path = PathBuf::from(FIXTURE_DIR).join("synthetic.json");
    let raw = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "{} missing or unreadable ({}); regenerate with: \
             cargo test --release --test parser_snapshot regenerate_synthetic_fixtures \
             -- --ignored --nocapture",
            path.display(),
            e
        )
    });
    let fixtures: Vec<SyntheticFixture> =
        serde_json::from_str(&raw).expect("synthetic.json must be valid JSON");
    assert!(
        fixtures.len() >= 10,
        "expected at least 10 synthetic fixtures, found {}",
        fixtures.len()
    );

    let mut mismatches = Vec::new();
    for f in &fixtures {
        let der = B64.decode(&f.der_b64).expect("decode der_b64");
        let leaf_cert = match parse_certificate(&der, true) {
            Some(c) => c,
            None => {
                mismatches.push(format!("{}: parse_certificate returned None", f.name));
                continue;
            }
        };
        let msg = build_msg(
            leaf_cert,
            None,
            Cow::Borrowed("X509LogEntry"),
            f.submission_timestamp,
            FIXED_CERT_INDEX,
            FIXED_CERT_LINK.to_string(),
            test_source(),
        );
        let (full, lite, doms) = serialize_all(&msg);
        if full != f.expected_full {
            mismatches.push(format!("{}: full mismatch", f.name));
        }
        if lite != f.expected_lite {
            mismatches.push(format!("{}: lite mismatch", f.name));
        }
        if doms != f.expected_domains_only {
            mismatches.push(format!("{}: domains_only mismatch", f.name));
        }
    }
    assert!(
        mismatches.is_empty(),
        "{} byte-mismatch(es) against synthetic snapshot:\n  {}\n\n\
         To accept after review:\n  cargo test --release --test parser_snapshot \
         regenerate_synthetic_fixtures -- --ignored --nocapture",
        mismatches.len(),
        mismatches.join("\n  ")
    );
    eprintln!(
        "snapshot_synthetic_corpus_matches: {} fixtures verified",
        fixtures.len()
    );
}

#[test]
fn snapshot_live_ct_corpus_matches() {
    let path = PathBuf::from(FIXTURE_DIR).join("live_ct.json");
    let raw = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "{} missing or unreadable ({}); regenerate with: \
             cargo test --release --test parser_snapshot regenerate_live_ct_fixtures \
             -- --ignored --nocapture",
            path.display(),
            e
        )
    });
    let fixtures: Vec<LiveCtFixture> =
        serde_json::from_str(&raw).expect("live_ct.json must be valid JSON");
    assert!(
        fixtures.len() >= 30,
        "expected at least 30 live CT fixtures, found {}",
        fixtures.len()
    );

    let mut mismatches = Vec::new();
    for f in &fixtures {
        let parsed = match parse_leaf_input(&f.leaf_input, &f.extra_data) {
            Some(p) => p,
            None => {
                mismatches.push(format!("{}: parse_leaf_input returned None", f.name));
                continue;
            }
        };
        let chain = parsed.parse_chain();
        let source = Arc::new(Source {
            name: Arc::from(f.log_name.as_str()),
            url: Arc::from(f.log_url.as_str()),
        });
        let cert_link = format!("{}ct/v1/get-entries?start={}&end={}", f.log_url, f.cert_index, f.cert_index);
        let msg = build_msg(
            parsed.leaf_cert,
            Some(chain),
            parsed.update_type,
            parsed.submission_timestamp,
            f.cert_index,
            cert_link,
            source,
        );
        let (full, lite, doms) = serialize_all(&msg);
        if full != f.expected_full {
            mismatches.push(format!("{}: full mismatch", f.name));
        }
        if lite != f.expected_lite {
            mismatches.push(format!("{}: lite mismatch", f.name));
        }
        if doms != f.expected_domains_only {
            mismatches.push(format!("{}: domains_only mismatch", f.name));
        }
    }
    assert!(
        mismatches.is_empty(),
        "{} byte-mismatch(es) against live CT snapshot:\n  {}\n\n\
         To accept after review:\n  cargo test --release --test parser_snapshot \
         regenerate_live_ct_fixtures -- --ignored --nocapture",
        mismatches.len(),
        mismatches.join("\n  ")
    );
    eprintln!(
        "snapshot_live_ct_corpus_matches: {} fixtures verified",
        fixtures.len()
    );
}

/// §1.5a invariant: skipping extension display-string parsing must not change
/// the `domains_only` output bytes for any corpus cert. The display strings
/// are not emitted in the domains_only variant, so the only thing that could
/// affect output is the `all_domains` list — and that's populated identically
/// in both paths (the SAN loop always runs for DNS names regardless of the
/// `parse_extensions` flag).
#[test]
fn parse_extensions_skip_preserves_domains_only_synthetic() {
    let path = PathBuf::from(FIXTURE_DIR).join("synthetic.json");
    let raw = std::fs::read_to_string(&path).expect("synthetic.json must exist");
    let fixtures: Vec<SyntheticFixture> = serde_json::from_str(&raw).unwrap();
    let opts_skip = ParseOptions {
        include_der: true,
        parse_extensions: false,
    };
    for f in &fixtures {
        let der = B64.decode(&f.der_b64).expect("decode der_b64");
        let leaf = parse_certificate_with_options(&der, opts_skip)
            .unwrap_or_else(|| panic!("parse failed for {}", f.name));
        let msg = build_msg(
            leaf,
            None,
            Cow::Borrowed("X509LogEntry"),
            f.submission_timestamp,
            FIXED_CERT_INDEX,
            FIXED_CERT_LINK.to_string(),
            test_source(),
        );
        let (_, _, doms) = serialize_all(&msg);
        assert_eq!(
            doms, f.expected_domains_only,
            "{}: domains_only diverged when parse_extensions=false",
            f.name
        );
    }
}

#[test]
fn parse_extensions_skip_preserves_domains_only_live_ct() {
    let path = PathBuf::from(FIXTURE_DIR).join("live_ct.json");
    let raw = std::fs::read_to_string(&path).expect("live_ct.json must exist");
    let fixtures: Vec<LiveCtFixture> = serde_json::from_str(&raw).unwrap();
    let opts_skip = ParseOptions {
        include_der: true,
        parse_extensions: false,
    };
    for f in &fixtures {
        let parsed =
            parse_leaf_input_with_options(&f.leaf_input, &f.extra_data, opts_skip).unwrap_or_else(
                || panic!("parse_leaf_input_with_options None for {}", f.name),
            );
        let chain = parsed.parse_chain();
        let source = Arc::new(Source {
            name: Arc::from(f.log_name.as_str()),
            url: Arc::from(f.log_url.as_str()),
        });
        let cert_link = format!(
            "{}ct/v1/get-entries?start={}&end={}",
            f.log_url, f.cert_index, f.cert_index
        );
        let msg = build_msg(
            parsed.leaf_cert,
            Some(chain),
            parsed.update_type,
            parsed.submission_timestamp,
            f.cert_index,
            cert_link,
            source,
        );
        let (_, _, doms) = serialize_all(&msg);
        assert_eq!(
            doms, f.expected_domains_only,
            "{}: domains_only diverged when parse_extensions=false",
            f.name
        );
    }
}

// ----- synthetic corpus generator -----

#[test]
#[ignore = "writes fixture files; refresh corpus by invoking explicitly"]
fn regenerate_synthetic_fixtures() {
    use rcgen::{
        CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
        SanType,
    };

    fn finalize(name: &str, der: Vec<u8>, sub_ts: f64) -> SyntheticFixture {
        let leaf = parse_certificate(&der, true)
            .unwrap_or_else(|| panic!("synthetic '{}' failed to parse", name));
        let msg = build_msg(
            leaf,
            None,
            Cow::Borrowed("X509LogEntry"),
            sub_ts,
            FIXED_CERT_INDEX,
            FIXED_CERT_LINK.to_string(),
            test_source(),
        );
        let (full, lite, doms) = serialize_all(&msg);
        SyntheticFixture {
            name: name.to_string(),
            der_b64: B64.encode(&der),
            submission_timestamp: sub_ts,
            expected_full: full,
            expected_lite: lite,
            expected_domains_only: doms,
        }
    }

    fn simple_sans(sans: Vec<&str>) -> Vec<u8> {
        let san_strs: Vec<String> = sans.into_iter().map(|s| s.to_string()).collect();
        let cert = rcgen::generate_simple_self_signed(san_strs).expect("rcgen failed");
        cert.cert.der().to_vec()
    }

    fn rich(name_cn: &str, sans: Vec<SanType>, is_ca: bool, key: KeyPair) -> Vec<u8> {
        let mut params = CertificateParams::default();
        params.distinguished_name.push(DnType::CommonName, name_cn);
        params.distinguished_name.push(DnType::OrganizationName, "Acme Snapshot Org");
        params.distinguished_name.push(DnType::CountryName, "US");
        params.subject_alt_names = sans;
        if is_ca {
            params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
            params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        } else {
            params.key_usages = vec![KeyUsagePurpose::DigitalSignature, KeyUsagePurpose::KeyEncipherment];
            params.extended_key_usages = vec![
                ExtendedKeyUsagePurpose::ServerAuth,
                ExtendedKeyUsagePurpose::ClientAuth,
            ];
        }
        let cert = params.self_signed(&key).expect("rcgen self_signed");
        cert.der().to_vec()
    }

    let mut fixtures = Vec::new();
    let base_ts = 1_700_000_001.0;

    // 1. RSA-default basic single SAN
    fixtures.push(finalize(
        "01_rsa_basic_single_san",
        simple_sans(vec!["one.example.test"]),
        base_ts,
    ));

    // 2. Multi-SAN (5)
    fixtures.push(finalize(
        "02_multi_san_5",
        simple_sans(vec![
            "a.example.test",
            "b.example.test",
            "c.example.test",
            "d.example.test",
            "e.example.test",
        ]),
        base_ts + 1.0,
    ));

    // 3. Wildcard SAN
    fixtures.push(finalize(
        "03_wildcard_san",
        simple_sans(vec!["*.wild.example.test", "wild.example.test"]),
        base_ts + 2.0,
    ));

    // 4. IDN punycode SAN
    fixtures.push(finalize(
        "04_idn_punycode_san",
        simple_sans(vec!["xn--bcher-kva.example.test", "xn--80akhbyknj4f.example.test"]),
        base_ts + 3.0,
    ));

    // 5. Long-name multi-attribute subject + EKU + multi-SAN
    {
        let key = KeyPair::generate().expect("keypair");
        let der = rich(
            "long-subject.example.test",
            vec![
                SanType::DnsName("long-subject.example.test".try_into().unwrap()),
                SanType::DnsName("alias.example.test".try_into().unwrap()),
            ],
            false,
            key,
        );
        fixtures.push(finalize("05_long_subject_eku", der, base_ts + 4.0));
    }

    // 6. IP-address SAN
    {
        let key = KeyPair::generate().expect("keypair");
        let der = rich(
            "ip-san.example.test",
            vec![
                SanType::IpAddress(std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 1))),
                SanType::IpAddress(std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)),
            ],
            false,
            key,
        );
        fixtures.push(finalize("06_ip_san", der, base_ts + 5.0));
    }

    // 7. Email-address SAN
    {
        let key = KeyPair::generate().expect("keypair");
        let der = rich(
            "email-san.example.test",
            vec![
                SanType::Rfc822Name("alice@example.test".try_into().unwrap()),
                SanType::DnsName("email-san.example.test".try_into().unwrap()),
            ],
            false,
            key,
        );
        fixtures.push(finalize("07_email_san", der, base_ts + 6.0));
    }

    // 8. CN-only, no SAN extension
    {
        let key = KeyPair::generate().expect("keypair");
        let mut params = CertificateParams::default();
        params.distinguished_name.push(DnType::CommonName, "cn-only.example.test");
        let cert = params.self_signed(&key).expect("cn-only self_signed");
        fixtures.push(finalize("08_cn_only_no_san", cert.der().to_vec(), base_ts + 7.0));
    }

    // 9. CA cert (basicConstraints CA:TRUE)
    {
        let key = KeyPair::generate().expect("keypair");
        let der = rich(
            "Snapshot Test Root CA",
            vec![SanType::DnsName("ca.example.test".try_into().unwrap())],
            true,
            key,
        );
        fixtures.push(finalize("09_ca_basic_constraints", der, base_ts + 8.0));
    }

    // 10. ECDSA-P256 keyed cert
    {
        let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("ecdsa keypair");
        let der = rich(
            "ecdsa.example.test",
            vec![
                SanType::DnsName("ecdsa.example.test".try_into().unwrap()),
                SanType::DnsName("ecdsa-alt.example.test".try_into().unwrap()),
            ],
            false,
            key,
        );
        fixtures.push(finalize("10_ecdsa_p256", der, base_ts + 9.0));
    }

    // 11. ECDSA-P384 keyed cert
    {
        let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).expect("ecdsa p384");
        let der = rich(
            "ecdsa-p384.example.test",
            vec![SanType::DnsName("ecdsa-p384.example.test".try_into().unwrap())],
            false,
            key,
        );
        fixtures.push(finalize("11_ecdsa_p384", der, base_ts + 10.0));
    }

    std::fs::create_dir_all(FIXTURE_DIR).unwrap();
    let path = PathBuf::from(FIXTURE_DIR).join("synthetic.json");
    let json = serde_json::to_string_pretty(&fixtures).unwrap();
    std::fs::write(&path, json).unwrap();
    eprintln!(
        "wrote {} synthetic fixtures to {}",
        fixtures.len(),
        path.display()
    );
}

// ----- live CT corpus generator -----

#[tokio::test(flavor = "current_thread")]
#[ignore = "fetches from live CT logs; refresh corpus by invoking explicitly"]
async fn regenerate_live_ct_fixtures() {
    // Three operators × ~17 entries each for issuer + shape diversity.
    // URLs are STH/get-entries roots — they end with `/`.
    let targets: &[(&str, &str, &str)] = &[
        (
            "letsencrypt_sycamore2026h2",
            "Let's Encrypt 'Sycamore2026h2'",
            "https://sycamore.ct.letsencrypt.org/2026h2/",
        ),
        (
            "google_argon2026h2",
            "Google 'Argon2026h2'",
            "https://ct.googleapis.com/logs/us1/argon2026h2/",
        ),
        (
            "cloudflare_nimbus2026",
            "Cloudflare 'Nimbus2026'",
            "https://ct.cloudflare.com/logs/nimbus2026/",
        ),
    ];

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .user_agent("certstream-server-rust snapshot-test")
        .build()
        .expect("reqwest client");

    let mut fixtures = Vec::new();
    for (slug, log_name, log_url) in targets {
        match fetch_log_window(&client, slug, log_name, log_url, 20).await {
            Ok(mut entries) => {
                eprintln!("  {}: fetched {} entries", slug, entries.len());
                fixtures.append(&mut entries);
            }
            Err(e) => {
                eprintln!("  {}: SKIPPED ({})", slug, e);
            }
        }
    }

    // Threshold accommodates a single CT log being temporarily unavailable.
    // With three logs at 20 entries each, the green-day count is 60; with
    // any single log down we still meet the 30-fixture floor.
    assert!(
        fixtures.len() >= 30,
        "expected ≥30 live CT fixtures, got {} — investigate log availability",
        fixtures.len()
    );

    std::fs::create_dir_all(FIXTURE_DIR).unwrap();
    let path = PathBuf::from(FIXTURE_DIR).join("live_ct.json");
    let json = serde_json::to_string_pretty(&fixtures).unwrap();
    std::fs::write(&path, json).unwrap();
    eprintln!(
        "wrote {} live CT fixtures to {}",
        fixtures.len(),
        path.display()
    );
}

async fn fetch_log_window(
    client: &reqwest::Client,
    slug: &str,
    log_name: &str,
    log_url: &str,
    want: usize,
) -> Result<Vec<LiveCtFixture>, String> {
    let sth_url = format!("{}ct/v1/get-sth", log_url);
    let sth: serde_json::Value = client
        .get(&sth_url)
        .send()
        .await
        .map_err(|e| format!("get-sth: {}", e))?
        .error_for_status()
        .map_err(|e| format!("get-sth status: {}", e))?
        .json()
        .await
        .map_err(|e| format!("get-sth json: {}", e))?;
    let tree_size = sth["tree_size"]
        .as_u64()
        .ok_or_else(|| "sth.tree_size missing".to_string())?;
    if tree_size < want as u64 + 5 {
        return Err(format!("tree_size {} too small", tree_size));
    }
    // Pull from ~50 behind the head so the entries are stable across retries.
    let start = tree_size.saturating_sub(50);
    let end = start + want as u64 - 1;
    let entries_url = format!(
        "{}ct/v1/get-entries?start={}&end={}",
        log_url, start, end
    );
    let entries: serde_json::Value = client
        .get(&entries_url)
        .send()
        .await
        .map_err(|e| format!("get-entries: {}", e))?
        .error_for_status()
        .map_err(|e| format!("get-entries status: {}", e))?
        .json()
        .await
        .map_err(|e| format!("get-entries json: {}", e))?;

    let arr = entries["entries"]
        .as_array()
        .ok_or_else(|| "entries.entries missing".to_string())?;

    let mut out = Vec::new();
    for (i, entry) in arr.iter().enumerate() {
        let leaf_input = entry["leaf_input"].as_str().unwrap_or("").to_string();
        let extra_data = entry["extra_data"].as_str().unwrap_or("").to_string();
        let cert_index = start + i as u64;
        let parsed = match parse_leaf_input(&leaf_input, &extra_data) {
            Some(p) => p,
            None => {
                eprintln!("    {} entry {}: parse_leaf_input returned None, skipping", slug, cert_index);
                continue;
            }
        };
        let chain = parsed.parse_chain();
        let source = Arc::new(Source {
            name: Arc::from(log_name),
            url: Arc::from(log_url),
        });
        let cert_link = format!(
            "{}ct/v1/get-entries?start={}&end={}",
            log_url, cert_index, cert_index
        );
        let msg = build_msg(
            parsed.leaf_cert,
            Some(chain),
            parsed.update_type,
            parsed.submission_timestamp,
            cert_index,
            cert_link,
            source,
        );
        let (full, lite, doms) = serialize_all(&msg);
        out.push(LiveCtFixture {
            name: format!("{}_{:03}", slug, i),
            log_name: log_name.to_string(),
            log_url: log_url.to_string(),
            cert_index,
            leaf_input,
            extra_data,
            expected_full: full,
            expected_lite: lite,
            expected_domains_only: doms,
        });
    }

    Ok(out)
}
