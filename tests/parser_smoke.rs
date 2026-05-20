//! Parser smoke tests at the integration boundary.
//!
//! These cover the `parse_certificate` contract from *outside* the crate —
//! a thin layer above the unit tests in `src/ct/parser.rs`. Goals:
//!   1. Confirm the public `pub use` surface stays callable from external code
//!      (catches accidental visibility regressions).
//!   2. Spot-check adversarial inputs that should return `None`, not panic.
//!
//! For systematic adversarial coverage, see `fuzz/fuzz_targets/parse_certificate.rs`.

use certstream_server_rust::ct::parse_certificate;

#[test]
fn empty_input_returns_none() {
    assert!(parse_certificate(&[], true).is_none());
    assert!(parse_certificate(&[], false).is_none());
}

#[test]
fn random_bytes_return_none_not_panic() {
    // A handful of structured-but-invalid blobs the parser is likely to
    // exercise different reject paths on.
    let cases: &[&[u8]] = &[
        b"\x00",
        b"\x30\x00",                                    // empty SEQUENCE
        b"\x30\x82\xff\xff",                             // length larger than buffer
        b"not-a-cert-at-all",
        &[0xff; 32],
        &[0x30, 0x82, 0x00, 0x10, 0x01, 0x02, 0x03],   // truncated body
    ];
    for (i, data) in cases.iter().enumerate() {
        assert!(
            parse_certificate(data, true).is_none(),
            "case {i} (is_leaf=true) should return None, not panic"
        );
        assert!(
            parse_certificate(data, false).is_none(),
            "case {i} (is_leaf=false) should return None, not panic"
        );
    }
}

#[test]
fn round_trips_a_self_signed_cert() {
    // Generate a self-signed cert via rcgen and confirm the parser produces
    // a populated `LeafCert` for well-formed input. The SAN "integration.test"
    // lands in the all_domains field; the subject CN is rcgen's default.
    let cert = rcgen::generate_simple_self_signed(vec!["integration.test".into()])
        .expect("rcgen failed");
    let der = cert.cert.der().to_vec();

    let parsed = parse_certificate(&der, true).expect("valid DER must parse");

    let subject_agg = parsed.subject.aggregated.as_deref().unwrap_or("");
    assert!(
        !subject_agg.is_empty(),
        "aggregated subject must be non-empty for a valid cert"
    );

    assert!(
        parsed.all_domains.iter().any(|d: &String| d == "integration.test"),
        "all_domains must surface the SAN, got {:?}",
        parsed.all_domains
    );

    // Fingerprint sanity: SHA-1 formatted as colon-separated uppercase hex
    // (20 bytes → 40 hex chars + 19 colons = 59 chars). This is the canonical
    // CT log presentation and several certstream clients parse it as-is.
    let fp: &str = parsed.fingerprint.as_ref();
    assert_eq!(fp.len(), 59, "SHA-1 fingerprint must be colon-separated hex");
    assert!(fp.chars().all(|c| c.is_ascii_hexdigit() || c == ':'));
    assert_eq!(fp.matches(':').count(), 19);
}
