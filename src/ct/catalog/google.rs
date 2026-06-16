//! Google v3 CT log catalog sources.
//!
//! Both the `usable` and `all` lists are signed with the same pinned RSA-SHA256
//! key (SPKI SHA-256 `f1d8b68e…`, captured + validated 2026-06-02). They differ
//! only in scope and code-default authority: `usable` is the vetted subset and
//! is authoritative by default; `all` widens to pending/qualified logs and is
//! non-authoritative until an operator opts in via
//! `ct_log.catalog_authority_overrides.google_v3_all: true`.

use super::verify::{verify_rsa_sha256_pem, VerifyError};
use super::SignedCatalog;

/// Pinned Google CT log-list signing key (SPKI PEM), bundled at compile time.
/// Rotation = replace these bytes and refresh the test fixture pair.
const GOOGLE_V3_PUBKEY_PEM: &str = include_str!("keys/google_v3_pubkey.pem");

/// First 16 hex of the SPKI SHA-256 of the embedded key. Asserted against the
/// embedded bytes by `verify::tests::embedded_key_fingerprint_matches_rfc_record`.
const GOOGLE_V3_FINGERPRINT16: &str = "f1d8b68e50210d8e";

pub struct GoogleV3Usable;

impl SignedCatalog for GoogleV3Usable {
    fn name(&self) -> &'static str {
        "google_v3_usable"
    }
    fn code_default_runtime_authoritative(&self) -> bool {
        true
    }
    fn list_url(&self) -> &'static str {
        "https://www.gstatic.com/ct/log_list/v3/log_list.json"
    }
    fn sig_url(&self) -> Option<&'static str> {
        Some("https://www.gstatic.com/ct/log_list/v3/log_list.sig")
    }
    fn expected_key_fingerprint(&self) -> Option<&'static str> {
        Some(GOOGLE_V3_FINGERPRINT16)
    }
    fn verify(&self, bytes: &[u8], sig: &[u8]) -> Result<(), VerifyError> {
        verify_rsa_sha256_pem(GOOGLE_V3_PUBKEY_PEM, bytes, sig)
    }
}

pub struct GoogleV3All;

impl SignedCatalog for GoogleV3All {
    fn name(&self) -> &'static str {
        "google_v3_all"
    }
    fn code_default_runtime_authoritative(&self) -> bool {
        false
    }
    fn list_url(&self) -> &'static str {
        "https://www.gstatic.com/ct/log_list/v3/all_logs_list.json"
    }
    fn sig_url(&self) -> Option<&'static str> {
        Some("https://www.gstatic.com/ct/log_list/v3/all_logs_list.sig")
    }
    fn expected_key_fingerprint(&self) -> Option<&'static str> {
        Some(GOOGLE_V3_FINGERPRINT16)
    }
    fn verify(&self, bytes: &[u8], sig: &[u8]) -> Result<(), VerifyError> {
        verify_rsa_sha256_pem(GOOGLE_V3_PUBKEY_PEM, bytes, sig)
    }
}
