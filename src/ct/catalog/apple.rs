//! Apple CT log catalog source.
//!
//! Apple does not publish a detached signature for this catalog. Authenticity
//! rests on the TLS-authenticated fetch of `valid.apple.com`. Apple therefore
//! has no detached-signature verifier and is non-runtime-authoritative by
//! default. Apple-only logs reach the runtime only via an explicit
//! `custom_logs` or `static_logs` declaration.

use super::verify::VerifyError;
use super::SignedCatalog;

pub struct Apple;

impl SignedCatalog for Apple {
    fn name(&self) -> &'static str {
        "apple"
    }
    fn code_default_runtime_authoritative(&self) -> bool {
        false
    }
    fn list_url(&self) -> &'static str {
        "https://valid.apple.com/ct/log_list/current_log_list.json"
    }
    fn sig_url(&self) -> Option<&'static str> {
        // No detached signature exists. `fetch_and_verify` treats a `None`
        // sig_url as the documented unverified-source policy and never calls
        // `verify`.
        None
    }
    fn expected_key_fingerprint(&self) -> Option<&'static str> {
        None
    }
    fn verify(&self, _bytes: &[u8], _sig: &[u8]) -> Result<(), VerifyError> {
        // Unreachable in normal flow (sig_url() is None). Defensive: an Apple
        // catalog can never produce a verified signature.
        Err(VerifyError::BadSignature)
    }
}
