//! PKCS#1 v1.5 RSA-SHA256 detached-signature verification for signed CT log
//! catalogs.
//!
//! Uses the `rsa` crate's own re-exported `sha2` (0.10) so the `Pkcs1v15Sign`
//! generic and the digest stay on the same `digest` major — the crate's own
//! `sha2` 0.11 (used elsewhere for cert fingerprints) is a different `digest`
//! line and is deliberately NOT used here.

use rsa::pkcs8::DecodePublicKey;
use rsa::sha2::{Digest, Sha256};
use rsa::{Pkcs1v15Sign, RsaPublicKey};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum VerifyError {
    #[error("trust anchor PEM did not parse as an RSA public key")]
    BadKey,
    #[error("signature did not verify against the pinned key")]
    BadSignature,
}

/// Verify a detached PKCS#1 v1.5 RSA-SHA256 `signature` over `message` against
/// an RSA public key in SPKI PEM form (`-----BEGIN PUBLIC KEY-----`).
pub fn verify_rsa_sha256_pem(
    pubkey_pem: &str,
    message: &[u8],
    signature: &[u8],
) -> Result<(), VerifyError> {
    let key = RsaPublicKey::from_public_key_pem(pubkey_pem).map_err(|_| VerifyError::BadKey)?;
    let digest = Sha256::digest(message);
    key.verify(Pkcs1v15Sign::new::<Sha256>(), &digest, signature)
        .map_err(|_| VerifyError::BadSignature)
}

/// First 16 hex chars of the SHA-256 of the SPKI DER bytes of an RSA public key
/// in PEM form. Used by the test that asserts the embedded trust anchor matches
/// the RFC-recorded fingerprint; the runtime value is the hardcoded constant in
/// `google.rs` (which this test pins to the embedded key).
#[cfg(test)]
pub fn spki_sha256_fingerprint16(pubkey_pem: &str) -> String {
    let key = RsaPublicKey::from_public_key_pem(pubkey_pem)
        .expect("embedded trust anchor PEM must parse");
    let der = rsa::pkcs8::EncodePublicKey::to_public_key_der(&key)
        .expect("embedded trust anchor must re-encode to SPKI DER");
    let digest = Sha256::digest(der.as_bytes());
    hex16(&digest)
}

#[cfg(test)]
fn hex16(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(16);
    for b in bytes.iter().take(8) {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_garbage_pem() {
        assert!(matches!(
            verify_rsa_sha256_pem("not a pem", b"x", b"y"),
            Err(VerifyError::BadKey)
        ));
    }

    /// Real Google trust anchor + a real (stored) log_list.json + its detached
    /// .sig must verify end-to-end. Locks the embedded key against live Google
    /// data captured 2026-06-02. If Google rotates the key, refresh the fixture
    /// pair AND the embedded key together.
    #[test]
    fn real_google_fixture_verifies_against_embedded_key() {
        let pem = include_str!("keys/google_v3_pubkey.pem");
        let json = include_bytes!("../../../tests/fixtures/catalog/google_v3_log_list.json");
        let sig = include_bytes!("../../../tests/fixtures/catalog/google_v3_log_list.sig");
        assert!(
            verify_rsa_sha256_pem(pem, json, sig).is_ok(),
            "embedded Google trust anchor must verify the stored real log_list.json/.sig pair"
        );
        // A one-byte tamper on real data must fail.
        let mut tampered = json.to_vec();
        tampered.push(b'x');
        assert!(verify_rsa_sha256_pem(pem, &tampered, sig).is_err());
    }

    /// The embedded trust anchor's SPKI fingerprint must match the value
/// recorded for the embedded Google trust anchor. Guards against a wrong or
/// rotated key being committed without updating the expected fingerprint.
    #[test]
    fn embedded_key_fingerprint_matches_rfc_record() {
        let pem = include_str!("keys/google_v3_pubkey.pem");
        assert_eq!(spki_sha256_fingerprint16(pem), "f1d8b68e50210d8e");
    }
}
