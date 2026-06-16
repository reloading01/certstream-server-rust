//! Issuer-CA SPKI TLS pinning for the Apple catalog fetch (`valid.apple.com`).
//!
//! Apple publishes no detached signature, so the authenticity signal for its
//! log list is the TLS connection. Beyond normal WebPKI chain validation, we
//! pin the issuer CA's SubjectPublicKeyInfo so a mis-issued-but-WebPKI-valid
//! certificate from a different CA cannot impersonate the catalog endpoint. We
//! pin the issuer SPKI, not the leaf, so Apple can rotate the leaf freely;
//! rotation of the issuer CA is a deliberate pin update.
//!
//! Mechanism: a `rustls::ServerCertVerifier` that first delegates to the default
//! WebPKI verifier (no weakening of normal validation), then requires one of the
//! presented `intermediates` to match the pinned SPKI hash. On mismatch it bumps
//! `certstream_ct_catalog_tls_pin_failed_total` and fails the handshake; the
//! Apple fetch then no-ops for that cycle (Apple is non-authoritative anyway, so
//! there is zero spawn impact).

use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::WebPkiServerVerifier;
use rustls::crypto::aws_lc_rs;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, Error as RustlsError, RootCertStore, SignatureScheme};
use sha2::{Digest, Sha256};
use tracing::{error, warn};

/// SPKI SHA-256 of `Apple Public Server RSA CA 1 - G1` (the issuer CA in the
/// `valid.apple.com` chain). Pin target. Asserted against the stored fixture by
/// `tests::fixture_issuer_spki_matches_pin`; rotation = update both together.
const APPLE_ISSUER_SPKI_SHA256: [u8; 32] = [
    0xf5, 0x5c, 0x39, 0x3b, 0x3f, 0x8c, 0xdf, 0xa6, 0xda, 0xa4, 0x09, 0x43, 0xa3, 0x3f, 0xa7, 0x8e,
    0x0c, 0x1a, 0x17, 0xe0, 0x1a, 0x40, 0xba, 0xca, 0x4a, 0x68, 0x5c, 0x65, 0x99, 0xf1, 0x01, 0xc6,
];

/// SHA-256 of a certificate's SubjectPublicKeyInfo (the raw SPKI DER bytes).
/// `None` if the DER does not parse as an X.509 certificate.
fn spki_sha256(cert_der: &[u8]) -> Option<[u8; 32]> {
    use x509_parser::prelude::FromDer;
    let (_, cert) = x509_parser::certificate::X509Certificate::from_der(cert_der).ok()?;
    let digest = Sha256::digest(cert.tbs_certificate.subject_pki.raw);
    Some(digest.into())
}

/// Returns true if any cert in `chain` carries the pinned issuer SPKI.
fn chain_contains_pin(chain: &[CertificateDer<'_>], pin: &[u8; 32]) -> bool {
    chain
        .iter()
        .filter_map(|c| spki_sha256(c.as_ref()))
        .any(|spki| &spki == pin)
}

/// A `ServerCertVerifier` that runs the inner WebPKI verifier, then additionally
/// requires the pinned issuer SPKI to appear among the presented intermediates.
#[derive(Debug)]
struct PinnedIssuerVerifier {
    inner: Arc<dyn ServerCertVerifier>,
    pin: [u8; 32],
}

impl ServerCertVerifier for PinnedIssuerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        // 1) Normal WebPKI validation first — never weaken it.
        self.inner
            .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)?;

        // 2) Issuer-SPKI pin: the pinned CA must be in the presented chain.
        if chain_contains_pin(intermediates, &self.pin) {
            Ok(ServerCertVerified::assertion())
        } else {
            metrics::counter!("certstream_ct_catalog_tls_pin_failed_total").increment(1);
            error!(
                "Apple catalog TLS pin FAILED: chain is WebPKI-valid but the pinned issuer-CA \
                 SPKI was not present — refusing the connection"
            );
            Err(RustlsError::General(
                "Apple catalog issuer-CA SPKI pin mismatch".into(),
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

/// Build a dedicated reqwest client that pins the Apple issuer-CA SPKI on top of
/// normal WebPKI validation. Used ONLY for the `apple` catalog fetch. `timeout`
/// The timeout bounds the fetch so a hung Apple endpoint cannot wedge startup.
pub fn build_apple_pinned_client(timeout: std::time::Duration) -> Result<reqwest::Client, String> {
    let provider = Arc::new(aws_lc_rs::default_provider());

    // Trust roots from the OS store (same source rustls-native-certs feeds the
    // default reqwest client).
    let mut roots = RootCertStore::empty();
    let native = rustls_native_certs::load_native_certs();
    for cert in native.certs {
        let _ = roots.add(cert);
    }
    if !native.errors.is_empty() {
        warn!(errors = ?native.errors, "some native root certs failed to load");
    }
    if roots.is_empty() {
        return Err("no native root certificates loaded; cannot validate Apple TLS".into());
    }

    let inner = WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider.clone())
        .build()
        .map_err(|e| format!("failed to build WebPKI verifier: {e}"))?;

    let verifier = Arc::new(PinnedIssuerVerifier {
        inner,
        pin: APPLE_ISSUER_SPKI_SHA256,
    });

    let config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("failed to set TLS protocol versions: {e}"))?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();

    reqwest::Client::builder()
        .user_agent(concat!("certstream-server-rust/", env!("CARGO_PKG_VERSION")))
        .use_preconfigured_tls(config)
        .timeout(timeout)
        .build()
        .map_err(|e| format!("failed to build pinned Apple client: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The pinned SPKI constant must equal the SPKI of the real stored issuer CA.
    /// Locks the pin to an actual cert; guards a typo or a stale rotation.
    #[test]
    fn fixture_issuer_spki_matches_pin() {
        let der = include_bytes!("../../../tests/fixtures/catalog/apple_issuer_ca.der");
        let spki = spki_sha256(der).expect("fixture must parse as X.509");
        assert_eq!(spki, APPLE_ISSUER_SPKI_SHA256);
    }

    /// A chain containing the pinned issuer CA passes the membership check; a
    /// chain without it does not.
    #[test]
    fn chain_membership_accept_and_reject() {
        let apple_ca = CertificateDer::from(
            include_bytes!("../../../tests/fixtures/catalog/apple_issuer_ca.der").to_vec(),
        );
        // The Google trust-anchor PEM is a *public key*, not a cert — its DER
        // won't parse as X.509, so spki_sha256 returns None and it can't match.
        // Use a second real cert that is NOT the Apple CA: the Google log_list
        // fixture is not a cert either, so build a "wrong" chain from an empty set
        // and from a chain that omits the pin.
        assert!(chain_contains_pin(
            std::slice::from_ref(&apple_ca),
            &APPLE_ISSUER_SPKI_SHA256
        ));
        // Empty chain → no match.
        assert!(!chain_contains_pin(&[], &APPLE_ISSUER_SPKI_SHA256));
        // Right chain, wrong pin → no match.
        let wrong_pin = [0u8; 32];
        assert!(!chain_contains_pin(
            std::slice::from_ref(&apple_ca),
            &wrong_pin
        ));
    }

    /// Non-certificate DER (e.g. a bare public key) yields no SPKI hash.
    #[test]
    fn non_cert_der_yields_none() {
        assert!(spki_sha256(b"not a certificate").is_none());
    }
}
