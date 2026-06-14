//! Signed CT log catalog source registry and signature verification.
//!
//! Upstream v1.5.0 fetched the Google + Apple log lists over plain `reqwest`
//! with no catalog-level verification. This module replaces the
//! anonymous-URL inputs (`ct_logs_url` / `additional_log_lists`) with a
//! code-owned registry of `SignedCatalog` sources, each carrying its fetch
//! endpoints, a verifier (pinned RSA-SHA256 for Google; none for Apple), and a
//! code-default runtime authority.
//!
//! A signature failure never halts ingest. The raw bytes are still returned for
//! parsing, but the source is forced non-authoritative for that cycle and
//! `certstream_ct_catalog_source_verified=0` exposes the failure.
//!
//! The trait is intentionally **synchronous** (object-safe, no `async_trait`
//! dep); the network I/O lives in the free `fetch_and_verify()` async fn.

mod apple;
mod google;
mod tls_pin;
mod verify;

pub use apple::Apple;
pub use google::{GoogleV3All, GoogleV3Usable};
pub use tls_pin::build_apple_pinned_client;
pub use verify::VerifyError;

use reqwest::Client;
use thiserror::Error;
use tracing::{error, warn};

/// Stable catalog-source IDs.
pub const CATALOG_SOURCE_IDS: &[&str] = &["google_v3_usable", "google_v3_all", "apple"];

#[derive(Error, Debug)]
pub enum CatalogFetchError {
    #[error("HTTP error fetching {what}: {source}")]
    Http {
        what: &'static str,
        #[source]
        source: reqwest::Error,
    },
}

/// A CT Log Catalog Source: where to fetch it, how to authenticate it, and its
/// code-default runtime authority. One impl per source; adding a future catalog
/// is one module here (+ a Python mirror) and an entry in [`catalog_registry`].
pub trait SignedCatalog: Send + Sync {
    /// Stable short identifier — the `catalog_source` metric label.
    fn name(&self) -> &'static str;
    /// Code-default: whether entries from this source drive fork auto-ingest.
    /// The effective value is `code_default && verified && !override_disables`,
    /// resolved by the caller against `ct_log.catalog_authority_overrides`.
    fn code_default_runtime_authoritative(&self) -> bool;
    /// The log-list JSON URL.
    fn list_url(&self) -> &'static str;
    /// The detached-signature URL, or `None` for a documented unverified source
    /// (Apple does not publish a detached signature).
    fn sig_url(&self) -> Option<&'static str>;
    /// `expected_key_fingerprint` for the failure-path ERROR log: first 16 hex
    /// chars of the embedded trust anchor's SPKI SHA-256. `None` when there is
    /// no verifier (Apple).
    fn expected_key_fingerprint(&self) -> Option<&'static str>;
    /// Verify a detached signature over `bytes`. Called only when `sig_url()`
    /// is `Some`. `Ok(())` = verified; `Err` = rotation / MITM / corruption.
    fn verify(&self, bytes: &[u8], sig: &[u8]) -> Result<(), VerifyError>;
}

/// Result of a successful catalog *fetch* (bytes in hand) with the verification
/// verdict attached. Network/IO failure is `Err` from [`fetch_and_verify`], not
/// a variant here — so `raw_bytes` is always parseable for audit.
pub struct CatalogFetch {
    pub raw_bytes: Vec<u8>,
    /// A verifier ran AND the signature passed.
    pub verified: bool,
    /// A verifier exists for this source.
    pub verifier_present: bool,
}

/// The compile-time registry of catalog sources, in fetch order.
pub fn catalog_registry() -> Vec<Box<dyn SignedCatalog>> {
    vec![
        Box::new(GoogleV3Usable),
        Box::new(GoogleV3All),
        Box::new(Apple),
    ]
}

/// Fetch a catalog's list (+ signature) and run its verifier. `Err` ONLY on
/// network/IO failure (bytes unobtainable). The verification *outcome* —
/// including "no verifier" (Apple) and "verifier rejected" (rotation/MITM) — is
/// reported in [`CatalogFetch`], never as `Err`, so the raw bytes stay
/// parseable for audit visibility. Emits the verified / verifier_present gauges.
pub async fn fetch_and_verify(
    client: &Client,
    cat: &dyn SignedCatalog,
) -> Result<CatalogFetch, CatalogFetchError> {
    let raw_bytes = client
        .get(cat.list_url())
        .send()
        .await
        .and_then(|r| r.error_for_status())
        .map_err(|source| CatalogFetchError::Http {
            what: "log list",
            source,
        })?
        .bytes()
        .await
        .map_err(|source| CatalogFetchError::Http {
            what: "log list body",
            source,
        })?
        .to_vec();

    let (verified, verifier_present) = match cat.sig_url() {
        // Documented unverified source: nothing to verify.
        None => (false, false),
        Some(sig_url) => {
            let sig = client
                .get(sig_url)
                .send()
                .await
                .and_then(|r| r.error_for_status())
                .map_err(|source| CatalogFetchError::Http {
                    what: "signature",
                    source,
                })?
                .bytes()
                .await
                .map_err(|source| CatalogFetchError::Http {
                    what: "signature body",
                    source,
                })?;
            match cat.verify(&raw_bytes, &sig) {
                Ok(()) => (true, true),
                Err(e) => {
                    error!(
                        catalog_source = cat.name(),
                        expected_key_fingerprint = cat.expected_key_fingerprint().unwrap_or(""),
                        error = %e,
                        "catalog signature verification FAILED — forcing non-authoritative this cycle"
                    );
                    (false, true)
                }
            }
        }
    };

    if !verifier_present {
        warn!(
            catalog_source = cat.name(),
            "catalog has no verifier (unverified-source policy); never runtime-authoritative"
        );
    }

    metrics::gauge!(
        "certstream_ct_catalog_source_verified",
        "catalog_source" => cat.name()
    )
    .set(if verified { 1.0 } else { 0.0 });
    metrics::gauge!(
        "certstream_ct_catalog_source_verifier_present",
        "catalog_source" => cat.name()
    )
    .set(if verifier_present { 1.0 } else { 0.0 });

    Ok(CatalogFetch {
        raw_bytes,
        verified,
        verifier_present,
    })
}

/// Resolve the effective runtime authority of a catalog source given its fetch
/// verdict and the operator's `catalog_authority_overrides`.
///
/// - `verified == false` → **never** authoritative (covers Apple permanently and
///   a failed-signature Google catalog), regardless of override.
/// - otherwise the override value wins if present, else the code default.
///
/// So an override can only *grant* authority to a source that currently
/// verifies; it can never promote an unverified source such as Apple.
pub fn effective_runtime_authoritative(
    cat: &dyn SignedCatalog,
    fetch: &CatalogFetch,
    overrides: &std::collections::HashMap<String, bool>,
) -> bool {
    if !fetch.verified {
        return false;
    }
    match overrides.get(cat.name()) {
        Some(&v) => v,
        None => cat.code_default_runtime_authoritative(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_ids_match_pinned_set() {
        let ids: Vec<&str> = catalog_registry().iter().map(|c| c.name()).collect();
        assert_eq!(ids, CATALOG_SOURCE_IDS, "registry order/IDs drifted from the pinned parity set");
    }

    #[test]
    fn apple_is_unverified_and_never_authoritative() {
        let apple = Apple;
        assert!(apple.sig_url().is_none());
        assert!(apple.expected_key_fingerprint().is_none());
        assert!(!apple.code_default_runtime_authoritative());
        // Even with an explicit override=true, an unverified source stays non-authoritative.
        let fetch = CatalogFetch { raw_bytes: vec![], verified: false, verifier_present: false };
        let mut ov = std::collections::HashMap::new();
        ov.insert("apple".to_string(), true);
        assert!(!effective_runtime_authoritative(&apple, &fetch, &ov));
    }

    #[test]
    fn google_usable_authoritative_by_default_when_verified() {
        let g = GoogleV3Usable;
        assert!(g.code_default_runtime_authoritative());
        let verified = CatalogFetch { raw_bytes: vec![], verified: true, verifier_present: true };
        let empty = std::collections::HashMap::new();
        assert!(effective_runtime_authoritative(&g, &verified, &empty));
        // A failed signature forces non-authoritative regardless of code default.
        let failed = CatalogFetch { raw_bytes: vec![], verified: false, verifier_present: true };
        assert!(!effective_runtime_authoritative(&g, &failed, &empty));
    }

    #[test]
    fn google_all_non_authoritative_until_overridden() {
        let g = GoogleV3All;
        assert!(!g.code_default_runtime_authoritative());
        let verified = CatalogFetch { raw_bytes: vec![], verified: true, verifier_present: true };
        let empty = std::collections::HashMap::new();
        assert!(!effective_runtime_authoritative(&g, &verified, &empty));
        // Operator opt-in grants authority to a verified source.
        let mut ov = std::collections::HashMap::new();
        ov.insert("google_v3_all".to_string(), true);
        assert!(effective_runtime_authoritative(&g, &verified, &ov));
    }
}
