//! Mechanism 2 of mimid-75nk (bead mimid-75nk.6): a client certificate
//! authenticated by DANE TLSA records (draft-atwood-mimi-provider-auth-00 §6,
//! draft-ietf-dance-client-auth-17 Format 1).
//!
//! The certificate is the one the request's connection presented
//! ([`ClientCertificate`](crate::tls::ClientCertificate)); the TLS layer
//! asks for one and checks only that the client holds its key
//! ([`crate::tls`]). For the request's `From` domain, mimid looks up TLSA
//! records at `_mimi._client.<domain>` with a DNSSEC-validating resolver
//! and checks the certificate against them (RFC 6698 §2.1, RFC 7671). If
//! one matches, the authenticated domain is the `From` domain.
//!
//! - Only a "secure" answer counts (§6: "the target provider MUST treat
//!   the TLSA records as usable only if their validation status is
//!   'secure'"). A "bogus" answer is refused.
//! - No TLSA records at the name: the mechanism does not apply, and the
//!   next one (PKIX) may still authenticate the certificate.
//! - DANE-EE(3): the leaf, or its SubjectPublicKeyInfo, matches the
//!   record. Its names, validity and key usage are not checked (RFC 7671
//!   §5.1).
//! - DANE-TA(2): a certificate of the presented chain above the leaf
//!   matches the record. The path from the leaf up to it validates per
//!   RFC 5280 with it as the trust anchor, the leaf's extended key usage,
//!   if any, includes id-kp-clientAuth, and a subjectAltName dNSName of the
//!   leaf matches the `From` domain (RFC 7671 §5.2.2, §5.2.3).
//! - PKIX-TA(0) and PKIX-EE(1) records are unusable, as for SMTP (RFC 7672
//!   §3.1.3): they would need a public CA trust store for clients, which is
//!   what the draft exists to avoid. So are unknown usages, selectors and
//!   matching types (RFC 6698 §4.1).
//!
//! The TLSA parsing and matching here are mimid's own until crate-pkix's
//! `pkix-dane` (PKIX-j32w.1) is written; then mimid uses it (see the TODO
//! on [`matches()`]).
//!
//! # Limitations
//!
//! - The reference identity for DANE-TA is the provider domain, not the
//!   TLSA owner name: draft-ietf-dance-client-auth-17 §5 asks for the name
//!   the client conveyed in its DANE Client Identity TLS extension, which
//!   for Format 1 is `_mimi._client.<domain>`, an underscore name a CA
//!   will not usually issue. The provider-auth draft does not say; mimid
//!   matches the `From` domain, as for PKIX ([`super::pkix`]).
//! - The DANE Client Identity TLS extension is neither read nor sent; the
//!   lookup waits for `From`, as the draft allows.
//! - A DANE-TA record whose trust anchor is not in the presented chain
//!   (a bare public key, RFC 7671 §5.2.2) does not match.
//! - Through a proxy only the leaf arrives, so only DANE-EE works.
//! - No revocation checking.

use std::sync::Arc;

use der::{Decode, Encode};
use pkix_identity::{ServerName, verify_dns_name};
use pkix_path::{DefaultVerifier, TrustAnchor, ValidationPolicy, validate_path};
use sha2::{Digest, Sha256, Sha512};
use x509_cert::Certificate;

use super::dns::{DnssecStatus, TxtLookupError};
use super::pkix::{MAX_CHAIN_LEN, MIN_RSA_BITS, client_auth, leaf_key_id};
use super::{
    AuthenticatedProvider, BoxFuture, InboundRequest, Mechanism, Outcome, ProviderAuthenticator,
    Refusal,
};
use crate::config::Domain;

/// The service label of a MIMI provider's client TLSA records
/// (draft-atwood-mimi-provider-auth-00 §6).
pub const SERVICE_LABEL: &str = "_mimi";

/// The most TLSA records of one answer that are tried. INVENTED, NOT FROM
/// SPEC.
pub const MAX_TLSA_RECORDS: usize = 8;

/// RFC 6698 §2.1.1 certificate usages.
const DANE_TA: u8 = 2;
const DANE_EE: u8 = 3;

/// RFC 6698 §2.1.2 selectors.
const FULL_CERTIFICATE: u8 = 0;
const SUBJECT_PUBLIC_KEY_INFO: u8 = 1;

/// RFC 6698 §2.1.3 matching types.
const EXACT: u8 = 0;
const SHA2_256: u8 = 1;
const SHA2_512: u8 = 2;

/// One TLSA record's data (RFC 6698 §2.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsaRecord {
    /// The certificate usage.
    pub usage: u8,
    /// The selector.
    pub selector: u8,
    /// The matching type.
    pub matching: u8,
    /// The certificate association data.
    pub data: Vec<u8>,
}

impl TlsaRecord {
    /// Whether mimid can use this record (see the module documentation).
    fn usable(&self) -> bool {
        matches!(self.usage, DANE_TA | DANE_EE)
            && matches!(self.selector, FULL_CERTIFICATE | SUBJECT_PUBLIC_KEY_INFO)
            && matches!(self.matching, EXACT | SHA2_256 | SHA2_512)
    }
}

/// Looks up TLSA records. Its failures are those of a TXT lookup
/// ([`TxtLookupError`]).
pub trait TlsaResolver: Send + Sync {
    /// The TLSA records at `name`, an absolute domain name, with the
    /// DNSSEC status of each.
    fn tlsa<'a>(
        &'a self,
        name: &'a str,
    ) -> BoxFuture<'a, Result<Vec<(TlsaRecord, DnssecStatus)>, TxtLookupError>>;
}

/// Whether `certificate` (DER) matches `record`'s selector, matching type
/// and data (RFC 6698 §2.1.2, §2.1.3). `None` if the certificate does not
/// decode.
///
/// TODO(PKIX-j32w.1): replace with crate-pkix's `pkix-dane` matching when
/// it exists; `TlsaRecord` and this function are a stopgap for it.
pub fn matches(record: &TlsaRecord, certificate: &[u8]) -> Option<bool> {
    let selected = match record.selector {
        FULL_CERTIFICATE => certificate.to_vec(),
        SUBJECT_PUBLIC_KEY_INFO => Certificate::from_der(certificate)
            .ok()?
            .tbs_certificate
            .subject_public_key_info
            .to_der()
            .ok()?,
        _ => return Some(false),
    };
    let associated = match record.matching {
        EXACT => selected,
        SHA2_256 => Sha256::digest(&selected).to_vec(),
        SHA2_512 => Sha512::digest(&selected).to_vec(),
        _ => return Some(false),
    };
    Some(associated == record.data)
}

/// Mechanism 2: client certificates checked against the source's TLSA
/// records.
pub struct DaneCertificates {
    resolver: Arc<dyn TlsaResolver>,
}

impl std::fmt::Debug for DaneCertificates {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DaneCertificates").finish_non_exhaustive()
    }
}

impl DaneCertificates {
    /// TLSA records looked up with `resolver`, which must validate DNSSEC.
    pub fn new(resolver: Arc<dyn TlsaResolver>) -> Self {
        Self { resolver }
    }

    async fn check(&self, chain: &[Vec<u8>], from: &Domain, now: i64) -> Outcome {
        if chain.is_empty() || chain.len() > MAX_CHAIN_LEN {
            return Outcome::Refused(Refusal::Certificate("chain length"));
        }
        let name = format!("{SERVICE_LABEL}._client.{from}.");
        let answer = match self.resolver.tlsa(&name).await {
            Ok(answer) => answer,
            Err(TxtLookupError::NoRecords) => return Outcome::NotApplicable,
            Err(TxtLookupError::Bogus) => return Outcome::Refused(Refusal::DnssecBogus),
            Err(TxtLookupError::Failed(reason)) => {
                tracing::debug!(name, reason, "TLSA lookup failed");
                return Outcome::Refused(Refusal::DnsFailure);
            }
        };
        if answer.iter().any(|(_, s)| *s != DnssecStatus::Secure) {
            return Outcome::Refused(Refusal::NotSecure);
        }
        let usable: Vec<&TlsaRecord> = answer
            .iter()
            .map(|(record, _)| record)
            .filter(|r| r.usable())
            .take(MAX_TLSA_RECORDS)
            .collect();
        if usable.is_empty() {
            return Outcome::Refused(Refusal::Certificate("no usable TLSA record"));
        }
        let leaf = &chain[0];
        let mut refusal = Refusal::Certificate("no TLSA record matches");
        for record in usable {
            let verdict = match record.usage {
                DANE_EE => match matches(record, leaf) {
                    Some(true) => Ok(()),
                    Some(false) => continue,
                    None => Err(Refusal::Certificate("not X.509")),
                },
                _ => match dane_ta(record, chain, from, now) {
                    None => continue,
                    Some(verdict) => verdict,
                },
            };
            match verdict {
                Ok(()) => {
                    return Outcome::Authenticated(AuthenticatedProvider {
                        domain: from.clone(),
                        mechanism: Mechanism::Dane,
                        key_id: leaf_key_id(leaf),
                        dnssec: Some(DnssecStatus::Secure),
                    });
                }
                Err(why) => refusal = why,
            }
        }
        Outcome::Refused(refusal)
    }
}

/// A DANE-TA(2) check of `chain` for `from` against `record`: `None` if no
/// certificate above the leaf matches it, else whether the path from the
/// leaf up to the matching certificate holds (see the module
/// documentation).
fn dane_ta(
    record: &TlsaRecord,
    chain: &[Vec<u8>],
    from: &Domain,
    now: i64,
) -> Option<Result<(), Refusal>> {
    let anchor_at = (1..chain.len()).find(|&i| matches(record, &chain[i]) == Some(true))?;
    Some(validate_to(chain, anchor_at, from, now))
}

fn validate_to(
    chain: &[Vec<u8>],
    anchor_at: usize,
    from: &Domain,
    now: i64,
) -> Result<(), Refusal> {
    let not_x509 = || Refusal::Certificate("not X.509");
    let path = chain[..anchor_at]
        .iter()
        .map(|der| Certificate::from_der(der))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| not_x509())?;
    let anchor = Certificate::from_der(&chain[anchor_at]).map_err(|_| not_x509())?;
    let mut policy = ValidationPolicy::new(u64::try_from(now).unwrap_or(0));
    policy.min_rsa_key_bits = Some(MIN_RSA_BITS);
    policy.max_path_len = u8::try_from(MAX_CHAIN_LEN).unwrap_or(u8::MAX);
    validate_path(
        &path,
        &[TrustAnchor::from_cert(anchor)],
        &policy,
        &DefaultVerifier,
    )
    .map_err(|error| Refusal::CertificatePath(error.to_string()))?;
    let leaf = &path[0];
    match client_auth(leaf) {
        Ok(true) => {}
        Ok(false) => return Err(Refusal::Certificate("no clientAuth")),
        Err(()) => return Err(Refusal::Certificate("malformed extKeyUsage")),
    }
    let name = ServerName::dns_name(from.as_str())
        .map_err(|_| Refusal::Certificate("domain is not a DNS-ID"))?;
    verify_dns_name(leaf, &name).map_err(|_| Refusal::Certificate("no dNSName for the domain"))
}

impl ProviderAuthenticator for DaneCertificates {
    fn authenticate<'a>(&'a self, request: &'a InboundRequest<'a>) -> BoxFuture<'a, Outcome> {
        Box::pin(async move {
            match request.certificate {
                None => Outcome::NotApplicable,
                Some(certificate) => {
                    self.check(&certificate.chain, request.from, request.now)
                        .await
                }
            }
        })
    }
}

#[cfg(test)]
#[path = "dane_tests.rs"]
mod tests;
