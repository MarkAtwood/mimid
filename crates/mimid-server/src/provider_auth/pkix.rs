//! Mechanism 3 of mimid-75nk (bead mimid-75nk.5): a PKIX client
//! certificate from configured trust anchors
//! (draft-atwood-mimi-provider-auth-00 §6).
//!
//! The certificate is the one the request's connection presented
//! ([`ClientCertificate`](crate::tls::ClientCertificate), from mimid's own TLS listener or a trusted
//! proxy; [`crate::tls`]). It authenticates the `From` domain when:
//!
//! - its path validates per RFC 5280 against the anchors configured for
//!   that domain (`[provider_auth.peers."<domain>"] pkix_anchors`) or for
//!   every domain (`[provider_auth] pkix_anchors`), at the current time,
//!   with RSA keys of at least [`MIN_RSA_BITS`] bits;
//! - an extended key usage extension, if the leaf has one, includes
//!   id-kp-clientAuth (§6); and
//! - a subjectAltName dNSName of the leaf matches the `From` domain as a
//!   DNS-ID (RFC 9525, through pkix-identity); the subject common name is
//!   never used.
//!
//! The check runs on every request, against that request's `From`, so a
//! connection authenticated for one domain cannot send as another.
//!
//! An anchor configured for one peer is used only for that peer, so a CA
//! a peer runs for itself cannot vouch for anyone else.
//!
//! # Limitations
//!
//! - No revocation checking (CRL or OCSP).
//! - No certificate-policy constraints are applied (RFC 5280
//!   `initial-policy-set` is any policy).
//! - A wildcard dNSName matches one leftmost label, as RFC 9525 §6.3
//!   allows, but not over a single-label suffix (`*.example`;
//!   pkix-identity). The draft does not say whether MIMI allows wildcards.
//! - Through a proxy only the leaf arrives, so an intermediate CA must be
//!   configured as an anchor itself.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use der::Decode;
use der::asn1::ObjectIdentifier;
use pkix_identity::{ServerName, verify_dns_name};
use pkix_path::{DefaultVerifier, TrustAnchor, ValidationPolicy, validate_path};
use rustls::pki_types::CertificateDer;
use rustls::pki_types::pem::PemObject;
use sha2::{Digest, Sha256};
use x509_cert::Certificate;
use x509_cert::ext::pkix::ExtendedKeyUsage;

use super::{
    AuthenticatedProvider, BoxFuture, InboundRequest, Mechanism, Outcome, ProviderAuthConfig,
    ProviderAuthenticator, Refusal,
};
use crate::config::Domain;

/// The smallest RSA modulus accepted anywhere in a path. INVENTED, NOT
/// FROM SPEC: the draft leaves algorithms to local policy.
pub const MIN_RSA_BITS: u32 = 2048;

/// The most certificates a presented chain may hold, leaf included.
/// INVENTED, NOT FROM SPEC.
pub const MAX_CHAIN_LEN: usize = 5;

/// RFC 5280 §4.2.1.12 id-kp-clientAuth.
const CLIENT_AUTH: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.2");

/// RFC 5280 §4.2.1.12 id-ce-extKeyUsage.
const EXT_KEY_USAGE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.37");

/// A configured anchor file that cannot be used.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PkixConfigError {
    /// The file cannot be read or holds no PEM certificate.
    #[error("cannot read a PEM certificate from {}", path.display())]
    Pem {
        /// The file.
        path: PathBuf,
    },
    /// A certificate in the file is not DER X.509.
    #[error("{} holds a certificate that is not X.509", path.display())]
    Certificate {
        /// The file.
        path: PathBuf,
        /// What the DER decoder said.
        #[source]
        source: der::Error,
    },
}

/// One configured anchor: its DER, to recognize it in a presented chain,
/// and its parsed form.
struct Anchor {
    der: Vec<u8>,
    anchor: TrustAnchor,
}

/// Mechanism 3: client certificates checked against configured anchors.
pub struct PkixCertificates {
    global: Vec<Anchor>,
    peers: BTreeMap<Domain, Vec<Anchor>>,
}

impl std::fmt::Debug for PkixCertificates {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PkixCertificates")
            .field("global", &self.global.len())
            .field("peers", &self.peers.keys().collect::<Vec<_>>())
            .finish()
    }
}

fn load(path: &Path) -> Result<Vec<Anchor>, PkixConfigError> {
    let ders: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(path)
        .and_then(Iterator::collect)
        .map_err(|_| PkixConfigError::Pem {
            path: path.to_owned(),
        })?;
    if ders.is_empty() {
        return Err(PkixConfigError::Pem {
            path: path.to_owned(),
        });
    }
    ders.into_iter()
        .map(|der| {
            let cert =
                Certificate::from_der(&der).map_err(|source| PkixConfigError::Certificate {
                    path: path.to_owned(),
                    source,
                })?;
            Ok(Anchor {
                der: der.to_vec(),
                anchor: TrustAnchor::from_cert(cert),
            })
        })
        .collect()
}

fn load_all(paths: &[PathBuf]) -> Result<Vec<Anchor>, PkixConfigError> {
    let mut anchors = Vec::new();
    for path in paths {
        anchors.extend(load(path)?);
    }
    Ok(anchors)
}

impl PkixCertificates {
    /// The anchors `config` names, or `None` if it names none.
    ///
    /// # Errors
    ///
    /// A file that cannot be read or holds no X.509 certificate.
    pub fn new(config: &ProviderAuthConfig) -> Result<Option<Self>, PkixConfigError> {
        let global = load_all(&config.pkix_anchors)?;
        let mut peers = BTreeMap::new();
        for (domain, peer) in &config.peers {
            if !peer.pkix_anchors.is_empty() {
                peers.insert(domain.clone(), load_all(&peer.pkix_anchors)?);
            }
        }
        Ok((!global.is_empty() || !peers.is_empty()).then_some(Self { global, peers }))
    }

    /// How many anchors are configured, for every domain and per peer.
    pub fn counts(&self) -> (usize, usize) {
        (self.global.len(), self.peers.values().map(Vec::len).sum())
    }

    /// The §6 check of `chain` (leaf first, DER) for `from` at `now`.
    fn check(&self, chain: &[Vec<u8>], from: &Domain, now: i64) -> Outcome {
        let anchors: Vec<&Anchor> = self
            .global
            .iter()
            .chain(self.peers.get(from).into_iter().flatten())
            .collect();
        if anchors.is_empty() {
            return Outcome::NotApplicable;
        }
        if chain.is_empty() || chain.len() > MAX_CHAIN_LEN {
            return Outcome::Refused(Refusal::Certificate("chain length"));
        }
        // A client may send the anchor itself at the end of its chain.
        let mut presented = chain;
        while let [rest @ .., last] = presented
            && !rest.is_empty()
            && anchors.iter().any(|a| a.der == *last)
        {
            presented = rest;
        }
        let Ok(certs) = presented
            .iter()
            .map(|der| Certificate::from_der(der))
            .collect::<Result<Vec<_>, _>>()
        else {
            return Outcome::Refused(Refusal::Certificate("not X.509"));
        };
        let mut policy = ValidationPolicy::new(u64::try_from(now).unwrap_or(0));
        policy.min_rsa_key_bits = Some(MIN_RSA_BITS);
        policy.max_path_len = u8::try_from(MAX_CHAIN_LEN).unwrap_or(u8::MAX);
        let trust: Vec<TrustAnchor> = anchors.iter().map(|a| a.anchor.clone()).collect();
        if let Err(error) = validate_path(&certs, &trust, &policy, &DefaultVerifier) {
            return Outcome::Refused(Refusal::CertificatePath(error.to_string()));
        }
        let leaf = &certs[0];
        match client_auth(leaf) {
            Ok(true) => {}
            Ok(false) => return Outcome::Refused(Refusal::Certificate("no clientAuth")),
            Err(()) => return Outcome::Refused(Refusal::Certificate("malformed extKeyUsage")),
        }
        let name = match ServerName::dns_name(from.as_str()) {
            Ok(name) => name,
            Err(_) => return Outcome::Refused(Refusal::Certificate("domain is not a DNS-ID")),
        };
        if verify_dns_name(leaf, &name).is_err() {
            return Outcome::Refused(Refusal::Certificate("no dNSName for the domain"));
        }
        let mut key_id = String::from("sha256:");
        for b in Sha256::digest(&chain[0]) {
            let _ = write!(key_id, "{b:02x}");
        }
        Outcome::Authenticated(AuthenticatedProvider {
            domain: from.clone(),
            mechanism: Mechanism::Pkix,
            key_id,
            dnssec: None,
        })
    }
}

/// Whether the leaf may authenticate a client: it has no extended key
/// usage extension, or one that lists id-kp-clientAuth (§6). `Err` if the
/// extension does not decode.
fn client_auth(leaf: &Certificate) -> Result<bool, ()> {
    let Some(ext) = leaf
        .tbs_certificate
        .extensions
        .iter()
        .flatten()
        .find(|e| e.extn_id == EXT_KEY_USAGE)
    else {
        return Ok(true);
    };
    let usage = ExtendedKeyUsage::from_der(ext.extn_value.as_bytes()).map_err(drop)?;
    Ok(usage.0.contains(&CLIENT_AUTH))
}

impl ProviderAuthenticator for PkixCertificates {
    fn authenticate<'a>(&'a self, request: &'a InboundRequest<'a>) -> BoxFuture<'a, Outcome> {
        let outcome = match request.certificate {
            None => Outcome::NotApplicable,
            Some(certificate) => self.check(&certificate.chain, request.from, request.now),
        };
        Box::pin(std::future::ready(outcome))
    }
}

#[cfg(test)]
#[path = "pkix_tests.rs"]
mod tests;
