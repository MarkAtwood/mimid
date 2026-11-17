//! Mechanism 1 of mimid-75nk (bead mimid-75nk.3): Ed25519 keys published
//! in the source provider's DNS, draft-atwood-mimi-provider-auth-00 §5.
//!
//! A key is a TXT record at `<selector>._mimi.<provider-domain>` whose data
//! (the character-strings concatenated) is `v=MIMI1; k=ed25519; p=<base64>`
//! ([`parse_key_record`]). The selector is the signature's `keyid`. The
//! first record of an answer that is a MIMI key record is used (§5.3 step
//! 5); an empty `p` means the key is revoked.
//!
//! Lookups go through a [`TxtResolver`] (and TLSA lookups for DANE,
//! [`super::dane`], through the same resolver). [`HickoryTxtResolver`] is a
//! validating stub resolver, over the system's resolvers or the ones
//! configured in `dns_servers` (decision by Mark, 2026-11-15): a "bogus"
//! answer fails, and the DNSSEC status of the record used is reported with
//! the key. The upstream resolvers must pass DNSSEC records through; AWS's
//! VPC resolver does not, and through it every validating lookup fails.
//! [`check_validation`] tells the operator at startup. Whether an insecure answer is accepted is local policy
//! (`require_dnssec`). The resolver caches answers for their TTL, and
//! negative answers for the negative-caching TTL (§5.3).

use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use std::net::IpAddr;

use hickory_resolver::TokioResolver;
use hickory_resolver::config::{NameServerConfig, ResolverConfig};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::net::{DnsError, NetError};
use hickory_resolver::proto::dnssec::Proof;
use hickory_resolver::proto::rr::{RData, RecordType};

use super::{BoxFuture, KeyLookup, KeySource, Mechanism, Refusal};
use crate::config::Domain;
use crate::httpsig::VerifyingKey;

/// The DNSSEC status of the record a key came from (RFC 4035 §4.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DnssecStatus {
    /// Validated from a trust anchor.
    Secure,
    /// Provably unsigned.
    Insecure,
    /// Neither: validation could not decide, or was not done.
    Indeterminate,
}

impl DnssecStatus {
    /// The name used in logs.
    pub fn name(self) -> &'static str {
        match self {
            Self::Secure => "secure",
            Self::Insecure => "insecure",
            Self::Indeterminate => "indeterminate",
        }
    }
}

/// A TXT answer: each record's character-strings concatenated, in answer
/// order, with the DNSSEC status of each.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxtAnswer {
    /// The records.
    pub records: Vec<(Vec<u8>, DnssecStatus)>,
}

/// Why a TXT lookup gave no answer.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum TxtLookupError {
    /// The name does not exist, or has no TXT records.
    #[error("no TXT records")]
    NoRecords,
    /// DNSSEC validation failed.
    #[error("DNSSEC validation failed")]
    Bogus,
    /// The lookup failed: no answer, a server failure, a timeout.
    #[error("DNS lookup failed: {0}")]
    Failed(String),
}

/// Looks up TXT records.
pub trait TxtResolver: Send + Sync {
    /// The TXT records at `name`, an absolute domain name.
    fn txt<'a>(&'a self, name: &'a str) -> BoxFuture<'a, Result<TxtAnswer, TxtLookupError>>;
}

/// A [`TxtResolver`] over hickory's validating stub resolver.
pub struct HickoryTxtResolver(TokioResolver);

impl std::fmt::Debug for HickoryTxtResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HickoryTxtResolver").finish_non_exhaustive()
    }
}

impl HickoryTxtResolver {
    /// A validating resolver that asks `servers`, or the system's
    /// resolvers (`/etc/resolv.conf`) when `servers` is empty.
    ///
    /// # Errors
    ///
    /// The resolver's error if the system configuration cannot be read.
    pub fn new(servers: &[IpAddr]) -> Result<Self, NetError> {
        let mut builder = if servers.is_empty() {
            TokioResolver::builder_tokio()?
        } else {
            TokioResolver::builder_with_config(
                ResolverConfig::from_parts(
                    None,
                    Vec::new(),
                    servers
                        .iter()
                        .map(|ip| NameServerConfig::udp_and_tcp(*ip))
                        .collect(),
                ),
                TokioRuntimeProvider::default(),
            )
        };
        builder.options_mut().validate = true;
        Ok(Self(builder.build()?))
    }
}

impl TxtResolver for HickoryTxtResolver {
    fn txt<'a>(&'a self, name: &'a str) -> BoxFuture<'a, Result<TxtAnswer, TxtLookupError>> {
        Box::pin(async move {
            let lookup = match self.0.lookup(name, RecordType::TXT).await {
                Ok(lookup) => lookup,
                Err(NetError::Dns(DnsError::NoRecordsFound(_))) => {
                    return Err(TxtLookupError::NoRecords);
                }
                Err(NetError::Dns(DnsError::DnssecBogus)) => return Err(TxtLookupError::Bogus),
                Err(error) => return Err(TxtLookupError::Failed(error.to_string())),
            };
            let mut records = Vec::new();
            for record in lookup.answers() {
                let RData::TXT(txt) = &record.data else {
                    continue;
                };
                let status = match record.proof {
                    Proof::Secure => DnssecStatus::Secure,
                    Proof::Insecure => DnssecStatus::Insecure,
                    Proof::Bogus => return Err(TxtLookupError::Bogus),
                    _ => DnssecStatus::Indeterminate,
                };
                records.push((
                    txt.txt_data
                        .iter()
                        .flat_map(|s| s.iter().copied())
                        .collect(),
                    status,
                ));
            }
            if records.is_empty() {
                return Err(TxtLookupError::NoRecords);
            }
            Ok(TxtAnswer { records })
        })
    }
}

impl super::dane::TlsaResolver for HickoryTxtResolver {
    fn tlsa<'a>(
        &'a self,
        name: &'a str,
    ) -> BoxFuture<'a, Result<Vec<(super::dane::TlsaRecord, DnssecStatus)>, TxtLookupError>> {
        Box::pin(async move {
            let lookup = match self.0.lookup(name, RecordType::TLSA).await {
                Ok(lookup) => lookup,
                Err(NetError::Dns(DnsError::NoRecordsFound(_))) => {
                    return Err(TxtLookupError::NoRecords);
                }
                Err(NetError::Dns(DnsError::DnssecBogus)) => return Err(TxtLookupError::Bogus),
                Err(error) => return Err(TxtLookupError::Failed(error.to_string())),
            };
            let mut records = Vec::new();
            for record in lookup.answers() {
                let RData::TLSA(tlsa) = &record.data else {
                    continue;
                };
                let status = match record.proof {
                    Proof::Secure => DnssecStatus::Secure,
                    Proof::Insecure => DnssecStatus::Insecure,
                    Proof::Bogus => return Err(TxtLookupError::Bogus),
                    _ => DnssecStatus::Indeterminate,
                };
                records.push((
                    super::dane::TlsaRecord {
                        usage: tlsa.cert_usage.into(),
                        selector: tlsa.selector.into(),
                        matching: tlsa.matching.into(),
                        data: tlsa.cert_data.clone(),
                    },
                    status,
                ));
            }
            if records.is_empty() {
                return Err(TxtLookupError::NoRecords);
            }
            Ok(records)
        })
    }
}

/// A name whose TXT records are DNSSEC-signed, for [`check_validation`].
/// INVENTED, NOT FROM SPEC: any signed name with a TXT record works.
pub const VALIDATION_CHECK_NAME: &str = "ietf.org.";

/// Looks up [`VALIDATION_CHECK_NAME`] and logs whether DNSSEC validation
/// works through `resolver`: INFO when the answer is secure, WARN when it
/// is not or the lookup fails, since then every DNS key record will be
/// refused or reported as not secure.
pub async fn check_validation(resolver: &dyn TxtResolver) {
    match resolver.txt(VALIDATION_CHECK_NAME).await {
        Ok(answer)
            if answer
                .records
                .iter()
                .all(|(_, s)| *s == DnssecStatus::Secure) =>
        {
            tracing::info!(
                name: "provider_auth_dnssec_ok",
                check_name = VALIDATION_CHECK_NAME,
                "DNSSEC validation works for DNS key records"
            );
        }
        Ok(_) => tracing::warn!(
            name: "provider_auth_dnssec_unproven",
            check_name = VALIDATION_CHECK_NAME,
            "a signed name did not validate as secure; set dns_servers to resolvers that pass DNSSEC"
        ),
        Err(error) => tracing::warn!(
            name: "provider_auth_dnssec_unavailable",
            check_name = VALIDATION_CHECK_NAME,
            error = &error as &dyn std::error::Error,
            "DNSSEC validation fails through these resolvers, so DNS key records will be refused; set dns_servers to resolvers that pass DNSSEC"
        ),
    }
}

/// What a TXT record says as a MIMI key record (§5.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyRecord {
    /// It does not begin with `v=MIMI1`: not a MIMI key record.
    NotMimi,
    /// An Ed25519 key.
    Key(VerifyingKey),
    /// `p` is empty: the key is revoked.
    Revoked,
    /// A MIMI key record mimid cannot use, and why.
    Unusable(&'static str),
}

/// Whitespace in a key record (§5.1 `WSP`).
fn wsp(byte: u8) -> bool {
    byte == b' ' || byte == b'\t'
}

/// Parses a key record's data (§5.1): `v=MIMI1` first, then `;`-separated
/// tags; `k` must be `ed25519` and `p` 32 bytes of padded base64, or empty
/// for a revoked key. Unknown tags are ignored.
pub fn parse_key_record(data: &[u8]) -> KeyRecord {
    let Some(rest) = data.strip_prefix(b"v=MIMI1") else {
        return KeyRecord::NotMimi;
    };
    // `v=MIMI1x` is a different version, not this one.
    if rest.first().is_some_and(|b| !wsp(*b) && *b != b';') {
        return KeyRecord::NotMimi;
    }
    let mut k = None;
    let mut p = None;
    for tag in rest.split(|b| *b == b';') {
        let tag = trim(tag);
        if tag.is_empty() {
            continue;
        }
        let Some(eq) = tag.iter().position(|b| *b == b'=') else {
            return KeyRecord::Unusable("a tag without =");
        };
        let name = trim(&tag[..eq]);
        let value = trim(&tag[eq + 1..]);
        let name_ok = name.first().is_some_and(u8::is_ascii_alphabetic)
            && name.iter().all(|b| b.is_ascii_alphanumeric() || *b == b'_');
        let value_ok = value
            .iter()
            .all(|b| (0x21..=0x7e).contains(b) && *b != b';');
        if !name_ok || !value_ok {
            return KeyRecord::Unusable("a malformed tag");
        }
        match name {
            b"k" => k = Some(value),
            b"p" => p = Some(value),
            _ => {}
        }
    }
    match k {
        Some(b"ed25519") => {}
        Some(_) => return KeyRecord::Unusable("key type is not ed25519"),
        None => return KeyRecord::Unusable("no k tag"),
    }
    match p {
        None => KeyRecord::Unusable("no p tag"),
        Some([]) => KeyRecord::Revoked,
        Some(p) => STANDARD
            .decode(p)
            .ok()
            .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
            .and_then(|bytes| VerifyingKey::from_bytes(&bytes))
            .map_or(
                KeyRecord::Unusable("p is not an Ed25519 key"),
                KeyRecord::Key,
            ),
    }
}

fn trim(bytes: &[u8]) -> &[u8] {
    let start = bytes.iter().position(|b| !wsp(*b)).unwrap_or(bytes.len());
    let end = bytes
        .iter()
        .rposition(|b| !wsp(*b))
        .map_or(start, |i| i + 1);
    &bytes[start..end]
}

/// Whether `keyid` is a selector (§5.1): one DNS label of letters, digits
/// and hyphens (RFC 1035 §2.3.1, with leading digits allowed), 1 to 63
/// octets, not beginning with `_`.
pub fn valid_selector(keyid: &str) -> bool {
    (1..=63).contains(&keyid.len())
        && keyid
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        && !keyid.starts_with('-')
        && !keyid.ends_with('-')
}

/// Mechanism 1: keys from `<keyid>._mimi.<domain>` TXT records.
pub struct DnsKeys {
    resolver: Arc<dyn TxtResolver>,
    require_dnssec: bool,
}

impl std::fmt::Debug for DnsKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DnsKeys")
            .field("require_dnssec", &self.require_dnssec)
            .finish_non_exhaustive()
    }
}

impl DnsKeys {
    /// Keys looked up with `resolver`; with `require_dnssec`, only from a
    /// secure answer.
    pub fn new(resolver: Arc<dyn TxtResolver>, require_dnssec: bool) -> Self {
        Self {
            resolver,
            require_dnssec,
        }
    }
}

impl KeySource for DnsKeys {
    fn mechanism(&self) -> Mechanism {
        Mechanism::DnsKey
    }

    fn key<'a>(&'a self, domain: &'a Domain, keyid: &'a str) -> BoxFuture<'a, KeyLookup> {
        Box::pin(async move {
            if !valid_selector(keyid) {
                return KeyLookup::Missing(Refusal::BadSelector);
            }
            let name = format!("{keyid}._mimi.{domain}.");
            let answer = match self.resolver.txt(&name).await {
                Ok(answer) => answer,
                Err(TxtLookupError::NoRecords) => return KeyLookup::Missing(Refusal::NoKeyRecord),
                Err(TxtLookupError::Bogus) => return KeyLookup::Missing(Refusal::DnssecBogus),
                Err(TxtLookupError::Failed(reason)) => {
                    tracing::debug!(name, reason, "key record lookup failed");
                    return KeyLookup::Missing(Refusal::DnsFailure);
                }
            };
            // §5.3 step 5: the first MIMI key record.
            let Some((record, status)) = answer
                .records
                .iter()
                .map(|(data, status)| (parse_key_record(data), *status))
                .find(|(record, _)| *record != KeyRecord::NotMimi)
            else {
                return KeyLookup::Missing(Refusal::NoKeyRecord);
            };
            if self.require_dnssec && status != DnssecStatus::Secure {
                return KeyLookup::Missing(Refusal::NotSecure);
            }
            match record {
                KeyRecord::Key(key) => KeyLookup::Found {
                    key,
                    dnssec: Some(status),
                },
                KeyRecord::Revoked => KeyLookup::Missing(Refusal::KeyRevoked),
                KeyRecord::Unusable(why) => KeyLookup::Missing(Refusal::BadKeyRecord(why)),
                KeyRecord::NotMimi => KeyLookup::Missing(Refusal::NoKeyRecord),
            }
        })
    }
}

#[cfg(test)]
mod live {
    use super::*;

    /// Needs network access: `cargo test -p mimid-server --lib
    /// provider_auth::dns::live -- --ignored`. Through a resolver that
    /// passes DNSSEC, a real signed TXT record validates as secure and a
    /// missing name is `NoRecords`.
    #[tokio::test]
    #[ignore = "needs DNS"]
    async fn a_dnssec_resolver_validates_txt_records() {
        let resolver = HickoryTxtResolver::new(&["1.1.1.1".parse().unwrap()]).unwrap();
        let answer = resolver.txt("_dmarc.ietf.org.").await.unwrap();
        assert!(
            answer
                .records
                .iter()
                .any(|(data, _)| data.starts_with(b"v=DMARC1"))
        );
        assert!(
            answer
                .records
                .iter()
                .all(|(_, s)| *s == DnssecStatus::Secure)
        );
        assert_eq!(
            resolver
                .txt("mimid1._mimi.nonexistent.reviewcommit.com.")
                .await,
            Err(TxtLookupError::NoRecords)
        );
    }
}

#[cfg(test)]
mod live_host {
    use super::*;

    /// Needs network access, run with `--ignored`: the mimid hackathon
    /// host's published key (bead mimid-75nk.3) is found, DNSSEC-secure,
    /// through mimid's own resolver and parser.
    #[tokio::test]
    #[ignore = "needs DNS"]
    async fn the_mimid_hosts_key_record_is_secure() {
        let resolver = HickoryTxtResolver::new(&["1.1.1.1".parse().unwrap()]).unwrap();
        let keys = DnsKeys::new(Arc::new(resolver), true);
        let domain = Domain::try_from("mimid.reviewcommit.com".to_owned()).unwrap();
        let found = keys.key(&domain, "mimid1").await;
        let KeyLookup::Found { key, dnssec } = found else {
            panic!("{found:?}");
        };
        assert_eq!(dnssec, Some(DnssecStatus::Secure));
        assert_eq!(
            STANDARD.encode(key.to_bytes()),
            "81rGxBkc1CHNwC9YBCnbDWqSbA1/7zdA6L56QLk27kQ="
        );
    }
}
