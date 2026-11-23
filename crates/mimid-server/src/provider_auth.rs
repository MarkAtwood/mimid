//! Provider authentication (epic mimid-75nk; bead mimid-75nk.1): how mimid
//! decides that a protocol request really comes from the provider its
//! `From` header names, and how it proves its own identity to peers.
//!
//! Inbound, [`check`] runs on every `/v1/` request. It takes the source
//! domain from `From` (protocol-07 §4.1), reads the body, and asks each
//! [`ProviderAuthenticator`] in turn. The first that authenticates the
//! source wins; the [`AuthenticatedProvider`] goes into the request's
//! extensions. If none does, the source's [`AuthMode`] decides: `enforce`
//! (the default; decision of mimid-75nk) answers `403` with an
//! `Accept-Signature` field naming the signature it requires ([`refuse`]), `observe` logs the
//! failure and lets the request through, for rollout with peers that do not
//! authenticate yet.
//!
//! Mechanisms (decision of mimid-75nk), numbered and tried in this order
//! (docs/operating.md lists them the same way):
//!
//! 1. [`Mechanism::TrustList`] (bead mimid-75nk.1): RFC 9421 request
//!    signatures ([`crate::httpsig`]) with Ed25519 keys configured per
//!    peer, by selector, in `[provider_auth.peers."<domain>"] keys`.
//! 2. [`Mechanism::DnsKey`] (bead mimid-75nk.3): the same signatures with
//!    keys published at `<selector>._mimi.<domain>`
//!    (draft-atwood-mimi-provider-auth-00 §5; [`dns`]), looked up with a
//!    DNSSEC-validating resolver. On unless `dns_keys = false`.
//! 3. [`Mechanism::Dane`] (bead mimid-75nk.6): the client certificate of
//!    the request's connection ([`crate::tls::ClientCertificate`]),
//!    checked against DNSSEC-secure TLSA records at
//!    `_mimi._client.<domain>` (draft-atwood-mimi-provider-auth-00 §6;
//!    [`dane`]). On unless `dane = false`; tried before PKIX, so that a
//!    provider with TLSA records is checked against them first.
//! 4. [`Mechanism::Pkix`] (bead mimid-75nk.5): the client certificate,
//!    validated per RFC 5280 against configured anchors and matched to the
//!    `From` domain as a DNS-ID (draft-atwood-mimi-provider-auth-00 §7;
//!    [`pkix`]). On when `pkix_anchors` names any.
//!
//! A signature counts only if it follows draft-atwood-mimi-provider-auth-00
//! §5.2 and §5.3: it covers `@method`, `@target-uri` and `from`
//! ([`REQUIRED_COMPONENTS`]), and `content-digest` when the request has a
//! body, with `created` and `keyid`; and `Content-Digest`, when the body
//! is not empty, matches it (RFC 9530). Signatures tagged `mimi` are tried
//! first. Since the key is chosen by the `From` domain and `from` is
//! covered, the authenticated domain is the `From` domain.
//!
//! Outbound, [`RequestSigner`] signs each request the
//! [`crate::peer::PeerClient`] sends with this server's own key, under the
//! label [`SIGNATURE_LABEL`], tagged `mimi`, with the configured selector
//! as `keyid`, covering `@method`, `@target-uri`, `content-digest` and
//! `from` (draft-atwood-mimi-provider-auth-00 §5.2), with a random
//! `nonce` (-01 §13.2).
//!
//! # Logging
//!
//! A refusal in `enforce` mode is a correct refusal: one DEBUG event with
//! the reason. In `observe` mode each failure is a DEBUG event, and the
//! first failure of each provider since start an INFO event, so an
//! operator sees which peers do not authenticate without one event per
//! request. A success is a DEBUG event. Each of these events names the
//! peer, the protocol endpoint (`endpoint`, the path segment after `/v1/`)
//! and the mechanism or the reason.
//!
//! # Limitations
//!
//! - A signature without a `nonce` can be replayed within
//!   [`MAX_SIGNATURE_AGE_SECS`]: -01 §13.2 asks signers for one, and a
//!   nonce-less signature is still accepted. One with a nonce is refused
//!   the second time ([`nonce`]). The nonces live in memory, so a restart
//!   forgets them.
//! - `@target-uri` is rebuilt from this server's configured `base_url`
//!   and the request path, so a peer must sign the URL from this server's
//!   directory.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError};

use axum::body::{Body, to_bytes};
use axum::extract::{Request, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri, header};
use axum::middleware::Next;
use axum::response::Response;
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use serde::Deserialize;

use crate::config::{BaseUrl, Domain};
use crate::httpsig::{self, SignatureParams, SigningKey, TimePolicy, VerifyingKey};
use crate::hub::Clock;
use crate::tls::ClientCertificate;
use nonce::{NonceCache, NonceRefusal};

/// The label of mimid's own request signatures. INVENTED, NOT FROM SPEC:
/// no MIMI document names one yet. Received signatures may use any label.
pub const SIGNATURE_LABEL: &str = "mimi";

/// The components a signature must cover to authenticate a provider
/// (draft-atwood-mimi-provider-auth-00 §5.2); `content-digest` too when
/// the request has a body.
pub const REQUIRED_COMPONENTS: [&str; 3] = ["@method", "@target-uri", "from"];

/// The `tag` of a MIMI provider signature (draft-atwood-mimi-provider-auth-00
/// §5.2).
pub const SIGNATURE_TAG: &str = "mimi";

/// The components mimid's own signatures cover.
const SIGNED_COMPONENTS: [&str; 4] = ["@method", "@target-uri", "content-digest", "from"];

/// How far in the future a signature's `created` may be. INVENTED, NOT
/// FROM SPEC.
pub const SIGNATURE_SKEW_SECS: i64 = 60;

/// How old a signature's `created` may be. INVENTED, NOT FROM SPEC.
pub const MAX_SIGNATURE_AGE_SECS: i64 = 300;

/// The default `keyid` of mimid's own signatures.
pub const DEFAULT_SELECTOR: &str = "mimid1";

/// The most signatures on one request that are tried. INVENTED, NOT FROM
/// SPEC.
const MAX_SIGNATURES_TRIED: usize = 4;

/// protocol-07 §4.1: the local-part of the `From` address.
const FROM_PREFIX: &str = "mimi@";

/// What happens to a request whose source does not authenticate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthMode {
    /// Refuse it with `403` ([`refuse`]).
    #[default]
    Enforce,
    /// Log the failure and accept it.
    Observe,
}

/// An Ed25519 public key from the configuration: 32 bytes, standard
/// base64 (as in a DKIM `p=` tag).
#[derive(Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(try_from = "String")]
pub struct TrustedKey(VerifyingKey);

impl TrustedKey {
    /// The key.
    pub fn key(&self) -> VerifyingKey {
        self.0
    }
}

impl fmt::Debug for TrustedKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// A configured key that is not 32 bytes of standard base64 naming a
/// valid Ed25519 point.
#[derive(Debug, thiserror::Error)]
#[error("not a base64 Ed25519 public key: {0:?}")]
pub struct InvalidTrustedKey(String);

impl TryFrom<String> for TrustedKey {
    type Error = InvalidTrustedKey;

    fn try_from(text: String) -> Result<Self, Self::Error> {
        STANDARD
            .decode(text.trim())
            .ok()
            .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
            .and_then(|bytes| VerifyingKey::from_bytes(&bytes))
            .map(Self)
            .ok_or(InvalidTrustedKey(text))
    }
}

/// `[provider_auth]` in the configuration file.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderAuthConfig {
    /// The mode for a provider with no `mode` of its own.
    #[serde(default)]
    pub mode: AuthMode,
    /// The `keyid` of this server's request signatures, and the selector
    /// of its DNS key record (`<selector>._mimi.<domain>`).
    #[serde(default = "default_selector")]
    pub selector: String,
    /// Whether to look up keys in DNS (mechanism 2, mimid-75nk.3). On by
    /// default: an open provider accepts DNS keys from anyone
    /// (draft-atwood-mimi-provider-auth-00 §10).
    #[serde(default = "default_true")]
    pub dns_keys: bool,
    /// Refuse a DNS key whose record is not DNSSEC-secure. Off by default:
    /// the draft makes this local policy (§5.3).
    #[serde(default)]
    pub require_dnssec: bool,
    /// The resolvers DNS key records are looked up through, validating
    /// DNSSEC; the system's when empty. They must pass DNSSEC records
    /// through (AWS's VPC resolver does not).
    #[serde(default)]
    pub dns_servers: Vec<std::net::IpAddr>,
    /// Whether to check client certificates against TLSA records
    /// (mechanism 3, mimid-75nk.6). On by default, like `dns_keys`; it
    /// needs the same validating resolvers.
    #[serde(default = "default_true")]
    pub dane: bool,
    /// PEM files of trust anchors for PKIX client certificates from any
    /// provider (mechanism 4, mimid-75nk.5): a federation's CA, say. Not a
    /// Web PKI root store (draft-atwood-mimi-provider-auth-00 §7).
    #[serde(default)]
    pub pkix_anchors: Vec<std::path::PathBuf>,
    /// Per-provider settings.
    #[serde(default)]
    pub peers: BTreeMap<Domain, PeerAuthConfig>,
}

fn default_true() -> bool {
    true
}

impl Default for ProviderAuthConfig {
    fn default() -> Self {
        Self {
            mode: AuthMode::default(),
            selector: default_selector(),
            dns_keys: true,
            dane: true,
            require_dnssec: false,
            dns_servers: Vec::new(),
            pkix_anchors: Vec::new(),
            peers: BTreeMap::new(),
        }
    }
}

fn default_selector() -> String {
    DEFAULT_SELECTOR.to_owned()
}

/// `[provider_auth.peers."<domain>"]`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerAuthConfig {
    /// This provider's mode, overriding the default.
    #[serde(default)]
    pub mode: Option<AuthMode>,
    /// Trusted request-signing keys, by selector (`keyid`).
    #[serde(default)]
    pub keys: BTreeMap<String, TrustedKey>,
    /// PEM files of trust anchors for this provider's client certificates
    /// only (mechanism 3, mimid-75nk.5).
    #[serde(default)]
    pub pkix_anchors: Vec<std::path::PathBuf>,
}

/// How a provider was authenticated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Mechanism {
    /// An RFC 9421 signature with a key configured for the provider.
    TrustList,
    /// An RFC 9421 signature with a key published in the provider's DNS
    /// (draft-atwood-mimi-provider-auth-00 §5).
    DnsKey,
    /// A client certificate from a configured trust anchor (-00 §7).
    Pkix,
    /// A client certificate matching the provider's DNSSEC-signed TLSA
    /// records (-00 §6).
    Dane,
}

impl Mechanism {
    /// The name used in logs.
    pub fn name(self) -> &'static str {
        match self {
            Self::TrustList => "trust_list",
            Self::DnsKey => "dns_key",
            Self::Pkix => "pkix",
            Self::Dane => "dane",
        }
    }
}

/// A provider that proved who it is, as put in the request's extensions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedProvider {
    /// The provider's domain, equal to the `From` domain.
    pub domain: Domain,
    /// How it proved it.
    pub mechanism: Mechanism,
    /// The key it used: the `keyid`, or for a certificate
    /// `sha256:<hex>` of the leaf.
    pub key_id: String,
    /// For a key from DNS, the DNSSEC status of its record.
    pub dnssec: Option<DnssecStatus>,
}

/// Why a provider was not authenticated.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Refusal {
    /// The request carries no credential any mechanism takes.
    #[error("no credentials")]
    NoCredentials,
    /// The request is signed, but no key is configured for the provider.
    #[error("no trusted key for the provider")]
    NoTrustedKey,
    /// A signature's `keyid` names no key of the provider's.
    #[error("unknown keyid")]
    UnknownKey,
    /// A signature has no `keyid` (draft-atwood-mimi-provider-auth-00
    /// §5.2).
    #[error("signature has no keyid")]
    NoKeyId,
    /// The `keyid` is not a selector: one DNS label, not starting with
    /// `_` (§5.1).
    #[error("keyid is not a selector")]
    BadSelector,
    /// No MIMI key record at `<keyid>._mimi.<domain>` (§5.3 step 5).
    #[error("no MIMI key record")]
    NoKeyRecord,
    /// The key record's `p` is empty: the key is revoked (§5.1).
    #[error("the key is revoked")]
    KeyRevoked,
    /// The key record is not usable: no or unknown `k`, or a malformed
    /// `p`.
    #[error("unusable key record: {0}")]
    BadKeyRecord(&'static str),
    /// The key record's DNSSEC validation failed ("bogus"; §5.3).
    #[error("DNSSEC validation of the key record failed")]
    DnssecBogus,
    /// DNSSEC is required by local policy and the answer was not secure.
    #[error("the key record is not DNSSEC-secure")]
    NotSecure,
    /// The DNS lookup failed.
    #[error("DNS lookup failed")]
    DnsFailure,
    /// A signature does not cover [`REQUIRED_COMPONENTS`].
    #[error("signature does not cover {0}")]
    NotCovered(&'static str),
    /// `Content-Digest` is missing or does not match the body.
    #[error("content-digest does not match the body")]
    Digest,
    /// The signature is malformed, unsupported, expired or wrong.
    #[error("signature refused: {0}")]
    Signature(#[source] httpsig::Error),
    /// The signature verifies but its `nonce` was already used by the same
    /// key, or is too long ([`nonce`]; provider-auth -01 §13.2).
    #[error("{0}")]
    Nonce(#[source] NonceRefusal),
    /// The client certificate's path does not validate against the
    /// anchors for the provider (RFC 5280).
    #[error("certificate path refused: {0}")]
    CertificatePath(String),
    /// The client certificate is unusable for the provider: the reason.
    #[error("certificate refused: {0}")]
    Certificate(&'static str),
}

impl Refusal {
    /// A stable token for the `reason` member of the 403's problem
    /// details, or `None` to say nothing beyond the problem type.
    ///
    /// draft-atwood-mimi-provider-auth-00 §9 lets a target provider
    /// "include a problem details body saying why authentication
    /// failed", and limits that to "what the source provider needs to
    /// fix its configuration". So this reports only what is the SOURCE
    /// provider's own configuration -- its DNS key record, its
    /// signature, its certificate -- and never what is the target's,
    /// such as whether a key or anchor is configured for that peer.
    /// Withholding the latter is also what keeps this from being an
    /// oracle for probing a target's trust list.
    ///
    /// The tokens are a stable part of the wire contract: add, but do
    /// not rename. The match has no catch-all, so a new
    /// [`Refusal`] variant does not compile until it is classified.
    pub fn public_reason(&self) -> Option<&'static str> {
        match self {
            // Nothing was presented. The peer knows what it sent, so
            // this tells it only that nothing was recognised.
            Self::NoCredentials => Some("no-credentials"),

            // The peer's own DNS, which it can read and fix.
            Self::NoKeyRecord => Some("no-key-record"),
            Self::KeyRevoked => Some("key-revoked"),
            Self::BadKeyRecord(_) => Some("unusable-key-record"),
            Self::DnssecBogus => Some("key-record-dnssec-bogus"),
            Self::NotSecure => Some("key-record-not-dnssec-secure"),

            // The peer's own signature.
            Self::NoKeyId => Some("signature-no-keyid"),
            Self::BadSelector => Some("keyid-not-a-selector"),
            Self::UnknownKey => Some("unknown-keyid"),
            Self::NotCovered(_) => Some("signature-incomplete"),
            Self::Digest => Some("content-digest-mismatch"),
            Self::Signature(_) => Some("signature-invalid"),
            Self::Nonce(_) => Some("nonce-refused"),

            // The peer's own certificate. This is the case that
            // prompted the change: a certificate without a dNSName for
            // its domain is one line away from working, and the peer
            // could not previously learn that.
            Self::Certificate(_) => Some("certificate-rejected"),
            Self::CertificatePath(_) => Some("certificate-path-rejected"),

            // The TARGET's configuration: that no key is configured for
            // this peer is ours to know, not theirs. Say nothing.
            Self::NoTrustedKey => None,

            // A transient fault here, not the peer's configuration.
            Self::DnsFailure => None,
            // Deliberately no catch-all: a new Refusal variant must fail
            // to compile here until someone decides which side's
            // configuration it is about.
        }
    }
}

/// What an authenticator makes of a request.
#[derive(Debug)]
pub enum Outcome {
    /// It authenticates the source.
    Authenticated(AuthenticatedProvider),
    /// The request carries nothing this mechanism checks.
    NotApplicable,
    /// The request carries this mechanism's credential, and it fails.
    Refused(Refusal),
}

/// A request as the authenticators see it.
#[derive(Debug, Clone, Copy)]
pub struct InboundRequest<'a> {
    /// The source domain, from `From`.
    pub from: &'a Domain,
    /// The method.
    pub method: &'a Method,
    /// The absolute URI the source addressed.
    pub uri: &'a Uri,
    /// The header fields.
    pub headers: &'a HeaderMap,
    /// The body.
    pub body: &'a [u8],
    /// Now, in seconds since the UNIX epoch.
    pub now: i64,
    /// The client certificate the connection presented, if any.
    pub certificate: Option<&'a ClientCertificate>,
}

/// A boxed future, for the mechanisms that wait on the network.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// One authentication mechanism.
pub trait ProviderAuthenticator: Send + Sync {
    /// Checks `request`.
    fn authenticate<'a>(&'a self, request: &'a InboundRequest<'a>) -> BoxFuture<'a, Outcome>;
}

/// What a [`KeySource`] found for a source domain and `keyid`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyLookup {
    /// The key, and the DNSSEC status of the answer it came in, if from
    /// DNS.
    Found {
        /// The public key.
        key: VerifyingKey,
        /// The DNSSEC status, for a key from DNS.
        dnssec: Option<DnssecStatus>,
    },
    /// No usable key, and why.
    Missing(Refusal),
}

/// Where a signature mechanism finds a source's keys.
pub trait KeySource: Send + Sync {
    /// The mechanism this source stands for.
    fn mechanism(&self) -> Mechanism;
    /// The key `domain` signs with under `keyid`.
    fn key<'a>(&'a self, domain: &'a Domain, keyid: &'a str) -> BoxFuture<'a, KeyLookup>;
}

/// An RFC 9421 signature mechanism over a [`KeySource`]
/// (draft-atwood-mimi-provider-auth-00 §5.3), refusing a replayed nonce
/// ([`nonce`]).
#[derive(Debug)]
pub struct Signatures<K> {
    source: K,
    nonces: Arc<NonceCache>,
}

impl<K> Signatures<K> {
    /// The mechanism with keys from `source`, recording nonces in
    /// `nonces`, which every signature mechanism of a server shares so a
    /// nonce cannot be replayed through another key source.
    pub fn new(source: K, nonces: Arc<NonceCache>) -> Self {
        Self { source, nonces }
    }
}

impl<K: KeySource> ProviderAuthenticator for Signatures<K> {
    fn authenticate<'a>(&'a self, request: &'a InboundRequest<'a>) -> BoxFuture<'a, Outcome> {
        Box::pin(verify_signatures(&self.source, &self.nonces, request))
    }
}

/// draft-atwood-mimi-provider-auth-00 §5.3, steps 2 to 7, with keys from
/// `source`, then the nonce check of -01 §13.2.
async fn verify_signatures(
    source: &dyn KeySource,
    nonces: &NonceCache,
    request: &InboundRequest<'_>,
) -> Outcome {
    let mut signatures = match httpsig::signatures(request.headers) {
        Ok(signatures) if signatures.is_empty() => return Outcome::NotApplicable,
        Ok(signatures) => signatures,
        Err(error) => return Outcome::Refused(Refusal::Signature(error)),
    };
    // Step 6: the digest is checked when there is content.
    if !request.body.is_empty()
        && httpsig::check_content_digest(request.headers, request.body).is_err()
    {
        return Outcome::Refused(Refusal::Digest);
    }
    // Step 2: signatures tagged `mimi` first.
    signatures.sort_by_key(|(_, params)| params.tag.as_deref() != Some(SIGNATURE_TAG));
    let parts = httpsig::RequestParts {
        method: request.method,
        uri: request.uri,
        headers: request.headers,
    };
    let time = TimePolicy {
        now: request.now,
        skew: SIGNATURE_SKEW_SECS,
        max_age: MAX_SIGNATURE_AGE_SECS,
    };
    let mut refusal = Refusal::UnknownKey;
    for (label, params) in signatures.iter().take(MAX_SIGNATURES_TRIED) {
        // Step 3: coverage, created and keyid, before any lookup.
        let covers = |c: &str| params.components.iter().any(|have| have == c);
        if let Some(missing) = REQUIRED_COMPONENTS.into_iter().find(|c| !covers(c)) {
            refusal = Refusal::NotCovered(missing);
            continue;
        }
        if !request.body.is_empty() && !covers(httpsig::CONTENT_DIGEST) {
            refusal = Refusal::NotCovered(httpsig::CONTENT_DIGEST);
            continue;
        }
        let Some(keyid) = params.keyid.as_deref() else {
            refusal = Refusal::NoKeyId;
            continue;
        };
        // Step 5.
        let (key, dnssec) = match source.key(request.from, keyid).await {
            KeyLookup::Found { key, dnssec } => (key, dnssec),
            KeyLookup::Missing(why) => {
                refusal = why;
                continue;
            }
        };
        // Steps 4 and 7.
        match httpsig::verify(&parts, label, time, |_| Some(key)) {
            Ok(verified) => {
                // -01 §13.2: a nonce counts once per key in the window.
                // verify checked created, so it is present.
                if let (Some(nonce), Some(created)) = (&verified.nonce, verified.created)
                    && let Err(why) =
                        nonces.check_and_record(request.from, keyid, nonce, created, request.now)
                {
                    refusal = Refusal::Nonce(why);
                    continue;
                }
                return Outcome::Authenticated(AuthenticatedProvider {
                    domain: request.from.clone(),
                    mechanism: source.mechanism(),
                    key_id: keyid.to_owned(),
                    dnssec,
                });
            }
            Err(error) => refusal = Refusal::Signature(error),
        }
    }
    Outcome::Refused(refusal)
}

/// Mechanism 4 of mimid-75nk: keys configured per provider.
#[derive(Debug, Default)]
pub struct TrustList {
    keys: BTreeMap<Domain, BTreeMap<String, VerifyingKey>>,
}

impl TrustList {
    /// The keys of `config`.
    pub fn new(config: &ProviderAuthConfig) -> Self {
        Self {
            keys: config
                .peers
                .iter()
                .filter(|(_, peer)| !peer.keys.is_empty())
                .map(|(domain, peer)| {
                    (
                        domain.clone(),
                        peer.keys
                            .iter()
                            .map(|(selector, key)| (selector.clone(), key.key()))
                            .collect(),
                    )
                })
                .collect(),
        }
    }
}

impl KeySource for TrustList {
    fn mechanism(&self) -> Mechanism {
        Mechanism::TrustList
    }

    fn key<'a>(&'a self, domain: &'a Domain, keyid: &'a str) -> BoxFuture<'a, KeyLookup> {
        let found = match self.keys.get(domain) {
            None => KeyLookup::Missing(Refusal::NoTrustedKey),
            Some(keys) => match keys.get(keyid) {
                Some(key) => KeyLookup::Found {
                    key: *key,
                    dnssec: None,
                },
                None => KeyLookup::Missing(Refusal::UnknownKey),
            },
        };
        Box::pin(std::future::ready(found))
    }
}

/// The inbound policy: the mechanisms in order and each provider's mode.
pub struct ProviderAuth {
    authenticators: Vec<Box<dyn ProviderAuthenticator>>,
    dns_keys: bool,
    dane: bool,
    require_dnssec: bool,
    default_mode: AuthMode,
    modes: BTreeMap<Domain, AuthMode>,
    base_url: String,
    clock: Arc<dyn Clock>,
    /// Providers whose observe-mode failure has been logged at INFO.
    observed: Mutex<BTreeSet<Domain>>,
    /// Nonces seen on verified signatures, shared by the signature
    /// mechanisms.
    nonces: Arc<NonceCache>,
}

impl fmt::Debug for ProviderAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProviderAuth")
            .field("default_mode", &self.default_mode)
            .field("modes", &self.modes)
            .finish_non_exhaustive()
    }
}

impl ProviderAuth {
    /// The policy of `config` for a server reachable at `base_url`, with
    /// the mechanisms built so far.
    pub fn new(config: &ProviderAuthConfig, base_url: &BaseUrl, clock: Arc<dyn Clock>) -> Self {
        let nonces = Arc::new(NonceCache::new(
            MAX_SIGNATURE_AGE_SECS.saturating_add(SIGNATURE_SKEW_SECS),
        ));
        Self {
            authenticators: vec![Box::new(Signatures::new(
                TrustList::new(config),
                Arc::clone(&nonces),
            ))],
            nonces,
            dns_keys: config.dns_keys,
            dane: config.dane,
            require_dnssec: config.require_dnssec,
            default_mode: config.mode,
            modes: config
                .peers
                .iter()
                .filter_map(|(domain, peer)| peer.mode.map(|mode| (domain.clone(), mode)))
                .collect(),
            base_url: base_url.to_string().trim_end_matches('/').to_owned(),
            clock,
            observed: Mutex::new(BTreeSet::new()),
        }
    }

    /// Adds mechanism 2, DNS-published keys looked up with `resolver`
    /// (mimid-75nk.3), after the trust list, unless the configuration
    /// turned it off (`dns_keys = false`).
    #[must_use]
    pub fn with_dns(mut self, resolver: Arc<dyn TxtResolver>) -> Self {
        if self.dns_keys {
            self.authenticators.push(Box::new(Signatures::new(
                DnsKeys::new(resolver, self.require_dnssec),
                Arc::clone(&self.nonces),
            )));
        }
        self
    }

    /// Adds mechanism 3, DANE client certificates (mimid-75nk.6), with
    /// TLSA records from `resolver`, unless `dane = false`. Call it before
    /// [`ProviderAuth::with_pkix`], so TLSA records are checked first.
    #[must_use]
    pub fn with_dane(mut self, resolver: Arc<dyn TlsaResolver>) -> Self {
        if self.dane {
            self.authenticators
                .push(Box::new(DaneCertificates::new(resolver)));
        }
        self
    }

    /// Adds mechanism 4, PKIX client certificates (mimid-75nk.5), after
    /// the signature mechanisms.
    #[must_use]
    pub fn with_pkix(mut self, pkix: PkixCertificates) -> Self {
        self.authenticators.push(Box::new(pkix));
        self
    }

    /// `domain`'s mode.
    pub fn mode(&self, domain: &Domain) -> AuthMode {
        self.modes.get(domain).copied().unwrap_or(self.default_mode)
    }

    /// Runs the mechanisms in order on `request`.
    ///
    /// # Errors
    ///
    /// The refusal of the last mechanism that refused, or
    /// [`Refusal::NoCredentials`] if none applied.
    pub async fn authenticate(
        &self,
        request: &InboundRequest<'_>,
    ) -> Result<AuthenticatedProvider, Refusal> {
        let mut refusal = Refusal::NoCredentials;
        for authenticator in &self.authenticators {
            match authenticator.authenticate(request).await {
                Outcome::Authenticated(provider) => return Ok(provider),
                Outcome::NotApplicable => {}
                Outcome::Refused(why) => refusal = why,
            }
        }
        Err(refusal)
    }

    /// Whether this is the first observe-mode failure of `domain`.
    fn first_observed(&self, domain: &Domain) -> bool {
        self.observed
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(domain.clone())
    }
}

/// The source domain of `headers`' single `From` header, `mimi@<domain>`
/// (protocol-07 §4.1).
fn from_domain(headers: &HeaderMap) -> Option<Domain> {
    let mut values = headers.get_all(header::FROM).iter();
    let (Some(value), None) = (values.next(), values.next()) else {
        return None;
    };
    let domain = value.to_str().ok()?.strip_prefix(FROM_PREFIX)?;
    Domain::try_from(domain.to_owned()).ok()
}

/// The protocol endpoint of a `/v1/` path, for logs: the segment after
/// `/v1/` (`keyMaterial`, `notify`, ...). The rest of the path names
/// rooms and users, which these events leave out.
fn endpoint_name(path: &str) -> &str {
    let rest = path.strip_prefix("/v1/").unwrap_or(path);
    rest.split('/').next().unwrap_or(rest)
}

/// The middleware: authenticates the source of every `/v1/` request
/// (see the module documentation). A request without a well-formed `From`
/// header goes through untouched, for its handler to refuse with `400`.
pub async fn check(
    State(auth): State<Arc<ProviderAuth>>,
    request: Request,
    next: Next,
) -> Response {
    if !request.uri().path().starts_with("/v1/") {
        return next.run(request).await;
    }
    let Some(from) = from_domain(request.headers()) else {
        return next.run(request).await;
    };
    let (mut parts, body) = request.into_parts();
    let Ok(body) = to_bytes(body, crate::http::MAX_BODY_LEN).await else {
        tracing::debug!(
            reason = "request body too large",
            status = StatusCode::PAYLOAD_TOO_LARGE.as_u16(),
            "request refused"
        );
        return crate::http::problem(StatusCode::PAYLOAD_TOO_LARGE, "too-large");
    };
    let path = parts
        .uri
        .path_and_query()
        .map_or("/", |p| p.as_str())
        .to_owned();
    let endpoint = endpoint_name(parts.uri.path());
    let Ok(uri) = format!("{}{path}", auth.base_url).parse::<Uri>() else {
        return crate::http::problem(StatusCode::BAD_REQUEST, "bad-target");
    };
    let now = i64::try_from(auth.clock.now_ms() / 1_000).unwrap_or(i64::MAX);
    let certificate = parts.extensions.get::<ClientCertificate>().cloned();
    let request = InboundRequest {
        from: &from,
        method: &parts.method,
        uri: &uri,
        headers: &parts.headers,
        body: &body,
        now,
        certificate: certificate.as_ref(),
    };
    match auth.authenticate(&request).await {
        Ok(provider) => {
            // No peer label: a provider with a DNS key can be anyone.
            crate::telemetry::metrics().provider_auth.add(
                1,
                &[
                    opentelemetry::KeyValue::new("outcome", "authenticated"),
                    opentelemetry::KeyValue::new("mechanism", provider.mechanism.name()),
                ],
            );
            tracing::debug!(
                peer = provider.domain.as_str(),
                endpoint,
                mechanism = provider.mechanism.name(),
                key_id = provider.key_id,
                dnssec = provider.dnssec.map(DnssecStatus::name),
                "provider authenticated"
            );
            parts.extensions.insert(provider);
        }
        Err(refusal) => match auth.mode(&from) {
            AuthMode::Enforce => {
                crate::telemetry::metrics()
                    .provider_auth
                    .add(1, &[opentelemetry::KeyValue::new("outcome", "refused")]);
                tracing::debug!(
                    peer = from.as_str(),
                    endpoint,
                    reason = %refusal,
                    status = StatusCode::FORBIDDEN.as_u16(),
                    "request refused: provider not authenticated"
                );
                return refuse(Some(&refusal));
            }
            AuthMode::Observe => {
                crate::telemetry::metrics()
                    .provider_auth
                    .add(1, &[opentelemetry::KeyValue::new("outcome", "observed")]);
                if auth.first_observed(&from) {
                    tracing::info!(
                        name: "provider_auth_observed",
                        peer = from.as_str(),
                        endpoint,
                        reason = %refusal,
                        "provider not authenticated; accepted in observe mode"
                    );
                } else {
                    tracing::debug!(
                        peer = from.as_str(),
                        endpoint,
                        reason = %refusal,
                        "provider not authenticated; accepted in observe mode"
                    );
                }
            }
        },
    }
    next.run(Request::from_parts(parts, Body::from(body))).await
}

/// The `Accept-Signature` field of a refusal (RFC 9421 §5.1): one
/// signature labeled [`SIGNATURE_LABEL`], covering `@method`,
/// `@target-uri`, `content-digest` and `from`, with `created`, tagged
/// `mimi`, by Ed25519.
pub const ACCEPT_SIGNATURE: &str = "mimi=(\"@method\" \"@target-uri\" \"content-digest\" \"from\");created;tag=\"mimi\";alg=\"ed25519\"";

/// The answer to a request whose source does not authenticate:
/// `403 Forbidden`, as draft-atwood-mimi-provider-auth-00 §11 says, with
/// [`ACCEPT_SIGNATURE`] and the RFC 9457 problem type
/// `provider-authentication`. Not `401`: RFC 9110 §15.5.2 requires a 401
/// to carry a `WWW-Authenticate` challenge, and RFC 9421 is not an HTTP
/// authentication scheme.
///
/// The body carries a `reason` member when
/// [`Refusal::public_reason`] gives one. An earlier version of this
/// function sent no reason at all, reading the draft's SHOULD NOT on
/// saying why each mechanism failed as a blanket prohibition. It is
/// not: §9 says a target provider "MAY include a problem details body
/// saying why authentication failed", and the SHOULD NOT is bounded by
/// "beyond what the source provider needs to fix its configuration".
/// Without a reason a peer whose certificate is one dNSName away from
/// working reads the `Accept-Signature` field as "use signatures
/// instead" and never learns the certificate was nearly right
/// (bead mimid-75nk.12).
pub fn refuse(why: Option<&Refusal>) -> Response {
    let reason = why.and_then(Refusal::public_reason);
    let mut response = match reason {
        Some(reason) => crate::http::problem_with(
            StatusCode::FORBIDDEN,
            "provider-authentication",
            &[("reason", reason.into())],
        ),
        None => crate::http::problem(StatusCode::FORBIDDEN, "provider-authentication"),
    };
    response.headers_mut().insert(
        HeaderName::from_static("accept-signature"),
        HeaderValue::from_static(ACCEPT_SIGNATURE),
    );
    response
}

/// Signs outbound requests with this server's key (see the module
/// documentation).
#[derive(Debug)]
pub struct RequestSigner {
    key: SigningKey,
    selector: String,
}

impl RequestSigner {
    /// A signer with `key`, whose `keyid` is `selector`.
    pub fn new(key: SigningKey, selector: String) -> Self {
        Self { key, selector }
    }

    /// The public key, for peers to configure or for DNS.
    pub fn public_key(&self) -> VerifyingKey {
        self.key.verifying_key()
    }

    /// The selector.
    pub fn selector(&self) -> &str {
        &self.selector
    }

    /// Adds `Content-Digest` for `body` and the signature to `headers`,
    /// which must hold the `From` header, for a request of `method` to
    /// `uri` at `now` (seconds since the UNIX epoch).
    ///
    /// # Errors
    ///
    /// As [`httpsig::sign`]: for example [`httpsig::Error::MissingField`]
    /// if `From` is absent, or [`httpsig::Error::BadValue`] if `uri` is
    /// not absolute.
    pub fn sign(
        &self,
        method: &Method,
        uri: &Uri,
        headers: &mut HeaderMap,
        body: &[u8],
        now: i64,
    ) -> Result<(), httpsig::Error> {
        // -01 §13.2: a nonce on every request, so a replayed keyMaterial
        // (or anything else that hands out what runs out) is refused by a
        // verifier that tracks them. 16 random bytes, base64url.
        let nonce = mimi_mls::label::random_array::<16>().map_err(|_| httpsig::Error::Random)?;
        self.sign_with_nonce(
            method,
            uri,
            headers,
            body,
            now,
            Some(&URL_SAFE_NO_PAD.encode(nonce)),
        )
    }

    /// [`RequestSigner::sign`] with the given `nonce`, or none: for
    /// reproducing published examples.
    ///
    /// # Errors
    ///
    /// As [`RequestSigner::sign`], except [`httpsig::Error::Random`].
    pub fn sign_with_nonce(
        &self,
        method: &Method,
        uri: &Uri,
        headers: &mut HeaderMap,
        body: &[u8],
        now: i64,
        nonce: Option<&str>,
    ) -> Result<(), httpsig::Error> {
        headers.insert(httpsig::CONTENT_DIGEST, httpsig::content_digest(body));
        let params = SignatureParams {
            components: SIGNED_COMPONENTS.map(str::to_owned).to_vec(),
            created: Some(now),
            nonce: nonce.map(str::to_owned),
            keyid: Some(self.selector.clone()),
            tag: Some(SIGNATURE_TAG.to_owned()),
            ..SignatureParams::default()
        };
        httpsig::sign_headers(method, uri, headers, SIGNATURE_LABEL, &params, &self.key)
    }

    /// The DNS TXT record value (draft-atwood-mimi-provider-auth-00 §5.1)
    /// for
    /// `<selector>._mimi.<domain>`.
    pub fn dns_record(&self) -> String {
        format!(
            "v=MIMI1; k=ed25519; p={}",
            STANDARD.encode(self.public_key().to_bytes())
        )
    }
}

pub mod dane;
pub mod dns;
pub mod nonce;
pub mod pkix;
pub use dane::{DaneCertificates, TlsaRecord, TlsaResolver};
pub use pkix::{PkixCertificates, PkixConfigError};

pub use dns::{
    DnsKeys, DnssecStatus, HickoryTxtResolver, KeyRecord, TxtAnswer, TxtLookupError, TxtResolver,
    VALIDATION_CHECK_NAME, check_validation, parse_key_record, valid_selector,
};

#[cfg(test)]
mod tests;
