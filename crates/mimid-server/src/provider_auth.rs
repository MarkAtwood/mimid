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
//! Mechanisms (decision of mimid-75nk, in build order):
//!
//! 1. [`Mechanism::TrustList`] (this bead): RFC 9421 request signatures
//!    ([`crate::httpsig`]) with Ed25519 keys configured per peer, by
//!    selector, in `[provider_auth.peers."<domain>"] keys`.
//! 2. DNS-published keys (mimid-75nk.3), 3. PKIX mutual TLS (mimid-75nk.5)
//!    and 4. DANE (mimid-75nk.6) are not built yet.
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
//! `from` (draft-atwood-mimi-provider-auth-00 §5.2).
//!
//! # Logging
//!
//! A refusal in `enforce` mode is a correct refusal: one DEBUG event with
//! the reason. In `observe` mode each failure is a DEBUG event, and the
//! first failure of each provider since start an INFO event, so an
//! operator sees which peers do not authenticate without one event per
//! request. A success is a DEBUG event.
//!
//! # Limitations
//!
//! - Only RFC 9421 with trust-listed keys so far; trust-listed CAs and
//!   certificates need mutual TLS (mimid-75nk.4, mimid-75nk.5).
//! - Nonces are not tracked, so a signed request can be replayed within
//!   [`MAX_SIGNATURE_AGE_SECS`].
//! - `@target-uri` is rebuilt from this server's configured `base_url`
//!   and the request path, so a peer must sign the URL from this server's
//!   directory.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::{Arc, Mutex, PoisonError};

use axum::body::{Body, to_bytes};
use axum::extract::{Request, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri, header};
use axum::middleware::Next;
use axum::response::Response;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde::Deserialize;

use crate::config::{BaseUrl, Domain};
use crate::httpsig::{self, SignatureParams, SigningKey, TimePolicy, VerifyingKey};
use crate::hub::Clock;

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
    /// The `keyid` of this server's request signatures, and its DNS
    /// selector later (mimid-75nk.3).
    #[serde(default = "default_selector")]
    pub selector: String,
    /// Per-provider settings.
    #[serde(default)]
    pub peers: BTreeMap<Domain, PeerAuthConfig>,
}

impl Default for ProviderAuthConfig {
    fn default() -> Self {
        Self {
            mode: AuthMode::default(),
            selector: default_selector(),
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
}

/// How a provider was authenticated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Mechanism {
    /// An RFC 9421 signature with a key configured for the provider.
    TrustList,
}

impl Mechanism {
    /// The name used in logs.
    pub fn name(self) -> &'static str {
        match self {
            Self::TrustList => "trust_list",
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
    /// The key it used: the `keyid`.
    pub key_id: String,
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
    /// A signature does not cover [`REQUIRED_COMPONENTS`].
    #[error("signature does not cover {0}")]
    NotCovered(&'static str),
    /// `Content-Digest` is missing or does not match the body.
    #[error("content-digest does not match the body")]
    Digest,
    /// The signature is malformed, unsupported, expired or wrong.
    #[error("signature refused: {0}")]
    Signature(#[source] httpsig::Error),
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
}

/// One authentication mechanism.
pub trait ProviderAuthenticator: Send + Sync {
    /// Checks `request`.
    fn authenticate(&self, request: &InboundRequest<'_>) -> Outcome;
}

/// Mechanism 4 of mimid-75nk: RFC 9421 signatures with keys configured
/// per provider.
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

impl ProviderAuthenticator for TrustList {
    fn authenticate(&self, request: &InboundRequest<'_>) -> Outcome {
        let labels = match httpsig::labels(request.headers) {
            Ok(labels) if labels.is_empty() => return Outcome::NotApplicable,
            Ok(labels) => labels,
            Err(error) => return Outcome::Refused(Refusal::Signature(error)),
        };
        let Some(keys) = self.keys.get(request.from) else {
            return Outcome::Refused(Refusal::NoTrustedKey);
        };
        // §5.3 step 6: the digest is checked when there is content.
        if !request.body.is_empty()
            && httpsig::check_content_digest(request.headers, request.body).is_err()
        {
            return Outcome::Refused(Refusal::Digest);
        }
        // §5.3 step 2: signatures tagged `mimi` first.
        let mut labels = labels;
        if let Ok(signatures) = httpsig::signatures(request.headers) {
            let tagged: BTreeSet<&str> = signatures
                .iter()
                .filter(|(_, p)| p.tag.as_deref() == Some(SIGNATURE_TAG))
                .map(|(label, _)| label.as_str())
                .collect();
            labels.sort_by_key(|label| !tagged.contains(label.as_str()));
        }
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
        for label in labels.iter().take(MAX_SIGNATURES_TRIED) {
            let verified = httpsig::verify(&parts, label, time, |params| {
                params.keyid.as_deref().and_then(|id| keys.get(id)).copied()
            });
            let params = match verified {
                Ok(params) => params,
                Err(httpsig::Error::UnknownKey) => {
                    refusal = Refusal::UnknownKey;
                    continue;
                }
                Err(error) => {
                    refusal = Refusal::Signature(error);
                    continue;
                }
            };
            let covers = |c: &str| params.components.iter().any(|have| have == c);
            if let Some(missing) = REQUIRED_COMPONENTS.into_iter().find(|c| !covers(c)) {
                refusal = Refusal::NotCovered(missing);
                continue;
            }
            if !request.body.is_empty() && !covers(httpsig::CONTENT_DIGEST) {
                refusal = Refusal::NotCovered(httpsig::CONTENT_DIGEST);
                continue;
            }
            return Outcome::Authenticated(AuthenticatedProvider {
                domain: request.from.clone(),
                mechanism: Mechanism::TrustList,
                key_id: params.keyid.unwrap_or_default(),
            });
        }
        Outcome::Refused(refusal)
    }
}

/// The inbound policy: the mechanisms in order and each provider's mode.
pub struct ProviderAuth {
    authenticators: Vec<Box<dyn ProviderAuthenticator>>,
    default_mode: AuthMode,
    modes: BTreeMap<Domain, AuthMode>,
    base_url: String,
    clock: Arc<dyn Clock>,
    /// Providers whose observe-mode failure has been logged at INFO.
    observed: Mutex<BTreeSet<Domain>>,
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
        Self {
            authenticators: vec![Box::new(TrustList::new(config))],
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
    pub fn authenticate(
        &self,
        request: &InboundRequest<'_>,
    ) -> Result<AuthenticatedProvider, Refusal> {
        let mut refusal = Refusal::NoCredentials;
        for authenticator in &self.authenticators {
            match authenticator.authenticate(request) {
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
    let Ok(uri) = format!("{}{path}", auth.base_url).parse::<Uri>() else {
        return crate::http::problem(StatusCode::BAD_REQUEST, "bad-target");
    };
    let now = i64::try_from(auth.clock.now_ms() / 1_000).unwrap_or(i64::MAX);
    let request = InboundRequest {
        from: &from,
        method: &parts.method,
        uri: &uri,
        headers: &parts.headers,
        body: &body,
        now,
    };
    match auth.authenticate(&request) {
        Ok(provider) => {
            tracing::debug!(
                peer = provider.domain.as_str(),
                mechanism = provider.mechanism.name(),
                key_id = provider.key_id,
                "provider authenticated"
            );
            parts.extensions.insert(provider);
        }
        Err(refusal) => match auth.mode(&from) {
            AuthMode::Enforce => {
                tracing::debug!(
                    peer = from.as_str(),
                    reason = %refusal,
                    status = StatusCode::FORBIDDEN.as_u16(),
                    "request refused: provider not authenticated"
                );
                return refuse();
            }
            AuthMode::Observe => {
                if auth.first_observed(&from) {
                    tracing::info!(
                        name: "provider_auth_observed",
                        peer = from.as_str(),
                        reason = %refusal,
                        "provider not authenticated; accepted in observe mode"
                    );
                } else {
                    tracing::debug!(
                        peer = from.as_str(),
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
/// authentication scheme. The reason stays in the log (the draft's
/// SHOULD NOT on saying why each mechanism failed).
pub fn refuse() -> Response {
    let mut response = crate::http::problem(StatusCode::FORBIDDEN, "provider-authentication");
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
        headers.insert(httpsig::CONTENT_DIGEST, httpsig::content_digest(body));
        let params = SignatureParams {
            components: SIGNED_COMPONENTS.map(str::to_owned).to_vec(),
            created: Some(now),
            keyid: Some(self.selector.clone()),
            tag: Some(SIGNATURE_TAG.to_owned()),
            ..SignatureParams::default()
        };
        httpsig::sign_headers(method, uri, headers, SIGNATURE_LABEL, &params, &self.key)
    }

    /// The DNS TXT record value of mimid-75nk.3's provisional format, for
    /// `<selector>._mimi.<domain>`.
    pub fn dns_record(&self) -> String {
        format!(
            "v=MIMI1; k=ed25519; p={}",
            STANDARD.encode(self.public_key().to_bytes())
        )
    }
}

#[cfg(test)]
mod tests;
