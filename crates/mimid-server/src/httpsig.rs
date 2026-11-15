//! RFC 9421 HTTP Message Signatures for requests, with Ed25519 (RFC 9421
//! §3.3.6), and RFC 9530 `Content-Digest` (bead mimid-75nk.2; decision of
//! mimid-75nk: mimid's own module, tested against RFC 9421 Appendix B).
//!
//! [`sign`] adds a `Signature-Input` and a `Signature` member under one
//! label; [`verify`] checks the member under a label against a key the
//! caller chooses from the signature's parameters. Both build the
//! signature base of RFC 9421 §2.5 from the covered components:
//!
//! - derived components (§2.2): `@method`, `@target-uri`, `@authority`,
//!   `@scheme`, `@path` and `@query`;
//! - header fields (§2.1), by lowercase name, each instance's value with
//!   leading and trailing whitespace removed and the instances joined by
//!   `", "`.
//!
//! The structured fields `Signature-Input` and `Signature` (RFC 9651
//! dictionaries) are parsed and serialized with the `sfv` crate, so the
//! `@signature-params` line is the canonical serialization of the inner
//! list, as §2.3 requires.
//!
//! # Limitations
//!
//! - Requests only: no response signing and no `;req` components.
//! - Component parameters (`;sf`, `;key`, `;bs`, `;tr`, `;name`) and the
//!   `@request-target`, `@query-param` and `@status` components are not
//!   supported; a signature that covers one is refused as unsupported.
//! - Only `ed25519`. A signature whose `alg` names another algorithm is
//!   refused.

use std::fmt;

use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, Uri};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use ed25519_dalek::Signer;
use sfv::{
    BareItem, Dictionary, InnerList, Item, Key, ListEntry, ListSerializer, Parameters, Parser,
};
use sha2::{Digest, Sha256, Sha512};

/// The `Signature-Input` header field (RFC 9421 §4.1).
pub const SIGNATURE_INPUT: &str = "signature-input";
/// The `Signature` header field (RFC 9421 §4.2).
pub const SIGNATURE: &str = "signature";
/// The `Content-Digest` header field (RFC 9530 §2).
pub const CONTENT_DIGEST: &str = "content-digest";

/// The RFC 9421 §6.2.2 algorithm name of Ed25519.
const ED25519: &str = "ed25519";

/// Why a signature could not be made or does not verify.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// `Signature-Input` or `Signature` is missing, repeated where it may
    /// not be, or not an RFC 9651 dictionary of the right shape.
    #[error("malformed {0}")]
    Malformed(&'static str),
    /// No `Signature-Input` member has the label.
    #[error("no signature labeled {0:?}")]
    NoSuchLabel(String),
    /// The signature covers a component or parameter this module does not
    /// implement.
    #[error("unsupported component or parameter {0:?}")]
    Unsupported(String),
    /// A covered component is listed twice (RFC 9421 §2.5).
    #[error("component {0:?} covered twice")]
    DuplicateComponent(String),
    /// A covered header field is absent from the message (RFC 9421 §2.5).
    #[error("covered field {0:?} is absent")]
    MissingField(String),
    /// A covered value cannot be put in the signature base: not visible
    /// ASCII, or a derived component the message cannot give.
    #[error("component {0:?} has no usable value")]
    BadValue(String),
    /// `alg` names an algorithm other than `ed25519`.
    #[error("algorithm {0:?} is not supported")]
    Algorithm(String),
    /// The caller has no key for the signature.
    #[error("no key for this signature")]
    UnknownKey,
    /// The signature does not verify.
    #[error("the signature does not verify")]
    BadSignature,
    /// `created` is missing, in the future past the allowed skew, or older
    /// than allowed, or `expires` has passed (RFC 9421 §3.2.1).
    #[error("the signature is not valid at this time")]
    Time,
    /// `Content-Digest` is missing, malformed, has no supported algorithm,
    /// or does not match the body (RFC 9530).
    #[error("content-digest does not match the body")]
    Digest,
}

/// An Ed25519 key that signs requests. Its `Debug` output never shows the
/// private key, and the key is zeroized when dropped.
pub struct SigningKey(ed25519_dalek::SigningKey);

impl SigningKey {
    /// The key whose 32-byte private key (RFC 8032 seed) is `seed`.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self(ed25519_dalek::SigningKey::from_bytes(seed))
    }

    /// The matching public key.
    pub fn verifying_key(&self) -> VerifyingKey {
        VerifyingKey(self.0.verifying_key())
    }
}

impl fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SigningKey")
            .field("public", &self.verifying_key())
            .finish_non_exhaustive()
    }
}

/// An Ed25519 public key that verifies request signatures.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct VerifyingKey(ed25519_dalek::VerifyingKey);

impl VerifyingKey {
    /// The key whose 32-byte encoding (RFC 8032 §5.1.5) is `bytes`, or
    /// `None` if it is not a valid point.
    pub fn from_bytes(bytes: &[u8; 32]) -> Option<Self> {
        ed25519_dalek::VerifyingKey::from_bytes(bytes)
            .ok()
            .map(Self)
    }

    /// The 32-byte encoding.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }
}

impl fmt::Debug for VerifyingKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "VerifyingKey({})", STANDARD.encode(self.0.as_bytes()))
    }
}

/// The parts of a request a signature covers. `uri` must be absolute
/// (scheme and authority) when the signature covers `@target-uri`,
/// `@scheme` or `@authority`; a server builds it from its own base URL and
/// the request's path and query.
#[derive(Debug, Clone, Copy)]
pub struct RequestParts<'a> {
    /// The request method.
    pub method: &'a Method,
    /// The request target as an absolute URI.
    pub uri: &'a Uri,
    /// The header fields.
    pub headers: &'a HeaderMap,
}

/// The signature parameters of RFC 9421 §2.3 that this module handles.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SignatureParams {
    /// The covered component identifiers, in order: derived components
    /// with their `@`, header fields by lowercase name.
    pub components: Vec<String>,
    /// `created`, seconds since the UNIX epoch.
    pub created: Option<i64>,
    /// `expires`, seconds since the UNIX epoch.
    pub expires: Option<i64>,
    /// `keyid`.
    pub keyid: Option<String>,
    /// `alg`.
    pub alg: Option<String>,
    /// `nonce`.
    pub nonce: Option<String>,
    /// `tag`.
    pub tag: Option<String>,
}

impl SignatureParams {
    /// As an RFC 9651 inner list with parameters, in the order `created`,
    /// `expires`, `nonce`, `alg`, `keyid`, `tag`.
    fn to_inner_list(&self) -> Result<InnerList, Error> {
        let mut items = Vec::new();
        for component in &self.components {
            let string = sfv::String::from_string(component.clone())
                .map_err(|_| Error::BadValue(component.clone()))?;
            items.push(Item {
                bare_item: BareItem::String(string),
                params: Parameters::new(),
            });
        }
        let mut params = Parameters::new();
        let key = |name: &str| {
            Key::from_string(name.to_owned()).map_err(|_| Error::Malformed(SIGNATURE_INPUT))
        };
        for (name, value) in [("created", self.created), ("expires", self.expires)] {
            if let Some(value) = value {
                let value = sfv::Integer::try_from(value).map_err(|_| Error::Time)?;
                params.insert(key(name)?, BareItem::Integer(value));
            }
        }
        for (name, value) in [
            ("nonce", &self.nonce),
            ("alg", &self.alg),
            ("keyid", &self.keyid),
            ("tag", &self.tag),
        ] {
            if let Some(value) = value {
                let string = sfv::String::from_string(value.clone())
                    .map_err(|_| Error::BadValue(name.to_owned()))?;
                params.insert(key(name)?, BareItem::String(string));
            }
        }
        Ok(InnerList { items, params })
    }

    /// Reads a parsed `Signature-Input` member.
    fn from_inner_list(list: &InnerList) -> Result<Self, Error> {
        let mut params = Self::default();
        for item in &list.items {
            let BareItem::String(name) = &item.bare_item else {
                return Err(Error::Malformed(SIGNATURE_INPUT));
            };
            if let Some((key, _)) = item.params.iter().next() {
                return Err(Error::Unsupported(format!(
                    "{};{}",
                    name.as_str(),
                    key.as_str()
                )));
            }
            params.components.push(name.as_str().to_owned());
        }
        for (key, value) in &list.params {
            let string = || {
                value
                    .as_string()
                    .map(|s| s.as_str().to_owned())
                    .ok_or(Error::Malformed(SIGNATURE_INPUT))
            };
            let integer = || {
                value
                    .as_integer()
                    .map(i64::from)
                    .ok_or(Error::Malformed(SIGNATURE_INPUT))
            };
            match key.as_str() {
                "created" => params.created = Some(integer()?),
                "expires" => params.expires = Some(integer()?),
                "keyid" => params.keyid = Some(string()?),
                "alg" => params.alg = Some(string()?),
                "nonce" => params.nonce = Some(string()?),
                "tag" => params.tag = Some(string()?),
                other => return Err(Error::Unsupported(other.to_owned())),
            }
        }
        Ok(params)
    }
}

/// The canonical serialization of `list`, as it appears after the label in
/// `Signature-Input` and on the `@signature-params` line.
fn serialize_inner_list(list: &InnerList) -> String {
    let mut out = String::new();
    {
        let mut serializer = ListSerializer::with_buffer(&mut out);
        let mut inner = serializer.inner_list();
        inner.items(&list.items);
        let _ = inner.finish().parameters(&list.params);
    }
    out
}

/// The value of one covered component (RFC 9421 §2.1, §2.2).
fn component_value(parts: &RequestParts<'_>, name: &str) -> Result<String, Error> {
    let bad = || Error::BadValue(name.to_owned());
    let uri = parts.uri;
    let value = match name {
        "@method" => parts.method.as_str().to_owned(),
        "@target-uri" => {
            if uri.scheme().is_none() || uri.authority().is_none() {
                return Err(bad());
            }
            uri.to_string()
        }
        "@authority" => {
            let authority = uri.authority().ok_or_else(bad)?;
            let host = authority.host().to_ascii_lowercase();
            let default_port = match uri.scheme_str() {
                Some("https") => Some(443),
                Some("http") => Some(80),
                _ => None,
            };
            match authority.port_u16() {
                Some(port) if Some(port) != default_port => format!("{host}:{port}"),
                _ => host,
            }
        }
        "@scheme" => uri.scheme_str().ok_or_else(bad)?.to_ascii_lowercase(),
        "@path" => match uri.path() {
            "" => "/".to_owned(),
            path => path.to_owned(),
        },
        "@query" => format!("?{}", uri.query().unwrap_or("")),
        derived if derived.starts_with('@') => return Err(Error::Unsupported(derived.to_owned())),
        field => {
            if field.bytes().any(|b| b.is_ascii_uppercase()) {
                return Err(Error::Unsupported(field.to_owned()));
            }
            let name = HeaderName::from_bytes(field.as_bytes()).map_err(|_| bad())?;
            let mut values = Vec::new();
            for value in parts.headers.get_all(&name) {
                let text = value.to_str().map_err(|_| bad())?;
                values.push(text.trim_matches([' ', '\t']).to_owned());
            }
            if values.is_empty() {
                return Err(Error::MissingField(field.to_owned()));
            }
            values.join(", ")
        }
    };
    if value.bytes().any(|b| !(b == b' ' || b.is_ascii_graphic())) {
        return Err(bad());
    }
    Ok(value)
}

/// The signature base of RFC 9421 §2.5 for `parts` and `list`.
fn signature_base(parts: &RequestParts<'_>, list: &InnerList) -> Result<String, Error> {
    let params = SignatureParams::from_inner_list(list)?;
    let mut base = String::new();
    let mut seen = std::collections::BTreeSet::new();
    for name in &params.components {
        if !seen.insert(name.as_str()) {
            return Err(Error::DuplicateComponent(name.clone()));
        }
        let value = component_value(parts, name)?;
        base.push_str(&format!("\"{name}\": {value}\n"));
    }
    base.push_str(&format!(
        "\"@signature-params\": {}",
        serialize_inner_list(list)
    ));
    Ok(base)
}

/// The signature base for `parts` and `params`, exactly as [`sign`] signs
/// it. For tests and logs at TRACE.
///
/// # Errors
///
/// As [`sign`].
pub fn signature_base_for(
    parts: &RequestParts<'_>,
    params: &SignatureParams,
) -> Result<String, Error> {
    signature_base(parts, &params.to_inner_list()?)
}

fn dictionary(headers: &HeaderMap, field: &'static str) -> Result<Dictionary, Error> {
    let values: Vec<&str> = headers
        .get_all(field)
        .iter()
        .map(|v| v.to_str().map_err(|_| Error::Malformed(field)))
        .collect::<Result<_, _>>()?;
    if values.is_empty() {
        return Ok(Dictionary::new());
    }
    // RFC 9651 §4.2: field lines are combined with commas before parsing.
    Parser::new(&values.join(", "))
        .parse::<Dictionary>()
        .map_err(|_| Error::Malformed(field))
}

/// The labels of the `Signature-Input` members in `headers`, in order.
///
/// # Errors
///
/// [`Error::Malformed`] if `Signature-Input` is not an RFC 9651
/// dictionary.
pub fn labels(headers: &HeaderMap) -> Result<Vec<String>, Error> {
    Ok(dictionary(headers, SIGNATURE_INPUT)?
        .keys()
        .map(|key| key.as_str().to_owned())
        .collect())
}

/// Signs `parts` with `key` under `label`, covering `params`, and returns
/// the `Signature-Input` and `Signature` member values to add (the label
/// and `=` included), so the caller can append them to existing fields.
/// `params.alg` is not set for the caller: RFC 9421 §2.3 makes it optional.
///
/// # Errors
///
/// [`Error::DuplicateComponent`], [`Error::MissingField`],
/// [`Error::BadValue`] or [`Error::Unsupported`] for a component that
/// cannot be covered, and [`Error::Malformed`] for a label that is not an
/// RFC 9651 key.
pub fn sign(
    parts: &RequestParts<'_>,
    label: &str,
    params: &SignatureParams,
    key: &SigningKey,
) -> Result<(HeaderValue, HeaderValue), Error> {
    if let Some(alg) = &params.alg
        && alg != ED25519
    {
        return Err(Error::Algorithm(alg.clone()));
    }
    let label =
        Key::from_string(label.to_owned()).map_err(|_| Error::Malformed(SIGNATURE_INPUT))?;
    let list = params.to_inner_list()?;
    let base = signature_base(parts, &list)?;
    let signature = key.0.sign(base.as_bytes()).to_bytes();
    let input = format!("{}={}", label.as_str(), serialize_inner_list(&list));
    let value = format!("{}=:{}:", label.as_str(), STANDARD.encode(signature));
    Ok((
        HeaderValue::from_str(&input).map_err(|_| Error::Malformed(SIGNATURE_INPUT))?,
        HeaderValue::from_str(&value).map_err(|_| Error::Malformed(SIGNATURE))?,
    ))
}

/// Adds the signature of [`sign`] to `headers`.
///
/// # Errors
///
/// As [`sign`].
pub fn sign_headers(
    method: &Method,
    uri: &Uri,
    headers: &mut HeaderMap,
    label: &str,
    params: &SignatureParams,
    key: &SigningKey,
) -> Result<(), Error> {
    let (input, signature) = sign(
        &RequestParts {
            method,
            uri,
            headers,
        },
        label,
        params,
        key,
    )?;
    headers.append(SIGNATURE_INPUT, input);
    headers.append(SIGNATURE, signature);
    Ok(())
}

/// What [`verify`] accepts in time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimePolicy {
    /// Now, in seconds since the UNIX epoch.
    pub now: i64,
    /// How far `created` may be in the future, for clock skew.
    pub skew: i64,
    /// How old `created` may be.
    pub max_age: i64,
}

/// Verifies the signature labeled `label` in `parts`, with the key that
/// `key_for` chooses from its parameters, and returns the parameters.
/// `created` is required, and is checked against `time`, as is `expires`
/// when present.
///
/// # Errors
///
/// [`Error::NoSuchLabel`], [`Error::Malformed`], [`Error::Unsupported`],
/// [`Error::Algorithm`], [`Error::UnknownKey`] when `key_for` returns
/// `None`, [`Error::Time`], the errors of building the signature base, and
/// [`Error::BadSignature`].
pub fn verify(
    parts: &RequestParts<'_>,
    label: &str,
    time: TimePolicy,
    key_for: impl FnOnce(&SignatureParams) -> Option<VerifyingKey>,
) -> Result<SignatureParams, Error> {
    let inputs = dictionary(parts.headers, SIGNATURE_INPUT)?;
    let signatures = dictionary(parts.headers, SIGNATURE)?;
    let Some(ListEntry::InnerList(list)) = inputs.get(label) else {
        return match inputs.get(label) {
            Some(_) => Err(Error::Malformed(SIGNATURE_INPUT)),
            None => Err(Error::NoSuchLabel(label.to_owned())),
        };
    };
    let Some(ListEntry::Item(Item {
        bare_item: BareItem::ByteSequence(signature),
        ..
    })) = signatures.get(label)
    else {
        return Err(Error::Malformed(SIGNATURE));
    };
    let params = SignatureParams::from_inner_list(list)?;
    if let Some(alg) = &params.alg
        && alg != ED25519
    {
        return Err(Error::Algorithm(alg.clone()));
    }
    let created = params.created.ok_or(Error::Time)?;
    if created > time.now.saturating_add(time.skew)
        || created < time.now.saturating_sub(time.max_age)
    {
        return Err(Error::Time);
    }
    if params.expires.is_some_and(|expires| expires <= time.now) {
        return Err(Error::Time);
    }
    let key = key_for(&params).ok_or(Error::UnknownKey)?;
    let base = signature_base(parts, list)?;
    let signature =
        ed25519_dalek::Signature::from_slice(signature).map_err(|_| Error::BadSignature)?;
    // Strict verification (RFC 8032 §5.1.7), as mimi-mls verifies MLS
    // signatures.
    key.0
        .verify_strict(base.as_bytes(), &signature)
        .map_err(|_| Error::BadSignature)?;
    Ok(params)
}

/// The `Content-Digest` value for `body` (RFC 9530 §2): `sha-256`.
pub fn content_digest(body: &[u8]) -> HeaderValue {
    let digest = Sha256::digest(body);
    HeaderValue::from_str(&format!("sha-256=:{}:", STANDARD.encode(digest)))
        .unwrap_or_else(|_| HeaderValue::from_static(""))
}

/// Checks `headers`' `Content-Digest` against `body` (RFC 9530): every
/// `sha-256` or `sha-512` member must match, and at least one must be
/// present. Members for other algorithms are ignored (RFC 9530 §2).
///
/// # Errors
///
/// [`Error::Digest`].
pub fn check_content_digest(headers: &HeaderMap, body: &[u8]) -> Result<(), Error> {
    let digests = dictionary(headers, CONTENT_DIGEST).map_err(|_| Error::Digest)?;
    let mut checked = false;
    for (name, entry) in &digests {
        let expected: Vec<u8> = match name.as_str() {
            "sha-256" => Sha256::digest(body).to_vec(),
            "sha-512" => Sha512::digest(body).to_vec(),
            _ => continue,
        };
        let ListEntry::Item(Item {
            bare_item: BareItem::ByteSequence(value),
            ..
        }) = entry
        else {
            return Err(Error::Digest);
        };
        if *value != expected {
            return Err(Error::Digest);
        }
        checked = true;
    }
    if checked { Ok(()) } else { Err(Error::Digest) }
}

#[cfg(test)]
mod tests;
