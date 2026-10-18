//! Franking wire types and HMACs (protocol-06 §5.4, §5.4.1).

use hmac::{Hmac, KeyInit, Mac, digest::Key};
use mimi_mls::wire::CipherSuite;
use sha2::Sha256;
use tls_codec::{Serialize, TlsDeserialize, TlsSerialize, TlsSize};

use crate::{Error, IdentifierUri};

/// `struct { uint8 franking_tag[32]; } FrankAAD;` (protocol-06 §5.4.1).
///
/// The `aad_item_data` of a `SafeAADItem` with component ID
/// [`FRANK_AAD`](crate::component_id::FRANK_AAD) (mls-extensions-10 §4.9;
/// decision mimid-1wgh.4.17). The fixed-size array has no length prefix, so
/// the encoding is exactly 32 bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, TlsSerialize, TlsDeserialize, TlsSize)]
pub struct FrankAad {
    /// `HMAC_SHA256(salt, application_data)` (§5.4.1.1); see
    /// [`franking_tag`].
    pub franking_tag: [u8; 32],
}

/// `Frank` (protocol-06 §5.4): the hub's frank on an application message,
/// carried in a `SubmitMessageResponse` and a [`FanoutMessage`](crate::FanoutMessage).
///
/// Decoding checks the wire form only. Neither `server_frank` nor the
/// signature is verified here.
#[derive(Debug, Clone, PartialEq, Eq, Hash, TlsSerialize, TlsDeserialize, TlsSize)]
pub struct Frank {
    /// `uint8 server_frank[32]` (§5.4.1.2); see [`server_frank`].
    pub server_frank: [u8; 32],
    /// The ciphersuite of `franking_integrity_signature`. Any `uint16`
    /// decodes.
    pub franking_signature_ciphersuite: CipherSuite,
    /// `opaque franking_integrity_signature<V>` (§5.4.1.2).
    pub franking_integrity_signature: Vec<u8>,
}

/// `struct { IdentifierUri sender_uri; IdentifierUri room_uri; uint64
/// accepted_timestamp; } ServerFrankingContext;` (protocol-06 §5.4.1.2).
///
/// The hub's context for a frank. Its TLS encoding follows the
/// `franking_tag` in the input to [`server_frank`].
#[derive(Debug, Clone, PartialEq, Eq, Hash, TlsSerialize, TlsDeserialize, TlsSize)]
pub struct ServerFrankingContext {
    /// The sender URI the client asserted to the hub.
    pub sender_uri: IdentifierUri,
    /// The room URI.
    pub room_uri: IdentifierUri,
    /// The hub acceptance time, in milliseconds from the UNIX epoch (§5.4).
    pub accepted_timestamp: u64,
}

/// `hub_key` (protocol-06 §5.4.1.2): the hub's secret HMAC key for
/// [`server_frank`].
///
/// The draft gives no length. The key never goes on the wire, so mimid fixes
/// it at 32 bytes, the HMAC-SHA256 output size (RFC 2104 §3). `Debug` prints
/// no key bytes. protocol-06 §5.4.1.2; decision mimid-1wgh.5.53.
pub struct HubKey([u8; 32]);

impl HubKey {
    /// Wraps 32 secret bytes.
    pub fn new(key: [u8; 32]) -> Self {
        Self(key)
    }
}

impl std::fmt::Debug for HubKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("HubKey(..)")
    }
}

type HmacSha256 = Hmac<Sha256>;

/// An HMAC-SHA256 instance keyed with `key`.
///
/// `key` is zero-padded to the 64-byte SHA-256 block, which RFC 2104 §2
/// step (1) makes identical to keying with `key` itself. That allows the
/// infallible [`KeyInit::new`] instead of `new_from_slice`, whose `Result`
/// is never `Err` for HMAC but would still need unwrapping.
fn hmac_sha256<const N: usize>(key: &[u8; N]) -> HmacSha256 {
    const { assert!(N <= 64) };
    let mut block = Key::<HmacSha256>::default();
    block[..N].copy_from_slice(key);
    HmacSha256::new(&block)
}

/// `franking_tag = HMAC_SHA256(salt, application_data)` (protocol-06
/// §5.4.1.1).
///
/// `salt` is the MIMI content salt (mimi-content-09 `salt: bstr .size 16`).
/// `application_data` is the whole MLS application_data, including the
/// ApplicationFraming when content advertisement is used (decision
/// mimid-1wgh.5.29).
pub fn franking_tag(salt: &[u8; 16], application_data: &[u8]) -> [u8; 32] {
    let mut mac = hmac_sha256(salt);
    mac.update(application_data);
    mac.finalize().into_bytes().into()
}

/// Checks a received `franking_tag` against `salt` and `application_data`
/// in constant time, as a receiver does in §5.4.1.3.
///
/// # Errors
///
/// [`Error::FrankingTagMismatch`] if the tag does not match.
pub fn verify_franking_tag(
    salt: &[u8; 16],
    application_data: &[u8],
    franking_tag: &[u8; 32],
) -> Result<(), Error> {
    let mut mac = hmac_sha256(salt);
    mac.update(application_data);
    mac.verify_slice(franking_tag)
        .map_err(|_| Error::FrankingTagMismatch)
}

/// The keyed MAC over `franking_tag || context`, before finalizing.
fn server_frank_mac(
    hub_key: &HubKey,
    franking_tag: &[u8; 32],
    context: &ServerFrankingContext,
) -> Result<HmacSha256, Error> {
    let encoded = context.tls_serialize_detached().map_err(Error::Encoding)?;
    let mut mac = hmac_sha256(&hub_key.0);
    // The raw 32-byte tag, then the TLS-encoded context (decision
    // mimid-1wgh.5.28).
    mac.update(franking_tag);
    mac.update(&encoded);
    Ok(mac)
}

/// `server_frank = HMAC_SHA256(hub_key, (franking_tag || context))`
/// (protocol-06 §5.4.1.2).
///
/// `||` is the raw 32-byte `franking_tag` followed by the TLS encoding of
/// `context` (decision mimid-1wgh.5.28).
///
/// # Errors
///
/// [`Error::Encoding`] if `context` cannot be TLS-encoded, which takes a URI
/// longer than 2^30 - 1 bytes.
pub fn server_frank(
    hub_key: &HubKey,
    franking_tag: &[u8; 32],
    context: &ServerFrankingContext,
) -> Result<[u8; 32], Error> {
    Ok(server_frank_mac(hub_key, franking_tag, context)?
        .finalize()
        .into_bytes()
        .into())
}

/// Checks a `server_frank` in constant time, as the hub does when it
/// validates an AbusiveMessage (§5.9).
///
/// # Errors
///
/// [`Error::ServerFrankMismatch`] if the frank does not match, or
/// [`Error::Encoding`] as for [`server_frank`].
pub fn verify_server_frank(
    hub_key: &HubKey,
    franking_tag: &[u8; 32],
    context: &ServerFrankingContext,
    server_frank: &[u8; 32],
) -> Result<(), Error> {
    server_frank_mac(hub_key, franking_tag, context)?
        .verify_slice(server_frank)
        .map_err(|_| Error::ServerFrankMismatch)
}
