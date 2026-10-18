//! Franking (protocol-06 §5.4, §5.4.1): wire types, HMACs and the
//! franking_integrity_signature.
//!
//! The hub computes [`server_frank`] and signs a [`FrankingIntegrityTbs`]
//! with [`FrankingIntegrityTbs::sign`]. A receiver checks the result with
//! [`ReceivedFrank::verify`] (§5.4.1.3).

use hmac::{Hmac, KeyInit, Mac, digest::Key};
use mimi_mls::label;
use mimi_mls::wire::{CipherSuite, Credential, SignaturePublicKey};
use sha2::Sha256;
use tls_codec::{Serialize, TlsDeserialize, TlsSerialize, TlsSize};

use crate::group_info::{check_cipher_suite, key_bytes};
use crate::{Error, IdentifierUri};

/// SignWithLabel label for [`FrankingIntegrityTbs`] (protocol-06
/// §5.4.1.2, §5.4.1.3).
const INTEGRITY_TBS_LABEL: &str = "FrankingIntegrityTBS";

/// `struct { SignaturePublicKey franking_signature_key; Credential
/// credential; } FrankingAgentData;` (protocol-06 §5.4.1).
///
/// The `data` of the GroupContext component
/// [`FRANKING_AGENT`](crate::component_id::FRANKING_AGENT) (0x0021), which
/// §10.2 registers as `franking_signature_key` and §5.4.1 calls
/// `franking_agent` (decision mimid-1wgh.4.18). It mirrors RFC 9420
/// §12.1.8.1 `ExternalSender`. Also the `update` of an `AppDataUpdate`
/// proposal, as [`FrankingAgentUpdate`].
///
/// The key uses the signature algorithm of the group's ciphersuite.
/// Decoding checks the wire form only; nothing here checks that
/// `credential` names the hub's domain (protocol-06 §5.4.1.3; decision
/// mimid-1wgh.5.56).
#[derive(Debug, Clone, PartialEq, Eq, Hash, TlsSerialize, TlsDeserialize, TlsSize)]
pub struct FrankingAgentData {
    /// The hub's franking public key, which verifies
    /// `franking_integrity_signature`.
    pub franking_signature_key: SignaturePublicKey,
    /// The hub's credential. §5.4.1.3 requires its domain to be the hub's.
    pub credential: Credential,
}

/// `FrankingAgentData FrankingAgentUpdate;` (protocol-06 §5.4.1), the
/// `update` of an `AppDataUpdate` proposal for the franking agent.
pub type FrankingAgentUpdate = FrankingAgentData;

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

/// `FrankingIntegrityTBS` (protocol-06 §5.4.1.2): what the hub signs to
/// produce `franking_integrity_signature`.
///
/// The TBS never goes on the wire. The hub builds it after computing
/// [`server_frank`]; a receiver rebuilds it from the received [`Frank`] and
/// the context it knows, as §5.4.1.3 says ("calculating the
/// ServerFrankingContext and FrankingIntegrityTBS"). The received
/// `server_frank` and ciphersuite go in unchanged, and [`IdentifierUri`]
/// encodes exactly the bytes it holds, so nothing is normalized.
#[derive(Debug, Clone, PartialEq, Eq, Hash, TlsSerialize, TlsDeserialize, TlsSize)]
pub struct FrankingIntegrityTbs {
    /// `opaque server_frank[32]`: no length prefix, the same encoding as
    /// [`Frank::server_frank`].
    pub server_frank: [u8; 32],
    /// The group's ciphersuite when the message was franked.
    pub franking_signature_ciphersuite: CipherSuite,
    /// The hub's context for the frank.
    pub context: ServerFrankingContext,
}

impl FrankingIntegrityTbs {
    /// Signs this TBS and returns the [`Frank`] the hub sends:
    /// `SignWithLabel(franking_private_key, "FrankingIntegrityTBS",
    /// FrankingIntegrityTBS)` (protocol-06 §5.4.1.2).
    ///
    /// `franking_private_key` is the raw private key matching the group's
    /// [`FrankingAgentData::franking_signature_key`] (a 32-byte Ed25519
    /// seed for suite 1).
    ///
    /// # Errors
    ///
    /// [`Error::UnsupportedCipherSuite`] unless
    /// `franking_signature_ciphersuite` is 1, [`Error::Encoding`] if the TBS
    /// cannot be encoded, and [`Error::Label`] if signing fails.
    pub fn sign(&self, franking_private_key: &[u8]) -> Result<Frank, Error> {
        check_cipher_suite(self.franking_signature_ciphersuite)?;
        let tbs_bytes = self.tls_serialize_detached().map_err(Error::Encoding)?;
        let franking_integrity_signature =
            label::sign_with_label(franking_private_key, INTEGRITY_TBS_LABEL, &tbs_bytes)
                .map_err(Error::Label)?;
        Ok(Frank {
            server_frank: self.server_frank,
            franking_signature_ciphersuite: self.franking_signature_ciphersuite,
            franking_integrity_signature,
        })
    }
}

impl Frank {
    /// Checks `franking_integrity_signature`: `VerifyWithLabel(
    /// franking_signature_key, "FrankingIntegrityTBS", FrankingIntegrityTBS,
    /// franking_integrity_signature)` (protocol-06 §5.4.1.3), where the TBS
    /// holds this frank's `server_frank` and ciphersuite, as received, and
    /// `context`.
    ///
    /// This proves the hub's franking key signed these values. It does not
    /// check `server_frank` itself, which needs the hub's [`HubKey`]
    /// ([`verify_server_frank`]).
    ///
    /// # Errors
    ///
    /// [`Error::UnsupportedCipherSuite`] unless
    /// `franking_signature_ciphersuite` is 1, [`Error::Decoding`] if the key
    /// encoding is malformed, [`Error::Encoding`] if the TBS cannot be
    /// encoded, and [`Error::Label`] if the signature does not verify.
    pub fn verify_integrity(
        &self,
        franking_signature_key: &SignaturePublicKey,
        context: &ServerFrankingContext,
    ) -> Result<(), Error> {
        check_cipher_suite(self.franking_signature_ciphersuite)?;
        let key = key_bytes(franking_signature_key.as_bytes())?;
        let tbs_bytes = FrankingIntegrityTbs {
            server_frank: self.server_frank,
            franking_signature_ciphersuite: self.franking_signature_ciphersuite,
            context: context.clone(),
        }
        .tls_serialize_detached()
        .map_err(Error::Encoding)?;
        label::verify_with_label(
            key.as_slice(),
            INTEGRITY_TBS_LABEL,
            &tbs_bytes,
            &self.franking_integrity_signature,
        )
        .map_err(Error::Label)
    }
}

/// What a receiver holds for frank verification (protocol-06 §5.4.1.3)
/// after decrypting an otherwise valid application message from the hub.
///
/// The caller extracts every field:
///
/// | Field | Source |
/// |---|---|
/// | `frank`, `accepted_timestamp` | the [`FanoutMessage`](crate::FanoutMessage)'s `frank` and `timestamp` |
/// | `franking_tag` | the [`FrankAad`] in the PrivateMessage's Safe AAD |
/// | `group_cipher_suite` | the MLS group |
/// | `franking_agent` | the GroupContext [`FRANKING_AGENT`](crate::component_id::FRANKING_AGENT) component |
/// | `salt`, `application_data`, `content_sender_uri`, `content_room_uri` | the decrypted MIMI content (mimi-content-09 `salt`, extensions 1 and 2) |
/// | `authenticated_sender_uri` | the credential in the sender's MLS LeafNode |
/// | `notify_room_uri` | the `/notify/{roomId}` path (decision mimid-1wgh.5.15) |
///
/// Before calling [`ReceivedFrank::verify`], the caller must check that
/// `franking_agent.credential` names the hub's domain (§5.4.1.3).
/// [`mimi_mls::wire`] exposes a credential only as encoded bytes, so this
/// crate cannot (protocol-06 §5.4.1.3; decision mimid-1wgh.5.56).
#[derive(Debug, Clone, Copy)]
pub struct ReceivedFrank<'a> {
    /// The hub's frank.
    pub frank: &'a Frank,
    /// The hub acceptance time from the FanoutMessage.
    pub accepted_timestamp: u64,
    /// The sender's `franking_tag` from the frank_aad component.
    pub franking_tag: &'a [u8; 32],
    /// The ciphersuite of the MLS group in use.
    pub group_cipher_suite: CipherSuite,
    /// The group's franking_agent component, its credential already
    /// checked by the caller.
    pub franking_agent: &'a FrankingAgentData,
    /// The MIMI content salt.
    pub salt: &'a [u8; 16],
    /// The whole MLS application_data (decision mimid-1wgh.5.29).
    pub application_data: &'a [u8],
    /// The sender URI asserted in the MIMI content extensions map.
    pub content_sender_uri: &'a IdentifierUri,
    /// The room URI asserted in the MIMI content extensions map.
    pub content_room_uri: &'a IdentifierUri,
    /// The sender URI from the sender's LeafNode credential.
    pub authenticated_sender_uri: &'a IdentifierUri,
    /// The room URI from the `/notify/{roomId}` path.
    pub notify_room_uri: &'a IdentifierUri,
}

impl ReceivedFrank<'_> {
    /// Runs the receiver checks of protocol-06 §5.4.1.3, in its order, and
    /// returns the [`ServerFrankingContext`] the receiver stores with the
    /// message alongside the frank.
    ///
    /// 1. `franking_signature_ciphersuite` equals `group_cipher_suite`;
    ///    a mismatch is an error (decision mimid-1wgh.5.57).
    /// 2. `franking_integrity_signature` verifies under
    ///    `franking_agent.franking_signature_key`, over a TBS whose context
    ///    holds `content_sender_uri`, `content_room_uri` and
    ///    `accepted_timestamp` ([`Frank::verify_integrity`]).
    /// 3. `franking_tag` is the HMAC of `application_data` under `salt`
    ///    ([`verify_franking_tag`]).
    /// 4. `content_sender_uri` equals `authenticated_sender_uri`.
    /// 5. `content_room_uri` equals `notify_room_uri`.
    ///
    /// The context is built from the content URIs, and URIs are compared
    /// byte for byte, without normalization (decision mimid-1wgh.5.58).
    ///
    /// A receiver cannot check `server_frank`: that needs the hub's
    /// [`HubKey`], so only the hub can, when it validates an abuse report
    /// ([`verify_server_frank`], §5.9). The franking_agent credential is the
    /// caller's to check (see [`ReceivedFrank`]).
    ///
    /// # Errors
    ///
    /// For the first check that fails: [`Error::FrankCipherSuiteMismatch`];
    /// [`Error::UnsupportedCipherSuite`], [`Error::Decoding`],
    /// [`Error::Encoding`] or [`Error::Label`] as for
    /// [`Frank::verify_integrity`]; [`Error::FrankingTagMismatch`];
    /// [`Error::FrankSenderMismatch`]; [`Error::FrankRoomMismatch`].
    pub fn verify(&self) -> Result<ServerFrankingContext, Error> {
        let frank_suite = self.frank.franking_signature_ciphersuite;
        // protocol-06 §5.4.1.3; decision mimid-1wgh.5.57
        if frank_suite != self.group_cipher_suite {
            return Err(Error::FrankCipherSuiteMismatch {
                frank: frank_suite.into(),
                group: self.group_cipher_suite.into(),
            });
        }
        // protocol-06 §5.4.1.3; decision mimid-1wgh.5.58 (content URIs)
        let context = ServerFrankingContext {
            sender_uri: self.content_sender_uri.clone(),
            room_uri: self.content_room_uri.clone(),
            accepted_timestamp: self.accepted_timestamp,
        };
        self.frank
            .verify_integrity(&self.franking_agent.franking_signature_key, &context)?;
        verify_franking_tag(self.salt, self.application_data, self.franking_tag)?;
        // Byte-exact URI comparison: protocol-06 §5.4.1.3; decision
        // mimid-1wgh.5.58
        if self.content_sender_uri != self.authenticated_sender_uri {
            return Err(Error::FrankSenderMismatch);
        }
        if self.content_room_uri != self.notify_room_uri {
            return Err(Error::FrankRoomMismatch);
        }
        Ok(context)
    }
}
