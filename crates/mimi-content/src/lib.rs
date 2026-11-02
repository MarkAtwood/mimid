//! MIMI message content format for mimid.
//!
//! Implements draft-ietf-mimi-content-10: the CBOR `mimiContent` structure
//! (media type `application/mimi-content`) and its MessageId derivation.
//! The crate is synchronous and pure. It does no I/O and no encryption.
//!
//! Build a [`MimiContent`] and call [`MimiContent::encode`] to get its
//! deterministic CBOR encoding (§6.1). [`MimiContent::decode`] reverses it,
//! accepting only deterministic encodings (decision mimid-1wgh.2.9).
//!
//! # Limitations
//!
//! - Only the registered extensions `senderUri` (1) and `roomUri` (2) are
//!   interpreted. Every other extension is kept as an [`ExtensionKey`] and
//!   the exact bytes of its value ([`RawValue`]), checked only against the
//!   generic rules of §6.
//! - Extension values have no size limit of their own (decision
//!   mimid-1wgh.2.15); they are bounded only by the input and by
//!   [`MAX_EXTENSION_DEPTH`].
//! - [`MessageId::compute`] supports only SHA-256 (hash algorithm ID 1),
//!   the §3.3 default. It trusts the caller to pass the authenticated
//!   sender and room URIs and the salt of the hashed message, and does not
//!   compare them with the `senderUri` and `roomUri` extensions
//!   (decision mimid-1wgh.2.10).
//! - §3.3 requires a receiver to reject a message whose `senderUri` or
//!   `roomUri` extension is present but differs from the URI of the
//!   enclosing protocol. The codec does not know those URIs, so it does not
//!   check this; each receive path must, comparing byte-exact (decision
//!   mimid-1wgh.5.58). mimid's paths that do: franking verification
//!   (mimi-protocol `frank`) and hub abuse reports, which go through it
//!   (bead mimid-1wgh.2.25).
//! - The encoder and decoder enforce the structural rules and limits of
//!   §4.4, §6.3 and §9.1 (MultiPart part count, nesting depth, total parts,
//!   topicId length). The other §9.1 checks (message IDs, timestamps,
//!   expiry sanity, body size) need context the codec lacks and are left
//!   to the caller (decision mimid-1wgh.2.19). Neither checks that
//!   `language` holds RFC 5646 tags, that `contentType` is a valid media
//!   type, or that `cid:` part references point at existing parts.
//! - Text fields are checked only for valid UTF-8 (§6.2). The decoder
//!   passes NUL, bidi controls and zero-width characters through
//!   unchanged; rendering them safely is the caller's job.
//! - It will never encrypt or decrypt external parts. Attachment encryption
//!   lives elsewhere in mimid.

#![forbid(unsafe_code)]

mod content;
mod decode;
mod encode;
mod extension;
mod message_id;

pub use content::{
    Disposition, Expiration, Extensions, ExternalPart, MessageId, MimiContent, NestedPart, Part,
    PartSemantics,
};
pub use decode::DecodeError;
pub use encode::{
    EncodeError, MAX_NESTING_DEPTH, MAX_PARTS, MAX_TOPIC_ID_LEN, MIN_MULTIPART_PARTS,
};
pub use extension::{
    ExtensionKey, MAX_EXTENSION_DEPTH, MAX_EXTENSION_KEY_LEN, MAX_INTEGER_KEY, RawValue,
};
pub use message_id::{MAX_MESSAGE_ID_URI_LEN, MessageIdError};
/// Re-exported because [`EncodeError::Cbor`] carries a minicbor error.
pub use minicbor;
