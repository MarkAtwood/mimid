//! MIMI message content format for mimid.
//!
//! Implements draft-ietf-mimi-content-09: the CBOR `mimiContent` structure
//! (media type `application/mimi-content`) and its MessageId derivation.
//! The crate is synchronous and pure. It does no I/O and no encryption.
//!
//! Build a [`MimiContent`] and call [`MimiContent::encode`] to get its
//! deterministic CBOR encoding (§6.1). [`MimiContent::decode`] reverses it,
//! accepting only deterministic encodings (decision mimid-1wgh.2.9).
//!
//! # Limitations
//!
//! - Only the registered extensions `senderUri` (1) and `roomUri` (2) can
//!   be represented. Unknown extension keys cannot be built or encoded,
//!   and the decoder rejects a message that carries one
//!   ([`DecodeError::UnsupportedExtension`]), even though such a message is
//!   valid.
//! - MessageId values are carried, not computed.
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

pub use content::{
    Disposition, Expiration, Extensions, ExternalPart, MessageId, MimiContent, NestedPart, Part,
    PartSemantics,
};
pub use decode::DecodeError;
pub use encode::{
    EncodeError, MAX_NESTING_DEPTH, MAX_PARTS, MAX_TOPIC_ID_LEN, MIN_MULTIPART_PARTS,
};
/// Re-exported because [`EncodeError::Cbor`] carries a minicbor error.
pub use minicbor;
