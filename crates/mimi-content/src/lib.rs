//! MIMI message content format for mimid.
//!
//! Implements draft-ietf-mimi-content-09: the CBOR `mimiContent` structure
//! (media type `application/mimi-content`) and its MessageId derivation.
//! The crate is synchronous and pure. It does no I/O and no encryption.
//!
//! Build a [`MimiContent`] and call [`MimiContent::encode`] to get its
//! deterministic CBOR encoding (§6.1).
//!
//! # Limitations
//!
//! - There is no decoder yet.
//! - Only the registered extensions `senderUri` (1) and `roomUri` (2) can
//!   be represented. Unknown extension keys cannot be built or encoded.
//! - MessageId values are carried, not computed.
//! - The encoder enforces the structural rules and limits of §4.4, §6.3
//!   and §9.1 (MultiPart part count, nesting depth, total parts, topicId
//!   length). It does not check that `language` holds RFC 5646 tags, that
//!   `contentType` is a valid media type, or that `cid:` part references
//!   point at existing parts.
//! - It will never encrypt or decrypt external parts. Attachment encryption
//!   lives elsewhere in mimid.

#![forbid(unsafe_code)]

mod content;
mod encode;

pub use content::{
    Disposition, Expiration, Extensions, ExternalPart, MessageId, MimiContent, NestedPart, Part,
    PartSemantics,
};
pub use encode::{
    EncodeError, MAX_NESTING_DEPTH, MAX_PARTS, MAX_TOPIC_ID_LEN, MIN_MULTIPART_PARTS,
};
/// Re-exported because [`EncodeError::Cbor`] carries a minicbor error.
pub use minicbor;
