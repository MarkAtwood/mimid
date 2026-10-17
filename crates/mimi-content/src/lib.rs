//! MIMI message content format for mimid.
//!
//! Implements draft-ietf-mimi-content-09: the CBOR `mimiContent` structure
//! (media type `application/mimi-content`) and its MessageId derivation.
//! The crate is synchronous and pure. It does no I/O and no encryption.
//!
//! # Limitations
//!
//! - This crate is a scaffold. It defines no types or codec yet.
//! - It will never encrypt or decrypt external parts. Attachment encryption
//!   lives elsewhere in mimid.

#![forbid(unsafe_code)]
