//! The `did_webvh` MLS credential of draft-atwood-mls-didwebvh-credential-00
//! ("User-Controlled Device Authorization for MLS using did:webvh
//! Credentials"), without an MLS library.
//!
//! This crate is synchronous and pure, does no I/O and never reads a clock.
//! It provides:
//!
//! - [`DidWebvhCredential`]: the `DIDWebVHCredential` structure, with the
//!   draft's 1,048,576-byte limits on `did_log` and `witness_file`;
//! - [`verify_credential`]: §Log Verification and §did:webvh Profile, giving
//!   a [`VerifiedLog`];
//! - [`DidWebvhHeads`]: the `did_webvh_heads` GroupContext extension;
//! - [`rules`]: §Binding to the LeafNode, §Expected Heads, §Rules, the
//!   Welcome checks and §Successor Credentials, over abstract leaves;
//! - [`CodePoints`]: the credential and extension types, which IANA has not
//!   assigned, as settings;
//! - [`controller`]: the controller side, writing a log whose DID documents
//!   list the user's devices, with pre-rotation.
//!
//! `mimi-mls` applies all of this to OpenMLS groups.
//!
//! The did:webvh method itself is "The did:webvh DID Method v1.0"
//! (<https://identity.foundation/didwebvh/v1.0/>), `spec-v1.0/` of
//! <https://github.com/decentralized-identity/didwebvh> at commit 91f3cba,
//! the commit the draft cites. `spec-v1.0/` is byte-identical at deef9cf
//! and at main bf3d9b4 (2026-11-02), the copy in `~/PROJECT/IETF/specs`.
//!
//! # Limitations
//!
//! - The did:webvh Read (Resolve) steps come from
//!   [`jmap_did_types::verify_webvh_log`] (decision mimid-1wgh.4.81.7).
//!   Where that verifier is stricter or looser than v1.0, so is this crate.
//!   It applies IDNA processing to the domain, which the profile's ASCII
//!   rule makes a no-op except for `xn--` labels: a malformed `xn--` label
//!   is refused, which an implementation doing no IDNA processing at all
//!   would accept.
//! - Integers above 2^53 - 1 in a log entry are refused; non-integer
//!   numbers with more precision than a double holds are not detected
//!   (decision mimid-1wgh.4.81.9). JSON nesting deeper than 128 levels is
//!   refused (serde_json's limit; the draft sets none).
//! - The ASCII domain rule leaves no way to write a port (`%3A`) in the
//!   DID (decision mimid-1wgh.4.81.12).
//! - An Ed25519 key's 32 bytes are not checked to be a valid curve point
//!   when building `authorized_keys`; a leaf with such a key fails MLS
//!   signature verification anyway (decision mimid-1wgh.4.81.10).
//! - [`DidWebvhHeads`] decoding is capped at [`heads::MAX_HEADS`] entries,
//!   a limit the draft does not set (decision mimid-1wgh.4.81.13).
//! - In an MLS `Credential`, the structure is carried inside an
//!   `opaque<V>`, which the draft does not say (decision mimid-1wgh.4.81.8).
//! - [`controller`] writes no witness proofs and no `witness` parameter, and
//!   its JCS handles only integers within ±(2^53 - 1). It does not publish
//!   the log: [`controller::DidLog::did_log`] gives the bytes to publish.

#![forbid(unsafe_code)]

mod config;
pub mod controller;
mod credential;
pub mod heads;
mod json;
mod keys;
pub mod rules;
mod tls;
mod verify;

pub use config::{CodePointError, CodePoints};
pub use credential::{
    CredentialError, DidWebvhCredential, MAX_DID_LOG_LENGTH, MAX_WITNESS_FILE_LENGTH,
};
pub use heads::{DidWebvhHead, DidWebvhHeads};
pub use json::{IJsonError, MAX_SAFE_INTEGER, check_i_json};
pub use keys::{PublicKey, authorized_keys, decode_ed25519_multikey, ed25519_multikey};
pub use tls::{DecodeError, EncodeError};
pub use verify::{LogError, VerifiedLog, verify_credential};
