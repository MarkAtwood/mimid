//! Wire types for draft-ietf-mimi-protocol-06.
//!
//! Message bodies use the TLS presentation language (protocol-06 §5), with
//! `<V>` vectors carrying the minimal variable-length integer prefix of
//! RFC 9420 §2.1.2. Types implement [`tls_codec::Serialize`] and
//! [`tls_codec::Deserialize`]; decode a complete body with
//! [`tls_codec::Deserialize::tls_deserialize_exact`], which rejects trailing
//! bytes.
//!
//! Types deliberately do not implement [`tls_codec::DeserializeBytes`]:
//! tls_codec 0.5.0's `VLBytes` implementation of it trips a `debug_assert!`
//! on truncated input, which would let hostile input panic a debug build.
//!
//! # Limitations
//!
//! - There is no authentication between providers. This crate does not
//!   protect against a malicious or impersonated provider, and mimid does not
//!   conform to protocol-06's mutually authenticated TLS transport.
//! - Only the primitives are implemented so far: [`Protocol`],
//!   [`IdentifierUri`] and [`Utf8String`].
//! - [`IdentifierUri`] is opaque bytes; URI syntax is not checked here.
//! - No per-field length caps beyond RFC 9420's 2^30 - 1 vector limit, which
//!   tls_codec enforces. Callers bound total body size (decision
//!   mimid-1wgh.5.34).

#![forbid(unsafe_code)]

mod utf8_string;

pub use tls_codec;
pub use utf8_string::Utf8String;

use tls_codec::{TlsDeserialize, TlsSerialize, TlsSize, VLBytes};

/// End-to-end protocol selector (protocol-06 §5).
///
/// Only `mls10` is defined. Decoding `reserved(0)` or any undefined value
/// fails with [`tls_codec::Error::UnknownValue`], because the `select
/// (protocol)` that follows cannot be parsed for it (decision
/// mimid-1wgh.5.36).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, TlsSerialize, TlsDeserialize, TlsSize)]
#[repr(u8)]
pub enum Protocol {
    /// MLS 1.0 (RFC 9420).
    Mls10 = 1,
}

/// A URI identifying a provider, user, client or room (protocol-06 §5.2).
///
/// Also used where the draft writes `IdentifierURI` or `RoomId`
/// (decision mimid-1wgh.5.19). An empty `uri` is valid on the wire: a
/// zero-length room ID means "absent" (decision mimid-1wgh.5.27). URI
/// syntax is checked by consumers, not here (decision mimid-1wgh.5.35).
#[derive(Debug, Clone, PartialEq, Eq, Hash, TlsSerialize, TlsDeserialize, TlsSize)]
pub struct IdentifierUri {
    /// The URI bytes, uninterpreted.
    pub uri: VLBytes,
}

/// Errors from constructing protocol-06 values.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// A [`Utf8String`] contained U+0000 (protocol-06 §7.6).
    #[error("UTF8String contains a null character at byte {index}")]
    NullInUtf8String {
        /// Byte offset of the first null.
        index: usize,
    },
    /// A [`Utf8String`] was not valid UTF-8 (protocol-06 §7.6).
    #[error("UTF8String is not valid UTF-8")]
    InvalidUtf8(#[source] std::string::FromUtf8Error),
}
