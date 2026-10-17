//! Codecs and policy evaluation for draft-ietf-mimi-room-policy-04.
//!
//! This crate is synchronous and pure, and does not depend on OpenMLS.
//! Every type is encoded in the TLS presentation language (RFC 8446 §3)
//! with MLS variable-length vectors (RFC 9420 §2.1.2), via [`tls_codec`].
//!
//! Decode with [`tls_codec::Deserialize::tls_deserialize_exact`], which
//! rejects trailing bytes. Decoding also rejects non-minimal varint
//! lengths, lengths above [`MAX_VECTOR_LENGTH`], [`Bool`] values other than
//! 0 and 1, and invalid UTF-8 in fields the drafts define as text.
//!
//! # Limitations
//!
//! - Only the primitives are implemented so far: [`Bool`], [`Uri`],
//!   [`MediaType`] and the [`component_id`] constants. The policy component
//!   codecs and evaluation are not yet present.
//! - [`Uri`] contents and the [`MediaType`] text fields are checked only for
//!   valid UTF-8, not for RFC 3986 or RFC 6838 syntax.
//! - The component IDs are the draft's suggested values; IANA has not
//!   assigned them.
//! - Only the `std::io::Read` decoding path ([`tls_codec::Deserialize`]) is
//!   provided. [`tls_codec::DeserializeBytes`] is deliberately not
//!   implemented, because tls_codec 0.5.0 does not enforce
//!   [`MAX_VECTOR_LENGTH`] on that path.

#![forbid(unsafe_code)]

pub use tls_codec;

use tls_codec::{TlsDeserialize, TlsSerialize, TlsSize};

/// The largest vector length, in bytes, that decoding accepts.
///
/// RFC 9420 §2.1.2 limits variable-length vector lengths to 30 bits. The
/// `mls` feature of [`tls_codec`] enforces this when decoding, and rejects
/// any longer vector with [`tls_codec::Error::InvalidVectorLength`].
pub const MAX_VECTOR_LENGTH: usize = (1 << 30) - 1;

/// The TLS `bool` enum of room-policy-04 §5 and Appendix B.
///
/// It is encoded as one byte. Decoding rejects every value other than 0 and
/// 1 with [`tls_codec::Error::UnknownValue`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, TlsSize, TlsSerialize, TlsDeserialize)]
#[repr(u8)]
pub enum Bool {
    /// `false(0)`.
    False = 0,
    /// `true(1)`.
    True = 1,
}

impl From<bool> for Bool {
    fn from(value: bool) -> Self {
        if value { Self::True } else { Self::False }
    }
}

impl From<Bool> for bool {
    fn from(value: Bool) -> Self {
        value == Bool::True
    }
}

/// The `Uri` struct of room-policy-04 Appendix B.
///
/// A field written as `Uri x<V>` is a vector of this struct, so each entry
/// carries its own length prefix (decision mimid-1wgh.3.15). A zero-length
/// `uri` is accepted, because it means "absent" (decision mimid-1wgh.3.18).
#[derive(Debug, Clone, PartialEq, Eq, Hash, TlsSize, TlsSerialize, TlsDeserialize)]
pub struct Uri {
    /// `opaque uri<V>`: "a valid Uniform Resource Identifier (URI)".
    ///
    /// Every valid URI is ASCII, so decoding rejects invalid UTF-8.
    pub uri: String,
}

/// The `Parameter` struct of mls-extensions-10 §6.2.2.
///
/// A [`MediaType`] carries a list of these.
#[derive(Debug, Clone, PartialEq, Eq, Hash, TlsSize, TlsSerialize, TlsDeserialize)]
pub struct Parameter {
    /// `opaque parameter_name<V>`. Decoding rejects invalid UTF-8.
    pub parameter_name: String,
    /// `opaque parameter_value<V>`, without the quotation marks of an RFC
    /// 2045 quoted-string or the first `\` of a quoted-pair. Decoding
    /// rejects invalid UTF-8.
    pub parameter_value: String,
}

/// The `MediaType` struct of mls-extensions-10 §6.2.2.
///
/// room-policy-04 §6.4 and §7.1 use it. mimi-mls has its own copy, and the
/// hub converts between the two, so that this crate stays free of MLS
/// dependencies (decision mimid-1wgh.3.11).
#[derive(Debug, Clone, PartialEq, Eq, Hash, TlsSize, TlsSerialize, TlsDeserialize)]
pub struct MediaType {
    /// `opaque type<V>`: an IANA top-level media type, a `/` character and
    /// the IANA media subtype. Decoding rejects invalid UTF-8.
    pub r#type: String,
    /// `Parameter parameters<V>`: zero or more parameters defined for the
    /// subtype.
    pub parameters: Vec<Parameter>,
}

/// MLS component IDs registered by room-policy-04 §10.1.
///
/// The draft leaves these as TBD0 to TBD12. These are its suggested values
/// (decision mimid-1wgh.3.27).
pub mod component_id {
    /// `uint16 ComponentID` of mls-extensions-10.
    pub type ComponentID = u16;

    /// `mls_operational_policy` (room-policy-04 §10.1.1, §7).
    pub const MLS_OPERATIONAL_POLICY: ComponentID = 0x0024;
    /// `roles_list` (room-policy-04 §10.1.2, §3).
    pub const ROLES_LIST: ComponentID = 0x0025;
    /// `preauth_list` (room-policy-04 §10.1.3, §4).
    pub const PREAUTH_LIST: ComponentID = 0x0026;
    /// `base_room_policy` (room-policy-04 §10.1.4, §5).
    pub const BASE_ROOM_POLICY: ComponentID = 0x0027;
    /// `status_notification_policy` (room-policy-04 §10.1.5, §6.1).
    pub const STATUS_NOTIFICATION_POLICY: ComponentID = 0x0028;
    /// `join_link_policy` (room-policy-04 §10.1.6, §6.2).
    pub const JOIN_LINK_POLICY: ComponentID = 0x0029;
    /// `join_links` (room-policy-04 §10.1.7, §6.2).
    pub const JOIN_LINKS: ComponentID = 0x002A;
    /// `link_preview_policy` (room-policy-04 §10.1.8, §6.3).
    pub const LINK_PREVIEW_POLICY: ComponentID = 0x002B;
    /// `asset_policy` (room-policy-04 §10.1.9, §6.4).
    pub const ASSET_POLICY: ComponentID = 0x002C;
    /// `logging_policy` (room-policy-04 §10.1.10, §6.5).
    pub const LOGGING_POLICY: ComponentID = 0x002D;
    /// `chat_history_policy` (room-policy-04 §10.1.11, §6.6).
    pub const CHAT_HISTORY_POLICY: ComponentID = 0x002E;
    /// `bot_policy` (room-policy-04 §10.1.12, §6.7).
    pub const BOT_POLICY: ComponentID = 0x002F;
    /// `message_expiration_policy` (room-policy-04 §10.1.13, §6.8).
    pub const MESSAGE_EXPIRATION_POLICY: ComponentID = 0x0030;
}
