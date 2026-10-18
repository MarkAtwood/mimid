//! Wire types for draft-ietf-mimi-protocol-06.
//!
//! The directory document (§5.1) is JSON: [`Directory`] implements
//! [`serde::Serialize`] and [`serde::Deserialize`] for use with
//! [`serde_json`], and its [`UriTemplate`] values expand into endpoint URLs.
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
//! - Implemented so far: the primitives ([`Protocol`], [`IdentifierUri`],
//!   [`Utf8String`]), the directory ([`Directory`], [`UriTemplate`]), and
//!   the codecs for the frank_aad ([`FrankAad`]), participant_list
//!   ([`ParticipantListData`], [`ParticipantListUpdate`]) and room_metadata
//!   ([`RoomMetaData`]) components, the update endpoint ([`UpdateRequest`],
//!   [`UpdateRoomResponse`]), the notify endpoint ([`FanoutMessage`],
//!   [`NotifyRequest`]) and [`Frank`].
//! - MLS structures come from [`mimi_mls::wire`], which cannot decode a
//!   SemiPrivateMessage. A [`HandshakeBundle`] or [`FanoutMessage`] whose
//!   handshake is a SemiPrivateMessage, which §5.3 and §5.5 allow, is
//!   rejected; only PublicMessage handshakes are accepted (decision
//!   mimid-1wgh.4.12). `moreProposals` and `externalProposals` entries
//!   must be PublicMessage proposals (decision mimid-1wgh.5.51).
//! - [`FanoutMessage`] arms follow decision mimid-1wgh.5.24: an application
//!   message must be a PrivateMessage, so a PublicMessage application
//!   message or a PrivateMessage proposal or commit is rejected.
//! - Endpoint codecs check the wire form only: no signature, frank, epoch
//!   or policy check happens here, and an empty `moreProposals`,
//!   `externalProposals` or `invalidProposals` list, or an empty `/notify`
//!   body, decodes (decision mimid-1wgh.5.49). [`NotifyRequest::decode`]
//!   rejects an empty `roomId` (decision mimid-1wgh.5.50).
//! - Component codecs check the wire form only. Applying a
//!   [`ParticipantListUpdate`] (index ranges, at most one change per user
//!   per commit) and authorizing any update are left to the caller (task
//!   mimid-1wgh.5.48).
//! - Opaque fields stay opaque: [`UserRolePair::user`] is not checked to be
//!   a URI (decision mimid-1wgh.5.46), and [`RichDescription`]'s fields are
//!   not checked to be UTF-8, a media type or a language tag (decision
//!   mimid-1wgh.5.47). [`RoomMetaData::room_avatar`] is not required to use
//!   `https` (decision mimid-1wgh.5.45). [`Uri`] is [`IdentifierUri`]
//!   (decision mimid-1wgh.5.44).
//! - [`UriTemplate`] supports RFC 6570 level 1 only (`{name}`), the only form
//!   §5.1 uses. Expanding a template that names a variable other than the
//!   one supplied is an error, not an empty expansion as RFC 6570 §3.2.1
//!   specifies (decision mimid-1wgh.5.41).
//! - [`Directory`] does not require `https` URLs (decision mimid-1wgh.34) or
//!   check placeholder names (decision mimid-1wgh.5.42). Templates and
//!   expanded URLs are capped at [`MAX_URL_LEN`] bytes, a limit invented
//!   here, not taken from the spec (decision mimid-1wgh.5.43).
//! - [`IdentifierUri`] checks RFC 3986 `URI` syntax only (decision
//!   mimid-1wgh.36). It does not check that a scheme is registered, that a
//!   host resolves, or anything a specific URI scheme requires.
//! - No per-field length caps beyond RFC 9420's 2^30 - 1 vector limit, which
//!   tls_codec enforces. Callers bound total body size (decision
//!   mimid-1wgh.5.34).

#![forbid(unsafe_code)]

mod component;
mod directory;
mod frank;
mod identifier_uri;
mod notify;
mod update;
mod uri_template;
mod utf8_string;

pub use component::{
    ParticipantListData, ParticipantListUpdate, RichDescription, RoomMetaData, RoomMetaUpdate, Uri,
    UserRolePair, UserindexRolePair,
};
pub use directory::Directory;
pub use frank::{Frank, FrankAad};
pub use identifier_uri::IdentifierUri;
pub use notify::{FanoutEvent, FanoutMessage, NotifyRequest};
pub use serde_json;
pub use tls_codec;
pub use update::{
    GroupInfoOption, HandshakeBundle, UpdateRequest, UpdateResponseCode, UpdateResult,
    UpdateRoomResponse,
};
pub use uri_template::{MAX_URL_LEN, UriTemplate};
pub use utf8_string::Utf8String;

use tls_codec::{TlsDeserialize, TlsSerialize, TlsSize};

/// MLS application component IDs (`uint16 ComponentID`, mls-extensions-10
/// §4.1) registered by protocol-06 §10.
pub mod component_id {
    /// `frank_aad` (§10.1), a Safe AAD component carrying
    /// [`FrankAad`](crate::FrankAad).
    pub const FRANK_AAD: u16 = 0x0020;
    /// `participant_list` (§10.3), a GroupContext component carrying
    /// [`ParticipantListData`](crate::ParticipantListData).
    pub const PARTICIPANT_LIST: u16 = 0x0022;
    /// `room_metadata` (§10.4), a GroupContext component carrying
    /// [`RoomMetaData`](crate::RoomMetaData).
    pub const ROOM_METADATA: u16 = 0x0023;
}

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
    /// An [`IdentifierUri`] was neither empty nor an RFC 3986 `URI`
    /// (decision mimid-1wgh.36).
    #[error("IdentifierUri is not an RFC 3986 URI")]
    InvalidUri,
    /// A [`UriTemplate`] was not an RFC 6570 level 1 template.
    #[error("not an RFC 6570 level 1 URI template (byte {index})")]
    InvalidUriTemplate {
        /// Byte offset of the first character that does not fit.
        index: usize,
    },
    /// A [`UriTemplate`] or an expanded URL exceeded [`MAX_URL_LEN`].
    #[error("URL of {len} bytes exceeds the {MAX_URL_LEN}-byte limit")]
    UrlTooLong {
        /// Length reached, or for an oversized expansion value a lower bound
        /// on it, in bytes.
        len: usize,
    },
    /// [`UriTemplate::expand`] met a variable other than the one supplied.
    #[error("URI template variable {name:?} has no value")]
    UndefinedVariable {
        /// The variable's name as written in the template.
        name: String,
    },
}
