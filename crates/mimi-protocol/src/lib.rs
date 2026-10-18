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
//!   [`NotifyRequest`]) and [`Frank`], the groupInfo endpoint
//!   ([`GroupInfoRequest`], [`GroupInfoResponse`], with
//!   [`encrypt_group_info`] and [`decrypt_group_info`]), and the franking
//!   HMACs
//!   ([`franking_tag`], [`server_frank`] over a [`ServerFrankingContext`],
//!   with constant-time [`verify_franking_tag`] and
//!   [`verify_server_frank`]), the franking_agent component
//!   ([`FrankingAgentData`]), the franking_integrity_signature
//!   ([`FrankingIntegrityTbs::sign`], [`Frank::verify_integrity`]), the
//!   §5.4.1.3 receiver checks ([`ReceivedFrank::verify`]), and the
//!   reportAbuse body ([`AbuseReport`], [`AbusiveMessage`],
//!   [`AbuseType`]).
//! - Franking takes the salt, sender URI and room URI as inputs: the caller
//!   extracts them from the MIMI content. [`ServerFrankingContext`] URIs
//!   are [`IdentifierUri`]s, so a non-ASCII URI must arrive percent-encoded.
//!   [`HubKey`] redacts `Debug` but is not zeroized on drop (protocol-06
//!   §5.4.1.2; decision mimid-1wgh.5.53). The franking_integrity_signature
//!   supports ciphersuite 1 only, like groupInfo signing.
//! - [`ReceivedFrank::verify`] does not check that the franking_agent
//!   credential names the hub's domain, which §5.4.1.3 requires: credentials
//!   are only encoded bytes here, so the caller checks it (decision
//!   mimid-1wgh.5.56). A frank whose ciphersuite is not the group's is an
//!   error (decision mimid-1wgh.5.57). A receiver cannot check
//!   `server_frank` at all; only the hub, holding the [`HubKey`], can. The
//!   signed context uses the content URIs, compared byte for byte, without
//!   normalization (decision mimid-1wgh.5.58).
//! - [`AbuseReport`] codecs check the wire form only. Validating an
//!   [`AbusiveMessage`] is left to the hub, composing the franking
//!   functions above. An empty [`AbuseReport::reporting_user`] means absent
//!   (decision mimid-1wgh.5.59). [`AbuseReport::note`] is opaque bytes, not
//!   checked to be UTF-8 (decision mimid-1wgh.5.60), and any [`AbuseType`]
//!   value is accepted (decision mimid-1wgh.5.32).
//! - MLS structures come from [`mimi_mls::wire`], which cannot decode a
//!   SemiPrivateMessage. A [`HandshakeBundle`] or [`FanoutMessage`] whose
//!   handshake is a SemiPrivateMessage, which §5.3 and §5.5 allow, is
//!   rejected; only PublicMessage handshakes are accepted (decision
//!   mimid-1wgh.4.12). `moreProposals` and `externalProposals` entries
//!   must be PublicMessage proposals (decision mimid-1wgh.5.51).
//! - groupInfo signing, verification and encryption support ciphersuite 1
//!   only, the one [`mimi_mls::label`] implements; other suites decode but
//!   [`GroupInfoRequest::verify`], [`GroupInfoSuccess::verify`] and the
//!   `sign` methods return [`Error::UnsupportedCipherSuite`]. HPKE for
//!   `encrypted_groupinfo_and_tree` always uses suite 1, since protocol-06
//!   §5.6 ties `cipher_suite` only to signing (decision mimid-1wgh.5.55;
//!   wg mimid-1wgh.37.59). Each `verify` checks the
//!   signature against the key carried in the same message: binding the
//!   requester's key to its credential, checking that `hub_sender` is the
//!   room's hub and that `room_id` is the room asked for, and authorizing
//!   the request are left to the caller. The `groupInfo` inside a
//!   [`GroupInfoRatchetTreeTbe`] is not checked to lack a ratchet_tree
//!   extension, and [`PendingProposal`] entries must be PublicMessage
//!   proposals, as for `moreProposals` (decision mimid-1wgh.5.54).
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

mod abuse;
mod component;
mod directory;
mod frank;
mod group_info;
mod identifier_uri;
mod notify;
mod update;
mod uri_template;
mod utf8_string;

pub use abuse::{AbuseReport, AbuseType, AbusiveMessage};
pub use component::{
    ParticipantListData, ParticipantListUpdate, RichDescription, RoomMetaData, RoomMetaUpdate, Uri,
    UserRolePair, UserindexRolePair,
};
pub use directory::Directory;
pub use frank::{
    Frank, FrankAad, FrankingAgentData, FrankingAgentUpdate, FrankingIntegrityTbs, HubKey,
    ReceivedFrank, ServerFrankingContext, franking_tag, server_frank, verify_franking_tag,
    verify_server_frank,
};
pub use group_info::{
    GroupInfoCode, GroupInfoRatchetTreeTbe, GroupInfoRequest, GroupInfoRequestTbs,
    GroupInfoResponse, GroupInfoResponseTbs, GroupInfoSuccess, PendingProposal, decrypt_group_info,
    encrypt_group_info,
};
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
    /// `franking_signature_key` (§10.2), the GroupContext component §5.4.1
    /// calls `franking_agent`, carrying
    /// [`FrankingAgentData`](crate::FrankingAgentData) (decision
    /// mimid-1wgh.4.18).
    pub const FRANKING_AGENT: u16 = 0x0021;
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

/// Errors from constructing or checking protocol-06 values.
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
    /// A `franking_tag` did not match its salt and application_data
    /// (§5.4.1.3).
    #[error("franking_tag does not match")]
    FrankingTagMismatch,
    /// A `server_frank` did not match its hub key, `franking_tag` and
    /// context (§5.4.1.2).
    #[error("server_frank does not match")]
    ServerFrankMismatch,
    /// A frank's `franking_signature_ciphersuite` is not the group's
    /// ciphersuite (§5.4.1.3; decision mimid-1wgh.5.57).
    #[error("frank ciphersuite {frank:#06x} is not the group's {group:#06x}")]
    FrankCipherSuiteMismatch {
        /// The ciphersuite named in the frank.
        frank: u16,
        /// The group's ciphersuite.
        group: u16,
    },
    /// The sender URI in a franked message's content is not the sender's
    /// authenticated identity (§5.4.1.3).
    #[error("franked sender URI does not match the authenticated sender")]
    FrankSenderMismatch,
    /// The room URI in a franked message's content is not the room it
    /// arrived for (§5.4.1.3).
    #[error("franked room URI does not match the room")]
    FrankRoomMismatch,
    /// A value could not be TLS-encoded.
    #[error("TLS encoding failed")]
    Encoding(#[source] tls_codec::Error),
    /// A key, ciphertext or decrypted plaintext could not be TLS-decoded.
    #[error("TLS decoding failed")]
    Decoding(#[source] tls_codec::Error),
    /// Signing, signature verification, encryption or decryption failed
    /// (RFC 9420 §5.1.2, §5.1.3).
    #[error("labeled signature or encryption failed")]
    Label(#[source] mimi_mls::label::Error),
    /// A signature was requested or checked under a ciphersuite other than
    /// 1, the only one supported (decision mimid-1wgh.23).
    #[error("ciphersuite {cipher_suite:#06x} is not supported")]
    UnsupportedCipherSuite {
        /// The ciphersuite named in the message.
        cipher_suite: u16,
    },
}
