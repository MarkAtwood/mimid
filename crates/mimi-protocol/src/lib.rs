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
//!   [`Utf8String`]), the directory ([`Directory`], [`UriTemplate`]), the
//!   keyMaterial endpoint ([`KeyMaterialRequest`], with
//!   [`KeyMaterialRequestTbs::sign`] and [`KeyMaterialRequest::verify`],
//!   and [`KeyMaterialResponse`]), and the codecs for the frank_aad ([`FrankAad`]), participant_list
//!   ([`ParticipantListData`], [`ParticipantListUpdate`]) and room_metadata
//!   ([`RoomMetaData`]) components, the update endpoint ([`UpdateRequest`],
//!   [`UpdateRoomResponse`]), the notify endpoint ([`FanoutMessage`],
//!   [`NotifyRequest`]) and [`Frank`], the submitMessage endpoint
//!   ([`SubmitMessageRequest`], [`SubmitMessageResponse`]), the groupInfo endpoint
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
//!   [`AbuseType`]), and the requestConsent and updateConsent body
//!   ([`ConsentEntry`], [`ConsentOperation`], [`ConsentScope`]), and the
//!   identifierQuery bodies ([`IdentifierRequest`], [`IdentifierResponse`]).
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
//! - keyMaterial signing and verification use suite 1's signature scheme
//!   (Ed25519) and require suite 1 in `acceptableCiphersuites`, because
//!   protocol-06 §5.2 names no suite for the signature (decision
//!   mimid-1wgh.5.61). An empty `acceptableCiphersuites` is rejected
//!   (decision mimid-1wgh.5.62). [`KeyMaterialRequest::verify`]
//!   checks the signature against the key in the same request only:
//!   binding it to the credential and the requesting provider, matching
//!   `targetUser` to the request path, and checking consent are left to the
//!   caller. An empty [`KeyMaterialRequestTbs::room_id`] means absent
//!   (decision mimid-1wgh.5.27). [`KeyMaterialResponse`] checks `clients`
//!   against `userStatus` (decision mimid-1wgh.5.63), and a
//!   `keyMaterialExhausted` client carries no fields (decision
//!   mimid-1wgh.5.64). It does not check that a KeyPackage uses an acceptable
//!   ciphersuite, meets `requiredCapabilities`, is unexpired or was never
//!   handed out before: those need the request, a clock or provider state.
//! - [`ConsentEntry`] codecs check the wire form only. They do not check
//!   that the operation suits the endpoint (`request` or `cancel` for
//!   requestConsent, `grant` or `revoke` for updateConsent), that the URIs
//!   are in the sending and receiving providers' domains, or that a
//!   `cancel` matches an earlier request's [`ConsentScope`]: §5.7 leaves
//!   those to the receiving server. An empty `requesterUri` or `targetUri`
//!   (decision mimid-1wgh.5.68) and a present but empty `roomId` (decision
//!   mimid-1wgh.5.69) are rejected. Granted KeyPackages are
//!   not checked beyond their wire form.
//! - [`IdentifierRequest`] and [`IdentifierResponse`] codecs check the wire
//!   form only: matching a query against profiles and applying search
//!   policy are the target provider's job. `searchValue`, `claimName`,
//!   `propertyName` and `fieldValue` are opaque bytes, not checked to be
//!   UTF-8 (as decision mimid-1wgh.5.60), and an empty `query_elements`
//!   decodes (decision mimid-1wgh.5.73). [`IdentifierResponse`] rejects an
//!   empty `uri` entry or `stableUri` (decision mimid-1wgh.5.72) and a
//!   `responseCode` that contradicts the results (decision
//!   mimid-1wgh.5.71); it does not
//!   check how `uri` relates to the profiles' `stableUri`s.
//! - [`FanoutMessage`] arms follow decision mimid-1wgh.5.24: an application
//!   message must be a PrivateMessage, so a PublicMessage application
//!   message or a PrivateMessage proposal or commit is rejected.
//! - [`SubmitMessageRequest`] requires a PrivateMessage carrying an
//!   application message and a non-empty `sendingUri` (decision
//!   mimid-1wgh.5.65); it does not check
//!   that the sender is a participant of the room. The spec's `case
//!   success` is read as `accepted` (decision mimid-1wgh.5.25). Its
//!   `protocol` byte is on the wire (decision mimid-1wgh.5.66), and
//!   `notAllowed` carries no fields (decision mimid-1wgh.5.67).
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
mod consent;
mod directory;
mod frank;
mod group_info;
mod identifier;
mod identifier_uri;
mod key_material;
mod notify;
mod submit;
mod update;
mod uri_template;
mod utf8_string;

pub use abuse::{AbuseReport, AbuseType, AbusiveMessage};
pub use component::{
    ParticipantListData, ParticipantListUpdate, RichDescription, RoomMetaData, RoomMetaUpdate, Uri,
    UserRolePair, UserindexRolePair,
};
pub use consent::{ConsentEntry, ConsentOperation, ConsentScope};
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
pub use identifier::{
    FieldSource, IdentifierQueryCode, IdentifierRequest, IdentifierResponse, ProfileField,
    QueryElement, QuerySearch, SearchIdentifierType, UserProfile,
};
pub use identifier_uri::IdentifierUri;
pub use key_material::{
    ClientKeyMaterial, KeyMaterialClientCode, KeyMaterialRequest, KeyMaterialRequestTbs,
    KeyMaterialResponse, KeyMaterialUserCode,
};
pub use notify::{FanoutEvent, FanoutMessage, NotifyRequest};
pub use serde_json;
pub use submit::{SubmitMessageRequest, SubmitMessageResponse, SubmitResponseCode, SubmitResult};
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
    /// A [`KeyMaterialRequestTbs`]'s `acceptableCiphersuites` list was
    /// empty; protocol-06 §5.2 requires a non-empty list.
    #[error("acceptableCiphersuites is empty")]
    EmptyCipherSuites,
    /// A [`KeyMaterialResponse`]'s `clients` list contradicts its
    /// `userStatus` (protocol-06 §5.2).
    #[error("clients list does not match userStatus {user_status:?}")]
    KeyMaterialClientsMismatch {
        /// The response's `userStatus`.
        user_status: KeyMaterialUserCode,
    },
    /// A [`ConsentEntry`] or [`ConsentScope`] had an empty `requesterUri`
    /// or `targetUri` (protocol-06 §5.7).
    #[error("consent requesterUri or targetUri is empty")]
    EmptyConsentUri,
    /// A [`ConsentEntry`] or [`ConsentScope`] had a `roomId` that is present
    /// but empty, a non-canonical way to say "any room" (protocol-06 §5.7).
    #[error("consent roomId is present but empty")]
    EmptyConsentRoomId,
    /// A [`ConsentEntry`] other than `grant` carried KeyPackages, which only
    /// the `grant` arm has (protocol-06 §5.7).
    #[error("{consent_operation:?} consent entry carries KeyPackages")]
    ClientKeyPackagesWithoutGrant {
        /// The entry's `consentOperation`.
        consent_operation: ConsentOperation,
    },
    /// An [`IdentifierResponse`] `uri` entry or a [`UserProfile`]
    /// `stableUri` was empty (protocol-06 §5.8).
    #[error("identifierQuery uri or stableUri is empty")]
    EmptyIdentifierQueryUri,
    /// An [`IdentifierResponse`]'s results contradict its `responseCode`:
    /// `success` needs at least one result and other codes none
    /// (protocol-06 §5.8).
    #[error("identifierQuery results do not match responseCode {response_code:?}")]
    IdentifierResultsMismatch {
        /// The response's `responseCode`.
        response_code: IdentifierQueryCode,
    },
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
