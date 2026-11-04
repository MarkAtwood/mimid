//! The participant_list (protocol-07 §7.5) and room_metadata (§7.6) MLS
//! application components.
//!
//! These are the `data` of a `ComponentData` entry in the GroupContext
//! `app_data_dictionary` extension (mls-extensions-10 §4.6), and the `update`
//! of an `AppDataUpdate` proposal (§4.7), under the component IDs in
//! [`crate::component_id`].

use tls_codec::{TlsDeserialize, TlsSerialize, TlsSize};

use crate::{IdentifierUri, Utf8String};

/// `struct { opaque user<V>; uint32 role_index; } UserRolePair;`
/// (protocol-07 §7.5).
///
/// `user` is opaque on the wire, as the spec defines it. It is not checked
/// to be a URI (protocol-07 §7.5; decision mimid-1wgh.5.46).
#[derive(Debug, Clone, PartialEq, Eq, Hash, TlsSerialize, TlsDeserialize, TlsSize)]
pub struct UserRolePair {
    /// The user's identifier, the same for all of that user's clients.
    pub user: Vec<u8>,
    /// The user's role (mimi-room-policy-04).
    pub role_index: u32,
}

/// `struct { UserRolePair participants<V>; } ParticipantListData;`
/// (protocol-07 §7.5), the `data` of the
/// [`PARTICIPANT_LIST`](crate::component_id::PARTICIPANT_LIST) component.
///
/// Decoding does not reject a user that appears more than once.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default, TlsSerialize, TlsDeserialize, TlsSize)]
pub struct ParticipantListData {
    /// One entry per user, including inactive and banned users.
    pub participants: Vec<UserRolePair>,
}

/// `struct { uint32 user_index; uint32 role_index; } UserindexRolePair;`
/// (protocol-07 §7.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, TlsSerialize, TlsDeserialize, TlsSize)]
pub struct UserindexRolePair {
    /// Index into the current [`ParticipantListData::participants`].
    pub user_index: u32,
    /// The user's new role.
    pub role_index: u32,
}

/// `ParticipantListUpdate` (protocol-07 §7.5), the `update` of an
/// `AppDataUpdate` proposal for the participant list.
///
/// The spec omits the `;` after `changedRoleParticipants<V>`; it is read as
/// written intent (decision mimid-1wgh.5.31).
///
/// Decoding checks only the wire form. Index ranges, and the rule that a
/// commit may touch each user at most once, are checked when the update is
/// applied, not here (task mimid-1wgh.5.48).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default, TlsSerialize, TlsDeserialize, TlsSize)]
pub struct ParticipantListUpdate {
    /// `changedRoleParticipants`: users whose role changes.
    pub changed_role_participants: Vec<UserindexRolePair>,
    /// `removedIndices`: indices of users to remove from the list.
    pub removed_indices: Vec<u32>,
    /// `addedParticipants`: users appended to the end of the list.
    pub added_participants: Vec<UserRolePair>,
}

/// `struct { opaque uri<V>; } Uri;` (protocol-07 §7.6).
///
/// Its wire form is that of [`IdentifierUri`] (§5.2), so the type is
/// shared: the value is empty, meaning absent, or an RFC 3986 `URI`
/// (protocol-07 §7.6; decision mimid-1wgh.5.44).
pub type Uri = IdentifierUri;

/// `RichDescription` (protocol-07 §7.6).
///
/// All three fields are opaque on the wire, as the spec defines them. None
/// is checked to be UTF-8, a media type or a language tag (protocol-07
/// §7.6; decision mimid-1wgh.5.47).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default, TlsSerialize, TlsDeserialize, TlsSize)]
pub struct RichDescription {
    /// The media type of `description_content`. Empty is equivalent to
    /// `text/plain;charset=utf-8`.
    pub media_type: Vec<u8>,
    /// The language of `description_content`.
    pub language_tag: Vec<u8>,
    /// The description itself.
    pub description_content: Vec<u8>,
}

/// `RoomMetaData` (protocol-07 §7.6), the `data` of the
/// [`ROOM_METADATA`](crate::component_id::ROOM_METADATA) component.
///
/// `room_avatar` is described as "an https URI resolving to an avatar
/// image", but decoding does not require the `https` scheme: check it
/// before fetching (protocol-07 §7.6; decision mimid-1wgh.5.45).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default, TlsSerialize, TlsDeserialize, TlsSize)]
pub struct RoomMetaData {
    /// The room's URI.
    pub room_uri: Uri,
    /// The room's human-readable name.
    pub room_name: Utf8String,
    /// Descriptions of the room, e.g. one per language.
    pub room_descriptions: Vec<RichDescription>,
    /// The room's avatar image.
    pub room_avatar: Uri,
    /// The room's subject.
    pub room_subject: Utf8String,
    /// The room's mood.
    pub room_mood: Utf8String,
}

/// `RoomMetaData RoomMetaUpdate;` (protocol-07 §7.6), the `update` of an
/// `AppDataUpdate` proposal for room metadata. A valid, authorized update
/// replaces the component's data entirely.
pub type RoomMetaUpdate = RoomMetaData;
