//! The store's records (docs/design/agent-frontends.md §2, "Data model"):
//! what the agent keeps in plaintext, in terms of no one front end.
//!
//! Every record is named by a store key ([`Key`]): a ULID minted by the
//! store, the same form as crate-jmap's `MemoryBackend` ids, so a key is
//! a valid RFC 8620 Id. A record a front end's write made may have that
//! front end's id as its key instead (a JMAP write keeps its JMAP id;
//! [`crate::action`]). Users are named by their MIMI user URI everywhere,
//! never by a key, so a record never needs another to say who it means.
//!
//! Room, Message, Person, Ban and ReadPosition records carry an
//! [`Ext`] map, keyed by front end (`"jmap"`, `"irc"`): the store saves
//! it with the record and never reads it.
//!
//! # Limitations
//!
//! - Times are milliseconds since the UNIX epoch; a finer time in a JMAP
//!   object is cut to the millisecond (the JMAP front end keeps its text,
//!   in `ext["jmap"]`).
//! - A participant whose role the agent could not read has no role index
//!   ([`Participant::role`] is `None`) until the next sync sets it.
//! - A read position may name a room the store does not hold: one a
//!   client named. A room deleted here ([`crate::Store::forget_room`])
//!   takes its messages, bans and read positions with it.

use std::collections::BTreeMap;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::content::BodyType;
use crate::report::KeptFrank;

/// A store key (see the module documentation).
pub type Key = String;

/// Front-end extensions of a record: front-end name to that front end's
/// JSON. The store keeps and saves it and never reads it.
pub type Ext = BTreeMap<String, serde_json::Value>;

/// `N` octets, written as lowercase hex.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Octets<const N: usize>(pub [u8; N]);

impl<const N: usize> Serialize for Octets<N> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&crate::blobs::hex(&self.0))
    }
}

impl<'de, const N: usize> Deserialize<'de> for Octets<N> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        Octets::from_hex(&text).ok_or_else(|| {
            serde::de::Error::custom(format!("not {N} octets of lowercase hex: {text:?}"))
        })
    }
}

impl<const N: usize> Octets<N> {
    /// `text` as `N` octets, or `None` unless it is exactly `2N` lowercase
    /// hex digits.
    #[must_use]
    pub fn from_hex(text: &str) -> Option<Self> {
        let digits = text.as_bytes();
        if digits.len() != 2 * N {
            return None;
        }
        let value = |c: u8| match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            _ => None,
        };
        let mut out = [0u8; N];
        let (pairs, _) = digits.as_chunks::<2>();
        for (octet, [high, low]) in out.iter_mut().zip(pairs) {
            *octet = value(*high)? << 4 | value(*low)?;
        }
        Some(Self(out))
    }
}

/// Where a room stands for this user.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub enum RoomStatus {
    /// The user is in the room.
    Active,
    /// The user asked to leave and the hub has not yet removed them.
    Leaving,
    /// The user is out of the room.
    Left,
}

/// A participant of a room.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Participant {
    /// The user URI.
    pub user: String,
    /// The room-policy-04 role index, or `None` until a sync sets it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<u32>,
}

/// One MIMI room the user is or was in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Room {
    /// The store key.
    pub key: Key,
    /// The room URI.
    pub uri: String,
    /// The room's `room_name`, if it has one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// The room's `room_subject` (protocol-07 §7.6), if it has room
    /// metadata; empty when no subject is set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    /// Who last changed the subject, and when, if a change was seen;
    /// `None` for a subject the room had when the record was made.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject_set: Option<SubjectSet>,
    /// Where the room stands.
    pub status: RoomStatus,
    /// The participants, banned ones included, with their roles.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub participants: Vec<Participant>,
    /// The room's role names by index.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub role_names: BTreeMap<u32, String>,
    /// The user's local expiry policy for the room, in seconds
    /// (draft-atwood-jmap-chat-00 §Chat `messageExpirySeconds`): a
    /// message older than this, counted from its arrival here
    /// ([`Message::received_at`]), is deleted ([`crate::expiry`]). `None`
    /// or 0: none. Not sent to anyone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message_expiry_seconds: Option<u64>,
    /// Front-end extensions.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub ext: Ext,
}

/// A change of a room's subject: the Commit that made it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SubjectSet {
    /// The user URI of the Commit's sender, if known
    /// (`Event::MembersChanged`'s `committer`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub by: Option<String>,
    /// The hub's acceptance time of the Commit, in milliseconds since the
    /// epoch.
    pub at: u64,
}

/// Who sent a message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub enum Sender {
    /// A user, by URI: the authenticated MLS sender, or the user for
    /// their own messages.
    User(String),
    /// The agent itself: a notice ([`Message::notice`]).
    Agent,
}

/// What a message replies to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub enum Reply {
    /// A stored message, by key.
    Message(Key),
    /// A message not stored here, by the reference octets of its MIMI
    /// message ID.
    Reference(Octets<10>),
}

/// An attachment of a message whose content is in the blob store.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Attachment {
    /// The blob id (`s` and the SHA-256 hex of the content).
    pub blob_id: String,
    /// The file name, made safe ([`crate::content::safe_filename`]).
    pub file_name: String,
    /// The media type.
    pub media_type: String,
    /// The content's length in octets.
    pub size: u64,
    /// The content's SHA-256, as hex.
    pub sha256: String,
}

/// A call to join that a message carries: a part of disposition
/// `session` (mimi-content-10 §4.4, §5.10; docs/design/agent-frontends.md
/// §7.24). Never fetched; the front ends show it as a link only if
/// [`Call::is_link`], and otherwise as text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Call {
    /// The URL, as received, cut to
    /// [`crate::content::MAX_CALL_URL_LEN`] octets.
    pub url: String,
    /// The part's description, as received, cut to
    /// [`crate::content::MAX_CALL_DESCRIPTION_CHARS`]; empty if none.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub description: String,
    /// The part's `expires`, in seconds since the UNIX epoch, or `None`
    /// for an inline part or an `expires` of 0.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires: Option<u32>,
}

impl Call {
    /// Whether the URL may be shown as a link
    /// ([`crate::content::is_call_link`]).
    #[must_use]
    pub fn is_link(&self) -> bool {
        crate::content::is_call_link(&self.url)
    }

    /// The call as one line of text, as the front ends show it where they
    /// show text (docs/design/agent-frontends.md §7.24): `call:
    /// <description> <<url>>` for a link, `call: <description> (not a web
    /// link: <url>)` otherwise, the description left out when empty, and
    /// every control character a space.
    #[must_use]
    pub fn text(&self) -> String {
        let one_line = |text: &str| -> String {
            text.chars()
                .map(|c| if c.is_control() { ' ' } else { c })
                .collect()
        };
        let mut line = "call:".to_owned();
        let description = one_line(&self.description);
        if !description.trim().is_empty() {
            line.push(' ');
            line.push_str(description.trim());
        }
        let url = one_line(&self.url);
        if self.is_link() {
            line.push_str(&format!(" <{url}>"));
        } else {
            line.push_str(&format!(" (not a web link: {url})"));
        }
        line
    }
}

/// An earlier version of an edited message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Revision {
    /// Its body.
    pub body: String,
    /// Its body type.
    pub body_type: BodyType,
    /// When it was replaced, in milliseconds.
    pub edited_at: u64,
}

/// A deleted message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Deletion {
    /// When, in milliseconds.
    pub at: u64,
    /// Retracted by its sender for everyone (mimi-content-10 §5.6), not
    /// only hidden here.
    pub for_all: bool,
}

/// What a notice of the agent's says ([`crate::notice`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub enum NoticeKind {
    /// A contact's did:webvh identity changed (`Event::IdentityChanged`).
    #[serde(rename_all = "camelCase")]
    IdentityChanged {
        /// The contact's user URI.
        user: String,
        /// The SCID first seen for them.
        pinned: String,
        /// The SCID now presented, or `None` for a BasicCredential.
        presented: Option<String>,
    },
    /// A client of a member was removed for lacking AppDataUpdate
    /// (`Event::RemovedWithoutAppDataUpdate`).
    #[serde(rename_all = "camelCase")]
    RemovedWithoutAppDataUpdate {
        /// The member's user URI, empty if the leaf named none.
        user: String,
        /// The epoch of the removing Commit.
        epoch: u64,
    },
}

/// A message in a room: received, sent by the user, or a notice.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Message {
    /// The store key.
    pub key: Key,
    /// The room's key.
    pub room: Key,
    /// The store's sequence number, given when stored. History is ordered
    /// by (`accepted_at`, `seq`); it is local only.
    pub seq: u64,
    /// Who sent it.
    pub sender: Sender,
    /// The first version's MIMI message ID, all 32 octets; `None` for a
    /// notice, and for a message stored before these were kept.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mimi_id: Option<Octets<32>>,
    /// The reference octets of its later versions, oldest first.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub aliases: Vec<Octets<10>>,
    /// The hub's acceptance time in milliseconds (for a notice, when it
    /// was made).
    pub accepted_at: u64,
    /// When it arrived here, in milliseconds (docs/design/agent-frontends.md
    /// §7.18): when this store stored a message received from the hub;
    /// for one this device sent, the hub's acceptance time
    /// (`accepted_at`), which is also when it reached the provider and
    /// stays the same when the outbox finishes the send after a crash
    /// (§3 step 10); for a notice, when it was made.
    pub received_at: u64,
    /// The stable id every front end shows it under
    /// ([`crate::convert::sender_msg_id`]); its random part is the
    /// message's reference octets.
    pub sender_msg_id: String,
    /// The text; empty when retracted, or for attachments or calls
    /// without text.
    pub body: String,
    /// The text's type.
    pub body_type: BodyType,
    /// What it replies to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub in_reply_to: Option<Reply>,
    /// The MIMI `topicId` ([`crate::convert::topic_id`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub topic_id: Option<String>,
    /// Its attachments in the blob store.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attachments: Vec<Attachment>,
    /// The calls to join it carries ([`Call`]).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub calls: Vec<Call>,
    /// Earlier versions, oldest first.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub edit_history: Vec<Revision>,
    /// When it was last edited, in milliseconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub edited_at: Option<u64>,
    /// Its deletion, if deleted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deleted: Option<Deletion>,
    /// What a report of it needs, for a received message.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kept_frank: Option<KeptFrank>,
    /// What a notice says.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notice: Option<NoticeKind>,
    /// When it is to be deleted, as its sender asked ([`crate::expiry`]).
    #[serde(default, skip_serializing_if = "MessageExpiry::is_none")]
    pub expiry: MessageExpiry,
    /// When the user first read it, in milliseconds: kept only for a
    /// received message whose [`MessageExpiry`] counts from the read
    /// ([`crate::Store::mark_read`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub read_at: Option<u64>,
    /// Front-end extensions.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub ext: Ext,
}

/// When a message is to be deleted, as its sender asked
/// (docs/design/agent-frontends.md §7.20; [`crate::expiry`]). The names
/// are those of draft-atwood-jmap-chat-00 §Message. Fixed when the
/// message is stored: an edit does not change it (mimi-content-10 §9.3).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MessageExpiry {
    /// When every copy is deleted, the sender's own included, in
    /// milliseconds (a whole second): mimi-content-10 §4.1 `expires`,
    /// absolute.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sender_expires_at: Option<u64>,
    /// A receiver's copy is deleted as soon as the user reads it; the
    /// sender's copy is not.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub burn_on_read: bool,
    /// A receiver's copy is deleted this many seconds after the user
    /// reads it; the sender's copy is not.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_after_read_seconds: Option<u32>,
}

impl MessageExpiry {
    /// Whether it asks for nothing.
    #[must_use]
    pub fn is_none(&self) -> bool {
        *self == Self::default()
    }

    /// Whether a receiver's copy is deleted on or after the user's read.
    #[must_use]
    pub fn counts_from_read(&self) -> bool {
        self.burn_on_read || self.expires_after_read_seconds.is_some()
    }
}

/// A user the agent has seen.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Person {
    /// The store key.
    pub key: Key,
    /// The user URI.
    pub user: String,
    /// The user's name for them, set locally.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    /// Their did:webvh DID, from their leaves.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub did: Option<String>,
    /// When their DID last changed, in milliseconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub did_changed_at: Option<u64>,
    /// When first seen, in milliseconds.
    pub first_seen: u64,
    /// Front-end extensions.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub ext: Ext,
}

/// A user a room holds in its "banned" role.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Ban {
    /// The store key.
    pub key: Key,
    /// The room's key.
    pub room: Key,
    /// The banned user's URI.
    pub user: String,
    /// The URI of the user who banned them: the user's own for a ban made
    /// here or by a committer not known ([`crate::sync::bans`]).
    pub banned_by: String,
    /// The reason, local.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// When the ban is lifted, in milliseconds; local.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
    /// Front-end extensions.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub ext: Ext,
}

/// How far the user has read in a room.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReadPosition {
    /// The store key.
    pub key: Key,
    /// The room's key.
    pub room: Key,
    /// The last message read, by key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<Key>,
    /// When, in milliseconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub at: Option<u64>,
    /// Front-end extensions.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub ext: Ext,
}

/// What is left of something deleted here, so that the journal
/// delivering it again does not store it again
/// (docs/design/agent-frontends.md §2).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub enum Tombstone {
    /// One version of a message deleted here.
    #[serde(rename_all = "camelCase")]
    Message {
        /// The room's key.
        room: Key,
        /// The reference octets of the message's first version or of a
        /// later one.
        reference: Octets<10>,
    },
    /// A room deleted here with everything in it
    /// ([`crate::State::remove_room`]; docs/design/agent-frontends.md
    /// §7.9), kept while the agent may still deliver its events.
    #[serde(rename_all = "camelCase")]
    Room {
        /// The room's key.
        key: Key,
        /// The room URI, which a record made for it again would share.
        uri: String,
    },
}

/// A pending invite, as the agent holds it. Not saved: it is read from
/// the agent at each sync.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invite {
    /// The agent's invite number.
    pub number: u64,
    /// The inviter's user URI, if the Welcome names one.
    pub inviter: Option<String>,
    /// The room's URI, if the Welcome could be read
    /// (`Agent::invite_details`).
    pub room: Option<String>,
    /// The room's name from the Welcome's room metadata, if it could be
    /// read and has one.
    pub room_name: Option<String>,
    /// The invite policy refused it.
    pub refused: bool,
}
