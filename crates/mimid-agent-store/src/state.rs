//! The store's in-memory state: every record, and the indexes rebuilt from
//! them at load.
//!
//! # Limitations
//!
//! - [`State::reindex`] walks every record; the `insert_*` methods keep
//!   the indexes without it.

use std::collections::{BTreeMap, BTreeSet};

use crate::content::BodyType;
use crate::convert::MessageRef;
use crate::record::{
    Ban, Deletion, Ext, Invite, Key, Message, Octets, Person, Reaction, ReadPosition, Revision,
    Room, Sender, Tombstone,
};
use crate::retry::PendingAttachment;
use crate::sync::MAX_EDIT_HISTORY;

/// Every record of one user's store.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct State {
    /// The user's URI.
    pub user: String,
    /// Store-wide front-end extensions (the JMAP accountId under
    /// `"jmap"`).
    pub ext: Ext,
    /// Rooms by key.
    pub rooms: BTreeMap<Key, Room>,
    /// People by key.
    pub people: BTreeMap<Key, Person>,
    /// Messages by key.
    pub messages: BTreeMap<Key, Message>,
    /// Bans by key.
    pub bans: BTreeMap<Key, Ban>,
    /// Read positions by key.
    pub read_positions: BTreeMap<Key, ReadPosition>,
    /// Received attachments waiting for another fetch ([`crate::retry`]).
    pub pending_attachments: Vec<PendingAttachment>,
    /// The next message sequence number.
    pub next_seq: u64,
    /// What was deleted here: the versions of messages deleted since the
    /// agent's delivery was last acknowledged ([`State::delete_message`]),
    /// and the rooms whose events the agent may still deliver
    /// ([`State::remove_room`]).
    pub tombstones: BTreeSet<Tombstone>,
    /// Pending invites, read from the agent; not saved.
    pub invites: Vec<Invite>,
    /// The indexes over the records.
    indexes: Indexes,
}

/// Lookups rebuilt from the records ([`State::reindex`]).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Indexes {
    room_of_uri: BTreeMap<String, Key>,
    person_of_user: BTreeMap<String, Key>,
    /// (room key, reference octets of the first version or an alias) to
    /// message key.
    message_of_ref: BTreeMap<(Key, MessageRef), Key>,
    /// (room key, reference octets of a reaction's message) to the key of
    /// the message it is kept on.
    reaction_of_ref: BTreeMap<(Key, MessageRef), Key>,
}

impl State {
    /// An empty store for `user`.
    #[must_use]
    pub fn new(user: impl Into<String>) -> Self {
        Self {
            user: user.into(),
            next_seq: 1,
            ..Self::default()
        }
    }

    /// Rebuilds the indexes from the records.
    pub fn reindex(&mut self) {
        let mut indexes = Indexes::default();
        for (key, room) in &self.rooms {
            indexes.room_of_uri.insert(room.uri.clone(), key.clone());
        }
        for (key, person) in &self.people {
            indexes
                .person_of_user
                .insert(person.user.clone(), key.clone());
        }
        for (key, message) in &self.messages {
            let references = reference_of(&message.sender_msg_id)
                .into_iter()
                .chain(message.aliases.iter().map(alias_ref));
            for reference in references {
                indexes
                    .message_of_ref
                    .insert((message.room.clone(), reference), key.clone());
            }
            for reaction in &message.reactions {
                indexes
                    .reaction_of_ref
                    .insert((message.room.clone(), reaction_ref(reaction)), key.clone());
            }
        }
        self.indexes = indexes;
    }

    /// Stores `room` under its key, indexed by its URI.
    pub fn insert_room(&mut self, room: Room) {
        self.indexes
            .room_of_uri
            .insert(room.uri.clone(), room.key.clone());
        self.rooms.insert(room.key.clone(), room);
    }

    /// Stores `person` under its key, indexed by its user URI.
    pub fn insert_person(&mut self, person: Person) {
        self.indexes
            .person_of_user
            .insert(person.user.clone(), person.key.clone());
        self.people.insert(person.key.clone(), person);
    }

    /// Stores `message` under its key, indexed in its room by the
    /// reference octets of its `senderMsgId` and of its aliases.
    pub fn insert_message(&mut self, message: Message) {
        let references = reference_of(&message.sender_msg_id)
            .into_iter()
            .chain(message.aliases.iter().map(alias_ref));
        for reference in references {
            self.indexes
                .message_of_ref
                .insert((message.room.clone(), reference), message.key.clone());
        }
        for reaction in &message.reactions {
            self.indexes.reaction_of_ref.insert(
                (message.room.clone(), reaction_ref(reaction)),
                message.key.clone(),
            );
        }
        self.messages.insert(message.key.clone(), message);
    }

    /// Adds `reaction` to message `key`, indexed by the reference octets
    /// of its message; false if there is no such message, or it holds a
    /// reaction of that key already.
    pub fn add_reaction(&mut self, key: &str, reaction: Reaction) -> bool {
        let Some(message) = self.messages.get_mut(key) else {
            return false;
        };
        if message.reactions.iter().any(|r| r.key == reaction.key) {
            return false;
        }
        self.indexes.reaction_of_ref.insert(
            (message.room.clone(), reaction_ref(&reaction)),
            key.to_owned(),
        );
        message.reactions.push(reaction);
        true
    }

    /// Takes the reactions of message `key` whose message `reference`
    /// names (a reaction message's parts are taken together, §5.7), and
    /// returns them.
    pub fn remove_reactions(&mut self, key: &str, reference: &MessageRef) -> Vec<Reaction> {
        let Some(message) = self.messages.get_mut(key) else {
            return Vec::new();
        };
        let taken: Vec<Reaction> = message
            .reactions
            .extract_if(.., |r| reaction_ref(r) == *reference)
            .collect();
        self.indexes
            .reaction_of_ref
            .remove(&(message.room.clone(), *reference));
        taken
    }

    /// The key of the message in room `room` that holds a reaction whose
    /// message `reference` names.
    #[must_use]
    pub fn reaction_of_ref(&self, room: &str, reference: &MessageRef) -> Option<&Key> {
        self.indexes
            .reaction_of_ref
            .get(&(room.to_owned(), *reference))
    }

    /// Adds `alias`, the MIMI message ID of a later version, to message
    /// `key`, and indexes it by its reference octets; false if there is
    /// no such message.
    pub fn add_alias(&mut self, key: &str, alias: &mimi_content::MessageId) -> bool {
        let Some(message) = self.messages.get_mut(key) else {
            return false;
        };
        message.aliases.push(crate::record::Octets(alias.0));
        self.indexes.message_of_ref.insert(
            (message.room.clone(), crate::convert::message_ref(alias)),
            key.to_owned(),
        );
        true
    }

    /// Deletes message `key` here (a front end's local delete) and keeps
    /// a [`Tombstone`] for its first version and each alias, so that the
    /// journal delivering it again, after a crash or a failed save, does
    /// not store it again ([`State::is_deleted`]). Returns the message, or
    /// `None` if there is none.
    pub fn delete_message(&mut self, key: &str) -> Option<Message> {
        let message = self.messages.remove(key)?;
        let references = reference_of(&message.sender_msg_id)
            .into_iter()
            .chain(message.aliases.iter().map(alias_ref));
        for reaction in &message.reactions {
            self.indexes
                .reaction_of_ref
                .remove(&(message.room.clone(), reaction_ref(reaction)));
        }
        for reference in references {
            self.indexes
                .message_of_ref
                .remove(&(message.room.clone(), reference));
            self.tombstones.insert(Tombstone::Message {
                room: message.room.clone(),
                reference: Octets(reference),
            });
        }
        Some(message)
    }

    /// Deletes message `key` at its expiry ([`crate::expiry`]): as
    /// [`State::delete_message`], with its tombstones, and with its
    /// attachments waiting for a retry. Returns the message, or `None` if
    /// there is none.
    pub fn expire_message(&mut self, key: &str) -> Option<Message> {
        let message = self.delete_message(key)?;
        self.pending_attachments.retain(|p| p.message != key);
        Some(message)
    }

    /// Edits message `key` to `body` of `body_type` at `at`, in
    /// milliseconds: its old body becomes the last of at most
    /// [`MAX_EDIT_HISTORY`] revisions (draft-atwood-jmap-chat-00 §Editing a
    /// Message). The edit's alias is the caller's to add. False if there
    /// is no such message.
    pub fn edit_message(&mut self, key: &str, body: String, body_type: BodyType, at: u64) -> bool {
        let Some(message) = self.messages.get_mut(key) else {
            return false;
        };
        let old = Revision {
            body: std::mem::replace(&mut message.body, body),
            body_type: message.body_type,
            edited_at: at,
        };
        message.edit_history.push(old);
        let excess = message.edit_history.len().saturating_sub(MAX_EDIT_HISTORY);
        message.edit_history.drain(..excess);
        message.body_type = body_type;
        message.edited_at = Some(at);
        true
    }

    /// Retracts message `key` for everyone at `at`, in milliseconds
    /// (mimi-content-10 §5.6): its content goes, with its reactions, the
    /// kept report record and any attachment still to fetch. The retraction's alias
    /// is the caller's to add. False if there is no such message.
    pub fn retract_message(&mut self, key: &str, at: u64) -> bool {
        let Some(message) = self.messages.get_mut(key) else {
            return false;
        };
        message.deleted = Some(Deletion { at, for_all: true });
        message.body = String::new();
        message.attachments.clear();
        message.calls.clear();
        message.edit_history.clear();
        for reaction in std::mem::take(&mut message.reactions) {
            self.indexes
                .reaction_of_ref
                .remove(&(message.room.clone(), reaction_ref(&reaction)));
        }
        message.kept_frank = None;
        self.pending_attachments.retain(|p| p.message != key);
        true
    }

    /// Removes person `key`; the user gets a new record when next seen.
    pub fn remove_person(&mut self, key: &str) -> Option<Person> {
        let person = self.people.remove(key)?;
        self.reindex();
        Some(person)
    }

    /// Deletes room `key` with everything the store keeps of it
    /// (docs/design/agent-frontends.md §7.9): the room record, its
    /// messages, bans and read positions, the attachments of its messages
    /// waiting for a retry, and the tombstones of its deleted messages. A
    /// [`Tombstone::Room`] takes their place, so that the journal
    /// delivering the room's events again does not store them again
    /// ([`State::is_forgotten`]). Returns what was deleted, or `None` if
    /// there is no such room.
    pub fn remove_room(&mut self, key: &str) -> Option<RemovedRoom> {
        let uri = self.rooms.get(key)?.uri.clone();
        self.remove_room_leaving(
            key,
            Tombstone::Room {
                key: key.to_owned(),
                uri,
            },
        )
    }

    /// Hides one-to-one room `key` here without leaving it (bead
    /// mimid-2vcw, option B): its record goes with everything in it, as
    /// [`State::remove_room`] deletes them, and a [`Tombstone::HiddenRoom`]
    /// keeps a record from being made for it again, until a new message
    /// newer than every message it held comes
    /// ([`State::reveal_hidden_room`]) or the user opens it again.
    /// `None` if there is no such room.
    pub fn hide_room(&mut self, key: &str) -> Option<RemovedRoom> {
        let uri = self.rooms.get(key)?.uri.clone();
        let after = self
            .messages
            .values()
            .filter(|m| m.room == key)
            .map(|m| m.accepted_at)
            .max()
            .unwrap_or(0);
        self.remove_room_leaving(
            key,
            Tombstone::HiddenRoom {
                key: key.to_owned(),
                uri,
                after,
            },
        )
    }

    /// Whether room `uri` is hidden here ([`State::hide_room`]).
    #[must_use]
    pub fn is_hidden(&self, uri: &str) -> bool {
        self.tombstones
            .iter()
            .any(|t| matches!(t, Tombstone::HiddenRoom { uri: u, .. } if u == uri))
    }

    /// The URIs of the rooms hidden here ([`State::hide_room`]).
    #[must_use]
    pub fn hidden_rooms(&self) -> Vec<String> {
        self.tombstones
            .iter()
            .filter_map(|t| match t {
                Tombstone::HiddenRoom { uri, .. } => Some(uri.clone()),
                _ => None,
            })
            .collect()
    }

    /// Ends the hiding of room `uri` if a message the hub accepted at
    /// `accepted_at` is newer than every message it held when it was
    /// hidden; a record may then be made for it. Whether it did.
    pub fn reveal_hidden_room(&mut self, uri: &str, accepted_at: u64) -> bool {
        let before = self.tombstones.len();
        self.tombstones.retain(|t| {
            !matches!(t, Tombstone::HiddenRoom { uri: u, after, .. }
                if u == uri && accepted_at > *after)
        });
        self.tombstones.len() != before
    }

    /// Removes record `key` and what is in it, as [`State::remove_room`]
    /// describes, leaving `tombstone` in its place.
    fn remove_room_leaving(&mut self, key: &str, tombstone: Tombstone) -> Option<RemovedRoom> {
        let room = self.rooms.remove(key)?;
        let messages: BTreeMap<Key, Message> =
            self.messages.extract_if(.., |_, m| m.room == key).collect();
        let bans: Vec<Key> = self
            .bans
            .extract_if(.., |_, b| b.room == key)
            .map(|(k, _)| k)
            .collect();
        self.read_positions.retain(|_, r| r.room != key);
        self.pending_attachments
            .retain(|p| p.room != room.uri && !messages.contains_key(&p.message));
        self.tombstones
            .retain(|t| !matches!(t, Tombstone::Message { room, .. } if room == key));
        self.tombstones.insert(tombstone);
        self.reindex();
        // Blobs are content-addressed: one another message names stays.
        let named: BTreeSet<&str> = self
            .messages
            .values()
            .flat_map(|m| m.attachments.iter().map(|a| a.blob_id.as_str()))
            .collect();
        let own = Sender::User(self.user.clone());
        let (mut blobs, mut sent) = (BTreeSet::new(), BTreeSet::new());
        for message in messages.values() {
            for attachment in &message.attachments {
                if !named.contains(attachment.blob_id.as_str()) {
                    blobs.insert(attachment.blob_id.clone());
                    if message.sender == own {
                        sent.insert(attachment.blob_id.clone());
                    }
                }
            }
        }
        Some(RemovedRoom {
            room,
            messages: messages.into_keys().collect(),
            bans,
            blobs,
            sent,
        })
    }

    /// Whether room `uri` was deleted ([`State::remove_room`]) or hidden
    /// ([`State::hide_room`]) here and its tombstone is still kept: no
    /// record is made for it.
    #[must_use]
    pub fn is_forgotten(&self, uri: &str) -> bool {
        self.tombstones.iter().any(|t| {
            matches!(t, Tombstone::Room { uri: u, .. } | Tombstone::HiddenRoom { uri: u, .. }
                if u == uri)
        })
    }

    /// The URIs of the rooms deleted here whose tombstones are kept.
    #[must_use]
    pub fn forgotten_rooms(&self) -> Vec<String> {
        self.tombstones
            .iter()
            .filter_map(|t| match t {
                Tombstone::Room { uri, .. } => Some(uri.clone()),
                Tombstone::Message { .. } | Tombstone::HiddenRoom { .. } => None,
            })
            .collect()
    }

    /// Forgets the tombstones of the rooms `uris`: records for them may be
    /// made again.
    pub fn clear_room_tombstones(&mut self, uris: &[String]) {
        self.tombstones.retain(|t| {
            !matches!(t, Tombstone::Room { uri, .. } | Tombstone::HiddenRoom { uri, .. }
                if uris.contains(uri))
        });
    }

    /// Whether the message in room `room` that `reference` names was
    /// deleted here since the last acknowledgement.
    #[must_use]
    pub fn is_deleted(&self, room: &str, reference: &MessageRef) -> bool {
        self.tombstones.contains(&Tombstone::Message {
            room: room.to_owned(),
            reference: Octets(*reference),
        })
    }

    /// Forgets the tombstones of messages: the agent's delivery has been
    /// acknowledged, so no event that stored one of them comes again.
    /// Room tombstones stay.
    pub fn clear_message_tombstones(&mut self) {
        self.tombstones
            .retain(|t| !matches!(t, Tombstone::Message { .. }));
    }

    /// The next message sequence number, taken.
    pub fn take_seq(&mut self) -> u64 {
        let seq = self.next_seq;
        self.next_seq = self.next_seq.saturating_add(1);
        seq
    }

    /// The key of the room with URI `uri`.
    #[must_use]
    pub fn room_of_uri(&self, uri: &str) -> Option<&Key> {
        self.indexes.room_of_uri.get(uri)
    }

    /// The key of the person with user URI `user`.
    #[must_use]
    pub fn person_of_user(&self, user: &str) -> Option<&Key> {
        self.indexes.person_of_user.get(user)
    }

    /// The key of the message in room `room` that `reference` names: its
    /// first version or one of its aliases.
    #[must_use]
    pub fn message_of_ref(&self, room: &str, reference: &MessageRef) -> Option<&Key> {
        self.indexes
            .message_of_ref
            .get(&(room.to_owned(), *reference))
    }
}

/// What [`State::remove_room`] deleted.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct RemovedRoom {
    /// The room record.
    pub room: Room,
    /// The keys of its messages.
    pub messages: Vec<Key>,
    /// The keys of its bans.
    pub bans: Vec<Key>,
    /// The blob ids its messages' attachments named that no message left
    /// names.
    pub blobs: BTreeSet<String>,
    /// Those of [`RemovedRoom::blobs`] that a message of the user's own
    /// named: the user's uploads.
    pub sent: BTreeSet<String>,
}

/// The reference octets of a message's later version `alias`.
fn alias_ref(alias: &Octets<32>) -> MessageRef {
    alias.reference()
}

/// The reference octets of the message of `reaction`.
fn reaction_ref(reaction: &Reaction) -> MessageRef {
    crate::convert::message_ref(&mimi_content::MessageId(reaction.mimi_id.0))
}

/// The reference octets of a `senderMsgId`: the last 10 octets of the
/// ULID's random part, or `None` if it is not a ULID.
#[must_use]
pub fn reference_of(sender_msg_id: &str) -> Option<MessageRef> {
    let ulid = ulid::Ulid::from_string(sender_msg_id).ok()?;
    let random = ulid.random().to_be_bytes();
    let mut out = [0u8; 10];
    out.copy_from_slice(&random[6..]);
    Some(out)
}

/// The acceptance time in milliseconds of a `senderMsgId`: the ULID's
/// time, or `None` if it is not a ULID.
#[must_use]
pub fn accepted_at_of(sender_msg_id: &str) -> Option<u64> {
    Some(ulid::Ulid::from_string(sender_msg_id).ok()?.timestamp_ms())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::{Participant, RoomStatus};
    use crate::report::KeptFrank;

    const ALICE: &str = "mimi://a.example/u/alice";
    const BOB: &str = "mimi://a.example/u/bob";

    fn message(key: &str, room: &str, body: &str) -> Message {
        Message {
            key: key.into(),
            room: room.into(),
            seq: 1,
            sender: Sender::User(ALICE.into()),
            mimi_id: None,
            aliases: Vec::new(),
            accepted_at: 1_000,
            received_at: 1_001,
            sender_msg_id: "01M7VA1QTK2Y4V6ER4Z3A3V6QN".into(),
            body: body.into(),
            body_type: BodyType::Plain,
            in_reply_to: None,
            in_reply_to_id: None,
            topic_id: None,
            attachments: vec![crate::record::Attachment {
                blob_id: "s00".into(),
                file_name: "a.txt".into(),
                media_type: "text/plain".into(),
                size: 1,
                sha256: "00".into(),
            }],
            extensions: Vec::new(),
            reactions: Vec::new(),
            calls: Vec::new(),
            edit_history: Vec::new(),
            edited_at: None,
            deleted: None,
            kept_frank: Some(KeptFrank {
                room: "mimi://a.example/r/one".into(),
                message: "00".into(),
                unverified: true,
            }),
            notice: None,
            expiry: Default::default(),
            read_at: None,
            ext: Ext::new(),
        }
    }

    /// Oracle: draft-atwood-jmap-chat-00 §Editing a Message: the old body
    /// becomes the last revision, edited at the edit's time, and at most
    /// MAX_EDIT_HISTORY are kept, oldest dropped first.
    #[test]
    fn an_edit_keeps_the_old_body_and_caps_the_history() {
        let mut state = State::new(ALICE);
        state.insert_message(message("M1", "R1", "v0"));
        for n in 1..=MAX_EDIT_HISTORY + 1 {
            let body = format!("v{n}");
            assert!(state.edit_message("M1", body, BodyType::Markdown, 2_000 + n as u64));
        }
        let m = &state.messages["M1"];
        let last = MAX_EDIT_HISTORY as u64 + 1;
        assert_eq!(m.body, format!("v{last}"));
        assert_eq!(m.body_type, BodyType::Markdown);
        assert_eq!(m.edited_at, Some(2_000 + last));
        assert_eq!(m.edit_history.len(), MAX_EDIT_HISTORY);
        // v0 was dropped; v1 (edited away at 2_002) is the oldest kept.
        assert_eq!(m.edit_history[0].body, "v1");
        assert_eq!(m.edit_history[0].edited_at, 2_002);
        assert_eq!(m.edit_history[0].body_type, BodyType::Markdown);
        assert!(!state.edit_message("M2", String::new(), BodyType::Plain, 0));
    }

    /// Oracle: mimi-content-10 §5.6 and draft-atwood-jmap-chat-00
    /// §Message `deletedAt`: a retracted message has no body, no
    /// attachments and no history; it keeps nothing to report either.
    #[test]
    fn a_retraction_empties_the_message() {
        let mut state = State::new(ALICE);
        state.insert_message(message("M1", "R1", "hello"));
        state.edit_message("M1", "hi".into(), BodyType::Plain, 2_000);
        assert!(state.retract_message("M1", 3_000));
        let m = &state.messages["M1"];
        assert_eq!(
            m.deleted,
            Some(Deletion {
                at: 3_000,
                for_all: true
            })
        );
        assert!(m.body.is_empty() && m.attachments.is_empty() && m.edit_history.is_empty());
        assert_eq!(m.kept_frank, None);
        assert!(!state.retract_message("M2", 3_000));
    }

    fn room(key: &str, uri: &str) -> Room {
        Room {
            key: key.into(),
            uri: uri.into(),
            name: None,
            subject: None,
            subject_set: None,
            status: RoomStatus::Active,
            participants: vec![Participant {
                user: ALICE.into(),
                role: Some(2),
            }],
            role_names: BTreeMap::new(),
            message_expiry_seconds: None,
            direct: false,
            parent: None,
            ext: Ext::new(),
        }
    }

    /// `message` with its sender `sender`, a `senderMsgId` whose
    /// reference octets are all `n`, and one attachment of blob `blob`.
    fn message_with(key: &str, room: &str, sender: &str, n: u8, blob: &str) -> Message {
        let mut random = [n; 16];
        random[..6].fill(0);
        let mut m = message(key, room, "text");
        m.sender = Sender::User(sender.into());
        m.sender_msg_id = ulid::Ulid::from_parts(1_000, u128::from_be_bytes(random)).to_string();
        m.attachments[0].blob_id = blob.into();
        m
    }

    fn pending(message: &str, room: &str) -> PendingAttachment {
        let part = mimi_content::ExternalPart {
            content_type: String::new(),
            url: String::new(),
            expires: 0,
            size: 0,
            enc_alg: 1,
            key: vec![0; 16],
            nonce: vec![],
            aad: vec![],
            hash_alg: 0,
            content_hash: vec![],
            description: String::new(),
            filename: String::new(),
        };
        PendingAttachment::new(message.into(), room.into(), 1, &part)
    }

    fn ban(key: &str, room: &str) -> Ban {
        Ban {
            key: key.into(),
            room: room.into(),
            user: BOB.into(),
            banned_by: ALICE.into(),
            reason: None,
            expires_at: None,
            ext: Ext::new(),
        }
    }

    /// Oracle: docs/design/agent-frontends.md §7.9, "Deleting a chat
    /// deletes its local data": every record of the room goes, with what
    /// waits for a retry and its message tombstones; a room tombstone is
    /// kept; the other room keeps everything, the blob its message shares
    /// included; the user's own attachments are told apart.
    #[test]
    fn a_removed_room_takes_everything_of_it_and_nothing_else() {
        const ONE: &str = "mimi://a.example/r/one";
        const TWO: &str = "mimi://a.example/r/two";
        let mut state = State::new(ALICE);
        state.insert_room(room("R1", ONE));
        state.insert_room(room("R2", TWO));
        state.insert_message(message_with("M1", "R1", ALICE, 1, "sown"));
        state.insert_message(message_with("M2", "R1", BOB, 2, "sshared"));
        state.insert_message(message_with("M3", "R1", BOB, 3, "sbob"));
        state.insert_message(message_with("M4", "R2", BOB, 4, "sshared"));
        for (key, room) in [("B1", "R1"), ("B2", "R2")] {
            state.bans.insert(key.into(), ban(key, room));
        }
        for (key, room) in [("C1", "R1"), ("C2", "R2")] {
            state.read_positions.insert(
                key.into(),
                ReadPosition {
                    key: key.into(),
                    room: room.into(),
                    message: None,
                    at: None,
                    ext: Ext::new(),
                },
            );
        }
        state.pending_attachments = vec![pending("M3", ONE), pending("M4", TWO)];
        for room in ["R1", "R2"] {
            state.tombstones.insert(Tombstone::Message {
                room: room.into(),
                reference: Octets([9; 10]),
            });
        }

        let removed = state.remove_room("R1").unwrap();
        assert_eq!(removed.room.uri, ONE);
        assert_eq!(removed.messages, ["M1", "M2", "M3"]);
        assert_eq!(removed.bans, ["B1"]);
        let set = |ids: &[&str]| ids.iter().map(|id| id.to_string()).collect::<BTreeSet<_>>();
        assert_eq!(removed.blobs, set(&["sbob", "sown"]));
        assert_eq!(removed.sent, set(&["sown"]));

        assert_eq!(state.rooms.keys().collect::<Vec<_>>(), ["R2"]);
        assert_eq!(state.messages.keys().collect::<Vec<_>>(), ["M4"]);
        assert_eq!(state.bans.keys().collect::<Vec<_>>(), ["B2"]);
        assert_eq!(state.read_positions.keys().collect::<Vec<_>>(), ["C2"]);
        let waiting: Vec<&str> = state
            .pending_attachments
            .iter()
            .map(|p| p.message.as_str())
            .collect();
        assert_eq!(waiting, ["M4"]);
        assert_eq!(
            state.tombstones,
            BTreeSet::from([
                Tombstone::Message {
                    room: "R2".into(),
                    reference: Octets([9; 10]),
                },
                Tombstone::Room {
                    key: "R1".into(),
                    uri: ONE.into(),
                },
            ])
        );
        assert_eq!(state.room_of_uri(ONE), None);
        assert_eq!(state.message_of_ref("R1", &[2; 10]), None);
        assert_eq!(state.message_of_ref("R2", &[4; 10]), Some(&"M4".into()));
        assert!(state.is_forgotten(ONE) && !state.is_forgotten(TWO));
        assert_eq!(state.forgotten_rooms(), [ONE]);
        assert!(state.remove_room("R1").is_none());

        // A message acknowledgement leaves the room tombstone; clearing it
        // by URI does not touch the message tombstones.
        state.clear_message_tombstones();
        assert!(state.is_forgotten(ONE));
        state.tombstones.insert(Tombstone::Message {
            room: "R2".into(),
            reference: Octets([9; 10]),
        });
        state.clear_room_tombstones(&[ONE.to_owned()]);
        assert!(!state.is_forgotten(ONE));
        assert!(state.is_deleted("R2", &[9; 10]));
    }

    #[test]
    fn a_removed_person_is_no_longer_found_by_user() {
        let mut state = State::new(ALICE);
        state.insert_person(Person {
            key: "P1".into(),
            user: "mimi://a.example/u/bob".into(),
            display_name: None,
            did: None,
            did_changed_at: None,
            first_seen: 0,
            ext: Ext::new(),
        });
        assert!(state.remove_person("P1").is_some());
        assert_eq!(state.person_of_user("mimi://a.example/u/bob"), None);
        assert!(state.remove_person("P1").is_none());
    }

    /// Bead mimid-2vcw: a hidden room is kept out until a message newer
    /// than every one it held; one delivered again is not newer.
    #[test]
    fn a_hidden_room_is_revealed_only_by_a_newer_message() {
        const ONE: &str = "mimi://a.example/r/one";
        const TWO: &str = "mimi://a.example/r/two";
        let mut state = State::new("mimi://a.example/u/bob".to_owned());
        state.hide_room("missing");
        assert!(state.hidden_rooms().is_empty());
        state.tombstones.insert(Tombstone::HiddenRoom {
            key: "k".to_owned(),
            uri: ONE.to_owned(),
            after: 500,
        });
        assert!(state.is_hidden(ONE) && state.is_forgotten(ONE));
        assert!(state.forgotten_rooms().is_empty(), "not a deleted room");
        assert!(!state.reveal_hidden_room(ONE, 499));
        assert!(!state.reveal_hidden_room(ONE, 500), "delivered again");
        assert!(!state.reveal_hidden_room(TWO, 501), "another room");
        assert!(state.is_hidden(ONE));
        assert!(state.reveal_hidden_room(ONE, 501));
        assert!(!state.is_hidden(ONE) && !state.is_forgotten(ONE));
    }
}
