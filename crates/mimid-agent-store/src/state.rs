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
    Ban, Deletion, Ext, Invite, Key, Message, Octets, Person, ReadPosition, Revision, Room,
    Tombstone,
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
    /// and rooms.
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
                .chain(message.aliases.iter().map(|alias| alias.0));
            for reference in references {
                indexes
                    .message_of_ref
                    .insert((message.room.clone(), reference), key.clone());
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
            .chain(message.aliases.iter().map(|alias| alias.0));
        for reference in references {
            self.indexes
                .message_of_ref
                .insert((message.room.clone(), reference), message.key.clone());
        }
        self.messages.insert(message.key.clone(), message);
    }

    /// Adds `alias`, the reference octets of a later version, to message
    /// `key`, and indexes it; false if there is no such message.
    pub fn add_alias(&mut self, key: &str, alias: MessageRef) -> bool {
        let Some(message) = self.messages.get_mut(key) else {
            return false;
        };
        message.aliases.push(crate::record::Octets(alias));
        self.indexes
            .message_of_ref
            .insert((message.room.clone(), alias), key.to_owned());
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
            .chain(message.aliases.iter().map(|alias| alias.0));
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
    /// (mimi-content-10 §5.6): its content goes, with the kept report
    /// record and any attachment still to fetch. The retraction's alias
    /// is the caller's to add. False if there is no such message.
    pub fn retract_message(&mut self, key: &str, at: u64) -> bool {
        let Some(message) = self.messages.get_mut(key) else {
            return false;
        };
        message.deleted = Some(Deletion { at, for_all: true });
        message.body = String::new();
        message.attachments.clear();
        message.edit_history.clear();
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

    /// Removes room `key` and its read positions. Its messages and bans
    /// stay, naming a room the store does not hold (bead mimid-1vul.9 is
    /// to delete them as well).
    pub fn remove_room(&mut self, key: &str) -> Option<Room> {
        let room = self.rooms.remove(key)?;
        self.read_positions.retain(|_, r| r.room != key);
        self.reindex();
        Some(room)
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
    use crate::record::{Participant, RoomStatus, Sender};
    use crate::report::KeptFrank;

    const ALICE: &str = "mimi://a.example/u/alice";

    fn message(key: &str, room: &str, body: &str) -> Message {
        Message {
            key: key.into(),
            room: room.into(),
            seq: 1,
            sender: Sender::User(ALICE.into()),
            mimi_id: None,
            aliases: Vec::new(),
            accepted_at: 1_000,
            sender_msg_id: "01M7VA1QTK2Y4V6ER4Z3A3V6QN".into(),
            body: body.into(),
            body_type: BodyType::Plain,
            in_reply_to: None,
            topic_id: None,
            attachments: vec![crate::record::Attachment {
                blob_id: "s00".into(),
                file_name: "a.txt".into(),
                media_type: "text/plain".into(),
                size: 1,
                sha256: "00".into(),
            }],
            edit_history: Vec::new(),
            edited_at: None,
            deleted: None,
            kept_frank: Some(KeptFrank {
                room: "mimi://a.example/r/one".into(),
                message: "00".into(),
                unverified: true,
            }),
            notice: None,
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

    #[test]
    fn a_removed_room_takes_its_read_positions_but_not_its_messages() {
        let mut state = State::new(ALICE);
        state.insert_room(Room {
            key: "R1".into(),
            uri: "mimi://a.example/r/one".into(),
            name: None,
            status: RoomStatus::Active,
            participants: vec![Participant {
                user: Some(ALICE.into()),
                role: Some(2),
            }],
            role_names: BTreeMap::new(),
            ext: Ext::new(),
        });
        state.insert_message(message("M1", "R1", "hello"));
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
        assert!(state.remove_room("R1").is_some());
        assert_eq!(state.room_of_uri("mimi://a.example/r/one"), None);
        assert!(state.messages.contains_key("M1"));
        assert_eq!(state.read_positions.keys().collect::<Vec<_>>(), vec!["C2"]);
        assert!(state.remove_room("R1").is_none());
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
}
