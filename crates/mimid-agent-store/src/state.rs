//! The store's in-memory state: every record, and the indexes rebuilt from
//! them at load.
//!
//! # Limitations
//!
//! - [`State::reindex`] walks every record; the `insert_*` methods keep
//!   the indexes without it.

use std::collections::BTreeMap;

use crate::convert::MessageRef;
use crate::record::{Ban, Ext, Invite, Key, Message, Person, ReadPosition, Room};
use crate::retry::PendingAttachment;

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
