//! How the JMAP front end keeps its objects in the store's database
//! (docs/design/agent-frontends.md §3 step 4): each record is rendered as
//! a JMAP object from what the record holds ([`Render`]), and the record's
//! `ext["jmap"]` holds every property of the object as the backend has it
//! that the rendering does not give exactly ([`not_rendered`]). Rendering
//! a record and laying its `ext["jmap"]` over it ([`laid_over`]) gives the
//! object back as it was saved, octet for octet once serialized, so a
//! restart changes nothing a client reads.
//!
//! `ext["jmap"]` is rebuilt from the backend's objects at each save
//! (`AgentChat::save`), not kept current between saves: the backend
//! changes JMAP-only properties itself (`unreadCount`, a Chat's
//! `members`), and the save is the one place that sees every object.
//!
//! A record without `ext["jmap"]` was made while no JMAP front end was
//! registered on the store (JMAP off, an IRC-only run). It is shown as a
//! new object, made as the projection makes one when a sync brings the
//! record ([`Render::new_chat`], [`Render::new_message`],
//! [`Render::new_ban`]; a person and a read position as they render),
//! and the next save keeps it in `ext["jmap"]`
//! (docs/design/agent-frontends.md §7.11).
//!
//! What a rendering cannot know comes from `ext["jmap"]`: a Chat's
//! `members`, `createdAt` and the other JMAP-only properties, the date
//! texts a client wrote with more or fewer digits than the store keeps,
//! and the JMAP id of a user who has no ChatContact (one a client
//! destroyed). A rendering fills those deterministically ([`EPOCH`],
//! [`UNKNOWN_ID`]), so the same record always renders the same. A
//! Message's `receivedAt` is the record's `received_at`, its arrival
//! here (docs/design/agent-frontends.md §7.18).
//!
//! # Limitations
//!
//! - In `ext["jmap"]`, null stands for a property the object lacks. An
//!   object holding an explicit null in a property its type does not name
//!   (crate-jmap's `extra`) comes back without it; `AgentChat::save`
//!   warns of any object it could not keep exactly.

use jmap_chat_types::{
    BodyType, Chat, ChatBan, ChatContact, ChatKind, ChatMember, ChatMemberRole, DeliveryState,
    Message, ReadPosition,
};
use jmap_server::{Id, UTCDate};
use mimid_agent_store::State;
use mimid_agent_store::convert::utc_date;
use mimid_agent_store::record::{self, Reply, RoomStatus, Sender};
use mimid_agent_store::sync::bans::BANNED_ROLE_INDEX;
use serde_json::{Map, Value, json};

use crate::backend::ROOM_ID;
use crate::project::{message_content, shown_content};

/// The Message property that carries a message's `mimid-on-behalf-of`
/// extension ([`Render::on_behalf_of`]): a vendor property, named with a
/// domain and a colon as RFC 8620 §1.8 asks of extensions not
/// registered. INVENTED, NOT FROM SPEC.
pub(crate) const ON_BEHALF_OF: &str = "mimid.invalid:onBehalfOf";

/// The front-end name the JMAP front end keeps its properties under in a
/// record's `ext`.
pub(crate) const JMAP: &str = "jmap";

/// A date a rendering needs and the record does not hold (a Chat's or a
/// ChatBan's `createdAt`); the object's own is in `ext["jmap"]`.
pub(crate) const EPOCH: &str = "1970-01-01T00:00:00Z";

/// The JMAP id a rendering gives a user who has no ChatContact; the
/// object's own is in `ext["jmap"]`.
pub(crate) const UNKNOWN_ID: &str = "unknown";

/// `value` through the JMAP type `T`, as the backend serializes it.
fn normal<T: serde::de::DeserializeOwned + serde::Serialize>(
    value: Value,
) -> Result<Value, String> {
    let typed: T = serde_json::from_value(value).map_err(|e| e.to_string())?;
    serde_json::to_value(typed).map_err(|e| e.to_string())
}

fn object(value: Value) -> Map<String, Value> {
    match value {
        Value::Object(map) => map,
        _ => Map::new(),
    }
}

fn date(ms: u64) -> UTCDate {
    UTCDate::from(utc_date(ms).as_str())
}

/// A message's expiry as draft-atwood-jmap-chat-00 §Message names it
/// (docs/design/agent-frontends.md §7.20, §7.22): `senderExpiresAt`,
/// `burnOnRead` and `expiresAfterReadSeconds`, null where it asks nothing.
pub(crate) fn expiry_props(message: &record::Message) -> Map<String, Value> {
    let expiry = &message.expiry;
    let mut fields = Map::new();
    fields.insert(
        "senderExpiresAt".to_owned(),
        expiry
            .sender_expires_at
            .map_or(Value::Null, |at| json!(utc_date(at))),
    );
    fields.insert(
        "burnOnRead".to_owned(),
        if expiry.burn_on_read {
            json!(true)
        } else {
            Value::Null
        },
    );
    fields.insert(
        "expiresAfterReadSeconds".to_owned(),
        json!(expiry.expires_after_read_seconds),
    );
    fields
}

/// Renders records as JMAP objects, naming users as the backend does: the
/// accountId for the user, else the ChatContact of their person record.
pub(crate) struct Render<'a> {
    pub(crate) state: &'a State,
    pub(crate) account: &'a Id,
    pub(crate) user: &'a str,
}

impl Render<'_> {
    /// The JMAP id that names `user`: the accountId for the user, else the
    /// ChatContact of their person record, if they have one.
    pub(crate) fn known_id(&self, user: &str) -> Option<Id> {
        if user == self.user {
            return Some(self.account.clone());
        }
        self.state
            .person_of_user(user)
            .map(|key| Id::from(key.as_str()))
    }

    fn id_of(&self, user: &str) -> Id {
        self.known_id(user).unwrap_or_else(|| Id::from(UNKNOWN_ID))
    }

    /// The ChatMembers of `room`, keeping the entries of `existing` for
    /// those already members; new entries are joined at `joined_at`. Each
    /// one's role is the room's (decision mimid-1wgh.62 item 9): `admin`
    /// for a participant whose role is named "admin", `member` otherwise;
    /// a banned participant (role 1, "banned") is not a member, and
    /// neither is a user with no ChatContact.
    pub(crate) fn members(
        &self,
        room: &record::Room,
        existing: &[ChatMember],
        joined_at: &UTCDate,
    ) -> Vec<ChatMember> {
        let mut members = Vec::with_capacity(room.participants.len());
        for participant in &room.participants {
            let name = participant
                .role
                .and_then(|index| room.role_names.get(&index).map(|n| (index, n.as_str())));
            let role = match name {
                Some((BANNED_ROLE_INDEX, "banned")) => continue,
                Some((_, "admin")) => ChatMemberRole::Admin,
                _ => ChatMemberRole::Member,
            };
            let Some(id) = self.known_id(&participant.user) else {
                continue;
            };
            members.push(match existing.iter().find(|m| m.id == id) {
                Some(m) => {
                    let mut m = m.clone();
                    m.role = role;
                    m
                }
                None => ChatMember::new(id, role, joined_at.clone()),
            });
        }
        members
    }

    /// Whether `room` is a call's own room, which this front end does
    /// not show as a Chat: `kind` (draft-atwood-jmap-chat-00 §Chat) has
    /// no value describing a call, so a Chat for one appears among the
    /// user's conversations, where it is not one (decision
    /// mimid-1wgh.120 as corrected by bead mimid-1wgh.121).
    ///
    /// A Chat here is a projection of the record, not the room's message
    /// container as it is at the provider
    /// (draft-atwood-jmap-chat-mimi-00 §Chat.roomId), so leaving one out
    /// loses nothing: the store keeps the room, and the call is reached
    /// through the VTC surface.
    #[must_use]
    pub(crate) fn is_call_room(room: &record::Room) -> bool {
        room.parent.is_some()
    }

    /// A call's own room AS the `VTCCall` for it: the call is the room,
    /// and this is derived on every read rather than stored (Mark
    /// 2026-11-25).
    ///
    /// There is no stored call object and so nothing to keep in step.
    /// The id is the room's store key, which is what makes that
    /// possible: a call created here and a call this agent was invited
    /// to get the same id by the same rule, so a read and a create
    /// cannot disagree and a restart loses nothing.
    ///
    /// `None` for a room with no parent, or one whose parent room this
    /// agent is not in: there would be no chat for a client to show the
    /// call against. Also `None` for a room the user is leaving or has
    /// left, which is how a call ends here.
    ///
    /// # Limitations
    ///
    /// - `createdAt` is [`EPOCH`], because `record::Room` keeps no
    ///   creation time and a derived object must be the same on every
    ///   read. Answering `now()` instead would change the object each
    ///   time a client fetched it.
    /// - `endedAt` and `endReason` are absent. Nothing in the room says
    ///   why a call stopped, and a call that has stopped is a room the
    ///   user is no longer in, which this returns `None` for.
    /// - `mediaTypes` is empty and `subject` absent: the room carries
    ///   neither, and the announcement that used to carry them is gone.
    ///   The SDP is what says which media a call carries.
    /// - `initiatorId` is the call room's admin by the role naming this
    ///   module already uses, not a recorded "who pressed call". With no
    ///   admin it is the first participant.
    pub(crate) fn new_call(&self, room: &record::Room) -> Option<Value> {
        if room.status != RoomStatus::Active {
            return None;
        }
        let parent = room.parent.as_deref()?;
        let chat = self.state.room_of_uri(parent)?;
        let initiator = room
            .participants
            .iter()
            .find(|p| {
                p.role
                    .and_then(|index| room.role_names.get(&index))
                    .is_some_and(|name| name == "admin")
            })
            .or_else(|| room.participants.first())
            .map(|p| p.user.clone())
            .unwrap_or_default();
        Some(json!({
            "id": room.key,
            "accountId": self.account,
            "callType": "room",
            "state": "active",
            "createdAt": EPOCH,
            "endedAt": Value::Null,
            "endReason": Value::Null,
            "initiatorId": initiator,
            "subject": Value::Null,
            "joinUri": "",
            "joinPassword": Value::Null,
            "mediaTypes": [],
            "activeParticipantCount": room.participants.len(),
            "parentCallId": Value::Null,
            "scheduledStartAt": Value::Null,
            "gatewayPin": Value::Null,
            "chatId": chat,
            crate::vtc_backend::MIMI_ROOM_ID: room.uri,
        }))
    }

    /// A room as the group Chat made for it when first shown, created and
    /// its members joined at `created_at`: named by the room's name (empty
    /// without one), `unreadCount` 0 (crate-jmap computes it at each
    /// `Chat/get`), no pins, not muted. The user is not a member of a room
    /// they are leaving or have left.
    pub(crate) fn new_chat(&self, room: &record::Room, created_at: UTCDate) -> Chat {
        let mut members = self.members(room, &[], &created_at);
        if room.status != RoomStatus::Active {
            members.retain(|m| m.id != *self.account);
        }
        let mut chat = Chat::new(
            Id::from(room.key.as_str()),
            self.kind(room),
            created_at,
            0,
            vec![],
            false,
            true,
        );
        if room.direct {
            chat.contact_id = self.contact_of(room);
        } else {
            chat.name = Some(room.name.clone().unwrap_or_default());
            chat.members = Some(members);
        }
        chat.message_expiry_seconds = room.message_expiry_seconds;
        chat.extra.insert(ROOM_ID.to_owned(), json!(room.uri));
        chat
    }

    /// A message as the Message made for it when first shown: `sentAt` its
    /// acceptance time, `receivedAt` its arrival here, delivered, its
    /// content as shown (a message deleted here alone emptied); a notice
    /// is the account's.
    ///
    /// # Errors
    ///
    /// The JMAP type refuses the object it makes.
    pub(crate) fn new_message(&self, message: &record::Message) -> Result<Message, String> {
        let sender = match &message.sender {
            Sender::User(user) => self.id_of(user),
            // A notice is the account's (bead mimid-1wgh.4.81.27); Sender
            // is #[non_exhaustive].
            _ => self.account.clone(),
        };
        let mut jmap = Message::new(
            Id::from(message.key.as_str()),
            Id::from(message.sender_msg_id.as_str()),
            sender,
            Id::from(message.room.as_str()),
            String::new(),
            BodyType::Plain,
            date(message.accepted_at),
            date(message.received_at),
            DeliveryState::Delivered,
        );
        jmap.reply_to = match &message.in_reply_to {
            Some(Reply::Message(target)) => Some(Id::from(target.as_str())),
            _ => None,
        };
        jmap.topic_id.clone_from(&message.topic_id);
        let mut value = object(serde_json::to_value(jmap).map_err(|e| e.to_string())?);
        value.extend(shown_content(message));
        value.extend(expiry_props(message));
        value.insert("reactions".to_owned(), self.reactions(message));
        if let on_behalf_of @ Value::Object(_) = Self::on_behalf_of(message) {
            value.insert(ON_BEHALF_OF.to_owned(), on_behalf_of);
        }
        serde_json::from_value(Value::Object(value)).map_err(|e| e.to_string())
    }

    /// A message's reactions as JMAP Chat's `reactions` map
    /// (draft-atwood-jmap-chat-00 §Reaction): each under its key
    /// ([`record::Reaction::key`], the `senderReactionId`), with `emoji`
    /// the reaction, `senderId` the accountId or the reacting user's
    /// ChatContact, and `sentAt` the hub's acceptance time.
    pub(crate) fn reactions(&self, message: &record::Message) -> Value {
        let mut map = Map::new();
        for r in &message.reactions {
            map.insert(
                r.key.clone(),
                json!({
                    "emoji": r.reaction,
                    "senderId": self.id_of(&r.sender),
                    "sentAt": utc_date(r.accepted_at),
                }),
            );
        }
        Value::Object(map)
    }

    /// The [`ON_BEHALF_OF`] property of a message: its
    /// `mimid-on-behalf-of` extension (docs/design/marmot-bridge.md §3.2)
    /// as `{"uri", "name", "src"}`, or null. Data for a client to show as
    /// "name (via sender)"; never a sender of its own.
    pub(crate) fn on_behalf_of(message: &record::Message) -> Value {
        match message.on_behalf_of() {
            Some(o) => json!({"uri": o.uri, "name": o.name, "src": o.src}),
            None => Value::Null,
        }
    }

    /// A ban as the ChatBan made for it when first shown, created at
    /// `created_at`, with the record's reason and expiry.
    pub(crate) fn new_ban(&self, ban: &record::Ban, created_at: UTCDate) -> ChatBan {
        let mut chat_ban = ChatBan::new(
            Id::from(ban.key.as_str()),
            Id::from(ban.room.as_str()),
            self.id_of(&ban.user),
            self.id_of(&ban.banned_by),
            created_at,
        );
        chat_ban.reason.clone_from(&ban.reason);
        chat_ban.expires_at = ban.expires_at.map(date);
        chat_ban
    }

    /// A person as a ChatContact.
    pub(crate) fn person(&self, person: &record::Person) -> Result<Map<String, Value>, String> {
        let seen = date(person.first_seen);
        let contact = ChatContact::new(
            Id::from(person.key.as_str()),
            person.user.clone(),
            person.user.clone(),
            seen.clone(),
            seen,
            false,
        );
        let mut value = object(serde_json::to_value(contact).map_err(|e| e.to_string())?);
        value.insert("displayName".to_owned(), json!(person.display_name));
        value.insert("did".to_owned(), json!(person.did));
        value.insert(
            "didChangedAt".to_owned(),
            json!(person.did_changed_at.map(utc_date)),
        );
        Ok(object(normal::<ChatContact>(Value::Object(value))?))
    }

    /// The kind of a room's Chat (draft-atwood-jmap-chat-00 §Chat):
    /// `direct` for a one-to-one room ([`record::Room::direct`]), else
    /// `group`.
    pub(crate) fn kind(&self, room: &record::Room) -> ChatKind {
        if room.direct {
            ChatKind::Direct
        } else {
            ChatKind::Group
        }
    }

    /// The `contactId` of a one-to-one room's Chat: the ChatContact of
    /// its other participant ([`record::Room::direct_peer`]), else of the
    /// first participant who is not the user.
    pub(crate) fn contact_of(&self, room: &record::Room) -> Option<Id> {
        let peer = room.direct_peer(self.user).or_else(|| {
            room.participants
                .iter()
                .map(|p| p.user.as_str())
                .find(|u| *u != self.user)
        })?;
        self.known_id(peer)
    }

    /// A room as a Chat, without the `members` of a group Chat.
    pub(crate) fn room(&self, room: &record::Room) -> Result<Map<String, Value>, String> {
        let mut chat = Chat::new(
            Id::from(room.key.as_str()),
            self.kind(room),
            UTCDate::from(EPOCH),
            0,
            vec![],
            false,
            true,
        );
        if room.direct {
            chat.contact_id = self.contact_of(room);
        } else {
            chat.name.clone_from(&room.name);
        }
        chat.message_expiry_seconds = room.message_expiry_seconds;
        chat.extra.insert(ROOM_ID.to_owned(), json!(room.uri));
        Ok(object(normal::<Chat>(
            serde_json::to_value(chat).map_err(|e| e.to_string())?,
        )?))
    }

    /// A message as a Message, `sentAt` its acceptance time and
    /// `receivedAt` its arrival here; a notice is the account's.
    pub(crate) fn message(&self, message: &record::Message) -> Result<Map<String, Value>, String> {
        let sender = match &message.sender {
            Sender::User(user) => self.id_of(user),
            // Sender is #[non_exhaustive]; a notice and anything else is
            // the account's.
            _ => self.account.clone(),
        };
        let mut jmap = Message::new(
            Id::from(message.key.as_str()),
            Id::from(message.sender_msg_id.as_str()),
            sender,
            Id::from(message.room.as_str()),
            String::new(),
            BodyType::Plain,
            date(message.accepted_at),
            date(message.received_at),
            DeliveryState::Delivered,
        );
        jmap.reply_to = match &message.in_reply_to {
            Some(Reply::Message(target)) => Some(Id::from(target.as_str())),
            _ => None,
        };
        jmap.topic_id.clone_from(&message.topic_id);
        let mut value = object(serde_json::to_value(jmap).map_err(|e| e.to_string())?);
        value.extend(message_content(message));
        value.extend(expiry_props(message));
        value.insert("reactions".to_owned(), self.reactions(message));
        if let on_behalf_of @ Value::Object(_) = Self::on_behalf_of(message) {
            value.insert(ON_BEHALF_OF.to_owned(), on_behalf_of);
        }
        Ok(object(normal::<Message>(Value::Object(value))?))
    }

    /// A ban as a ChatBan.
    pub(crate) fn ban(&self, ban: &record::Ban) -> Result<Map<String, Value>, String> {
        let chat_ban = self.new_ban(ban, UTCDate::from(EPOCH));
        Ok(object(normal::<ChatBan>(
            serde_json::to_value(chat_ban).map_err(|e| e.to_string())?,
        )?))
    }

    /// A read position as a ReadPosition.
    pub(crate) fn read_position(
        &self,
        position: &record::ReadPosition,
    ) -> Result<Map<String, Value>, String> {
        let mut jmap = ReadPosition::new(
            Id::from(position.key.as_str()),
            Id::from(position.room.as_str()),
        );
        jmap.last_read_message_id = position.message.as_deref().map(Id::from);
        jmap.last_read_at = position.at.map(date);
        Ok(object(normal::<ReadPosition>(
            serde_json::to_value(jmap).map_err(|e| e.to_string())?,
        )?))
    }
}

/// The properties of `object` (as the backend serializes it) that
/// `rendered` does not give exactly, with null for each property
/// `rendered` has and `object` lacks: what `ext["jmap"]` keeps.
pub(crate) fn not_rendered(
    object: &Map<String, Value>,
    rendered: &Map<String, Value>,
) -> Map<String, Value> {
    let mut kept: Map<String, Value> = object
        .iter()
        .filter(|(k, v)| rendered.get(*k) != Some(*v))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    for k in rendered.keys() {
        if !object.contains_key(k) {
            kept.insert(k.clone(), Value::Null);
        }
    }
    kept
}

/// `ext` laid over `rendered`: each property set, or taken out for null,
/// then through the JMAP type `T`.
pub(crate) fn laid_over<T: serde::de::DeserializeOwned + serde::Serialize>(
    mut rendered: Map<String, Value>,
    ext: &Map<String, Value>,
) -> Result<Map<String, Value>, String> {
    for (k, v) in ext {
        if v.is_null() {
            rendered.remove(k);
        } else {
            rendered.insert(k.clone(), v.clone());
        }
    }
    Ok(object(normal::<T>(Value::Object(rendered))?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use mimid_agent_store::content::BodyType as Body;
    use mimid_agent_store::convert::parse_utc_date;
    use mimid_agent_store::record::{
        Ban, Deletion, Message as MessageRecord, Participant, Person, ReadPosition as Position,
        Revision, Room,
    };
    use mimid_agent_store::{State, accepted_at_of};

    const BOB: &str = "mimi://a.example/u/bob";

    /// Objects as the backend holds them, with what the store cannot
    /// say: dates with `.000Z` and with six digits, a Chat's members and
    /// unread count, a sender whose ChatContact is gone, a local deletion.
    fn objects() -> Vec<(&'static str, Value)> {
        vec![
            (
                "ChatContact",
                json!({"id": "P1", "identity": "mimi://a.example/u/alice",
                "login": "mimi://a.example/u/alice", "firstSeenAt": "2026-11-20T01:45:00.000Z",
                "lastSeenAt": "2026-11-20T01:46:00Z", "blocked": false,
                "displayName": "Alice A."}),
            ),
            (
                "Chat",
                json!({"id": "R1", "kind": "group", "createdAt": "2026-11-20T01:45:00.087Z",
                "unreadCount": 2, "pinnedMessageIds": [], "muted": false,
                "receiveTypingIndicators": true, "name": "kept",
                "roomId": "mimi://a.example/r/one",
                "members": [{"id": "P1", "role": "admin", "joinedAt": "2026-11-20T01:45:00Z"},
                            {"id": "bob", "role": "member",
                             "joinedAt": "2026-11-20T01:45:00Z"}]}),
            ),
            (
                "Message",
                json!({"id": "M1", "senderMsgId": "01M7VA1QTK2Y4V6ER4Z3A3V6QN",
                "senderId": "gone", "chatId": "R1", "body": "hello", "bodyType": "text/plain",
                "attachments": [],
                "sentAt": "2026-11-20T01:45:00.499Z", "receivedAt": "2026-11-20T01:45:00.937Z",
                "deliveryState": "delivered", "readAt": "2026-11-20T01:47:00.123456Z",
                "deletedAt": "2026-11-20T01:48:00.000Z"}),
            ),
            (
                "Message",
                json!({"id": "M2", "senderMsgId": "01M7VA1SH7BF44J3XAZZRD6RXZ",
                "senderId": "bob", "chatId": "R1", "body": "after", "bodyType": "text/plain",
                "attachments": [],
                "sentAt": "2026-11-16T12:00:00Z", "receivedAt": "2026-11-20T01:45:02.887Z",
                "deliveryState": "delivered", "editedAt": "2026-11-20T01:45:03.069Z",
                "editHistory": [{"body": "before", "bodyType": "text/plain",
                                 "editedAt": "2026-11-20T01:45:03.069Z"}]}),
            ),
            (
                "ChatBan",
                json!({"id": "B1", "chatId": "GONE", "userId": "P1", "bannedBy": "bob",
                "createdAt": "2026-11-20T01:45:14.237Z", "reason": "spam",
                "expiresAt": "2030-01-01T00:00:00.000Z"}),
            ),
            (
                "ReadPosition",
                json!({"id": "C1", "chatId": "R1", "lastReadMessageId": "M2",
                "lastReadAt": "2026-11-20T01:47:00.1Z"}),
            ),
        ]
    }

    fn typed(type_name: &str, value: Value) -> Map<String, Value> {
        object(
            match type_name {
                "ChatContact" => normal::<ChatContact>(value),
                "Chat" => normal::<Chat>(value),
                "ChatBan" => normal::<ChatBan>(value),
                "Message" => normal::<Message>(value),
                _ => normal::<ReadPosition>(value),
            }
            .unwrap(),
        )
    }

    fn ms(date: &str) -> u64 {
        parse_utc_date(date).unwrap()
    }

    /// The records of [`objects`], written out by hand: what the store
    /// holds of each, with users by URI. The sender of M1 ("gone") is a
    /// user whose person record a client destroyed.
    fn records() -> State {
        const ALICE: &str = "mimi://a.example/u/alice";
        const CAROL: &str = "mimi://a.example/u/carol";
        let mut state = State::new(BOB);
        state.insert_person(Person {
            key: "P1".into(),
            user: ALICE.into(),
            display_name: Some("Alice A.".into()),
            did: None,
            did_changed_at: None,
            first_seen: ms("2026-11-20T01:45:00.000Z"),
            ext: Default::default(),
        });
        state.insert_room(Room {
            key: "R1".into(),
            uri: "mimi://a.example/r/one".into(),
            name: Some("kept".into()),
            subject: None,
            subject_set: None,
            status: RoomStatus::Active,
            participants: [ALICE, BOB]
                .map(|user| Participant {
                    user: user.into(),
                    role: None,
                })
                .into(),
            role_names: Default::default(),
            message_expiry_seconds: None,
            direct: false,
            parent: None,
            ext: Default::default(),
        });
        let message = |key: &str, seq, sender: &str, id: &str, body: &str| MessageRecord {
            key: key.into(),
            room: "R1".into(),
            seq,
            sender: Sender::User(sender.into()),
            mimi_id: None,
            aliases: Vec::new(),
            accepted_at: accepted_at_of(id).unwrap(),
            received_at: 0,
            sender_msg_id: id.into(),
            body: body.into(),
            body_type: Body::Plain,
            in_reply_to: None,
            in_reply_to_id: None,
            topic_id: None,
            attachments: Vec::new(),
            extensions: Vec::new(),
            reactions: Vec::new(),
            calls: Vec::new(),
            edit_history: Vec::new(),
            edited_at: None,
            deleted: None,
            kept_frank: None,
            notice: None,
            expiry: Default::default(),
            read_at: None,
            ext: Default::default(),
        };
        let mut m1 = message("M1", 1, CAROL, "01M7VA1QTK2Y4V6ER4Z3A3V6QN", "hello");
        m1.received_at = ms("2026-11-20T01:45:00.937Z");
        m1.deleted = Some(Deletion {
            at: ms("2026-11-20T01:48:00.000Z"),
            for_all: false,
        });
        state.insert_message(m1);
        let mut m2 = message("M2", 2, BOB, "01M7VA1SH7BF44J3XAZZRD6RXZ", "after");
        m2.received_at = ms("2026-11-20T01:45:02.887Z");
        m2.edited_at = Some(ms("2026-11-20T01:45:03.069Z"));
        m2.edit_history = vec![Revision {
            body: "before".into(),
            body_type: Body::Plain,
            edited_at: ms("2026-11-20T01:45:03.069Z"),
        }];
        state.insert_message(m2);
        state.bans.insert(
            "B1".into(),
            Ban {
                key: "B1".into(),
                room: "GONE".into(),
                user: ALICE.into(),
                banned_by: BOB.into(),
                reason: Some("spam".into()),
                expires_at: Some(ms("2030-01-01T00:00:00.000Z")),
                ext: Default::default(),
            },
        );
        state.read_positions.insert(
            "C1".into(),
            Position {
                key: "C1".into(),
                room: "R1".into(),
                message: Some("M2".into()),
                at: Some(ms("2026-11-20T01:47:00.1Z")),
                ext: Default::default(),
            },
        );
        state
    }

    /// Each object renders back to itself from its record with what
    /// `ext["jmap"]` keeps, and the rest of what it says is the record's,
    /// not kept twice.
    #[test]
    fn every_object_renders_back_exactly() {
        let state = records();
        let objects: Vec<_> = objects()
            .into_iter()
            .map(|(t, v)| (t, typed(t, v)))
            .collect();
        let account = Id::from("bob");
        let render = Render {
            state: &state,
            account: &account,
            user: BOB,
        };
        for (type_name, object) in &objects {
            let id = object["id"].as_str().unwrap();
            let (rendered, back): (_, fn(_, &_) -> _) = match *type_name {
                "ChatContact" => (render.person(&state.people[id]), laid_over::<ChatContact>),
                "Chat" => (render.room(&state.rooms[id]), laid_over::<Chat>),
                "ChatBan" => (render.ban(&state.bans[id]), laid_over::<ChatBan>),
                "Message" => (render.message(&state.messages[id]), laid_over::<Message>),
                _ => (
                    render.read_position(&state.read_positions[id]),
                    laid_over::<ReadPosition>,
                ),
            };
            let rendered = rendered.unwrap();
            let kept = not_rendered(object, &rendered);
            assert_eq!(
                back(rendered, &kept).as_ref(),
                Ok(object),
                "{type_name} {id}"
            );
            for held in [
                "body",
                "identity",
                "roomId",
                "chatId",
                "reason",
                "displayName",
            ] {
                assert!(
                    !kept.contains_key(held),
                    "{type_name} {id} keeps {held} twice"
                );
            }
        }
        // What the store knows: the sender has no ChatContact, so the
        // rendering names none and ext["jmap"] keeps the object's; the
        // dates it holds are the same millisecond as the text kept beside
        // them.
        let m1 = render.message(&state.messages["M1"]).unwrap();
        assert_eq!(m1["senderId"], json!(UNKNOWN_ID));
        assert_eq!(not_rendered(&objects[2].1, &m1)["senderId"], json!("gone"));
        let m2 = render.message(&state.messages["M2"]).unwrap();
        assert!(
            not_rendered(&objects[3].1, &m2)
                .get("editHistory")
                .is_none()
        );
    }

    /// A record with no `ext["jmap"]` is made as the projection makes a
    /// new object: members from the participants (the user out of a room
    /// left), a locally deleted message emptied, a ban with its terms, and
    /// the dates given.
    #[test]
    fn records_without_ext_are_made_as_new_objects() {
        let mut state = records();
        let account = Id::from("bob");
        let at = UTCDate::from("2026-11-21T00:00:00.000Z");
        let render = Render {
            state: &state,
            account: &account,
            user: BOB,
        };
        let chat = serde_json::to_value(render.new_chat(&state.rooms["R1"], at.clone())).unwrap();
        assert_eq!(
            chat,
            json!({"id": "R1", "kind": "group", "createdAt": at, "unreadCount": 0,
                   "pinnedMessageIds": [], "muted": false, "receiveTypingIndicators": true,
                   "name": "kept", "roomId": "mimi://a.example/r/one",
                   "activeCallId": null, "activeCallAccountId": null,
                   "members": [{"id": "P1", "role": "member", "joinedAt": at},
                               {"id": "bob", "role": "member", "joinedAt": at}]})
        );
        let m1 = serde_json::to_value(render.new_message(&state.messages["M1"]).unwrap()).unwrap();
        assert_eq!(m1["senderId"], json!(UNKNOWN_ID));
        assert_eq!(m1["body"], json!(""));
        assert_eq!(m1["deletedAt"], json!("2026-11-20T01:48:00Z"));
        assert_eq!(m1["sentAt"], json!("2026-11-20T01:45:00.499Z"));
        assert_eq!(m1["receivedAt"], json!("2026-11-20T01:45:00.937Z"));
        let m2 = serde_json::to_value(render.new_message(&state.messages["M2"]).unwrap()).unwrap();
        assert_eq!(m2["senderId"], json!("bob"));
        assert_eq!(m2["body"], json!("after"));
        assert_eq!(m2["editHistory"][0]["body"], json!("before"));
        let ban = serde_json::to_value(render.new_ban(&state.bans["B1"], at.clone())).unwrap();
        assert_eq!(
            ban,
            json!({"id": "B1", "chatId": "GONE", "userId": "P1", "bannedBy": "bob",
                   "createdAt": at, "reason": "spam", "expiresAt": "2030-01-01T00:00:00Z"})
        );
        state.rooms.get_mut("R1").unwrap().status = RoomStatus::Leaving;
        let render = Render {
            state: &state,
            account: &account,
            user: BOB,
        };
        let left = render.new_chat(&state.rooms["R1"], at);
        let ids: Vec<_> = left.members.unwrap().into_iter().map(|m| m.id).collect();
        assert_eq!(ids, [Id::from("P1")]);
    }

    #[test]
    fn what_is_not_rendered_lays_back_to_the_object() {
        let object = json!({"id": "c1", "chatId": "r1", "lastReadAt": "2026-11-20T01:45:00.000Z",
                            "x": 1});
        let rendered = json!({"id": "c1", "chatId": "r1", "lastReadAt": "2026-11-20T01:45:00Z",
                              "lastReadMessageId": "m1"});
        let (object, rendered) = (super::object(object), super::object(rendered));
        let kept = not_rendered(&object, &rendered);
        assert_eq!(
            Value::Object(kept.clone()),
            json!({"lastReadAt": "2026-11-20T01:45:00.000Z", "x": 1, "lastReadMessageId": null})
        );
        assert_eq!(laid_over::<ReadPosition>(rendered, &kept).unwrap(), object);
    }
}
