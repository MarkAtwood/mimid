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
//! `members`), and the save is the one place that sees every object. A
//! record without `ext["jmap"]` has no JMAP object.
//!
//! What a rendering cannot know comes from `ext["jmap"]`: a Chat's
//! `members`, `createdAt` and the other JMAP-only properties, a
//! Message's `receivedAt`, the date texts a client wrote with more or
//! fewer digits than the store keeps, and the JMAP id of a user who is
//! not known (§7.7). A rendering fills those deterministically
//! ([`EPOCH`], [`UNKNOWN_ID`], `sentAt` for `receivedAt`), so the same
//! record always renders the same.
//!
//! # Limitations
//!
//! - In `ext["jmap"]`, null stands for a property the object lacks. An
//!   object holding an explicit null in a property its type does not name
//!   (crate-jmap's `extra`) comes back without it; `AgentChat::save`
//!   warns of any object it could not keep exactly.

use jmap_chat_types::{
    BodyType, Chat, ChatBan, ChatContact, ChatKind, DeliveryState, Message, ReadPosition,
};
use jmap_server::{Id, UTCDate};
use mimid_agent_store::State;
use mimid_agent_store::convert::utc_date;
use mimid_agent_store::record::{self, Reply, Sender};
use serde_json::{Map, Value, json};

use crate::backend::ROOM_ID;
use crate::project::message_content;

pub(crate) use mimid_agent_store::merge::JMAP;

/// A date a rendering needs and the record does not hold (a Chat's or a
/// ChatBan's `createdAt`); the object's own is in `ext["jmap"]`.
pub(crate) const EPOCH: &str = "1970-01-01T00:00:00Z";

/// The JMAP id a rendering gives a user who is not known, or who has no
/// ChatContact; the object's own is in `ext["jmap"]`.
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

/// Renders records as JMAP objects, naming users as the backend does: the
/// accountId for the user, else the ChatContact of their person record.
pub(crate) struct Render<'a> {
    pub(crate) state: &'a State,
    pub(crate) account: &'a Id,
    pub(crate) user: &'a str,
}

impl Render<'_> {
    fn id_of(&self, user: Option<&str>) -> Id {
        match user {
            Some(user) if user == self.user => self.account.clone(),
            Some(user) => self
                .state
                .person_of_user(user)
                .map_or_else(|| Id::from(UNKNOWN_ID), |key| Id::from(key.as_str())),
            None => Id::from(UNKNOWN_ID),
        }
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

    /// A room as a group Chat, without its `members`.
    pub(crate) fn room(&self, room: &record::Room) -> Result<Map<String, Value>, String> {
        let mut chat = Chat::new(
            Id::from(room.key.as_str()),
            ChatKind::Group,
            UTCDate::from(EPOCH),
            0,
            vec![],
            false,
            true,
        );
        chat.name.clone_from(&room.name);
        chat.extra.insert(ROOM_ID.to_owned(), json!(room.uri));
        Ok(object(normal::<Chat>(
            serde_json::to_value(chat).map_err(|e| e.to_string())?,
        )?))
    }

    /// A message as a Message, `sentAt` and `receivedAt` its acceptance
    /// time; a notice is the account's.
    pub(crate) fn message(&self, message: &record::Message) -> Result<Map<String, Value>, String> {
        let sender = match &message.sender {
            Sender::User(user) => self.id_of(Some(user)),
            Sender::Agent => self.account.clone(),
            _ => self.id_of(None),
        };
        let at = date(message.accepted_at);
        let mut jmap = Message::new(
            Id::from(message.key.as_str()),
            Id::from(message.sender_msg_id.as_str()),
            sender,
            Id::from(message.room.as_str()),
            String::new(),
            BodyType::Plain,
            at.clone(),
            at,
            DeliveryState::Delivered,
        );
        jmap.reply_to = match &message.in_reply_to {
            Some(Reply::Message(target)) => Some(Id::from(target.as_str())),
            _ => None,
        };
        jmap.topic_id.clone_from(&message.topic_id);
        let mut value = object(serde_json::to_value(jmap).map_err(|e| e.to_string())?);
        value.extend(message_content(message));
        Ok(object(normal::<Message>(Value::Object(value))?))
    }

    /// A ban as a ChatBan.
    pub(crate) fn ban(&self, ban: &record::Ban) -> Result<Map<String, Value>, String> {
        let mut chat_ban = ChatBan::new(
            Id::from(ban.key.as_str()),
            Id::from(ban.room.as_str()),
            self.id_of(ban.user.as_deref()),
            self.id_of(ban.banned_by.as_deref()),
            UTCDate::from(EPOCH),
        );
        chat_ban.reason.clone_from(&ban.reason);
        chat_ban.expires_at = ban.expires_at.map(date);
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
    use mimid_agent_store::merge::merge_object;

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

    /// Each object, written into the records as a JMAP write is, renders
    /// back to itself with what `ext["jmap"]` keeps, and the rest of what
    /// it says is the record's, not kept twice.
    #[test]
    fn every_object_renders_back_exactly() {
        let mut state = State::new(BOB);
        let objects: Vec<_> = objects()
            .into_iter()
            .map(|(t, v)| (t, typed(t, v)))
            .collect();
        for (type_name, object) in &objects {
            merge_object(&mut state, "bob", type_name, object.clone(), false).unwrap();
        }
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
        // What the store knows: the sender is unknown; the dates it holds
        // are the same millisecond as the text kept beside them.
        assert_eq!(
            state.messages["M1"].sender,
            mimid_agent_store::record::Sender::Unknown
        );
        let m2 = render.message(&state.messages["M2"]).unwrap();
        assert!(
            not_rendered(&objects[3].1, &m2)
                .get("editHistory")
                .is_none()
        );
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
