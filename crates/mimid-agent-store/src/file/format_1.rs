//! The format-1 reader: `chat.json` as mimid-agent-jmap's `persist`
//! writes it, converted to records.
//!
//! Format 1 is `{format: 1, account, objects, pending_attachments?,
//! franks?, mimi_ids?}`, where `objects` maps each JMAP type name
//! (ChatContact, Chat, ChatBan, Message, ReadPosition) to its objects as
//! JSON, and the side tables are keyed by Message id. The conversion:
//!
//! - every JMAP id becomes the record's key, and the JMAP accountId goes
//!   into the state's `ext["jmap"]["account"]`;
//! - a JMAP id naming the account (a member, a sender, a banner) becomes
//!   the user's own URI, and one naming a ChatContact becomes that
//!   contact's `identity`;
//! - every property of an object that its record does not hold goes into
//!   the record's `ext["jmap"]` unchanged ([`JMAP`]); Chat `members` goes
//!   there as well as into the participants, since its roles and times
//!   are JMAP's;
//! - a Message's acceptance time is its `senderMsgId`'s ULID time, and
//!   messages get sequence numbers in (acceptance time, key) order;
//! - a Message sent by the account with no kept MIMI message ID whose text
//!   begins as a notice of the agent's does ([`crate::notice`]) is a
//!   notice, sent by [`Sender::Agent`], with no [`NoticeKind`]: format 1
//!   kept only its text.
//!
//! # Limitations
//!
//! - A Message, Chat member or ChatBan naming a ChatContact that is not
//!   in the file (a JMAP client may destroy ChatContacts) is kept, with
//!   that user unknown: [`Sender::Unknown`], or `None` for a participant,
//!   a banned user or a banner. The JMAP id it named stays in the
//!   record's `ext["jmap"]` under the same property. One warning per
//!   file gives the count (Mark's decision, docs/design/agent-frontends.md
//!   §7.7).
//! - A notice read from format 1 has no kind, only its text.
//! - A reply to a message not stored was not kept by format 1, so
//!   [`Reply::Reference`] never comes from it.
//!
//! [`NoticeKind`]: crate::record::NoticeKind

use std::collections::BTreeMap;

use serde::Deserialize;
use serde_json::{Map, Value};

use super::FileError;
use crate::content::BodyType;
use crate::convert::parse_utc_date;
use crate::record::{
    Attachment, Ban, Deletion, Ext, Message, Octets, Participant, Person, ReadPosition, Reply,
    Revision, Room, RoomStatus, Sender,
};
use crate::report::KeptFrank;
use crate::retry::PendingAttachment;
use crate::state::{State, accepted_at_of};

/// The front-end name format-1 properties are kept under in `ext`.
pub const JMAP: &str = "jmap";

/// The beginnings of the agent's notice texts ([`crate::notice`]).
const NOTICE_PREFIXES: [&str; 2] = [
    "Security notice from your mimid agent",
    "Notice from your mimid agent:",
];

/// Format 1 as written.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Format1 {
    format: u32,
    account: String,
    objects: BTreeMap<String, Vec<Map<String, Value>>>,
    #[serde(default, rename = "pending_attachments")]
    pending_attachments: Vec<PendingAttachment>,
    #[serde(default)]
    franks: BTreeMap<String, KeptFrank>,
    #[serde(default, rename = "mimi_ids")]
    mimi_ids: BTreeMap<String, MimiIds>,
}

/// A Message's MIMI message IDs in format 1.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MimiIds {
    #[serde(default)]
    first: Option<String>,
    #[serde(default)]
    aliases: Vec<String>,
}

fn malformed(why: impl Into<String>) -> FileError {
    FileError::Malformed(why.into())
}

/// One JMAP object being converted: its properties are taken one by one,
/// and what is left becomes `ext["jmap"]`.
struct Object {
    what: &'static str,
    id: String,
    rest: Map<String, Value>,
}

impl Object {
    fn new(what: &'static str, mut value: Map<String, Value>) -> Result<Self, FileError> {
        let id = match value.remove("id") {
            Some(Value::String(id)) => id,
            _ => return Err(malformed(format!("a {what} without an id"))),
        };
        Ok(Self {
            what,
            id,
            rest: value,
        })
    }

    fn bad(&self, property: &str, why: &str) -> FileError {
        malformed(format!("{} {}: {property} {why}", self.what, self.id))
    }

    /// Takes `property`, which is absent, null or a string.
    fn string(&mut self, property: &str) -> Result<Option<String>, FileError> {
        match self.rest.remove(property) {
            None | Some(Value::Null) => Ok(None),
            Some(Value::String(s)) => Ok(Some(s)),
            Some(_) => Err(self.bad(property, "is not a string")),
        }
    }

    /// Takes `property`, which must be a string.
    fn required(&mut self, property: &str) -> Result<String, FileError> {
        self.string(property)?
            .ok_or_else(|| self.bad(property, "is missing"))
    }

    /// Takes `property`, a UTCDate, as milliseconds.
    fn date(&mut self, property: &str) -> Result<Option<u64>, FileError> {
        match self.string(property)? {
            None => Ok(None),
            Some(text) => parse_utc_date(&text)
                .map(Some)
                .ok_or_else(|| self.bad(property, "is not a UTCDate")),
        }
    }

    /// Takes `property`, which is absent, null or a boolean.
    fn flag(&mut self, property: &str) -> Result<bool, FileError> {
        match self.rest.remove(property) {
            None | Some(Value::Null) => Ok(false),
            Some(Value::Bool(b)) => Ok(b),
            Some(_) => Err(self.bad(property, "is not a boolean")),
        }
    }

    /// Takes `property`, which is absent, null or an array.
    fn array(&mut self, property: &str) -> Result<Vec<Value>, FileError> {
        match self.rest.remove(property) {
            None | Some(Value::Null) => Ok(Vec::new()),
            Some(Value::Array(a)) => Ok(a),
            Some(_) => Err(self.bad(property, "is not an array")),
        }
    }

    /// What is left, as the record's `ext`.
    fn ext(self) -> Ext {
        let mut ext = Ext::new();
        if !self.rest.is_empty() {
            ext.insert(JMAP.to_owned(), Value::Object(self.rest));
        }
        ext
    }
}

fn body_type(object: &Object, text: Option<&str>) -> Result<BodyType, FileError> {
    match text {
        None | Some("text/plain") => Ok(BodyType::Plain),
        Some("text/markdown") => Ok(BodyType::Markdown),
        Some(_) => Err(object.bad("bodyType", "is not text/plain or text/markdown")),
    }
}

/// The state in format-1 `bytes`, which must be `user`'s. See the module
/// documentation for the conversion.
///
/// # Errors
///
/// [`FileError::Malformed`] if `bytes` is not format 1, holds an unknown
/// type, an object without an id, a property of the wrong type, a date
/// that is not a UTCDate, a `senderMsgId` that is not a ULID, a reference
/// to a Chat not in the file, or malformed side tables. A reference to a
/// ChatContact not in the file is kept as an unknown user (see the module
/// documentation).
pub fn read_format_1(bytes: &[u8], user: &str) -> Result<State, FileError> {
    let mut file: Format1 = serde_json::from_slice(bytes).map_err(|e| malformed(e.to_string()))?;
    if file.format != 1 {
        return Err(malformed(format!("format {}", file.format)));
    }
    if let Some(name) = file.objects.keys().find(|name| {
        !matches!(
            name.as_str(),
            "ChatContact" | "Chat" | "ChatBan" | "Message" | "ReadPosition"
        )
    }) {
        return Err(malformed(format!("unknown type {name}")));
    }
    let mut take = |name: &str| file.objects.remove(name).unwrap_or_default();
    let (contacts, chats, bans, messages, positions) = (
        take("ChatContact"),
        take("Chat"),
        take("ChatBan"),
        take("Message"),
        take("ReadPosition"),
    );
    let mut state = State::new(user);
    state.ext.insert(
        JMAP.to_owned(),
        serde_json::json!({ "account": file.account }),
    );

    for value in contacts {
        let person = person(Object::new("ChatContact", value)?)?;
        insert(&mut state.people, person.key.clone(), person, "ChatContact")?;
    }
    let users = Users {
        account: &file.account,
        user,
        people: &state.people,
        unknown: std::cell::Cell::new(0),
    };
    let mut rooms = BTreeMap::new();
    for value in chats {
        let room = room(Object::new("Chat", value)?, &users)?;
        insert(&mut rooms, room.key.clone(), room, "Chat")?;
    }
    let mut ban_records = BTreeMap::new();
    for value in bans {
        let ban = ban(Object::new("ChatBan", value)?, &users, &rooms)?;
        insert(&mut ban_records, ban.key.clone(), ban, "ChatBan")?;
    }
    let mut message_records = BTreeMap::new();
    for value in messages {
        let object = Object::new("Message", value)?;
        let ids = file.mimi_ids.remove(&object.id);
        let frank = file.franks.remove(&object.id);
        let message = message(object, &users, &rooms, ids, frank)?;
        insert(
            &mut message_records,
            message.key.clone(),
            message,
            "Message",
        )?;
    }
    let mut position_records = BTreeMap::new();
    for value in positions {
        let position = read_position(Object::new("ReadPosition", value)?, &rooms)?;
        insert(
            &mut position_records,
            position.key.clone(),
            position,
            "ReadPosition",
        )?;
    }

    let unknown = users.unknown.get();
    if unknown > 0 {
        tracing::warn!(
            name: "chat_v1_unknown_contacts",
            unknown,
            "format-1 store: Messages, Chat members or ChatBans name ChatContacts \
             that are not in the file; they are kept with the user unknown"
        );
    }

    // Sequence numbers in history order.
    let mut order: Vec<(u64, String)> = message_records
        .values()
        .map(|m: &Message| (m.accepted_at, m.key.clone()))
        .collect();
    order.sort();
    for (seq, (_, key)) in (1u64..).zip(&order) {
        if let Some(message) = message_records.get_mut(key) {
            message.seq = seq;
        }
    }
    state.next_seq = u64::try_from(order.len())
        .unwrap_or(u64::MAX)
        .saturating_add(1);
    state.rooms = rooms;
    state.bans = ban_records;
    state.messages = message_records;
    state.read_positions = position_records;
    state.pending_attachments = file.pending_attachments;
    state.reindex();
    Ok(state)
}

fn insert<R>(
    map: &mut BTreeMap<String, R>,
    key: String,
    record: R,
    what: &str,
) -> Result<(), FileError> {
    if map.contains_key(&key) {
        return Err(malformed(format!("{what} {key} twice")));
    }
    map.insert(key, record);
    Ok(())
}

/// Resolves the JMAP ids that name users.
struct Users<'a> {
    account: &'a str,
    user: &'a str,
    people: &'a BTreeMap<String, Person>,
    /// How many items named a ChatContact not in the file.
    unknown: std::cell::Cell<usize>,
}

impl Users<'_> {
    /// The user URI JMAP id `id` names, or `None` for a ChatContact that
    /// is not in the file.
    fn uri(&self, id: &str) -> Option<String> {
        if id == self.account {
            return Some(self.user.to_owned());
        }
        self.people.get(id).map(|p| p.user.clone())
    }

    /// Counts one more item naming an unknown user.
    fn count_unknown(&self) {
        self.unknown.set(self.unknown.get() + 1);
    }

    /// The user URI JMAP id `id`, taken from `property` of `object`,
    /// names; for an unknown one, `id` goes back into `object`'s rest, so
    /// it lands in `ext["jmap"]`.
    fn take(&self, object: &mut Object, property: &str, id: String) -> Option<String> {
        let uri = self.uri(&id);
        if uri.is_none() {
            object.rest.insert(property.to_owned(), Value::String(id));
        }
        uri
    }
}

fn person(mut o: Object) -> Result<Person, FileError> {
    Ok(Person {
        user: o.required("identity")?,
        display_name: o.string("displayName")?,
        did: o.string("did")?,
        did_changed_at: o.date("didChangedAt")?,
        first_seen: o
            .date("firstSeenAt")?
            .ok_or_else(|| o.bad("firstSeenAt", "is missing"))?,
        key: o.id.clone(),
        ext: o.ext(),
    })
}

fn room(mut o: Object, users: &Users<'_>) -> Result<Room, FileError> {
    let uri = o.required("roomId")?;
    let name = o.string("name")?;
    // Kept in ext as well: its roles and times are JMAP's.
    let members = o.rest.get("members").cloned().unwrap_or(Value::Null);
    let mut participants = Vec::new();
    for member in members.as_array().into_iter().flatten() {
        let id = member
            .get("id")
            .and_then(Value::as_str)
            .ok_or_else(|| o.bad("members", "has a member without an id"))?;
        let user = users.uri(id);
        if user.is_none() {
            users.count_unknown();
        }
        participants.push(Participant { user, role: None });
    }
    Ok(Room {
        key: o.id.clone(),
        uri,
        name,
        status: RoomStatus::Active,
        participants,
        role_names: BTreeMap::new(),
        ext: o.ext(),
    })
}

fn room_key(o: &Object, rooms: &BTreeMap<String, Room>, chat: String) -> Result<String, FileError> {
    if rooms.contains_key(&chat) {
        Ok(chat)
    } else {
        Err(o.bad("chatId", &format!("names no Chat ({chat})")))
    }
}

fn ban(mut o: Object, users: &Users<'_>, rooms: &BTreeMap<String, Room>) -> Result<Ban, FileError> {
    let chat = o.required("chatId")?;
    let room = room_key(&o, rooms, chat)?;
    let user = o.required("userId")?;
    let user = users.take(&mut o, "userId", user);
    let banned_by = o.required("bannedBy")?;
    let banned_by = users.take(&mut o, "bannedBy", banned_by);
    if user.is_none() || banned_by.is_none() {
        users.count_unknown();
    }
    Ok(Ban {
        key: o.id.clone(),
        room,
        user,
        banned_by,
        reason: o.string("reason")?,
        expires_at: o.date("expiresAt")?,
        ext: o.ext(),
    })
}

/// An Attachment, which must hold exactly what [`Attachment`] holds.
fn attachment(o: &Object, value: Value) -> Result<Attachment, FileError> {
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct Jmap {
        blob_id: String,
        filename: String,
        content_type: String,
        size: u64,
        sha256: String,
    }
    let a: Jmap = serde_json::from_value(value)
        .map_err(|e| o.bad("attachments", &format!("has an Attachment that {e}")))?;
    Ok(Attachment {
        blob_id: a.blob_id,
        file_name: a.filename,
        media_type: a.content_type,
        size: a.size,
        sha256: a.sha256,
    })
}

/// An `editHistory` entry, which must hold exactly what [`Revision`]
/// holds.
fn revision(o: &Object, value: Value) -> Result<Revision, FileError> {
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct Jmap {
        body: String,
        body_type: String,
        edited_at: String,
    }
    let r: Jmap = serde_json::from_value(value)
        .map_err(|e| o.bad("editHistory", &format!("has an entry that {e}")))?;
    Ok(Revision {
        body: r.body,
        body_type: body_type(o, Some(&r.body_type))?,
        edited_at: parse_utc_date(&r.edited_at)
            .ok_or_else(|| o.bad("editHistory", "has an editedAt that is not a UTCDate"))?,
    })
}

fn message(
    mut o: Object,
    users: &Users<'_>,
    rooms: &BTreeMap<String, Room>,
    ids: Option<MimiIds>,
    kept_frank: Option<KeptFrank>,
) -> Result<Message, FileError> {
    let chat = o.required("chatId")?;
    let room = room_key(&o, rooms, chat)?;
    let sender_msg_id = o.required("senderMsgId")?;
    let accepted_at =
        accepted_at_of(&sender_msg_id).ok_or_else(|| o.bad("senderMsgId", "is not a ULID"))?;
    let sender_id = o.required("senderId")?;
    let body = o.string("body")?.unwrap_or_default();
    let kind = o.string("bodyType")?;
    let body_type = body_type(&o, kind.as_deref())?;
    let (mimi_id, aliases) = match ids {
        None => (None, Vec::new()),
        Some(ids) => {
            let first = match ids.first {
                None => None,
                Some(hex) => Some(
                    Octets::from_hex(&hex)
                        .ok_or_else(|| o.bad("mimiIds.first", "is not 32 octets of hex"))?,
                ),
            };
            let aliases = ids
                .aliases
                .iter()
                .map(|a| Octets::from_hex(a))
                .collect::<Option<Vec<_>>>()
                .ok_or_else(|| o.bad("mimiIds.aliases", "has one that is not 10 octets of hex"))?;
            (first, aliases)
        }
    };
    let sender = if sender_id == users.account
        && mimi_id.is_none()
        && NOTICE_PREFIXES.iter().any(|p| body.starts_with(p))
    {
        Sender::Agent
    } else {
        match users.take(&mut o, "senderId", sender_id) {
            Some(uri) => Sender::User(uri),
            None => {
                users.count_unknown();
                Sender::Unknown
            }
        }
    };
    let in_reply_to = o.string("replyTo")?.map(Reply::Message);
    let topic_id = o.string("topicId")?;
    let attachments = o
        .array("attachments")?
        .into_iter()
        .map(|a| attachment(&o, a))
        .collect::<Result<_, _>>()?;
    let edit_history = o
        .array("editHistory")?
        .into_iter()
        .map(|r| revision(&o, r))
        .collect::<Result<_, _>>()?;
    let edited_at = o.date("editedAt")?;
    let deleted_at = o.date("deletedAt")?;
    let for_all = o.flag("deletedForAll")?;
    let deleted = match (deleted_at, for_all) {
        (Some(at), for_all) => Some(Deletion { at, for_all }),
        (None, false) => None,
        (None, true) => return Err(o.bad("deletedForAll", "is set without deletedAt")),
    };
    Ok(Message {
        key: o.id.clone(),
        room,
        seq: 0,
        sender,
        mimi_id,
        aliases,
        accepted_at,
        sender_msg_id,
        body,
        body_type,
        in_reply_to,
        topic_id,
        attachments,
        edit_history,
        edited_at,
        deleted,
        kept_frank,
        notice: None,
        ext: o.ext(),
    })
}

fn read_position(mut o: Object, rooms: &BTreeMap<String, Room>) -> Result<ReadPosition, FileError> {
    let chat = o.required("chatId")?;
    let room = room_key(&o, rooms, chat)?;
    Ok(ReadPosition {
        key: o.id.clone(),
        room,
        message: o.string("lastReadMessageId")?,
        at: o.date("lastReadAt")?,
        ext: o.ext(),
    })
}
