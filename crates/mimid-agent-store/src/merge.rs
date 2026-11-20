//! The JMAP front end's own writes, written into the records until they
//! go through the store (step 5 of docs/design/agent-frontends.md §3):
//! [`merge_object`] takes a JMAP object as the front end holds it after a
//! write and writes it into its record, and [`forget_object`] removes the
//! record of an object the front end destroyed.
//!
//! The conversion of an object: its JMAP id is the record's key; a JMAP
//! id naming the account (a member, a sender, a banner) is the user's own
//! URI, and one naming a ChatContact is that contact's `identity`; every
//! property the record does not hold goes into the record's `ext["jmap"]`
//! unchanged ([`JMAP`]); a Message's acceptance time is its
//! `senderMsgId`'s ULID time.
//!
//! # Limitations
//!
//! - An object naming a ChatContact the records do not hold (a client may
//!   destroy a ChatContact, and Chat members, ChatBans and Messages keep
//!   naming it) gives that user as unknown: [`Sender::Unknown`], or `None`
//!   for a participant, a banned user or a banner, with the JMAP id kept
//!   in `ext["jmap"]` under the same property. An object naming a Chat the
//!   records do not hold (a client may destroy a Chat, and crate-jmap
//!   keeps its Messages and ChatBans) keeps the Chat's id as its room key.
//!   Both happen in a running agent, so the records allow them.
//! - Temporary: step 5 replaces it with `Store` methods.

use std::collections::BTreeMap;

use serde::Deserialize;
use serde_json::{Map, Value};

use crate::content::BodyType;
use crate::convert::parse_utc_date;
use crate::db::FileError;
use crate::record::{
    Attachment, Ban, Deletion, Ext, Message, Participant, Person, ReadPosition, Reply, Revision,
    Room, RoomStatus, Sender,
};
use crate::state::{State, accepted_at_of};

/// The front-end name JMAP properties are kept under in `ext`.
pub const JMAP: &str = "jmap";

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

/// Resolves the JMAP ids that name users.
struct Users<'a> {
    account: &'a str,
    user: &'a str,
    people: &'a BTreeMap<String, Person>,
}

impl Users<'_> {
    /// The user URI JMAP id `id` names, or `None` for a ChatContact the
    /// records do not hold.
    fn uri(&self, id: &str) -> Option<String> {
        if id == self.account {
            return Some(self.user.to_owned());
        }
        self.people.get(id).map(|p| p.user.clone())
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
        participants.push(Participant {
            user: users.uri(id),
            role: None,
        });
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

fn ban(mut o: Object, users: &Users<'_>) -> Result<Ban, FileError> {
    let room = o.required("chatId")?;
    let user = o.required("userId")?;
    let user = users.take(&mut o, "userId", user);
    let banned_by = o.required("bannedBy")?;
    let banned_by = users.take(&mut o, "bannedBy", banned_by);
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

fn message(mut o: Object, users: &Users<'_>) -> Result<Message, FileError> {
    let room = o.required("chatId")?;
    let sender_msg_id = o.required("senderMsgId")?;
    let accepted_at =
        accepted_at_of(&sender_msg_id).ok_or_else(|| o.bad("senderMsgId", "is not a ULID"))?;
    let sender_id = o.required("senderId")?;
    let body = o.string("body")?.unwrap_or_default();
    let kind = o.string("bodyType")?;
    let body_type = body_type(&o, kind.as_deref())?;
    let sender = match users.take(&mut o, "senderId", sender_id) {
        Some(uri) => Sender::User(uri),
        None => Sender::Unknown,
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
        mimi_id: None,
        aliases: Vec::new(),
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
        kept_frank: None,
        notice: None,
        ext: o.ext(),
    })
}

fn read_position(mut o: Object) -> Result<ReadPosition, FileError> {
    let room = o.required("chatId")?;
    Ok(ReadPosition {
        key: o.id.clone(),
        room,
        message: o.string("lastReadMessageId")?,
        at: o.date("lastReadAt")?,
        ext: o.ext(),
    })
}

/// Writes one JMAP object of type `type_name`, as a JMAP front end holds
/// it after a write of its own, into `state`; `account` is its accountId.
/// A new key gets a record made from the object (see the module
/// documentation; a new message also gets the next sequence number). For a record that exists, only what the
/// front end may change is taken, and what the store owns is kept:
///
/// - Person: the display name;
/// - Room: nothing but `ext`;
/// - Ban: the reason and expiry;
/// - Message: a local deletion, or with `content` (the front end sent an
///   edit or retraction of the user's own message) the body, body type,
///   attachments, edit history and deletion;
/// - Read position: everything.
///
/// Every record keeps the object's other properties in `ext["jmap"]`.
/// This is how the JMAP front end's own writes reach the records until
/// they go through the store (step 5 of docs/design/agent-frontends.md
/// §3).
///
/// # Errors
///
/// [`FileError::Malformed`] for an object without an id, with a property
/// of the wrong type, a date that is not a UTCDate or a `senderMsgId`
/// that is not a ULID, or of a type that is not one of the five.
pub fn merge_object(
    state: &mut State,
    account: &str,
    type_name: &str,
    object: Map<String, Value>,
    content: bool,
) -> Result<(), FileError> {
    let user = state.user.clone();
    let users = |people| users_of(account, &user, people);
    match type_name {
        "ChatContact" => {
            let new = person(Object::new("ChatContact", object)?)?;
            match state.people.get_mut(&new.key) {
                Some(old) => {
                    old.display_name = new.display_name;
                    old.ext = new.ext;
                }
                None => state.insert_person(new),
            }
        }
        "Chat" => {
            let new = room(Object::new("Chat", object)?, &users(&state.people))?;
            match state.rooms.get_mut(&new.key) {
                Some(old) => old.ext = new.ext,
                None => state.insert_room(new),
            }
        }
        "ChatBan" => {
            let new = ban(Object::new("ChatBan", object)?, &users(&state.people))?;
            match state.bans.get_mut(&new.key) {
                Some(old) => {
                    old.reason = new.reason;
                    old.expires_at = new.expires_at;
                    old.ext = new.ext;
                }
                None => {
                    state.bans.insert(new.key.clone(), new);
                }
            }
        }
        "Message" => {
            let mut new = message(Object::new("Message", object)?, &users(&state.people))?;
            match state.messages.get_mut(&new.key) {
                Some(old) => {
                    old.ext = new.ext;
                    if content {
                        old.body = new.body;
                        old.body_type = new.body_type;
                        old.attachments = new.attachments;
                        old.edit_history = new.edit_history;
                        old.edited_at = new.edited_at;
                        old.deleted = new.deleted;
                    } else if old.deleted.is_none() {
                        old.deleted = new.deleted;
                    }
                }
                None => {
                    new.seq = state.take_seq();
                    state.insert_message(new);
                }
            }
        }
        "ReadPosition" => {
            let new = read_position(Object::new("ReadPosition", object)?)?;
            state.read_positions.insert(new.key.clone(), new);
        }
        other => return Err(malformed(format!("unknown type {other}"))),
    }
    Ok(())
}

/// Removes the record of the JMAP object `id` of type `type_name`, which
/// the JMAP front end destroyed: for a Chat, its room record and its read
/// positions (crate-jmap destroys a Chat's ReadPositions with it), but
/// not its messages or bans, which crate-jmap keeps; for a Message, with
/// a tombstone ([`State::delete_message`]).
pub fn forget_object(state: &mut State, type_name: &str, id: &str) {
    match type_name {
        "ChatContact" => {
            state.people.remove(id);
        }
        "Chat" => {
            state.rooms.remove(id);
            state.read_positions.retain(|_, r| r.room != id);
        }
        "ChatBan" => {
            state.bans.remove(id);
        }
        "Message" => {
            state.delete_message(id);
        }
        "ReadPosition" => {
            state.read_positions.remove(id);
        }
        _ => return,
    }
    state.reindex();
}

/// A [`Users`] for one object.
fn users_of<'a>(
    account: &'a str,
    user: &'a str,
    people: &'a BTreeMap<String, Person>,
) -> Users<'a> {
    Users {
        account,
        user,
        people,
    }
}
