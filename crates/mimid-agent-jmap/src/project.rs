//! The JMAP projection of the store (docs/design/agent-frontends.md §2,
//! "The JMAP projection"): what the store's change feed publishes, from a
//! sync or from any front end's write, written into the `MemoryBackend`
//! as JMAP objects under the records' keys. It runs in every save, before
//! the records are written (`JmapExt`, the JMAP front end's
//! [`mimid_agent_store::Frontend`]), so a record is never saved without
//! the JMAP object it should have, whoever made it.
//!
//! Each record is written as the JMAP object it is now: one record-to-
//! object function per type, merged over the object the backend holds,
//! so the JMAP-only properties it has (`unreadCount`, `readAt`,
//! `privateMetadata` and the rest) stay as they are. Only the properties
//! the store owns are written, and only those that differ, so a change
//! the backend already shows writes nothing. A record named several times
//! in one commit is written once. People come first, then rooms,
//! messages and bans, so a Chat's members and a Message's sender name
//! ChatContacts that exist; deleted records go last.
//!
//! The JMAP front end's own writes come through the feed too. A record
//! added whose object exists was made by a JMAP write hook, which shows
//! it already: nothing is written. A changed record writes only what
//! differs, which for a JMAP write is nothing, except a Chat's `members`,
//! which a member change shows again from the room's participants, as the
//! sync that follows it would.
//!
//! | Record | JMAP object | Properties the store owns |
//! |---|---|---|
//! | Person | ChatContact | `identity`, `login`, `firstSeenAt`, `lastSeenAt` (made only), `did`, `didChangedAt` |
//! | Room | Chat, kind `group` | `name`, `roomId` (made only), `members` |
//! | Message | Message | `senderMsgId`, `senderId`, `chatId`, `sentAt`, `receivedAt`, `replyTo`, `topicId`, `deliveryState` (made only); `body`, `bodyType`, `attachments`, `editedAt`, `editHistory`, `deletedAt`, `deletedForAll` |
//! | Ban | ChatBan | all, made only; destroyed when the record is gone |
//!
//! A record deleted (a forgotten person, a deleted message, a room
//! deleted with its messages and bans) destroys its object, if there is
//! one. Invites and read positions have no projection: JMAP Chat has no
//! object for an invite, and only JMAP writes read positions.
//!
//! # Limitations
//!
//! - A Chat's `createdAt`, a ChatContact's `firstSeenAt` and a Message's
//!   `receivedAt` are when the object is made here, as before the store.
//! - Dates the store owns are compared to the millisecond, so an object
//!   whose date text differs (a client's, or one with more digits) is not
//!   rewritten for that alone.
//! - Destroying a Chat destroys each of its Messages, one Message change
//!   each, so a long history can push a client's state out of the change
//!   log ([`crate::CHANGE_LOG_LIMIT`]): its next `/changes` is then
//!   `cannotCalculateChanges` and it resyncs.

use jmap_chat_server::ChatStore;
use jmap_chat_types::{
    BodyType, Chat, ChatBan, ChatContact, ChatKind, ChatMember, ChatMemberRole, DeliveryState,
    Message,
};
use jmap_server::{
    BackendSetError, GetObject, Id, JmapObject, JmapReads, SetErrorType, SetObject, now_utc_string,
};
use mimid_agent_store::convert::{parse_utc_date, utc_date};
use mimid_agent_store::record::{self, Reply, Sender};
use mimid_agent_store::sync::bans::BANNED_ROLE_INDEX;
use mimid_agent_store::{Change, Store};
use serde_json::{Map, Value, json};

use crate::backend::ROOM_ID;
use crate::edits::retraction_patch;
use crate::persist::JmapExt;
use crate::sync::SyncError;

/// The records one commit names, each once, in the order first named.
#[derive(Default)]
struct Named {
    keys: Vec<String>,
    added: std::collections::BTreeSet<String>,
    changed: std::collections::BTreeSet<String>,
    left: std::collections::BTreeSet<String>,
}

impl Named {
    fn name(&mut self, key: String) -> String {
        if !self.keys.contains(&key) {
            self.keys.push(key.clone());
        }
        key
    }

    fn added(&mut self, key: String) {
        let key = self.name(key);
        self.added.insert(key);
    }

    fn changed(&mut self, key: String) {
        let key = self.name(key);
        self.changed.insert(key);
    }

    fn left(&mut self, key: String) {
        let key = self.name(key);
        self.left.insert(key);
    }
}

fn now() -> jmap_server::UTCDate {
    now_utc_string()
}

/// `value` as a JMAP `T`, through serde (crate-jmap's types are
/// `#[non_exhaustive]`, AGENTS.md).
fn from_json<T: serde::de::DeserializeOwned>(value: Value) -> Result<T, SyncError> {
    serde_json::from_value(value).map_err(|e| SyncError::Store(format!("building an object: {e}")))
}

fn to_json<T: serde::Serialize>(value: &T) -> Result<Value, SyncError> {
    serde_json::to_value(value).map_err(|e| SyncError::Store(format!("reading an object: {e}")))
}

/// Whether two values of property `key` say the same: an absent value is
/// null, `deletedForAll` false is null, an empty `editHistory` is null,
/// and two strings that are both UTCDates are the same if they name the
/// same millisecond.
fn same(key: &str, a: Option<&Value>, b: Option<&Value>) -> bool {
    fn norm<'v>(key: &str, v: Option<&'v Value>) -> Option<&'v Value> {
        match (key, v) {
            (_, None | Some(Value::Null)) => None,
            ("deletedForAll", Some(Value::Bool(false))) => None,
            ("editHistory", Some(Value::Array(a))) if a.is_empty() => None,
            (_, v) => v,
        }
    }
    fn equal(a: &Value, b: &Value) -> bool {
        match (a, b) {
            (Value::String(a), Value::String(b)) => {
                a == b || parse_utc_date(a).is_some_and(|ms| parse_utc_date(b) == Some(ms))
            }
            (Value::Array(a), Value::Array(b)) => {
                a.len() == b.len() && a.iter().zip(b).all(|(a, b)| equal(a, b))
            }
            (Value::Object(a), Value::Object(b)) => {
                a.len() == b.len() && a.iter().all(|(k, v)| b.get(k).is_some_and(|w| equal(v, w)))
            }
            (a, b) => a == b,
        }
    }
    match (norm(key, a), norm(key, b)) {
        (None, None) => true,
        (Some(a), Some(b)) => equal(a, b),
        _ => false,
    }
}

/// The properties of `desired` (a whole object, as JSON) named in `keys`
/// that `existing` does not already say.
fn patch_of(existing: &Value, desired: &Value, keys: &[&str]) -> Map<String, Value> {
    let mut patch = Map::new();
    for key in keys {
        let want = desired.get(*key);
        if !same(key, existing.get(*key), want) {
            patch.insert((*key).to_owned(), want.cloned().unwrap_or(Value::Null));
        }
    }
    patch
}

/// The Message properties the store owns after the message is made.
const MESSAGE_CONTENT: [&str; 7] = [
    "body",
    "bodyType",
    "attachments",
    "editedAt",
    "editHistory",
    "deletedAt",
    "deletedForAll",
];

/// The ChatContact properties the store owns after the contact is made.
const CONTACT_DID: [&str; 2] = ["did", "didChangedAt"];

/// The JSON of a record's attachment as a JMAP Attachment.
fn attachment_json(a: &record::Attachment) -> Value {
    json!({
        "blobId": a.blob_id,
        "filename": a.file_name,
        "contentType": a.media_type,
        "size": a.size,
        "sha256": a.sha256,
    })
}

fn body_type_json(body_type: mimid_agent_store::content::BodyType) -> Value {
    match body_type {
        mimid_agent_store::content::BodyType::Markdown => json!(BodyType::Markdown),
        _ => json!(BodyType::Plain),
    }
}

/// The content properties ([`MESSAGE_CONTENT`]) of `message` as JMAP
/// shows them: a retraction as [`retraction_patch`] makes it.
pub(crate) fn message_content(message: &record::Message) -> Map<String, Value> {
    let date = |ms: Option<u64>| ms.map_or(Value::Null, |ms| json!(utc_date(ms)));
    let mut fields = Map::new();
    fields.insert("body".to_owned(), json!(message.body));
    fields.insert("bodyType".to_owned(), body_type_json(message.body_type));
    fields.insert(
        "attachments".to_owned(),
        Value::Array(message.attachments.iter().map(attachment_json).collect()),
    );
    fields.insert("editedAt".to_owned(), date(message.edited_at));
    let history: Vec<Value> = message
        .edit_history
        .iter()
        .map(|r| {
            json!({
                "body": r.body,
                "bodyType": body_type_json(r.body_type),
                "editedAt": utc_date(r.edited_at),
            })
        })
        .collect();
    fields.insert(
        "editHistory".to_owned(),
        if history.is_empty() {
            Value::Null
        } else {
            Value::Array(history)
        },
    );
    match message.deleted {
        Some(record::Deletion { at, for_all: true }) => {
            if let Value::Object(retraction) =
                retraction_patch(&jmap_server::UTCDate::from(utc_date(at).as_str()))
            {
                fields.extend(retraction);
            }
        }
        Some(record::Deletion { at, .. }) => {
            fields.insert("deletedAt".to_owned(), json!(utc_date(at)));
            fields.insert("deletedForAll".to_owned(), Value::Null);
        }
        None => {
            fields.insert("deletedAt".to_owned(), Value::Null);
            fields.insert("deletedForAll".to_owned(), Value::Null);
        }
    }
    fields
}

/// A Message's content properties as the projection writes them: as
/// [`message_content`] renders them, but for a message deleted here alone
/// emptied as crate-jmap empties it (draft-atwood-jmap-chat-00 §Message
/// `deletedAt`: empty `body` and `attachments`, no `editHistory`), while
/// the record keeps its content for reports.
fn shown_content(message: &record::Message) -> Map<String, Value> {
    let mut content = message_content(message);
    if matches!(
        message.deleted,
        Some(record::Deletion { for_all: false, .. })
    ) {
        content.insert("body".to_owned(), json!(""));
        content.insert("attachments".to_owned(), json!([]));
        content.insert("editHistory".to_owned(), Value::Null);
    }
    content
}

impl JmapExt {
    /// Writes the records `changes` name into the backend (see the module
    /// documentation).
    pub(crate) async fn project(&self, store: &Store, changes: &[Change]) -> Result<(), SyncError> {
        let (mut people, mut rooms, mut messages, mut bans) = (
            Named::default(),
            Named::default(),
            Named::default(),
            Named::default(),
        );
        let mut gone: Vec<(&'static str, String)> = Vec::new();
        for change in changes.iter().cloned() {
            match change {
                Change::PersonAdded(key) => people.added(key),
                Change::PersonChanged(key) => people.changed(key),
                Change::PersonForgotten(key) => gone.push((ChatContact::TYPE_NAME, key)),
                Change::RoomAdded(key) => rooms.added(key),
                Change::RoomChanged(key) => rooms.changed(key),
                Change::RoomLeft(key) => rooms.left(key),
                Change::RoomForgotten {
                    key,
                    messages,
                    bans,
                } => {
                    gone.push((Chat::TYPE_NAME, key));
                    gone.extend(messages.into_iter().map(|m| (Message::TYPE_NAME, m)));
                    gone.extend(bans.into_iter().map(|b| (ChatBan::TYPE_NAME, b)));
                }
                Change::MessageAdded(key) => messages.added(key),
                Change::MessageChanged(key) => messages.changed(key),
                Change::MessageDeleted(key) => gone.push((Message::TYPE_NAME, key)),
                Change::BanAdded(key) => bans.added(key),
                Change::BanChanged(key) | Change::BanLifted(key) => bans.changed(key),
                // Invites and read positions have no projection; Change is
                // #[non_exhaustive].
                _ => {}
            }
        }
        for key in &people.keys {
            self.project_person(store, key, people.added.contains(key))
                .await?;
        }
        for key in &rooms.keys {
            self.project_room(
                store,
                key,
                rooms.added.contains(key),
                rooms.changed.contains(key),
                rooms.left.contains(key),
            )
            .await?;
        }
        for key in &messages.keys {
            self.project_message(store, key, messages.added.contains(key))
                .await?;
        }
        for key in &bans.keys {
            self.project_ban(store, key).await?;
        }
        for (type_name, key) in gone {
            match type_name {
                "ChatContact" => self.destroy_unheld::<ChatContact>(&key).await,
                "Chat" => self.destroy_unheld::<Chat>(&key).await,
                "ChatBan" => self.destroy_unheld::<ChatBan>(&key).await,
                _ => self.destroy_unheld::<Message>(&key).await,
            }
        }
        Ok(())
    }

    /// The stored object `id` of type `O`.
    async fn stored<O: GetObject + Send + Sync>(&self, id: &Id) -> Result<Option<O>, SyncError> {
        let (mut found, _) = self
            .inner
            .get_objects::<O>(&(), &self.account, Some(std::slice::from_ref(id)), None)
            .await?;
        Ok(found.pop())
    }

    /// Destroys object `key` of type `O`, whose record is gone, if the
    /// backend holds it; a failure is logged, since the record is gone
    /// already.
    async fn destroy_unheld<O: SetObject + Send + Sync>(&self, key: &str) {
        match self
            .inner
            .destroy_object::<O>(&(), &self.account, &Id::from(key))
            .await
        {
            Ok(()) => {}
            Err(BackendSetError::SetError(e)) if e.error_type == SetErrorType::NotFound => {}
            Err(error) => tracing::error!(
                name: "agent_chat_destroy_failed",
                type_name = O::TYPE_NAME,
                error = ?error,
                "an object whose record was deleted was not destroyed"
            ),
        }
    }

    /// The JMAP id that names user `user`: the accountId for the user,
    /// else the ChatContact of their person record.
    fn id_of_user(&self, store: &Store, user: &str) -> Option<Id> {
        if user == self.user {
            return Some(self.account.clone());
        }
        store
            .state()
            .person_of_user(user)
            .map(|key| Id::from(key.as_str()))
    }

    /// A person record as its ChatContact: made when `added` and absent,
    /// else its `did` and `didChangedAt` written where they differ.
    async fn project_person(&self, store: &Store, key: &str, added: bool) -> Result<(), SyncError> {
        let Some(person) = store.state().people.get(key).cloned() else {
            return Ok(());
        };
        let id = Id::from(key);
        let existing = self.stored::<ChatContact>(&id).await?;
        let did = json!({
            "did": person.did,
            "didChangedAt": person.did_changed_at.map(utc_date),
        });
        match existing {
            None if added => {
                let seen = jmap_server::UTCDate::from(utc_date(person.first_seen).as_str());
                let contact = ChatContact::new(
                    id,
                    person.user.clone(),
                    person.user.clone(),
                    seen.clone(),
                    seen,
                    false,
                );
                let mut value = to_json(&contact)?;
                if let (Value::Object(value), Value::Object(did)) = (&mut value, did) {
                    value.extend(did.into_iter().filter(|(_, v)| !v.is_null()));
                }
                self.inner
                    .insert_object(&self.account, from_json::<ChatContact>(value)?)
                    .await?;
            }
            None => {}
            Some(contact) => {
                let patch = patch_of(&to_json(&contact)?, &did, &CONTACT_DID);
                if !patch.is_empty() {
                    self.inner
                        .update_object::<ChatContact>(
                            &(),
                            &self.account,
                            &id,
                            from_json(Value::Object(patch))?,
                        )
                        .await?;
                }
            }
        }
        Ok(())
    }

    /// The ChatMembers of room record `room`, keeping the entries of
    /// `existing` for those already members. The user is the accountId;
    /// everyone else is their person's ChatContact. New entries are joined
    /// now. Each one's role is the room's (decision mimid-1wgh.62 item 9):
    /// `admin` for a participant whose role is named "admin", `member`
    /// otherwise; a banned participant (role 1, "banned") is not a member.
    fn members_of(
        &self,
        store: &Store,
        room: &record::Room,
        existing: &[ChatMember],
    ) -> Vec<ChatMember> {
        let mut members = Vec::with_capacity(room.participants.len());
        for participant in &room.participants {
            let user = &participant.user;
            let name = participant
                .role
                .and_then(|index| room.role_names.get(&index).map(|n| (index, n.as_str())));
            let role = match name {
                Some((BANNED_ROLE_INDEX, "banned")) => continue,
                Some((_, "admin")) => ChatMemberRole::Admin,
                _ => ChatMemberRole::Member,
            };
            let Some(id) = self.id_of_user(store, user) else {
                continue;
            };
            members.push(match existing.iter().find(|m| m.id == id) {
                Some(m) => {
                    let mut m = m.clone();
                    m.role = role;
                    m
                }
                None => ChatMember::new(id, role, now()),
            });
        }
        members
    }

    /// A room record as its Chat: made when `added` and absent, named by
    /// the room's name; else, when `changed`, its `members` shown again
    /// from the participants, and, when `left`, the accountId taken out of
    /// them. An added room whose Chat exists was made by a JMAP write,
    /// which shows it.
    async fn project_room(
        &self,
        store: &Store,
        key: &str,
        added: bool,
        changed: bool,
        left: bool,
    ) -> Result<(), SyncError> {
        let Some(room) = store.state().rooms.get(key).cloned() else {
            return Ok(());
        };
        let id = Id::from(key);
        let existing = self.stored::<Chat>(&id).await?;
        let members = match existing {
            None if added => {
                let mut members = self.members_of(store, &room, &[]);
                if left {
                    members.retain(|m| m.id != self.account);
                }
                let mut chat = Chat::new(id, ChatKind::Group, now(), 0, vec![], false, true);
                chat.name = Some(room.name.clone().unwrap_or_default());
                chat.members = Some(members);
                chat.extra.insert(ROOM_ID.to_owned(), json!(room.uri));
                self.inner.insert_object(&self.account, chat).await?;
                return Ok(());
            }
            // A Chat a client is destroying.
            None => return Ok(()),
            Some(chat) => chat.members.unwrap_or_default(),
        };
        let mut after = if changed {
            self.members_of(store, &room, &members)
        } else {
            members.clone()
        };
        if left {
            after.retain(|m| m.id != self.account);
        }
        if after != members {
            self.inner
                .update_object::<Chat>(
                    &(),
                    &self.account,
                    &id,
                    from_json(json!({ "members": after }))?,
                )
                .await?;
        }
        Ok(())
    }

    /// A message record as its Message: made when `added` and absent;
    /// else, unless `added` (a JMAP write made the object), its content
    /// written where it differs.
    async fn project_message(
        &self,
        store: &Store,
        key: &str,
        added: bool,
    ) -> Result<(), SyncError> {
        let Some(message) = store.state().messages.get(key).cloned() else {
            return Ok(());
        };
        let id = Id::from(key);
        let content = Value::Object(shown_content(&message));
        match self.stored::<Message>(&id).await? {
            None if added => {
                let sender = match &message.sender {
                    Sender::User(user) => self.id_of_user(store, user),
                    // A notice is the account's (sync::store_notice before
                    // the store; bead mimid-1wgh.4.81.27).
                    _ => Some(self.account.clone()),
                };
                let Some(sender) = sender else {
                    return Err(SyncError::Store(format!(
                        "message {key} names a sender with no ChatContact"
                    )));
                };
                let mut jmap = Message::new(
                    id,
                    Id::from(message.sender_msg_id.as_str()),
                    sender,
                    Id::from(message.room.as_str()),
                    String::new(),
                    BodyType::Plain,
                    jmap_server::UTCDate::from(utc_date(message.accepted_at).as_str()),
                    now(),
                    DeliveryState::Delivered,
                );
                jmap.reply_to = match &message.in_reply_to {
                    Some(Reply::Message(target)) => Some(Id::from(target.as_str())),
                    _ => None,
                };
                jmap.topic_id = message.topic_id.clone();
                let mut value = to_json(&jmap)?;
                if let (Value::Object(value), Value::Object(content)) = (&mut value, content) {
                    value.extend(content);
                }
                self.inner
                    .insert_object(&self.account, from_json::<Message>(value)?)
                    .await?;
            }
            // A Message a client is destroying.
            None => {}
            Some(_) if added => {}
            Some(existing) => {
                let existing = to_json(&existing)?;
                // The content as the type writes it, merged over the
                // object, so only what really differs is written.
                let mut desired = existing.clone();
                if let (Value::Object(desired), Value::Object(content)) = (&mut desired, content) {
                    desired.extend(content);
                }
                let desired = to_json(&from_json::<Message>(desired)?)?;
                let patch = patch_of(&existing, &desired, &MESSAGE_CONTENT);
                if !patch.is_empty() {
                    self.inner
                        .update_object::<Message>(
                            &(),
                            &self.account,
                            &id,
                            from_json(Value::Object(patch))?,
                        )
                        .await?;
                }
            }
        }
        Ok(())
    }

    /// A ban record as its ChatBan: made when absent, destroyed when the
    /// record is gone.
    async fn project_ban(&self, store: &Store, key: &str) -> Result<(), SyncError> {
        let ban = store.state().bans.get(key).cloned();
        let id = Id::from(key);
        let existing = self.stored::<ChatBan>(&id).await?;
        match (ban, existing) {
            (Some(ban), None) => {
                let user = self.id_of_user(store, &ban.user);
                let banned_by = self.id_of_user(store, &ban.banned_by);
                let (Some(user), Some(banned_by)) = (user, banned_by) else {
                    return Err(SyncError::Store(format!(
                        "ban {key} names a user with no ChatContact"
                    )));
                };
                let chat_ban =
                    ChatBan::new(id, Id::from(ban.room.as_str()), user, banned_by, now());
                self.inner.insert_object(&self.account, chat_ban).await?;
            }
            (None, Some(_)) => {
                self.inner
                    .destroy_object::<ChatBan>(&(), &self.account, &id)
                    .await?;
            }
            _ => {}
        }
        Ok(())
    }
}
