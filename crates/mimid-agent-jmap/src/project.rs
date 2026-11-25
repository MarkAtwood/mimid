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
//! | Room | Chat, kind `group`, or `direct` with `contactId` for a one-to-one room (§7.29) | `name`, `roomId` (made only), `members` (a group Chat), `messageExpirySeconds` |
//! | Message | Message | `senderMsgId`, `senderId`, `chatId`, `sentAt`, `receivedAt`, `replyTo`, `topicId`, `deliveryState`, `senderExpiresAt`, `burnOnRead`, `expiresAfterReadSeconds` (made only); `reactions`, `body`, `bodyType`, `attachments`, `actions` (the calls, §7.24), `editedAt`, `editHistory`, `deletedAt`, `deletedForAll` |
//! | Ban | ChatBan | all, made only; destroyed when the record is gone |
//! | Read position | ReadPosition | `chatId` (made only), `lastReadMessageId`, `lastReadAt`; destroyed when the record is gone |
//!
//! A record deleted (a forgotten person, a deleted message, a room
//! deleted with its messages and bans) destroys its object, if there is
//! one; a message deleted at its expiry is hard-deleted
//! (`ChatMessageLifecycle::expire_message`). Invites have no projection:
//! JMAP Chat has no object for an invite. A read position another front
//! end moved (IRC's `MARKREAD`, docs/design/agent-frontends.md §7.34) is
//! the ReadPosition of the same key, made if there is none.
//!
//! # Limitations
//!
//! - A Chat's `createdAt` and a ChatContact's `firstSeenAt` are when the
//!   object is made here, as before the store. A Message's `receivedAt`
//!   is the record's arrival time (docs/design/agent-frontends.md §7.18).
//! - Dates the store owns are compared to the millisecond, so an object
//!   whose date text differs (a client's, or one with more digits) is not
//!   rewritten for that alone.
//! - Destroying a Chat destroys each of its Messages, one Message change
//!   each, so a long history can push a client's state out of the change
//!   log ([`crate::CHANGE_LOG_LIMIT`]): its next `/changes` is then
//!   `cannotCalculateChanges` and it resyncs.

use jmap_chat_server::{ChatMessageLifecycle, ChatStore};

/// What [`JmapExt::project`] lists for a Message hard-deleted at its
/// expiry, beside the type names of the objects it destroys.
const EXPIRED: &str = "expired Message";
use jmap_chat_types::{BodyType, Chat, ChatBan, ChatContact, Message, ReadPosition};
use jmap_server::{
    BackendSetError, GetObject, Id, JmapObject, JmapReads, SetErrorType, SetObject, now_utc_string,
};
use mimid_agent_store::convert::{parse_utc_date, utc_date};
use mimid_agent_store::record::{self, Sender};
use mimid_agent_store::{Change, State, Store};
use serde_json::{Map, Value, json};

use crate::edits::retraction_patch;
use crate::persist::JmapExt;
use crate::render::Render;
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
            ("reactions", Some(Value::Object(m))) if m.is_empty() => None,
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
const MESSAGE_CONTENT: [&str; 9] = [
    "reactions",
    "body",
    "bodyType",
    "attachments",
    "actions",
    "editedAt",
    "editHistory",
    "deletedAt",
    "deletedForAll",
];

/// The ChatContact properties the store owns after the contact is made.
const CONTACT_DID: [&str; 2] = ["did", "didChangedAt"];

/// The ReadPosition properties the store owns after it is made.
const POSITION: [&str; 2] = ["lastReadMessageId", "lastReadAt"];

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

/// The MessageAction and Endpoint `type` of a video or voice call
/// (draft-atwood-jmap-chat-00 §Endpoint): a call to join is shown as a
/// MessageAction of this type (docs/design/agent-frontends.md §7.24).
pub(crate) const VTC: &str = "urn:ietf:params:jmap:chat:cap:vtc";

/// The JSON of a record's call as a JMAP MessageAction
/// (draft-atwood-jmap-chat-00 §MessageAction): `type` [`VTC`], `uri` the
/// URL, `label` the description if it has one, `expiresAt` the part's
/// `expires` if it has one. Only for a call that [`record::Call::is_link`].
fn action_json(call: &record::Call) -> Value {
    let mut action = Map::new();
    action.insert("type".to_owned(), json!(VTC));
    action.insert("uri".to_owned(), json!(call.url));
    if !call.description.is_empty() {
        action.insert("label".to_owned(), json!(call.description));
    }
    if let Some(at) = call.expires {
        action.insert(
            "expiresAt".to_owned(),
            json!(utc_date(u64::from(at) * 1000)),
        );
    }
    Value::Object(action)
}

/// A Message's `body` for `message`: its text, then a line of
/// [`record::Call::text`] for each call that is no link, which is shown
/// as text and never as a MessageAction (docs/design/agent-frontends.md
/// §7.24).
fn body_json(message: &record::Message) -> Value {
    let mut body = message.body.clone();
    for call in message.calls.iter().filter(|c| !c.is_link()) {
        if !body.is_empty() {
            body.push('\n');
        }
        body.push_str(&call.text());
    }
    json!(body)
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
    fields.insert("body".to_owned(), body_json(message));
    fields.insert("bodyType".to_owned(), body_type_json(message.body_type));
    fields.insert(
        "attachments".to_owned(),
        Value::Array(message.attachments.iter().map(attachment_json).collect()),
    );
    fields.insert(
        "actions".to_owned(),
        Value::Array(
            message
                .calls
                .iter()
                .filter(|c| c.is_link())
                .map(action_json)
                .collect(),
        ),
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
/// `deletedAt`: empty `body` and `attachments`, no `editHistory`; and no
/// `actions`, docs/design/agent-frontends.md §7.24), while
/// the record keeps its content for reports.
pub(crate) fn shown_content(message: &record::Message) -> Map<String, Value> {
    let mut content = message_content(message);
    if matches!(
        message.deleted,
        Some(record::Deletion { for_all: false, .. })
    ) {
        content.insert("body".to_owned(), json!(""));
        content.insert("attachments".to_owned(), json!([]));
        content.insert("actions".to_owned(), json!([]));
        content.insert("editHistory".to_owned(), Value::Null);
    }
    content
}

impl JmapExt {
    /// Writes the records `changes` name into the backend (see the module
    /// documentation).
    pub(crate) async fn project(&self, store: &Store, changes: &[Change]) -> Result<(), SyncError> {
        let (mut people, mut rooms, mut messages, mut bans, mut positions) = (
            Named::default(),
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
                Change::MessageExpired(key) => gone.push((EXPIRED, key)),
                Change::BanAdded(key) => bans.added(key),
                Change::BanChanged(key) | Change::BanLifted(key) => bans.changed(key),
                Change::ReadPositionMoved(key) => positions.changed(key),
                Change::ReadPositionForgotten(key) => gone.push((ReadPosition::TYPE_NAME, key)),
                // Invites have no projection; Change is #[non_exhaustive].
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
        for key in &positions.keys {
            self.project_read_position(store, key).await?;
        }
        for (type_name, key) in gone {
            match type_name {
                "ChatContact" => self.destroy_unheld::<ChatContact>(&key).await,
                "Chat" => self.destroy_unheld::<Chat>(&key).await,
                "ChatBan" => self.destroy_unheld::<ChatBan>(&key).await,
                "ReadPosition" => self.destroy_unheld::<ReadPosition>(&key).await,
                EXPIRED => self.expire(&key).await,
                _ => self.destroy_unheld::<Message>(&key).await,
            }
        }
        Ok(())
    }

    /// A read position as its ReadPosition: made if absent, else its
    /// `lastReadMessageId` and `lastReadAt` written where they differ. A
    /// JMAP write shows it already, so writes nothing.
    async fn project_read_position(&self, store: &Store, key: &str) -> Result<(), SyncError> {
        let Some(position) = store.state().read_positions.get(key).cloned() else {
            return Ok(());
        };
        let rendered = self
            .render(&store.state())
            .read_position(&position)
            .map_err(SyncError::Store)?;
        let id = Id::from(key);
        match self.stored::<ReadPosition>(&id).await? {
            None => {
                self.inner
                    .insert_object(
                        &self.account,
                        from_json::<ReadPosition>(Value::Object(rendered))?,
                    )
                    .await?;
            }
            Some(existing) => {
                let patch = patch_of(&to_json(&existing)?, &Value::Object(rendered), &POSITION);
                if !patch.is_empty() {
                    self.inner
                        .update_object::<ReadPosition>(
                            &self.account,
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

    /// The stored object `id` of type `O`.
    async fn stored<O: GetObject + Send + Sync>(&self, id: &Id) -> Result<Option<O>, SyncError> {
        let (mut found, _) = self
            .inner
            .get_objects::<O>(
                &self.account,
                &self.account,
                Some(std::slice::from_ref(id)),
                None,
            )
            .await?;
        Ok(found.pop())
    }

    /// Destroys object `key` of type `O`, whose record is gone, if the
    /// backend holds it; a failure is logged, since the record is gone
    /// already.
    async fn destroy_unheld<O: SetObject + Send + Sync>(&self, key: &str) {
        match self
            .inner
            .destroy_object::<O>(&self.account, &self.account, &Id::from(key))
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

    /// Hard-deletes Message `key`, whose record expired
    /// (draft-atwood-jmap-chat-00 §Message: "A hard-deleted message appears
    /// in the `destroyed` list of subsequent `Message/changes` responses";
    /// crate-jmap's `expire_message` also unpins it, §Chat
    /// `pinnedMessageIds`); nothing if the backend has no such Message.
    async fn expire(&self, key: &str) {
        if let Err(error) = self
            .inner
            .expire_message(&self.account, &self.account, &Id::from(key))
            .await
        {
            tracing::error!(
                name: "agent_chat_expire_failed",
                error = %error,
                "a Message whose record expired was not destroyed"
            );
        }
    }

    /// The records of `state` rendered as this front end names users.
    fn render<'a>(&'a self, state: &'a State) -> Render<'a> {
        Render {
            state,
            account: &self.account,
            user: &self.user,
        }
    }

    /// Whether `user` has a JMAP id: the user, or a person with a
    /// ChatContact.
    fn names(&self, store: &Store, user: &str) -> bool {
        self.render(&store.state()).known_id(user).is_some()
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
                let contact = self
                    .render(&store.state())
                    .person(&person)
                    .map_err(SyncError::Store)?;
                self.inner
                    .insert_object(
                        &self.account,
                        from_json::<ChatContact>(Value::Object(contact))?,
                    )
                    .await?;
            }
            None => {}
            Some(contact) => {
                let patch = patch_of(&to_json(&contact)?, &did, &CONTACT_DID);
                if !patch.is_empty() {
                    self.inner
                        .update_object::<ChatContact>(
                            &self.account,
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

    /// The stored `VTCCall` whose `mimiRoomId` is `uri`, if this account
    /// has one. The mirror of `AgentChat::call_of_room`, on the side that
    /// projects rather than the side that serves.
    async fn call_naming_room(
        &self,
        uri: &str,
    ) -> Result<Option<jmap_vtc_types::VtcCall>, SyncError> {
        let (calls, _) = self
            .inner
            .get_objects::<jmap_vtc_types::VtcCall>(&self.account, &self.account, None, None)
            .await
            .map_err(|e| SyncError::Store(format!("reading the calls: {e}")))?;
        Ok(calls.into_iter().find(|call| {
            call.extra
                .get(crate::vtc_backend::MIMI_ROOM_ID)
                .and_then(serde_json::Value::as_str)
                == Some(uri)
        }))
    }

    /// A call's own room as a `VTCCall`, for the side that did not start
    /// the call (bead mimid-1wgh.114.11).
    ///
    /// `Store::start_call` invites the chat's people to the call room, so
    /// both sides get its signals as messages; but only the agent that
    /// ran `VTCCall/set` had a `VTCCall`, and
    /// `crate::vtc_stream`'s pump drops a signal it cannot name a call
    /// for. Without this a call could not connect in either direction:
    /// the other side opened the socket, subscribed, and received
    /// nothing.
    ///
    /// The id is the room's store key, as a Chat's is, so it is the same
    /// at every projection and across restarts; `mimiRoomId` is the
    /// room's URI, which is what crosses providers.
    ///
    /// # Limitations
    ///
    /// - `mediaTypes` is empty, and `subject` and `joinUri` are empty or
    ///   absent: the room carries none of them, and the creator's choices
    ///   do not cross with it. They belong in the announcement of bead
    ///   mimid-1wgh.114.1, which is what a client should read them from.
    ///   Signalling does not depend on them: the SDP is what says which
    ///   media a call carries.
    /// - `initiatorId` is the call room's admin by the role naming
    ///   `crate::render` already uses, not a recorded "who pressed call",
    ///   which the room does not keep. With no admin it is the first
    ///   participant.
    /// - `createdAt` is when this agent first projected the room, not
    ///   when the call started.
    async fn project_call_room(
        &self,
        store: &Store,
        room: &record::Room,
        added: bool,
    ) -> Result<(), SyncError> {
        // With `[jmap] vtc` off no VTCCall type is served, so a record
        // here would be invisible to every client and misleading to
        // anything that read the store (decision mimid-1wgh.119).
        if !self.vtc {
            return Ok(());
        }
        // The agent that started the call already has a VTCCall of its
        // own, with the id `VTCCall/set` minted; this must not make a
        // second one for the same room. It is matched on `mimiRoomId`
        // rather than on the id, exactly because that id is not the
        // room's key (`AgentChat::call_of_room` does the same).
        if self.call_naming_room(&room.uri).await?.is_some() {
            return Ok(());
        }
        if !added {
            return Ok(());
        }
        // The chat the call hangs under, by the parent room's store key,
        // which is the Chat's id. A call whose parent this agent is not
        // in gets no record: there would be no chat for a client to show
        // it against.
        let Some(parent) = room.parent.as_deref() else {
            return Ok(());
        };
        let Some(chat) = store.state().room_of_uri(parent).cloned() else {
            return Ok(());
        };
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
        let call: jmap_vtc_types::VtcCall = from_json(json!({
            "id": room.key,
            "accountId": self.account,
            "callType": "room",
            "state": "active",
            "createdAt": now(),
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
        }))?;
        self.inner.insert_object(&self.account, call).await?;
        tracing::debug!(
            room = %room.uri,
            "a call room was projected as a VTCCall"
        );
        Ok(())
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
        // A call's own room gets no Chat
        // (crate::render::Render::is_call_room): it gets a VTCCall, so
        // that a client on the receiving side has the record a call
        // signal is addressed to (bead mimid-1wgh.114.11).
        if crate::render::Render::is_call_room(&room) {
            return self.project_call_room(store, &room, added).await;
        }
        let id = Id::from(key);
        let existing = self.stored::<Chat>(&id).await?;
        // The room's local expiry policy, which another front end may set
        // (docs/design/agent-frontends.md §7.21).
        if let Some(chat) = &existing
            && changed
            && chat.message_expiry_seconds != room.message_expiry_seconds
        {
            self.inner
                .update_object::<Chat>(
                    &self.account,
                    &self.account,
                    &id,
                    from_json(json!({ "messageExpirySeconds": room.message_expiry_seconds }))?,
                )
                .await?;
        }
        let members = match existing {
            None if added => {
                let mut chat = self.render(&store.state()).new_chat(&room, now());
                if left && let Some(members) = &mut chat.members {
                    members.retain(|m| m.id != self.account);
                }
                self.inner.insert_object(&self.account, chat).await?;
                return Ok(());
            }
            // A Chat a client is destroying.
            None => return Ok(()),
            // A direct Chat has no members (draft-atwood-jmap-chat-00
            // §Chat `members`: "Group chats only").
            Some(chat) if chat.kind == jmap_chat_types::ChatKind::Direct => return Ok(()),
            Some(chat) => chat.members.unwrap_or_default(),
        };
        let mut after = if changed {
            self.render(&store.state()).members(&room, &members, &now())
        } else {
            members.clone()
        };
        if left {
            after.retain(|m| m.id != self.account);
        }
        if after != members {
            self.inner
                .update_object::<Chat>(
                    &self.account,
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
        // A room with no Chat has nowhere to put a Message
        // (crate::render::Render::is_call_room).
        if store
            .state()
            .rooms
            .get(&message.room)
            .is_some_and(crate::render::Render::is_call_room)
        {
            return Ok(());
        }
        let id = Id::from(key);
        match self.stored::<Message>(&id).await? {
            None if added => {
                if let Sender::User(user) = &message.sender
                    && !self.names(store, user)
                {
                    return Err(SyncError::Store(format!(
                        "message {key} names a sender with no ChatContact"
                    )));
                }
                let jmap = self
                    .render(&store.state())
                    .new_message(&message)
                    .map_err(SyncError::Store)?;
                self.inner.insert_object(&self.account, jmap).await?;
            }
            // A Message a client is destroying.
            None => {}
            Some(_) if added => {}
            Some(existing) => {
                let existing = to_json(&existing)?;
                // The content as the type writes it, merged over the
                // object, so only what really differs is written.
                let mut desired = existing.clone();
                let reactions = self.render(&store.state()).reactions(&message);
                if let Value::Object(desired) = &mut desired {
                    desired.extend(shown_content(&message));
                    desired.insert("reactions".to_owned(), reactions);
                }
                let desired = to_json(&from_json::<Message>(desired)?)?;
                let patch = patch_of(&existing, &desired, &MESSAGE_CONTENT);
                if !patch.is_empty() {
                    self.inner
                        .update_object::<Message>(
                            &self.account,
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
                if !(self.names(store, &ban.user) && self.names(store, &ban.banned_by)) {
                    return Err(SyncError::Store(format!(
                        "ban {key} names a user with no ChatContact"
                    )));
                }
                let chat_ban = self.render(&store.state()).new_ban(&ban, now());
                self.inner.insert_object(&self.account, chat_ban).await?;
            }
            (None, Some(_)) => {
                self.inner
                    .destroy_object::<ChatBan>(&self.account, &self.account, &id)
                    .await?;
            }
            _ => {}
        }
        Ok(())
    }
}
