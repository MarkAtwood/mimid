//! [`AgentChat`]: a JMAP Chat backend whose store is crate-jmap's
//! `MemoryBackend` and whose writes go to MIMI rooms through an [`Agent`].

use std::sync::Arc;

use jmap_chat_server::memory::{MemoryBackend, MemoryError};
use jmap_chat_server::{
    AttachmentBlob, ChatEvents, ChatLimits, ChatMessageLifecycle, ChatModeration, ChatResolvers,
    ChatRestrictions, ChatSettings, ChatStore, DelegateChatAccessPolicy, DelegateChatSpaces,
    DelegateSpacePolicy,
};
use jmap_chat_types::{
    BodyType, Chat, ChatBan, ChatContact, ChatMember, ChatMemberRole, DeliveryState, Message,
    ReadPosition,
};
use jmap_server::{
    BackendSetError, DelegateJmapReads, Dispatcher, GetObject, Id, JmapAccounts, JmapObject,
    JmapReads, SetError, SetErrorType, SetObject, UTCDate,
};
use mimid_agent_core::{Agent, AgentError, MAX_TEXT_LEN};
use serde_json::{Value, json};
use tokio::sync::Mutex;

use crate::convert::utc_date;
use crate::project::VTC;
use mimid_agent_store::action::{MemberChanges, OutgoingFile, Role, SendOptions};
use mimid_agent_store::blobs::{BlobError, BlobQuota, BlobStore, MAX_ATTACHMENT_LEN};
use mimid_agent_store::convert::parse_utc_date;
use mimid_agent_store::record::{Call, MessageExpiry};
use mimid_agent_store::{ActionError, ExpiryError, Store};

pub use mimid_agent_store::InvitePolicy;
pub use mimid_agent_store::sync::MAX_ATTACHMENTS_PER_MESSAGE;

/// The Chat property that names its MIMI room
/// (draft-atwood-jmap-chat-mimi-00 §Chat.roomId).
pub(crate) const ROOM_ID: &str = "roomId";

/// The change-log entries the store keeps per data type, by default: a
/// client's `/changes` from an older state is `cannotCalculateChanges`
/// (RFC 8620 §5.2) and it resyncs. INVENTED VALUE, NOT FROM SPEC
/// (decision mimid-1wgh.66).
pub const CHANGE_LOG_LIMIT: usize = 4096;

/// Settings of an [`AgentChat`].
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Options {
    /// Which invites to join.
    pub invites: InvitePolicy,
    /// The change-log entries kept per data type ([`CHANGE_LOG_LIMIT`]
    /// by default; at least one is kept).
    pub change_log_limit: usize,
    /// The quota of unreferenced blobs ([`BlobQuota::default`] by
    /// default; decision mimid-1wgh.68).
    pub blob_quota: BlobQuota,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            invites: InvitePolicy::default(),
            change_log_limit: CHANGE_LOG_LIMIT,
            blob_quota: BlobQuota::default(),
        }
    }
}

impl Options {
    /// Options with invite policy `invites`.
    pub fn with_invites(mut self, invites: InvitePolicy) -> Self {
        self.invites = invites;
        self
    }

    /// Options keeping `limit` change-log entries per data type.
    pub fn with_change_log_limit(mut self, limit: usize) -> Self {
        self.change_log_limit = limit;
        self
    }

    /// Options holding unreferenced blobs to `quota`.
    pub fn with_blob_quota(mut self, quota: BlobQuota) -> Self {
        self.blob_quota = quota;
        self
    }
}

/// One user's MIMI rooms as a JMAP Chat account.
///
/// The records live in a [`Store`], which is the agent's journal
/// consumer and may serve other front ends too ([`AgentChat::over`]); the
/// JMAP objects live in a crate-jmap `MemoryBackend`, a projection of the
/// records under their keys, which every save of the store brings up to
/// date with what the store's change feed publishes (the `project` module).
/// Each client write is a call of the store's method for it
/// ([`mimid_agent_store::action`]), which sends what means something in
/// MIMI through the [`Agent`] and writes the records; the write hook
/// translates JMAP ids to store keys and user URIs, and the store's
/// errors to SetErrors, then writes the JMAP object and saves. See the
/// crate documentation for what maps and what does not.
pub struct AgentChat {
    pub(crate) inner: MemoryBackend,
    pub(crate) account: Id,
    pub(crate) user: String,
    /// The agent, the records and the blob store, maybe shared with other
    /// front ends.
    pub(crate) store: Arc<Store>,
    pub(crate) options: Options,
}

impl std::fmt::Debug for AgentChat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AgentChat")
            .field("account", &self.account)
            .field("user", &self.user)
            .finish_non_exhaustive()
    }
}

impl AgentChat {
    /// An account `account_id` over `agent`, empty until the first
    /// [`AgentChat::sync`], with a [`Store`] of its own that joins the
    /// invites [`Options::invites`] allows.
    pub fn new(agent: Agent, account_id: Id, options: Options) -> Self {
        let store = Arc::new(Store::new(agent, options.invites.clone()));
        Self::build(store, account_id, options)
    }

    /// An account `account_id` over `store`, which the caller has opened
    /// ([`Store::open_database`]) and given its blob store
    /// ([`Store::with_blobs`]), and which other front ends may share:
    /// each record of it is shown, under its key, as the object it was
    /// saved as, and a record saved with no JMAP object (stored while
    /// JMAP was off) as an object made new from the record, as a sync
    /// would have made it (docs/design/agent-frontends.md §7.11). From now on every save of the store,
    /// whoever asks for it, shows the changes it publishes as JMAP objects
    /// and keeps them in `ext["jmap"]` (see `persist`). The store's
    /// invite policy and blob quota are its own: [`Options::invites`] and
    /// [`Options::blob_quota`] are not used.
    ///
    /// # Errors
    ///
    /// [`crate::PersistError::Malformed`] if the records are another
    /// account's, or a record, with what `ext["jmap"]` keeps of it, does
    /// not make a JMAP object.
    pub fn over(
        store: Arc<Store>,
        account_id: Id,
        options: Options,
    ) -> Result<Self, crate::PersistError> {
        let chat = Self::build(store, account_id, options);
        chat.load_records(std::path::Path::new("the plaintext store"))?;
        Ok(chat)
    }

    /// An account over `store`, with the JMAP front end registered on it.
    fn build(store: Arc<Store>, account_id: Id, options: Options) -> Self {
        // Decision mimid-1wgh.66: a bounded change log, and no outbound or
        // lifecycle events recorded, since nothing here reads them (every
        // outbound change goes to the agent in the write hooks).
        let inner = MemoryBackend::new()
            .with_change_log_limit(options.change_log_limit)
            .with_event_limit(0);
        inner.register_account(&account_id);
        let user = store.user().to_owned();
        // Every save, whoever asks for it, shows its changes and rebuilds
        // ext["jmap"] first.
        store.add_frontend(Arc::new(crate::persist::JmapExt {
            inner: inner.clone(),
            account: account_id.clone(),
            user: user.clone(),
        }));
        Self {
            inner,
            account: account_id,
            user,
            store,
            options,
        }
    }

    /// Keeps attachments in a [`BlobStore`] in `dir` (created 0700 if
    /// missing): uploads, the attachments of Messages sent, and those
    /// fetched for Messages received, with unreferenced blobs held to
    /// [`Options::blob_quota`]. Without it Messages carry no attachments:
    /// the account's limits allow none and received ones are left out. A
    /// store that has a blob store already ([`AgentChat::over`]) keeps it,
    /// and this logs a warning.
    ///
    /// # Errors
    ///
    /// The [`BlobError`] of [`BlobStore::open`].
    pub fn with_blobs(self, dir: impl Into<std::path::PathBuf>) -> Result<Self, BlobError> {
        let blobs = BlobStore::open(dir)?.with_quota(self.options.blob_quota);
        if self.store.set_blobs(blobs).is_err() {
            tracing::warn!(
                name: "agent_chat_blob_store_kept",
                "the store has a blob store already; it is kept"
            );
        }
        Ok(self)
    }

    /// Every blob id the store names, for the blob store's quota
    /// (decision mimid-1wgh.68; [`Store::blobs_in_use`]): each message's
    /// attachments ([`Store::referenced_blobs`]), and the value of any
    /// property named `blobId` or ending in `BlobId`, at any depth, of what
    /// the records keep for JMAP alone (`ext["jmap"]`: an attachment's
    /// thumbnail, a Chat's avatar), and whatever other front ends name. A destroyed Message is no longer stored and a
    /// retracted one has no attachments, so theirs do not count.
    /// Attachments waiting for another fetch ([`crate::retry`]) name a
    /// URL, not a blob here, so they add nothing; a blob a retry stores is
    /// named by its Message in the same sync and is younger than
    /// [`crate::MIN_UNREFERENCED_AGE`] meanwhile.
    ///
    /// # Errors
    ///
    /// None now; the [`crate::PersistError`] is kept for callers.
    pub async fn referenced_blobs(
        &self,
    ) -> Result<std::collections::BTreeSet<String>, crate::PersistError> {
        Ok(self.store.blobs_in_use())
    }

    /// The blob store, if there is one: the daemon serves uploads and
    /// downloads from it.
    pub fn blobs(&self) -> Option<&BlobStore> {
        self.store.blobs()
    }

    /// Test-only: drains the store's recorded outbound and lifecycle
    /// events and returns how many there were (decision mimid-1wgh.66:
    /// none are recorded).
    #[doc(hidden)]
    pub fn drain_store_events_for_test(&self) -> (usize, usize) {
        (
            self.inner.drain_outbound_events().len(),
            self.inner.drain_lifecycle_events().len(),
        )
    }

    /// Registers the JMAP Chat methods (`Chat/*`, `Message/*`,
    /// `ChatContact/*`, `ChatBan/*` and the rest of crate-jmap's set) and
    /// `Message/reportAbuse` ([`crate::report`]) on `dispatcher`, served
    /// by `this`.
    pub fn register(this: &Arc<Self>, dispatcher: &mut Dispatcher<()>) {
        jmap_chat_server::register_chat_handlers(dispatcher, Arc::clone(this));
        crate::report::register(this, dispatcher);
    }

    /// The JMAP account id.
    pub fn account_id(&self) -> &Id {
        &self.account
    }

    /// The agent, for what JMAP Chat has no method for: publishing
    /// KeyPackages and consent decisions. Never `Agent::receive` or
    /// `Agent::acknowledge` ([`Store::agent`]).
    pub fn agent(&self) -> &Arc<Mutex<Agent>> {
        self.store.agent()
    }

    /// The store this account is over.
    pub fn store(&self) -> &Arc<Store> {
        &self.store
    }

    /// The Chat bound to MIMI room `room`: the key of its room record.
    pub fn chat_of_room(&self, room: &str) -> Option<Id> {
        self.store
            .state()
            .room_of_uri(room)
            .map(|key| Id::from(key.as_str()))
    }

    /// The MIMI room of Chat `chat`.
    pub fn room_of_chat(&self, chat: &Id) -> Option<String> {
        self.store
            .state()
            .rooms
            .get(chat.as_ref())
            .map(|room| room.uri.clone())
    }

    /// `result`, after saving the store when it is a success.
    async fn saved<T, E>(&self, result: Result<T, E>) -> Result<T, E> {
        if result.is_ok() {
            self.save_or_log().await;
        }
        result
    }

    /// The stored object `id` of type `O`.
    pub(crate) async fn stored<O: GetObject + Send + Sync>(
        &self,
        id: &Id,
    ) -> Result<Option<O>, MemoryError> {
        let (mut found, _) = self
            .inner
            .get_objects::<O>(&(), &self.account, Some(std::slice::from_ref(id)), None)
            .await?;
        Ok(found.pop())
    }

    /// The `identity` of ChatContact `id`.
    pub(crate) async fn contact_identity(&self, id: &Id) -> Result<Option<String>, MemoryError> {
        Ok(self.stored::<ChatContact>(id).await?.map(|c| c.identity))
    }

    /// The MIMI user URIs of the ChatContacts `ids`, or `invalidProperties`
    /// on `property` if one is not a ChatContact.
    pub(crate) async fn users_of(
        &self,
        ids: &[Id],
        property: &str,
    ) -> Result<Vec<String>, SetFailure> {
        let mut users = Vec::with_capacity(ids.len());
        for id in ids {
            match self.contact_identity(id).await.map_err(SetFailure::Other)? {
                Some(user) => users.push(user),
                None => {
                    return Err(SetFailure::set(
                        set_error(
                            SetErrorType::InvalidProperties,
                            format!("{id} is not a ChatContact"),
                        )
                        .with_properties([property]),
                    ));
                }
            }
        }
        Ok(users)
    }

    fn check_account(&self, account_id: &Id) -> Result<(), SetFailure> {
        if *account_id == self.account {
            Ok(())
        } else {
            Err(SetFailure::set(set_error(
                SetErrorType::Forbidden,
                "not this agent's account",
            )))
        }
    }

    /// `Chat/set` create: a group Chat hosts a new MIMI room named after
    /// the Chat and invites its other members.
    async fn create_chat<O, F>(&self, build: F) -> Result<(Id, O), BackendSetError<MemoryError>>
    where
        O: SetObject + Send + Sync,
        F: FnOnce(&Id) -> O + Send,
    {
        let id = self.inner.mint_id();
        let mut value = serde_json::to_value(build(&id)).map_err(serde_failure)?;
        if value["kind"] != "group" {
            return Err(forbidden(
                "only a group Chat maps to a MIMI room; direct Chats are not supported",
            ));
        }
        let name = value["name"].as_str().unwrap_or_default().to_owned();
        let members: Vec<ChatMember> =
            serde_json::from_value(value["members"].clone()).unwrap_or_default();
        let others: Vec<Id> = members
            .iter()
            .filter(|m| m.id != self.account)
            .map(|m| m.id.clone())
            .collect();
        let users = self
            .users_of(&others, "memberIds")
            .await
            .map_err(SetFailure::into_backend)?;

        let room = self
            .store
            .create_room(key(&id), &name, &users)
            .await
            .map_err(action_failure)?;
        // Local (docs/design/agent-frontends.md §7.21).
        if let Some(seconds) = value["messageExpirySeconds"].as_u64() {
            self.store.set_message_expiry(&room.key, Some(seconds));
        }
        value[ROOM_ID] = json!(room.uri);
        let chat = serde_json::from_value::<O>(value).map_err(serde_failure)?;
        let chat = self.insert_shown(&id, chat).await?;
        Ok((id, chat))
    }

    /// `Chat/set` update of a Chat bound to a room
    /// ([`Store::change_members`]): added members are invited, removed
    /// members are removed from the room (`Agent::remove`), a changed role
    /// is a role change (`Agent::change_role`: "admin" and "member" are the
    /// room's roles of those names), and the owner's own removal leaves
    /// the room (decision mimid-1wgh.62 items 7, 8). The owner's own role
    /// cannot be changed.
    async fn update_room_chat(&self, chat_id: &Id, patch: &Value) -> Result<(), SetFailure> {
        let Some(after) = patch.get("members") else {
            return Ok(());
        };
        let after: Vec<ChatMember> = serde_json::from_value(after.clone()).map_err(|e| {
            SetFailure::set(
                set_error(SetErrorType::InvalidPatch, e.to_string()).with_properties(["members"]),
            )
        })?;
        let before = self
            .stored::<Chat>(chat_id)
            .await
            .map_err(SetFailure::Other)?
            .and_then(|c| c.members)
            .unwrap_or_default();
        let has = |list: &[ChatMember], id: &Id| list.iter().any(|m| m.id == *id);
        let removed: Vec<Id> = before
            .iter()
            .filter(|m| !has(&after, &m.id))
            .map(|m| m.id.clone())
            .collect();
        let added: Vec<Id> = after
            .iter()
            .filter(|m| !has(&before, &m.id))
            .map(|m| m.id.clone())
            .collect();
        let role_of = |list: &[ChatMember], id: &Id| {
            list.iter().find(|m| m.id == *id).map(|m| m.role.clone())
        };
        let changed: Vec<(Id, ChatMemberRole)> = after
            .iter()
            .filter(|m| role_of(&before, &m.id).is_some_and(|r| r != m.role))
            .map(|m| (m.id.clone(), m.role.clone()))
            .collect();
        if changed.iter().any(|(id, _)| *id == self.account) {
            return Err(SetFailure::set(
                set_error(
                    SetErrorType::Forbidden,
                    "the owner's own role in a MIMI room cannot be changed",
                )
                .with_properties(["members"]),
            ));
        }
        let others: Vec<Id> = removed
            .iter()
            .filter(|id| **id != self.account)
            .cloned()
            .collect();
        let leaving = others.len() < removed.len();
        let added = self.users_of(&added, "addMembers").await?;
        let removed = self.users_of(&others, "removeMembers").await?;
        let changed_ids: Vec<Id> = changed.iter().map(|(id, _)| id.clone()).collect();
        let changed_users = self.users_of(&changed_ids, "updateMemberRoles").await?;
        let mut changes = MemberChanges::new();
        changes.invite = added;
        changes.remove = removed;
        changes.roles = changed_users
            .into_iter()
            .zip(&changed)
            .map(|(user, (_, role))| {
                let role = if *role == ChatMemberRole::Admin {
                    Role::Admin
                } else {
                    Role::Member
                };
                (user, role)
            })
            .collect();
        changes.leave = leaving;
        self.store
            .change_members(chat_id.as_ref(), &changes)
            .await
            .map_err(action_set_failure)
    }

    /// `Message/set` create ([`Store::send`]): the body goes to the Chat's
    /// room as a `text/plain` MIMI message, with each attachment's blob
    /// encrypted, uploaded and sent as an ExternalPart
    /// (`Agent::send_message`), and the stored Message, the client's
    /// attachments included, carries the `senderMsgId` its recipients
    /// derive. crate-jmap has already checked each blob's size and digest
    /// (`attachment_blob`); a blob gone since is `invalidProperties`.
    async fn create_message_in_room<F>(
        &self,
        build: F,
    ) -> Result<(Id, Message), BackendSetError<MemoryError>>
    where
        F: FnOnce(&Id) -> Message + Send,
    {
        let id = self.inner.mint_id();
        let mut message = build(&id);
        if self.room_of_chat(&message.chat_id).is_none() {
            return Err(forbidden("the Chat is not bound to a MIMI room"));
        }
        if let Some(property) = unsupported_message_property(&message) {
            return Err(BackendSetError::SetError(Box::new(
                set_error(
                    SetErrorType::Forbidden,
                    format!("{property} is not supported over MIMI by this server"),
                )
                .with_properties([property]),
            )));
        }
        let expiry = requested_expiry(&message)?;
        if let Some(call) = requested_call(&message)? {
            if message.reply_to.is_some() {
                return Err(BackendSetError::SetError(Box::new(
                    set_error(
                        SetErrorType::Forbidden,
                        "a call to join is not sent as a reply by this server",
                    )
                    .with_properties(["replyTo"]),
                )));
            }
            let sent = self
                .store
                .send_call(
                    key(&id),
                    message.chat_id.as_ref(),
                    &message.body,
                    &call,
                    expiry,
                )
                .await
                .map_err(action_failure)?;
            message.sender_msg_id = Id::from(sent.sender_msg_id.as_str());
            message.delivery_state = DeliveryState::Delivered;
            message.delivered_at = Some(utc_date(sent.accepted_at));
            let stored = self.insert_shown(&id, message).await?;
            return Ok((id, stored));
        }
        let files: Vec<OutgoingFile> = message
            .attachments
            .iter()
            .map(|a| OutgoingFile::new(a.blob_id.as_ref(), &a.content_type, &a.filename))
            .collect();
        let mut options = SendOptions::new();
        options.expiry = expiry;
        if let Some(target) = &message.reply_to {
            // §Message `replyTo`: it must name a Message of the same Chat.
            if !self.store.state().messages.contains_key(target.as_ref()) {
                return Err(action_failure(ActionError::NotReferable(key(target))));
            }
            options.in_reply_to = Some(key(target));
        }
        let sent = self
            .store
            .send_message(
                key(&id),
                message.chat_id.as_ref(),
                &message.body,
                &files,
                &options,
            )
            .await
            .map_err(action_failure)?;
        message.sender_msg_id = Id::from(sent.sender_msg_id.as_str());
        message.delivery_state = DeliveryState::Delivered;
        message.delivered_at = Some(utc_date(sent.accepted_at));
        let stored = self.insert_shown(&id, message).await?;
        Ok((id, stored))
    }

    /// `Chat/set` destroy (draft-atwood-jmap-chat-00 §Destroying a Chat;
    /// docs/design/agent-frontends.md §7.9): the room is left if the agent
    /// is in it ([`Store::leave`]), the Chat is destroyed (crate-jmap
    /// destroys its ReadPositions), and the store deletes the room with its
    /// records ([`Store::forget_room`]). The save that follows destroys
    /// its Messages and ChatBans too ([`crate::project`]), each a change of
    /// its type, so a client's `/changes` sees them go, and then deletes
    /// the blobs of its attachments that nothing names any more
    /// ([`Store::save`]). The history of the room's other members is
    /// theirs: nothing is sent but the leave.
    async fn destroy_chat<O: SetObject + Send + Sync>(
        &self,
        caller: &(),
        account_id: &Id,
        id: &Id,
    ) -> Result<(), BackendSetError<MemoryError>> {
        if self.room_of_chat(id).is_some() {
            self.store
                .leave(id.as_ref())
                .await
                .map_err(action_failure)?;
        }
        self.inner
            .destroy_object::<O>(caller, account_id, id)
            .await?;
        self.store.forget_room(id.as_ref()).await;
        // The blobs stay if this fails: the database still names them.
        self.save_or_log().await;
        Ok(())
    }

    /// Stores `object`, the JMAP object `id` a write hook made for the
    /// record of the same key that the store just made. A save may have
    /// come between and shown the record already ([`crate::project`]):
    /// the object the hook made then replaces it, property by property,
    /// so the `/set` response and the stored object agree.
    pub(crate) async fn insert_shown<O: SetObject + Send + Sync>(
        &self,
        id: &Id,
        object: O,
    ) -> Result<O, BackendSetError<MemoryError>> {
        let value = serde_json::to_value(&object).map_err(serde_failure)?;
        match self.inner.insert_object(&self.account, object).await {
            Err(BackendSetError::SetError(e)) if e.error_type == SetErrorType::AlreadyExists => {}
            inserted => return inserted,
        }
        let patch: serde_json::Map<String, Value> = value
            .as_object()
            .into_iter()
            .flatten()
            .filter(|(key, _)| *key != "id")
            .map(|(key, v)| (key.clone(), v.clone()))
            .collect();
        let patch = serde_json::from_value(Value::Object(patch)).map_err(serde_failure)?;
        self.inner
            .update_object::<O>(&(), &self.account, id, patch)
            .await?;
        serde_json::from_value(value).map_err(serde_failure)
    }

    /// Writes into the records what a client changed of a local object
    /// `id` of type `type_name` (a ChatContact's `displayName`, a
    /// ReadPosition, a Message's local deletion), as the backend holds it
    /// after the write, through the store's method for it. A failure to
    /// read the object is logged: the write has already succeeded.
    async fn record_local(&self, type_name: &str, id: &Id) {
        if let Err(error) = self.try_record_local(type_name, id).await {
            tracing::error!(
                name: "agent_chat_record_failed",
                type_name,
                error = &error as &dyn std::error::Error,
                "a JMAP write was not written into the store's records"
            );
        }
    }

    async fn try_record_local(&self, type_name: &str, id: &Id) -> Result<(), MemoryError> {
        let date = |d: &UTCDate| parse_utc_date(d.as_ref());
        match type_name {
            "ChatContact" => {
                if let Some(contact) = self.stored::<ChatContact>(id).await? {
                    let held = self
                        .store
                        .rename_person(id.as_ref(), contact.display_name.clone());
                    if !held {
                        self.store
                            .add_person(key(id), &contact.identity, contact.display_name);
                    }
                }
            }
            "ReadPosition" => {
                if let Some(position) = self.stored::<ReadPosition>(id).await? {
                    self.store.set_read_position(
                        key(id),
                        key(&position.chat_id),
                        position.last_read_message_id.as_ref().map(key),
                        position.last_read_at.as_ref().and_then(date),
                    );
                }
            }
            "Message" => {
                let Some(message) = self.stored::<Message>(id).await? else {
                    return Ok(());
                };
                if let Some(at) = message.deleted_at.as_ref().and_then(date) {
                    self.store.mark_deleted(id.as_ref(), at);
                }
                // The owner's readAt is the read of the read rules
                // (docs/design/agent-frontends.md §7.22); only the first
                // counts.
                if let Some(at) = message.read_at.as_ref().and_then(date) {
                    self.store.mark_read(id.as_ref(), at);
                }
            }
            _ => {}
        }
        Ok(())
    }

    /// Forgets in the records the local object `id` of type `type_name`
    /// that a client destroyed: a Message (with a tombstone), a
    /// ChatContact or a ReadPosition.
    fn forget_local(&self, type_name: &str, id: &Id) {
        match type_name {
            "Message" => {
                self.store.delete_message(id.as_ref());
            }
            "ChatContact" => {
                self.store.forget_person(id.as_ref());
            }
            "ReadPosition" => {
                self.store.forget_read_position(id.as_ref());
            }
            _ => {}
        }
    }
}

/// The store key of the record JMAP id `id` names: the same text.
pub(crate) fn key(id: &Id) -> String {
    id.as_ref().to_owned()
}

/// `invalidProperties` on `attachments`: blob `id` is not in the store, or
/// there is no store.
fn no_blob(id: Option<&str>) -> BackendSetError<MemoryError> {
    let description = match id {
        Some(id) => format!("no blob {id}"),
        None => "this account stores no attachments".to_owned(),
    };
    BackendSetError::SetError(Box::new(
        set_error(SetErrorType::InvalidProperties, description).with_properties(["attachments"]),
    ))
}

/// The first property of a Message to create that MIMI text messages do
/// not carry here.
fn unsupported_message_property(message: &Message) -> Option<&'static str> {
    if message.body_type != BodyType::Plain {
        Some("bodyType")
    } else if !message.mentions.is_empty() {
        Some("mentions")
    } else if !message.broadcast_mentions.is_empty() {
        Some("broadcastMentions")
    } else if message.thread_root_id.is_some() && message.reply_to.is_none() {
        // crate-jmap derives threadRootId from replyTo itself
        // (draft-atwood-jmap-chat-00 §Threads); one a client set without
        // replyTo has no MIMI form.
        Some("threadRootId")
    } else if message.topic_id.is_some() {
        Some("topicId")
    } else if message.subject.is_some() {
        Some("subject")
    } else {
        None
    }
}

/// The expiry a `Message/set` create asks (draft-atwood-jmap-chat-00
/// §Message; docs/design/agent-frontends.md §7.20, §7.22), or
/// `invalidProperties` on the property that cannot be sent: an
/// `expiresAfterReadSeconds` past `uint .size 4`, as `expires` and
/// [`mimid_agent_store::expiry::READ_EXPIRY_KEY`] carry it, or a date
/// that does not parse. crate-jmap has already refused a
/// `senderExpiresAt` in the past; the store checks it again, that it is
/// at most a year ahead, and that `expiresAfterReadSeconds` is at most a
/// year.
fn requested_expiry(message: &Message) -> Result<MessageExpiry, BackendSetError<MemoryError>> {
    let invalid = |property: &str, why: &str| {
        BackendSetError::SetError(Box::new(
            set_error(SetErrorType::InvalidProperties, why).with_properties([property]),
        ))
    };
    let mut expiry = MessageExpiry::default();
    if let Some(at) = &message.sender_expires_at {
        expiry.sender_expires_at = Some(
            parse_utc_date(at.as_ref())
                .ok_or_else(|| invalid("senderExpiresAt", "not a UTCDate"))?,
        );
    }
    expiry.burn_on_read = message.burn_on_read == Some(true);
    if let Some(seconds) = message.expires_after_read_seconds {
        expiry.expires_after_read_seconds = Some(u32::try_from(seconds).map_err(|_| {
            invalid(
                "expiresAfterReadSeconds",
                "more seconds than MIMI carries (2^32 - 1)",
            )
        })?);
    }
    Ok(expiry)
}

/// The call to join a `Message/set` create asks
/// (docs/design/agent-frontends.md §7.24), as its `actions`: none for no
/// actions; one MessageAction of `type` [`VTC`] (draft-atwood-jmap-chat-00
/// §Endpoint), its `uri` the URL, its `label` the description and its
/// `expiresAt` the part's `expires`, cut to the second. Anything else is
/// `invalidProperties` on `actions`: another type, more than one action,
/// `metadata` (MIMI has no place for it), an `expiresAt` that is no
/// UTCDate or past `uint .size 4` seconds, or attachments beside it.
/// [`Store::send_call`] checks the URL and the label's length.
fn requested_call(message: &Message) -> Result<Option<Call>, BackendSetError<MemoryError>> {
    let invalid = |why: &str| {
        BackendSetError::SetError(Box::new(
            set_error(SetErrorType::InvalidProperties, why).with_properties(["actions"]),
        ))
    };
    let [action] = message.actions.as_slice() else {
        return if message.actions.is_empty() {
            Ok(None)
        } else {
            Err(invalid("at most one action, a call, is sent over MIMI"))
        };
    };
    if action.action_type != VTC {
        return Err(invalid(&format!("only a call ({VTC}) is sent over MIMI")));
    }
    if action.metadata.is_some() {
        return Err(invalid("a call's metadata is not sent over MIMI"));
    }
    if !message.attachments.is_empty() {
        return Err(invalid("a call is sent without attachments"));
    }
    let expires = match &action.expires_at {
        None => None,
        Some(at) => {
            let ms = parse_utc_date(at.as_ref()).ok_or_else(|| invalid("not a UTCDate"))?;
            Some(u32::try_from(ms / 1000).map_err(|_| invalid("expiresAt is too far ahead"))?)
        }
    };
    Ok(Some(Call {
        url: action.uri.clone(),
        description: action.label.clone().unwrap_or_default(),
        expires,
    }))
}

/// A failure of a write hook before the store is touched.
pub(crate) enum SetFailure {
    Set(Box<SetError>),
    Other(MemoryError),
}

impl SetFailure {
    fn set(e: SetError) -> Self {
        Self::Set(Box::new(e))
    }

    fn into_backend(self) -> BackendSetError<MemoryError> {
        match self {
            Self::Set(e) => BackendSetError::SetError(e),
            Self::Other(e) => BackendSetError::Other(e),
        }
    }
}

pub(crate) fn set_error(kind: SetErrorType, description: impl Into<String>) -> SetError {
    SetError::new(kind).with_description(description)
}

pub(crate) fn forbidden(description: &str) -> BackendSetError<MemoryError> {
    BackendSetError::SetError(Box::new(set_error(SetErrorType::Forbidden, description)))
}

pub(crate) fn serde_failure(e: serde_json::Error) -> BackendSetError<MemoryError> {
    BackendSetError::Other(MemoryError::new(format!("converting an object: {e}")))
}

/// The failure for an agent error: the hub's or the room's refusal is
/// `forbidden`, a room the agent is not in is `notFound`, a value the
/// agent refuses is `invalidProperties`, each with the agent's
/// description (the client is the user's own); anything else (network,
/// storage, MLS) is the handler's `serverFail`.
pub(crate) fn agent_set_failure(e: AgentError) -> SetFailure {
    let kind = match &e {
        AgentError::Refused { .. } | AgentError::NoKeyMaterial { .. } => SetErrorType::Forbidden,
        AgentError::NoSuchRoom(_) => SetErrorType::NotFound,
        AgentError::Invalid(_) => SetErrorType::InvalidProperties,
        _ => return SetFailure::Other(MemoryError::new(e.to_string())),
    };
    SetFailure::set(set_error(kind, e.to_string()))
}

/// The failure for a refusal of the store's write methods: the agent's
/// as [`agent_set_failure`]; a room the store does not hold, a role
/// change the room does not allow and a message that cannot be edited
/// `forbidden`; an attachment not in the blob store `invalidProperties`;
/// anything else `serverFail`.
pub(crate) fn action_set_failure(e: ActionError) -> SetFailure {
    let members = |description: &str| {
        SetFailure::set(
            set_error(SetErrorType::Forbidden, description).with_properties(["members"]),
        )
    };
    let forbidden =
        |description: &str| SetFailure::set(set_error(SetErrorType::Forbidden, description));
    match e {
        ActionError::Agent(e) => agent_set_failure(e),
        ActionError::NoSuchRoom(_) => forbidden("the Chat is not bound to a MIMI room"),
        ActionError::NoAdminRole => members("the room has no admin role"),
        ActionError::OwnRole => members("the owner's own role in a MIMI room cannot be changed"),
        // Only edits and retractions name a message, and a Message whose
        // record is gone has no MIMI message ID either.
        ActionError::NoSuchMessage(_) | ActionError::NotEditable(_) => forbidden(
            "no MIMI message ID is kept for this Message, so it cannot be edited or retracted",
        ),
        ActionError::TooManyVersions => forbidden("the Message has too many versions"),
        // draft-atwood-jmap-chat-00 §Message `replyTo`: "Servers MUST
        // validate that this ID exists in the same Chat before storing."
        ActionError::NotReferable(_) => SetFailure::set(
            set_error(
                SetErrorType::InvalidProperties,
                "replyTo names no Message of this Chat that MIMI can refer to",
            )
            .with_properties(["replyTo"]),
        ),
        ActionError::NoBlobStore => match no_blob(None) {
            BackendSetError::SetError(e) => SetFailure::Set(e),
            _ => SetFailure::Other(MemoryError::new("no blob store")),
        },
        ActionError::NoSuchBlob(id) => match no_blob(Some(&id)) {
            BackendSetError::SetError(e) => SetFailure::Set(e),
            _ => SetFailure::Other(MemoryError::new(format!("no blob {id}"))),
        },
        // draft-atwood-jmap-chat-00 §Message `senderExpiresAt`: "in
        // `Message/set` the rejection is an `invalidProperties` SetError
        // with `properties: ["senderExpiresAt"]`".
        ActionError::InvalidCall(_) => SetFailure::set(
            set_error(SetErrorType::InvalidProperties, e.to_string()).with_properties(["actions"]),
        ),
        ActionError::Expiry(e) => {
            let property = match e {
                ExpiryError::ReadTooLong => "expiresAfterReadSeconds",
                _ => "senderExpiresAt",
            };
            SetFailure::set(
                set_error(SetErrorType::InvalidProperties, e.to_string())
                    .with_properties([property]),
            )
        }
        e => SetFailure::Other(MemoryError::new(e.to_string())),
    }
}

pub(crate) fn action_failure(e: ActionError) -> BackendSetError<MemoryError> {
    action_set_failure(e).into_backend()
}

/// The JMAP types this backend serves; the rest of crate-jmap's set
/// (Space, SpaceInvite, SpaceBan, CustomEmoji, PresenceStatus) has no MIMI
/// meaning here. ChatBan writes go through the ChatBan hooks
/// ([`crate::moderate`]), not the generic ones.
fn served(type_name: &str) -> bool {
    matches!(
        type_name,
        "Chat" | "Message" | "ChatContact" | "ReadPosition" | "ChatBan"
    )
}

/// Writes of these types are local: they change only this account.
fn local(type_name: &str) -> bool {
    matches!(type_name, "ChatContact" | "ReadPosition")
}

fn unsupported_type(type_name: &str) -> BackendSetError<MemoryError> {
    BackendSetError::SetError(Box::new(set_error(
        SetErrorType::Forbidden,
        format!("{type_name} is not supported by this server"),
    )))
}

/// Whether `chat` is bound to a MIMI room.
fn room_bound(chat: &Chat) -> bool {
    chat.extra.contains_key(ROOM_ID)
}

impl JmapAccounts for AgentChat {
    type Error = MemoryError;
    type CallerCtx = ();

    async fn account_exists(&self, caller: &(), account_id: &Id) -> Result<bool, MemoryError> {
        Ok(*account_id == self.account && self.inner.account_exists(caller, account_id).await?)
    }
}

impl DelegateJmapReads for AgentChat {
    type Target = MemoryBackend;

    fn jmap_reads(&self) -> &MemoryBackend {
        &self.inner
    }
}

impl ChatStore for AgentChat {
    async fn create_object<O, F>(
        &self,
        caller: &(),
        account_id: &Id,
        create_id: &str,
        build: F,
    ) -> Result<(Id, O), BackendSetError<MemoryError>>
    where
        O: SetObject + Send + Sync,
        F: FnOnce(&Id) -> O + Send,
    {
        self.check_account(account_id)
            .map_err(SetFailure::into_backend)?;
        let result = match O::TYPE_NAME {
            "Chat" => self.create_chat(build).await,
            name if local(name) => {
                let created = self
                    .inner
                    .create_object(caller, account_id, create_id, build)
                    .await;
                if let Ok((id, _)) = &created {
                    self.record_local(name, id).await;
                }
                created
            }
            name => Err(unsupported_type(name)),
        };
        self.saved(result).await
    }

    async fn create_message<F>(
        &self,
        _caller: &(),
        account_id: &Id,
        _create_id: &str,
        build: F,
    ) -> Result<(Id, Message), BackendSetError<MemoryError>>
    where
        F: FnOnce(&Id) -> Message + Send,
    {
        self.check_account(account_id)
            .map_err(SetFailure::into_backend)?;
        let result = self.create_message_in_room(build).await;
        self.saved(result).await
    }

    async fn update_object<O: SetObject + Send + Sync>(
        &self,
        caller: &(),
        account_id: &Id,
        id: &Id,
        patch: O::Patch,
    ) -> Result<Option<O>, BackendSetError<MemoryError>> {
        self.check_account(account_id)
            .map_err(SetFailure::into_backend)?;
        let mut patch = patch;
        let mut content = false;
        let mut expiry_policy = None;
        match O::TYPE_NAME {
            "Chat" => {
                if self.room_of_chat(id).is_some() {
                    let value = serde_json::to_value(&patch).map_err(serde_failure)?;
                    self.update_room_chat(id, &value)
                        .await
                        .map_err(SetFailure::into_backend)?;
                    // Local (docs/design/agent-frontends.md §7.21); null
                    // clears it.
                    expiry_policy = value
                        .get("messageExpirySeconds")
                        .map(serde_json::Value::as_u64);
                }
            }
            // may_update_message admits local Message properties, edits
            // and deletions; edits and deletions for all go to the room
            // first (crate::edits).
            "Message" => {
                let value = serde_json::to_value(&patch).map_err(serde_failure)?;
                if let Some(changed) = self.send_change(id, &value).await? {
                    patch = serde_json::from_value(changed).map_err(serde_failure)?;
                    content = true;
                }
            }
            name if local(name) => {}
            name => return Err(unsupported_type(name)),
        }
        let result = self
            .inner
            .update_object::<O>(caller, account_id, id, patch)
            .await;
        // An edit or retraction is in the records already.
        if result.is_ok() && !content {
            self.record_local(O::TYPE_NAME, id).await;
        }
        if result.is_ok()
            && let Some(seconds) = expiry_policy
        {
            self.store.set_message_expiry(id.as_ref(), seconds);
        }
        self.saved(result).await
    }

    async fn destroy_object<O: SetObject + Send + Sync>(
        &self,
        caller: &(),
        account_id: &Id,
        id: &Id,
    ) -> Result<(), BackendSetError<MemoryError>> {
        self.check_account(account_id)
            .map_err(SetFailure::into_backend)?;
        let result = match O::TYPE_NAME {
            // It saves by itself.
            "Chat" => return self.destroy_chat::<O>(caller, account_id, id).await,
            // Destroying a Message or a local object is local.
            name if name == "Message" || local(name) => {
                self.inner
                    .destroy_object::<O>(caller, account_id, id)
                    .await?;
                self.forget_local(name, id);
                Ok(())
            }
            name => Err(unsupported_type(name)),
        };
        self.saved(result).await
    }

    fn supports_type<O: JmapObject>(&self, _caller: &(), account_id: &Id) -> bool {
        *account_id == self.account && served(O::TYPE_NAME)
    }
}

/// Every write that reaches other members already went to the agent in
/// the write hooks; typing, receipts, reactions and presence are not sent
/// (crate Limitations), so `on_outbound_event` is the trait's no-op.
/// MemoryBackend's on_chat_destroyed, on_space_destroyed and
/// on_space_ban_created only record events for its tests, without bound,
/// so they are left at the trait defaults too.
impl ChatEvents for AgentChat {}

impl ChatRestrictions for AgentChat {
    /// draft-atwood-jmap-chat-mimi-00 §Chat.roomId: a room's name,
    /// description and avatar are MLS group state that the agent does not
    /// change, so a client may not set them on a room-bound Chat. Member
    /// roles go to the room (`update_room_chat`; decision mimid-1wgh.62).
    async fn may_update_chat(
        &self,
        _caller: &(),
        _account_id: &Id,
        chat: &Chat,
        patch_keys: &[&str],
    ) -> Result<Result<(), SetError>, MemoryError> {
        const ROOM_STATE: &[&str] = &["name", "description", "avatarBlobId"];
        let refused = patch_keys
            .iter()
            .map(|k| k.split('/').next().unwrap_or(k))
            .find(|k| ROOM_STATE.contains(k));
        Ok(match refused {
            Some(key) if room_bound(chat) => Err(set_error(
                SetErrorType::Forbidden,
                format!("{key} of a MIMI room cannot be changed here"),
            )
            .with_properties([key])),
            _ => Ok(()),
        })
    }

    /// The owner's read state and `privateMetadata` of a Message are
    /// local; `body` and `bodyType` (an edit) and `deletedForAll` (a
    /// retraction) go to the room as MIMI content with `replaces`, and
    /// `deletedAt` alone is a local deletion (crate::edits; decision
    /// mimid-1wgh.65). crate-jmap checks that only the owner's Messages are
    /// edited or deleted for all. Mentions and reactions are not sent over
    /// MIMI here.
    async fn may_update_message(
        &self,
        _caller: &(),
        _account_id: &Id,
        _chat: &Chat,
        _message: &Message,
        patch_keys: &[&str],
    ) -> Result<Result<(), SetError>, MemoryError> {
        const ALLOWED: &[&str] = &[
            "readAt",
            "privateMetadata",
            "body",
            "bodyType",
            "deletedAt",
            "deletedForAll",
        ];
        let refused = patch_keys
            .iter()
            .map(|k| k.split('/').next().unwrap_or(k))
            .find(|k| !ALLOWED.contains(k));
        Ok(match refused {
            Some(key) => Err(set_error(
                SetErrorType::Forbidden,
                format!("{key} is not supported over MIMI by this server"),
            )
            .with_properties([key])),
            None => Ok(()),
        })
    }
}

impl ChatModeration for AgentChat {
    /// [`crate::moderate`]: the ban is `Agent::ban`, one Commit that also
    /// removes the user's clients, in place of the default's
    /// `removeMembers` update.
    async fn create_chat_ban<F>(
        &self,
        _caller: &(),
        account_id: &Id,
        _create_id: &str,
        build: F,
    ) -> Result<(Id, ChatBan), BackendSetError<MemoryError>>
    where
        F: FnOnce(&Id) -> ChatBan + Send,
    {
        self.check_account(account_id)
            .map_err(SetFailure::into_backend)?;
        let result = self.create_ban(build).await;
        self.saved(result).await
    }

    /// `reason` and `expiresAt` are this account's only
    /// ([`crate::moderate`]).
    async fn update_chat_ban(
        &self,
        caller: &(),
        account_id: &Id,
        id: &Id,
        patch: jmap_types::PatchObject,
    ) -> Result<Option<ChatBan>, BackendSetError<MemoryError>> {
        self.check_account(account_id)
            .map_err(SetFailure::into_backend)?;
        let result = self
            .inner
            .update_object::<ChatBan>(caller, account_id, id, patch)
            .await;
        if result.is_ok()
            && let Some(ban) = self
                .stored::<ChatBan>(id)
                .await
                .map_err(BackendSetError::Other)?
        {
            let expires_at = ban
                .expires_at
                .as_ref()
                .and_then(|d| parse_utc_date(d.as_ref()));
            self.store
                .set_ban_terms(id.as_ref(), ban.reason, expires_at);
        }
        self.saved(result).await
    }

    /// `Agent::unban`, never adding a client ([`crate::moderate`]).
    async fn destroy_chat_ban(
        &self,
        _caller: &(),
        account_id: &Id,
        id: &Id,
    ) -> Result<(), BackendSetError<MemoryError>> {
        self.check_account(account_id)
            .map_err(SetFailure::into_backend)?;
        let result = self.destroy_ban(id).await;
        self.saved(result).await
    }

    /// draft-atwood-jmap-chat-mimi-00 §Moderation `kickMembers`:
    /// `Agent::kick` of each user ([`crate::moderate`]).
    async fn kick_chat_members(
        &self,
        _caller: &(),
        account_id: &Id,
        chat: &Chat,
        user_ids: &[Id],
    ) -> Result<Result<(), SetError>, MemoryError> {
        if let Err(failure) = self.check_account(account_id) {
            return match failure {
                SetFailure::Set(e) => Ok(Err(*e)),
                SetFailure::Other(e) => Err(e),
            };
        }
        self.kick(chat, user_ids).await
    }
}

impl ChatSettings for AgentChat {
    /// What this backend accepts, not `MemoryBackend`'s defaults: one
    /// `text/plain` body of at most [`MAX_TEXT_LEN`] octets (what
    /// `Agent::send_message` takes) and no threads (see the crate
    /// Limitations). With a blob store, up to
    /// [`MAX_ATTACHMENTS_PER_MESSAGE`] attachments of at most
    /// [`MAX_ATTACHMENT_LEN`] octets each; without one, none. The JMAP
    /// layer checks a create against these before it reaches the agent.
    fn limits(&self, caller: &(), account_id: &Id) -> ChatLimits {
        let (count, bytes) = match self.store.blobs() {
            Some(_) => (
                MAX_ATTACHMENTS_PER_MESSAGE as u64,
                MAX_ATTACHMENT_LEN as u64,
            ),
            None => (0, 0),
        };
        self.inner
            .limits(caller, account_id)
            .with_supported_body_types(&["text/plain"])
            .with_max_body_bytes(MAX_TEXT_LEN as u64)
            .with_max_attachments_per_message(count)
            .with_max_attachment_bytes(bytes)
            .with_supports_threads(false)
    }

    /// Edits keep the old bodies, at most
    /// [`crate::edits::MAX_EDIT_HISTORY`] (decision mimid-1wgh.65).
    fn retains_edit_history(&self) -> bool {
        true
    }

    fn maintains_unread_count(&self) -> bool {
        self.inner.maintains_unread_count()
    }

    async fn owner_user_id(
        &self,
        _caller: &(),
        account_id: &Id,
    ) -> Result<Option<String>, MemoryError> {
        Ok((*account_id == self.account).then(|| self.user.clone()))
    }
}

impl ChatResolvers for AgentChat {
    /// The size and digest of a blob in the store, which crate-jmap
    /// compares with the Attachment; a blob the store does not have is
    /// `invalidProperties` on `attachments`.
    async fn attachment_blob(
        &self,
        _caller: &(),
        account_id: &Id,
        blob_id: &Id,
    ) -> Result<Result<Option<AttachmentBlob>, SetError>, MemoryError> {
        let refused = |e: BackendSetError<MemoryError>| match e {
            BackendSetError::SetError(e) => Ok(Err(*e)),
            BackendSetError::Other(e) => Err(e),
            e => Err(MemoryError::new(e.to_string())),
        };
        let Some(blobs) = self.store.blobs().filter(|_| *account_id == self.account) else {
            return refused(no_blob(None));
        };
        match blobs.info(blob_id.as_ref()) {
            Ok(Some(info)) => Ok(Ok(Some(AttachmentBlob::new(info.size, info.sha256)))),
            Ok(None) => refused(no_blob(Some(blob_id.as_ref()))),
            Err(e) => Err(MemoryError::new(e.to_string())),
        }
    }
}

// The rest is MemoryBackend's.

impl DelegateChatSpaces for AgentChat {
    type Target = MemoryBackend;

    fn chat_spaces(&self) -> &MemoryBackend {
        &self.inner
    }
}

impl DelegateSpacePolicy for AgentChat {
    type Target = MemoryBackend;

    fn space_policy(&self) -> &MemoryBackend {
        &self.inner
    }
}

impl DelegateChatAccessPolicy for AgentChat {
    type Target = MemoryBackend;

    fn chat_access_policy(&self) -> &MemoryBackend {
        &self.inner
    }
}

/// Expiry is the store's (docs/design/agent-frontends.md §7.20 to
/// §7.23): it deletes each record at its deadline and the projection
/// hard-deletes the Message (`crate::project`). These hooks are for the
/// handler's own deletions, which go to the store too.
impl ChatMessageLifecycle for AgentChat {
    /// draft-atwood-jmap-chat-00 §Message `burnOnRead`: the owner's
    /// `readAt` on a received burn-on-read Message. The backend checks the
    /// patch and hard-deletes the Message in one step; then the store
    /// deletes the record as read ([`Store::mark_read`]), everywhere, and
    /// saves.
    async fn read_and_burn_message(
        &self,
        caller: &(),
        account_id: &Id,
        message_id: &Id,
        patch: jmap_types::PatchObject,
    ) -> Result<(), BackendSetError<MemoryError>> {
        self.check_account(account_id)
            .map_err(SetFailure::into_backend)?;
        let read_at = serde_json::to_value(&patch)
            .ok()
            .and_then(|p| p.get("readAt").and_then(Value::as_str).map(str::to_owned))
            .and_then(|at| parse_utc_date(&at))
            .unwrap_or_else(mimid_agent_store::sync::now_ms);
        self.inner
            .read_and_burn_message(caller, account_id, message_id, patch)
            .await?;
        if !self.store.mark_read(message_id.as_ref(), read_at) {
            // The record had no read rule the object showed: delete it as
            // the object was.
            self.store.expire(message_id.as_ref());
        }
        self.save_or_log().await;
        Ok(())
    }

    /// A Message the handler expires: the store deletes the record as at
    /// its expiry, then the backend the Message.
    async fn expire_message(
        &self,
        caller: &(),
        account_id: &Id,
        message_id: &Id,
    ) -> Result<(), MemoryError> {
        if *account_id != self.account {
            return Ok(());
        }
        let expired = self.store.expire(message_id.as_ref());
        self.inner
            .expire_message(caller, account_id, message_id)
            .await?;
        if expired {
            self.save_or_log().await;
        }
        Ok(())
    }
}
