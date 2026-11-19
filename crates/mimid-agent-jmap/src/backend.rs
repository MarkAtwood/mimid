//! [`AgentChat`]: a JMAP Chat backend whose store is crate-jmap's
//! `MemoryBackend` and whose writes go to MIMI rooms through an [`Agent`].

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex as StdMutex, PoisonError};

use jmap_chat_server::memory::{MemoryBackend, MemoryError};
use jmap_chat_server::{
    AttachmentBlob, ChatEvents, ChatLimits, ChatModeration, ChatResolvers, ChatRestrictions,
    ChatSettings, ChatStore, DelegateChatAccessPolicy, DelegateChatMessageLifecycle,
    DelegateChatSpaces, DelegateSpacePolicy,
};
use jmap_chat_types::{
    BodyType, Chat, ChatBan, ChatContact, ChatMember, ChatMemberRole, DeliveryState, Message,
};
use jmap_server::{
    BackendSetError, DelegateJmapReads, Dispatcher, GetObject, Id, JmapAccounts, JmapObject,
    JmapReads, SetError, SetErrorType, SetObject,
};
use mimid_agent_core::{
    Agent, AgentError, HostOptions, MAX_TEXT_LEN, OutgoingAttachment, RoomStatus,
};
use serde_json::{Value, json};
use tokio::sync::Mutex;

use crate::blobs::{BlobError, BlobQuota, BlobStore, MAX_ATTACHMENT_LEN};
use crate::convert::{MessageRef, message_ref, sender_msg_id, utc_date};

/// The Chat property that names its MIMI room
/// (draft-atwood-jmap-chat-mimi-00 §Chat.roomId).
pub(crate) const ROOM_ID: &str = "roomId";

/// room-policy-04 §8.1.3: the "banned" role's index.
pub(crate) const BANNED_ROLE_INDEX: u32 = 1;

/// The role the agent gives the participants it adds: "member" in its
/// default role list (decision mimid-1wgh.56).
const MEMBER_ROLE_INDEX: u32 = 2;

/// The change-log entries the store keeps per data type, by default: a
/// client's `/changes` from an older state is `cannotCalculateChanges`
/// (RFC 8620 §5.2) and it resyncs. INVENTED VALUE, NOT FROM SPEC
/// (decision mimid-1wgh.66).
pub const CHANGE_LOG_LIMIT: usize = 4096;

/// The most attachments one Message carries, sent or received; the
/// account's `maxAttachmentsPerMessage` when it has a blob store.
/// INVENTED, NOT FROM SPEC.
pub const MAX_ATTACHMENTS_PER_MESSAGE: usize = 8;

/// Which pending invites [`AgentChat::sync`] joins.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum InvitePolicy {
    /// Join when the Welcome's sender ([`Agent::inviter`]) is a user this
    /// user has allowed (`Agent::allow`, a granted consent record). The
    /// default.
    #[default]
    FromAllowed,
    /// Join every invite.
    Any,
    /// Join none; invites stay pending in the agent.
    Never,
}

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

/// The links between JMAP ids and MIMI names, kept beside the store.
#[derive(Debug, Default)]
pub(crate) struct Links {
    pub(crate) chat_of_room: BTreeMap<String, Id>,
    pub(crate) room_of_chat: BTreeMap<String, String>,
    pub(crate) contact_of_user: BTreeMap<String, Id>,
    /// (Chat id, reference octets of a MIMI message ID) to Message id.
    pub(crate) messages: BTreeMap<(String, MessageRef), Id>,
}

/// One user's MIMI rooms as a JMAP Chat account.
///
/// Objects live in a crate-jmap `MemoryBackend`; client writes that mean
/// something in MIMI go to the [`Agent`] before they are stored, and
/// [`AgentChat::sync`] stores what the agent received. See the crate
/// documentation for what maps and what does not.
pub struct AgentChat {
    pub(crate) inner: MemoryBackend,
    pub(crate) account: Id,
    pub(crate) user: String,
    pub(crate) agent: Arc<Mutex<Agent>>,
    pub(crate) links: StdMutex<Links>,
    pub(crate) options: Options,
    /// The plaintext store file ([`AgentChat::persisted_at`]).
    pub(crate) store_path: Option<std::path::PathBuf>,
    /// One [`AgentChat::save`] at a time.
    pub(crate) save_lock: Mutex<()>,
    /// The attachments' content ([`AgentChat::with_blobs`]).
    pub(crate) blobs: Option<BlobStore>,
    /// Received attachments to fetch again ([`crate::retry`]).
    pub(crate) pending: StdMutex<Vec<crate::retry::PendingAttachment>>,
    /// Each active room's epoch when ChatContact `did`s were last set
    /// from its leaves; a change of any sets them again.
    pub(crate) did_epochs: StdMutex<BTreeMap<String, u64>>,
    /// What a report of each received Message needs (its frank, or its
    /// content unverified), by Message id, for `Message/reportAbuse`
    /// ([`crate::report`]).
    pub(crate) franks: StdMutex<BTreeMap<String, crate::report::KeptFrank>>,
    /// Each Message's MIMI message IDs, by Message id ([`crate::edits`]).
    pub(crate) mimi_ids: StdMutex<BTreeMap<String, crate::edits::MimiIds>>,
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
    /// [`AgentChat::sync`].
    pub fn new(agent: Agent, account_id: Id, options: Options) -> Self {
        // Decision mimid-1wgh.66: a bounded change log, and no outbound or
        // lifecycle events recorded, since nothing here reads them (every
        // outbound change goes to the agent in the write hooks).
        let inner = MemoryBackend::new()
            .with_change_log_limit(options.change_log_limit)
            .with_event_limit(0);
        inner.register_account(&account_id);
        Self {
            inner,
            account: account_id,
            user: agent.user().to_owned(),
            agent: Arc::new(Mutex::new(agent)),
            links: StdMutex::new(Links::default()),
            options,
            store_path: None,
            save_lock: Mutex::new(()),
            blobs: None,
            pending: StdMutex::new(Vec::new()),
            did_epochs: StdMutex::new(BTreeMap::new()),
            franks: StdMutex::new(BTreeMap::new()),
            mimi_ids: StdMutex::new(BTreeMap::new()),
        }
    }

    /// Keeps attachments in a [`BlobStore`] in `dir` (created 0700 if
    /// missing): uploads, the attachments of Messages sent, and those
    /// fetched for Messages received, with unreferenced blobs held to
    /// [`Options::blob_quota`]. Without it Messages carry no attachments:
    /// the account's limits allow none and received ones are left out.
    ///
    /// # Errors
    ///
    /// The [`BlobError`] of [`BlobStore::open`].
    pub fn with_blobs(mut self, dir: impl Into<std::path::PathBuf>) -> Result<Self, BlobError> {
        self.blobs = Some(BlobStore::open(dir)?.with_quota(self.options.blob_quota));
        Ok(self)
    }

    /// Every blob id a stored object names, for the blob store's quota
    /// (decision mimid-1wgh.68): the value of any property named `blobId`
    /// or ending in `BlobId`, at any depth, of every Chat, ChatBan,
    /// ChatContact, Message and ReadPosition. A Message's attachments and
    /// their thumbnails, its edit history and a Chat's avatar all count;
    /// a destroyed Message is no longer stored and a retracted one has no
    /// attachments, so theirs do not. Attachments waiting for another
    /// fetch ([`crate::retry`]) name a URL, not a blob here, so they add
    /// nothing; a blob a retry stores is named by its Message in the same
    /// sync and is younger than [`crate::MIN_UNREFERENCED_AGE`] meanwhile.
    ///
    /// # Errors
    ///
    /// The [`crate::PersistError`] of reading the objects.
    pub async fn referenced_blobs(
        &self,
    ) -> Result<std::collections::BTreeSet<String>, crate::PersistError> {
        let mut objects = self.all::<Message>().await?;
        objects.extend(self.all::<Chat>().await?);
        objects.extend(self.all::<ChatContact>().await?);
        objects.extend(self.all::<ChatBan>().await?);
        objects.extend(self.all::<jmap_chat_types::ReadPosition>().await?);
        let mut ids = std::collections::BTreeSet::new();
        for object in &objects {
            collect_blob_ids(object, &mut ids);
        }
        Ok(ids)
    }

    /// The blob store, if there is one: the daemon serves uploads and
    /// downloads from it.
    pub fn blobs(&self) -> Option<&BlobStore> {
        self.blobs.as_ref()
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
    /// KeyPackages and consent decisions.
    pub fn agent(&self) -> &Arc<Mutex<Agent>> {
        &self.agent
    }

    /// The Chat bound to MIMI room `room`.
    pub fn chat_of_room(&self, room: &str) -> Option<Id> {
        self.links().chat_of_room.get(room).cloned()
    }

    /// The MIMI room of Chat `chat`.
    pub fn room_of_chat(&self, chat: &Id) -> Option<String> {
        self.links().room_of_chat.get(chat.as_ref()).cloned()
    }

    pub(crate) fn links(&self) -> std::sync::MutexGuard<'_, Links> {
        self.links.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// `result`, after saving the store when it is a success.
    async fn saved<T, E>(&self, result: Result<T, E>) -> Result<T, E> {
        if result.is_ok() {
            self.save_or_log().await;
        }
        result
    }

    pub(crate) fn link_room(&self, room: &str, chat: &Id) {
        let mut links = self.links();
        links.chat_of_room.insert(room.to_owned(), chat.clone());
        links
            .room_of_chat
            .insert(chat.as_ref().to_owned(), room.to_owned());
    }

    pub(crate) fn link_message(&self, chat: &Id, reference: MessageRef, message: &Id) {
        self.links()
            .messages
            .insert((chat.as_ref().to_owned(), reference), message.clone());
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

        let room = {
            let mut agent = self.agent.lock().await;
            let room = agent
                .host_room(&HostOptions::named(name))
                .await
                .map_err(agent_failure)?;
            for user in &users {
                if let Err(e) = agent.invite(&room, user).await {
                    // Do not keep a room the client was told was not made.
                    if let Err(leave) = agent.leave(&room).await {
                        tracing::warn!(%room, error = %leave, "leaving a half-made room");
                    }
                    return Err(agent_failure(e));
                }
            }
            room
        };
        value[ROOM_ID] = json!(room);
        let chat = serde_json::from_value::<O>(value).map_err(serde_failure)?;
        let chat = self.inner.insert_object(&self.account, chat).await?;
        self.link_room(&room, &id);
        Ok((id, chat))
    }

    /// `Chat/set` update of a Chat bound to `room`: added members are
    /// invited, removed members are removed from the room
    /// (`Agent::remove`), a changed role is a role change
    /// (`Agent::change_role`: "admin" is the room's role named "admin",
    /// "member" role 2), and the owner's own removal leaves the room
    /// (decision mimid-1wgh.62 items 7, 8). The owner's own role cannot be
    /// changed.
    async fn update_room_chat(
        &self,
        room: &str,
        chat_id: &Id,
        patch: &Value,
    ) -> Result<(), SetFailure> {
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
        let mut agent = self.agent.lock().await;
        for user in &added {
            agent.invite(room, user).await.map_err(agent_set_failure)?;
        }
        for user in &removed {
            agent.remove(room, user).await.map_err(agent_set_failure)?;
        }
        for (user, (_, role)) in changed_users.iter().zip(&changed) {
            let index = if *role == ChatMemberRole::Admin {
                agent
                    .roles(room)
                    .map_err(agent_set_failure)?
                    .into_iter()
                    .find(|(_, name)| name == "admin")
                    .map(|(index, _)| index)
                    .ok_or_else(|| {
                        SetFailure::set(
                            set_error(SetErrorType::Forbidden, "the room has no admin role")
                                .with_properties(["members"]),
                        )
                    })?
            } else {
                MEMBER_ROLE_INDEX
            };
            agent
                .change_role(room, user, index)
                .await
                .map_err(agent_set_failure)?;
        }
        if leaving {
            agent.leave(room).await.map_err(agent_set_failure)?;
        }
        Ok(())
    }

    /// `Message/set` create: the body goes to the Chat's room as a
    /// `text/plain` MIMI message, with each attachment's blob encrypted,
    /// uploaded and sent as an ExternalPart (`Agent::send_message`), and
    /// the stored Message, the client's attachments included, carries the
    /// `senderMsgId` its recipients derive.
    async fn create_message_in_room<F>(
        &self,
        build: F,
    ) -> Result<(Id, Message), BackendSetError<MemoryError>>
    where
        F: FnOnce(&Id) -> Message + Send,
    {
        let id = self.inner.mint_id();
        let mut message = build(&id);
        let Some(room) = self.room_of_chat(&message.chat_id) else {
            return Err(forbidden("the Chat is not bound to a MIMI room"));
        };
        if let Some(property) = unsupported_message_property(&message) {
            return Err(BackendSetError::SetError(Box::new(
                set_error(
                    SetErrorType::Forbidden,
                    format!("{property} is not supported over MIMI by this server"),
                )
                .with_properties([property]),
            )));
        }
        let attachments = self.outgoing_attachments(&message)?;
        let sent = self
            .agent
            .lock()
            .await
            .send_message(&room, &message.body, &attachments)
            .await
            .map_err(agent_failure)?;
        message.sender_msg_id = sender_msg_id(sent.accepted_at, &sent.message_id);
        message.delivery_state = DeliveryState::Delivered;
        message.delivered_at = Some(utc_date(sent.accepted_at));
        let chat_id = message.chat_id.clone();
        let stored = self.inner.insert_object(&self.account, message).await?;
        self.link_message(&chat_id, message_ref(&sent.message_id), &id);
        self.keep_first_id(&id, &sent.message_id);
        Ok((id, stored))
    }

    /// The content of `message`'s attachments, read from the blob store,
    /// with the media type and file name the client gave. crate-jmap has
    /// already checked each blob's size and digest (`attachment_blob`); a
    /// blob gone since is `invalidProperties`.
    fn outgoing_attachments(
        &self,
        message: &Message,
    ) -> Result<Vec<OutgoingAttachment>, BackendSetError<MemoryError>> {
        if message.attachments.is_empty() {
            return Ok(Vec::new());
        }
        let Some(blobs) = &self.blobs else {
            return Err(no_blob(None));
        };
        let now = std::time::SystemTime::now();
        message
            .attachments
            .iter()
            .map(|attachment| {
                // Decision mimid-1wgh.68: not evicted while it is sent,
                // before the Message that names it is stored.
                blobs
                    .touch(attachment.blob_id.as_ref(), now)
                    .map_err(|e| BackendSetError::Other(MemoryError::new(e.to_string())))?;
                let content = blobs
                    .get(attachment.blob_id.as_ref())
                    .map_err(|e| BackendSetError::Other(MemoryError::new(e.to_string())))?
                    .ok_or_else(|| no_blob(Some(&attachment.blob_id)))?;
                Ok(OutgoingAttachment {
                    content,
                    content_type: attachment.content_type.clone(),
                    filename: attachment.filename.clone(),
                })
            })
            .collect()
    }
}

/// Adds to `ids` the string value of every property of `value`, at any
/// depth, named `blobId` or ending in `BlobId`.
fn collect_blob_ids(value: &Value, ids: &mut std::collections::BTreeSet<String>) {
    match value {
        Value::Object(map) => {
            for (key, value) in map {
                if (key == "blobId" || key.ends_with("BlobId"))
                    && let Value::String(id) = value
                {
                    ids.insert(id.clone());
                }
                collect_blob_ids(value, ids);
            }
        }
        Value::Array(values) => {
            for value in values {
                collect_blob_ids(value, ids);
            }
        }
        _ => {}
    }
}

/// `invalidProperties` on `attachments`: blob `id` is not in the store, or
/// there is no store.
fn no_blob(id: Option<&Id>) -> BackendSetError<MemoryError> {
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
    } else if message.reply_to.is_some() {
        Some("replyTo")
    } else if message.thread_root_id.is_some() {
        Some("threadRootId")
    } else if message.topic_id.is_some() {
        Some("topicId")
    } else if message.subject.is_some() {
        Some("subject")
    } else if message.sender_expires_at.is_some() {
        Some("senderExpiresAt")
    } else if message.burn_on_read.is_some() {
        Some("burnOnRead")
    } else if message.expires_after_read_seconds.is_some() {
        Some("expiresAfterReadSeconds")
    } else {
        None
    }
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

pub(crate) fn agent_failure(e: AgentError) -> BackendSetError<MemoryError> {
    agent_set_failure(e).into_backend()
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
                self.inner
                    .create_object(caller, account_id, create_id, build)
                    .await
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
        match O::TYPE_NAME {
            "Chat" => {
                if let Some(room) = self.room_of_chat(id) {
                    let value = serde_json::to_value(&patch).map_err(serde_failure)?;
                    self.update_room_chat(&room, id, &value)
                        .await
                        .map_err(SetFailure::into_backend)?;
                }
            }
            // may_update_message admits local Message properties, edits
            // and deletions; edits and deletions for all go to the room
            // first (crate::edits).
            "Message" => {
                let value = serde_json::to_value(&patch).map_err(serde_failure)?;
                if let Some(changed) = self.send_change(id, &value).await? {
                    patch = serde_json::from_value(changed).map_err(serde_failure)?;
                }
            }
            name if local(name) => {}
            name => return Err(unsupported_type(name)),
        }
        let result = self
            .inner
            .update_object::<O>(caller, account_id, id, patch)
            .await;
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
            "Chat" => {
                if let Some(room) = self.room_of_chat(id) {
                    let mut agent = self.agent.lock().await;
                    let active = agent
                        .rooms()
                        .iter()
                        .any(|r| r.uri == room && r.status == RoomStatus::Active);
                    if active {
                        agent.leave(&room).await.map_err(agent_failure)?;
                    }
                }
                self.inner
                    .destroy_object::<O>(caller, account_id, id)
                    .await?;
                let mut links = self.links();
                if let Some(room) = links.room_of_chat.remove(id.as_ref()) {
                    links.chat_of_room.remove(&room);
                }
                links.messages.retain(|(chat, _), _| chat != id.as_ref());
                Ok(())
            }
            // Destroying a Message or a local object is local.
            "Message" => {
                self.inner
                    .destroy_object::<O>(caller, account_id, id)
                    .await?;
                self.links().messages.retain(|_, message| message != id);
                Ok(())
            }
            name if local(name) => self.inner.destroy_object::<O>(caller, account_id, id).await,
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
        let (count, bytes) = match self.blobs {
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
        let Some(blobs) = self.blobs.as_ref().filter(|_| *account_id == self.account) else {
            return refused(no_blob(None));
        };
        match blobs.info(blob_id.as_ref()) {
            Ok(Some(info)) => Ok(Ok(Some(AttachmentBlob::new(info.size, info.sha256)))),
            Ok(None) => refused(no_blob(Some(blob_id))),
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

impl DelegateChatMessageLifecycle for AgentChat {
    type Target = MemoryBackend;

    fn chat_message_lifecycle(&self) -> &MemoryBackend {
        &self.inner
    }
}
