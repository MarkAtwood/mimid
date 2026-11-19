//! [`AgentChat`]: a JMAP Chat backend whose store is crate-jmap's
//! `MemoryBackend` and whose writes go to MIMI rooms through an [`Agent`].

use std::collections::{BTreeMap, HashSet};
use std::sync::{Arc, Mutex as StdMutex, PoisonError};

use jmap_chat_server::memory::{MemoryBackend, MemoryError};
use jmap_chat_server::{
    AttachmentBlob, ChatBackend, ChatLimits, EmojiSetOp, InviteJoinRefusal, OpResult,
    OutboundEvent, SlowModeError, SpacePatchOp,
};
use jmap_chat_types::{
    BodyType, Chat, ChatContact, ChatMember, ChatMemberRole, ChatPermission, DeliveryState, Message,
};
use jmap_server::{
    BackendChangesError, BackendQueryError, BackendSetError, ChangesParams, ChangesResult,
    Dispatcher, GetObject, Id, JmapBackend, JmapObject, QueryChangesParams, QueryChangesResult,
    QueryObject, QueryParams, QueryResult, SetError, SetErrorType, SetObject, State,
};
use mimid_agent_core::{
    Agent, AgentError, HostOptions, MAX_TEXT_LEN, OutgoingAttachment, RoomStatus,
};
use serde_json::{Value, json};
use tokio::sync::Mutex;

use crate::blobs::{BlobError, BlobStore, MAX_ATTACHMENT_LEN};
use crate::convert::{MessageRef, message_ref, sender_msg_id, utc_date};

/// The Chat property that names its MIMI room
/// (draft-atwood-jmap-chat-mimi-00 §Chat.roomId).
pub(crate) const ROOM_ID: &str = "roomId";

/// room-policy-04 §8.1.3: the "banned" role's index.
pub(crate) const BANNED_ROLE_INDEX: u32 = 1;

/// The role the agent gives the participants it adds: "member" in its
/// default role list (decision mimid-1wgh.56).
const MEMBER_ROLE_INDEX: u32 = 2;

/// The id passed to a handler's `build` closure before the store mints the
/// real one; the object is rebuilt under the real id before it is stored.
const PLACEHOLDER_ID: &str = "pending";

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
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct Options {
    /// Which invites to join.
    pub invites: InvitePolicy,
}

impl Options {
    /// Options with invite policy `invites`.
    pub fn with_invites(mut self, invites: InvitePolicy) -> Self {
        self.invites = invites;
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
        let inner = MemoryBackend::new();
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
        }
    }

    /// Keeps attachments in a [`BlobStore`] in `dir` (created 0700 if
    /// missing): uploads, the attachments of Messages sent, and those
    /// fetched for Messages received. Without it Messages carry no
    /// attachments: the account's limits allow none and received ones are
    /// left out.
    ///
    /// # Errors
    ///
    /// The [`BlobError`] of [`BlobStore::open`].
    pub fn with_blobs(mut self, dir: impl Into<std::path::PathBuf>) -> Result<Self, BlobError> {
        self.blobs = Some(BlobStore::open(dir)?);
        Ok(self)
    }

    /// The blob store, if there is one: the daemon serves uploads and
    /// downloads from it.
    pub fn blobs(&self) -> Option<&BlobStore> {
        self.blobs.as_ref()
    }

    /// Registers the JMAP Chat methods (`Chat/*`, `Message/*`,
    /// `ChatContact/*` and the rest of crate-jmap's set) and
    /// `Message/reportAbuse` ([`crate::report`]) and `Chat/kick`,
    /// `Chat/ban` and `Chat/unban` ([`crate::moderate`]) on `dispatcher`,
    /// served by
    /// `this`.
    pub fn register(this: &Arc<Self>, dispatcher: &mut Dispatcher<()>) {
        jmap_chat_server::register_chat_handlers(dispatcher, Arc::clone(this));
        crate::report::register(this, dispatcher);
        crate::moderate::register(this, dispatcher);
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
    async fn users_of(&self, ids: &[Id], property: &str) -> Result<Vec<String>, SetFailure> {
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
    async fn create_chat<O, F>(
        &self,
        create_id: &str,
        build: F,
    ) -> Result<(Id, O), BackendSetError<MemoryError>>
    where
        O: SetObject + Send + Sync,
        F: FnOnce(&Id) -> O + Send,
    {
        let mut value =
            serde_json::to_value(build(&Id::from(PLACEHOLDER_ID))).map_err(serde_failure)?;
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
        // Checked here so the store's build closure cannot fail: the value
        // differs from this one only in its `id`, a minted ULID.
        serde_json::from_value::<O>(value.clone()).map_err(serde_failure)?;
        let (id, chat) = self
            .inner
            .create_object::<O, _>(&(), &self.account, create_id, move |id| {
                value["id"] = json!(id);
                serde_json::from_value(value).expect("the same value decoded a moment ago")
            })
            .await?;
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
        create_id: &str,
        build: F,
    ) -> Result<(Id, Message), BackendSetError<MemoryError>>
    where
        F: FnOnce(&Id) -> Message + Send,
    {
        let mut message = build(&Id::from(PLACEHOLDER_ID));
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
        let (id, stored) = self
            .inner
            .create_object::<Message, _>(&(), &self.account, create_id, move |id| {
                message.id = id.clone();
                message
            })
            .await?;
        self.link_message(&chat_id, message_ref(&sent.message_id), &id);
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
        message
            .attachments
            .iter()
            .map(|attachment| {
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
enum SetFailure {
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

fn set_error(kind: SetErrorType, description: impl Into<String>) -> SetError {
    SetError::new(kind).with_description(description)
}

fn forbidden(description: &str) -> BackendSetError<MemoryError> {
    BackendSetError::SetError(Box::new(set_error(SetErrorType::Forbidden, description)))
}

fn serde_failure(e: serde_json::Error) -> BackendSetError<MemoryError> {
    BackendSetError::Other(MemoryError::new(format!("converting an object: {e}")))
}

/// The failure for an agent error: the hub's or the room's refusal is
/// `forbidden`, a room the agent is not in is `notFound`, a value the
/// agent refuses is `invalidProperties`, each with the agent's
/// description (the client is the user's own); anything else (network,
/// storage, MLS) is the handler's `serverFail`.
fn agent_set_failure(e: AgentError) -> SetFailure {
    let kind = match &e {
        AgentError::Refused { .. } | AgentError::NoKeyMaterial { .. } => SetErrorType::Forbidden,
        AgentError::NoSuchRoom(_) => SetErrorType::NotFound,
        AgentError::Invalid(_) => SetErrorType::InvalidProperties,
        _ => return SetFailure::Other(MemoryError::new(e.to_string())),
    };
    SetFailure::set(set_error(kind, e.to_string()))
}

fn agent_failure(e: AgentError) -> BackendSetError<MemoryError> {
    agent_set_failure(e).into_backend()
}

/// The JMAP types this backend serves; the rest of crate-jmap's set
/// (Space, SpaceInvite, SpaceBan, CustomEmoji, PresenceStatus) has no MIMI
/// meaning here.
fn served(type_name: &str) -> bool {
    matches!(
        type_name,
        "Chat" | "Message" | "ChatContact" | "ReadPosition"
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

impl JmapBackend for AgentChat {
    type Error = MemoryError;
    type CallerCtx = ();

    async fn account_exists(&self, caller: &(), account_id: &Id) -> Result<bool, MemoryError> {
        Ok(*account_id == self.account && self.inner.account_exists(caller, account_id).await?)
    }

    async fn get_objects<O: GetObject + Send + Sync>(
        &self,
        caller: &(),
        account_id: &Id,
        ids: Option<&[Id]>,
        properties: Option<&[String]>,
    ) -> Result<(Vec<O>, Vec<Id>), MemoryError> {
        self.inner
            .get_objects(caller, account_id, ids, properties)
            .await
    }

    async fn get_state<O: JmapObject + Send + Sync>(
        &self,
        caller: &(),
        account_id: &Id,
    ) -> Result<State, MemoryError> {
        self.inner.get_state::<O>(caller, account_id).await
    }

    async fn get_changes<O: JmapObject + Send + Sync>(
        &self,
        caller: &(),
        account_id: &Id,
        params: ChangesParams<'_>,
    ) -> Result<ChangesResult, BackendChangesError<MemoryError>> {
        self.inner
            .get_changes::<O>(caller, account_id, params)
            .await
    }

    async fn query_objects<O: QueryObject + Send + Sync>(
        &self,
        caller: &(),
        account_id: &Id,
        params: QueryParams<'_, O>,
    ) -> Result<QueryResult, BackendQueryError<MemoryError>> {
        self.inner.query_objects(caller, account_id, params).await
    }

    async fn query_changes<O: QueryObject + Send + Sync>(
        &self,
        caller: &(),
        account_id: &Id,
        params: QueryChangesParams<'_, O>,
    ) -> Result<QueryChangesResult, BackendChangesError<MemoryError>> {
        self.inner.query_changes(caller, account_id, params).await
    }
}

impl ChatBackend for AgentChat {
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
            "Chat" => self.create_chat(create_id, build).await,
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
        create_id: &str,
        build: F,
    ) -> Result<(Id, Message), BackendSetError<MemoryError>>
    where
        F: FnOnce(&Id) -> Message + Send,
    {
        self.check_account(account_id)
            .map_err(SetFailure::into_backend)?;
        let result = self.create_message_in_room(create_id, build).await;
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
        match O::TYPE_NAME {
            "Chat" => {
                if let Some(room) = self.room_of_chat(id) {
                    let value = serde_json::to_value(&patch).map_err(serde_failure)?;
                    self.update_room_chat(&room, id, &value)
                        .await
                        .map_err(SetFailure::into_backend)?;
                }
            }
            // may_update_message admits only local Message properties.
            "Message" => {}
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

    /// Every write that reaches other members already went to the agent
    /// in the write hooks; typing, receipts, reactions and presence are
    /// not sent (crate Limitations).
    async fn on_outbound_event(&self, _caller: &(), _account_id: &Id, _event: &OutboundEvent) {}

    async fn owner_user_id(
        &self,
        _caller: &(),
        account_id: &Id,
    ) -> Result<Option<String>, MemoryError> {
        Ok((*account_id == self.account).then(|| self.user.clone()))
    }

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

    /// Only the owner's own read state of a Message is writable: edits,
    /// retractions and reactions are not sent over MIMI here.
    async fn may_update_message(
        &self,
        _caller: &(),
        _account_id: &Id,
        _chat: &Chat,
        _message: &Message,
        patch_keys: &[&str],
    ) -> Result<Result<(), SetError>, MemoryError> {
        const LOCAL: &[&str] = &["readAt", "privateMetadata"];
        let refused = patch_keys
            .iter()
            .map(|k| k.split('/').next().unwrap_or(k))
            .find(|k| !LOCAL.contains(k));
        Ok(match refused {
            Some(key) => Err(set_error(
                SetErrorType::Forbidden,
                format!("{key} is not supported over MIMI by this server"),
            )
            .with_properties([key])),
            None => Ok(()),
        })
    }

    // The rest is MemoryBackend's. Its on_chat_destroyed,
    // on_space_destroyed and on_space_ban_created only record events for
    // its tests, without bound, so they are left at the trait defaults.

    async fn generate_invite_code(
        &self,
        caller: &(),
        account_id: &Id,
    ) -> Result<String, MemoryError> {
        self.inner.generate_invite_code(caller, account_id).await
    }

    async fn join_space_with_invite(
        &self,
        caller: &(),
        account_id: &Id,
        invite_id: &Id,
        joined_at: &jmap_types::UTCDate,
    ) -> Result<Result<(), InviteJoinRefusal>, MemoryError> {
        self.inner
            .join_space_with_invite(caller, account_id, invite_id, joined_at)
            .await
    }

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

    fn protect_last_admin(&self, caller: &(), account_id: &Id) -> bool {
        self.inner.protect_last_admin(caller, account_id)
    }

    fn space_extension_properties(&self, caller: &(), account_id: &Id) -> &'static [&'static str] {
        self.inner.space_extension_properties(caller, account_id)
    }

    async fn apply_space_patch(
        &self,
        caller: &(),
        account_id: &Id,
        space_id: &Id,
        ops: Vec<SpacePatchOp>,
    ) -> Result<Vec<OpResult>, BackendSetError<MemoryError>> {
        self.inner
            .apply_space_patch(caller, account_id, space_id, ops)
            .await
    }

    async fn apply_space_metadata_patch(
        &self,
        caller: &(),
        account_id: &Id,
        space_id: &Id,
        patch: jmap_chat_types::SpaceMetadataPatch,
    ) -> Result<Option<jmap_chat_types::Space>, BackendSetError<MemoryError>> {
        self.inner
            .apply_space_metadata_patch(caller, account_id, space_id, patch)
            .await
    }

    fn retains_edit_history(&self) -> bool {
        self.inner.retains_edit_history()
    }

    fn maintains_unread_count(&self) -> bool {
        self.inner.maintains_unread_count()
    }

    async fn everyone_permissions(
        &self,
        caller: &(),
        account_id: &Id,
        space: &jmap_chat_types::Space,
    ) -> Result<HashSet<ChatPermission>, MemoryError> {
        self.inner
            .everyone_permissions(caller, account_id, space)
            .await
    }

    async fn may_set_custom_emoji(
        &self,
        caller: &(),
        account_id: &Id,
        target_space_id: Option<&Id>,
        op: EmojiSetOp,
    ) -> Result<Result<(), SetError>, MemoryError> {
        self.inner
            .may_set_custom_emoji(caller, account_id, target_space_id, op)
            .await
    }

    async fn may_broadcast_mention(
        &self,
        caller: &(),
        account_id: &Id,
        space_id: &Id,
        chat_id: &Id,
    ) -> Result<Result<(), SetError>, MemoryError> {
        self.inner
            .may_broadcast_mention(caller, account_id, space_id, chat_id)
            .await
    }

    async fn may_send_message(
        &self,
        caller: &(),
        account_id: &Id,
        chat_id: &Id,
    ) -> Result<Result<(), SetError>, MemoryError> {
        self.inner
            .may_send_message(caller, account_id, chat_id)
            .await
    }

    async fn may_view_chat(
        &self,
        caller: &(),
        account_id: &Id,
        chat_id: &Id,
    ) -> Result<bool, MemoryError> {
        self.inner.may_view_chat(caller, account_id, chat_id).await
    }

    async fn may_set_pinned_messages(
        &self,
        caller: &(),
        account_id: &Id,
        chat_id: &Id,
    ) -> Result<Result<(), SetError>, MemoryError> {
        self.inner
            .may_set_pinned_messages(caller, account_id, chat_id)
            .await
    }

    async fn may_set_space_ban(
        &self,
        caller: &(),
        account_id: &Id,
        space_id: &Id,
    ) -> Result<Result<(), SetError>, MemoryError> {
        self.inner
            .may_set_space_ban(caller, account_id, space_id)
            .await
    }

    async fn may_set_space_invite(
        &self,
        caller: &(),
        account_id: &Id,
        space_id: &Id,
        created_by: Option<&Id>,
    ) -> Result<Result<(), SetError>, MemoryError> {
        self.inner
            .may_set_space_invite(caller, account_id, space_id, created_by)
            .await
    }

    async fn may_get_space_invite(
        &self,
        caller: &(),
        account_id: &Id,
        invite: &jmap_chat_types::SpaceInvite,
    ) -> Result<bool, MemoryError> {
        self.inner
            .may_get_space_invite(caller, account_id, invite)
            .await
    }

    async fn may_get_space_ban(
        &self,
        caller: &(),
        account_id: &Id,
        ban: &jmap_chat_types::SpaceBan,
    ) -> Result<bool, MemoryError> {
        self.inner.may_get_space_ban(caller, account_id, ban).await
    }

    async fn slow_mode_check(
        &self,
        caller: &(),
        account_id: &Id,
        chat_id: &Id,
    ) -> Result<(), SlowModeError> {
        self.inner
            .slow_mode_check(caller, account_id, chat_id)
            .await
    }

    async fn expire_message(
        &self,
        caller: &(),
        account_id: &Id,
        message_id: &Id,
    ) -> Result<(), MemoryError> {
        self.inner
            .expire_message(caller, account_id, message_id)
            .await
    }

    async fn read_and_burn_message(
        &self,
        caller: &(),
        account_id: &Id,
        message_id: &Id,
        patch: jmap_types::PatchObject,
    ) -> Result<(), BackendSetError<MemoryError>> {
        self.inner
            .read_and_burn_message(caller, account_id, message_id, patch)
            .await
    }
}
