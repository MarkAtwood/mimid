//! [`AgentChat::sync`]: what the agent received, stored as JMAP objects.

use jmap_chat_server::ChatBackend;
use jmap_chat_server::memory::MemoryError;
use jmap_chat_types::{
    Attachment, BodyType, Chat, ChatContact, ChatKind, ChatMember, ChatMemberRole, DeliveryState,
    Message,
};
use jmap_server::{BackendSetError, Id, JmapBackend, now_utc_string};
use mimi_content::{ExternalPart, Part};
use mimid_agent_core::{Agent, AgentError, Event, ReceivedMessage, RoomStatus};
use serde_json::json;

use crate::backend::{AgentChat, InvitePolicy, MAX_ATTACHMENTS_PER_MESSAGE, ROOM_ID};
use crate::blobs::{hex, is_media_type};
use crate::convert::{MessageRef, message_ref, sender_msg_id, topic_id, utc_date};

/// The creation id given to the store for objects sync makes; no client
/// sees it.
const SYNC_CREATE_ID: &str = "sync";

/// The longest file name kept for a received attachment, in characters;
/// a longer one is cut. INVENTED, NOT FROM SPEC.
pub(crate) const MAX_FILENAME_CHARS: usize = 255;

/// The file name of a received attachment that has none.
const FALLBACK_FILENAME: &str = "attachment";

/// The media type of a received attachment whose own is not one.
const FALLBACK_CONTENT_TYPE: &str = "application/octet-stream";

/// What one [`AgentChat::sync`] did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct SyncReport {
    /// Messages stored.
    pub messages: usize,
    /// Rooms joined from invites.
    pub joined: Vec<String>,
    /// Invites left pending by the invite policy, by number.
    pub pending_invites: Vec<u64>,
    /// Received messages not stored, with why: neither text nor
    /// attachments, or an edit.
    pub skipped: Vec<String>,
    /// The agent's problems ([`Event::Problem`]), and received
    /// attachments left out or waiting for a retry because they could not
    /// be fetched, opened or stored, as text.
    pub problems: Vec<String>,
    /// Attachments fetched on a retry and added to their Messages
    /// ([`crate::retry`]).
    pub attachments_retried: usize,
}

/// A failure of [`AgentChat::sync`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SyncError {
    /// The agent failed: the server could not be reached, or local state.
    #[error(transparent)]
    Agent(#[from] AgentError),
    /// The store refused a write.
    #[error("storing: {0}")]
    Store(String),
    /// The plaintext store file could not be written.
    #[error(transparent)]
    Persist(#[from] crate::PersistError),
}

impl From<MemoryError> for SyncError {
    fn from(e: MemoryError) -> Self {
        Self::Store(e.to_string())
    }
}

impl From<BackendSetError<MemoryError>> for SyncError {
    fn from(e: BackendSetError<MemoryError>) -> Self {
        Self::Store(match e {
            BackendSetError::SetError(e) => format!("{e:?}"),
            BackendSetError::Other(e) => e.to_string(),
            e => format!("{e}"),
        })
    }
}

fn now() -> jmap_server::UTCDate {
    now_utc_string()
}

impl AgentChat {
    /// Polls the agent and stores what came: joined rooms as Chats,
    /// received text as Messages, membership changes as Chat `members`.
    /// Pending invites are joined as [`crate::Options::invites`] allows.
    /// Call it whenever the client should see new state; the store's
    /// `/changes` then report it.
    ///
    /// # Errors
    ///
    /// [`SyncError::Agent`] if polling fails (nothing is lost: the agent
    /// keeps what it has not delivered), and [`SyncError::Store`] if the
    /// store refuses a write.
    pub async fn sync(&self) -> Result<SyncReport, SyncError> {
        let mut agent = self.agent.lock().await;
        let mut report = SyncReport::default();
        // A join's held messages come with the next poll, so a round that
        // joins is followed by one more.
        for _ in 0..2 {
            let (events, receipt) = agent.receive().await?;
            let joined = self.accept_invites(&mut agent, &mut report).await?;
            self.reconcile_rooms(&mut agent).await?;
            for event in events {
                self.apply(&mut agent, event, &mut report).await?;
            }
            // A Commit or a join may bring or change a contact's did_webvh
            // leaves (their ChatContact `did`).
            let epochs: std::collections::BTreeMap<String, u64> = agent
                .rooms()
                .into_iter()
                .filter(|room| room.status != RoomStatus::Left)
                .filter_map(|room| agent.epoch(&room.uri).ok().map(|e| (room.uri, e)))
                .collect();
            let moved = *self
                .did_epochs
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                != epochs;
            if moved {
                self.refresh_contact_dids(&mut agent, None).await?;
                *self
                    .did_epochs
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = epochs;
            }
            // Stored first, then acknowledged: what the agent delivered
            // can't be decrypted again, and an event not acknowledged
            // comes again after a crash (store_message skips a message it
            // has).
            self.save().await?;
            agent.acknowledge(receipt)?;
            if joined == 0 {
                break;
            }
        }
        if self.retry_attachments(&mut agent, &mut report).await? {
            self.save().await?;
        }
        Ok(report)
    }

    /// Joins the pending invites the policy allows; returns how many.
    async fn accept_invites(
        &self,
        agent: &mut Agent,
        report: &mut SyncReport,
    ) -> Result<usize, SyncError> {
        let invites = agent.invites();
        if invites.is_empty() {
            return Ok(0);
        }
        let allowed: Vec<String> = match self.options.invites {
            InvitePolicy::FromAllowed => agent
                .consents()
                .await?
                .into_iter()
                .filter(|r| r.target == self.user && r.decision.as_deref() == Some("grant"))
                .map(|r| r.requester)
                .collect(),
            _ => Vec::new(),
        };
        let mut joined = 0;
        for invite in invites {
            let accept = match self.options.invites {
                InvitePolicy::Any => true,
                InvitePolicy::Never => false,
                InvitePolicy::FromAllowed => match agent.inviter(invite.number) {
                    Ok(inviter) => allowed.contains(&inviter),
                    Err(e) => {
                        report
                            .problems
                            .push(format!("invite {}: {e}", invite.number));
                        false
                    }
                },
            };
            if !accept {
                report.pending_invites.push(invite.number);
                continue;
            }
            match agent.join(invite.number) {
                Ok(room) => {
                    report.joined.push(room);
                    joined += 1;
                }
                Err(e) => report
                    .problems
                    .push(format!("joining invite {}: {e}", invite.number)),
            }
        }
        Ok(joined)
    }

    /// Makes a Chat for every room the agent is in that has none.
    async fn reconcile_rooms(&self, agent: &mut Agent) -> Result<(), SyncError> {
        for room in agent.rooms() {
            if room.status != RoomStatus::Left && self.chat_of_room(&room.uri).is_none() {
                self.make_chat(agent, &room.uri).await?;
            }
        }
        Ok(())
    }

    /// The Chat of `room`, made if there is none.
    async fn chat_for(&self, agent: &mut Agent, room: &str) -> Result<Id, SyncError> {
        match self.chat_of_room(room) {
            Some(chat) => Ok(chat),
            None => self.make_chat(agent, room).await,
        }
    }

    /// A Chat for a room the agent joined: a group named by the room's
    /// `room_name`, its members the room's participants.
    async fn make_chat(&self, agent: &mut Agent, room: &str) -> Result<Id, SyncError> {
        let name = agent.room_name(room).ok().flatten().unwrap_or_default();
        let participants = agent.participants(room).unwrap_or_default();
        let members = self.members_of(&participants, &[]).await?;
        let created = now();
        let room_uri = room.to_owned();
        let (id, _) = self
            .inner
            .create_object::<Chat, _>(&(), &self.account, SYNC_CREATE_ID, move |id| {
                let mut chat =
                    Chat::new(id.clone(), ChatKind::Group, created, 0, vec![], false, true);
                chat.name = Some(name);
                chat.members = Some(members);
                chat.extra.insert(ROOM_ID.to_owned(), json!(room_uri));
                chat
            })
            .await?;
        self.link_room(room, &id);
        Ok(id)
    }

    /// ChatMembers for `participants`, keeping the entries of `existing`
    /// for those already members. The owner is the accountId; everyone
    /// else is a ChatContact. New entries are `member` (roles are not
    /// mapped) and joined now.
    async fn members_of(
        &self,
        participants: &[String],
        existing: &[ChatMember],
    ) -> Result<Vec<ChatMember>, SyncError> {
        let mut members = Vec::with_capacity(participants.len());
        for user in participants {
            let id = if *user == self.user {
                self.account.clone()
            } else {
                self.contact_for(user).await?
            };
            members.push(match existing.iter().find(|m| m.id == id) {
                Some(m) => m.clone(),
                None => ChatMember::new(id, ChatMemberRole::Member, now()),
            });
        }
        Ok(members)
    }

    /// The ChatContact whose `identity` is user URI `user`, made if there
    /// is none (draft-atwood-jmap-chat-mimi-00 §Senders).
    async fn contact_for(&self, user: &str) -> Result<Id, SyncError> {
        if let Some(id) = self.links().contact_of_user.get(user) {
            return Ok(id.clone());
        }
        let (contacts, _) = self
            .inner
            .get_objects::<ChatContact>(&(), &self.account, None, None)
            .await?;
        let id = match contacts.into_iter().find(|c| c.identity == user) {
            Some(contact) => contact.id,
            None => {
                let seen = now();
                let identity = user.to_owned();
                self.inner
                    .create_object::<ChatContact, _>(
                        &(),
                        &self.account,
                        SYNC_CREATE_ID,
                        move |id| {
                            ChatContact::new(
                                id.clone(),
                                identity.clone(),
                                identity,
                                seen.clone(),
                                seen,
                                false,
                            )
                        },
                    )
                    .await?
                    .0
            }
        };
        self.links()
            .contact_of_user
            .insert(user.to_owned(), id.clone());
        Ok(id)
    }

    async fn apply(
        &self,
        agent: &mut Agent,
        event: Event,
        report: &mut SyncReport,
    ) -> Result<(), SyncError> {
        match event {
            Event::IdentityChanged {
                room,
                user,
                pinned,
                presented,
            } => {
                self.store_identity_notice(agent, &room, &user, &pinned, presented.as_deref())
                    .await?;
                self.refresh_contact_dids(agent, Some((&user, presented.as_deref())))
                    .await
            }
            Event::Message(message) => self.store_message(agent, *message, report).await,
            Event::MembersChanged {
                room, participants, ..
            } => self.set_members(agent, &room, &participants).await,
            Event::Left { room } => {
                let Some(chat) = self.chat_of_room(&room) else {
                    return Ok(());
                };
                let members = self
                    .stored::<Chat>(&chat)
                    .await?
                    .and_then(|c| c.members)
                    .unwrap_or_default();
                let remaining: Vec<ChatMember> = members
                    .into_iter()
                    .filter(|m| m.id != self.account)
                    .collect();
                self.patch_chat(&chat, json!({ "members": remaining }))
                    .await
            }
            Event::Problem { room, description } => {
                report.problems.push(match room {
                    Some(room) => format!("{room}: {description}"),
                    None => description,
                });
                Ok(())
            }
            // Invites are read from Agent::invites; proposals need nothing.
            _ => Ok(()),
        }
    }

    /// draft-atwood-mls-didwebvh-credential-01 §Reference Identifiers
    /// ("MUST alert the user if a contact's SCID changes"): stores, in the
    /// Chat of `room`, a plain-text notice that `user`'s identity changed
    /// and should be verified (bead mimid-1wgh.4.81.27, Mark's decision
    /// (1)). It is a Message any JMAP Chat client shows, with no property
    /// of mimid's own (Mark rejected mimid-only properties).
    ///
    /// The notice's `senderId` is the accountId. JMAP Chat has no system
    /// sender, and mimid-agent-jmap had no convention for one; a made-up
    /// ChatContact would be shown as a person, and could be confused with a
    /// participant. The notice is written by the account's own agent, so
    /// the accountId is truthful and can never be read as coming from the
    /// contact; the body says it is the agent's notice. INVENTED, NOT FROM
    /// SPEC (bead mimid-1wgh.4.81.27).
    ///
    /// Idempotent: the notice is keyed by (Chat, [`notice_ref`] of the
    /// room, user, pinned and presented SCIDs), the same key received
    /// Messages use, and that key is rebuilt from `senderMsgId` when the
    /// store is restored. An event the journal delivers again, or the same
    /// mismatch reported again at a later Commit (the pin is kept), stores
    /// nothing more.
    async fn store_identity_notice(
        &self,
        agent: &mut Agent,
        room: &str,
        user: &str,
        pinned: &str,
        presented: Option<&str>,
    ) -> Result<(), SyncError> {
        let chat = self.chat_for(agent, room).await?;
        let reference = notice_ref(room, user, pinned, presented);
        if self
            .links()
            .messages
            .contains_key(&(chat.as_ref().to_owned(), reference))
        {
            return Ok(());
        }
        let contact = self.contact_for(user).await?;
        let name = self
            .stored::<ChatContact>(&contact)
            .await?
            .and_then(|c| c.display_name)
            .filter(|name| !name.trim().is_empty())
            .unwrap_or_else(|| user.to_owned());
        let body = identity_notice(&name, pinned, presented);
        let at = crate::retry::now_secs().saturating_mul(1000);
        let mut random = [0u8; 16];
        random[6..].copy_from_slice(&reference);
        let sender_msg_id = Id::from(
            ulid::Ulid::from_parts(at, u128::from_be_bytes(random))
                .to_string()
                .as_str(),
        );
        let mut message = Message::new(
            Id::from("pending"),
            sender_msg_id,
            self.account.clone(),
            chat.clone(),
            body,
            BodyType::Plain,
            utc_date(at),
            now(),
            DeliveryState::Delivered,
        );
        let (id, _) = self
            .inner
            .create_object::<Message, _>(&(), &self.account, SYNC_CREATE_ID, move |id| {
                message.id = id.clone();
                message
            })
            .await?;
        self.link_message(&chat, reference, &id);
        Ok(())
    }

    /// Sets each ChatContact's `did` (draft-atwood-jmap-chat-did-00
    /// §Optional `did` field) to the DID of its user's `did_webvh` leaves
    /// in the agent's active rooms (the head DID document's `id`, not the
    /// bare SCID), and clears it for a user seen only with
    /// BasicCredential leaves. A user absent from every room keeps what
    /// the contact has. When the user's leaves present several DIDs,
    /// `changed` (a user and the SCID an [`Event::IdentityChanged`]
    /// reported) picks the DID with that SCID, so `did` changes when the
    /// identity notice goes out; otherwise the one the contact has is
    /// kept, and failing that the first in order. Replacing or clearing a
    /// DID the contact had also sets `didChangedAt` (§DID changes); a
    /// first binding does not.
    ///
    /// The property is standard, server-set, and set here without the
    /// `urn:ietf:params:jmap:chat:did` capability, which the agent cannot
    /// advertise (see the crate documentation, # Mapping).
    pub(crate) async fn refresh_contact_dids(
        &self,
        agent: &mut Agent,
        changed: Option<(&str, Option<&str>)>,
    ) -> Result<(), SyncError> {
        // user -> (SCID, DID) of its did_webvh leaves; Basic-only users map
        // to an empty list.
        let mut seen: std::collections::BTreeMap<String, Vec<(String, String)>> =
            std::collections::BTreeMap::new();
        for room in agent.rooms() {
            if room.status == RoomStatus::Left {
                continue;
            }
            let Ok(clients) = agent.clients(&room.uri) else {
                continue;
            };
            for client in clients {
                if client.user.is_empty() || client.user == self.user {
                    continue;
                }
                let entry = seen.entry(client.user).or_default();
                if let (Some(scid), Some(did)) = (client.scid, client.did)
                    && !entry.iter().any(|(_, d)| *d == did)
                {
                    entry.push((scid, did));
                }
            }
        }
        for (user, mut dids) in seen {
            dids.sort();
            let contact = self.contact_for(&user).await?;
            let current = self
                .stored::<ChatContact>(&contact)
                .await?
                .and_then(|c| c.did)
                .map(|d| d.to_string());
            let preferred = changed
                .filter(|(u, _)| *u == user)
                .and_then(|(_, scid)| scid)
                .and_then(|scid| dids.iter().find(|(s, _)| s == scid))
                .map(|(_, did)| did.clone());
            let kept = current.clone().filter(|c| dids.iter().any(|(_, d)| d == c));
            let wanted = preferred
                .or(kept)
                .or_else(|| dids.first().map(|(_, did)| did.clone()));
            if wanted == current {
                continue;
            }
            // draft-atwood-jmap-chat-did-00 §DID changes: a DID bound
            // before that is now different, or gone, sets didChangedAt; a
            // first binding does not.
            let patch = if current.is_some() {
                json!({ "did": wanted, "didChangedAt": now() })
            } else {
                json!({ "did": wanted })
            };
            let patch =
                serde_json::from_value(patch).map_err(|e| SyncError::Store(e.to_string()))?;
            self.inner
                .update_object::<ChatContact>(&(), &self.account, &contact, patch)
                .await?;
        }
        Ok(())
    }

    async fn set_members(
        &self,
        agent: &mut Agent,
        room: &str,
        participants: &[String],
    ) -> Result<(), SyncError> {
        let chat = self.chat_for(agent, room).await?;
        let existing = self
            .stored::<Chat>(&chat)
            .await?
            .and_then(|c| c.members)
            .unwrap_or_default();
        let members = self.members_of(participants, &existing).await?;
        if members == existing {
            return Ok(());
        }
        self.patch_chat(&chat, json!({ "members": members })).await
    }

    async fn patch_chat(&self, chat: &Id, patch: serde_json::Value) -> Result<(), SyncError> {
        let patch = serde_json::from_value(patch).map_err(|e| SyncError::Store(e.to_string()))?;
        self.inner
            .update_object::<Chat>(&(), &self.account, chat, patch)
            .await?;
        Ok(())
    }

    /// Stores a received message (draft-atwood-jmap-chat-mimi-00
    /// §Message Identifiers, §Senders, §Topics).
    async fn store_message(
        &self,
        agent: &mut Agent,
        received: ReceivedMessage,
        report: &mut SyncReport,
    ) -> Result<(), SyncError> {
        let chat = self.chat_for(agent, &received.room).await?;
        let reference = message_ref(&received.message_id);
        let key = (chat.as_ref().to_owned(), reference);
        if self.links().messages.contains_key(&key) {
            return Ok(());
        }
        let content = &received.content;
        if content.replaces.is_some() {
            report
                .skipped
                .push(format!("{}: an edit or retraction", received.room));
            return Ok(());
        }
        let parts = received.attachments();
        let text = match received.text.clone() {
            Some(text) => text,
            None if !parts.is_empty() => String::new(),
            None => {
                report
                    .skipped
                    .push(format!("{}: neither text nor attachments", received.room));
                return Ok(());
            }
        };
        let (attachments, retry) = self
            .fetch_attachments(agent, &received.room, &parts, report)
            .await;
        let body_type = match &content.nested_part.part {
            Part::Single { content_type, .. }
                if content_type
                    .to_ascii_lowercase()
                    .starts_with("text/markdown") =>
            {
                BodyType::Markdown
            }
            _ => BodyType::Plain,
        };
        let sender = if received.sender == self.user {
            self.account.clone()
        } else {
            self.contact_for(&received.sender).await?
        };
        let reply_to = content.in_reply_to.as_ref().and_then(|id| {
            self.links()
                .messages
                .get(&(chat.as_ref().to_owned(), message_ref(id)))
                .cloned()
        });
        let mut message = Message::new(
            Id::from("pending"),
            sender_msg_id(received.accepted_at, &received.message_id),
            sender,
            chat.clone(),
            text,
            body_type,
            utc_date(received.accepted_at),
            now(),
            DeliveryState::Delivered,
        );
        message.reply_to = reply_to;
        message.topic_id = topic_id(&content.topic_id);
        message.attachments = attachments;
        let (id, _) = self
            .inner
            .create_object::<Message, _>(&(), &self.account, SYNC_CREATE_ID, move |id| {
                message.id = id.clone();
                message
            })
            .await?;
        self.link_message(&chat, reference, &id);
        self.keep_for_retry(&id, &received.room, retry, report);
        report.messages += 1;
        Ok(())
    }

    /// Fetches, opens and stores the attachments `parts` of a message in
    /// `room`, and returns them as JMAP Attachments: the part's file name
    /// (made safe, or [`FALLBACK_FILENAME`]) and media type (or
    /// [`FALLBACK_CONTENT_TYPE`]), the plaintext's size and SHA-256. Also
    /// returns, by position, the ones whose fetch failed in a way that may
    /// pass, for [`crate::retry`]. Any other failure is reported in
    /// `report.problems` and left out, as are those past
    /// [`MAX_ATTACHMENTS_PER_MESSAGE`] and all of them without a blob store.
    async fn fetch_attachments(
        &self,
        // Not &Agent: that is not Send across an await (see
        // the_sync_future_is_send).
        agent: &mut Agent,
        room: &str,
        parts: &[&ExternalPart],
        report: &mut SyncReport,
    ) -> (Vec<Attachment>, Vec<(u32, ExternalPart)>) {
        if parts.is_empty() {
            return (Vec::new(), Vec::new());
        }
        if self.blobs.is_none() {
            report.problems.push(format!(
                "{room}: {} attachments left out: no blob store",
                parts.len()
            ));
            return (Vec::new(), Vec::new());
        }
        if parts.len() > MAX_ATTACHMENTS_PER_MESSAGE {
            report.problems.push(format!(
                "{room}: {} attachments past the first {MAX_ATTACHMENTS_PER_MESSAGE} left out",
                parts.len() - MAX_ATTACHMENTS_PER_MESSAGE
            ));
        }
        let mut attachments = Vec::with_capacity(parts.len().min(MAX_ATTACHMENTS_PER_MESSAGE));
        let mut retry = Vec::new();
        // Problems name an attachment by its position, not its file name:
        // the daemon logs them, and a file name is message content.
        for (number, part) in (1..).zip(parts.iter().take(MAX_ATTACHMENTS_PER_MESSAGE)) {
            match self.fetch_one(agent, room, part).await {
                Ok(attachment) => attachments.push(attachment),
                Err((e, true)) => {
                    report.problems.push(format!(
                        "{room}: attachment {number} not fetched yet, will retry: {e}"
                    ));
                    retry.push((number, (*part).clone()));
                }
                Err((e, false)) => report
                    .problems
                    .push(format!("{room}: attachment {number} left out: {e}")),
            }
        }
        (attachments, retry)
    }

    /// Fetches, opens and stores one attachment. The error says whether it
    /// may pass ([`crate::retry`]; a blob store write failure may).
    async fn fetch_one(
        &self,
        agent: &mut Agent,
        room: &str,
        part: &ExternalPart,
    ) -> Result<Attachment, (String, bool)> {
        let Some(blobs) = &self.blobs else {
            return Err(("no blob store".to_owned(), false));
        };
        let plaintext = agent
            .fetch_attachment(room, part)
            .await
            .map_err(|e| (e.to_string(), crate::retry::may_pass(&e)))?;
        let info = blobs.put(&plaintext).map_err(|e| (e.to_string(), true))?;
        let content_type = if is_media_type(&part.content_type) {
            part.content_type.as_str()
        } else {
            FALLBACK_CONTENT_TYPE
        };
        // Attachment is #[non_exhaustive]: built through serde (AGENTS.md).
        serde_json::from_value(json!({
            "blobId": info.id,
            "filename": safe_filename(&part.filename),
            "contentType": content_type,
            "size": info.size,
            "sha256": hex(&info.sha256),
        }))
        .map_err(|e| (e.to_string(), false))
    }

    /// Keeps `failed`, attachments of Message `message` in `room`, for
    /// retry; past [`crate::retry::MAX_PENDING`] they are given up.
    fn keep_for_retry(
        &self,
        message: &Id,
        room: &str,
        failed: Vec<(u32, ExternalPart)>,
        report: &mut SyncReport,
    ) {
        if failed.is_empty() {
            return;
        }
        let mut pending = self
            .pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for (number, part) in failed {
            if pending.len() >= crate::retry::MAX_PENDING {
                report.problems.push(format!(
                    "{room}: attachment {number} left out: too many attachments waiting for retry"
                ));
                continue;
            }
            pending.push(crate::retry::PendingAttachment::new(
                message.as_ref().to_owned(),
                room.to_owned(),
                number,
                &part,
            ));
        }
    }

    /// Fetches again up to [`crate::retry::MAX_RETRIES_PER_SYNC`] pending
    /// attachments that are due; one that arrives is added to its Message.
    /// Returns whether the pending list or a Message changed.
    async fn retry_attachments(
        &self,
        agent: &mut Agent,
        report: &mut SyncReport,
    ) -> Result<bool, SyncError> {
        let now = crate::retry::now_secs();
        let due: Vec<crate::retry::PendingAttachment> = self
            .pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .filter(|p| p.next_try <= now)
            .take(crate::retry::MAX_RETRIES_PER_SYNC)
            .cloned()
            .collect();
        if due.is_empty() {
            return Ok(false);
        }
        for entry in due {
            let (room, number) = (entry.room.clone(), entry.number);
            let message_id = Id::from(entry.message.clone());
            let outcome = match entry.part.external_part() {
                None => Err(("the kept part is damaged".to_owned(), false)),
                Some(part) => self.fetch_one(agent, &room, &part).await,
            };
            // The entry leaves the list unless it is kept for another try.
            let mut keep = None;
            match outcome {
                Ok(attachment) => {
                    // None: the Message was destroyed meanwhile.
                    if let Some(message) = self.stored::<Message>(&message_id).await? {
                        let mut attachments = message.attachments;
                        attachments.push(attachment);
                        let patch = serde_json::from_value(json!({ "attachments": attachments }))
                            .map_err(|e| SyncError::Store(e.to_string()))?;
                        self.inner
                            .update_object::<Message>(&(), &self.account, &message_id, patch)
                            .await?;
                        report.attachments_retried += 1;
                    }
                }
                Err((e, true)) if entry.attempts + 1 < crate::retry::MAX_ATTEMPTS => {
                    let attempts = entry.attempts + 1;
                    keep = Some(crate::retry::PendingAttachment {
                        attempts,
                        next_try: now.saturating_add(crate::retry::delay_after(attempts)),
                        ..entry.clone()
                    });
                    report.problems.push(format!(
                        "{room}: attachment {number} still not fetched, will retry: {e}"
                    ));
                }
                Err((e, _)) => report
                    .problems
                    .push(format!("{room}: attachment {number} given up: {e}")),
            }
            let mut pending = self
                .pending
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(index) = pending.iter().position(|p| *p == entry) {
                match keep {
                    Some(updated) => pending[index] = updated,
                    None => {
                        pending.remove(index);
                    }
                }
            }
        }
        Ok(true)
    }
}

/// A received attachment's file name as an Attachment may carry it
/// (draft-atwood-jmap-chat-00 §Attachment: no `/`, `\` or null): those
/// and other control characters become `_`, it is cut to
/// [`MAX_FILENAME_CHARS`], and an empty one is [`FALLBACK_FILENAME`].
/// The reference octets (the random part of `senderMsgId`) of the identity
/// notice for one mismatch: the first 10 octets of SHA-256 over a label and
/// the room, user, pinned SCID and presented SCID (`basic` for a
/// BasicCredential leaf), each ended by a NUL. INVENTED, NOT FROM SPEC.
pub(crate) fn notice_ref(
    room: &str,
    user: &str,
    pinned: &str,
    presented: Option<&str>,
) -> MessageRef {
    use sha2::{Digest, Sha256};
    let mut hash = Sha256::new();
    for part in [
        "mimid identity-changed notice",
        room,
        user,
        pinned,
        presented.unwrap_or("basic"),
    ] {
        hash.update(part.as_bytes());
        hash.update([0]);
    }
    let digest = hash.finalize();
    let mut out = [0u8; 10];
    out.copy_from_slice(&digest[..10]);
    out
}

/// The text of an identity notice for contact `name`. Only public values:
/// the name and the SCIDs.
pub(crate) fn identity_notice(name: &str, pinned: &str, presented: Option<&str>) -> String {
    let change = match presented {
        Some(presented) => format!(
            "A device of {name} now presents a different did:webvh identity (SCID {presented}) \
             from the one first seen for them (SCID {pinned})."
        ),
        None => format!(
            "A device of {name} presents no did:webvh credential, but {name} was first seen \
             with one (SCID {pinned})."
        ),
    };
    format!(
        "Security notice from your mimid agent, not from {name}: the identity of {name} \
         changed. {change} Verify the new identity with {name} by other means before you \
         trust messages from that device."
    )
}

pub(crate) fn safe_filename(name: &str) -> String {
    let safe: String = name
        .chars()
        .take(MAX_FILENAME_CHARS)
        .map(|c| {
            if c == '/' || c == '\\' || c.is_control() {
                '_'
            } else {
                c
            }
        })
        .collect();
    if safe.trim().is_empty() {
        FALLBACK_FILENAME.to_owned()
    } else {
        safe
    }
}

#[cfg(test)]
mod tests {
    use std::future::Future;

    use super::*;

    /// A daemon runs `sync` in a spawned task, which needs a `Send` future:
    /// holding `&Agent` across an await does not give one, since `Agent`
    /// (its SQLite connection) is not `Sync`. A compile-time check.
    #[test]
    fn received_file_names_are_made_safe() {
        assert_eq!(safe_filename("report.pdf"), "report.pdf");
        assert_eq!(safe_filename("../../etc/passwd"), ".._.._etc_passwd");
        assert_eq!(safe_filename("a\\b\0c\nd"), "a_b_c_d");
        assert_eq!(safe_filename(""), FALLBACK_FILENAME);
        assert_eq!(safe_filename("   "), FALLBACK_FILENAME);
        // Bidi and zero-width characters are the client's to render
        // safely; they are not control characters (Cc) and stay.
        assert_eq!(safe_filename("a\u{202e}b\u{200b}"), "a\u{202e}b\u{200b}");
        let long = "\u{e9}".repeat(MAX_FILENAME_CHARS + 10);
        assert_eq!(safe_filename(&long).chars().count(), MAX_FILENAME_CHARS);
    }

    #[test]
    fn the_sync_future_is_send() {
        fn sync_of(
            chat: &AgentChat,
        ) -> impl Future<Output = Result<SyncReport, SyncError>> + Send + '_ {
            chat.sync()
        }
        let _ = sync_of;
    }
}
