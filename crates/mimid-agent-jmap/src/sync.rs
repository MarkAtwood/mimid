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
use crate::convert::{message_ref, sender_msg_id, topic_id, utc_date};

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
    /// attachments left out because they could not be fetched, opened or
    /// stored, as text.
    pub problems: Vec<String>,
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
        let attachments = self
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
        report.messages += 1;
        Ok(())
    }

    /// Fetches, opens and stores the attachments `parts` of a message in
    /// `room`, and returns them as JMAP Attachments: the part's file name
    /// (made safe, or [`FALLBACK_FILENAME`]) and media type (or
    /// [`FALLBACK_CONTENT_TYPE`]), the plaintext's size and SHA-256. One
    /// that fails is reported in `report.problems` and left out, as are
    /// those past [`MAX_ATTACHMENTS_PER_MESSAGE`] and all of them without a
    /// blob store.
    async fn fetch_attachments(
        &self,
        // Not &Agent: that is not Send across an await (see
        // the_sync_future_is_send).
        agent: &mut Agent,
        room: &str,
        parts: &[&ExternalPart],
        report: &mut SyncReport,
    ) -> Vec<Attachment> {
        if parts.is_empty() {
            return Vec::new();
        }
        let Some(blobs) = &self.blobs else {
            report.problems.push(format!(
                "{room}: {} attachments left out: no blob store",
                parts.len()
            ));
            return Vec::new();
        };
        if parts.len() > MAX_ATTACHMENTS_PER_MESSAGE {
            report.problems.push(format!(
                "{room}: {} attachments past the first {MAX_ATTACHMENTS_PER_MESSAGE} left out",
                parts.len() - MAX_ATTACHMENTS_PER_MESSAGE
            ));
        }
        let mut attachments = Vec::with_capacity(parts.len().min(MAX_ATTACHMENTS_PER_MESSAGE));
        // Problems name an attachment by its position, not its file name:
        // the daemon logs them, and a file name is message content.
        for (number, part) in (1..).zip(parts.iter().take(MAX_ATTACHMENTS_PER_MESSAGE)) {
            let filename = safe_filename(&part.filename);
            let stored = match agent.fetch_attachment(room, part).await {
                Ok(plaintext) => blobs.put(&plaintext).map_err(|e| e.to_string()),
                Err(e) => Err(e.to_string()),
            };
            let info = match stored {
                Ok(info) => info,
                Err(e) => {
                    report
                        .problems
                        .push(format!("{room}: attachment {number} left out: {e}"));
                    continue;
                }
            };
            let content_type = if is_media_type(&part.content_type) {
                part.content_type.as_str()
            } else {
                FALLBACK_CONTENT_TYPE
            };
            // Attachment is #[non_exhaustive]: built through serde
            // (AGENTS.md).
            match serde_json::from_value(json!({
                "blobId": info.id,
                "filename": filename,
                "contentType": content_type,
                "size": info.size,
                "sha256": hex(&info.sha256),
            })) {
                Ok(attachment) => attachments.push(attachment),
                Err(e) => report
                    .problems
                    .push(format!("{room}: attachment {number} left out: {e}")),
            }
        }
        attachments
    }
}

/// A received attachment's file name as an Attachment may carry it
/// (draft-atwood-jmap-chat-00 §Attachment: no `/`, `\` or null): those
/// and other control characters become `_`, it is cut to
/// [`MAX_FILENAME_CHARS`], and an empty one is [`FALLBACK_FILENAME`].
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
