//! The user's own actions (docs/design/agent-frontends.md §2, "The change
//! feed"; §3 step 5): every write a front end makes is a [`Store`] method
//! that takes store keys and user URIs, makes the agent call if the
//! action means something in MIMI, and writes the result into the
//! records. A front end translates its own names to keys and URIs, calls
//! the method, shows the record it gets back, and then saves
//! ([`Store::save`]). The methods do not save by themselves, so that the
//! record and what the calling front end shows of it are saved together.
//! Each records what it changed ([`crate::Change`]); the save publishes
//! it to every front end ([`crate::Frontend`], [`Store::subscribe`]), so
//! the others learn of the write. A method the agent acts on also wakes
//! the sync loop ([`Store::sync_wanted`]).
//!
//! | Action | Method | Agent |
//! |---|---|---|
//! | Host a room and invite | [`Store::create_room`] | `host_room`, `invite` |
//! | Invite, remove, change roles, leave | [`Store::change_members`] | `invite`, `remove`, `change_role`, `leave` |
//! | Leave a room | [`Store::leave`] | `leave` |
//! | Delete a room here, with its messages | [`Store::forget_room`], [`Store::delete_blobs`] | none |
//! | Send | [`Store::send`] | `send_message` |
//! | Edit, retract | [`Store::edit`], [`Store::retract`] | `send_edit`, `send_retraction` |
//! | Delete here | [`Store::mark_deleted`], [`Store::delete_message`] | none |
//! | Ban, unban, kick | [`Store::ban`], [`Store::unban`], [`Store::kick`] | `ban`, `unban`, `kick` |
//! | A ban's reason and expiry | [`Store::set_ban_terms`] | none |
//! | Report | [`Store::report`] | `report_abuse` |
//! | People | [`Store::add_person`], [`Store::rename_person`], [`Store::forget_person`] | none |
//! | Read positions | [`Store::set_read_position`], [`Store::forget_read_position`] | none |
//! | Consent and invites | [`Store::allow`], [`Store::deny`], [`Store::accept_invite`] | `allow`, `deny`, `join` |
//!
//! A method that makes a record takes its key: [`Store::new_key`], or a
//! front end's own id of the same form (a JMAP write keeps its JMAP id).
//!
//! # Limitations
//!
//! - A write method makes no person records. The people a write names
//!   (an invited user, say) get one at the next [`Store::sync`] that sees
//!   them in a room, as before the store.
//! - Reactions are not an action: the agent sends none
//!   (docs/design/agent-frontends.md §4, "The mapping").
//! - Each method locks the agent for its own calls only; a front end that
//!   needs several in a row ([`Store::change_members`]) gets them under
//!   one lock.

use std::collections::{BTreeMap, BTreeSet};

use mimid_agent_core::frank::{decode_abusive_message, decode_unverified_message};
use mimid_agent_core::{
    AbuseType, AgentError, HostOptions, OutgoingAttachment, ReportOutcome, ReportedMessage,
    RoomStatus,
};
use sha2::{Digest, Sha256};

use crate::blobs::{BlobError, MIN_UNREFERENCED_AGE, hex};
use crate::change::Change;
use crate::content::BodyType;
use crate::convert::{message_ref, sender_msg_id};
use crate::record::{
    Attachment, Ban, Deletion, Key, Message, Octets, Person, ReadPosition, Room,
    RoomStatus as Status, Sender,
};
use crate::state::RemovedRoom;
use crate::store::Store;
use crate::sync::{MAX_ALIASES, RoomRoles, now_ms};

/// The role index the agent gives the participants it adds and the ones
/// it makes members again: "member" in its default role list (decision
/// mimid-1wgh.56).
pub const MEMBER_ROLE_INDEX: u32 = 2;

/// Why a write was not made. Nothing was sent, except where a variant
/// says otherwise.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ActionError {
    /// The agent failed or refused: the hub's or the room's refusal, a
    /// room it is not in, a value it does not take, or the network.
    #[error(transparent)]
    Agent(#[from] AgentError),
    /// The store holds no room of this key.
    #[error("no room {0}")]
    NoSuchRoom(Key),
    /// The store holds no message of this key.
    #[error("no message {0}")]
    NoSuchMessage(Key),
    /// A role change to admin in a room with no role named "admin".
    #[error("the room has no admin role")]
    NoAdminRole,
    /// A role change of the user themselves.
    #[error("the user's own role in a MIMI room cannot be changed")]
    OwnRole,
    /// An edit or retraction of a message whose first MIMI message ID is
    /// not kept (one stored before the IDs were kept, or a notice).
    #[error("no MIMI message ID is kept for message {0}, so it cannot be edited or retracted")]
    NotEditable(Key),
    /// An edit or retraction of a message with [`MAX_ALIASES`] versions.
    #[error("the message has too many versions")]
    TooManyVersions,
    /// Attachments to send, and no blob store.
    #[error("this store keeps no attachments")]
    NoBlobStore,
    /// An attachment to send names a blob the blob store does not have.
    #[error("no blob {0}")]
    NoSuchBlob(String),
    /// The blob store failed.
    #[error(transparent)]
    Blob(#[from] BlobError),
    /// A message to report that keeps nothing to report: not stored, the
    /// user's own, or retracted.
    #[error("message {0} cannot be reported: it is not a received message")]
    NotReportable(Key),
    /// Messages to report from more than one room.
    #[error("the messages are not all in one room")]
    NotOneRoom,
    /// What a message kept for reports does not decode.
    #[error("a message kept for reports does not decode")]
    Unreadable(#[source] AgentError),
}

/// A role a user can be given in a room.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Role {
    /// The room's role named "admin".
    Admin,
    /// [`MEMBER_ROLE_INDEX`].
    Member,
}

/// Changes to a room's participants, made in this order: invites,
/// removals, role changes, then the user's own leaving.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct MemberChanges {
    /// Users to invite.
    pub invite: Vec<String>,
    /// Users to remove from the room.
    pub remove: Vec<String>,
    /// Users whose role changes.
    pub roles: Vec<(String, Role)>,
    /// The user leaves the room.
    pub leave: bool,
}

impl MemberChanges {
    /// No changes.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

/// A report [`Store::report`] made.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Reported {
    /// The URI of the messages' room.
    pub room: String,
    /// The hub's answer.
    pub outcome: ReportOutcome,
}

/// A room [`Store::forget_room`] deleted.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ForgottenRoom {
    /// What was deleted.
    pub removed: RemovedRoom,
    /// When.
    pub at: std::time::SystemTime,
}

/// An attachment to send, by blob.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct OutgoingFile {
    /// The blob id in the blob store.
    pub blob_id: String,
    /// Its media type.
    pub media_type: String,
    /// A suggested file name, or empty.
    pub file_name: String,
}

impl OutgoingFile {
    /// Blob `blob_id`, of `media_type`, named `file_name`.
    #[must_use]
    pub fn new(
        blob_id: impl Into<String>,
        media_type: impl Into<String>,
        file_name: impl Into<String>,
    ) -> Self {
        Self {
            blob_id: blob_id.into(),
            media_type: media_type.into(),
            file_name: file_name.into(),
        }
    }
}

impl Store {
    /// The URI of room `key`.
    fn room_uri(&self, key: &str) -> Result<String, ActionError> {
        self.state()
            .rooms
            .get(key)
            .map(|room| room.uri.clone())
            .ok_or_else(|| ActionError::NoSuchRoom(key.to_owned()))
    }

    /// Sets the participants, role indexes and role names of room `key`
    /// from the agent, if it is in the room.
    fn refresh_participants(&self, agent: &mimid_agent_core::Agent, key: &str, uri: &str) {
        let Ok(participants) = agent.participants(uri) else {
            return;
        };
        let roles = RoomRoles::of(agent, uri);
        if let Some(room) = self.state().rooms.get_mut(key) {
            room.participants = roles.participants(&participants);
            room.role_names = roles.names();
        }
    }

    /// Hosts a new room named `name`, invites `invite` to it, and records
    /// it under `key`. If an invite fails, the room is left again and
    /// nothing is recorded.
    ///
    /// # Errors
    ///
    /// [`ActionError::Agent`] if hosting or an invite fails.
    pub async fn create_room(
        &self,
        key: Key,
        name: &str,
        invite: &[String],
    ) -> Result<Room, ActionError> {
        let mut agent = self.agent.lock().await;
        let uri = agent.host_room(&HostOptions::named(name)).await?;
        for user in invite {
            if let Err(e) = agent.invite(&uri, user).await {
                // Do not keep a room the caller is told was not made.
                if let Err(leave) = agent.leave(&uri).await {
                    tracing::warn!(room = %uri, error = %leave, "leaving a half-made room");
                }
                return Err(e.into());
            }
        }
        let participants = agent.participants(&uri).unwrap_or_default();
        let roles = RoomRoles::of(&agent, &uri);
        let room = Room {
            key,
            name: agent.room_name(&uri).ok().flatten(),
            uri,
            status: Status::Active,
            participants: roles.participants(&participants),
            role_names: roles.names(),
            ext: BTreeMap::new(),
        };
        self.state().insert_room(room.clone());
        self.record([Change::RoomAdded(room.key.clone())]);
        self.want_sync();
        Ok(room)
    }

    /// Makes `changes` in room `key` under one lock of the agent, in the
    /// order [`MemberChanges`] gives; the hub's room policy decides each.
    /// The room's participants are then read again from the agent.
    ///
    /// # Errors
    ///
    /// [`ActionError::NoSuchRoom`], [`ActionError::OwnRole`] if a role
    /// change names the user, [`ActionError::NoAdminRole`], and
    /// [`ActionError::Agent`]. The changes before a failed one stay made.
    pub async fn change_members(
        &self,
        key: &str,
        changes: &MemberChanges,
    ) -> Result<(), ActionError> {
        let uri = self.room_uri(key)?;
        if changes.roles.iter().any(|(user, _)| *user == self.user) {
            return Err(ActionError::OwnRole);
        }
        let mut agent = self.agent.lock().await;
        let result = async {
            for user in &changes.invite {
                agent.invite(&uri, user).await?;
            }
            for user in &changes.remove {
                agent.remove(&uri, user).await?;
            }
            for (user, role) in &changes.roles {
                let index = match role {
                    Role::Admin => agent
                        .roles(&uri)?
                        .into_iter()
                        .find(|(_, name)| name == "admin")
                        .map(|(index, _)| index)
                        .ok_or(ActionError::NoAdminRole)?,
                    Role::Member => MEMBER_ROLE_INDEX,
                };
                agent.change_role(&uri, user, index).await?;
            }
            if changes.leave {
                agent.leave(&uri).await?;
                if let Some(room) = self.state().rooms.get_mut(key) {
                    room.status = Status::Leaving;
                }
                self.record([Change::RoomLeft(key.to_owned())]);
            }
            Ok(())
        }
        .await;
        self.refresh_participants(&agent, key, &uri);
        if !(changes.invite.is_empty() && changes.remove.is_empty() && changes.roles.is_empty()) {
            self.record([Change::RoomChanged(key.to_owned())]);
        }
        self.want_sync();
        result
    }

    /// Leaves room `key`, if the agent is in it: every device of the user
    /// leaves, and only a new invite brings them back
    /// (`Agent::leave`). The record stays, as leaving.
    ///
    /// # Errors
    ///
    /// [`ActionError::NoSuchRoom`], and [`ActionError::Agent`] if leaving
    /// fails.
    pub async fn leave(&self, key: &str) -> Result<(), ActionError> {
        let uri = self.room_uri(key)?;
        let mut agent = self.agent.lock().await;
        let active = agent
            .rooms()
            .iter()
            .any(|r| r.uri == uri && r.status == RoomStatus::Active);
        if active {
            agent.leave(&uri).await?;
            if let Some(room) = self.state().rooms.get_mut(key) {
                room.status = Status::Leaving;
            }
            self.record([Change::RoomLeft(key.to_owned())]);
            self.want_sync();
        }
        Ok(())
    }

    /// Deletes room `key` here with everything the store keeps of it
    /// (docs/design/agent-frontends.md §7.9; [`crate::State::remove_room`]):
    /// its record, messages, bans, read positions and attachments waiting
    /// for a retry. A tombstone keeps [`Store::sync`] from storing the
    /// room's events again while the agent can still deliver them. The
    /// agent is not told: [`Store::leave`] first to leave the room too. A
    /// room the agent is still in is not kept out: the next sync makes a
    /// new record for it.
    ///
    /// The deletion is a [`Change::RoomForgotten`]. The blobs of its
    /// attachments stay in the blob store until the next save that writes
    /// the records ([`Store::save`]), which then deletes those nothing
    /// names any more ([`Store::delete_blobs`]). Takes the agent lock, so
    /// it waits for a sync that is running. `None` if there is no such
    /// room.
    pub async fn forget_room(&self, key: &str) -> Option<ForgottenRoom> {
        let _agent = self.agent.lock().await;
        let removed = self.state().remove_room(key)?;
        let forgotten = ForgottenRoom {
            removed,
            at: std::time::SystemTime::now(),
        };
        self.record([Change::RoomForgotten {
            key: key.to_owned(),
            messages: forgotten.removed.messages.clone(),
            bans: forgotten.removed.bans.clone(),
        }]);
        self.delete_blobs_after_save(forgotten.clone());
        Some(forgotten)
    }

    /// Deletes from the blob store the blobs of the attachments of a room
    /// [`Store::forget_room`] deleted, except those in `referenced` (every
    /// blob id that a record or a front end still names,
    /// [`Store::blobs_in_use`]) and those stored
    /// again since. A blob of the user's own message is the user's upload:
    /// it is deleted only if it was last stored or sent at least
    /// [`crate::blobs::MIN_UNREFERENCED_AGE`] before the room was
    /// forgotten, since RFC 8620 §6 keeps an unreferenced upload that long;
    /// otherwise the blob store's quota deletes it later. Returns how many
    /// it deleted; 0 without a blob store. [`Store::save`] calls it for
    /// every room forgotten since the last save that wrote.
    ///
    /// # Errors
    ///
    /// [`ActionError::Blob`] for the first blob that cannot be deleted;
    /// the rest are then left.
    pub fn delete_blobs(
        &self,
        forgotten: &ForgottenRoom,
        referenced: &BTreeSet<String>,
    ) -> Result<usize, ActionError> {
        let Some(blobs) = self.blobs.get() else {
            return Ok(0);
        };
        let uploads_by = forgotten
            .at
            .checked_sub(MIN_UNREFERENCED_AGE)
            .unwrap_or(std::time::UNIX_EPOCH);
        let mut deleted = 0;
        for id in &forgotten.removed.blobs {
            let stored_by = if forgotten.removed.sent.contains(id) {
                uploads_by
            } else {
                forgotten.at
            };
            if blobs.delete_if_unreferenced(id, referenced, stored_by)? {
                deleted += 1;
            }
        }
        Ok(deleted)
    }

    /// Sends `text` and the attachments `files` to room `key` as one
    /// `text/plain` MIMI message (`Agent::send_message`: each blob is read
    /// from the blob store, encrypted, uploaded and sent as an
    /// ExternalPart), and records it under `key` as the user's.
    ///
    /// # Errors
    ///
    /// [`ActionError::NoSuchRoom`]; [`ActionError::NoBlobStore`],
    /// [`ActionError::NoSuchBlob`] or [`ActionError::Blob`] for the
    /// attachments; [`ActionError::Agent`] if sending fails.
    pub async fn send(
        &self,
        key: Key,
        room: &str,
        text: &str,
        files: &[OutgoingFile],
    ) -> Result<Message, ActionError> {
        let uri = self.room_uri(room)?;
        let (outgoing, attachments) = self.read_files(files)?;
        // The agent stays locked until the record is in: the agent has
        // journaled the message as this user's own (docs/design/
        // agent-frontends.md §3 step 10), and a sync in between would
        // store that entry before this record exists, and this one
        // again.
        let mut agent = self.agent.lock().await;
        let sent = agent.send_message(&uri, text, &outgoing).await?;
        let mut state = self.state();
        let seq = state.take_seq();
        let message = Message {
            key,
            room: room.to_owned(),
            seq,
            sender: Sender::User(self.user.clone()),
            mimi_id: Some(Octets(sent.message_id.0)),
            aliases: Vec::new(),
            accepted_at: sent.accepted_at,
            sender_msg_id: sender_msg_id(sent.accepted_at, &sent.message_id),
            body: text.to_owned(),
            body_type: BodyType::Plain,
            in_reply_to: None,
            topic_id: None,
            attachments,
            edit_history: Vec::new(),
            edited_at: None,
            deleted: None,
            kept_frank: None,
            notice: None,
            ext: BTreeMap::new(),
        };
        state.insert_message(message.clone());
        drop(state);
        drop(agent);
        self.record([Change::MessageAdded(message.key.clone())]);
        self.want_sync();
        Ok(message)
    }

    /// The content of `files` from the blob store, as the agent sends
    /// them and as the message records them. Each blob is touched first,
    /// so it is not evicted while it is sent, before the message that
    /// names it is recorded (decision mimid-1wgh.68).
    fn read_files(
        &self,
        files: &[OutgoingFile],
    ) -> Result<(Vec<OutgoingAttachment>, Vec<Attachment>), ActionError> {
        if files.is_empty() {
            return Ok((Vec::new(), Vec::new()));
        }
        let blobs = self.blobs.get().ok_or(ActionError::NoBlobStore)?;
        let now = std::time::SystemTime::now();
        let mut outgoing = Vec::with_capacity(files.len());
        let mut attachments = Vec::with_capacity(files.len());
        for file in files {
            blobs.touch(&file.blob_id, now)?;
            let content = blobs
                .get(&file.blob_id)?
                .ok_or_else(|| ActionError::NoSuchBlob(file.blob_id.clone()))?;
            attachments.push(Attachment {
                blob_id: file.blob_id.clone(),
                file_name: file.file_name.clone(),
                media_type: file.media_type.clone(),
                size: content.len() as u64,
                sha256: hex(&Sha256::digest(&content)),
            });
            outgoing.push(OutgoingAttachment {
                content,
                content_type: file.media_type.clone(),
                filename: file.file_name.clone(),
            });
        }
        Ok((outgoing, attachments))
    }

    /// The room URI and first MIMI message ID of message `key`, which the
    /// user may edit or retract.
    fn editable(&self, key: &str) -> Result<(String, mimi_content::MessageId), ActionError> {
        let state = self.state();
        let message = state
            .messages
            .get(key)
            .ok_or_else(|| ActionError::NoSuchMessage(key.to_owned()))?;
        let uri = state
            .rooms
            .get(&message.room)
            .map(|room| room.uri.clone())
            .ok_or_else(|| ActionError::NoSuchRoom(message.room.clone()))?;
        let first = message
            .mimi_id
            .ok_or_else(|| ActionError::NotEditable(key.to_owned()))?;
        if message.aliases.len() >= MAX_ALIASES {
            return Err(ActionError::TooManyVersions);
        }
        Ok((uri, mimi_content::MessageId(first.0)))
    }

    /// Edits the user's message `key` to `text` of `body_type`
    /// (decision mimid-1wgh.65): the edit goes to the room as MIMI content
    /// with `replaces` naming the first version, then the record takes it,
    /// at the hub's acceptance time, with the old body kept as a revision
    /// ([`crate::State::edit_message`]) and the edit's ID as an alias. That
    /// the user sent the message is the caller's to check.
    ///
    /// # Errors
    ///
    /// [`ActionError::NoSuchMessage`], [`ActionError::NoSuchRoom`] for a
    /// message of a room the store does not hold,
    /// [`ActionError::NotEditable`], [`ActionError::TooManyVersions`], and
    /// [`ActionError::Agent`] if sending fails.
    pub async fn edit(
        &self,
        key: &str,
        text: &str,
        body_type: BodyType,
    ) -> Result<Message, ActionError> {
        let (uri, first) = self.editable(key)?;
        // Locked until the alias is in, as in Store::send.
        let mut agent = self.agent.lock().await;
        let sent = agent.send_edit(&uri, &first, text).await?;
        let edited = {
            let mut state = self.state();
            state.edit_message(key, text.to_owned(), body_type, sent.accepted_at);
            state.add_alias(key, message_ref(&sent.message_id));
            state.messages.get(key).cloned()
        };
        drop(agent);
        self.changed_message(key, edited)
    }

    /// Retracts the user's message `key` for everyone (decision
    /// mimid-1wgh.65): the retraction goes to the room, then the record
    /// loses its content at the hub's acceptance time
    /// ([`crate::State::retract_message`]) and takes the retraction's ID as
    /// an alias. That the user sent the message is the caller's to check.
    ///
    /// # Errors
    ///
    /// As [`Store::edit`].
    pub async fn retract(&self, key: &str) -> Result<Message, ActionError> {
        let (uri, first) = self.editable(key)?;
        // Locked until the alias is in, as in Store::send.
        let mut agent = self.agent.lock().await;
        let sent = agent.send_retraction(&uri, &first).await?;
        let retracted = {
            let mut state = self.state();
            state.retract_message(key, sent.accepted_at);
            state.add_alias(key, message_ref(&sent.message_id));
            state.messages.get(key).cloned()
        };
        drop(agent);
        self.changed_message(key, retracted)
    }

    /// Marks message `key` deleted here at `at`, in milliseconds, unless
    /// it is deleted already; nothing is sent. The record keeps its
    /// content (a front end hides it) and what it kept for reports. False
    /// if there is no such message.
    pub fn mark_deleted(&self, key: &str, at: u64) -> bool {
        let mut state = self.state();
        let Some(message) = state.messages.get_mut(key) else {
            return false;
        };
        if message.deleted.is_none() {
            message.deleted = Some(Deletion { at, for_all: false });
            drop(state);
            self.record([Change::MessageChanged(key.to_owned())]);
        }
        true
    }

    /// A [`Change::MessageChanged`] of `key`, after an edit or retraction
    /// was sent and recorded; the record as it is now.
    fn changed_message(&self, key: &str, now: Option<Message>) -> Result<Message, ActionError> {
        self.want_sync();
        let message = now.ok_or_else(|| ActionError::NoSuchMessage(key.to_owned()))?;
        self.record([Change::MessageChanged(key.to_owned())]);
        Ok(message)
    }

    /// Deletes message `key` here, in every front end, with a tombstone
    /// so the journal does not bring it back ([`crate::State::delete_message`]);
    /// nothing is sent.
    pub fn delete_message(&self, key: &str) -> Option<Message> {
        let message = self.state().delete_message(key)?;
        self.record([Change::MessageDeleted(key.to_owned())]);
        Some(message)
    }

    /// Bans `user` in room `key` (`Agent::ban`: one Commit that gives the
    /// user the room's "banned" role and removes all their clients), and
    /// records the ban under `ban_key`, with the user as banner, `reason`
    /// and `expires_at` (milliseconds), both local. The agent stays locked
    /// until the ban is recorded, so a sync cannot record the room's new
    /// ban first and twice.
    ///
    /// # Errors
    ///
    /// [`ActionError::NoSuchRoom`], and [`ActionError::Agent`] if the ban
    /// fails.
    pub async fn ban(
        &self,
        ban_key: Key,
        key: &str,
        user: &str,
        reason: Option<String>,
        expires_at: Option<u64>,
    ) -> Result<Ban, ActionError> {
        let uri = self.room_uri(key)?;
        let mut agent = self.agent.lock().await;
        agent.ban(&uri, user).await?;
        let ban = Ban {
            key: ban_key,
            room: key.to_owned(),
            user: user.to_owned(),
            banned_by: self.user.clone(),
            reason,
            expires_at,
            ext: BTreeMap::new(),
        };
        self.state().bans.insert(ban.key.clone(), ban.clone());
        self.refresh_participants(&agent, key, &uri);
        self.record([
            Change::BanAdded(ban.key.clone()),
            Change::RoomChanged(key.to_owned()),
        ]);
        self.want_sync();
        Ok(ban)
    }

    /// Sets the local `reason` and `expires_at` (milliseconds) of ban
    /// `key`; false if there is no such ban.
    pub fn set_ban_terms(
        &self,
        key: &str,
        reason: Option<String>,
        expires_at: Option<u64>,
    ) -> bool {
        let mut state = self.state();
        let Some(ban) = state.bans.get_mut(key) else {
            return false;
        };
        ban.reason = reason;
        ban.expires_at = expires_at;
        drop(state);
        self.record([Change::BanChanged(key.to_owned())]);
        true
    }

    /// Lifts ban `key`: the user is unbanned in its room if the room still
    /// holds them banned (`Agent::unban`: the member role again, no client
    /// added), and the record goes. A ban the room no longer holds is only
    /// removed. None if there is no such ban.
    ///
    /// # Errors
    ///
    /// [`ActionError::Agent`] if the unban fails; the record then stays.
    pub async fn unban(&self, key: &str) -> Result<Option<Ban>, ActionError> {
        let mut agent = self.agent.lock().await;
        let Some(ban) = self.state().bans.get(key).cloned() else {
            return Ok(None);
        };
        self.lift_ban(&mut agent, &ban).await?;
        let uri = {
            let mut state = self.state();
            state.bans.remove(key);
            state.rooms.get(&ban.room).map(|r| r.uri.clone())
        };
        self.record([Change::BanLifted(key.to_owned())]);
        if let Some(uri) = uri {
            self.refresh_participants(&agent, &ban.room, &uri);
            self.record([Change::RoomChanged(ban.room.clone())]);
        }
        self.want_sync();
        Ok(Some(ban))
    }

    /// Kicks each of `users` from room `key` (`Agent::kick`): their
    /// clients leave the group and they stay participants. One Commit per
    /// user.
    ///
    /// # Errors
    ///
    /// [`ActionError::NoSuchRoom`], and [`ActionError::Agent`] for the
    /// first kick that fails; the kicks before it stay made.
    pub async fn kick(&self, key: &str, users: &[String]) -> Result<(), ActionError> {
        let uri = self.room_uri(key)?;
        let mut agent = self.agent.lock().await;
        let result = async {
            for user in users {
                agent.kick(&uri, user).await?;
            }
            Ok(())
        }
        .await;
        // The records change with the agent's member change, at the sync.
        self.want_sync();
        result
    }

    /// Reports the received messages `keys`, all of one room, to the
    /// room's hub through the user's server (`Agent::report_abuse`), with
    /// what each kept for reports ([`crate::report::KeptFrank`]): franked
    /// ones as protocol-07 §5.9 `AbusiveMessage`s, unfranked ones
    /// unverified (decisions mimid-1wgh.59, mimid-1wgh.60). The messages
    /// are checked in order.
    ///
    /// # Errors
    ///
    /// [`ActionError::NotReportable`] for the first message that keeps
    /// nothing, [`ActionError::NotOneRoom`] at the first of another room,
    /// [`ActionError::Unreadable`] if what one kept does not decode, and
    /// [`ActionError::Agent`] if the report cannot be made. Nothing is then
    /// sent, except for the last.
    pub async fn report(
        &self,
        keys: &[Key],
        reason: AbuseType,
        note: &str,
    ) -> Result<Reported, ActionError> {
        let mut room: Option<String> = None;
        let mut messages = Vec::with_capacity(keys.len());
        for key in keys {
            let kept = self
                .state()
                .messages
                .get(key)
                .and_then(|m| m.kept_frank.clone())
                .ok_or_else(|| ActionError::NotReportable(key.clone()))?;
            match &room {
                None => room = Some(kept.room.clone()),
                Some(first) if *first == kept.room => {}
                Some(_) => return Err(ActionError::NotOneRoom),
            }
            let message = crate::blobs::unhex(&kept.message)
                .ok_or_else(|| AgentError::Invalid("not hex".to_owned()))
                .and_then(|bytes| {
                    if kept.unverified {
                        decode_unverified_message(&bytes).map(ReportedMessage::Unfranked)
                    } else {
                        decode_abusive_message(&bytes).map(ReportedMessage::Franked)
                    }
                })
                .map_err(ActionError::Unreadable)?;
            messages.push(message);
        }
        let Some(room) = room else {
            return Err(ActionError::Agent(AgentError::Invalid(
                "no messages to report".to_owned(),
            )));
        };
        let agent = self.agent.lock().await;
        let outcome = agent.report_abuse(&room, &messages, reason, note).await?;
        Ok(Reported { room, outcome })
    }

    /// Records a person for `user` under `key`, with `display_name`, the
    /// user's local name for them, as first seen now.
    pub fn add_person(&self, key: Key, user: &str, display_name: Option<String>) -> Person {
        let person = Person {
            key,
            user: user.to_owned(),
            display_name,
            did: None,
            did_changed_at: None,
            first_seen: now_ms(),
            ext: BTreeMap::new(),
        };
        self.state().insert_person(person.clone());
        self.record([Change::PersonAdded(person.key.clone())]);
        person
    }

    /// Sets the user's local name for person `key`; false if there is no
    /// such person.
    pub fn rename_person(&self, key: &str, display_name: Option<String>) -> bool {
        let mut state = self.state();
        let Some(person) = state.people.get_mut(key) else {
            return false;
        };
        person.display_name = display_name;
        drop(state);
        self.record([Change::PersonChanged(key.to_owned())]);
        true
    }

    /// Forgets person `key`; the user gets a new record when next seen.
    pub fn forget_person(&self, key: &str) -> Option<Person> {
        let person = self.state().remove_person(key)?;
        self.record([Change::PersonForgotten(key.to_owned())]);
        Some(person)
    }

    /// Sets read position `key` in room `room`: the last message read and
    /// when (milliseconds). The room need not be one the store holds.
    pub fn set_read_position(
        &self,
        key: Key,
        room: Key,
        message: Option<Key>,
        at: Option<u64>,
    ) -> ReadPosition {
        let mut state = self.state();
        let position = state
            .read_positions
            .entry(key.clone())
            .or_insert_with(|| ReadPosition {
                key,
                room: room.clone(),
                message: None,
                at: None,
                ext: BTreeMap::new(),
            });
        position.room = room;
        position.message = message;
        position.at = at;
        let position = position.clone();
        drop(state);
        self.record([Change::ReadPositionMoved(position.key.clone())]);
        position
    }

    /// Forgets read position `key`.
    pub fn forget_read_position(&self, key: &str) -> Option<ReadPosition> {
        let position = self.state().read_positions.remove(key)?;
        self.record([Change::ReadPositionForgotten(key.to_owned())]);
        Some(position)
    }

    /// Allows `user`: their invites are joined from the next
    /// [`Store::sync`] under [`crate::InvitePolicy::FromAllowed`]
    /// (`Agent::allow`, a Consent/set `grant`).
    ///
    /// # Errors
    ///
    /// [`ActionError::Agent`] if the server refuses or cannot be reached.
    pub async fn allow(&self, user: &str) -> Result<(), ActionError> {
        self.agent.lock().await.allow(user).await?;
        // A pending invite from them is joined at the sync.
        self.want_sync();
        Ok(())
    }

    /// Refuses `user` (`Agent::deny`, a Consent/set `revoke`).
    ///
    /// # Errors
    ///
    /// As [`Store::allow`].
    pub async fn deny(&self, user: &str) -> Result<(), ActionError> {
        self.agent.lock().await.deny(user).await?;
        self.want_sync();
        Ok(())
    }

    /// Joins pending invite `number`, whatever the invite policy says
    /// (`Agent::join`), and returns the room's URI. The room's record and
    /// messages come with the next [`Store::sync`].
    ///
    /// # Errors
    ///
    /// [`ActionError::Agent`] if there is no such invite or joining fails.
    pub async fn accept_invite(&self, number: u64) -> Result<String, ActionError> {
        let uri = self.agent.lock().await.join(number)?;
        self.state().invites.retain(|i| i.number != number);
        self.record([Change::InviteGone(number)]);
        // The room's record and messages come with the sync.
        self.want_sync();
        Ok(uri)
    }
}
