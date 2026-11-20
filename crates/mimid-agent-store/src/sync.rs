//! [`Store::sync`]: what the agent received, written into the records
//! (docs/design/agent-frontends.md §2, §3 step 3).
//!
//! The store is the agent's only journal consumer. Each round of a sync
//! polls the agent, joins the invites [`InvitePolicy`] allows and the
//! user's rooms this device is not in, writes every event into the
//! records, mirrors the rooms' bans and the people's DIDs, hands the
//! changed records to the front end ([`Commit`]), which shows and saves
//! them, and only then acknowledges what the agent delivered: a message
//! cannot be decrypted again, and an event not acknowledged comes again
//! after a crash (a message already stored is skipped, and so is one
//! deleted here since: [`State::delete_message`] keeps a tombstone until
//! the next acknowledgement).
//!
//! - **Rooms**: every room the agent is in, and is not out of, has a
//!   record, with its participants, their role indexes and the room's
//!   role names as the agent reports them after the round's events.
//! - **People**: a person record per user URI, made when the user is
//!   first seen as a participant who is not banned, a sender, the subject
//!   of a notice, a holder of leaves, a banned user or a banner. Each
//!   person's did:webvh DID is set again whenever an active room's epoch
//!   moves ([`Store::sync`]).
//! - **Messages**: a received message is stored once per room and
//!   reference octets, with its first MIMI message ID; a reply resolves
//!   within the room. Edits and retractions change the message they name
//!   ([`replace`]). Attachments are fetched into the blob store, or kept
//!   for a retry ([`attachments`]).
//! - **Notices**: the identity-change and removed-without-AppDataUpdate
//!   notices are messages from [`Sender::Agent`], once per key
//!   ([`crate::notice`]).
//! - **Bans** ([`bans`]): every participant a room holds in its "banned"
//!   role has one ban record, and an expired ban is lifted.
//!
//! # Limitations
//!
//! - The sync holds the agent for its whole run, attachment fetches and
//!   the front end's commit included.
//! - The store does not save by itself: the front end's commit calls
//!   [`Store::save`] once it has shown the changes, so what the front end
//!   keeps in the records (`ext`) is saved with them.

use std::collections::BTreeMap;

use mimi_content::{ExternalPart, MessageId};
use mimid_agent_core::{Agent, AgentError, Event, ReceivedMessage, ReportedMessage, RoomStatus};

use crate::change::Change;
use crate::convert::{MessageRef, message_ref, sender_msg_id, topic_id};
use crate::notice::{identity_notice, notice_ref, removal_notice, removal_notice_ref};
use crate::record::{
    Key, Message, NoticeKind, Octets, Participant, Person, Reply, Room, RoomStatus as Status,
    Sender,
};
use crate::report::KeptFrank;
use crate::state::State;
use crate::store::Store;

pub mod attachments;
pub mod bans;
pub mod replace;

pub use attachments::MAX_ATTACHMENTS_PER_MESSAGE;
pub use replace::{MAX_ALIASES, MAX_EDIT_HISTORY};

/// Which pending invites [`Store::sync`] joins.
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

/// What one [`Store::sync`] did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct SyncReport {
    /// Messages stored.
    pub messages: usize,
    /// Rooms joined from invites.
    pub joined: Vec<String>,
    /// Invites left pending by the invite policy, by number.
    pub pending_invites: Vec<u64>,
    /// Edits and retractions applied to stored messages ([`replace`]).
    pub edits: usize,
    /// Received messages not stored, with why: neither text nor
    /// attachments, or an edit or retraction of a message not stored
    /// here or already retracted.
    pub skipped: Vec<String>,
    /// The agent's problems ([`Event::Problem`]), received attachments
    /// left out or waiting for a retry because they could not be fetched,
    /// opened or stored, and edits and retractions refused (not by the
    /// original sender), as text.
    pub problems: Vec<String>,
    /// Attachments fetched on a retry and added to their messages
    /// ([`crate::retry`]).
    pub attachments_retried: usize,
}

/// A failure of [`Store::sync`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SyncError<E> {
    /// The agent failed: the server could not be reached, or local state.
    /// Nothing is lost: the agent keeps what was not acknowledged.
    #[error(transparent)]
    Agent(#[from] AgentError),
    /// The front end's [`Commit`] failed; what the round delivered was
    /// not acknowledged.
    #[error(transparent)]
    Commit(E),
}

/// What a front end does with the records a sync round changed, before
/// the agent's delivery is acknowledged: show them, and save the store.
pub trait Commit {
    /// Why it failed.
    type Error;

    /// Shows `changes` ([`Change`]) and saves the store
    /// ([`Store::save`]); the records are read from [`Store::state`]. An
    /// error stops the sync before the round is acknowledged, so the agent
    /// delivers it again.
    fn commit(
        &self,
        changes: Vec<Change>,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send;
}

/// A room's participants with their roles, and its role names, read from
/// the agent.
pub(crate) struct RoomRoles {
    pub(crate) participants: Vec<(String, u32)>,
    pub(crate) names: Vec<(u32, String)>,
}

impl RoomRoles {
    /// Empty for a room the agent is not in.
    pub(crate) fn of(agent: &Agent, room: &str) -> Self {
        Self {
            participants: agent.participant_roles(room).unwrap_or_default(),
            names: agent.roles(room).unwrap_or_default(),
        }
    }

    /// The role index of `user`.
    fn role_of(&self, user: &str) -> Option<u32> {
        self.participants
            .iter()
            .find(|(u, _)| u == user)
            .map(|(_, r)| *r)
    }

    /// Whether `user` holds the role room-policy-04 §8.1.3 names
    /// "banned" (index 1).
    fn is_banned(&self, user: &str) -> bool {
        self.role_of(user).is_some_and(|index| {
            index == bans::BANNED_ROLE_INDEX
                && self
                    .names
                    .iter()
                    .any(|(i, name)| *i == index && name == "banned")
        })
    }

    /// `participants` as records, with their role indexes.
    fn participants(&self, participants: &[String]) -> Vec<Participant> {
        participants
            .iter()
            .map(|user| Participant {
                user: Some(user.clone()),
                role: self.role_of(user),
            })
            .collect()
    }

    fn names(&self) -> BTreeMap<u32, String> {
        self.names.iter().cloned().collect()
    }
}

/// Milliseconds since the UNIX epoch.
pub(crate) fn now_ms() -> u64 {
    crate::retry::now_secs().saturating_mul(1000)
}

impl Store {
    /// Polls the agent and writes what came into the records, then hands
    /// the changes to `commit` and acknowledges; see the module
    /// documentation. Joined rooms become room records, received text
    /// messages, membership changes participants. Pending invites are
    /// joined as the [`InvitePolicy`] allows, then the user's rooms this
    /// device is not in are joined by external Commit
    /// (`Agent::join_own_rooms`; decision mimid-1wgh.61). A round that
    /// joins is followed by one more, since a join's held messages come
    /// with the next poll. Last, attachments due for a retry are fetched,
    /// and committed if any changed.
    ///
    /// # Errors
    ///
    /// [`SyncError::Agent`] if polling fails, and [`SyncError::Commit`]
    /// if `commit` does. Either way nothing is lost: the agent keeps what
    /// it has not had acknowledged.
    pub async fn sync<C: Commit + Sync>(
        &self,
        commit: &C,
    ) -> Result<SyncReport, SyncError<C::Error>> {
        let mut agent = self.agent.lock().await;
        let mut report = SyncReport::default();
        let mut changes = Vec::new();
        self.expire_bans(&mut agent, &mut changes, &mut report.problems)
            .await;
        for _ in 0..2 {
            let (events, receipt) = agent.receive().await?;
            let mut joined = self.accept_invites(&mut agent, &mut report).await?;
            // This user's rooms that this device is not in yet: a new
            // device joins them by external Commit (decision
            // mimid-1wgh.61). After the invites, so a room this device
            // was invited to is joined from its Welcome.
            match agent.join_own_rooms().await {
                Ok(own) => {
                    joined += own.joined.len();
                    report.joined.extend(own.joined);
                    report.problems.extend(
                        own.failed
                            .into_iter()
                            .map(|(room, why)| format!("joining {room} from this device: {why}")),
                    );
                }
                Err(e) => report
                    .problems
                    .push(format!("listing this user's rooms: {e}")),
            }
            self.fill_roles(&agent);
            self.reconcile_rooms(&agent, &mut changes);
            let mut committers = bans::Committers::default();
            for event in events {
                if let Event::MembersChanged {
                    room, committer, ..
                } = &event
                {
                    committers.saw(room, committer.as_deref());
                }
                self.apply(&mut agent, event, &mut report, &mut changes)
                    .await;
            }
            self.mirror_bans(&agent, &committers, &mut changes);
            // A Commit or a join may bring or change a person's did_webvh
            // leaves.
            let epochs: BTreeMap<String, u64> = agent
                .rooms()
                .into_iter()
                .filter(|room| room.status != RoomStatus::Left)
                .filter_map(|room| agent.epoch(&room.uri).ok().map(|e| (room.uri, e)))
                .collect();
            let moved = {
                let mut last = self
                    .did_epochs
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let moved = *last != epochs;
                *last = epochs;
                moved
            };
            if moved {
                self.refresh_dids(&agent, None, &mut changes);
            }
            // Committed first, then acknowledged.
            commit
                .commit(std::mem::take(&mut changes))
                .await
                .map_err(SyncError::Commit)?;
            agent.acknowledge(receipt)?;
            // Every event that stored a message deleted since is
            // acknowledged now (receive returned all those not yet
            // acknowledged), so none of them comes again.
            self.state().clear_message_tombstones();
            if joined == 0 {
                break;
            }
        }
        if self
            .retry_attachments(&mut agent, &mut report, &mut changes)
            .await
        {
            commit.commit(changes).await.map_err(SyncError::Commit)?;
        }
        Ok(report)
    }

    /// Joins the pending invites the policy allows; returns how many. The
    /// rest are kept in [`State::invites`], refused.
    async fn accept_invites<E>(
        &self,
        agent: &mut Agent,
        report: &mut SyncReport,
    ) -> Result<usize, SyncError<E>> {
        let invites = agent.invites();
        if invites.is_empty() {
            self.state().invites.clear();
            return Ok(0);
        }
        let allowed: Vec<String> = match self.invites {
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
        let mut pending = Vec::new();
        for invite in invites {
            let inviter = agent.inviter(invite.number);
            let accept = match self.invites {
                InvitePolicy::Any => true,
                InvitePolicy::Never => false,
                InvitePolicy::FromAllowed => match &inviter {
                    Ok(inviter) => allowed.contains(inviter),
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
                pending.push(crate::record::Invite {
                    number: invite.number,
                    inviter: inviter.ok(),
                    refused: true,
                });
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
        self.state().invites = pending;
        Ok(joined)
    }

    /// Sets the participants, role indexes and role names of every room
    /// the agent is in whose record lacks them: one a front end made. Not a
    /// [`Change`]: the front end shows the same members.
    fn fill_roles(&self, agent: &Agent) {
        let active: Vec<String> = agent
            .rooms()
            .into_iter()
            .filter(|room| room.status == RoomStatus::Active)
            .map(|room| room.uri)
            .collect();
        let mut state = self.state();
        for uri in active {
            let Some(key) = state.room_of_uri(&uri).cloned() else {
                continue;
            };
            let Some(room) = state.rooms.get_mut(&key) else {
                continue;
            };
            let lacking = room.role_names.is_empty()
                || room.participants.is_empty()
                || room.participants.iter().any(|p| p.role.is_none());
            if !lacking {
                continue;
            }
            let Ok(participants) = agent.participants(&uri) else {
                continue;
            };
            let roles = RoomRoles::of(agent, &uri);
            room.participants = roles.participants(&participants);
            room.role_names = roles.names();
        }
    }

    /// Makes a record for every room the agent is in, and is not out of,
    /// that has none.
    fn reconcile_rooms(&self, agent: &Agent, changes: &mut Vec<Change>) {
        for room in agent.rooms() {
            if room.status != RoomStatus::Left {
                self.room_for(agent, &room.uri, changes);
            }
        }
    }

    /// The key of the record of room `uri`, made if there is none: named
    /// by the room's `room_name`, with its participants and roles. A
    /// person is made for each participant who is not the user and not
    /// banned.
    pub(crate) fn room_for(&self, agent: &Agent, uri: &str, changes: &mut Vec<Change>) -> Key {
        if let Some(key) = self.state().room_of_uri(uri) {
            return key.clone();
        }
        let name = agent.room_name(uri).ok().flatten();
        let participants = agent.participants(uri).unwrap_or_default();
        let roles = RoomRoles::of(agent, uri);
        let mut state = self.state();
        for user in &participants {
            if *user != self.user && !roles.is_banned(user) {
                self.person_for(&mut state, user, changes);
            }
        }
        let key = self.mint();
        state.insert_room(Room {
            key: key.clone(),
            uri: uri.to_owned(),
            name,
            status: Status::Active,
            participants: roles.participants(&participants),
            role_names: roles.names(),
            ext: BTreeMap::new(),
        });
        changes.push(Change::RoomAdded(key.clone()));
        key
    }

    /// The key of the person record of `user`, made if there is none.
    pub(crate) fn person_for(
        &self,
        state: &mut State,
        user: &str,
        changes: &mut Vec<Change>,
    ) -> Key {
        if let Some(key) = state.person_of_user(user) {
            return key.clone();
        }
        let key = self.mint();
        state.insert_person(Person {
            key: key.clone(),
            user: user.to_owned(),
            display_name: None,
            did: None,
            did_changed_at: None,
            first_seen: now_ms(),
            ext: BTreeMap::new(),
        });
        changes.push(Change::PersonAdded(key.clone()));
        key
    }

    async fn apply(
        &self,
        agent: &mut Agent,
        event: Event,
        report: &mut SyncReport,
        changes: &mut Vec<Change>,
    ) {
        match event {
            Event::IdentityChanged {
                room,
                user,
                pinned,
                presented,
            } => {
                let reference = notice_ref(&room, &user, &pinned, presented.as_deref());
                let kind = NoticeKind::IdentityChanged {
                    user: user.clone(),
                    pinned: pinned.clone(),
                    presented: presented.clone(),
                };
                self.store_notice(agent, &room, &user, reference, kind, changes, |name| {
                    identity_notice(name, &pinned, presented.as_deref())
                });
                self.refresh_dids(agent, Some((&user, presented.as_deref())), changes);
            }
            Event::RemovedWithoutAppDataUpdate { room, user, epoch } => {
                let reference = removal_notice_ref(&room, &user, epoch);
                let kind = NoticeKind::RemovedWithoutAppDataUpdate {
                    user: user.clone(),
                    epoch,
                };
                self.store_notice(
                    agent,
                    &room,
                    &user,
                    reference,
                    kind,
                    changes,
                    removal_notice,
                );
            }
            Event::Message(message) => {
                self.store_message(agent, *message, report, changes).await;
            }
            Event::MembersChanged {
                room, participants, ..
            } => self.set_participants(agent, &room, &participants, changes),
            Event::Left { room } => {
                let mut state = self.state();
                let Some(key) = state.room_of_uri(&room).cloned() else {
                    return;
                };
                if let Some(record) = state.rooms.get_mut(&key) {
                    record.status = Status::Left;
                    record
                        .participants
                        .retain(|p| p.user.as_deref() != Some(self.user.as_str()));
                }
                changes.push(Change::RoomLeft(key));
            }
            Event::Problem { room, description } => {
                report.problems.push(match room {
                    Some(room) => format!("{room}: {description}"),
                    None => description,
                });
            }
            // Invites are read from Agent::invites; proposals need nothing.
            _ => {}
        }
    }

    /// Sets the participants of room `uri` to `participants`, with their
    /// roles as the agent has them now. Always a [`Change::RoomChanged`]:
    /// the front end shows the members again, as it did before the store.
    fn set_participants(
        &self,
        agent: &Agent,
        uri: &str,
        participants: &[String],
        changes: &mut Vec<Change>,
    ) {
        let key = self.room_for(agent, uri, changes);
        let roles = RoomRoles::of(agent, uri);
        let mut state = self.state();
        for user in participants {
            if *user != self.user && !roles.is_banned(user) {
                self.person_for(&mut state, user, changes);
            }
        }
        if let Some(room) = state.rooms.get_mut(&key) {
            room.participants = roles.participants(participants);
            room.role_names = roles.names();
        }
        changes.push(Change::RoomChanged(key));
    }

    /// draft-atwood-mls-didwebvh-credential-01 §Reference Identifiers
    /// ("MUST alert the user if a contact's SCID changes"), bead
    /// mimid-1wgh.4.81.27, and bead mimid-4lp4.4: stores, in room `uri`, a
    /// notice of `kind` about `user`, its text `body` of the user's
    /// display name (or URI; "a member" for an empty `user`), sent by
    /// [`Sender::Agent`], keyed by `reference` ([`crate::notice`]), unless
    /// one is there already. An event the journal delivers again, or the
    /// same mismatch reported again at a later Commit, stores nothing
    /// more.
    #[allow(clippy::too_many_arguments)]
    fn store_notice(
        &self,
        agent: &Agent,
        uri: &str,
        user: &str,
        reference: MessageRef,
        kind: NoticeKind,
        changes: &mut Vec<Change>,
        body: impl FnOnce(&str) -> String,
    ) {
        let room = self.room_for(agent, uri, changes);
        let mut state = self.state();
        if state.message_of_ref(&room, &reference).is_some() || state.is_deleted(&room, &reference)
        {
            return;
        }
        let name = if user.is_empty() {
            "a member".to_owned()
        } else {
            let person = self.person_for(&mut state, user, changes);
            state
                .people
                .get(&person)
                .and_then(|p| p.display_name.clone())
                .filter(|name| !name.trim().is_empty())
                .unwrap_or_else(|| user.to_owned())
        };
        let at = now_ms();
        let mut random = [0u8; 16];
        random[6..].copy_from_slice(&reference);
        let key = self.mint();
        let seq = state.take_seq();
        state.insert_message(Message {
            key: key.clone(),
            room,
            seq,
            sender: Sender::Agent,
            mimi_id: None,
            aliases: Vec::new(),
            accepted_at: at,
            sender_msg_id: ulid::Ulid::from_parts(at, u128::from_be_bytes(random)).to_string(),
            body: body(&name),
            body_type: crate::content::BodyType::Plain,
            in_reply_to: None,
            topic_id: None,
            attachments: Vec::new(),
            edit_history: Vec::new(),
            edited_at: None,
            deleted: None,
            kept_frank: None,
            notice: Some(kind),
            ext: BTreeMap::new(),
        });
        changes.push(Change::MessageAdded(key));
    }

    /// Sets each person's `did` to the DID of their `did_webvh` leaves in
    /// the agent's active rooms (the head DID document's `id`, not the
    /// bare SCID), and clears it for a user seen only with BasicCredential
    /// leaves. A user absent from every room keeps what the record has.
    /// When the user's leaves present several DIDs, `changed` (a user and
    /// the SCID an [`Event::IdentityChanged`] reported) picks the DID with
    /// that SCID, so `did` changes when the identity notice goes out;
    /// otherwise the one the record has is kept, and failing that the
    /// first in order. Replacing or clearing a DID the record had also
    /// sets `did_changed_at` (draft-atwood-jmap-chat-did-00 §DID changes);
    /// a first binding does not.
    pub(crate) fn refresh_dids(
        &self,
        agent: &Agent,
        changed: Option<(&str, Option<&str>)>,
        changes: &mut Vec<Change>,
    ) {
        // user -> (SCID, DID) of its did_webvh leaves; Basic-only users map
        // to an empty list.
        let mut seen: BTreeMap<String, Vec<(String, String)>> = BTreeMap::new();
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
        let mut state = self.state();
        for (user, mut dids) in seen {
            dids.sort();
            let key = self.person_for(&mut state, &user, changes);
            let Some(person) = state.people.get_mut(&key) else {
                continue;
            };
            let current = person.did.clone();
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
            if current.is_some() {
                person.did_changed_at = Some(now_ms());
            }
            person.did = wanted;
            changes.push(Change::PersonChanged(key));
        }
    }

    /// Stores a received message (draft-atwood-jmap-chat-mimi-00
    /// §Message Identifiers, §Senders, §Topics), or applies it to the
    /// message it replaces ([`replace`]).
    async fn store_message(
        &self,
        agent: &mut Agent,
        received: ReceivedMessage,
        report: &mut SyncReport,
        changes: &mut Vec<Change>,
    ) {
        let room = self.room_for(agent, &received.room, changes);
        let reference = message_ref(&received.message_id);
        {
            let state = self.state();
            if state.message_of_ref(&room, &reference).is_some()
                || state.is_deleted(&room, &reference)
            {
                return;
            }
        }
        if let Some(replaces) = &received.content.replaces {
            self.apply_replacement(&room, replaces, &received, report, changes);
            return;
        }
        let parts = received.attachments();
        let text = match received.text.clone() {
            Some(text) => text,
            None if !parts.is_empty() => String::new(),
            None => {
                report
                    .skipped
                    .push(format!("{}: neither text nor attachments", received.room));
                return;
            }
        };
        let (attachments, retry) = self
            .fetch_attachments(agent, &received.room, &parts, report)
            .await;
        let kept_frank = keep_reportable(&received, report);
        let content = &received.content;
        let mut state = self.state();
        if received.sender != self.user {
            self.person_for(&mut state, &received.sender, changes);
        }
        let in_reply_to = content.in_reply_to.as_ref().map(|id| {
            let target = message_ref(id);
            match state.message_of_ref(&room, &target) {
                Some(key) => Reply::Message(key.clone()),
                None => Reply::Reference(Octets(target)),
            }
        });
        let key = self.mint();
        let seq = state.take_seq();
        state.insert_message(Message {
            key: key.clone(),
            room,
            seq,
            sender: Sender::User(received.sender.clone()),
            mimi_id: Some(Octets(received.message_id.0)),
            aliases: Vec::new(),
            accepted_at: received.accepted_at,
            sender_msg_id: sender_msg_id(received.accepted_at, &received.message_id),
            body: text,
            body_type: crate::content::body_type(content),
            in_reply_to,
            topic_id: topic_id(&content.topic_id),
            attachments,
            edit_history: Vec::new(),
            edited_at: None,
            deleted: None,
            kept_frank,
            notice: None,
            ext: BTreeMap::new(),
        });
        changes.push(Change::MessageAdded(key.clone()));
        keep_for_retry(&mut state, &key, &received.room, retry, report);
        report.messages += 1;
    }
}

/// What a report of `received` needs: its frank and content, or its
/// content alone if it has no frank (decisions mimid-1wgh.59,
/// mimid-1wgh.60). `None`, with a problem in `report`, if it cannot be
/// encoded.
pub(crate) fn keep_reportable(
    received: &ReceivedMessage,
    report: &mut SyncReport,
) -> Option<KeptFrank> {
    use mimid_agent_core::frank::{encode_abusive_message, encode_unverified_message};
    let (encoded, unverified) = match received.reported_message() {
        ReportedMessage::Franked(message) => (encode_abusive_message(&message), false),
        ReportedMessage::Unfranked(message) => (encode_unverified_message(&message), true),
        // ReportedMessage is #[non_exhaustive]; nothing else exists.
        _ => return None,
    };
    match encoded {
        Ok(bytes) => Some(KeptFrank {
            room: received.room.clone(),
            message: crate::blobs::hex(&bytes),
            unverified,
        }),
        // Not for a message that was decoded; kept as a problem, not an
        // error, since the message itself is stored.
        Err(e) => {
            report.problems.push(format!(
                "{}: a message was not kept for reports, so it cannot be reported: {e}",
                received.room
            ));
            None
        }
    }
}

/// Keeps `failed`, attachments of message `message` in room `room`, for
/// retry; past [`crate::retry::MAX_PENDING`] they are given up.
fn keep_for_retry(
    state: &mut State,
    message: &str,
    room: &str,
    failed: Vec<(u32, ExternalPart)>,
    report: &mut SyncReport,
) {
    for (number, part) in failed {
        if state.pending_attachments.len() >= crate::retry::MAX_PENDING {
            report.problems.push(format!(
                "{room}: attachment {number} left out: too many attachments waiting for retry"
            ));
            continue;
        }
        state
            .pending_attachments
            .push(crate::retry::PendingAttachment::new(
                message.to_owned(),
                room.to_owned(),
                number,
                &part,
            ));
    }
}

/// The reference octets of `id`, as kept in a record.
pub(crate) fn alias_of(id: &MessageId) -> Octets<10> {
    Octets(message_ref(id))
}

#[cfg(test)]
mod tests {
    use std::future::Future;

    use super::*;

    struct Nothing;

    impl Commit for Nothing {
        type Error = std::convert::Infallible;

        async fn commit(&self, _changes: Vec<Change>) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    /// A daemon runs `sync` in a spawned task, which needs a `Send` future:
    /// holding `&Agent` or the state lock across an await does not give
    /// one. A compile-time check.
    #[test]
    fn the_sync_future_is_send() {
        fn sync_of<'a>(
            store: &'a Store,
            commit: &'a Nothing,
        ) -> impl Future<Output = Result<SyncReport, SyncError<std::convert::Infallible>>> + Send + 'a
        {
            store.sync(commit)
        }
        let _ = sync_of;
    }
}
