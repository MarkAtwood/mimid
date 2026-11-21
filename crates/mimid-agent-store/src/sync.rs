//! [`Store::sync`]: what the agent received, written into the records
//! (docs/design/agent-frontends.md §2, §3 step 3).
//!
//! The store is the agent's only journal consumer. Each round of a sync
//! polls the agent, joins the invites [`InvitePolicy`] allows and the
//! user's rooms this device is not in, writes every event into the
//! records, mirrors the rooms' bans and the people's DIDs, records what
//! changed ([`Change`]), saves ([`Store::save`]: every front end is handed
//! the changes and shows them, then the records are written and the
//! changes published), acknowledging what the agent delivered in the
//! transaction that writes the records (`Agent::acknowledge_in`; bead
//! mimid-1vul.10): a message cannot be decrypted again, so the records of
//! a delivery and its acknowledgement commit together, or neither does
//! and the delivery comes again (a message already stored is skipped, and
//! so is one deleted here since: [`State::delete_message`] keeps a
//! tombstone until the next acknowledgement).
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
//!   for a retry ([`attachments`]). A part of disposition `session` is a
//!   call to join, kept in the message as a [`crate::record::Call`] and
//!   never fetched (docs/design/agent-frontends.md §7.24).
//! - **Notices**: the identity-change and removed-without-AppDataUpdate
//!   notices are messages from [`Sender::Agent`], once per key
//!   ([`crate::notice`]).
//! - **Bans** ([`bans`]): every participant a room holds in its "banned"
//!   role has one ban record, and an expired ban is lifted.
//! - **Rooms deleted here** ([`Store::forget_room`]; docs/design/agent-frontends.md
//!   §7.9): while a room's tombstone is kept, no record is made for it
//!   and its events are dropped, messages and notices included. The
//!   tombstone goes once a round that found the agent out of the room is
//!   acknowledged, or at once when the agent is in the room again.
//!
//! # Limitations
//!
//! - The sync holds the agent for its whole run, attachment fetches and
//!   the save (with every front end's part in it) included.
//! - Events of a room deleted here and joined again before an earlier
//!   delivery of it was acknowledged (a failed save, then a new invite
//!   accepted) are stored in the new record.
//! - The save has every front end show the changes and bring its `ext` up
//!   to date first ([`crate::Frontend`]), so what a front end keeps in the
//!   records is saved with them.
//! - The tombstones count on this being the only caller of
//!   `Agent::receive`, `Agent::acknowledge` and `Agent::acknowledge_in`.

use std::collections::BTreeMap;

use mimi_content::{ExternalPart, MessageId};
use mimid_agent_core::{Agent, AgentError, Event, ReceivedMessage, ReportedMessage, RoomStatus};

use crate::change::Change;
use crate::convert::{MessageRef, message_ref, sender_msg_id, topic_id};
use crate::notice::{
    identity_notice, lost_notice, lost_notice_ref, notice_ref, removal_notice, removal_notice_ref,
};
use crate::record::{
    Call, Key, Message, NoticeKind, Octets, Participant, Person, Reply, Room, RoomStatus as Status,
    Sender, SubjectSet,
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
pub enum SyncError {
    /// The agent failed: the server could not be reached, or local state.
    /// Nothing is lost: the agent keeps what was not acknowledged.
    #[error(transparent)]
    Agent(#[from] AgentError),
    /// The save failed: a front end could not show the changes
    /// ([`crate::FileError::Frontend`]), or the records could not be
    /// written. What the round delivered was not acknowledged.
    #[error(transparent)]
    Save(crate::db::FileError),
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
    pub(crate) fn participants(&self, participants: &[String]) -> Vec<Participant> {
        participants
            .iter()
            .map(|user| Participant {
                user: user.clone(),
                role: self.role_of(user),
            })
            .collect()
    }

    pub(crate) fn names(&self) -> BTreeMap<u32, String> {
        self.names.iter().cloned().collect()
    }
}

/// Milliseconds since the UNIX epoch, to the millisecond: a message's
/// arrival time (docs/design/agent-frontends.md §7.18) is compared with
/// the hub's acceptance time, which has milliseconds.
pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

impl Store {
    /// Polls the agent and writes what came into the records, then saves,
    /// which publishes the changes, and acknowledges; see the module
    /// documentation. Joined rooms become room records, received text
    /// messages, membership changes participants. Pending invites are
    /// joined as the [`InvitePolicy`] allows, then the user's rooms this
    /// device is not in are joined by external Commit
    /// (`Agent::join_own_rooms`; decision mimid-1wgh.61). A round that
    /// joins is followed by one more, since a join's held messages come
    /// with the next poll. Last, attachments due for a retry are fetched,
    /// and saved if any changed.
    ///
    /// # Errors
    ///
    /// [`SyncError::Agent`] if polling fails, and [`SyncError::Save`] if
    /// the save does. Either way nothing is lost: the agent keeps what it
    /// has not had acknowledged.
    pub async fn sync(&self) -> Result<SyncReport, SyncError> {
        let mut agent = self.agent.lock().await;
        let mut report = SyncReport::default();
        let mut changes = Vec::new();
        self.expire_bans(&mut agent, &mut changes, &mut report.problems)
            .await;
        for _ in 0..2 {
            let (events, receipt) = agent.receive().await?;
            let settled = self.settle_forgotten_rooms(&agent);
            let mut joined = self
                .accept_invites(&mut agent, &mut report, &mut changes)
                .await?;
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
            // Shown, then saved and acknowledged in one transaction.
            self.record(std::mem::take(&mut changes));
            self.save_acknowledging(Some((&mut agent, receipt)))
                .await
                .map_err(SyncError::Save)?;
            // Every event that stored a message deleted since is
            // acknowledged now (receive returned all those not yet
            // acknowledged), so none of them comes again.
            {
                let mut state = self.state();
                state.clear_message_tombstones();
                state.clear_room_tombstones(&settled);
            }
            if joined == 0 {
                break;
            }
        }
        if self
            .retry_attachments(&mut agent, &mut report, &mut changes)
            .await
        {
            self.record(changes);
            self.save().await.map_err(SyncError::Save)?;
        }
        Ok(report)
    }

    /// Joins the pending invites the policy allows; returns how many. The
    /// rest are kept in [`State::invites`], refused.
    async fn accept_invites(
        &self,
        agent: &mut Agent,
        report: &mut SyncReport,
        changes: &mut Vec<Change>,
    ) -> Result<usize, SyncError> {
        let invites = agent.invites();
        if invites.is_empty() {
            self.set_invites(Vec::new(), changes);
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
            // One staging gives the inviter and the room's URI and name,
            // which a front end shows the invite under (bead mimid-br6m).
            let details = agent.invite_details(invite.number);
            let accept = match self.invites {
                InvitePolicy::Any => true,
                InvitePolicy::Never => false,
                InvitePolicy::FromAllowed => match &details {
                    Ok(details) => allowed.contains(&details.inviter),
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
                let details = details.ok();
                pending.push(crate::record::Invite {
                    number: invite.number,
                    inviter: details.as_ref().map(|d| d.inviter.clone()),
                    room: details.as_ref().and_then(|d| d.room.clone()),
                    room_name: details.and_then(|d| d.room_name),
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
        self.set_invites(pending, changes);
        Ok(joined)
    }

    /// Replaces the pending invites with `pending`: an
    /// [`Change::InvitePending`] for each new one, an
    /// [`Change::InviteGone`] for each one gone.
    fn set_invites(&self, pending: Vec<crate::record::Invite>, changes: &mut Vec<Change>) {
        let mut state = self.state();
        let had = |list: &[crate::record::Invite], number| list.iter().any(|i| i.number == number);
        for invite in &pending {
            if !had(&state.invites, invite.number) {
                changes.push(Change::InvitePending(invite.number));
            }
        }
        for invite in &state.invites {
            if !had(&pending, invite.number) {
                changes.push(Change::InviteGone(invite.number));
            }
        }
        state.invites = pending;
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

    /// Settles the tombstones of rooms deleted here
    /// (docs/design/agent-frontends.md §7.9), right after the agent's
    /// delivery was read. A room the agent is active in again was joined
    /// again (a new invite, or [`Store::forget_room`] without leaving): its
    /// tombstone goes now, so the round stores its events. A room the
    /// agent is out of, or does not know, can send nothing more: every
    /// event of it is in this delivery or acknowledged before, so its
    /// tombstone may go once this round is acknowledged; those are
    /// returned. A room still being left keeps its tombstone.
    fn settle_forgotten_rooms(&self, agent: &Agent) -> Vec<String> {
        let forgotten = self.state().forgotten_rooms();
        if forgotten.is_empty() {
            return forgotten;
        }
        let rooms = agent.rooms();
        let status = |uri: &str| rooms.iter().find(|r| r.uri == uri).map(|r| r.status);
        let (mut rejoined, mut settled) = (Vec::new(), Vec::new());
        for uri in forgotten {
            match status(&uri) {
                Some(RoomStatus::Active) => rejoined.push(uri),
                Some(RoomStatus::Leaving) => {}
                _ => settled.push(uri),
            }
        }
        self.state().clear_room_tombstones(&rejoined);
        settled
    }

    /// Makes a record for every room the agent is in, and is not out of,
    /// that has none, unless it was deleted here. A record that is leaving
    /// or left, of a room the agent is active in, was joined again (a new
    /// invite): it becomes active, with the room's participants and roles
    /// as they are now (bead mimid-bmtk). An active record of a room the
    /// agent is leaving becomes leaving.
    fn reconcile_rooms(&self, agent: &Agent, changes: &mut Vec<Change>) {
        for room in agent.rooms() {
            if room.status == RoomStatus::Left {
                continue;
            }
            let Some(key) = self.room_for(agent, &room.uri, changes) else {
                continue;
            };
            if room.status == RoomStatus::Active {
                self.rejoined(agent, &key, &room.uri, changes);
            } else if room.status == RoomStatus::Leaving {
                // A leave the agent finished from its outbox (after a crash,
                // or a lost answer) while Store::leave returned an error
                // (docs/design/agent-frontends.md §7.19).
                let mut state = self.state();
                if let Some(record) = state.rooms.get_mut(&key)
                    && record.status == Status::Active
                {
                    record.status = Status::Leaving;
                    changes.push(Change::RoomLeft(key.clone()));
                }
            }
        }
    }

    /// Makes record `key` of room `uri`, which the agent is active in,
    /// active again if it is not, with its participants and roles, a person made for each participant who
    /// is not the user and not banned, and a [`Change::RoomChanged`].
    fn rejoined(&self, agent: &Agent, key: &str, uri: &str, changes: &mut Vec<Change>) {
        let inactive = self
            .state()
            .rooms
            .get(key)
            .is_some_and(|room| room.status != Status::Active);
        if !inactive {
            return;
        }
        let participants = agent.participants(uri).unwrap_or_default();
        let roles = RoomRoles::of(agent, uri);
        let mut state = self.state();
        for user in &participants {
            if *user != self.user && !roles.is_banned(user) {
                self.person_for(&mut state, user, changes);
            }
        }
        if let Some(room) = state.rooms.get_mut(key) {
            room.status = Status::Active;
            room.participants = roles.participants(&participants);
            room.role_names = roles.names();
            changes.push(Change::RoomChanged(key.to_owned()));
        }
    }

    /// The key of the record of room `uri`, made if there is none: named
    /// by the room's `room_name`, with its participants and roles. A
    /// person is made for each participant who is not the user and not
    /// banned. `None` for a room deleted here ([`State::is_forgotten`]),
    /// whose events are dropped.
    pub(crate) fn room_for(
        &self,
        agent: &Agent,
        uri: &str,
        changes: &mut Vec<Change>,
    ) -> Option<Key> {
        {
            let state = self.state();
            if let Some(key) = state.room_of_uri(uri) {
                return Some(key.clone());
            }
            if state.is_forgotten(uri) {
                return None;
            }
        }
        let name = agent.room_name(uri).ok().flatten();
        let subject = agent.room_subject(uri).ok().flatten();
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
            subject,
            subject_set: None,
            status: Status::Active,
            participants: roles.participants(&participants),
            role_names: roles.names(),
            message_expiry_seconds: None,
            ext: BTreeMap::new(),
        });
        changes.push(Change::RoomAdded(key.clone()));
        Some(key)
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
            Event::MessagesLost { room, from, to } => {
                let reference = lost_notice_ref(&room, to);
                let kind = NoticeKind::MessagesLost { from, to };
                self.store_notice(agent, &room, "", reference, kind, changes, |_| {
                    lost_notice(from, to)
                });
            }
            // A message this device sent is stored as a received one: a
            // record of it that Store::send made already has its MIMI
            // message ID, so it is not stored twice.
            Event::Message(message) => {
                self.store_message(agent, *message, false, report, changes)
                    .await;
            }
            Event::Sent(message) => {
                self.store_message(agent, *message, true, report, changes)
                    .await;
            }
            Event::MembersChanged {
                room, participants, ..
            } => self.set_participants(agent, &room, &participants, changes),
            Event::Left { room } => {
                // A room the agent is active in again was joined again
                // after this event (bead mimid-bmtk).
                let active = agent
                    .rooms()
                    .iter()
                    .any(|r| r.uri == room && r.status == RoomStatus::Active);
                if active {
                    return;
                }
                let mut state = self.state();
                let Some(key) = state.room_of_uri(&room).cloned() else {
                    return;
                };
                if let Some(record) = state.rooms.get_mut(&key) {
                    record.status = Status::Left;
                    record.participants.retain(|p| p.user != self.user);
                }
                changes.push(Change::RoomLeft(key));
            }
            Event::RoomMetadataChanged {
                room,
                committer,
                accepted_at,
            } => self.set_metadata(agent, &room, committer, accepted_at, changes),
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
        let Some(key) = self.room_for(agent, uri, changes) else {
            return;
        };
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

    /// Reads the name and subject of room `uri` again after a Commit by
    /// `committer`, accepted at `accepted_at`, changed its room metadata;
    /// a changed subject records who set it and when. A
    /// [`Change::RoomChanged`] if either changed. A room the agent is no
    /// longer in keeps what it had.
    fn set_metadata(
        &self,
        agent: &Agent,
        uri: &str,
        committer: Option<String>,
        accepted_at: u64,
        changes: &mut Vec<Change>,
    ) {
        let Some(key) = self.room_for(agent, uri, changes) else {
            return;
        };
        let (Ok(name), Ok(subject)) = (agent.room_name(uri), agent.room_subject(uri)) else {
            return;
        };
        let mut state = self.state();
        let Some(room) = state.rooms.get_mut(&key) else {
            return;
        };
        if room.name == name && room.subject == subject {
            return;
        }
        if room.subject != subject {
            room.subject_set = Some(SubjectSet {
                by: committer,
                at: accepted_at,
            });
        }
        room.name = name;
        room.subject = subject;
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
        let Some(room) = self.room_for(agent, uri, changes) else {
            return;
        };
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
            received_at: at,
            sender_msg_id: ulid::Ulid::from_parts(at, u128::from_be_bytes(random)).to_string(),
            body: body(&name),
            body_type: crate::content::BodyType::Plain,
            in_reply_to: None,
            topic_id: None,
            attachments: Vec::new(),
            calls: Vec::new(),
            edit_history: Vec::new(),
            edited_at: None,
            deleted: None,
            kept_frank: None,
            notice: Some(kind),
            expiry: Default::default(),
            read_at: None,
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
            if room.status == RoomStatus::Left || self.state().is_forgotten(&room.uri) {
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
    /// message it replaces ([`replace`]). `sent_here`: this device sent
    /// it (`Event::Sent`), so it arrived when the hub accepted it; any
    /// other message arrives now (docs/design/agent-frontends.md §7.18).
    async fn store_message(
        &self,
        agent: &mut Agent,
        received: ReceivedMessage,
        sent_here: bool,
        report: &mut SyncReport,
        changes: &mut Vec<Change>,
    ) {
        let Some(room) = self.room_for(agent, &received.room, changes) else {
            return;
        };
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
        // docs/design/agent-frontends.md §7.20, §7.22; decision
        // mimid-1wgh.2.19: the agent checks expiry sanity.
        let expiry = match crate::expiry::received(&received.content, now_ms()) {
            crate::expiry::Received::Expiry(expiry, problem) => {
                report
                    .problems
                    .extend(problem.map(|p| format!("{}: {p}", received.room)));
                expiry
            }
            crate::expiry::Received::Discard(why) => {
                tracing::warn!(
                    name: "agent_message_discarded",
                    room = %received.room,
                    reason = %why,
                    "a received message was discarded"
                );
                report
                    .problems
                    .push(format!("{}: a message was discarded: {why}", received.room));
                return;
            }
        };
        // draft-atwood-jmap-chat-00 §Message `senderExpiresAt`: "Servers
        // MUST reject a `senderExpiresAt` value that is already in the past
        // at delivery time." Not stored; a delivery of it again finds it
        // past as well.
        if expiry.sender_expires_at.is_some_and(|at| at <= now_ms()) {
            report.skipped.push(format!(
                "{}: a message whose expiry had passed",
                received.room
            ));
            return;
        }
        // Session parts are calls to join, never fetched (mimi-content-10
        // §5.10; docs/design/agent-frontends.md §7.24); attachments()
        // leaves them out.
        let parts = received.attachments();
        let calls = calls_of(&received, report);
        let text = match received.text.clone() {
            Some(text) => text,
            None if !parts.is_empty() || !calls.is_empty() => String::new(),
            None => {
                report.skipped.push(format!(
                    "{}: neither text nor attachments nor a call",
                    received.room
                ));
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
        let expiring = !expiry.is_none()
            || state
                .rooms
                .get(&room)
                .is_some_and(|r| r.message_expiry_seconds.is_some());
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
            received_at: if sent_here {
                received.accepted_at
            } else {
                now_ms()
            },
            sender_msg_id: sender_msg_id(received.accepted_at, &received.message_id),
            body: text,
            body_type: crate::content::body_type(content),
            in_reply_to,
            topic_id: topic_id(&content.topic_id),
            attachments,
            calls,
            edit_history: Vec::new(),
            edited_at: None,
            deleted: None,
            kept_frank,
            notice: None,
            expiry,
            read_at: None,
            ext: BTreeMap::new(),
        });
        changes.push(Change::MessageAdded(key.clone()));
        keep_for_retry(&mut state, &key, &received.room, retry, report);
        report.messages += 1;
        if expiring {
            drop(state);
            self.want_expiry();
        }
    }
}

/// The calls to join of `received` ([`crate::content::call_of`]), at most
/// [`crate::content::MAX_CALLS_PER_MESSAGE`]; a session part that names
/// no call, and each past the limit, is a problem in `report`.
fn calls_of(received: &ReceivedMessage, report: &mut SyncReport) -> Vec<Call> {
    let mut calls = Vec::new();
    for part in received.session_parts() {
        match crate::content::call_of(part) {
            Some(_) if calls.len() >= crate::content::MAX_CALLS_PER_MESSAGE => {
                report.problems.push(format!(
                    "{}: a call past the first {} left out",
                    received.room,
                    crate::content::MAX_CALLS_PER_MESSAGE
                ));
            }
            Some(call) => calls.push(call),
            None => report.problems.push(format!(
                "{}: a session part that names no URL left out",
                received.room
            )),
        }
    }
    calls
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

    /// A daemon runs `sync` in a spawned task, which needs a `Send` future:
    /// holding `&Agent` or the state lock across an await does not give
    /// one. A compile-time check.
    #[test]
    fn the_sync_future_is_send() {
        fn sync_of(
            store: &Store,
        ) -> impl Future<Output = Result<SyncReport, SyncError>> + Send + '_ {
            store.sync()
        }
        let _ = sync_of;
    }
}
