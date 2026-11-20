//! Bans at each sync (decision mimid-1wgh.62 item 13; bead mimid-cqof):
//! every participant an active room holds in its "banned" role (role 1)
//! has one ban record in that room, and a ban whose user no longer holds
//! that role is removed. The participant list does not say who banned a
//! user, so a new ban's `banned_by` comes from the Commits the sync read
//! for the room: when they all have the same committer, the ban is that
//! committer's. Otherwise the banner is not known and `banned_by` is the
//! user's own URI: a ban from before this device joined, one read in the
//! same sync as another member's Commit to the room, or one read back from
//! a journal entry older than the committer. INVENTED, NOT FROM SPEC. A
//! mirrored ban has no reason.
//!
//! A ban whose `expires_at` has passed is lifted (draft-atwood-jmap-chat-00
//! §ChatBan: "the server MUST lift it"): the user is unbanned in the room
//! if the room still holds them banned, and the record is removed.
//!
//! # Limitations
//!
//! - A mirrored ban whose banner is not known names the user as banner,
//!   though the user may not have banned anyone.
//! - An expired ban the hub refuses to lift (the user lost `canUnban`)
//!   stays, and each sync reports it in [`super::SyncReport::problems`].

use std::collections::BTreeMap;

use mimid_agent_core::{Agent, RoomStatus};

use crate::change::Change;
use crate::record::Ban;
use crate::store::Store;

/// room-policy-04 §8.1.3: the "banned" role's index.
pub const BANNED_ROLE_INDEX: u32 = 1;

/// The users that `room` holds in its "banned" role, or `None` when the
/// agent cannot read the room's participant list.
#[must_use]
pub fn banned_users(agent: &Agent, room: &str) -> Option<Vec<String>> {
    let participants = agent.participant_roles(room).ok()?;
    let banned_named = agent
        .roles(room)
        .ok()?
        .iter()
        .any(|(index, name)| *index == BANNED_ROLE_INDEX && name == "banned");
    if !banned_named {
        return Some(Vec::new());
    }
    Some(
        participants
            .into_iter()
            .filter(|(_, role)| *role == BANNED_ROLE_INDEX)
            .map(|(user, _)| user)
            .collect(),
    )
}

/// The committers of the Commits one sync read, per room: a room's entry
/// is its committer when every Commit read for it had the same known one,
/// and `None` otherwise (bead mimid-cqof).
#[derive(Debug, Default)]
pub(crate) struct Committers(BTreeMap<String, Option<String>>);

impl Committers {
    /// Records a Commit to `room` by `committer` (`None`: not known).
    pub(crate) fn saw(&mut self, room: &str, committer: Option<&str>) {
        let committer = committer.map(str::to_owned);
        self.0
            .entry(room.to_owned())
            .and_modify(|seen| {
                if *seen != committer {
                    *seen = None;
                }
            })
            .or_insert(committer);
    }

    /// The one committer of every Commit read for `room`, if known.
    fn of(&self, room: &str) -> Option<&str> {
        self.0.get(room).and_then(Option::as_deref)
    }
}

impl Store {
    /// Each participant an active room holds banned has one ban record in
    /// it, and no one else has one (see the module documentation).
    pub(crate) fn mirror_bans(
        &self,
        agent: &Agent,
        committers: &Committers,
        changes: &mut Vec<Change>,
    ) {
        for room in agent.rooms() {
            if room.status != RoomStatus::Active {
                continue;
            }
            let Some(banned) = banned_users(agent, &room.uri) else {
                continue;
            };
            let mut state = self.state();
            let Some(key) = state.room_of_uri(&room.uri).cloned() else {
                continue;
            };
            for user in &banned {
                self.person_for(&mut state, user, changes);
            }
            let lifted: Vec<String> = state
                .bans
                .values()
                .filter(|b| b.room == key)
                .filter(|b| !banned.contains(&b.user))
                .map(|b| b.key.clone())
                .collect();
            for ban in lifted {
                state.bans.remove(&ban);
                changes.push(Change::BanLifted(ban));
            }
            let new: Vec<&String> = banned
                .iter()
                .filter(|user| {
                    !state
                        .bans
                        .values()
                        .any(|b| b.room == key && b.user == **user)
                })
                .collect();
            if new.is_empty() {
                continue;
            }
            let banned_by = match committers.of(&room.uri) {
                Some(committer) if committer != self.user => {
                    self.person_for(&mut state, committer, changes);
                    committer.to_owned()
                }
                _ => self.user.clone(),
            };
            for user in new {
                let ban = self.mint();
                state.bans.insert(
                    ban.clone(),
                    Ban {
                        key: ban.clone(),
                        room: key.clone(),
                        user: user.clone(),
                        banned_by: banned_by.clone(),
                        reason: None,
                        expires_at: None,
                        ext: BTreeMap::new(),
                    },
                );
                changes.push(Change::BanAdded(ban));
            }
        }
    }

    /// Lifts every ban whose `expires_at` has passed; one that cannot be
    /// lifted is reported in `problems` and kept.
    pub(crate) async fn expire_bans(
        &self,
        agent: &mut Agent,
        changes: &mut Vec<Change>,
        problems: &mut Vec<String>,
    ) {
        let now = crate::retry::now_secs();
        let expired: Vec<Ban> = self
            .state()
            .bans
            .values()
            .filter(|b| b.expires_at.is_some_and(|t| t / 1000 <= now))
            .cloned()
            .collect();
        for ban in expired {
            if let Err(e) = self.lift_ban(agent, &ban).await {
                problems.push(format!("lifting the expired ChatBan {}: {e}", ban.key));
                continue;
            }
            self.state().bans.remove(&ban.key);
            changes.push(Change::BanLifted(ban.key));
        }
    }

    /// Unbans the user of `ban` in its room if the room still holds them
    /// banned. A ban the room no longer holds (the room left, the user
    /// unbanned or removed elsewhere) needs nothing. The record is left to
    /// the caller.
    ///
    /// # Errors
    ///
    /// The agent's, if the unban fails.
    pub async fn lift_ban(
        &self,
        agent: &mut Agent,
        ban: &Ban,
    ) -> Result<(), mimid_agent_core::AgentError> {
        let room = self.state().rooms.get(&ban.room).map(|r| r.uri.clone());
        if let Some(room) = room
            && banned_users(agent, &room).is_some_and(|banned| banned.contains(&ban.user))
        {
            agent.unban(&room, &ban.user).await?;
        }
        Ok(())
    }
}
