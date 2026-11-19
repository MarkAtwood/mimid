//! Kicking, banning and unbanning from a JMAP Chat client
//! (draft-atwood-jmap-chat-mimi-00 §Moderation at jmap-chat-spec 516c61b;
//! beads mimid-90cd, mimid-1t3p; decision mimid-1wgh.62). Removing a
//! member and changing its role are `Chat/set` `removeMembers` and
//! `updateMemberRoles` (see the crate documentation).
//!
//! - **`ChatBan/set` create** (draft-atwood-jmap-chat-00 §ChatBan) on a
//!   Chat bound to a room is `Agent::ban`: one Commit that gives the user
//!   the room's "banned" role and removes all its clients (room-policy-04
//!   §8.1.3 `canBan`). Once the hub accepts it, the ChatBan is stored and
//!   the user leaves the Chat's `members`.
//! - **`ChatBan/set` destroy** is `Agent::unban`: the user gets the member
//!   role again and no client is added (`canUnban`). The user's devices
//!   do not come back by themselves (see `Agent::unban`). Since `members`
//!   mirrors the participant list, the user shows in `members` again at
//!   the next sync, as a member without clients.
//! - **`ChatBan/set` update** of `reason` or `expiresAt` changes only this
//!   account: MIMI has no field for either.
//! - **`expiresAt`**: [`AgentChat::sync`] lifts a ban whose `expiresAt` has
//!   passed, as a destroy does (draft-atwood-jmap-chat-00 §ChatBan: "the
//!   server MUST lift it").
//! - **`Chat/set` `kickMembers`** (draft-atwood-jmap-chat-mimi-00
//!   §Moderation) is `Agent::kick` for each listed user: their clients
//!   leave the group and they stay in the participant list (`canKick`).
//!   `members` does not change.
//! - **Bans made elsewhere**: at each sync, every participant that an
//!   active room holds in its "banned" role (role 1) has one ChatBan in
//!   the room's Chat, and a ChatBan whose user no longer holds that role
//!   is destroyed. The participant list does not say who banned a user,
//!   so a new ChatBan's `bannedBy` comes from the Commits this sync read
//!   for the room (bead mimid-cqof; decision mimid-1wgh.62 item 13): when
//!   they all have the same committer, the ban is that committer's, and
//!   `bannedBy` is its ChatContact id, or the accountId when the
//!   committer is the owner (another device of the owner, or this one).
//!   Otherwise the banner is not known and `bannedBy` is the accountId,
//!   as before: a ban from before this device joined, one read in the
//!   same sync as another member's Commit to the room, or one read back
//!   from a journal entry older than the committer. INVENTED, NOT FROM
//!   SPEC. A mirrored ban has no `reason`.
//!
//! crate-jmap checks first that the caller holds the `"admin"` role in the
//! Chat's `members` (the mirror of the room's "admin" role), so a member's
//! `ChatBan/set` create, update or destroy is `forbidden` without reaching
//! the hub. A kick is checked only by the hub. A ChatBan whose `userId` is
//! not a ChatContact, or a `kickMembers` naming one or the accountId, is
//! `invalidProperties`; a user the agent refuses before sending (not a
//! participant, already banned, no client to kick) is
//! `invalidProperties` with the agent's reason; the hub's refusal is
//! `forbidden` with its answer.
//!
//! # Limitations
//!
//! - A ban takes only a current participant; banning a user who is not in
//!   the room is not offered.
//! - A `kickMembers` of several users is one Commit per user; if one is
//!   refused, the kicks before it stay applied.
//! - A ban this account issued keeps its `bannedBy`, `reason` and
//!   `expiresAt` only on this device; another device of the user, or
//!   this one after losing the store, sees it as made elsewhere.
//! - A mirrored ban whose banner is not known names the accountId as
//!   `bannedBy`, though the owner may not have banned anyone. That
//!   happens for bans from before this device joined the room, for a ban
//!   read in the same sync as a Commit by another member of the room, and
//!   for every ban when the store is rebuilt.
//! - An expired ban the hub refuses to lift (the owner lost `canUnban`)
//!   stays, and each sync reports it in [`crate::SyncReport::problems`].

use jmap_chat_server::ChatBackend;
use jmap_chat_server::memory::MemoryError;
use jmap_chat_types::{Chat, ChatBan, ChatMember};
use jmap_server::{BackendSetError, Id, JmapBackend, SetError, SetErrorType};
use std::collections::BTreeMap;

use mimid_agent_core::{Agent, RoomStatus};
use serde_json::json;

use crate::backend::{
    AgentChat, BANNED_ROLE_INDEX, SetFailure, agent_failure, agent_set_failure, forbidden,
    serde_failure, set_error,
};
use crate::sync::SyncError;

/// The users that `room` holds in its "banned" role, or `None` when the
/// agent cannot read the room's participant list.
pub(crate) fn banned_users(agent: &Agent, room: &str) -> Option<Vec<String>> {
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

fn invalid_property(property: &str, description: impl Into<String>) -> SetError {
    set_error(SetErrorType::InvalidProperties, description).with_properties([property])
}

impl AgentChat {
    /// `ChatBan/set` create: bans the user in the Chat's room, then stores
    /// the ban under an id minted first and drops the user from `members`.
    pub(crate) async fn create_ban<F>(
        &self,
        build: F,
    ) -> Result<(Id, ChatBan), BackendSetError<MemoryError>>
    where
        F: FnOnce(&Id) -> ChatBan + Send,
    {
        let id = self.inner.mint_id();
        let ban = build(&id);
        let room = self
            .room_of_chat(&ban.chat_id)
            .ok_or_else(|| forbidden("the Chat is not bound to a MIMI room"))?;
        let user = self
            .contact_identity(&ban.user_id)
            .await
            .map_err(BackendSetError::Other)?
            .ok_or_else(|| {
                BackendSetError::SetError(Box::new(invalid_property(
                    "userId",
                    "userId is not a ChatContact",
                )))
            })?;
        // Held until the ban is stored, so a sync cannot mirror the room's
        // new ban first and store it twice.
        let mut agent = self.agent.lock().await;
        agent.ban(&room, &user).await.map_err(agent_failure)?;
        let ban = self.inner.insert_object(&self.account, ban).await?;
        self.drop_member(&ban.chat_id, &ban.user_id).await?;
        drop(agent);
        Ok((id, ban))
    }

    /// Removes `user` from the stored `members` of `chat`, if there.
    async fn drop_member(&self, chat: &Id, user: &Id) -> Result<(), BackendSetError<MemoryError>> {
        let Some(members) = self
            .stored::<Chat>(chat)
            .await
            .map_err(BackendSetError::Other)?
            .and_then(|c| c.members)
        else {
            return Ok(());
        };
        if members.iter().all(|m| m.id != *user) {
            return Ok(());
        }
        let after: Vec<ChatMember> = members.into_iter().filter(|m| m.id != *user).collect();
        let patch = serde_json::from_value(json!({ "members": after })).map_err(serde_failure)?;
        self.inner
            .update_object::<Chat>(&(), &self.account, chat, patch)
            .await?;
        Ok(())
    }

    /// `ChatBan/set` destroy: [`AgentChat::lift_ban`].
    pub(crate) async fn destroy_ban(&self, id: &Id) -> Result<(), BackendSetError<MemoryError>> {
        let Some(ban) = self
            .stored::<ChatBan>(id)
            .await
            .map_err(BackendSetError::Other)?
        else {
            // The store's notFound.
            return self
                .inner
                .destroy_object::<ChatBan>(&(), &self.account, id)
                .await;
        };
        let mut agent = self.agent.lock().await;
        self.lift_ban(&mut agent, &ban).await
    }

    /// Unbans the user of `ban` in the Chat's room if the room still holds
    /// it banned, then destroys the ban. A ban the room no longer holds
    /// (the room left, the user unbanned or removed elsewhere) is only
    /// destroyed.
    pub(crate) async fn lift_ban(
        &self,
        agent: &mut Agent,
        ban: &ChatBan,
    ) -> Result<(), BackendSetError<MemoryError>> {
        let user = self
            .contact_identity(&ban.user_id)
            .await
            .map_err(BackendSetError::Other)?;
        if let (Some(room), Some(user)) = (self.room_of_chat(&ban.chat_id), user)
            && banned_users(agent, &room).is_some_and(|banned| banned.contains(&user))
        {
            agent.unban(&room, &user).await.map_err(agent_failure)?;
        }
        self.inner
            .destroy_object::<ChatBan>(&(), &self.account, &ban.id)
            .await
    }

    /// `Chat/set` `kickMembers` of `chat`: `Agent::kick` of each user.
    pub(crate) async fn kick(
        &self,
        chat: &Chat,
        user_ids: &[Id],
    ) -> Result<Result<(), SetError>, MemoryError> {
        let refused = |failure: SetFailure| match failure {
            SetFailure::Set(e) => Ok(Err(*e)),
            SetFailure::Other(e) => Err(e),
        };
        let Some(room) = self.room_of_chat(&chat.id) else {
            return Ok(Err(invalid_property(
                "kickMembers",
                "the Chat is not bound to a MIMI room",
            )));
        };
        if user_ids.contains(&self.account) {
            return Ok(Err(invalid_property(
                "kickMembers",
                "kickMembers names the accountId",
            )));
        }
        let users = match self.users_of(user_ids, "kickMembers").await {
            Ok(users) => users,
            Err(failure) => return refused(failure),
        };
        let mut agent = self.agent.lock().await;
        for user in &users {
            if let Err(e) = agent.kick(&room, user).await {
                return refused(agent_set_failure(e));
            }
        }
        Ok(Ok(()))
    }

    /// Sync: each participant an active room holds banned has one ChatBan
    /// in the room's Chat, and no one else has one (decision
    /// mimid-1wgh.62 item 13). A new ChatBan's `bannedBy` is the room's
    /// one committer in `committers`, else the accountId (bead
    /// mimid-cqof).
    pub(crate) async fn mirror_bans(
        &self,
        agent: &mut Agent,
        committers: &Committers,
    ) -> Result<(), SyncError> {
        let (bans, _) = self
            .inner
            .get_objects::<ChatBan>(&(), &self.account, None, None)
            .await?;
        for room in agent.rooms() {
            if room.status != RoomStatus::Active {
                continue;
            }
            let Some(chat) = self.chat_of_room(&room.uri) else {
                continue;
            };
            let Some(banned) = banned_users(agent, &room.uri) else {
                continue;
            };
            let mut banned_ids = Vec::with_capacity(banned.len());
            for user in &banned {
                banned_ids.push(self.contact_for(user).await?);
            }
            for ban in bans.iter().filter(|b| b.chat_id == chat) {
                if !banned_ids.contains(&ban.user_id) {
                    self.inner
                        .destroy_object::<ChatBan>(&(), &self.account, &ban.id)
                        .await?;
                }
            }
            let new: Vec<Id> = banned_ids
                .into_iter()
                .filter(|user| !bans.iter().any(|b| b.chat_id == chat && b.user_id == *user))
                .collect();
            if new.is_empty() {
                continue;
            }
            let banned_by = match committers.of(&room.uri) {
                Some(committer) if committer != self.user => self.contact_for(committer).await?,
                _ => self.account.clone(),
            };
            for user in new {
                let ban = ChatBan::new(
                    self.inner.mint_id(),
                    chat.clone(),
                    user,
                    banned_by.clone(),
                    jmap_server::now_utc_string(),
                );
                self.inner.insert_object(&self.account, ban).await?;
            }
        }
        Ok(())
    }

    /// Sync: lifts every ban whose `expiresAt` has passed (draft-atwood-
    /// jmap-chat-00 §ChatBan `expiresAt`: "the server MUST lift it"); a
    /// ban that cannot be lifted is reported in `problems` and kept.
    pub(crate) async fn expire_bans(
        &self,
        agent: &mut Agent,
        problems: &mut Vec<String>,
    ) -> Result<(), SyncError> {
        let now = i64::try_from(crate::retry::now_secs()).unwrap_or(i64::MAX);
        let (bans, _) = self
            .inner
            .get_objects::<ChatBan>(&(), &self.account, None, None)
            .await?;
        for ban in bans {
            let expired = ban
                .expires_at
                .as_ref()
                .is_some_and(|t| t.to_epoch_seconds().is_ok_and(|t| t <= now));
            if !expired {
                continue;
            }
            if let Err(e) = self.lift_ban(agent, &ban).await {
                problems.push(format!(
                    "lifting the expired ChatBan {}: {}",
                    ban.id,
                    SyncError::from(e)
                ));
            }
        }
        Ok(())
    }
}
