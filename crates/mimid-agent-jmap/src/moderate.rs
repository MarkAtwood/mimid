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
//! - **Bans made elsewhere** ([`mimid_agent_store::sync::bans`], shown
//!   here as ChatBans): at each sync, every participant that an
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

use jmap_chat_server::ChatStore;
use jmap_chat_server::memory::MemoryError;
use jmap_chat_types::{Chat, ChatBan, ChatMember};
use jmap_server::{BackendSetError, Id, SetError, SetErrorType};

use mimid_agent_store::convert::parse_utc_date;
use serde_json::json;

use crate::backend::{
    AgentChat, SetFailure, action_failure, action_set_failure, forbidden, key, serde_failure,
    set_error,
};

fn invalid_property(property: &str, description: impl Into<String>) -> SetError {
    set_error(SetErrorType::InvalidProperties, description).with_properties([property])
}

impl AgentChat {
    /// `ChatBan/set` create: bans the user in the Chat's room and records
    /// the ban ([`mimid_agent_store::Store::ban`]) under an id minted
    /// first, then stores the ChatBan and drops the user from `members`.
    /// The store records the ban before it lets the agent go, so a sync
    /// cannot mirror the room's new ban first and store it twice.
    pub(crate) async fn create_ban<F>(
        &self,
        build: F,
    ) -> Result<(Id, ChatBan), BackendSetError<MemoryError>>
    where
        F: FnOnce(&Id) -> ChatBan + Send,
    {
        let id = self.inner.mint_id();
        let ban = build(&id);
        if self.room_of_chat(&ban.chat_id).is_none() {
            return Err(forbidden("the Chat is not bound to a MIMI room"));
        }
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
        let expires_at = ban
            .expires_at
            .as_ref()
            .and_then(|d| parse_utc_date(d.as_ref()));
        self.store
            .ban(
                key(&id),
                ban.chat_id.as_ref(),
                &user,
                ban.reason.clone(),
                expires_at,
            )
            .await
            .map_err(action_failure)?;
        let ban = self.insert_shown(&id, ban).await?;
        self.drop_member(&ban.chat_id, &ban.user_id).await?;
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
            .update_object::<Chat>(&self.account, &self.account, chat, patch)
            .await?;
        Ok(())
    }

    /// `ChatBan/set` destroy: lifts the ban
    /// ([`mimid_agent_store::Store::unban`]: the user is unbanned in the
    /// Chat's room if the room still holds them banned, and the record
    /// goes), then destroys the ChatBan.
    pub(crate) async fn destroy_ban(&self, id: &Id) -> Result<(), BackendSetError<MemoryError>> {
        if self
            .stored::<ChatBan>(id)
            .await
            .map_err(BackendSetError::Other)?
            .is_some()
        {
            self.store
                .unban(id.as_ref())
                .await
                .map_err(action_failure)?;
        }
        // The store's notFound when there is no ChatBan.
        self.inner
            .destroy_object::<ChatBan>(&self.account, &self.account, id)
            .await
    }

    /// `Chat/set` `kickMembers` of `chat`: `Agent::kick` of each user
    /// ([`mimid_agent_store::Store::kick`]).
    pub(crate) async fn kick(
        &self,
        chat: &Chat,
        user_ids: &[Id],
    ) -> Result<Result<(), SetError>, MemoryError> {
        let refused = |failure: SetFailure| match failure {
            SetFailure::Set(e) => Ok(Err(*e)),
            SetFailure::Other(e) => Err(e),
        };
        if self.room_of_chat(&chat.id).is_none() {
            return Ok(Err(invalid_property(
                "kickMembers",
                "the Chat is not bound to a MIMI room",
            )));
        }
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
        match self.store.kick(chat.id.as_ref(), &users).await {
            Ok(()) => Ok(Ok(())),
            Err(e) => refused(action_set_failure(e)),
        }
    }
}
