//! Kicking, banning and unbanning from a JMAP Chat client (bead
//! mimid-90cd; decision mimid-1wgh.62). INVENTED, NOT FROM SPEC:
//! draft-atwood-jmap-chat-00 has no kick or ban for a group Chat (its
//! SpaceBan and `manage_members` are for Spaces), and
//! draft-atwood-jmap-chat-mimi-00 none at all. Removing a member and
//! changing its role are `Chat/set` `removeMembers` and
//! `updateMemberRoles`, as the draft has them.
//!
//! [`KICK`], [`BAN`] and [`UNBAN`] each take:
//!
//! - `accountId`;
//! - `chatId`: a Chat bound to a MIMI room;
//! - `memberId`: the ChatContact id of the user to act on, not the
//!   accountId.
//!
//! and answer `{accountId}` once the hub has accepted the Commit
//! (`Agent::kick`, `Agent::ban`, `Agent::unban`): a kick removes the
//! user's clients and leaves the participant list alone, a ban gives the
//! user the room's "banned" role and removes its clients, an unban gives
//! it the member role back without adding clients (room-policy-04 §8.1.2,
//! §8.1.3). The Chat's `members` change at the next sync.
//!
//! A Chat not bound to a room, an unknown ChatContact, the accountId, or a
//! request the agent refuses before sending (the user is not a
//! participant, has no client to kick, is banned already or not banned)
//! is `invalidArguments`. The hub's refusal (the room policy: the caller's
//! role lacks `canKick`, `canBan` or `canUnban`) is the method error
//! `forbidden` with the hub's answer. A server or hub that cannot be
//! reached is `serverUnavailable`.
//!
//! # Limitations
//!
//! - The methods are served under the JMAP Chat capability, which does
//!   not define them.
//! - A ban takes only a current participant; banning a user who is not in
//!   the room is not offered.
//! - Unbanned and kicked users' devices do not come back by themselves;
//!   see `Agent::unban`.

use std::sync::Arc;

use jmap_server::{
    CallContext, Dispatcher, HandlerFuture, HandlerOutput, Id, JmapError, JmapHandler,
};
use mimid_agent_core::AgentError;
use serde_json::{Value, json};

use crate::backend::AgentChat;

/// `Chat/kick`.
pub const KICK: &str = "Chat/kick";
/// `Chat/ban`.
pub const BAN: &str = "Chat/ban";
/// `Chat/unban`.
pub const UNBAN: &str = "Chat/unban";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Action {
    Kick,
    Ban,
    Unban,
}

impl Action {
    fn method(self) -> &'static str {
        match self {
            Self::Kick => KICK,
            Self::Ban => BAN,
            Self::Unban => UNBAN,
        }
    }
}

/// Registers [`KICK`], [`BAN`] and [`UNBAN`] on `dispatcher`, served by
/// `chat`.
pub(crate) fn register(chat: &Arc<AgentChat>, dispatcher: &mut Dispatcher<()>) {
    for action in [Action::Kick, Action::Ban, Action::Unban] {
        dispatcher.register(
            action.method(),
            Arc::new(Handler {
                chat: Arc::clone(chat),
                action,
            }),
        );
    }
}

struct Handler {
    chat: Arc<AgentChat>,
    action: Action,
}

impl JmapHandler<()> for Handler {
    fn call(&self, cx: CallContext<()>) -> HandlerFuture {
        let chat = Arc::clone(&self.chat);
        let action = self.action;
        Box::pin(async move { chat.moderate(action, cx.args).await.map(HandlerOutput::new) })
    }
}

fn invalid(method: &str, why: impl Into<String>) -> JmapError {
    let why = why.into();
    tracing::debug!(method, why, "moderation request refused");
    JmapError::invalid_arguments(why)
}

impl AgentChat {
    async fn moderate(&self, action: Action, args: Value) -> Result<Value, JmapError> {
        let method = action.method();
        let Value::Object(args) = args else {
            return Err(invalid(method, "arguments must be an object"));
        };
        match args.get("accountId") {
            Some(Value::String(id)) if id == self.account.as_ref() => {}
            Some(Value::String(_)) => return Err(JmapError::account_not_found()),
            _ => return Err(invalid(method, "accountId is required")),
        }
        let id = |key: &str| match args.get(key) {
            Some(Value::String(id)) => Ok(Id::from(id.as_str())),
            _ => Err(invalid(method, format!("{key} is required"))),
        };
        let chat = id("chatId")?;
        let member = id("memberId")?;
        let room = self
            .room_of_chat(&chat)
            .ok_or_else(|| invalid(method, "chatId is not a Chat bound to a MIMI room"))?;
        if member == self.account {
            return Err(invalid(method, "memberId is this account"));
        }
        let user = self
            .contact_identity(&member)
            .await
            .map_err(|e| JmapError::server_fail(e.to_string()))?
            .ok_or_else(|| invalid(method, "memberId is not a ChatContact"))?;
        let mut agent = self.agent.lock().await;
        let done = match action {
            Action::Kick => agent.kick(&room, &user).await,
            Action::Ban => agent.ban(&room, &user).await,
            Action::Unban => agent.unban(&room, &user).await,
        };
        done.map_err(|e| agent_error(method, e))?;
        Ok(json!({ "accountId": self.account }))
    }
}

fn agent_error(method: &str, error: AgentError) -> JmapError {
    match error {
        AgentError::Invalid(why) => invalid(method, why),
        AgentError::NoSuchRoom(_) => invalid(method, "the Chat's room is not known to the agent"),
        AgentError::Refused { reason, .. } => {
            let mut error = JmapError::forbidden();
            error.description = Some(reason);
            error
        }
        AgentError::Http { .. } => JmapError::server_unavailable(),
        AgentError::Status { status, .. } if status >= 500 => JmapError::server_unavailable(),
        AgentError::Method { ref kind, .. } if kind == "serverUnavailable" => {
            JmapError::server_unavailable()
        }
        error => {
            tracing::error!(
                name: "moderation_failed",
                method,
                error = &error as &dyn std::error::Error,
                "moderation failed"
            );
            JmapError::server_fail("internal error")
        }
    }
}
