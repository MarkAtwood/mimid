//! Delivering `ChatMessagePush` to a subscribed client
//! (draft-atwood-jmap-chat-push-00 §Delivery; bead mimid-1wgh.99).
//!
//! The subscription half is [`crate::push`]. This is the half that wakes
//! a phone: a loop over the store's change feed that, for each new
//! inbound message, builds the payload with crate-jmap's
//! `jmap_chat_server::push` and sends it encrypted to every subscription
//! whose `chatPush` covers the account.
//!
//! What each side owns:
//!
//! - **crate-jmap** decides everything the draft specifies:
//!   `should_push` applies §Delivery's suppression rules (the owner's own
//!   message, a Chat left, a muted Chat, a blocked contact),
//!   `build_chat_message_push` derives the entry and its urgency, and
//!   `fit_chat_message_push` splits a payload that would exceed the push
//!   service's size limit.
//! - **this module** supplies the records those functions read, and does
//!   the RFC 8291 encryption and the POST, with
//!   [`mimid_agent_store::push_crypto`].
//!
//! The agent holds plaintext, so unlike the provider it can fill
//! `bodySnippet`, `hasMention` and `mentionScopes`: the draft's §e2ee
//! case is the provider's, not this one's
//! (docs/design/purple-mimi.md §12.1 on who sees plaintext).
//!
//! # Limitations
//!
//! - A push is sent after the message is stored, not inside the same
//!   transaction. crate-jmap's `should_push` documents that a caller
//!   "MUST read the set of subscriptions under the same lock or
//!   transaction as the message write"; mimid reads them afterwards from
//!   the change feed, so a subscription created in the same instant as a
//!   message may or may not receive it. The draft's own first SHOULD NOT
//!   ("the message was stored before the `PushSubscription` was
//!   created") covers the direction that matters.
//! - Only `Change::MessageAdded` pushes. An edit, a reaction and a
//!   deletion do not, which matches the draft: `ChatMessagePush` stands
//!   in for the `StateChange` of new messages only, and every other
//!   change is announced by an ordinary `StateChange`.
//! - mimid sends no `StateChange` of its own on this path, so a client
//!   whose `chatPush` excludes a message is not woken for it at all.
//!   The draft has the server send a `StateChange` instead; the agent's
//!   EventSource serves a connected client, but a sleeping phone is not
//!   woken. Tracked on the bead.
//! - The `unreadCount` badge is not filled. `owner_unread_count` exists
//!   in crate-jmap and wants a ReadPosition projection this endpoint
//!   does not keep yet (bead mimid-1wgh.11.11.1).
//! - A failing endpoint is not retried. A 404 or 410 unregisters it, as
//!   RFC 8030 intends; any other failure is logged and the push is lost.

use std::collections::HashMap;
use std::sync::Arc;

use jmap_chat_server::{OwnerFlags, PushItem, build_chat_message_push, fit_chat_message_push};
use jmap_chat_types::{Chat, ChatContact, ChatPushConfig, Message};
use jmap_server::{Id, JmapReads, State};
use mimid_agent_store::Change;
use mimid_agent_store::push_crypto::{self, ClientKeys, SecretKey};
use tokio::sync::{broadcast, watch};

use crate::backend::AgentChat;
use crate::push::{CHAT_PUSH_PROPERTY, FRONT_END};

/// How long a push service should hold an undelivered push, seconds. The
/// IRC front end's value, for the same reason: a week covers a phone
/// that is off over a holiday.
const TTL_SECONDS: u64 = 7 * 24 * 3600;

/// How long a VAPID token stays valid, seconds (RFC 8292 caps it at 24
/// hours).
const VAPID_LIFETIME_SECONDS: u64 = 12 * 3600;

/// Payloads are padded to this many octets before encryption, so their
/// length tells the push service less about the message.
const PAD_TO: usize = 1024;

/// The name the agent's VAPID key is kept under, shared with the IRC
/// front end: one provider identity per agent, whichever front end
/// pushes (RFC 8292 §2, the `aud` claim is the push service).
const VAPID_KEY: &str = "vapid";

/// The most octets in one push body. RFC 8030 sets no value and services
/// differ; 4096 is the common floor. INVENTED, NOT FROM SPEC.
const MAX_BODY_BYTES: usize = 4096;

/// Follows the store's change feed and pushes each new inbound message
/// to every subscription that asked for it, until `stop`.
pub(crate) async fn run(chat: Arc<AgentChat>, mut stop: watch::Receiver<bool>) {
    let Some(subscriptions) = chat.push_store().cloned() else {
        return;
    };
    // One VAPID key per agent, made on first use and kept.
    let vapid = match subscriptions.key(VAPID_KEY, || {
        push_crypto::random_secret()
            .map(|key| key.to_bytes().to_vec())
            .map_err(|e| e.to_string())
    }) {
        Ok(bytes) => match SecretKey::from_slice(&bytes) {
            Ok(key) => key,
            Err(_) => {
                tracing::warn!(
                    name: "agent_jmap_push_key_unusable",
                    "the stored VAPID key is not a P-256 secret; push is off"
                );
                return;
            }
        },
        Err(error) => {
            tracing::warn!(
                name: "agent_jmap_push_key_failed",
                error = &error as &dyn std::error::Error,
                "the VAPID key could not be read; push is off"
            );
            return;
        }
    };
    let client = reqwest::Client::new();
    let store = Arc::clone(chat.store());
    let mut feed = store.subscribe();
    let mut mark = store.last_seq();
    loop {
        tokio::select! {
            _ = stop.changed() => {
                if *stop.borrow() {
                    return;
                }
            }
            woken = feed.recv() => match woken {
                Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => {}
                Err(broadcast::error::RecvError::Closed) => return,
            },
        }
        let changes = match store.changes_since(mark) {
            Ok(changes) => changes,
            // Fell behind the log: skip to the present rather than push
            // a backlog a phone has no use for.
            Err(_too_old) => {
                mark = store.last_seq();
                continue;
            }
        };
        let mut added = Vec::new();
        for (seq, change) in changes {
            mark = seq;
            if let Change::MessageAdded(key) = change {
                added.push(key);
            }
        }
        for key in added {
            deliver(&chat, &client, &vapid, key.as_ref()).await;
        }
    }
}

/// Builds and sends the pushes one new message calls for.
async fn deliver(chat: &Arc<AgentChat>, client: &reqwest::Client, vapid: &SecretKey, key: &str) {
    let id = Id::from(key);
    let Some(message) = object::<Message>(chat, &id).await else {
        return;
    };
    let sender_id = message.sender_id.clone();
    let chat_id = message.chat_id.clone();
    let (Some(room), Some(sender)) = (
        object::<Chat>(chat, &chat_id).await,
        object::<ChatContact>(chat, &sender_id).await,
    ) else {
        return;
    };
    let caps = std::iter::once((chat.account_id().clone(), AgentChat::chat_push_capability()))
        .collect::<HashMap<_, _>>();
    // Both predicates are the deployment's to define
    // (draft §ChatMessageEntry on `here` and `admins`). The agent serves
    // one user, who is present whenever their client is: `active` is
    // true, and `admin` is left to the room's roles, which this endpoint
    // does not read, so false.
    let owner = OwnerFlags::new(true, false);

    for (subscription, config) in configs(chat).await {
        let allowed = jmap_chat_server::should_push(
            chat.as_ref(),
            &(),
            chat.account_id(),
            &config,
            &caps,
            &message,
            owner,
        )
        .await;
        match allowed {
            Ok(true) => {}
            Ok(false) => continue,
            Err(error) => {
                tracing::warn!(
                    name: "agent_jmap_push_undecided",
                    error = &error as &dyn std::error::Error,
                    "whether to push could not be decided; not pushing"
                );
                continue;
            }
        }
        let built = build_chat_message_push(
            chat.account_id(),
            State::from(message.id.as_ref()),
            &config,
            &AgentChat::chat_push_capability(),
            owner,
            // PushItem is #[non_exhaustive]; `sender_member` stays
            // unset because this endpoint keeps no SpaceMember
            // projection, so a channel nick falls back to the
            // ChatContact's display name (draft §ChatMessageEntry).
            PushItem::new(&message, &room, &sender),
            // The badge count needs a ReadPosition projection this
            // endpoint does not keep (bead mimid-1wgh.11.11.1).
            None,
        );
        let urgency = serde_json::to_value(built.urgency)
            .ok()
            .and_then(|value| value.as_str().map(str::to_owned))
            .unwrap_or_else(|| "normal".to_owned());
        // A payload too large for the service is split rather than
        // dropped; a `None` is an entry that cannot be made to fit.
        for part in fit_chat_message_push(built.payload, MAX_BODY_BYTES) {
            let Some(part) = part else {
                tracing::warn!(
                    name: "agent_jmap_push_too_large",
                    "an entry does not fit a push body and was dropped"
                );
                continue;
            };
            let Ok(body) = serde_json::to_vec(&part) else {
                continue;
            };
            send(chat, client, vapid, &subscription, &body, &urgency).await;
        }
    }
}

/// One projected object of this account, or `None` if it is missing or
/// unreadable.
async fn object<O>(chat: &Arc<AgentChat>, id: &Id) -> Option<O>
where
    O: jmap_server::GetObject + Send + Sync,
{
    match chat
        .inner
        .get_objects::<O>(&(), chat.account_id(), Some(std::slice::from_ref(id)), None)
        .await
    {
        Ok((mut found, _)) => found.pop(),
        Err(error) => {
            tracing::warn!(
                name: "agent_jmap_push_object_unreadable",
                error = &error as &dyn std::error::Error,
                "a record a push needs could not be read"
            );
            None
        }
    }
}

/// Each stored subscription with a `chatPush` config for this account.
async fn configs(
    chat: &Arc<AgentChat>,
) -> Vec<(mimid_agent_store::push::Subscription, ChatPushConfig)> {
    let Some(store) = chat.push_store() else {
        return Vec::new();
    };
    let Ok(rows) = store.list(FRONT_END) else {
        return Vec::new();
    };
    let account = chat.account_id().as_ref().to_owned();
    rows.into_iter()
        .filter_map(|row| {
            let config = row
                .ext
                .get("extra")?
                .get(CHAT_PUSH_PROPERTY)?
                .get(&account)?
                .clone();
            serde_json::from_value::<ChatPushConfig>(config)
                .ok()
                .map(|config| (row, config))
        })
        .collect()
}

/// POSTs one encrypted push to a subscription's endpoint.
async fn send(
    chat: &Arc<AgentChat>,
    client: &reqwest::Client,
    vapid: &SecretKey,
    subscription: &mimid_agent_store::push::Subscription,
    body: &[u8],
    urgency: &str,
) {
    let (Some(p256dh), Some(auth)) = (
        subscription.keys.get("p256dh"),
        subscription.keys.get("auth"),
    ) else {
        return;
    };
    let Some(keys) = ClientKeys::parse(p256dh, auth) else {
        return;
    };
    let Ok(url) = reqwest::Url::parse(&subscription.endpoint) else {
        return;
    };
    let host = url.host_str().unwrap_or("?").to_owned();
    let encrypted = match push_crypto::encrypt(body, &keys, PAD_TO) {
        Ok(encrypted) => encrypted,
        Err(error) => {
            tracing::warn!(
                name: "agent_jmap_push_failed",
                host = %host,
                error = &error as &dyn std::error::Error,
                "a push was not encrypted"
            );
            return;
        }
    };
    let expires = mimid_agent_store::sync::now_ms() / 1000 + VAPID_LIFETIME_SECONDS;
    let authorization =
        push_crypto::vapid_authorization(vapid, &url.origin().ascii_serialization(), expires);
    let sent = client
        .post(url)
        .header("TTL", TTL_SECONDS.to_string())
        .header("Urgency", urgency)
        .header("Content-Encoding", "aes128gcm")
        .header("Content-Type", "application/octet-stream")
        .header("Authorization", authorization)
        .body(encrypted)
        .send()
        .await;
    match sent {
        Ok(response) if response.status().is_success() => {
            tracing::debug!(host = %host, "pushed a ChatMessagePush");
        }
        // RFC 8030 §7: the subscription is gone for good.
        Ok(response) if matches!(response.status().as_u16(), 404 | 410) => {
            tracing::info!(
                name: "agent_jmap_push_gone",
                host = %host,
                status = response.status().as_u16(),
                "a push endpoint is gone; the subscription is dropped"
            );
            if let Some(store) = chat.push_store() {
                let _ = store.unregister(FRONT_END, &subscription.endpoint);
            }
        }
        Ok(response) => {
            tracing::warn!(
                name: "agent_jmap_push_refused",
                host = %host,
                status = response.status().as_u16(),
                "a push service refused a push"
            );
        }
        Err(error) => {
            tracing::warn!(
                name: "agent_jmap_push_unreachable",
                host = %host,
                error = &error as &dyn std::error::Error,
                "a push service could not be reached"
            );
        }
    }
}
