//! RFC 8620 §7.2 push subscriptions on the agent's own JMAP endpoint,
//! with the `chatPush` extension of draft-atwood-jmap-chat-push-00 (bead
//! mimid-1wgh.99).
//!
//! The draft and the RFC are implemented by crate-jmap:
//! `jmap_server::push` serves `PushSubscription/get` and `/set` over the
//! [`PushSubscriptionBackend`] trait, and
//! `jmap_chat_server::validate_chat_push` checks the `chatPush`
//! property. This module is the storage half of that trait, over
//! [`mimid_agent_store::push`], which the IRC front end's
//! `soju.im/webpush` already uses: rows are keyed by front end, so JMAP's
//! subscriptions sit beside IRC's in the agent's database under
//! [`FRONT_END`] without a schema change.
//!
//! A [`mimid_agent_store::push::Subscription`] holds the endpoint, the
//! client's keys and a free `ext` for "the front end's own fields". The
//! RFC 8620 properties that have nowhere else to live (`id`,
//! `deviceClientId`, `expires`, `types`), the verification code mimid
//! expects, and the `chatPush` map all go in `ext` as this module's
//! private `Stored`.
//!
//! # Limitations
//!
//! - Push is offered only when the daemon hands the endpoint a
//!   subscription store ([`AgentChat::enable_push`]); without one,
//!   `PushSubscription/get` and `/set` are not registered at all, as
//!   decision mimid-1wgh.12.30 had it for every endpoint before this
//!   draft.
//! - A subscription is keyed in the database by its endpoint URL, so a
//!   client that registers the same URL twice replaces its own earlier
//!   subscription rather than holding two. RFC 8620 does not forbid two,
//!   but a client has no reason to want them.
//! - Nothing here delivers a `ChatMessagePush`. This is the subscription
//!   half; the delivery half is the rest of bead mimid-1wgh.99.
//! - `PushVerification` is not sent. RFC 8620 §7.2.2 has the server POST
//!   one to the endpoint and the client echo its code; mimid stores a
//!   code of the required strength and will accept it, but until
//!   delivery exists there is nothing to carry the verification, so a
//!   subscription stays unverified. Tracked on the bead.

use std::collections::BTreeMap;
use std::sync::Arc;

use jmap_chat_server::memory::MemoryError;
use jmap_chat_types::ChatPushCapability;
use jmap_server::{BackendSetError, SetError, SetErrorType};
use jmap_server::{PushSubscriptionBackend, StoredPushSubscription};
use jmap_types::{Id, PushSubscription};
use mimid_agent_store::push::{PushError, PushSubscriptions, Subscription};
use serde::{Deserialize, Serialize};

use crate::backend::AgentChat;

/// The `front_end` value JMAP's subscriptions are stored under, beside
/// the IRC front end's own (`irc`).
pub const FRONT_END: &str = "jmap";

/// The `PushSubscription` property the draft adds, and the key it is
/// stored under inside a row's `ext.extra`.
pub const CHAT_PUSH_PROPERTY: &str = "chatPush";

/// The capability a request must name in `using` to get or set
/// `chatPush` (draft-atwood-jmap-chat-push-00 §capability).
pub const CHAT_PUSH_CAPABILITY: &str = "urn:ietf:params:jmap:chat:push";

/// Octets of CSPRNG output in a verification code. RFC 8620 §7.2.2: the
/// code "MUST contain sufficient entropy to avoid the client being able
/// to guess the code via brute force"; 32 octets is 256 bits, over the
/// 128 the trait requires.
const CODE_OCTETS: usize = 32;

/// The longest `bodySnippet` this endpoint sends, advertised as
/// `maxSnippetBytes`. INVENTED, NOT FROM SPEC: the draft sets no value.
/// 200 octets is about two lines on a phone.
const MAX_SNIPPET_BYTES: u64 = 200;

/// The most `ChatMessageEntry` objects in one payload, advertised as
/// `maxMessagesPerPush`. INVENTED, NOT FROM SPEC. Web Push bodies are
/// commonly capped near 4 KB, which a handful of entries fits.
const MAX_MESSAGES_PER_PUSH: u64 = 8;

/// What JMAP keeps in a stored subscription's `ext`: the RFC 8620
/// properties the store has no column for, and the code mimid expects
/// back from the client.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Stored {
    /// The JMAP id. The store keys rows by endpoint, so the id lives
    /// here and a lookup scans the front end's rows.
    id: String,
    /// RFC 8620 §7.2 `deviceClientId`.
    device_client_id: String,
    /// RFC 8620 §7.2 `expires`, as the client sent it or as the handler
    /// limited it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    expires: Option<jmap_types::UTCDate>,
    /// RFC 8620 §7.2 `types`; absent means every type.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    types: Option<Vec<String>>,
    /// The code mimid expects in `verificationCode`.
    expected_code: String,
    /// True once the client has echoed [`Stored::expected_code`].
    #[serde(default)]
    verified: bool,
    /// Extension properties, `chatPush` among them, as validated.
    #[serde(default, skip_serializing_if = "serde_json::Map::is_empty")]
    extra: serde_json::Map<String, serde_json::Value>,
}

/// A fresh subscription id: 16 octets of CSPRNG output as hex, so two
/// clients cannot collide and an id reveals nothing.
fn fresh_id() -> Result<String, BackendSetError<MemoryError>> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes)
        .map_err(|e| BackendSetError::Other(MemoryError::new(e.to_string())))?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

/// A verification code of [`CODE_OCTETS`] from the system CSPRNG, hex.
fn code() -> Result<String, PushError> {
    let mut bytes = [0u8; CODE_OCTETS];
    getrandom::fill(&mut bytes).map_err(|e| PushError::Malformed(e.to_string()))?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

/// `error` as the answer a `/set` should give: a SetError for the two
/// cases RFC 8620 names, and the backend's own error for anything else,
/// which the handler reports as a method-level failure rather than
/// pretending the client's object was at fault.
fn set_error(error: PushError) -> BackendSetError<MemoryError> {
    match error {
        // RFC 8620 §7.2.2: "The server MUST limit the number of push
        // subscriptions any one user may have."
        PushError::TooMany => {
            BackendSetError::SetError(Box::new(SetError::new(SetErrorType::OverQuota)))
        }
        PushError::TooLong => BackendSetError::SetError(Box::new(
            SetError::new(SetErrorType::InvalidProperties).with_properties(["url".to_owned()]),
        )),
        other => BackendSetError::Other(MemoryError::new(other.to_string())),
    }
}

/// Runs the delivery loop until `stop` is set: each new inbound message
/// becomes a `ChatMessagePush` to every subscription whose `chatPush`
/// covers the account. Returns at once when
/// push is not enabled.
pub async fn deliver(chat: Arc<AgentChat>, stop: tokio::sync::watch::Receiver<bool>) {
    crate::push_deliver::run(chat, stop).await;
}

impl AgentChat {
    /// The subscription store, when the daemon gave this endpoint one
    /// ([`AgentChat::enable_push`]). The daemon reads it to decide
    /// whether to spawn [`deliver`].
    pub fn push_store(&self) -> Option<&Arc<PushSubscriptions>> {
        self.push.as_ref()
    }

    /// This endpoint's `urn:ietf:params:jmap:chat:push` capability, which
    /// bounds what a `ChatPushConfig` may ask for.
    pub fn chat_push_capability() -> ChatPushCapability {
        // Built through serde: crate-jmap's types are
        // #[non_exhaustive] and AGENTS.md says not to reach for a
        // constructor. supportedUrgencyValues must hold at least
        // "normal" and "high" (§capability).
        serde_json::from_value(serde_json::json!({
            "maxSnippetBytes": MAX_SNIPPET_BYTES,
            "supportedUrgencyValues": ["very-low", "low", "normal", "high"],
            "maxMessagesPerPush": MAX_MESSAGES_PER_PUSH,
        }))
        .expect("the capability object is built from literals")
    }

    /// `extra`'s `chatPush` against this account's capability
    /// (`jmap_chat_server::validate_chat_push`).
    fn check_chat_push(
        &self,
        extra: &serde_json::Map<String, serde_json::Value>,
    ) -> Result<(), Box<SetError>> {
        let caps = std::iter::once((self.account_id().clone(), Self::chat_push_capability()))
            .collect::<std::collections::HashMap<_, _>>();
        jmap_chat_server::validate_chat_push(extra, &caps)
    }

    /// Every stored subscription of this endpoint, newest id last.
    fn push_rows(&self) -> Result<Vec<(Subscription, Stored)>, PushError> {
        let Some(store) = self.push_store() else {
            return Ok(Vec::new());
        };
        let mut found = Vec::new();
        for subscription in store.list(FRONT_END)? {
            // A row whose ext is not ours is skipped rather than failing
            // the call: another front end's row, or one from an older
            // shape, must not make /get fail.
            if let Ok(stored) = serde_json::from_value::<Stored>(subscription.ext.clone()) {
                found.push((subscription, stored));
            }
        }
        found.sort_by(|a, b| a.1.id.cmp(&b.1.id));
        Ok(found)
    }

    /// The `PushSubscription` a row stands for.
    fn as_jmap(subscription: &Subscription, stored: &Stored) -> PushSubscription {
        // Through serde, as for every crate-jmap type (AGENTS.md).
        let mut object = serde_json::json!({
            "id": stored.id,
            "deviceClientId": stored.device_client_id,
            "url": subscription.endpoint,
        });
        let map = object
            .as_object_mut()
            .expect("json! built an object just above");
        if !subscription.keys.is_empty() {
            map.insert("keys".to_owned(), serde_json::json!(subscription.keys));
        }
        if let Some(expires) = &stored.expires {
            map.insert("expires".to_owned(), serde_json::json!(expires));
        }
        if let Some(types) = &stored.types {
            map.insert("types".to_owned(), serde_json::json!(types));
        }
        for (name, value) in &stored.extra {
            map.insert(name.clone(), value.clone());
        }
        serde_json::from_value(object).expect("the stored fields are a PushSubscription")
    }

    /// The row for `id`, or `None`.
    fn row_of(&self, id: &Id) -> Result<Option<(Subscription, Stored)>, PushError> {
        Ok(self
            .push_rows()?
            .into_iter()
            .find(|(_, stored)| stored.id == id.as_ref()))
    }

    /// Stores `push` under `front_end`, keeping `stored` in its `ext`.
    fn put(&self, push: &PushSubscription, stored: &Stored) -> Result<(), PushError> {
        let Some(store) = self.push_store() else {
            return Err(PushError::Malformed("push is not enabled".to_owned()));
        };
        // PushKeys is typed; the store keeps the same two names the
        // `aes128gcm` coding uses, so the mapping is by name.
        let mut keys: BTreeMap<String, String> = BTreeMap::new();
        if let Some(sent) = &push.keys {
            keys.insert("p256dh".to_owned(), sent.p256dh.clone());
            keys.insert("auth".to_owned(), sent.auth.clone());
            for (name, value) in &sent.extra {
                if let Some(text) = value.as_str() {
                    keys.insert(name.clone(), text.to_owned());
                }
            }
        }
        let url = push.url.clone().unwrap_or_default();
        let ext = serde_json::to_value(stored).map_err(|e| PushError::Malformed(e.to_string()))?;
        store.register(&Subscription::new(FRONT_END, &url, keys, ext))
    }
}

impl PushSubscriptionBackend for AgentChat {
    /// `chatPush` is gated on the capability rather than always valid, so
    /// a request that does not name it in `using` neither reads nor
    /// writes the property (draft-atwood-jmap-chat-push-00 §capability).
    const PUSH_SUBSCRIPTION_EXTENSION_CAPABILITIES: &'static [(&'static str, &'static str)] =
        &[("chatPush", CHAT_PUSH_CAPABILITY)];

    async fn list_push_subscriptions(
        &self,
        _caller: &Self::CallerCtx,
    ) -> Result<Vec<StoredPushSubscription>, Self::Error> {
        // A store failure is not a MemoryError, and /get has no
        // SetError to carry it, so an unreadable row set is reported
        // as no subscriptions rather than as a broken account. The
        // failure is logged.
        let rows = self.push_rows().unwrap_or_else(|error| {
            tracing::warn!(
                error = &error as &dyn std::error::Error,
                "the push subscriptions could not be read"
            );
            Vec::new()
        });
        Ok(rows
            .iter()
            .map(|(subscription, stored)| StoredPushSubscription {
                subscription: Self::as_jmap(subscription, stored),
                expected_code: stored.expected_code.clone(),
            })
            .collect())
    }

    async fn create_push_subscription(
        &self,
        _caller: &Self::CallerCtx,
        new: PushSubscription,
    ) -> Result<StoredPushSubscription, BackendSetError<Self::Error>> {
        // The extension properties are validated here, in the same call
        // as the store, as the trait requires.
        self.check_chat_push(&new.extra)
            .map_err(BackendSetError::SetError)?;
        let expected_code = code().map_err(set_error)?;
        let stored = Stored {
            id: fresh_id()?,
            device_client_id: new.device_client_id.clone(),
            expires: new.expires.clone(),
            types: new.types.clone(),
            expected_code: expected_code.clone(),
            verified: false,
            extra: new.extra.clone(),
        };
        self.put(&new, &stored).map_err(set_error)?;
        // The handler echoes the id from what the backend returns.
        let subscription = Self::as_jmap(
            &Subscription::new(
                FRONT_END,
                new.url.clone().unwrap_or_default(),
                BTreeMap::new(),
                serde_json::Value::Null,
            ),
            &stored,
        );
        Ok(StoredPushSubscription {
            subscription,
            expected_code,
        })
    }

    async fn update_push_subscription(
        &self,
        _caller: &Self::CallerCtx,
        sub: PushSubscription,
    ) -> Result<PushSubscription, BackendSetError<Self::Error>> {
        self.check_chat_push(&sub.extra)
            .map_err(BackendSetError::SetError)?;
        let Some(id) = sub.id.clone() else {
            return Err(BackendSetError::SetError(Box::new(SetError::new(
                SetErrorType::NotFound,
            ))));
        };
        let Some((previous, mut stored)) = self.row_of(&id).map_err(set_error)? else {
            return Err(BackendSetError::SetError(Box::new(SetError::new(
                SetErrorType::NotFound,
            ))));
        };
        // A client that echoes the code verifies the subscription.
        if sub
            .verification_code
            .as_deref()
            .is_some_and(|code| code == stored.expected_code)
        {
            stored.verified = true;
        }
        stored.expires = sub.expires.clone();
        stored.types = sub.types.clone();
        stored.extra = sub.extra.clone();
        // The url is immutable, which the handler has already checked, so
        // the row keeps its key; drop the old one if it moved anyway.
        if Some(&previous.endpoint) != sub.url.as_ref()
            && let Some(store) = self.push_store()
        {
            store
                .unregister(FRONT_END, &previous.endpoint)
                .map_err(set_error)?;
        }
        self.put(&sub, &stored).map_err(set_error)?;
        Ok(sub)
    }

    async fn destroy_push_subscription(
        &self,
        _caller: &Self::CallerCtx,
        id: &Id,
    ) -> Result<(), BackendSetError<Self::Error>> {
        let Some((subscription, _)) = self.row_of(id).map_err(set_error)? else {
            return Err(BackendSetError::SetError(Box::new(SetError::new(
                SetErrorType::NotFound,
            ))));
        };
        let Some(store) = self.push_store() else {
            return Err(BackendSetError::SetError(Box::new(SetError::new(
                SetErrorType::NotFound,
            ))));
        };
        store
            .unregister(FRONT_END, &subscription.endpoint)
            .map_err(set_error)?;
        Ok(())
    }
}
