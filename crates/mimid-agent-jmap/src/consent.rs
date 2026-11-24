//! Consent from a JMAP Chat client (bead mimid-1wgh.93).
//!
//! mimid-server's provider endpoint has the full set — `Consent/get`,
//! `Consent/changes`, `Consent/query` and `Consent/set` — but the agent's
//! own endpoint, which a user's client talks to (decision
//! mimid-1wgh.38), had none, so the decision that lets an invite from
//! someone new be joined was reachable only from IRC
//! (`/msg mimid allow`). With `invites = from-allowed`, the default, a
//! user whose only client is a JMAP one could not act on such an invite
//! at all.
//!
//! Consent lives at the provider, not in the store: these methods read
//! and write it through the agent
//! ([`Store::consents`](mimid_agent_store::Store::consents),
//! `Store::allow`, `Store::deny`), and nothing here caches it. So each
//! call reaches the server, and a server that cannot be reached is
//! `serverUnavailable`.
//!
//! `Consent/get` takes `accountId` and optional `ids`; it answers
//! `{accountId, state, list, notFound}`. A Consent object is
//! `{id, requester, target, room, decision, requested}`, as the agent's
//! `ConsentRecord` holds it.
//!
//! `Consent/query` takes `accountId` and answers `{accountId, ids}`, in
//! the order the server listed them.
//!
//! `Consent/set` takes `accountId` and `update`: a map from Consent id to
//! a patch whose only accepted property is `decision`, `"grant"` or
//! `"revoke"`. A grant is [`Store::allow`](mimid_agent_store::Store), a
//! revoke is `Store::deny`, each on that record's `requester`. The answer
//! is `{accountId, oldState, newState, updated, notUpdated}`.
//!
//! # Limitations
//!
//! - No `create` or `destroy`: a consent record is made by the asker's
//!   request, and a decision only updates it. A client asking for either
//!   gets `notCreated`/`notDestroyed` with `forbidden`.
//! - No `Consent/changes`, and `state` is a digest of what the last read
//!   returned rather than the server's own state string, so
//!   `canCalculateChanges` would be false. A client re-reads instead. The
//!   agent's EventSource does not yet push the Consent type.
//! - `ifInState` is not honoured: there is no stored state to compare
//!   with, since consent is the provider's.
//! - A decision names a requester, so two records from one requester (a
//!   per-room consent and an any-room one) are decided together by the
//!   agent's `allow`/`deny`, which are per user.

use std::sync::Arc;

use jmap_server::{
    CallContext, Dispatcher, HandlerFuture, HandlerOutput, Id, JmapError, JmapHandler,
};
use mimid_agent_core::ConsentRecord;
use mimid_agent_store::ActionError;
use serde_json::{Map, Value, json};

use crate::backend::AgentChat;

/// The methods' names.
pub const GET: &str = "Consent/get";
/// See [`GET`].
pub const QUERY: &str = "Consent/query";
/// See [`GET`].
pub const SET: &str = "Consent/set";

/// The decisions `Consent/set` accepts.
const GRANT: &str = "grant";
/// See [`GRANT`].
const REVOKE: &str = "revoke";

/// Registers the three methods on `dispatcher`, served by `chat`.
pub(crate) fn register(chat: &Arc<AgentChat>, dispatcher: &mut Dispatcher<Id>) {
    dispatcher.register(GET, Arc::new(Handler(Arc::clone(chat), Which::Get)));
    dispatcher.register(QUERY, Arc::new(Handler(Arc::clone(chat), Which::Query)));
    dispatcher.register(SET, Arc::new(Handler(Arc::clone(chat), Which::Set)));
}

#[derive(Clone, Copy)]
enum Which {
    Get,
    Query,
    Set,
}

struct Handler(Arc<AgentChat>, Which);

impl JmapHandler<Id> for Handler {
    fn call(&self, cx: CallContext<Id>) -> HandlerFuture {
        let chat = Arc::clone(&self.0);
        let which = self.1;
        Box::pin(async move {
            let answer = match which {
                Which::Get => chat.consent_get(cx.args).await,
                Which::Query => chat.consent_query(cx.args).await,
                Which::Set => chat.consent_set(cx.args).await,
            };
            answer.map(HandlerOutput::new)
        })
    }
}

fn invalid(method: &str, why: impl Into<String>) -> JmapError {
    let why = why.into();
    tracing::debug!(method, why, "consent call refused");
    JmapError::invalid_arguments(why)
}

/// The agent could not reach the provider, which holds consent.
fn unavailable(method: &str, error: &ActionError) -> JmapError {
    tracing::warn!(
        method,
        error = error as &dyn std::error::Error,
        "consent could not be read or written at the provider"
    );
    JmapError::server_unavailable()
}

/// `args` as an object whose `accountId` is this account's.
fn checked_args(
    chat: &AgentChat,
    method: &str,
    args: Value,
) -> Result<Map<String, Value>, JmapError> {
    let Value::Object(args) = args else {
        return Err(invalid(method, "arguments must be an object"));
    };
    match args.get("accountId") {
        Some(Value::String(id)) if id == chat.account_id().as_ref() => Ok(args),
        Some(_) => Err(JmapError::account_not_found()),
        None => Err(invalid(method, "accountId is required")),
    }
}

/// One Consent record as JMAP.
fn object(record: &ConsentRecord) -> Value {
    json!({
        "id": record.id,
        "requester": record.requester,
        "target": record.target,
        "room": record.room,
        "decision": record.decision,
        "requested": record.requested,
    })
}

/// A state string standing for what this read returned. Not the
/// provider's own state (see the module's Limitations).
fn state_of(records: &[ConsentRecord]) -> String {
    use std::hash::{Hash, Hasher};

    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    for record in records {
        record.id.hash(&mut hasher);
        record.decision.hash(&mut hasher);
        record.requested.hash(&mut hasher);
    }
    format!("{:x}", hasher.finish())
}

impl AgentChat {
    async fn consent_get(&self, args: Value) -> Result<Value, JmapError> {
        let args = checked_args(self, GET, args)?;
        let records = self
            .store()
            .consents()
            .await
            .map_err(|e| unavailable(GET, &e))?;
        let state = state_of(&records);

        let (list, not_found) = match args.get("ids") {
            None | Some(Value::Null) => (
                records.iter().map(object).collect::<Vec<Value>>(),
                Vec::new(),
            ),
            Some(Value::Array(ids)) => {
                let mut list = Vec::new();
                let mut not_found = Vec::new();
                for id in ids {
                    let Value::String(id) = id else {
                        return Err(invalid(GET, "every id must be a string"));
                    };
                    match records.iter().find(|r| r.id == *id) {
                        Some(record) => list.push(object(record)),
                        None => not_found.push(Value::String(id.clone())),
                    }
                }
                (list, not_found)
            }
            Some(_) => return Err(invalid(GET, "ids must be an array or null")),
        };

        Ok(json!({
            "accountId": self.account_id().as_ref(),
            "state": state,
            "list": list,
            "notFound": not_found,
        }))
    }

    async fn consent_query(&self, args: Value) -> Result<Value, JmapError> {
        let _ = checked_args(self, QUERY, args)?;
        let records = self
            .store()
            .consents()
            .await
            .map_err(|e| unavailable(QUERY, &e))?;
        Ok(json!({
            "accountId": self.account_id().as_ref(),
            "queryState": state_of(&records),
            "canCalculateChanges": false,
            "position": 0,
            "total": records.len(),
            "ids": records
                .iter()
                .map(|r| Value::String(r.id.clone()))
                .collect::<Vec<Value>>(),
        }))
    }

    async fn consent_set(&self, args: Value) -> Result<Value, JmapError> {
        let args = checked_args(self, SET, args)?;
        let records = self
            .store()
            .consents()
            .await
            .map_err(|e| unavailable(SET, &e))?;
        let old_state = state_of(&records);

        let mut updated = Map::new();
        let mut not_updated = Map::new();

        if let Some(update) = args.get("update") {
            let Value::Object(update) = update else {
                return Err(invalid(SET, "update must be an object"));
            };
            for (id, patch) in update {
                match self.decide(&records, id, patch).await {
                    Ok(()) => {
                        updated.insert(id.clone(), Value::Null);
                    }
                    Err(error) => {
                        not_updated.insert(id.clone(), error);
                    }
                }
            }
        }

        // create and destroy are not ours: a record exists because
        // someone asked (see the module's Limitations).
        let mut not_created = Map::new();
        if let Some(Value::Object(create)) = args.get("create") {
            for id in create.keys() {
                not_created.insert(
                    id.clone(),
                    json!({
                        "type": "forbidden",
                        "description": "a Consent record is made by the asker's request",
                    }),
                );
            }
        }
        let mut not_destroyed = Map::new();
        if let Some(Value::Array(destroy)) = args.get("destroy") {
            for id in destroy {
                if let Value::String(id) = id {
                    not_destroyed.insert(
                        id.clone(),
                        json!({
                            "type": "forbidden",
                            "description": "a Consent record cannot be destroyed; \
                                            revoke it instead",
                        }),
                    );
                }
            }
        }

        // The new state is read again, so it reflects the decisions just
        // made rather than being guessed at.
        let new_state = match self.store().consents().await {
            Ok(after) => state_of(&after),
            Err(_) => old_state.clone(),
        };

        Ok(json!({
            "accountId": self.account_id().as_ref(),
            "oldState": old_state,
            "newState": new_state,
            "created": Value::Null,
            "updated": Value::Object(updated),
            "destroyed": Value::Array(Vec::new()),
            "notCreated": Value::Object(not_created),
            "notUpdated": Value::Object(not_updated),
            "notDestroyed": Value::Object(not_destroyed),
        }))
    }

    /// Applies one `Consent/set` update patch, or says why not as a
    /// SetError.
    async fn decide(
        &self,
        records: &[ConsentRecord],
        id: &str,
        patch: &Value,
    ) -> Result<(), Value> {
        let set_error = |kind: &str, why: &str| json!({ "type": kind, "description": why });

        let Some(record) = records.iter().find(|r| r.id == id) else {
            return Err(set_error("notFound", "no such Consent record"));
        };
        let Value::Object(patch) = patch else {
            return Err(set_error("invalidPatch", "the patch must be an object"));
        };
        // Only `decision` may be set; naming anything else is an error
        // rather than a silent no-op.
        let unknown: Vec<&String> = patch.keys().filter(|key| *key != "decision").collect();
        if !unknown.is_empty() {
            return Err(json!({
                "type": "invalidProperties",
                "properties": unknown,
                "description": "only decision may be set",
            }));
        }
        let decision = match patch.get("decision") {
            Some(Value::String(decision)) => decision.as_str(),
            Some(_) | None => {
                return Err(json!({
                    "type": "invalidProperties",
                    "properties": ["decision"],
                    "description": "decision must be \"grant\" or \"revoke\"",
                }));
            }
        };

        let outcome = match decision {
            GRANT => self.store().allow(&record.requester).await,
            REVOKE => self.store().deny(&record.requester).await,
            _ => {
                return Err(json!({
                    "type": "invalidProperties",
                    "properties": ["decision"],
                    "description": "decision must be \"grant\" or \"revoke\"",
                }));
            }
        };
        outcome.map_err(|error| {
            tracing::warn!(
                method = SET,
                error = &error as &dyn std::error::Error,
                "a consent decision was refused"
            );
            set_error("serverFail", "the provider refused the decision")
        })
    }
}
