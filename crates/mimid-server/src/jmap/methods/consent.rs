//! `Consent/get`, `Consent/changes`, `Consent/query` and `Consent/set`
//! (draft-atwood-jmap-chat-mimi-00 §Consent; bead mimid-1wgh.12.43).
//!
//! A Consent record is one of the account's [`ConsentRecord`]s: one
//! ConsentScope (protocol-07 §5.7) in which the account's user is the
//! requester or the target. The URIs are kept and shown in RFC 3986
//! §6.2.2 normal form (decision mimid-1wgh.52). The type's state is the
//! account's highest Consent modseq ([`Store::consent_state`]).
//!
//! `Consent/set` delivers each change through
//! [`Follower::send_consent`] before storing it: a `request` or `cancel`
//! when the user is the requester, a `grant` or `revoke` when the user is
//! the target. mimid sends revokes: the draft lets a server skip them, and
//! a requester that is told can stop asking. An unknown other user is
//! `invalidProperties` naming that user's URI; an entry another provider
//! did not take is the SetError `consentNotSent`, and the record does not
//! change.
//!
//! # Limitations
//!
//! - The changes of one call are delivered and stored one at a time, not
//!   as one transaction.
//! - `Consent/query` has no `/queryChanges` (`canCalculateChanges` is
//!   `false`), and takes a FilterCondition only, not a FilterOperator.
//! - A record whose scope another account of this server also holds is
//!   changed in both accounts, but not in one transaction.

use std::sync::Arc;

use jmap_server::{CallContext, HandlerFuture, HandlerOutput, JmapError, JmapHandler};
use mimi_protocol::ConsentOperation;
use serde_json::{Map, Value, json};

use super::Services;
use crate::follower::Follower;
use crate::follower::consent::ConsentSendError;
use crate::hub::{lookup_uri, user_uri_domain};
use crate::jmap::api::Methods;
use crate::jmap::auth::Account;
use crate::jmap::projection::utc_date;
use crate::store::{ConsentDecision, ConsentKey, ConsentPatch, ConsentRecord, Store};

/// The properties of a Consent record.
const PROPERTIES: &[&str] = &[
    "id",
    "requesterUri",
    "targetUri",
    "roomId",
    "requested",
    "decision",
    "updated",
];

#[derive(Clone, Copy)]
enum Method {
    Get,
    Changes,
    Query,
    Set,
}

/// Registers the four Consent methods.
pub(super) fn register(methods: &mut Methods, services: &Services) {
    for (name, method) in [
        ("Consent/get", Method::Get),
        ("Consent/changes", Method::Changes),
        ("Consent/query", Method::Query),
        ("Consent/set", Method::Set),
    ] {
        methods.add(
            name,
            Arc::new(Handler {
                store: services.store.clone(),
                follower: Arc::clone(&services.follower),
                method,
            }),
        );
    }
}

struct Handler {
    store: Store,
    follower: Arc<Follower>,
    method: Method,
}

impl JmapHandler<Account> for Handler {
    fn call(&self, cx: CallContext<Account>) -> HandlerFuture {
        let CallContext { args, caller, .. } = cx;
        let (store, follower, method) =
            (self.store.clone(), Arc::clone(&self.follower), self.method);
        Box::pin(async move {
            let Value::Object(args) = args else {
                return Err(JmapError::invalid_arguments("arguments must be an object"));
            };
            let account_id = match args.get("accountId") {
                Some(Value::String(id)) => id.clone(),
                _ => return Err(JmapError::invalid_arguments("accountId is required")),
            };
            caller
                .check_account_id(&account_id)
                .map_err(|_| JmapError::account_not_found())?;
            let cx = Cx {
                store: &store,
                follower: &follower,
                owner: lookup_uri(caller.user().as_str(), "userUri").into_owned(),
                account_id,
            };
            let primary = match method {
                Method::Get => cx.get(&args).await?,
                Method::Changes => cx.changes(&args).await?,
                Method::Query => cx.query(&args).await?,
                Method::Set => cx.set(&args).await?,
            };
            Ok(HandlerOutput::new(primary))
        })
    }
}

fn server_fail(error: &(dyn std::error::Error + 'static)) -> JmapError {
    tracing::error!(name: "jmap_consent_failed", error, "Consent method failed");
    JmapError::server_fail("internal error")
}

fn set_error(kind: &str, properties: Option<&[&str]>) -> Value {
    match properties {
        Some(properties) => json!({ "type": kind, "properties": properties }),
        None => json!({ "type": kind }),
    }
}

fn decision_name(decision: Option<ConsentDecision>) -> Value {
    match decision {
        Some(ConsentDecision::Grant) => json!("grant"),
        Some(ConsentDecision::Revoke) => json!("revoke"),
        None => Value::Null,
    }
}

fn object(record: &ConsentRecord) -> Map<String, Value> {
    let mut object = Map::new();
    object.insert("id".into(), json!(record.id));
    object.insert("requesterUri".into(), json!(record.requester_uri));
    object.insert("targetUri".into(), json!(record.target_uri));
    object.insert("roomId".into(), json!(record.room_id));
    object.insert("requested".into(), json!(record.requested));
    object.insert("decision".into(), decision_name(record.decision));
    object.insert("updated".into(), json!(utc_date(record.updated_ms)));
    object
}

fn strings(args: &Map<String, Value>, key: &str) -> Result<Option<Vec<String>>, JmapError> {
    match args.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => serde_json::from_value(value.clone())
            .map(Some)
            .map_err(|_| JmapError::invalid_arguments(format!("{key} must be a string array"))),
    }
}

fn unsigned(args: &Map<String, Value>, key: &str) -> Result<Option<u64>, JmapError> {
    match args.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => value
            .as_u64()
            .map(Some)
            .ok_or_else(|| JmapError::invalid_arguments(format!("{key} must be an UnsignedInt"))),
    }
}

fn or_null(map: Map<String, Value>) -> Value {
    if map.is_empty() {
        Value::Null
    } else {
        Value::Object(map)
    }
}

/// The scope of a create, checked.
struct Scope {
    requester: String,
    target: String,
    room: Option<String>,
}

impl Scope {
    fn key(&self) -> ConsentKey<'_> {
        ConsentKey {
            requester_uri: &self.requester,
            target_uri: &self.target,
            room_id: self.room.as_deref(),
        }
    }
}

/// The record's scope, as a key.
fn key_of(record: &ConsentRecord) -> ConsentKey<'_> {
    ConsentKey {
        requester_uri: &record.requester_uri,
        target_uri: &record.target_uri,
        room_id: record.room_id.as_deref(),
    }
}

/// The property naming the other user of a record whose owner is (or is
/// not) the target.
fn other_property(as_target: bool) -> &'static str {
    if as_target {
        "requesterUri"
    } else {
        "targetUri"
    }
}

/// A delivery failure as a SetError, or a method error for the database.
fn send_error(error: ConsentSendError, as_target: bool) -> Result<Value, JmapError> {
    match error {
        ConsentSendError::Store(error) => Err(server_fail(&error)),
        ConsentSendError::UnknownUser | ConsentSendError::InvalidUri(_) => Ok(set_error(
            "invalidProperties",
            Some(&[other_property(as_target)]),
        )),
        error => {
            tracing::debug!(
                error = &error as &dyn std::error::Error,
                "consent entry not delivered"
            );
            Ok(json!({ "type": "consentNotSent", "description": error.to_string() }))
        }
    }
}

struct Cx<'a> {
    store: &'a Store,
    follower: &'a Follower,
    /// The account's user, in RFC 3986 normal form.
    owner: String,
    account_id: String,
}

impl Cx<'_> {
    async fn state(&self) -> Result<String, JmapError> {
        Ok(self
            .store
            .consent_state(&self.owner)
            .await
            .map_err(|e| server_fail(&e))?
            .to_string())
    }

    async fn records(&self) -> Result<Vec<ConsentRecord>, JmapError> {
        self.store
            .consent_records(&self.owner)
            .await
            .map_err(|e| server_fail(&e))
    }

    async fn get(&self, args: &Map<String, Value>) -> Result<Value, JmapError> {
        let ids = strings(args, "ids")?;
        let properties = strings(args, "properties")?;
        if let Some(unknown) = properties
            .iter()
            .flatten()
            .find(|p| !PROPERTIES.contains(&p.as_str()))
        {
            return Err(JmapError::invalid_arguments(format!(
                "unknown property {unknown}"
            )));
        }
        let state = self.state().await?;
        let records = self.records().await?;
        let keep = |object: Map<String, Value>| -> Value {
            Value::Object(match &properties {
                None => object,
                Some(properties) => object
                    .into_iter()
                    .filter(|(key, _)| key == "id" || properties.contains(key))
                    .collect(),
            })
        };
        let (list, not_found): (Vec<Value>, Vec<String>) = match ids {
            None => (
                records.iter().map(|r| keep(object(r))).collect(),
                Vec::new(),
            ),
            Some(ids) => {
                let mut list = Vec::new();
                let mut not_found = Vec::new();
                let mut seen = std::collections::BTreeSet::new();
                for id in ids {
                    if !seen.insert(id.clone()) {
                        continue;
                    }
                    match records.iter().find(|r| r.id == id) {
                        Some(record) => list.push(keep(object(record))),
                        None => not_found.push(id),
                    }
                }
                (list, not_found)
            }
        };
        Ok(json!({
            "accountId": self.account_id,
            "state": state,
            "list": list,
            "notFound": not_found,
        }))
    }

    async fn changes(&self, args: &Map<String, Value>) -> Result<Value, JmapError> {
        let Some(Value::String(since)) = args.get("sinceState") else {
            return Err(JmapError::invalid_arguments("sinceState is required"));
        };
        let max_changes = unsigned(args, "maxChanges")?;
        if max_changes == Some(0) {
            return Err(JmapError::invalid_arguments("maxChanges must be positive"));
        }
        let since_value = since
            .parse::<u64>()
            .map_err(|_| JmapError::cannot_calculate_changes())?;
        let changes = self
            .store
            .consent_changes(&self.owner, since_value, max_changes)
            .await
            .map_err(|e| server_fail(&e))?
            .ok_or_else(JmapError::cannot_calculate_changes)?;
        Ok(json!({
            "accountId": self.account_id,
            "oldState": since,
            "newState": changes.new_state.to_string(),
            "hasMoreChanges": false,
            "created": changes.created,
            "updated": changes.updated,
            "destroyed": changes.destroyed,
        }))
    }

    async fn query(&self, args: &Map<String, Value>) -> Result<Value, JmapError> {
        // The filter: a FilterCondition of asTarget, requested, decision.
        let mut as_target = None;
        let mut requested = None;
        let mut decision = None;
        match args.get("filter") {
            None | Some(Value::Null) => {}
            Some(Value::Object(filter)) => {
                for (key, value) in filter {
                    match (key.as_str(), value) {
                        ("asTarget", Value::Bool(b)) => as_target = Some(*b),
                        ("requested", Value::Bool(b)) => requested = Some(*b),
                        ("decision", Value::String(d)) if d == "grant" || d == "revoke" => {
                            decision = Some(d.clone());
                        }
                        _ => return Err(JmapError::unsupported_filter()),
                    }
                }
            }
            Some(_) => return Err(JmapError::unsupported_filter()),
        }
        // The sort: `updated` only, ascending by default.
        let mut ascending = true;
        match args.get("sort") {
            None | Some(Value::Null) => {}
            Some(Value::Array(sort)) => {
                for comparator in sort {
                    let Value::Object(comparator) = comparator else {
                        return Err(JmapError::unsupported_sort());
                    };
                    if comparator.get("property") != Some(&json!("updated")) {
                        return Err(JmapError::unsupported_sort());
                    }
                    match comparator.get("isAscending") {
                        None => ascending = true,
                        Some(Value::Bool(b)) => ascending = *b,
                        Some(_) => return Err(JmapError::unsupported_sort()),
                    }
                }
            }
            Some(_) => return Err(JmapError::unsupported_sort()),
        }
        if args.get("anchor").is_some_and(|a| !a.is_null()) {
            return Err(JmapError::invalid_arguments("anchor is not supported"));
        }
        let position = match args.get("position") {
            None | Some(Value::Null) => 0,
            Some(value) => value.as_u64().ok_or_else(|| {
                JmapError::invalid_arguments("position must be a non-negative Int")
            })?,
        };
        let limit = unsigned(args, "limit")?;
        let calculate_total = args.get("calculateTotal") == Some(&Value::Bool(true));

        let state = self.state().await?;
        let mut records: Vec<ConsentRecord> = self
            .records()
            .await?
            .into_iter()
            .filter(|r| as_target.is_none_or(|t| r.as_target() == t))
            .filter(|r| requested.is_none_or(|q| r.requested == q))
            .filter(|r| {
                decision
                    .as_deref()
                    .is_none_or(|d| decision_name(r.decision) == json!(d))
            })
            .collect();
        // consent_records is ordered by updated, then id.
        if !ascending {
            records.reverse();
        }
        let total = records.len();
        let start = usize::try_from(position).unwrap_or(usize::MAX).min(total);
        let ids: Vec<&str> = records[start..]
            .iter()
            .take(limit.map_or(usize::MAX, |l| usize::try_from(l).unwrap_or(usize::MAX)))
            .map(|r| r.id.as_str())
            .collect();
        let mut response = json!({
            "accountId": self.account_id,
            "queryState": state,
            "canCalculateChanges": false,
            "position": start,
            "ids": ids,
        });
        if calculate_total {
            response["total"] = json!(total);
        }
        if let Some(limit) = limit {
            response["limit"] = json!(limit);
        }
        Ok(response)
    }

    /// Checks a create's properties; returns the scope, `requested` and
    /// `decision`, or the SetError.
    fn create_args(&self, create: &Value) -> Result<(Scope, bool, Option<ConsentDecision>), Value> {
        let invalid = |property: &str| set_error("invalidProperties", Some(&[property]));
        let Value::Object(create) = create else {
            return Err(set_error("invalidProperties", None));
        };
        if let Some(other) = create.keys().find(|key| {
            !matches!(
                key.as_str(),
                "requesterUri" | "targetUri" | "roomId" | "requested" | "decision"
            )
        }) {
            return Err(invalid(other));
        }
        let user = |property: &'static str| -> Result<String, Value> {
            let Some(Value::String(text)) = create.get(property) else {
                return Err(invalid(property));
            };
            let uri = lookup_uri(text, property).into_owned();
            // protocol-07 §2.1: a user URI (decision mimid-1wgh.6.76).
            if user_uri_domain(&uri).is_none() {
                return Err(invalid(property));
            }
            Ok(uri)
        };
        let requester = user("requesterUri")?;
        let target = user("targetUri")?;
        let room = match create.get("roomId") {
            None | Some(Value::Null) => None,
            Some(Value::String(text)) if !text.is_empty() => {
                Some(lookup_uri(text, "roomId").into_owned())
            }
            Some(_) => return Err(invalid("roomId")),
        };
        let as_target = target == self.owner;
        if (requester == self.owner) == as_target {
            // Neither or both is the account's user.
            return Err(set_error(
                "invalidProperties",
                Some(&["requesterUri", "targetUri"]),
            ));
        }
        let decision = match create.get("decision") {
            None | Some(Value::Null) => None,
            Some(Value::String(d)) if d == "grant" => Some(ConsentDecision::Grant),
            Some(Value::String(d)) if d == "revoke" => Some(ConsentDecision::Revoke),
            Some(_) => return Err(invalid("decision")),
        };
        let requested = match (as_target, create.get("requested")) {
            // Server-set when the owner is the target.
            (true, Some(_)) => return Err(invalid("requested")),
            (true, None) => false,
            (false, None | Some(Value::Bool(true))) => true,
            (false, Some(_)) => return Err(invalid("requested")),
        };
        match (as_target, decision) {
            // A create as target records a decision; as requester it asks.
            (true, None) | (false, Some(_)) => return Err(invalid("decision")),
            _ => {}
        }
        Ok((
            Scope {
                requester,
                target,
                room,
            },
            requested,
            decision,
        ))
    }

    async fn create_one(&self, create: &Value) -> Result<Result<Value, Value>, JmapError> {
        let (scope, requested, decision) = match self.create_args(create) {
            Ok(parsed) => parsed,
            Err(error) => return Ok(Err(error)),
        };
        let as_target = scope.target == self.owner;
        let key = scope.key();
        let existing = self
            .records()
            .await?
            .into_iter()
            .find(|r| same_scope(&key_of(r), &key));
        if let Some(existing) = existing {
            return Ok(Err(
                json!({ "type": "alreadyExists", "existingId": existing.id }),
            ));
        }
        let operation = match decision {
            Some(ConsentDecision::Revoke) => ConsentOperation::Revoke,
            Some(_) => ConsentOperation::Grant,
            None => ConsentOperation::Request,
        };
        if let Err(error) = self.follower.send_consent(operation, &key).await {
            return send_error(error, as_target).map(Err);
        }
        let now = now_ms();
        match self
            .store
            .create_consent_record(&self.owner, &key, requested, decision, now)
            .await
            .map_err(|e| server_fail(&e))?
        {
            Ok(record) => Ok(Ok(json!({
                "id": record.id,
                "roomId": record.room_id,
                "requested": record.requested,
                "decision": decision_name(record.decision),
                "updated": utc_date(record.updated_ms),
            }))),
            Err(existing_id) => Ok(Err(
                json!({ "type": "alreadyExists", "existingId": existing_id }),
            )),
        }
    }

    async fn update_one(&self, id: &str, patch: &Value) -> Result<Result<Value, Value>, JmapError> {
        let Some(record) = self
            .store
            .consent_record(&self.owner, id)
            .await
            .map_err(|e| server_fail(&e))?
        else {
            return Ok(Err(set_error("notFound", None)));
        };
        let Value::Object(patch) = patch else {
            return Ok(Err(set_error("invalidPatch", None)));
        };
        let as_target = record.as_target();
        let settable = if as_target { "decision" } else { "requested" };
        if let Some(other) = patch.keys().find(|key| key.as_str() != settable) {
            return Ok(Err(set_error("invalidProperties", Some(&[other.as_str()]))));
        }
        let (operation, change) = if as_target {
            let decision = match patch.get("decision") {
                None => return Ok(Ok(Value::Null)),
                Some(Value::Null) => None,
                Some(Value::String(d)) if d == "grant" => Some(ConsentDecision::Grant),
                Some(Value::String(d)) if d == "revoke" => Some(ConsentDecision::Revoke),
                Some(_) => return Ok(Err(set_error("invalidProperties", Some(&["decision"])))),
            };
            let operation = match decision {
                Some(ConsentDecision::Revoke) => Some(ConsentOperation::Revoke),
                Some(_) => Some(ConsentOperation::Grant),
                // Back to the server's own policy: nothing is sent.
                None => None,
            };
            let requested = if decision.is_some() {
                Some(false)
            } else {
                None
            };
            (
                operation,
                ConsentPatch {
                    requested,
                    decision: Some(decision),
                },
            )
        } else {
            let requested = match patch.get("requested") {
                None => return Ok(Ok(Value::Null)),
                Some(Value::Bool(b)) => *b,
                Some(_) => return Ok(Err(set_error("invalidProperties", Some(&["requested"])))),
            };
            let operation = (requested != record.requested).then_some(if requested {
                ConsentOperation::Request
            } else {
                ConsentOperation::Cancel
            });
            (
                operation,
                ConsentPatch {
                    requested: Some(requested),
                    decision: None,
                },
            )
        };
        if let Some(operation) = operation
            && let Err(error) = self
                .follower
                .send_consent(operation, &key_of(&record))
                .await
        {
            return send_error(error, as_target).map(Err);
        }
        let Some(patched) = self
            .store
            .patch_consent_record(&self.owner, id, change, now_ms())
            .await
            .map_err(|e| server_fail(&e))?
        else {
            return Ok(Err(set_error("notFound", None)));
        };
        Ok(Ok(json!({
            "requested": patched.requested,
            "updated": utc_date(patched.updated_ms),
        })))
    }

    async fn destroy_one(&self, id: &str) -> Result<Result<(), Value>, JmapError> {
        let Some(record) = self
            .store
            .consent_record(&self.owner, id)
            .await
            .map_err(|e| server_fail(&e))?
        else {
            return Ok(Err(set_error("notFound", None)));
        };
        if !record.as_target()
            && record.requested
            && let Err(error) = self
                .follower
                .send_consent(ConsentOperation::Cancel, &key_of(&record))
                .await
        {
            return send_error(error, false).map(Err);
        }
        if self
            .store
            .destroy_consent_record(&self.owner, id)
            .await
            .map_err(|e| server_fail(&e))?
        {
            Ok(Ok(()))
        } else {
            Ok(Err(set_error("notFound", None)))
        }
    }

    async fn set(&self, args: &Map<String, Value>) -> Result<Value, JmapError> {
        let old_state = self.state().await?;
        if let Some(expected) = args.get("ifInState")
            && !expected.is_null()
            && expected.as_str() != Some(old_state.as_str())
        {
            return Err(JmapError::state_mismatch());
        }
        let mut created = Map::new();
        let mut not_created = Map::new();
        match args.get("create") {
            None | Some(Value::Null) => {}
            Some(Value::Object(creates)) => {
                for (creation_id, create) in creates {
                    match self.create_one(create).await? {
                        Ok(value) => created.insert(creation_id.clone(), value),
                        Err(error) => not_created.insert(creation_id.clone(), error),
                    };
                }
            }
            Some(_) => return Err(JmapError::invalid_arguments("create must be an object")),
        }
        let mut updated = Map::new();
        let mut not_updated = Map::new();
        match args.get("update") {
            None | Some(Value::Null) => {}
            Some(Value::Object(updates)) => {
                for (id, patch) in updates {
                    match self.update_one(id, patch).await? {
                        Ok(value) => updated.insert(id.clone(), value),
                        Err(error) => not_updated.insert(id.clone(), error),
                    };
                }
            }
            Some(_) => return Err(JmapError::invalid_arguments("update must be an object")),
        }
        let mut destroyed = Vec::new();
        let mut not_destroyed = Map::new();
        for id in strings(args, "destroy")?.into_iter().flatten() {
            match self.destroy_one(&id).await? {
                Ok(()) => destroyed.push(id),
                Err(error) => {
                    not_destroyed.insert(id, error);
                }
            }
        }
        let new_state = self.state().await?;
        Ok(json!({
            "accountId": self.account_id,
            "oldState": old_state,
            "newState": new_state,
            "created": or_null(created),
            "updated": or_null(updated),
            "destroyed": if destroyed.is_empty() { Value::Null } else { json!(destroyed) },
            "notCreated": or_null(not_created),
            "notUpdated": or_null(not_updated),
            "notDestroyed": or_null(not_destroyed),
        }))
    }
}

/// Milliseconds since the UNIX epoch.
fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// Whether two keys name the same ConsentScope.
fn same_scope(a: &ConsentKey<'_>, b: &ConsentKey<'_>) -> bool {
    a.requester_uri == b.requester_uri && a.target_uri == b.target_uri && a.room_id == b.room_id
}
