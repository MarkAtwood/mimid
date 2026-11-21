//! `Client/get`, `Client/changes` and `Client/set`
//! (draft-atwood-jmap-chat-mimi-00 §Clients, jmap-chat-spec bde5330; bead
//! mimid-e64f.22).
//!
//! A Client record is one signature key bound to the account
//! ([`KeyPackages::clients`]). Its `id` is the base32 of the SHA-256 of
//! the key, the last segment of the client URI mimid gives the client
//! ([`client_record_id`]; decision mimid-1wgh.7.8), and `signatureKey` the
//! unpadded base64url of the TLS-encoded SignaturePublicKey (RFC 9420
//! §5.1.1; the draft's byte-string rule, §Conventions).
//!
//! The type's state is the highest number of the account's rows in the
//! client change log (`client_change`, written by triggers when a key is
//! bound or unbound), and `Client/changes` is standard RFC 8620 §5.2 over
//! it, with intermediate states for `maxChanges`.
//!
//! `Client/set`: create and update are always `forbidden`; destroy unbinds
//! the key ([`KeyPackages::unbind_client`]): its KeyPackages are destroyed
//! and it no longer counts toward `maxClients` or passes Room/create's
//! check. An unknown id is `notFound`.
//!
//! # Limitations
//!
//! - The change log keeps every row; nothing prunes it.
//! - A key bound before migration 0015 has no stored key and is not
//!   listed.

use std::collections::BTreeMap;
use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jmap_server::{CallContext, HandlerFuture, HandlerOutput, JmapError, JmapHandler};
use mimi_mls::tls_codec::{Serialize, VLBytes};
use serde_json::{Map, Value, json};

use super::Services;
use crate::follower::key_packages::{KeyPackages, client_record_id};
use crate::jmap::api::Methods;
use crate::jmap::auth::Account;
use crate::store::Store;

/// The properties of a Client record.
const PROPERTIES: &[&str] = &["id", "signatureKey"];

/// One Client record as both bindings show it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ClientEntry {
    /// `id`.
    pub(crate) id: String,
    /// The TLS-encoded SignaturePublicKey.
    pub(crate) signature_key: Vec<u8>,
}

#[derive(Clone, Copy)]
enum Method {
    Get,
    Changes,
    Set,
}

/// Registers `Client/get`, `Client/changes` and `Client/set` when the
/// follower holds the local users' KeyPackages, which bind the keys.
pub(super) fn register(methods: &mut Methods, services: &Services) {
    let Some(key_packages) = services.follower.key_packages() else {
        return;
    };
    for (name, method) in [
        ("Client/get", Method::Get),
        ("Client/changes", Method::Changes),
        ("Client/set", Method::Set),
    ] {
        methods.add(
            name,
            Arc::new(Handler {
                key_packages: Arc::clone(key_packages),
                store: services.store.clone(),
                method,
            }),
        );
    }
}

struct Handler {
    key_packages: Arc<KeyPackages>,
    store: Store,
    method: Method,
}

impl JmapHandler<Account> for Handler {
    fn call(&self, cx: CallContext<Account>) -> HandlerFuture {
        let CallContext { args, caller, .. } = cx;
        let key_packages = Arc::clone(&self.key_packages);
        let store = self.store.clone();
        let method = self.method;
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
            let primary = match method {
                Method::Get => get(&key_packages, &store, &caller, &account_id, &args).await?,
                Method::Changes => changes(&store, &caller, &account_id, &args).await?,
                Method::Set => set(&key_packages, &store, &caller, &account_id, &args).await?,
            };
            Ok(HandlerOutput::new(primary))
        })
    }
}

fn server_fail(error: &(dyn std::error::Error + 'static)) -> JmapError {
    tracing::error!(name: "jmap_client_failed", error, "Client method failed");
    JmapError::server_fail("internal error")
}

/// The account's Client state, as `Client/get` reports it.
///
/// # Errors
///
/// Returns [`crate::store::StoreError`] if the store fails.
pub(crate) async fn client_state(
    store: &Store,
    caller: &Account,
) -> Result<String, crate::store::StoreError> {
    Ok(store
        .client_modseq(caller.user().as_str())
        .await?
        .to_string())
}

/// `Client/get` of every record, as both bindings call it: the state and
/// the records. The state is read first, so a change between the two
/// reads comes again from `/changes`.
///
/// # Errors
///
/// `serverFail` if the store fails.
pub(crate) async fn list(
    key_packages: &KeyPackages,
    store: &Store,
    caller: &Account,
) -> Result<(String, Vec<ClientEntry>), JmapError> {
    let state = client_state(store, caller)
        .await
        .map_err(|e| server_fail(&e))?;
    let rows = key_packages
        .clients(caller.user())
        .await
        .map_err(|e| server_fail(&e))?;
    let entries = rows
        .into_iter()
        .map(|row| {
            let signature_key = VLBytes::new(row.signature_key)
                .tls_serialize_detached()
                .map_err(|e| server_fail(&e))?;
            Ok(ClientEntry {
                id: client_record_id(&row.client_id).to_owned(),
                signature_key,
            })
        })
        .collect::<Result<_, JmapError>>()?;
    Ok((state, entries))
}

/// One `Client/set` destroy of record `id`, as both bindings call it:
/// whether there was one.
///
/// # Errors
///
/// `serverFail` if the store fails.
pub(crate) async fn destroy_one(
    key_packages: &KeyPackages,
    caller: &Account,
    id: &str,
) -> Result<bool, JmapError> {
    // Only Id characters reach the store; anything else names no record.
    if id.is_empty() || !id.bytes().all(|b| b.is_ascii_alphanumeric()) {
        return Ok(false);
    }
    key_packages
        .unbind_client(caller.user(), &key_packages.client_uri_of_record(id))
        .await
        .map_err(|e| server_fail(&e))
}

fn object(entry: &ClientEntry) -> Map<String, Value> {
    let mut object = Map::new();
    object.insert("id".into(), json!(entry.id));
    object.insert(
        "signatureKey".into(),
        json!(URL_SAFE_NO_PAD.encode(&entry.signature_key)),
    );
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

async fn get(
    key_packages: &KeyPackages,
    store: &Store,
    caller: &Account,
    account_id: &str,
    args: &Map<String, Value>,
) -> Result<Value, JmapError> {
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
    let (state, entries) = list(key_packages, store, caller).await?;
    let by_id: BTreeMap<String, Map<String, Value>> = entries
        .iter()
        .map(|entry| (entry.id.clone(), object(entry)))
        .collect();
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
        None => (by_id.into_values().map(keep).collect(), Vec::new()),
        Some(ids) => {
            let mut list = Vec::new();
            let mut not_found = Vec::new();
            let mut seen = std::collections::BTreeSet::new();
            for id in ids {
                if !seen.insert(id.clone()) {
                    continue;
                }
                match by_id.get(&id) {
                    Some(object) => list.push(keep(object.clone())),
                    None => not_found.push(id),
                }
            }
            (list, not_found)
        }
    };
    Ok(json!({
        "accountId": account_id,
        "state": state,
        "list": list,
        "notFound": not_found,
    }))
}

/// `Client/changes` (RFC 8620 §5.2).
async fn changes(
    store: &Store,
    caller: &Account,
    account_id: &str,
    args: &Map<String, Value>,
) -> Result<Value, JmapError> {
    let Some(Value::String(since)) = args.get("sinceState") else {
        return Err(JmapError::invalid_arguments("sinceState is required"));
    };
    let max_changes = match args.get("maxChanges") {
        None | Some(Value::Null) => None,
        Some(value) => match value.as_u64() {
            Some(max) if max > 0 => Some(max),
            _ => {
                return Err(JmapError::invalid_arguments(
                    "maxChanges must be a positive integer",
                ));
            }
        },
    };
    let since_modseq = since
        .parse::<u64>()
        .ok()
        .filter(|_| !since.is_empty() && since.bytes().all(|b| b.is_ascii_digit()))
        .ok_or_else(JmapError::cannot_calculate_changes)?;
    let found = store
        .client_changes(caller.user().as_str(), since_modseq, max_changes)
        .await
        .map_err(|e| server_fail(&e))?
        .ok_or_else(JmapError::cannot_calculate_changes)?;
    let ids = |clients: Vec<String>| -> Vec<String> {
        clients
            .iter()
            .map(|client| client_record_id(client).to_owned())
            .collect()
    };
    Ok(json!({
        "accountId": account_id,
        "oldState": since,
        "newState": found.new_modseq.to_string(),
        "hasMoreChanges": found.has_more,
        "created": ids(found.created),
        "updated": ids(found.updated),
        "destroyed": ids(found.destroyed),
    }))
}

/// A SetError of type `kind` whose `description` names the check that
/// failed (clean-room finding C5).
fn set_error(kind: &str, description: &str) -> Value {
    json!({ "type": kind, "description": description })
}

async fn set(
    key_packages: &KeyPackages,
    store: &Store,
    caller: &Account,
    account_id: &str,
    args: &Map<String, Value>,
) -> Result<Value, JmapError> {
    let state_now = || async {
        client_state(store, caller)
            .await
            .map_err(|e| server_fail(&e))
    };
    let old_state = state_now().await?;
    if let Some(expected) = args.get("ifInState")
        && !expected.is_null()
        && expected.as_str() != Some(old_state.as_str())
    {
        return Err(JmapError::state_mismatch());
    }
    let refused = |key: &str| -> Map<String, Value> {
        match args.get(key) {
            Some(Value::Object(map)) => map
                .keys()
                .map(|id| {
                    (
                        id.clone(),
                        set_error("forbidden", "Client records can only be destroyed"),
                    )
                })
                .collect(),
            _ => Map::new(),
        }
    };
    // §Client/set: only destroy is supported.
    let not_created = refused("create");
    let not_updated = refused("update");
    let mut destroyed = Vec::new();
    let mut not_destroyed = Map::new();
    for id in strings(args, "destroy")?.into_iter().flatten() {
        if destroy_one(key_packages, caller, &id).await? {
            destroyed.push(id);
        } else {
            not_destroyed.insert(
                id,
                set_error("notFound", "no Client record of this account has this id"),
            );
        }
    }
    let new_state = state_now().await?;
    let or_null = |map: Map<String, Value>| {
        if map.is_empty() {
            Value::Null
        } else {
            Value::Object(map)
        }
    };
    Ok(json!({
        "accountId": account_id,
        "oldState": old_state,
        "newState": new_state,
        "created": Value::Null,
        "updated": Value::Null,
        "destroyed": if destroyed.is_empty() { Value::Null } else { json!(destroyed) },
        "notCreated": or_null(not_created),
        "notUpdated": or_null(not_updated),
        "notDestroyed": or_null(not_destroyed),
    }))
}
