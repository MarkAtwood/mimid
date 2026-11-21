//! `KeyPackage/get`, `KeyPackage/changes` and `KeyPackage/set`
//! (draft-atwood-jmap-chat-mimi-00 §KeyPackages; bead mimid-1wgh.12.3;
//! `/changes` from findings log F9).
//!
//! A KeyPackage record is one of the account's stored KeyPackages
//! ([`KeyPackages`]). Its `id` and `keyPackageRef` are both the unpadded
//! base64url of the TLS-encoded KeyPackageRef (RFC 9420 §5.2; decision
//! JM-2 of the mimid-1wgh.12 plan), so an id names one KeyPackage for good.
//! `keyPackage` is the unpadded base64url of the KeyPackage as uploaded,
//! and `lastResort` is derived from it.
//!
//! The type's state is the highest number of the account's rows in the
//! KeyPackage change log (`key_package_change`, written by triggers on
//! every store and removal), so it changes when a KeyPackage is created,
//! destroyed, replaced or handed out to a keyMaterial request.
//!
//! `KeyPackage/changes` is standard RFC 8620 §5.2 `/changes` over that
//! log (findings log F9): a KeyPackage handed out, destroyed or replaced
//! is in `destroyed`; one stored and removed again since `sinceState` is
//! left out. With `maxChanges` it returns intermediate states.
//!
//! `KeyPackage/set`:
//!
//! - create: `keyPackage` is required; `lastResort` may be given and must
//!   equal the derived value; any other property is `invalidProperties`.
//!   The KeyPackage must pass [`KeyPackages::upload_key_package_with`]'s
//!   checks, else `invalidProperties` naming `keyPackage`, with a
//!   `description` naming the check that failed (clean-room findings C4,
//!   C5). A last-resort
//!   KeyPackage replaces the client's previous one. Past `maxKeyPackages`,
//!   counted after that replacement (decision mimid-1wgh.12.27), it is
//!   `overQuota`.
//! - update: always `forbidden`.
//! - destroy: removes the KeyPackage; an unknown id is `notFound`.
//!
//! # Limitations
//!
//! - The change log keeps every row; nothing prunes it.
//! - The creates of one call are checked and stored one at a time, not as
//!   one transaction: an earlier create stays stored if a later one fails.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::SystemTime;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jmap_server::{CallContext, HandlerFuture, HandlerOutput, JmapError, JmapHandler};
use mimi_mls::tls_codec::Deserialize;
use mimi_mls::wire::{KeyPackage, KeyPackageError};
use serde_json::{Map, Value, json};

use super::Services;
use crate::follower::key_packages::{KeyPackageEntry, KeyPackages, UploadError};
use crate::jmap::api::Methods;
use crate::jmap::auth::Account;
use crate::jmap::session::MAX_KEY_PACKAGE_LIFETIME;
use crate::store::{InsertOptions, Store};

/// The properties of a KeyPackage record.
const PROPERTIES: &[&str] = &["id", "keyPackage", "keyPackageRef", "lastResort"];

/// Which method a [`Handler`] serves.
#[derive(Clone, Copy)]
enum Method {
    Get,
    Changes,
    Set,
}

/// Registers `KeyPackage/get`, `KeyPackage/changes` and `KeyPackage/set`
/// when the follower holds the local users' KeyPackages.
pub(super) fn register(methods: &mut Methods, services: &Services) {
    let Some(key_packages) = services.follower.key_packages() else {
        return;
    };
    for (name, method) in [
        ("KeyPackage/get", Method::Get),
        ("KeyPackage/changes", Method::Changes),
        ("KeyPackage/set", Method::Set),
    ] {
        methods.add(
            name,
            Arc::new(Handler {
                key_packages: Arc::clone(key_packages),
                store: services.store.clone(),
                max_key_packages: services.max_key_packages,
                method,
            }),
        );
    }
}

struct Handler {
    key_packages: Arc<KeyPackages>,
    store: Store,
    max_key_packages: u64,
    method: Method,
}

impl JmapHandler<Account> for Handler {
    fn call(&self, cx: CallContext<Account>) -> HandlerFuture {
        let CallContext { args, caller, .. } = cx;
        let key_packages = Arc::clone(&self.key_packages);
        let store = self.store.clone();
        let (max, method) = (self.max_key_packages, self.method);
        Box::pin(async move {
            let args = match args {
                Value::Object(args) => args,
                _ => return Err(JmapError::invalid_arguments("arguments must be an object")),
            };
            let account_id = match args.get("accountId") {
                Some(Value::String(id)) => id.clone(),
                _ => return Err(JmapError::invalid_arguments("accountId is required")),
            };
            caller
                .check_account_id(&account_id)
                .map_err(|_| JmapError::account_not_found())?;
            let primary = match method {
                Method::Set => {
                    set_key_packages(&key_packages, &store, &caller, &account_id, &args, max)
                        .await?
                }
                Method::Get => {
                    get_key_packages(&key_packages, &store, &caller, &account_id, &args).await?
                }
                Method::Changes => changes(&store, &caller, &account_id, &args).await?,
            };
            Ok(HandlerOutput::new(primary))
        })
    }
}

fn server_fail(error: &(dyn std::error::Error + 'static)) -> JmapError {
    tracing::error!(
        name: "jmap_key_package_failed",
        error,
        "KeyPackage method failed"
    );
    JmapError::server_fail("internal error")
}

/// The account's stored KeyPackages, with their bytes.
async fn stored(
    key_packages: &KeyPackages,
    caller: &Account,
) -> Result<Vec<(KeyPackageEntry, Vec<u8>)>, JmapError> {
    key_packages
        .list_key_packages_with_bytes(caller.user())
        .await
        .map_err(|e| server_fail(&e))
}

/// The account's KeyPackage state, as `KeyPackage/get` reports it, for
/// EventSource (bead mimid-1wgh.12.40).
///
/// # Errors
///
/// Returns [`crate::store::StoreError`] if the store fails.
pub(crate) async fn key_package_state(
    store: &Store,
    caller: &Account,
) -> Result<String, crate::store::StoreError> {
    Ok(store
        .key_package_modseq(caller.user().as_str())
        .await?
        .to_string())
}

/// The state, or `serverFail`.
async fn state_now(store: &Store, caller: &Account) -> Result<String, JmapError> {
    key_package_state(store, caller)
        .await
        .map_err(|e| server_fail(&e))
}

/// `KeyPackage/changes` (RFC 8620 §5.2; findings log F9).
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
        .key_package_changes(caller.user().as_str(), since_modseq, max_changes)
        .await
        .map_err(|e| server_fail(&e))?
        .ok_or_else(JmapError::cannot_calculate_changes)?;
    let ids = |refs: Vec<Vec<u8>>| -> Vec<String> {
        refs.iter().map(|r| URL_SAFE_NO_PAD.encode(r)).collect()
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

fn object(entry: &KeyPackageEntry, bytes: &[u8]) -> Map<String, Value> {
    let id = URL_SAFE_NO_PAD.encode(&entry.reference);
    let mut object = Map::new();
    object.insert("id".into(), json!(id));
    object.insert("keyPackage".into(), json!(URL_SAFE_NO_PAD.encode(bytes)));
    object.insert("keyPackageRef".into(), json!(id));
    object.insert("lastResort".into(), json!(entry.last_resort));
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

async fn get_key_packages(
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
        .map(|(entry, bytes)| {
            let object = object(entry, bytes);
            (URL_SAFE_NO_PAD.encode(&entry.reference), object)
        })
        .collect();
    let keep = |object: Map<String, Value>| -> Map<String, Value> {
        match &properties {
            None => object,
            Some(properties) => object
                .into_iter()
                .filter(|(key, _)| key == "id" || properties.contains(key))
                .collect(),
        }
    };
    let (list, not_found): (Vec<Value>, Vec<String>) = match ids {
        None => (
            by_id
                .into_values()
                .map(|o| Value::Object(keep(o)))
                .collect(),
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
                match by_id.get(&id) {
                    Some(object) => list.push(Value::Object(keep(object.clone()))),
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

/// A SetError of type `kind`, naming `properties` if given, whose
/// `description` names the check that failed (clean-room finding C5).
fn set_error(kind: &str, properties: Option<&[&str]>, description: &str) -> Value {
    match properties {
        Some(properties) => {
            json!({ "type": kind, "properties": properties, "description": description })
        }
        None => json!({ "type": kind, "description": description }),
    }
}

/// Checks one create's properties; returns the KeyPackage bytes and the
/// claimed `lastResort`, if given.
fn create_args(create: &Value) -> Result<(Vec<u8>, Option<bool>), Value> {
    let Value::Object(create) = create else {
        return Err(set_error(
            "invalidProperties",
            None,
            "a create must be an object",
        ));
    };
    if let Some(other) = create
        .keys()
        .find(|key| !matches!(key.as_str(), "keyPackage" | "lastResort"))
    {
        let other: &str = other;
        return Err(set_error(
            "invalidProperties",
            Some(&[other]),
            "only keyPackage and lastResort may be given",
        ));
    }
    let bytes = match create.get("keyPackage") {
        Some(Value::String(text)) => URL_SAFE_NO_PAD.decode(text).map_err(|_| {
            set_error(
                "invalidProperties",
                Some(&["keyPackage"]),
                "keyPackage is not unpadded base64url",
            )
        })?,
        _ => {
            return Err(set_error(
                "invalidProperties",
                Some(&["keyPackage"]),
                "keyPackage is required and must be a string",
            ));
        }
    };
    let last_resort = match create.get("lastResort") {
        None => None,
        Some(Value::Bool(value)) => Some(*value),
        Some(_) => {
            return Err(set_error(
                "invalidProperties",
                Some(&["lastResort"]),
                "lastResort must be a Boolean",
            ));
        }
    };
    Ok((bytes, last_resort))
}

/// Whether `bytes` is a last-resort KeyPackage, if it decodes and
/// verifies; the full checks are the upload's.
fn derived_last_resort(bytes: &[u8]) -> Option<bool> {
    let key_package = KeyPackage::tls_deserialize_exact(bytes).ok()?;
    key_package
        .verify(SystemTime::now())
        .ok()
        .map(|info| info.is_last_resort())
}

/// One `KeyPackage/set` create of the KeyPackage `bytes`, with the
/// claimed `lastResort` if given, as both bindings call it: the stored
/// entry, or the SetError (`invalidProperties`, `overQuota`).
///
/// # Errors
///
/// `serverFail` if the store fails.
pub(crate) async fn create_one(
    key_packages: &KeyPackages,
    caller: &Account,
    bytes: &[u8],
    claimed: Option<bool>,
    max_key_packages: u64,
) -> Result<Result<KeyPackageEntry, Value>, JmapError> {
    // findings log F10: RFC 8620 §5.3 `tooLarge`.
    if bytes.len() > crate::jmap::MAX_MLS_OBJECT_SIZE {
        return Ok(Err(set_error(
            "tooLarge",
            Some(&["keyPackage"]),
            "keyPackage is larger than maxMlsObjectSize",
        )));
    }
    if let (Some(claimed), Some(derived)) = (claimed, derived_last_resort(bytes))
        && claimed != derived
    {
        return Ok(Err(set_error(
            "invalidProperties",
            Some(&["lastResort"]),
            "lastResort does not match the KeyPackage",
        )));
    }
    let options = InsertOptions {
        replace_last_resort: true,
        max_key_packages: Some(max_key_packages),
        max_clients: key_packages.max_clients(),
    };
    match key_packages
        .upload_key_package_with(caller.user(), bytes, options)
        .await
    {
        Ok(entry) => Ok(Ok(entry)),
        // §KeyPackage/set: past maxKeyPackages, or a new signature key past
        // maxClients (bead mimid-e64f.22).
        Err(UploadError::OverQuota) => Ok(Err(set_error(
            "overQuota",
            None,
            &format!("the account would have more than maxKeyPackages ({max_key_packages})"),
        ))),
        Err(UploadError::TooManyClients) => Ok(Err(set_error(
            "overQuota",
            None,
            "the signature key is new and maxClients keys are already bound",
        ))),
        Err(UploadError::Store(error)) => Err(server_fail(&error)),
        Err(error) => {
            tracing::debug!(
                error = &error as &dyn std::error::Error,
                "KeyPackage create refused"
            );
            Ok(Err(set_error(
                "invalidProperties",
                Some(&["keyPackage"]),
                &upload_refusal(&error),
            )))
        }
    }
}

/// The `description` of a refused upload (draft-atwood-jmap-chat-mimi-00
/// §capability: a server MAY say which check failed; clean-room finding
/// C5): the error and its sources, or, for a lifetime past
/// `maxKeyPackageLifetime`, that limit (clean-room finding C4).
fn upload_refusal(error: &UploadError) -> String {
    if let UploadError::Invalid(KeyPackageError::LifetimeTooLong) = error {
        return format!(
            "the KeyPackage's leaf node lifetime is longer than maxKeyPackageLifetime \
             ({MAX_KEY_PACKAGE_LIFETIME} seconds)"
        );
    }
    crate::jmap::error_chain(error)
}

/// One `KeyPackage/set` destroy of the KeyPackage whose TLS-encoded
/// KeyPackageRef is `reference`, as both bindings call it: whether there
/// was one.
///
/// # Errors
///
/// `serverFail` if the store fails.
pub(crate) async fn destroy_one(
    key_packages: &KeyPackages,
    caller: &Account,
    reference: &[u8],
) -> Result<bool, JmapError> {
    key_packages
        .delete_key_package(caller.user(), reference)
        .await
        .map_err(|e| server_fail(&e))
}

/// `KeyPackage/get` of every record, as both bindings call it: the state
/// and each entry with its bytes. The state is read first, so a change
/// between the two reads comes again from `/changes` rather than being
/// missed.
///
/// # Errors
///
/// `serverFail` if the store fails.
pub(crate) async fn list(
    key_packages: &KeyPackages,
    store: &Store,
    caller: &Account,
) -> Result<(String, Vec<(KeyPackageEntry, Vec<u8>)>), JmapError> {
    let state = state_now(store, caller).await?;
    let entries = stored(key_packages, caller).await?;
    Ok((state, entries))
}

async fn set_key_packages(
    key_packages: &KeyPackages,
    store: &Store,
    caller: &Account,
    account_id: &str,
    args: &Map<String, Value>,
    max_key_packages: u64,
) -> Result<Value, JmapError> {
    let old_state = state_now(store, caller).await?;
    if let Some(expected) = args.get("ifInState")
        && !expected.is_null()
        && expected.as_str() != Some(old_state.as_str())
    {
        return Err(JmapError::state_mismatch());
    }
    let mut created = Map::new();
    let mut not_created = Map::new();
    if let Some(creates) = args.get("create").filter(|v| !v.is_null()) {
        let Value::Object(creates) = creates else {
            return Err(JmapError::invalid_arguments("create must be an object"));
        };
        for (creation_id, create) in creates {
            let (bytes, claimed) = match create_args(create) {
                Ok(parsed) => parsed,
                Err(error) => {
                    not_created.insert(creation_id.clone(), error);
                    continue;
                }
            };
            match create_one(key_packages, caller, &bytes, claimed, max_key_packages).await? {
                Ok(entry) => {
                    let id = URL_SAFE_NO_PAD.encode(&entry.reference);
                    created.insert(
                        creation_id.clone(),
                        json!({ "id": id, "keyPackageRef": id, "lastResort": entry.last_resort }),
                    );
                }
                Err(error) => {
                    not_created.insert(creation_id.clone(), error);
                }
            }
        }
    }

    let mut not_updated = Map::new();
    if let Some(Value::Object(updates)) = args.get("update") {
        for id in updates.keys() {
            not_updated.insert(
                id.clone(),
                set_error("forbidden", None, "KeyPackage records cannot be updated"),
            );
        }
    }

    let mut destroyed = Vec::new();
    let mut not_destroyed = Map::new();
    for id in strings(args, "destroy")?.into_iter().flatten() {
        let deleted = match URL_SAFE_NO_PAD.decode(&id) {
            Ok(reference) => destroy_one(key_packages, caller, &reference).await?,
            Err(_) => false,
        };
        if deleted {
            destroyed.push(id);
        } else {
            not_destroyed.insert(
                id,
                set_error(
                    "notFound",
                    None,
                    "no KeyPackage of this account has this id",
                ),
            );
        }
    }

    let new_state = state_now(store, caller).await?;
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
        "created": or_null(created),
        "updated": Value::Null,
        "destroyed": if destroyed.is_empty() { Value::Null } else { json!(destroyed) },
        "notCreated": or_null(not_created),
        "notUpdated": or_null(not_updated),
        "notDestroyed": or_null(not_destroyed),
    }))
}
