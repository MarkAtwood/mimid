//! `KeyPackage/get` and `KeyPackage/set` (draft-atwood-jmap-chat-mimi-00
//! §KeyPackages; bead mimid-1wgh.12.3).
//!
//! A KeyPackage record is one of the account's stored KeyPackages
//! ([`KeyPackages`]). Its `id` and `keyPackageRef` are both the unpadded
//! base64url of the TLS-encoded KeyPackageRef (RFC 9420 §5.2; decision
//! JM-2 of the mimid-1wgh.12 plan), so an id names one KeyPackage for good.
//! `keyPackage` is the unpadded base64url of the KeyPackage as uploaded,
//! and `lastResort` is derived from it.
//!
//! The type's state is a digest of the account's stored KeyPackageRefs, so
//! it changes when a KeyPackage is created, destroyed, replaced or handed
//! out to a keyMaterial request.
//!
//! `KeyPackage/set`:
//!
//! - create: `keyPackage` is required; `lastResort` may be given and must
//!   equal the derived value; any other property is `invalidProperties`.
//!   The KeyPackage must pass [`KeyPackages::upload_key_package_with`]'s
//!   checks, else `invalidProperties` naming `keyPackage`. A last-resort
//!   KeyPackage replaces the client's previous one. Past `maxKeyPackages`,
//!   counted after that replacement (decision mimid-1wgh.12.27), it is
//!   `overQuota`.
//! - update: always `forbidden`.
//! - destroy: removes the KeyPackage; an unknown id is `notFound`.
//!
//! # Limitations
//!
//! - There is no `KeyPackage/changes`, so the state is not pushed through
//!   EventSource; a client re-reads with `KeyPackage/get`.
//! - The creates of one call are checked and stored one at a time, not as
//!   one transaction: an earlier create stays stored if a later one fails.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::SystemTime;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jmap_server::{CallContext, HandlerFuture, HandlerOutput, JmapError, JmapHandler};
use mimi_mls::tls_codec::Deserialize;
use mimi_mls::wire::KeyPackage;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use super::Services;
use crate::follower::key_packages::{KeyPackageEntry, KeyPackages, UploadError};
use crate::jmap::api::Methods;
use crate::jmap::auth::Account;
use crate::store::InsertOptions;

/// The properties of a KeyPackage record.
const PROPERTIES: &[&str] = &["id", "keyPackage", "keyPackageRef", "lastResort"];

/// Registers `KeyPackage/get` and `KeyPackage/set` when the follower holds
/// the local users' KeyPackages.
pub(super) fn register(methods: &mut Methods, services: &Services) {
    let Some(key_packages) = services.follower.key_packages() else {
        return;
    };
    for (method, set) in [("KeyPackage/get", false), ("KeyPackage/set", true)] {
        methods.add(
            method,
            Arc::new(Handler {
                key_packages: Arc::clone(key_packages),
                max_key_packages: services.max_key_packages,
                set,
            }),
        );
    }
}

struct Handler {
    key_packages: Arc<KeyPackages>,
    max_key_packages: u64,
    set: bool,
}

impl JmapHandler<Account> for Handler {
    fn call(&self, cx: CallContext<Account>) -> HandlerFuture {
        let CallContext { args, caller, .. } = cx;
        let key_packages = Arc::clone(&self.key_packages);
        let (max, set) = (self.max_key_packages, self.set);
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
            let primary = if set {
                set_key_packages(&key_packages, &caller, &account_id, &args, max).await?
            } else {
                get_key_packages(&key_packages, &caller, &account_id, &args).await?
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

/// The state: a digest of the stored KeyPackageRefs, in order.
fn state_of(entries: &[(KeyPackageEntry, Vec<u8>)]) -> String {
    let mut refs: Vec<&[u8]> = entries
        .iter()
        .map(|(e, _)| e.reference.as_slice())
        .collect();
    refs.sort_unstable();
    let mut digest = Sha256::new();
    for reference in refs {
        digest.update(
            u32::try_from(reference.len())
                .unwrap_or(u32::MAX)
                .to_be_bytes(),
        );
        digest.update(reference);
    }
    digest.finalize()[..8]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
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
    let entries = stored(key_packages, caller).await?;
    let state = state_of(&entries);
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

fn set_error(kind: &str, properties: Option<&[&str]>) -> Value {
    match properties {
        Some(properties) => json!({ "type": kind, "properties": properties }),
        None => json!({ "type": kind }),
    }
}

/// Checks one create's properties; returns the KeyPackage bytes and the
/// claimed `lastResort`, if given.
fn create_args(create: &Value) -> Result<(Vec<u8>, Option<bool>), Value> {
    let Value::Object(create) = create else {
        return Err(set_error("invalidProperties", None));
    };
    if let Some(other) = create
        .keys()
        .find(|key| !matches!(key.as_str(), "keyPackage" | "lastResort"))
    {
        let other: &str = other;
        return Err(set_error("invalidProperties", Some(&[other])));
    }
    let bytes = match create.get("keyPackage") {
        Some(Value::String(text)) => URL_SAFE_NO_PAD
            .decode(text)
            .map_err(|_| set_error("invalidProperties", Some(&["keyPackage"])))?,
        _ => return Err(set_error("invalidProperties", Some(&["keyPackage"]))),
    };
    let last_resort = match create.get("lastResort") {
        None => None,
        Some(Value::Bool(value)) => Some(*value),
        Some(_) => return Err(set_error("invalidProperties", Some(&["lastResort"]))),
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

async fn set_key_packages(
    key_packages: &KeyPackages,
    caller: &Account,
    account_id: &str,
    args: &Map<String, Value>,
    max_key_packages: u64,
) -> Result<Value, JmapError> {
    let old_state = state_of(&stored(key_packages, caller).await?);
    if let Some(expected) = args.get("ifInState")
        && !expected.is_null()
        && expected.as_str() != Some(old_state.as_str())
    {
        return Err(JmapError::state_mismatch());
    }
    let options = InsertOptions {
        replace_last_resort: true,
        max_key_packages: Some(max_key_packages),
    };

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
            if let (Some(claimed), Some(derived)) = (claimed, derived_last_resort(&bytes))
                && claimed != derived
            {
                not_created.insert(
                    creation_id.clone(),
                    set_error("invalidProperties", Some(&["lastResort"])),
                );
                continue;
            }
            match key_packages
                .upload_key_package_with(caller.user(), &bytes, options)
                .await
            {
                Ok(entry) => {
                    let id = URL_SAFE_NO_PAD.encode(&entry.reference);
                    created.insert(
                        creation_id.clone(),
                        json!({ "id": id, "keyPackageRef": id, "lastResort": entry.last_resort }),
                    );
                }
                Err(UploadError::OverQuota) => {
                    not_created.insert(creation_id.clone(), set_error("overQuota", None));
                }
                Err(UploadError::Store(error)) => return Err(server_fail(&error)),
                Err(error) => {
                    tracing::debug!(
                        error = &error as &dyn std::error::Error,
                        "KeyPackage create refused"
                    );
                    not_created.insert(
                        creation_id.clone(),
                        set_error("invalidProperties", Some(&["keyPackage"])),
                    );
                }
            }
        }
    }

    let mut not_updated = Map::new();
    if let Some(Value::Object(updates)) = args.get("update") {
        for id in updates.keys() {
            not_updated.insert(id.clone(), set_error("forbidden", None));
        }
    }

    let mut destroyed = Vec::new();
    let mut not_destroyed = Map::new();
    for id in strings(args, "destroy")?.into_iter().flatten() {
        let deleted = match URL_SAFE_NO_PAD.decode(&id) {
            Ok(reference) => key_packages
                .delete_key_package(caller.user(), &reference)
                .await
                .map_err(|e| server_fail(&e))?,
            Err(_) => false,
        };
        if deleted {
            destroyed.push(id);
        } else {
            not_destroyed.insert(id, set_error("notFound", None));
        }
    }

    let new_state = state_of(&stored(key_packages, caller).await?);
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
