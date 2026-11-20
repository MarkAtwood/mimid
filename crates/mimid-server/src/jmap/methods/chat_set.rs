//! `Chat/set` (draft-atwood-jmap-chat-00 §Chat/set; decisions
//! mimid-1wgh.12.22, mimid-1wgh.63).
//!
//! Every Chat is roomed, and its name, members and metadata are MLS group
//! state (draft-atwood-jmap-chat-mimi-00 §Chat.roomId), so every create and
//! destroy, and every update of any other property, is refused with
//! `forbidden`. An update whose keys are all `privateMetadata` or its
//! PatchObject paths is applied (draft-ietf-jmap-metadata-05 §3.2), in the
//! order §3.2 gives:
//!
//! 1. without `urn:ietf:params:jmap:metadata` in `using`,
//!    `invalidProperties` (§3);
//! 2. a patch error the request alone shows, `invalidPatch`;
//! 3. a Chat the account does not have, `notFound`; a write to shared
//!    `metadata`, `forbidden` (decision mimid-1wgh.63 item 2);
//! 4. an unsupported or invalid namespace, `invalidProperties`
//!    ([`check_metadata_write`]); a missing parent or a path through a
//!    non-object, `invalidPatch`; too deep a value or a malformed Binary,
//!    `invalidProperties` ([`check_metadata_depth`]);
//! 5. more than [`MAX_CHAT_PRIVATE_METADATA_LEN`] octets, `overQuota`.
//!
//! # Limitations
//!
//! - The per-user updates base L1026 allows (`muted`, `muteUntil`,
//!   `receiveTypingIndicators`, `messageExpirySeconds`, `receiptSharing`)
//!   and `pinnedMessageIds` are refused (decisions mimid-1wgh.12.22,
//!   mimid-1wgh.12.29).
//! - A Chat cannot be destroyed (base §Destroying a Chat).
//! - An update that mixes `privateMetadata` with other properties is
//!   refused whole with `forbidden`.

use std::collections::BTreeMap;
use std::sync::Arc;

use jmap_metadata_server::{
    InvalidMetadataWrite, SetKind, check_metadata_depth, check_metadata_write,
};
use jmap_metadata_types::DataTypeMetadataInfo;
use jmap_server::{CallContext, HandlerFuture, HandlerOutput, JmapError, JmapHandler};
use serde_json::{Map, Value, json};

use super::Services;
use crate::jmap::api::Methods;
use crate::jmap::auth::Account;
use crate::jmap::bus::{Change, ChangeBus};
use crate::jmap::metadata::{
    self, InvalidPatch, MAX_CHAT_PRIVATE_METADATA_LEN, PRIVATE_METADATA, check_patch_shape,
};
use crate::jmap::projection::Projection;
use crate::store::{MetadataUpdate, Store};

/// Registers `Chat/set`.
pub(super) fn register(methods: &mut Methods, services: &Services) {
    methods.add(
        "Chat/set",
        Arc::new(Handler {
            projection: Arc::clone(&services.projection),
            store: services.store.clone(),
            bus: services.bus.clone(),
        }),
    );
}

struct Handler {
    projection: Arc<Projection>,
    store: Store,
    bus: ChangeBus,
}

impl JmapHandler<Account> for Handler {
    fn call(&self, cx: CallContext<Account>) -> HandlerFuture {
        let CallContext { args, caller, .. } = cx;
        let (projection, store, bus) = (
            Arc::clone(&self.projection),
            self.store.clone(),
            self.bus.clone(),
        );
        Box::pin(async move {
            chat_set(&projection, &store, &bus, args, &caller)
                .await
                .map(HandlerOutput::new)
        })
    }
}

fn set_error(kind: &str) -> Value {
    json!({"type": kind})
}

fn invalid_properties(error: &InvalidMetadataWrite) -> Value {
    json!({
        "type": "invalidProperties",
        "properties": [error.property()],
        "description": error.description(),
    })
}

fn invalid_patch(error: &InvalidPatch) -> Value {
    json!({"type": "invalidPatch", "description": error.0})
}

/// `serverFail` for an internal failure, logged here because its text
/// does not reach the client.
fn server_fail(error: &(dyn std::error::Error + 'static)) -> JmapError {
    tracing::error!(
        name: "jmap_chat_set_failed",
        error,
        "Chat/set failed: internal error"
    );
    JmapError::server_fail("internal error")
}

async fn chat_set(
    projection: &Projection,
    store: &Store,
    bus: &ChangeBus,
    args: Value,
    account: &Account,
) -> Result<Value, JmapError> {
    let Value::Object(args) = args else {
        return Err(JmapError::invalid_arguments("arguments must be an object"));
    };
    let account_id = match args.get("accountId") {
        Some(Value::String(account_id)) => account_id.clone(),
        _ => return Err(JmapError::invalid_arguments("accountId is required")),
    };
    account
        .check_account_id(&account_id)
        .map_err(|_| JmapError::account_not_found())?;
    let object = |key: &str| match args.get(key) {
        None | Some(Value::Null) => Ok(Map::new()),
        Some(Value::Object(map)) => Ok(map.clone()),
        Some(_) => Err(JmapError::invalid_arguments(format!(
            "{key} must be an object"
        ))),
    };
    let create = object("create")?;
    let update = object("update")?;
    let destroy: Vec<String> = match args.get("destroy") {
        None | Some(Value::Null) => Vec::new(),
        Some(value) => serde_json::from_value(value.clone())
            .map_err(|_| JmapError::invalid_arguments("destroy must be an Id array"))?,
    };
    let mut patches = Vec::with_capacity(update.len());
    for (id, patch) in &update {
        let Value::Object(patch) = patch else {
            return Err(JmapError::invalid_arguments(
                "an update must be a PatchObject",
            ));
        };
        patches.push((id.clone(), patch));
    }
    let (old_state, found) = projection
        .chat_ids(account)
        .await
        .map_err(|e| server_fail(&e))?;
    match args.get("ifInState") {
        None | Some(Value::Null) => {}
        Some(Value::String(expected)) if *expected == old_state => {}
        Some(Value::String(_)) => return Err(JmapError::state_mismatch()),
        Some(_) => return Err(JmapError::invalid_arguments("ifInState must be a string")),
    }
    let refused = |id: &String| {
        if found.contains(id) {
            set_error("forbidden")
        } else {
            set_error("notFound")
        }
    };
    let info = metadata::chat_info();
    let mut updated = BTreeMap::new();
    let mut not_updated = BTreeMap::new();
    let mut written = false;
    for (id, patch) in patches {
        match update_one(store, account, &found, &info, &id, patch).await? {
            Ok(changed) => {
                written |= changed;
                updated.insert(id, Value::Null);
            }
            Err(error) => {
                not_updated.insert(id, error);
            }
        }
    }
    let new_state = if written {
        bus.publish(Change::ChatMetadata {
            user_uri: account.user().as_str().to_owned(),
        });
        projection
            .chat_ids(account)
            .await
            .map_err(|e| server_fail(&e))?
            .0
    } else {
        old_state.clone()
    };
    let not_created: BTreeMap<String, Value> = create
        .keys()
        .map(|key| (key.clone(), set_error("forbidden")))
        .collect();
    let not_destroyed: BTreeMap<String, Value> =
        destroy.iter().map(|id| (id.clone(), refused(id))).collect();
    let or_null = |map: BTreeMap<String, Value>| {
        if map.is_empty() {
            Value::Null
        } else {
            json!(map)
        }
    };
    Ok(json!({
        "accountId": account_id,
        "oldState": old_state,
        "newState": new_state,
        "created": null,
        "updated": or_null(updated),
        "destroyed": null,
        "notCreated": or_null(not_created),
        "notUpdated": or_null(not_updated),
        "notDestroyed": or_null(not_destroyed),
    }))
}

/// One `Chat/set` update of Chat `id` with `patch`, among the account's
/// Chats `found`: whether it wrote anything, or the SetError.
async fn update_one(
    store: &Store,
    account: &Account,
    found: &std::collections::BTreeSet<String>,
    info: &DataTypeMetadataInfo,
    id: &str,
    patch: &Map<String, Value>,
) -> Result<Result<bool, Value>, JmapError> {
    let refused = || {
        if found.contains(id) {
            set_error("forbidden")
        } else {
            set_error("notFound")
        }
    };
    if patch.is_empty() || patch.keys().any(|key| metadata::root(key).is_none()) {
        return Ok(Err(refused()));
    }
    // draft-ietf-jmap-metadata-05 §3: without the capability "Foo/set
    // MUST reject any write to them with an "invalidProperties"
    // SetError".
    if !account.metadata() {
        return Ok(Err(json!({
            "type": "invalidProperties",
            "properties": patch.keys().collect::<Vec<_>>(),
            "description": "the request does not use urn:ietf:params:jmap:metadata",
        })));
    }
    if let Err(error) = check_patch_shape(patch) {
        return Ok(Err(invalid_patch(&error)));
    }
    if !found.contains(id) {
        return Ok(Err(set_error("notFound")));
    }
    if patch
        .keys()
        .any(|key| metadata::root(key) == Some(metadata::METADATA))
    {
        // Decision mimid-1wgh.63 item 2.
        return Ok(Err(set_error("forbidden")));
    }
    let outcome = store
        .update_chat_private_metadata(account.user().as_str(), id, |stored| {
            change(stored, patch, info)
        })
        .await
        .map_err(|e| server_fail(&e))?;
    Ok(match outcome {
        MetadataUpdate::Written => Ok(true),
        MetadataUpdate::Unchanged => Ok(false),
        MetadataUpdate::Refused(error) => Err(error),
        // Gone since `found` was read, or a variant added later.
        _ => Err(set_error("notFound")),
    })
}

/// One `Chat/set` update of the privateMetadata of Chat `id` with
/// `patch`, as both bindings call it: the same checks and write as a
/// `Chat/set` with that one update, `Ok(())` or the SetError.
///
/// # Errors
///
/// `serverFail` if the store fails.
pub(crate) async fn update_private_metadata(
    projection: &Projection,
    store: &Store,
    bus: &ChangeBus,
    account: &Account,
    id: &str,
    patch: &Map<String, Value>,
) -> Result<Result<(), Value>, JmapError> {
    let (_, found) = projection
        .chat_ids(account)
        .await
        .map_err(|e| server_fail(&e))?;
    let outcome = update_one(store, account, &found, &metadata::chat_info(), id, patch).await?;
    if outcome == Ok(true) {
        bus.publish(Change::ChatMetadata {
            user_uri: account.user().as_str().to_owned(),
        });
    }
    Ok(outcome.map(drop))
}

/// The new stored privateMetadata for `patch` over `stored`, `None` if it
/// is unchanged, or the SetError (module docs, steps 4 and 5).
fn change(
    stored: Option<&str>,
    patch: &Map<String, Value>,
    info: &DataTypeMetadataInfo,
) -> Result<Option<String>, Value> {
    let current: Map<String, Value> = match stored {
        None => Map::new(),
        // The schema stores only JSON objects.
        Some(text) => serde_json::from_str(text).map_err(|_| set_error("serverFail"))?,
    };
    let before = Map::from_iter([(PRIVATE_METADATA.to_owned(), Value::Object(current.clone()))]);
    check_metadata_write(SetKind::Update, patch, Some(&before), info)
        .map_err(|e| invalid_properties(&e))?;
    let mut next = current.clone();
    metadata::apply(&mut next, patch).map_err(|e| invalid_patch(&e))?;
    let after = Map::from_iter([(PRIVATE_METADATA.to_owned(), Value::Object(next.clone()))]);
    check_metadata_depth(patch, &after, info).map_err(|e| invalid_properties(&e))?;
    if next == current {
        return Ok(None);
    }
    let text = serde_json::to_string(&next).map_err(|_| set_error("serverFail"))?;
    if text.len() > MAX_CHAT_PRIVATE_METADATA_LEN {
        return Err(json!({
            "type": "overQuota",
            "description": format!(
                "a Chat's privateMetadata may take at most {MAX_CHAT_PRIVATE_METADATA_LEN} octets"
            ),
        }));
    }
    Ok(Some(text))
}
