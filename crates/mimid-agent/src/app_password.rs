//! `AppPassword/get` and `AppPassword/set`: the agent's own JMAP methods
//! for the credentials every front end checks logins against
//! (docs/design/frontend-auth.md §3.6, §4.2; bead mimid-e13m.6).
//!
//! INVENTED, NOT FROM SPEC (decision mimid-1wgh.126): no JMAP draft has
//! these. They sit under the agent's own capability [`CAPABILITY`], named
//! like mimid-server's `tag:reviewcommit.com,2026:mimid:live`, and are
//! the agent's: nothing is forwarded to the provider, which never sees a
//! credential.
//!
//! Without them a user whose only client speaks JMAP Chat could not add
//! a password for a new device, nor revoke a lost one, without a shell or
//! an IRC client (§3.6 names all three places).
//!
//! An `AppPassword` object is one row of the credential table as the CLI
//! and `/msg mimid passwords` show it, and never a secret or a verifier:
//!
//! | Property | Type | From [`CredentialInfo`] |
//! |---|---|---|
//! | `id` | `Id` | `c` and the row's integer id, which is never reused |
//! | `name` | `String` | `name` |
//! | `kind` | `String` | `app-password` or `agent-token` |
//! | `createdAt` | `UTCDate` | `created_at` |
//! | `createdBy` | `String` | `created_by` |
//! | `lastUsedAt` | `UTCDate\|null` | `last_used_at` |
//! | `lastUsedBy` | `String\|null` | `last_used_by`: front end and peer |
//! | `revokedAt` | `UTCDate\|null` | `revoked_at`, kept 30 days |
//!
//! `AppPassword/get` takes `accountId` and optional `ids`, and answers
//! `{accountId, state, list, notFound}`. Revoked rows are listed too, as
//! the CLI lists them, so a client can show that a device was revoked.
//!
//! `AppPassword/set` takes `accountId`, and:
//!
//! - `create`: a map from creation id to `{"name": "<1 to 32 of
//!   [a-z0-9-]>"}`. **The created object carries `secret` once**, the
//!   password in the form it is shown (`kqzv-trwm-hpaf-dnye`); the agent
//!   keeps only a SCRAM verifier, so it cannot be shown again. The
//!   response is the only place it appears, which is why §4.2 requires
//!   this endpoint to be loopback or TLS.
//! - `destroy`: a list of ids, each revoked. Sessions that logged in with
//!   one close (§3.7).
//!
//! # Limitations
//!
//! - `update` is refused with `forbidden`: no property of a credential is
//!   writable. Renaming one would break what the user wrote down, and the
//!   secret cannot be changed in place. A client destroys and creates.
//! - The agent token cannot be destroyed, only replaced
//!   (`mimid-agent <config> app-password rotate-token`); a `destroy` of it
//!   is `forbidden`, as §3.4 says.
//! - `createdBy` is `jmap`, without the credential that asked, because
//!   the dispatcher's caller context carries the account and not the
//!   login (bead mimid-e13m.17). The CLI records `cli` and IRC records
//!   `irc (<credential>)`.
//! - `state` is a digest of the listing, not a stored state string, so
//!   there is no `AppPassword/changes` and `ifInState` is not honoured; a
//!   client re-reads. A login does not move the state: `lastUsedAt` and
//!   `lastUsedBy` are left out of the digest, so merely using a device
//!   does not look like a change to every other client.
//! - No `AppPassword/query`: there are at most
//!   [`MAX_ACTIVE`](mimid_agent_store::credentials::MAX_ACTIVE)
//!   unrevoked credentials, so a client gets them all from
//!   `AppPassword/get`.

use std::hash::{Hash, Hasher};
use std::sync::Arc;

use jmap_server::{
    CallContext, Dispatcher, HandlerFuture, HandlerOutput, Id, JmapError, JmapHandler,
};
use mimid_agent_store::convert::utc_date;
use mimid_agent_store::credentials::{CredentialError, CredentialInfo, Credentials, Kind};
use serde_json::{Map, Value, json};

/// The agent's own capability for these methods (docs/design/
/// frontend-auth.md §3.6). INVENTED, NOT FROM SPEC.
pub const CAPABILITY: &str = "tag:reviewcommit.com,2026:mimid:app-passwords";

/// `AppPassword/get`.
pub const GET: &str = "AppPassword/get";

/// `AppPassword/set`.
pub const SET: &str = "AppPassword/set";

/// What `AppPassword/set` records as a credential's `created_by`. See the
/// module's limitations.
const CREATED_BY: &str = "jmap";

/// Registers both methods on `dispatcher`, over `credentials`, for
/// `account`.
pub(crate) fn register(
    credentials: &Arc<Credentials>,
    account: &Id,
    dispatcher: &mut Dispatcher<Id>,
) {
    for (name, which) in [(GET, Which::Get), (SET, Which::Set)] {
        dispatcher.register(
            name,
            Arc::new(Handler {
                credentials: Arc::clone(credentials),
                account: account.clone(),
                which,
            }),
        );
    }
}

#[derive(Clone, Copy)]
enum Which {
    Get,
    Set,
}

struct Handler {
    credentials: Arc<Credentials>,
    account: Id,
    which: Which,
}

impl JmapHandler<Id> for Handler {
    fn call(&self, cx: CallContext<Id>) -> HandlerFuture {
        let credentials = Arc::clone(&self.credentials);
        let account = self.account.clone();
        let which = self.which;
        Box::pin(async move {
            match which {
                Which::Get => get(&credentials, &account, cx.args),
                Which::Set => set(&credentials, &account, cx.args),
            }
        })
    }
}

/// The id of the credential `info` describes: `c` and its integer id,
/// which is never reused, so the id is stable and unique even after the
/// name is given to another credential.
fn object_id(info: &CredentialInfo) -> String {
    format!("c{}", info.id.0)
}

/// One credential as JMAP. Never a secret or a verifier.
fn object(info: &CredentialInfo) -> Value {
    json!({
        "id": object_id(info),
        "name": info.name,
        "kind": info.kind.as_str(),
        "createdAt": utc_date(info.created_at),
        "createdBy": info.created_by,
        "lastUsedAt": info.last_used_at.map(utc_date),
        "lastUsedBy": info.last_used_by,
        "revokedAt": info.revoked_at.map(utc_date),
    })
}

/// A digest of `infos`, as the listing's `state`. The last use is left
/// out: see the module's limitations.
fn state_of(infos: &[CredentialInfo]) -> String {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    for info in infos {
        info.id.0.hash(&mut hasher);
        info.name.hash(&mut hasher);
        info.kind.as_str().hash(&mut hasher);
        info.created_at.hash(&mut hasher);
        info.revoked_at.hash(&mut hasher);
    }
    format!("{:x}", hasher.finish())
}

fn invalid(method: &str, why: impl Into<String>) -> JmapError {
    let why = why.into();
    tracing::debug!(method, why, "app password call refused");
    JmapError::invalid_arguments(why)
}

/// The credential table could not be read or written.
fn unavailable(method: &str, error: &CredentialError) -> JmapError {
    tracing::error!(
        name: "agent_credentials_unreadable",
        method,
        error = error as &dyn std::error::Error,
        "the credential table could not be read or written for a JMAP call"
    );
    JmapError::server_unavailable()
}

/// `args` as an object whose `accountId` is `account`.
fn checked_args(account: &Id, method: &str, args: Value) -> Result<Map<String, Value>, JmapError> {
    let Value::Object(args) = args else {
        return Err(invalid(method, "arguments must be an object"));
    };
    match args.get("accountId") {
        Some(Value::String(id)) if id == account.as_ref() => Ok(args),
        Some(_) => Err(JmapError::account_not_found()),
        None => Err(invalid(method, "accountId is required")),
    }
}

/// `AppPassword/get`.
fn get(credentials: &Credentials, account: &Id, args: Value) -> Result<HandlerOutput, JmapError> {
    let args = checked_args(account, GET, args)?;
    credentials.refresh().map_err(|e| unavailable(GET, &e))?;
    let infos = credentials.list();
    let (list, not_found) = match args.get("ids") {
        None | Some(Value::Null) => (infos.iter().map(object).collect::<Vec<Value>>(), Vec::new()),
        Some(Value::Array(ids)) => {
            let mut list = Vec::new();
            let mut not_found = Vec::new();
            for id in ids {
                let Value::String(id) = id else {
                    return Err(invalid(GET, "every id must be a string"));
                };
                match infos.iter().find(|info| object_id(info) == *id) {
                    Some(info) => list.push(object(info)),
                    None => not_found.push(Value::String(id.clone())),
                }
            }
            (list, not_found)
        }
        Some(_) => return Err(invalid(GET, "ids must be an array or null")),
    };
    Ok(HandlerOutput::new(json!({
        "accountId": account.as_ref(),
        "state": state_of(&infos),
        "list": list,
        "notFound": not_found,
    })))
}

/// `AppPassword/set`.
fn set(credentials: &Credentials, account: &Id, args: Value) -> Result<HandlerOutput, JmapError> {
    let args = checked_args(account, SET, args)?;
    credentials.refresh().map_err(|e| unavailable(SET, &e))?;
    let before = credentials.list();
    let old_state = state_of(&before);

    let mut created = Map::new();
    let mut not_created = Map::new();
    if let Some(create) = args.get("create") {
        let Value::Object(create) = create else {
            return Err(invalid(SET, "create must be an object"));
        };
        for (creation_id, properties) in create {
            match add(credentials, properties) {
                Ok(object) => {
                    created.insert(creation_id.clone(), object);
                }
                Err(error) => {
                    not_created.insert(creation_id.clone(), error);
                }
            }
        }
    }

    // No property of a credential is writable (see the module's
    // limitations).
    let mut not_updated = Map::new();
    if let Some(update) = args.get("update") {
        let Value::Object(update) = update else {
            return Err(invalid(SET, "update must be an object"));
        };
        for id in update.keys() {
            not_updated.insert(
                id.clone(),
                json!({
                    "type": "forbidden",
                    "description": "no property of a credential is writable; \
                                    destroy it and create another",
                }),
            );
        }
    }

    let mut destroyed = Vec::new();
    let mut not_destroyed = Map::new();
    if let Some(destroy) = args.get("destroy") {
        let Value::Array(destroy) = destroy else {
            return Err(invalid(SET, "destroy must be an array"));
        };
        for id in destroy {
            let Value::String(id) = id else {
                return Err(invalid(SET, "every id must be a string"));
            };
            match revoke(credentials, &before, id) {
                Ok(()) => destroyed.push(Value::String(id.clone())),
                Err(error) => {
                    not_destroyed.insert(id.clone(), error);
                }
            }
        }
    }

    // Read again, so the new state is what the writes left rather than a
    // guess.
    let new_state = match credentials.refresh() {
        Ok(_) => state_of(&credentials.list()),
        Err(_) => old_state.clone(),
    };
    Ok(HandlerOutput::new(json!({
        "accountId": account.as_ref(),
        "oldState": old_state,
        "newState": new_state,
        "created": Value::Object(created),
        "updated": Value::Null,
        "destroyed": Value::Array(destroyed),
        "notCreated": Value::Object(not_created),
        "notUpdated": Value::Object(not_updated),
        "notDestroyed": Value::Object(not_destroyed),
    })))
}

/// One `create`: the new credential's object, with its `secret` once, or
/// a SetError.
fn add(credentials: &Credentials, properties: &Value) -> Result<Value, Value> {
    let Value::Object(properties) = properties else {
        return Err(set_error("invalidProperties", "a create must be an object"));
    };
    if let Some(property) = properties.keys().find(|key| *key != "name") {
        return Err(json!({
            "type": "invalidProperties",
            "properties": [property],
            "description": "only name may be given; the agent makes the secret",
        }));
    }
    let name = match properties.get("name") {
        Some(Value::String(name)) => name,
        Some(_) => {
            return Err(json!({
                "type": "invalidProperties",
                "properties": ["name"],
                "description": "name must be a string",
            }));
        }
        None => {
            return Err(json!({
                "type": "invalidProperties",
                "properties": ["name"],
                "description": "name is required",
            }));
        }
    };
    match credentials.add(name, CREATED_BY) {
        Ok((info, password)) => {
            let mut object = object(&info);
            if let Value::Object(map) = &mut object {
                // The one place the secret appears: the agent keeps only
                // a SCRAM verifier (docs/design/frontend-auth.md §3.3).
                map.insert("secret".to_owned(), json!(password.shown()));
            }
            Ok(object)
        }
        Err(error @ (CredentialError::Name(_) | CredentialError::Exists(_))) => Err(json!({
            "type": "invalidProperties",
            "properties": ["name"],
            "description": error.to_string(),
        })),
        Err(error @ CredentialError::TooMany) => Err(set_error("overQuota", error.to_string())),
        Err(error) => {
            tracing::error!(
                name: "agent_credential_add_failed",
                error = &error as &dyn std::error::Error,
                "a JMAP client could not be given an app password"
            );
            Err(set_error("serverFail", "the credential could not be made"))
        }
    }
}

/// One `destroy`: revokes the credential with id `id`, or a SetError.
fn revoke(credentials: &Credentials, before: &[CredentialInfo], id: &str) -> Result<(), Value> {
    let Some(info) = before.iter().find(|info| object_id(info) == id) else {
        return Err(set_error("notFound", "no credential has that id"));
    };
    if info.revoked_at.is_some() {
        return Err(set_error("notFound", "that credential is revoked already"));
    }
    if info.kind == Kind::AgentToken {
        return Err(set_error(
            "forbidden",
            "the agent token cannot be revoked; replace it with \
             `mimid-agent <config> app-password rotate-token`",
        ));
    }
    match credentials.revoke(&info.name, CREATED_BY) {
        Ok(_) => Ok(()),
        Err(error @ CredentialError::NoSuch(_)) => Err(set_error("notFound", error.to_string())),
        Err(error @ CredentialError::NotRevocable) => {
            Err(set_error("forbidden", error.to_string()))
        }
        Err(error) => {
            tracing::error!(
                name: "agent_credential_revoke_failed",
                error = &error as &dyn std::error::Error,
                "a JMAP client could not revoke an app password"
            );
            Err(set_error(
                "serverFail",
                "the credential could not be revoked",
            ))
        }
    }
}

/// A SetError (RFC 8620 §5.3).
fn set_error(kind: &str, description: impl Into<String>) -> Value {
    json!({"type": kind, "description": description.into()})
}
