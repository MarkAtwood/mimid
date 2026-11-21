//! `KeyMaterial/fetch` (draft-atwood-jmap-chat-mimi-00 §KeyMaterial/fetch;
//! bead mimid-1wgh.12.5).
//!
//! Arguments: `accountId`, `roomId`, and `request`, the unpadded base64url
//! of a KeyMaterialRequest (protocol-07 §5.2) the client signed. The call
//! is `invalidArguments` if `request` does not decode, if its
//! `requestingUser` is not the account's user, if its `roomId` is not
//! `roomId`, or if no Chat of the account is bound to that room.
//!
//! Otherwise the request goes through the follower's relay
//! ([`Follower::relay_key_material`](crate::follower::Follower::relay_key_material)):
//! to this server's hub in-process when it hosts the room, which serves a
//! local target user from the KeyPackage store and asks the target
//! provider otherwise; to the room's hub when another provider hosts it,
//! even for a local target, so that hub sees the request it will forward
//! the Welcome for. A provider that cannot be reached, or answers with a
//! 5xx, is `serverUnavailable`; one that answers with a 4xx is
//! `invalidArguments` (decision JM-6).
//!
//! The KeyMaterialResponse is answered as `userStatus` (the code's name),
//! `userUri`, and `clients`: per client `clientStatus`, `clientUri`,
//! `keyPackage` (unpadded base64url, for `success`) and
//! `clientCapabilities` (unpadded base64url of the MLS Capabilities, when
//! present), and as `response`, the unpadded base64url of the whole
//! KeyMaterialResponse exactly as the provider answered (findings log
//! F5), so a client need not rebuild it from the split fields.
//!
//! An account that calls it more often than the server's limit allows
//! gets the method-level error `rateLimited` with `retryAfter`, before
//! anything is checked or relayed (draft-atwood-jmap-chat-mimi-00
//! §capability and §Security Considerations, "Servers SHOULD rate-limit
//! key material requests per requester"; [`crate::jmap::rate`]; bead
//! mimid-e64f.21).

use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jmap_server::{CallContext, HandlerFuture, HandlerOutput, JmapError, JmapHandler};
use mimi_mls::tls_codec::{Deserialize, Serialize};
use mimi_protocol::{
    ClientKeyMaterial, KeyMaterialRequest, KeyMaterialResponse, KeyMaterialUserCode,
};
use serde_json::{Map, Value, json};

use super::Services;
use crate::follower::relay::RelayError;
use crate::follower::{Follower, FollowerError};
use crate::jmap::api::Methods;
use crate::jmap::auth::Account;
use crate::jmap::rate::RateLimiter;
use crate::peer::PeerError;
use crate::store::Store;

/// Registers `KeyMaterial/fetch`.
pub(super) fn register(methods: &mut Methods, services: &Services) {
    methods.add(
        "KeyMaterial/fetch",
        Arc::new(Handler {
            follower: Arc::clone(&services.follower),
            store: services.store.clone(),
            limiter: services.key_material_limiter.clone(),
        }),
    );
}

struct Handler {
    follower: Arc<Follower>,
    store: Store,
    limiter: Option<RateLimiter>,
}

impl JmapHandler<Account> for Handler {
    fn call(&self, cx: CallContext<Account>) -> HandlerFuture {
        let CallContext { args, caller, .. } = cx;
        let follower = Arc::clone(&self.follower);
        let store = self.store.clone();
        let limiter = self.limiter.clone();
        Box::pin(async move {
            fetch(&follower, &store, limiter.as_ref(), &caller, args)
                .await
                .map(HandlerOutput::new)
        })
    }
}

fn invalid(why: &str) -> JmapError {
    JmapError::invalid_arguments(why)
}

fn server_fail(error: &(dyn std::error::Error + 'static)) -> JmapError {
    tracing::error!(
        name: "jmap_key_material_failed",
        error,
        "KeyMaterial/fetch failed"
    );
    JmapError::server_fail("internal error")
}

/// The draft's name for a `userStatus` code (protocol-07 §5.2).
fn user_status(code: KeyMaterialUserCode) -> &'static str {
    match code {
        KeyMaterialUserCode::Success => "success",
        KeyMaterialUserCode::PartialSuccess => "partialSuccess",
        KeyMaterialUserCode::IncompatibleProtocol => "incompatibleProtocol",
        KeyMaterialUserCode::NoCompatibleMaterial => "noCompatibleMaterial",
        KeyMaterialUserCode::UserUnknown => "userUnknown",
        KeyMaterialUserCode::NoConsent => "noConsent",
        KeyMaterialUserCode::NoConsentForThisRoom => "noConsentForThisRoom",
        KeyMaterialUserCode::UserDeleted => "userDeleted",
    }
}

fn client(material: &ClientKeyMaterial) -> Result<Value, mimi_mls::tls_codec::Error> {
    let encode = |bytes: Vec<u8>| URL_SAFE_NO_PAD.encode(bytes);
    let mut object = Map::new();
    match material {
        ClientKeyMaterial::Success {
            client_uri,
            key_package,
        } => {
            object.insert("clientStatus".into(), json!("success"));
            object.insert("clientUri".into(), json!(client_uri.as_str()));
            object.insert(
                "keyPackage".into(),
                json!(encode(key_package.tls_serialize_detached()?)),
            );
        }
        ClientKeyMaterial::KeyMaterialExhausted { client_uri } => {
            object.insert("clientStatus".into(), json!("keyMaterialExhausted"));
            object.insert("clientUri".into(), json!(client_uri.as_str()));
        }
        ClientKeyMaterial::NothingCompatible {
            client_uri,
            client_capabilities,
        } => {
            object.insert("clientStatus".into(), json!("nothingCompatible"));
            object.insert("clientUri".into(), json!(client_uri.as_str()));
            if let Some(capabilities) = client_capabilities {
                object.insert(
                    "clientCapabilities".into(),
                    json!(encode(capabilities.tls_serialize_detached()?)),
                );
            }
        }
    }
    Ok(Value::Object(object))
}

/// `KeyMaterial/fetch` of the KeyMaterialRequest `request` for `room_id`,
/// as both bindings call it: every check, the relay, and the
/// KeyMaterialResponse as received.
///
/// # Errors
///
/// The method's `invalidArguments`, `serverUnavailable` and `serverFail`.
pub(crate) async fn fetch_core(
    follower: &Follower,
    store: &Store,
    limiter: Option<&RateLimiter>,
    caller: &Account,
    room_id: &str,
    request: &[u8],
) -> Result<Vec<u8>, JmapError> {
    if let Some(limiter) = limiter {
        limiter.check("KeyMaterial/fetch", caller.account_id())?;
    }
    super::room_common::check_mls_object("KeyMaterial/fetch", "request", request)?;
    let decoded = KeyMaterialRequest::tls_deserialize_exact(request)
        .map_err(|_| invalid("request is not a KeyMaterialRequest"))?;
    let tbs = decoded.tbs();
    if tbs.requesting_user.as_str() != caller.user().as_str() {
        return Err(invalid("requestingUser is not this account's user"));
    }
    if tbs.room_id.as_str() != room_id {
        return Err(invalid("the request's roomId is not roomId"));
    }
    let (_, chats) = store
        .projection_chats(caller.user().as_str())
        .await
        .map_err(|e| server_fail(&e))?;
    if !chats
        .iter()
        .any(|chat| chat.room_id == *room_id && chat.bound)
    {
        return Err(invalid("no Chat of this account is bound to roomId"));
    }
    match follower.relay_key_material(caller.user(), request).await {
        Ok(response) => Ok(response),
        // A provider asked for the material: the room's hub (this server
        // relays) or the target's provider (this server is the hub).
        // Decision JM-6: a 4xx is invalidArguments; no answer, a 5xx or a
        // broken directory is serverUnavailable.
        Err(FollowerError::Relay(
            RelayError::Peer(error) | RelayError::Hub(crate::hub::HubError::Peer(error)),
        )) => {
            tracing::debug!(
                error = &error as &dyn std::error::Error,
                "KeyMaterial/fetch: the provider did not answer the request"
            );
            Err(match error {
                PeerError::Rejected { status, .. } if (400..500).contains(&status) => {
                    invalid("the provider refused the request")
                }
                _ => JmapError::server_unavailable(),
            })
        }
        Err(FollowerError::Relay(
            RelayError::WrongIdentity { .. }
            | RelayError::InvalidRoomId
            | RelayError::InvalidRequest(_),
        )) => Err(invalid("the request is not valid for this room")),
        Err(error) => Err(server_fail(&error)),
    }
}

async fn fetch(
    follower: &Follower,
    store: &Store,
    limiter: Option<&RateLimiter>,
    caller: &Account,
    args: Value,
) -> Result<Value, JmapError> {
    let Value::Object(args) = args else {
        return Err(invalid("arguments must be an object"));
    };
    let account_id = match args.get("accountId") {
        Some(Value::String(id)) => id.clone(),
        _ => return Err(invalid("accountId is required")),
    };
    caller
        .check_account_id(&account_id)
        .map_err(|_| JmapError::account_not_found())?;
    let Some(Value::String(room_id)) = args.get("roomId") else {
        return Err(invalid("roomId is required"));
    };
    let Some(Value::String(request)) = args.get("request") else {
        return Err(invalid("request is required"));
    };
    let request = URL_SAFE_NO_PAD
        .decode(request)
        .map_err(|_| invalid("request is not unpadded base64url"))?;
    let bytes = fetch_core(follower, store, limiter, caller, room_id, &request).await?;
    let response =
        KeyMaterialResponse::tls_deserialize_exact(&bytes[..]).map_err(|e| server_fail(&e))?;
    let clients = response
        .clients
        .iter()
        .map(client)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| server_fail(&e))?;
    Ok(json!({
        "accountId": account_id,
        "userStatus": user_status(response.user_status),
        "userUri": response.user_uri.as_str(),
        "clients": clients,
        "response": URL_SAFE_NO_PAD.encode(&bytes),
    }))
}
