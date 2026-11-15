//! What the room methods share (draft-atwood-jmap-chat-mimi-00 §Rooms):
//! argument checks, the bound-Chat rule, and how a relay failure maps to a
//! JMAP error (decision JM-6).

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jmap_server::JmapError;
use serde_json::{Map, Value};

use crate::follower::FollowerError;
use crate::follower::relay::RelayError;
use crate::jmap::auth::Account;
use crate::peer::PeerError;
use crate::store::Store;

/// The checked common arguments of a room method.
pub(super) struct RoomCall {
    pub(super) account_id: String,
    pub(super) room_id: String,
    pub(super) args: Map<String, Value>,
}

pub(super) fn invalid(method: &'static str, why: &str) -> JmapError {
    tracing::debug!(method, why, "room method refused");
    JmapError::invalid_arguments(why)
}

pub(super) fn server_fail(
    method: &'static str,
    error: &(dyn std::error::Error + 'static),
) -> JmapError {
    tracing::error!(name: "jmap_room_method_failed", method, error, "room method failed");
    JmapError::server_fail("internal error")
}

/// Checks `accountId` and `roomId`. With `bound`, a Chat of the account
/// must be bound to the room; otherwise any Chat with that `roomId` will do
/// (§Room/unbind).
pub(super) async fn room_call(
    method: &'static str,
    store: &Store,
    caller: &Account,
    args: Value,
    bound: bool,
) -> Result<RoomCall, JmapError> {
    let Value::Object(args) = args else {
        return Err(invalid(method, "arguments must be an object"));
    };
    let account_id = match args.get("accountId") {
        Some(Value::String(id)) => id.clone(),
        _ => return Err(invalid(method, "accountId is required")),
    };
    caller
        .check_account_id(&account_id)
        .map_err(|_| JmapError::account_not_found())?;
    let room_id = match args.get("roomId") {
        Some(Value::String(room_id)) => room_id.clone(),
        _ => return Err(invalid(method, "roomId is required")),
    };
    let (_, chats) = store
        .projection_chats(caller.user().as_str())
        .await
        .map_err(|e| server_fail(method, &e))?;
    if !chats
        .iter()
        .any(|chat| chat.room_id == room_id && (chat.bound || !bound))
    {
        return Err(invalid(
            method,
            if bound {
                "no Chat of this account is bound to roomId"
            } else {
                "no Chat of this account has roomId"
            },
        ));
    }
    Ok(RoomCall {
        account_id,
        room_id,
        args,
    })
}

/// The unpadded base64url argument `key`.
pub(super) fn bytes(
    method: &'static str,
    args: &Map<String, Value>,
    key: &str,
) -> Result<Vec<u8>, JmapError> {
    match args.get(key) {
        Some(Value::String(text)) => URL_SAFE_NO_PAD
            .decode(text)
            .map_err(|_| invalid(method, &format!("{key} is not unpadded base64url"))),
        _ => Err(invalid(method, &format!("{key} is required"))),
    }
}

/// A relay failure as a JMAP error: a hub that does not answer, answers
/// 5xx or has a broken directory is `serverUnavailable`; a 4xx, or a
/// request the relay refuses as malformed, is `invalidArguments`
/// (decision JM-6).
pub(super) fn relay_error(method: &'static str, error: FollowerError) -> JmapError {
    match error {
        FollowerError::Relay(
            RelayError::Peer(error) | RelayError::Hub(crate::hub::HubError::Peer(error)),
        ) => {
            tracing::debug!(
                method,
                error = &error as &dyn std::error::Error,
                "the hub did not answer the request"
            );
            match error {
                PeerError::Rejected { status, .. } if (400..500).contains(&status) => {
                    invalid(method, "the hub refused the request")
                }
                _ => JmapError::server_unavailable(),
            }
        }
        FollowerError::Relay(
            RelayError::WrongIdentity { .. }
            | RelayError::InvalidRoomId
            | RelayError::InvalidRequest(_)
            | RelayError::RequestTooLarge
            | RelayError::Hub(crate::hub::HubError::InvalidRequest(_)),
        )
        | FollowerError::InvalidRequest(_) => {
            invalid(method, "the request is not valid for this room")
        }
        error => server_fail(method, &error),
    }
}
