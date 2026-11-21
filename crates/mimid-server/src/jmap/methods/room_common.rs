//! What the room methods share (draft-atwood-jmap-chat-mimi-00 §Rooms):
//! argument checks, the bound-Chat rule, and how a relay failure maps to a
//! JMAP error (decision JM-6).

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jmap_server::JmapError;
use serde_json::{Map, Value};

use crate::follower::FollowerError;
use crate::follower::relay::RelayError;
use crate::jmap::MAX_MLS_OBJECT_SIZE;
use crate::jmap::auth::Account;
use crate::peer::PeerError;
use crate::store::Store;

/// The checked common arguments of a room method.
pub(super) struct RoomCall {
    pub(super) account_id: String,
    pub(super) room_id: String,
    pub(super) args: Map<String, Value>,
}

pub(crate) fn invalid(method: &'static str, why: &str) -> JmapError {
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

/// Refuses `bytes`, the MLS or MIMI structure argument `name` of
/// `method`, if it is larger than `maxMlsObjectSize`
/// ([`MAX_MLS_OBJECT_SIZE`]; findings log F10). Both bindings call it
/// through the methods' core functions, so they enforce the one limit.
pub(crate) fn check_mls_object(
    method: &'static str,
    name: &str,
    bytes: &[u8],
) -> Result<(), JmapError> {
    if bytes.len() > MAX_MLS_OBJECT_SIZE {
        Err(invalid(
            method,
            &format!("{name} is larger than maxMlsObjectSize"),
        ))
    } else {
        Ok(())
    }
}

/// Checks `accountId` and reads `roomId`, as every room method does
/// first.
fn call_args(method: &'static str, caller: &Account, args: Value) -> Result<RoomCall, JmapError> {
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
    Ok(RoomCall {
        account_id,
        room_id,
        args,
    })
}

/// Checks `accountId` and reads `roomId`; the method's core function
/// checks the room ([`require_chat`] or [`require_room_uri`]), so that the
/// live stream, which calls the core function, gets the same checks.
pub(super) fn room_call(
    method: &'static str,
    caller: &Account,
    args: Value,
) -> Result<RoomCall, JmapError> {
    call_args(method, caller, args)
}

/// Requires a Chat of `caller`'s account with `room_id`. With `bound`, it
/// must be bound to the room; otherwise any Chat with that `roomId` will
/// do (§Room/unbind).
pub(crate) async fn require_chat(
    method: &'static str,
    store: &Store,
    caller: &Account,
    room_id: &str,
    bound: bool,
) -> Result<(), JmapError> {
    let (_, chats) = store
        .projection_chats(caller.user().as_str())
        .await
        .map_err(|e| server_fail(method, &e))?;
    if chats
        .iter()
        .any(|chat| chat.room_id == room_id && (chat.bound || !bound))
    {
        Ok(())
    } else {
        Err(invalid(
            method,
            if bound {
                "no Chat of this account is bound to roomId"
            } else {
                "no Chat of this account has roomId"
            },
        ))
    }
}

/// Requires `room_id` to be a MIMI room URI, without requiring a Chat of
/// the account for it: GroupInfo/fetch and the external Commit of
/// Room/update reach a room the account is not in yet
/// (draft-atwood-jmap-chat-mimi-00 §GroupInfo/fetch, §Room/update; bead
/// mimid-1wgh.12.46).
pub(crate) fn require_room_uri(method: &'static str, room_id: &str) -> Result<(), JmapError> {
    if crate::hub::room_uri_domain(room_id).is_some() {
        Ok(())
    } else {
        Err(invalid(method, "roomId is not a MIMI room URI"))
    }
}

/// Whether a Chat of `caller`'s account is bound to `room_id`.
pub(super) async fn has_bound_chat(
    method: &'static str,
    store: &Store,
    caller: &Account,
    room_id: &str,
) -> Result<bool, JmapError> {
    let (_, chats) = store
        .projection_chats(caller.user().as_str())
        .await
        .map_err(|e| server_fail(method, &e))?;
    Ok(chats
        .iter()
        .any(|chat| chat.room_id == room_id && chat.bound))
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
                PeerError::Rejected { status, .. } if (400..500).contains(&status) => invalid(
                    method,
                    &format!("the hub refused the request (HTTP {status})"),
                ),
                _ => unavailable(&error),
            }
        }
        // A room this server's hub does not host: as a remote hub's 404
        // (bead mimid-1wgh.12.46: GroupInfo/fetch and an external
        // Room/update can name any room).
        FollowerError::Relay(RelayError::Hub(crate::hub::HubError::NoSuchRoom)) => {
            invalid(method, "no such room")
        }
        // Decision mimid-1wgh.81. A remote hub's 422 for the same is the
        // generic refusal above.
        FollowerError::Relay(RelayError::Hub(crate::hub::HubError::GroupInfoTooLarge {
            ..
        })) => invalid(
            method,
            "the room's GroupInfo and ratchet tree are too large to send",
        ),
        FollowerError::Relay(
            RelayError::WrongIdentity { .. }
            | RelayError::InvalidRoomId
            | RelayError::InvalidRequest(_)
            | RelayError::RequestTooLarge
            | RelayError::Hub(crate::hub::HubError::InvalidRequest(_)),
        )
        | FollowerError::InvalidRequest(_) => invalid(
            method,
            &format!(
                "the request is not valid for this room: {}",
                crate::jmap::error_chain(&error)
            ),
        ),
        error => server_fail(method, &error),
    }
}

/// `serverUnavailable`, with a description saying whether the provider
/// asked (the room's hub, or the target user's provider) answered an
/// error status or could not be reached (clean-room finding C5). The
/// transport error itself stays in the log: it can name local files.
pub(crate) fn unavailable(error: &PeerError) -> JmapError {
    let mut unavailable = JmapError::server_unavailable();
    unavailable.description = Some(match error {
        PeerError::Rejected { status, .. } => {
            format!("the provider asked answered HTTP {status}")
        }
        _ => "the provider asked could not be reached".to_owned(),
    });
    unavailable
}
