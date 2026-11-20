//! `GroupInfo/fetch` (draft-atwood-jmap-chat-mimi-00 §GroupInfo/fetch;
//! bead mimid-1wgh.12.8).
//!
//! Arguments: `accountId`, `roomId`, and `request`, the unpadded base64url
//! of a GroupInfoRequest (protocol-07 §5.6) the client signed. It is
//! `invalidArguments` if `request` does not decode, if `roomId` is not a
//! MIMI room URI, or if the room's hub hosts no such room. The account
//! need not be in the room: an external join reaches a room it is not in
//! yet, and the hub decides by room policy (bead mimid-1wgh.12.46). The
//! request goes through the follower's
//! relay ([`Follower::relay_group_info`]), in-process when this server is
//! the hub, else to the room's hub; a hub that cannot be reached is
//! `serverUnavailable` (decision JM-6).
//!
//! The answer is the GroupInfoResponse's `status` by name and the whole
//! `response`, unpadded base64url and unchanged: the GroupInfo and tree in
//! it are encrypted to the client's `groupInfoPublicKey`, and the client
//! checks the hub's signature.

use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jmap_server::{CallContext, HandlerFuture, HandlerOutput, JmapError, JmapHandler};
use mimi_mls::tls_codec::Deserialize;
use mimi_protocol::{GroupInfoCode, GroupInfoRequest, GroupInfoResponse};
use serde_json::{Value, json};

use super::Services;
use super::room_common::{bytes, invalid, relay_error, require_room_uri, room_call, server_fail};
use crate::follower::Follower;
use crate::jmap::api::Methods;
use crate::jmap::auth::Account;

const METHOD: &str = "GroupInfo/fetch";

/// Registers `GroupInfo/fetch`.
pub(super) fn register(methods: &mut Methods, services: &Services) {
    methods.add(
        METHOD,
        Arc::new(Handler {
            follower: Arc::clone(&services.follower),
        }),
    );
}

struct Handler {
    follower: Arc<Follower>,
}

impl JmapHandler<Account> for Handler {
    fn call(&self, cx: CallContext<Account>) -> HandlerFuture {
        let CallContext { args, caller, .. } = cx;
        let follower = Arc::clone(&self.follower);
        Box::pin(async move {
            fetch(&follower, &caller, args)
                .await
                .map(HandlerOutput::new)
        })
    }
}

async fn fetch(follower: &Follower, caller: &Account, args: Value) -> Result<Value, JmapError> {
    let call = room_call(METHOD, caller, args)?;
    let request = bytes(METHOD, &call.args, "request")?;
    let (status, response) = fetch_core(follower, caller, &call.room_id, &request).await?;
    Ok(json!({
        "accountId": call.account_id,
        "status": match status {
            GroupInfoCode::Success => "success",
            GroupInfoCode::NotAuthorized => "notAuthorized",
            GroupInfoCode::NoSuchRoom => "noSuchRoom",
        },
        "response": URL_SAFE_NO_PAD.encode(&response),
    }))
}

/// `GroupInfo/fetch` of `room_id` with the GroupInfoRequest `request`, as
/// both bindings call it: the status and the whole GroupInfoResponse.
///
/// # Errors
///
/// The method's `invalidArguments`, `serverUnavailable` and `serverFail`.
pub(crate) async fn fetch_core(
    follower: &Follower,
    caller: &Account,
    room_id: &str,
    request: &[u8],
) -> Result<(GroupInfoCode, Vec<u8>), JmapError> {
    super::room_common::check_mls_object("GroupInfo/fetch", "request", request)?;
    // Any room the client names: the room's hub decides by its policy
    // whether to answer (bead mimid-1wgh.12.46). The relay checks that the
    // request's credential is the account's user.
    require_room_uri(METHOD, room_id)?;
    GroupInfoRequest::tls_deserialize_exact(request)
        .map_err(|_| invalid(METHOD, "request is not a GroupInfoRequest"))?;
    let response = follower
        .relay_group_info(caller.user(), room_id, request)
        .await
        .map_err(|error| relay_error(METHOD, error))?;
    let status = GroupInfoResponse::tls_deserialize_exact(&response[..])
        .map_err(|e| server_fail(METHOD, &e))?
        .status();
    Ok((status, response))
}
