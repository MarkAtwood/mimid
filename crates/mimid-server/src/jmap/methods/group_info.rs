//! `GroupInfo/fetch` (draft-atwood-jmap-chat-mimi-00 §GroupInfo/fetch;
//! bead mimid-1wgh.12.8).
//!
//! Arguments: `accountId`, `roomId`, and `request`, the unpadded base64url
//! of a GroupInfoRequest (protocol-07 §5.6) the client signed. It is
//! `invalidArguments` if `request` does not decode or no Chat of the
//! account is bound to the room. The request goes through the follower's
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
use super::room_common::{bytes, invalid, relay_error, room_call, server_fail};
use crate::follower::Follower;
use crate::jmap::api::Methods;
use crate::jmap::auth::Account;
use crate::store::Store;

const METHOD: &str = "GroupInfo/fetch";

/// Registers `GroupInfo/fetch`.
pub(super) fn register(methods: &mut Methods, services: &Services) {
    methods.add(
        METHOD,
        Arc::new(Handler {
            follower: Arc::clone(&services.follower),
            store: services.store.clone(),
        }),
    );
}

struct Handler {
    follower: Arc<Follower>,
    store: Store,
}

impl JmapHandler<Account> for Handler {
    fn call(&self, cx: CallContext<Account>) -> HandlerFuture {
        let CallContext { args, caller, .. } = cx;
        let (follower, store) = (Arc::clone(&self.follower), self.store.clone());
        Box::pin(async move {
            fetch(&follower, &store, &caller, args)
                .await
                .map(HandlerOutput::new)
        })
    }
}

async fn fetch(
    follower: &Follower,
    store: &Store,
    caller: &Account,
    args: Value,
) -> Result<Value, JmapError> {
    let call = room_call(METHOD, store, caller, args, true).await?;
    let request = bytes(METHOD, &call.args, "request")?;
    GroupInfoRequest::tls_deserialize_exact(&request[..])
        .map_err(|_| invalid(METHOD, "request is not a GroupInfoRequest"))?;
    let response = follower
        .relay_group_info(caller.user(), &call.room_id, &request)
        .await
        .map_err(|error| relay_error(METHOD, error))?;
    let status = GroupInfoResponse::tls_deserialize_exact(&response[..])
        .map_err(|e| server_fail(METHOD, &e))?
        .status();
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
