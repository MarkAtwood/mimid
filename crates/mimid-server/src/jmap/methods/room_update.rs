//! `Room/update` (draft-atwood-jmap-chat-mimi-00 §Room/update; bead
//! mimid-1wgh.12.6).
//!
//! Arguments: `accountId`, `roomId`, and `request`, the unpadded base64url
//! of an UpdateRequest (protocol-07 §5.3). It is `invalidArguments` if
//! `request` does not decode or no Chat of the account is bound to the
//! room. The request goes through the follower's relay
//! ([`Follower::relay_update`]), in-process when this server is the hub,
//! which on success stores the account's own handshake in the room's log
//! (decision mimid-1wgh.7.30), as the draft requires, so the account's
//! other clients and the room's other local users receive it.
//!
//! The answer is the UpdateRoomResponse: `responseCode` by name,
//! `errorDescription`, and `acceptedAt`, `currentEpoch` or
//! `invalidProposals` (unpadded base64url ProposalRefs) as the code has.

use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jmap_server::{CallContext, HandlerFuture, HandlerOutput, JmapError, JmapHandler};
use mimi_mls::tls_codec::{Deserialize, Serialize};
use mimi_protocol::{UpdateRequest, UpdateResult, UpdateRoomResponse};
use serde_json::{Value, json};

use super::Services;
use super::room_common::{bytes, invalid, relay_error, room_call, server_fail};
use crate::follower::Follower;
use crate::jmap::api::Methods;
use crate::jmap::auth::Account;
use crate::jmap::projection::utc_date;
use crate::store::Store;

const METHOD: &str = "Room/update";

/// Registers `Room/update`.
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
            update(&follower, &store, &caller, args)
                .await
                .map(HandlerOutput::new)
        })
    }
}

async fn update(
    follower: &Follower,
    store: &Store,
    caller: &Account,
    args: Value,
) -> Result<Value, JmapError> {
    let call = room_call(METHOD, store, caller, args, true).await?;
    let request = bytes(METHOD, &call.args, "request")?;
    UpdateRequest::tls_deserialize_exact(&request[..])
        .map_err(|_| invalid(METHOD, "request is not an UpdateRequest"))?;
    let response = follower
        .relay_update(caller.user(), &call.room_id, &request)
        .await
        .map_err(|error| relay_error(METHOD, error))?;
    let response = UpdateRoomResponse::tls_deserialize_exact(&response[..])
        .map_err(|e| server_fail(METHOD, &e))?;
    let mut answer = json!({
        "accountId": call.account_id,
        "errorDescription": response.error_description.as_str(),
    });
    match response.result {
        UpdateResult::Success { accepted_timestamp } => {
            answer["responseCode"] = json!("success");
            answer["acceptedAt"] = json!(utc_date(accepted_timestamp));
        }
        UpdateResult::WrongEpoch { current_epoch } => {
            answer["responseCode"] = json!("wrongEpoch");
            answer["currentEpoch"] = json!(current_epoch);
        }
        UpdateResult::NotAllowed => answer["responseCode"] = json!("notAllowed"),
        UpdateResult::InvalidProposal { invalid_proposals } => {
            answer["responseCode"] = json!("invalidProposal");
            let refs = invalid_proposals
                .iter()
                .map(|r| {
                    r.tls_serialize_detached()
                        .map(|b| URL_SAFE_NO_PAD.encode(b))
                })
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| server_fail(METHOD, &e))?;
            answer["invalidProposals"] = json!(refs);
        }
    }
    Ok(answer)
}
