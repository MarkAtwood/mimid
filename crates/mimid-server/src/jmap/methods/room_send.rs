//! `Room/send` (draft-atwood-jmap-chat-mimi-00 §Room/send; bead
//! mimid-1wgh.12.7, planned as Message/set before the draft named it
//! Room/send).
//!
//! Arguments: `accountId`, `roomId`, and `message`, the unpadded base64url
//! of an MLSMessage of wire format PrivateMessage. It is `invalidArguments`
//! if `message` does not decode as one or no Chat of the account is bound
//! to the room. The server wraps it in a SubmitMessageRequest with
//! `sendingUri` the account's user (protocol-07 §5.4) and relays it
//! ([`Follower::relay_submit_message`]), in-process when this server is the
//! hub; on acceptance the message is stored in the room's log (decision
//! mimid-1wgh.7.30), as the draft requires.
//!
//! The answer is the SubmitMessageResponse: `responseCode` by name, and
//! `acceptedAt` or `currentEpoch` as the code has.

use std::sync::Arc;

use jmap_server::{CallContext, HandlerFuture, HandlerOutput, JmapError, JmapHandler};
use mimi_mls::tls_codec::{Deserialize, Serialize};
use mimi_mls::wire::MLSMessage;
use mimi_protocol::{
    IdentifierUri, Protocol, SubmitMessageRequest, SubmitMessageResponse, SubmitResult,
};
use serde_json::{Value, json};

use super::Services;
use super::room_common::{bytes, invalid, relay_error, room_call, server_fail};
use crate::follower::Follower;
use crate::jmap::api::Methods;
use crate::jmap::auth::Account;
use crate::jmap::projection::utc_date;
use crate::store::Store;

const METHOD: &str = "Room/send";

/// Registers `Room/send`.
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
            send(&follower, &store, &caller, args)
                .await
                .map(HandlerOutput::new)
        })
    }
}

async fn send(
    follower: &Follower,
    store: &Store,
    caller: &Account,
    args: Value,
) -> Result<Value, JmapError> {
    let call = room_call(METHOD, store, caller, args, true).await?;
    let message = bytes(METHOD, &call.args, "message")?;
    let app_message = MLSMessage::tls_deserialize_exact(&message[..])
        .map_err(|_| invalid(METHOD, "message is not an MLSMessage"))?;
    let sending_uri = IdentifierUri::new(caller.user().as_str())
        .map_err(|_| invalid(METHOD, "this account's user URI is not an IdentifierUri"))?;
    let request = SubmitMessageRequest {
        protocol: Protocol::Mls10,
        app_message,
        sending_uri,
    };
    // protocol-07 §5.4: a PrivateMessage of content type application; the
    // request's own check refuses anything else when it is decoded.
    let request = request
        .tls_serialize_detached()
        .map_err(|_| invalid(METHOD, "message is not a PrivateMessage"))?;
    SubmitMessageRequest::tls_deserialize_exact(&request[..])
        .map_err(|_| invalid(METHOD, "message is not a PrivateMessage"))?;
    let response = follower
        .relay_submit_message(caller.user(), &call.room_id, &request)
        .await
        .map_err(|error| relay_error(METHOD, error))?;
    let response = SubmitMessageResponse::tls_deserialize_exact(&response[..])
        .map_err(|e| server_fail(METHOD, &e))?;
    let mut answer = json!({ "accountId": call.account_id });
    match response.result {
        SubmitResult::Accepted {
            accepted_timestamp, ..
        } => {
            answer["responseCode"] = json!("accepted");
            answer["acceptedAt"] = json!(utc_date(accepted_timestamp));
        }
        SubmitResult::NotAllowed => answer["responseCode"] = json!("notAllowed"),
        SubmitResult::EpochTooOld { current_epoch } => {
            answer["responseCode"] = json!("epochTooOld");
            answer["currentEpoch"] = json!(current_epoch);
        }
    }
    Ok(answer)
}
