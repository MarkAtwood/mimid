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
//! `acceptedAt` or `currentEpoch` as the code has. An accepted message
//! also gets `frank`, the hub's Frank when it franked the message
//! (findings log F3), and `messageIds`, the ids of the Messages stored
//! for it in the account (findings log F18).

use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jmap_server::{CallContext, HandlerFuture, HandlerOutput, JmapError, JmapHandler};
use mimi_mls::tls_codec::{Deserialize, Serialize};
use mimi_mls::wire::MLSMessage;
use mimi_protocol::{
    IdentifierUri, Protocol, SubmitMessageRequest, SubmitMessageResponse, SubmitResult,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::Services;
use super::room_common::{
    bytes, check_mls_object, invalid, relay_error, require_chat, room_call, server_fail,
};
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
    let call = room_call(METHOD, caller, args)?;
    let message = bytes(METHOD, &call.args, "message")?;
    let mut answer = json!({ "accountId": call.account_id });
    let sent = send_core(follower, store, caller, &call.room_id, &message).await?;
    match sent.result {
        SubmitResult::Accepted {
            accepted_timestamp,
            frank,
        } => {
            answer["responseCode"] = json!("accepted");
            answer["acceptedAt"] = json!(utc_date(accepted_timestamp));
            if let Some(frank) = frank {
                let frank = frank
                    .tls_serialize_detached()
                    .map_err(|e| server_fail(METHOD, &e))?;
                answer["frank"] = json!(URL_SAFE_NO_PAD.encode(frank));
            }
            answer["messageIds"] = json!(sent.message_ids);
        }
        SubmitResult::NotAllowed => answer["responseCode"] = json!("notAllowed"),
        SubmitResult::EpochTooOld { current_epoch } => {
            answer["responseCode"] = json!("epochTooOld");
            answer["currentEpoch"] = json!(current_epoch);
        }
    }
    Ok(answer)
}

/// What `Room/send` did.
pub(crate) struct SendOutcome {
    /// The hub's answer, frank included.
    pub(crate) result: SubmitResult,
    /// When the hub accepted: the ids of the Messages stored for the
    /// message in the account (findings log F18).
    pub(crate) message_ids: Vec<String>,
}

/// `Room/send` of the MLSMessage `message` to `room_id` for `caller`, as
/// both bindings call it (docs/design/binary-live-stream.md §5.10): every
/// check, the relay, the hub's SubmitResult, frank included, and the ids
/// of the Messages stored for an accepted message.
///
/// # Errors
///
/// The method's `invalidArguments`, `serverUnavailable` and `serverFail`.
pub(crate) async fn send_core(
    follower: &Follower,
    store: &Store,
    caller: &Account,
    room_id: &str,
    message: &[u8],
) -> Result<SendOutcome, JmapError> {
    check_mls_object(METHOD, "message", message)?;
    require_chat(METHOD, store, caller, room_id, true).await?;
    let app_message = MLSMessage::tls_deserialize_exact(message)
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
        .relay_submit_message(caller.user(), room_id, &request)
        .await
        .map_err(|error| relay_error(METHOD, error))?;
    let response = SubmitMessageResponse::tls_deserialize_exact(&response[..])
        .map_err(|e| server_fail(METHOD, &e))?;
    let message_ids = match response.result {
        SubmitResult::Accepted { .. } => store
            .projection_accepted_ids(
                caller.user().as_str(),
                room_id,
                &Sha256::digest(message).into(),
            )
            .await
            .map_err(|e| server_fail(METHOD, &e))?,
        _ => Vec::new(),
    };
    Ok(SendOutcome {
        result: response.result,
        message_ids,
    })
}
