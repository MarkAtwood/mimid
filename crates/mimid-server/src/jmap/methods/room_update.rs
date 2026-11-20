//! `Room/update` (draft-atwood-jmap-chat-mimi-00 §Room/update; bead
//! mimid-1wgh.12.6).
//!
//! Arguments: `accountId`, `roomId`, and `request`, the unpadded base64url
//! of an UpdateRequest (protocol-07 §5.3). It is `invalidArguments` if
//! `request` does not decode, if it is an external Commit whose UpdatePath
//! credential is not the account's user, or if no Chat of the account is
//! bound to the room and the request is not an external Commit (bead
//! mimid-1wgh.12.46: an account joins a room it is not in by external
//! Commit; when the hub accepts it the follower binds the account's Chat).
//! The request goes through the follower's relay
//! ([`Follower::relay_update`]), in-process when this server is the hub,
//! which on success stores the account's own handshake in the room's log
//! (decision mimid-1wgh.7.30), as the draft requires, so the account's
//! other clients and the room's other local users receive it.
//!
//! The answer is the UpdateRoomResponse: `responseCode` by name,
//! `errorDescription`, and `acceptedAt`, `currentEpoch` or
//! `invalidProposals` (unpadded base64url ProposalRefs) as the code has,
//! and on success `messageIds`, the ids of the Messages stored for the
//! handshake in the account (findings log F18).

use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jmap_server::{CallContext, HandlerFuture, HandlerOutput, JmapError, JmapHandler};
use mimi_mls::tls_codec::{Deserialize, Serialize};
use mimi_protocol::{HandshakeBundle, UpdateRequest, UpdateResult, UpdateRoomResponse};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::Services;
use super::room_common::{
    bytes, check_mls_object, has_bound_chat, invalid, relay_error, require_room_uri, room_call,
    server_fail,
};
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
    let call = room_call(METHOD, caller, args)?;
    let request = bytes(METHOD, &call.args, "request")?;
    let (response, message_ids) =
        update_core(follower, store, caller, &call.room_id, &request).await?;
    let mut answer = json!({
        "accountId": call.account_id,
        "errorDescription": response.error_description.as_str(),
    });
    match response.result {
        UpdateResult::Success { accepted_timestamp } => {
            answer["responseCode"] = json!("success");
            answer["acceptedAt"] = json!(utc_date(accepted_timestamp));
            answer["messageIds"] = json!(message_ids);
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

/// `Room/update` of `room_id` with the UpdateRequest `request`, as both
/// bindings call it: every check, the relay, the hub's response, and on
/// success the ids of the Messages stored for the handshake in the
/// account (findings log F18).
///
/// # Errors
///
/// The method's `invalidArguments`, `serverUnavailable` and `serverFail`.
pub(crate) async fn update_core(
    follower: &Follower,
    store: &Store,
    caller: &Account,
    room_id: &str,
    request: &[u8],
) -> Result<(UpdateRoomResponse, Vec<String>), JmapError> {
    check_mls_object(METHOD, "request", request)?;
    require_room_uri(METHOD, room_id)?;
    let decoded = UpdateRequest::tls_deserialize_exact(request)
        .map_err(|_| invalid(METHOD, "request is not an UpdateRequest"))?;
    // An external Commit must join as the account's own user, whether or
    // not the account is in the room: its leaf key is bound to no
    // KeyPackage the account published, so this is the only check that it
    // is the account's (bead mimid-1wgh.12.46).
    let joiner = match &decoded.bundle {
        HandshakeBundle::Commit {
            proposal_or_commit, ..
        } => proposal_or_commit.external_commit_identity(),
        HandshakeBundle::Proposal { .. } => None,
    };
    if let Some(identity) = joiner
        && identity != caller.user().as_str().as_bytes()
    {
        return Err(invalid(
            METHOD,
            "the external Commit joins a user other than this account's",
        ));
    }
    // Without a bound Chat only an external Commit is allowed; when the hub
    // accepts it the follower makes the account a member and binds the
    // Chat (Follower::relay_update).
    if joiner.is_none() && !has_bound_chat(METHOD, store, caller, room_id).await? {
        return Err(invalid(
            METHOD,
            "no Chat of this account is bound to roomId",
        ));
    }
    let response = follower
        .relay_update(caller.user(), room_id, request)
        .await
        .map_err(|error| relay_error(METHOD, error))?;
    let response = UpdateRoomResponse::tls_deserialize_exact(&response[..])
        .map_err(|e| server_fail(METHOD, &e))?;
    let message_ids = match response.result {
        UpdateResult::Success { .. } => {
            let handshake = match &decoded.bundle {
                HandshakeBundle::Commit {
                    proposal_or_commit, ..
                }
                | HandshakeBundle::Proposal {
                    proposal_or_commit, ..
                } => proposal_or_commit,
            };
            let hash = Sha256::digest(handshake.as_bytes()).into();
            store
                .projection_accepted_ids(caller.user().as_str(), room_id, &hash)
                .await
                .map_err(|e| server_fail(METHOD, &e))?
        }
        _ => Vec::new(),
    };
    Ok((response, message_ids))
}
