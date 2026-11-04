//! protocol-07 §5.6 `POST /groupInfo/{roomId}`: give a client what it needs
//! to join a room's group by external Commit.
//!
//! The steps, under the hub's writer lock (decision mimid-1wgh.6.7), which
//! keeps the room's in-memory state and its stored snapshot in step:
//!
//! 1. Look up the room, then decode the [`GroupInfoRequest`]. The body size
//!    cap is [`crate::http::MAX_BODY_LEN`], enforced before the body
//!    reaches the hub.
//! 2. The request's signature must verify with `requestingSignatureKey`,
//!    over the TBS bytes as received ([`GroupInfoRequest::verify`]).
//! 3. `requestingCredential` must be a BasicCredential whose identity is a
//!    user URI (decision mimid-1wgh.6.1), and the `From` domain must be
//!    that URI's domain (decision mimid-1wgh.6.9).
//! 4. Room policy must let that user fetch the GroupInfo
//!    ([`policy::authorize_group_info`]): a listed participant whose role
//!    holds `canAddOwnClient`, or an unlisted user allowed by `canOpenJoin`
//!    or by preauthorization. A request with a `joiningCode` is refused
//!    (decision mimid-1wgh.6.13).
//! 5. The payload is the stored GroupInfo, which never embeds a
//!    ratchet_tree (decision mimid-1wgh.6.11), the stored ratchet tree as a
//!    `full` [`RatchetTreeOption`], and the current epoch's pending
//!    proposals in hub order with their `hub_accepted_time`. It is
//!    encrypted to `groupInfoPublicKey` with the room ID as context
//!    ([`encrypt_group_info`]).
//! 6. The `GroupInfoResponseTBS` is signed with the hub's key. `hub_sender`
//!    is that key with the credential `mimi://<hub domain>` (decisions
//!    mimid-1wgh.6.18, mimid-1wgh.6.35), and `cipher_suite` is the
//!    request's.
//!
//! Every refusal in steps 2 to 5 is `notAuthorized`, the only failure
//! code §5.6 defines besides `noSuchRoom` (decision mimid-1wgh.6.59). A
//! room not hosted here is [`HubError::NoSuchRoom`], which HTTP answers
//! with `404` (decisions mimid-1wgh.6.8, mimid-1wgh.6.60). Nothing is
//! written.
//!
//! # Limitations
//!
//! - With BasicCredential the hub cannot bind `requestingSignatureKey` to
//!   `requestingCredential`, so anyone who claims the identity of a
//!   participant holding `canAddOwnClient` gets the room's GroupInfo, ratchet
//!   tree and pending proposals. The `From` check is a consistency check, not
//!   security (decision mimid-1wgh.6.9). The external Commit that follows
//!   still goes through `/update` and room policy.
//! - A request is not correlated with the external Commit that follows it
//!   (decision mimid-1wgh.6.14).
//! - Join codes are not supported (decision mimid-1wgh.6.13).
//! - The ratchet tree is always sent `full` (decision mimid-1wgh.6.11).
//! - A `groupInfoPublicKey` that HPKE cannot encrypt to gets
//!   `notAuthorized`, as §5.6 has no code for a malformed request.

use mimi_mls::tls_codec::{Deserialize, Serialize};
use mimi_mls::wire::{ExternalSender, GroupInfo, MLSMessage, RatchetTreeOption};
use mimi_protocol::{
    GroupInfoRatchetTreeTbe, GroupInfoRequest, GroupInfoResponse, GroupInfoResponseTbs,
    PendingProposal, Protocol, encrypt_group_info,
};

use super::room::{GROUP_INFO_MESSAGE_HEADER, hub_sender};
use super::state::{room_state, user_domain};
use super::{Hub, HubError, Room, policy};
use crate::config::Domain;
use crate::store::{RoomSnapshot, StoreError};

/// Runs [`Hub::group_info`].
pub(super) async fn group_info(
    hub: &Hub,
    room_id: &str,
    from: &Domain,
    request: &[u8],
) -> Result<Vec<u8>, HubError> {
    let rooms = hub.rooms.lock().await;
    // protocol-07 §5.6; decision mimid-1wgh.6.60: 404, not a noSuchRoom body.
    if !rooms.contains_key(room_id) {
        return Err(HubError::NoSuchRoom);
    }
    let decoded =
        GroupInfoRequest::tls_deserialize_exact(request).map_err(HubError::InvalidRequest)?;
    // A `&Room` must not live across an await: the Observer's MLS store is
    // not `Sync`. It is used only inside this block.
    let epoch = {
        let room = rooms.get(room_id).ok_or(HubError::NoSuchRoom)?;
        if let Err(reason) = check(room, room_id, from, &decoded) {
            return refuse(room_id, reason);
        }
        room.observer.epoch()
    };
    let snapshot = hub
        .store
        .room(room_id)
        .await?
        .ok_or(StoreError::Corrupt("hosted room is not stored"))?;
    if snapshot.epoch != epoch {
        return Err(HubError::SnapshotMismatch {
            room_id: room_id.to_owned(),
        });
    }
    let pending = hub
        .store
        .pending_proposals_with_times(room_id, epoch)
        .await?;
    let pending_count = pending.len();
    let tbe = payload(&snapshot, pending)?;
    let tbs = decoded.tbs();
    // protocol-07 §5.6; decisions mimid-1wgh.5.30 (room_id context),
    // mimid-1wgh.5.55 (suite-1 HPKE).
    let encrypted = match encrypt_group_info(&tbs.group_info_public_key, room_id.as_bytes(), &tbe) {
        Ok(encrypted) => encrypted,
        Err(mimi_protocol::Error::Encoding(error)) => return Err(HubError::Encode(error)),
        Err(_) => return refuse(room_id, "groupInfoPublicKey is unusable"),
    };
    let (key, credential) = hub_sender(hub.signing_key.public(), &hub.domain)?;
    let response_tbs = GroupInfoResponseTbs {
        protocol: Protocol::Mls10,
        room_id: room_id.as_bytes().to_vec(),
        cipher_suite: tbs.cipher_suite,
        hub_sender: ExternalSender::tls_deserialize_exact([key, credential].concat())
            .map_err(HubError::Encode)?,
        encrypted_groupinfo_and_tree: encrypted,
    };
    let success = hub.signing_key.sign_group_info_response(response_tbs)?;
    let body = GroupInfoResponse::Success(success)
        .tls_serialize_detached()
        .map_err(HubError::Encode)?;
    tracing::info!(
        room_id,
        epoch,
        pending_proposals = pending_count,
        "GroupInfo served"
    );
    Ok(body)
}

/// Runs steps 2 to 4 of the module documentation. Returns why the request
/// is refused, if it is.
fn check(
    room: &Room,
    room_id: &str,
    from: &Domain,
    request: &GroupInfoRequest,
) -> Result<(), &'static str> {
    request
        .verify()
        .map_err(|_| "unsupported cipher_suite or bad request signature")?;
    let tbs = request.tbs();
    let requester = tbs
        .requesting_credential
        .identity()
        .ok_or("requesting credential is not a BasicCredential")?;
    // Decision mimid-1wgh.6.9: a consistency check, made before anything
    // else reads the room.
    let requester_domain = std::str::from_utf8(requester).ok().and_then(user_domain);
    if requester_domain != Some(from.as_str()) {
        return Err("From domain is not the requesting credential's domain");
    }
    // create_room refuses a room without a valid base_room_policy, so a
    // missing one here is defence in depth (decisions mimid-1wgh.6.51,
    // mimid-1wgh.6.57).
    let state = room_state(&room.observer).map_err(|error| {
        tracing::warn!(room_id, %error, "room policy state unusable; GroupInfo refused");
        "room policy state unusable"
    })?;
    policy::authorize_group_info(&state, requester, tbs.joining_code.as_deref()).map_err(|denied| {
        tracing::debug!(room_id, %denied, "groupInfo refused by room policy");
        "refused by room policy"
    })
}

/// Builds the `GroupInfoRatchetTreeTBE` from the room's stored snapshot and
/// its current pending proposals as (proposal, `hub_accepted_time`).
fn payload(
    snapshot: &RoomSnapshot,
    pending: Vec<(Vec<u8>, u64)>,
) -> Result<GroupInfoRatchetTreeTbe, HubError> {
    let corrupt = |what| HubError::Store(StoreError::Corrupt(what));
    let group_info = snapshot
        .group_info
        .strip_prefix(&GROUP_INFO_MESSAGE_HEADER)
        .and_then(|body| GroupInfo::tls_deserialize_exact(body).ok())
        .ok_or_else(|| corrupt("stored GroupInfo does not decode"))?;
    let ratchet_tree_option = RatchetTreeOption::full(&snapshot.ratchet_tree)
        .map_err(|_| corrupt("stored ratchet tree does not decode"))?;
    let pending_proposals = pending
        .into_iter()
        .map(|(proposal, hub_accepted_time)| {
            Ok(PendingProposal {
                proposal: MLSMessage::tls_deserialize_exact(proposal)
                    .map_err(|_| corrupt("stored pending proposal does not decode"))?,
                hub_accepted_time,
            })
        })
        .collect::<Result<_, HubError>>()?;
    Ok(GroupInfoRatchetTreeTbe {
        group_info,
        ratchet_tree_option,
        pending_proposals,
    })
}

/// Logs why a request is refused and answers `notAuthorized`
/// (protocol-07 §5.6; decision mimid-1wgh.6.59).
fn refuse(room_id: &str, reason: &str) -> Result<Vec<u8>, HubError> {
    tracing::debug!(room_id, reason, "groupInfo refused");
    GroupInfoResponse::NotAuthorized {
        protocol: Protocol::Mls10,
        room_id: room_id.as_bytes().to_vec(),
    }
    .tls_serialize_detached()
    .map_err(HubError::Encode)
}
