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
//! 4. A requester that holds a leaf of the group gets the GroupInfo
//!    without a policy check: `requestingSignatureKey` is the signature key
//!    of a current leaf whose member identity is the requesting
//!    credential's (decision mimid-1wgh.81). The request's signature in
//!    step 2 proves it holds that leaf's private key. This is how a joiner
//!    whose Welcome came with the `distributionService` RatchetTreeOption
//!    gets the tree: the Commit that added it is merged, so its leaf is in
//!    the hub's tree, and a member is entitled to the tree it is in.
//! 5. Anyone else needs room policy to let it fetch the GroupInfo
//!    ([`policy::authorize_group_info`]): a listed participant whose role
//!    holds `canAddOwnClient`, or an unlisted user allowed by `canOpenJoin`
//!    or by preauthorization. A request with a `joiningCode` is refused
//!    (decision mimid-1wgh.6.13).
//! 6. The payload is the stored GroupInfo, which never embeds a
//!    ratchet_tree (decision mimid-1wgh.6.11), the stored ratchet tree as a
//!    `full` [`RatchetTreeOption`], and the current epoch's pending
//!    proposals in hub order with their `hub_accepted_time`. It is
//!    encrypted to `groupInfoPublicKey` with the room ID as context
//!    ([`encrypt_group_info`]).
//! 7. The `GroupInfoResponseTBS` is signed with the hub's key. `hub_sender`
//!    is that key with the credential `mimi://<hub domain>` (decisions
//!    mimid-1wgh.6.18, mimid-1wgh.6.35), and `cipher_suite` is the
//!    request's.
//! 8. A response longer than a peer reads ([`crate::http::MAX_BODY_LEN`],
//!    decision mimid-1wgh.6.67) is not sent: the answer is
//!    [`HubError::GroupInfoTooLarge`] (decision mimid-1wgh.81). The hub
//!    refuses a Commit whose newcomers would get that answer
//!    ([`response_len`]), so it comes only when pending proposals have
//!    grown the response since.
//!
//! Every refusal in steps 2 to 6 is `notAuthorized`, the only failure
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
//! - The ratchet tree is always sent `full` (decision mimid-1wgh.6.11), so
//!   a room whose tree does not fit one response cannot be joined, by
//!   external Commit or by a Welcome without the tree (decision
//!   mimid-1wgh.81).
//! - The response is the current epoch's. A joiner whose Welcome is for an
//!   earlier epoch cannot use it (decision mimid-1wgh.81).
//! - A `groupInfoPublicKey` that HPKE cannot encrypt to gets
//!   `notAuthorized`, as §5.6 has no code for a malformed request.

use mimi_mls::tls_codec::{Deserialize, Serialize, VLBytes};
use mimi_mls::wire::{
    CipherSuite, ExternalSender, GroupInfo, HPKECiphertext, HPKEPublicKey, MLSMessage,
    RatchetTreeOption,
};
use mimi_protocol::{
    GroupInfoRatchetTreeTbe, GroupInfoRequest, GroupInfoResponse, GroupInfoResponseTbs,
    PendingProposal, Protocol, encrypt_group_info,
};

use super::room::{GROUP_INFO_MESSAGE_HEADER, hub_sender};
use super::state::{room_state, user_domain};
use super::{Hub, HubError, Room, policy};
use crate::config::Domain;
use crate::store::StoreError;

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
    let tbe = payload(&snapshot.group_info, &snapshot.ratchet_tree, pending)?;
    let tbs = decoded.tbs();
    let Some(encrypted) = encrypt(&tbs.group_info_public_key, room_id, &tbe)? else {
        return refuse(room_id, "groupInfoPublicKey is unusable");
    };
    let body = signed_response(hub, room_id, tbs.cipher_suite, encrypted)?;
    // Decision mimid-1wgh.81: never a response a peer will not read.
    if body.len() > hub.body_limit {
        tracing::info!(
            name: "group_info_too_large",
            room_id,
            epoch,
            len = body.len(),
            limit = hub.body_limit,
            "GroupInfo and ratchet tree too large for one response; not served"
        );
        return Err(HubError::GroupInfoTooLarge { len: body.len() });
    }
    tracing::info!(
        name: "group_info_served",
        room_id,
        epoch,
        pending_proposals = pending_count,
        "GroupInfo served"
    );
    Ok(body)
}

/// The length of the groupInfo response a newcomer of the epoch the hub
/// just merged would get: `group_info` (with its MLSMessage header) and
/// `ratchet_tree` are that epoch's, and there are no pending proposals yet.
/// The response is built in full, encrypted to a key made for the purpose,
/// since its length does not depend on the requester's key (decision
/// mimid-1wgh.81).
///
/// # Errors
///
/// [`HubError::Store`] if `group_info` or `ratchet_tree` does not decode,
/// [`HubError::KeyGeneration`] if no HPKE key can be made, and the errors
/// of signing and encoding.
pub(super) fn response_len(
    hub: &Hub,
    room_id: &str,
    group_info: &[u8],
    ratchet_tree: &[u8],
) -> Result<usize, HubError> {
    let tbe = payload(group_info, ratchet_tree, Vec::new())?;
    let (_, public) =
        mimi_mls::label::HpkePrivateKey::generate().map_err(|_| HubError::KeyGeneration)?;
    let public = VLBytes::new(public)
        .tls_serialize_detached()
        .and_then(HPKEPublicKey::tls_deserialize_exact)
        .map_err(HubError::Encode)?;
    let encrypted = encrypt(&public, room_id, &tbe)?.ok_or(HubError::Store(
        StoreError::Corrupt("a fresh HPKE key is unusable"),
    ))?;
    let suite_1 = CipherSuite::tls_deserialize_exact([0x00, 0x01]).map_err(HubError::Encode)?;
    Ok(signed_response(hub, room_id, suite_1, encrypted)?.len())
}

/// Encrypts `tbe` to `group_info_public_key` with the room ID as context
/// (protocol-07 §5.6; decisions mimid-1wgh.5.30, mimid-1wgh.5.55). `None`
/// if HPKE cannot encrypt to the key.
fn encrypt(
    group_info_public_key: &HPKEPublicKey,
    room_id: &str,
    tbe: &GroupInfoRatchetTreeTbe,
) -> Result<Option<HPKECiphertext>, HubError> {
    match encrypt_group_info(group_info_public_key, room_id.as_bytes(), tbe) {
        Ok(encrypted) => Ok(Some(encrypted)),
        Err(mimi_protocol::Error::Encoding(error)) => Err(HubError::Encode(error)),
        Err(_) => Ok(None),
    }
}

/// The encoded `success` GroupInfoResponse carrying `encrypted`, signed
/// with the hub's key (step 7).
fn signed_response(
    hub: &Hub,
    room_id: &str,
    cipher_suite: CipherSuite,
    encrypted: HPKECiphertext,
) -> Result<Vec<u8>, HubError> {
    let (key, credential) = hub_sender(hub.signing_key.public(), &hub.domain)?;
    let response_tbs = GroupInfoResponseTbs {
        protocol: Protocol::Mls10,
        room_id: room_id.as_bytes().to_vec(),
        cipher_suite,
        hub_sender: ExternalSender::tls_deserialize_exact([key, credential].concat())
            .map_err(HubError::Encode)?,
        encrypted_groupinfo_and_tree: encrypted,
    };
    let success = hub.signing_key.sign_group_info_response(response_tbs)?;
    GroupInfoResponse::Success(success)
        .tls_serialize_detached()
        .map_err(HubError::Encode)
}

/// Runs steps 2 to 5 of the module documentation. Returns why the request
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
    // Decision mimid-1wgh.81: a member, by the leaf key it signed with.
    if holds_leaf(room, requester, tbs.requesting_signature_key.as_bytes()) {
        return Ok(());
    }
    // A malformed policy component is refused at creation, so this is
    // defence in depth (decision mimid-1wgh.6.51); a missing one makes an
    // open room (decision mimid-1wgh.52).
    let state = room_state(&room.observer, room_id).map_err(|error| {
        tracing::warn!(
            name: "group_info_policy_unusable",
            room_id,
            error = &error as &dyn std::error::Error,
            "room policy state unusable; GroupInfo refused"
        );
        "room policy state unusable"
    })?;
    policy::authorize_group_info(&state, requester, tbs.joining_code.as_deref()).map_err(|denied| {
        tracing::debug!(
            room_id,
            denied = &denied as &dyn std::error::Error,
            "groupInfo refused by room policy"
        );
        "refused by room policy"
    })
}

/// Whether `signature_key` (an encoded `SignaturePublicKey`) is the
/// signature key of a current leaf of the room whose member identity is
/// `requester` (step 4; decision mimid-1wgh.81).
fn holds_leaf(room: &Room, requester: &[u8], signature_key: &[u8]) -> bool {
    let Ok(key) = VLBytes::tls_deserialize_exact(signature_key) else {
        return false;
    };
    let identities = room.observer.members();
    room.observer
        .member_signature_keys()
        .iter()
        .filter(|(_, leaf_key)| leaf_key.as_slice() == key.as_slice())
        .any(|(index, _)| {
            identities
                .iter()
                .any(|(leaf, identity)| leaf == index && identity.as_slice() == requester)
        })
}

/// Builds the `GroupInfoRatchetTreeTBE` from a stored GroupInfo (with its
/// MLSMessage header) and ratchet tree, and the pending proposals as
/// (proposal, `hub_accepted_time`).
fn payload(
    group_info: &[u8],
    ratchet_tree: &[u8],
    pending: Vec<(Vec<u8>, u64)>,
) -> Result<GroupInfoRatchetTreeTbe, HubError> {
    let corrupt = |what| HubError::Store(StoreError::Corrupt(what));
    let group_info = group_info
        .strip_prefix(&GROUP_INFO_MESSAGE_HEADER)
        .and_then(|body| GroupInfo::tls_deserialize_exact(body).ok())
        .ok_or_else(|| corrupt("stored GroupInfo does not decode"))?;
    let ratchet_tree_option = RatchetTreeOption::full(ratchet_tree)
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
