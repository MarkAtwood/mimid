//! protocol-06 §5.3 `POST /update/{roomId}`: accept a Commit or proposals,
//! log them in hub order and enqueue their fanout.
//!
//! The steps, under the hub's writer lock (decision mimid-1wgh.6.7):
//!
//! 1. Look up the room, then decode the [`UpdateRequest`]. The body size
//!    cap is [`crate::http::MAX_BODY_LEN`], enforced before the body reaches
//!    the hub.
//! 2. A request whose exact bytes were already accepted for the room gets
//!    `success` with the logged acceptance time again, and nothing is
//!    written. This runs before every other check, as for submitMessage
//!    (decision mimid-1wgh.6.50).
//! 3. The handshake message must name the room's group, and its epoch must
//!    be the current one, or the answer is `wrongEpoch` with the current
//!    epoch.
//!
//! For a Commit:
//!
//! 4. [`Observer::process`] stages it. MLS validity alone decides whether
//!    it can win the epoch (decision mimid-1wgh.6.5); the hub's `apply`
//!    function for AppDataUpdates is [`components::apply_commit_op`]
//!    (decision mimid-1wgh.6.53).
//! 5. An external Commit is refused while proposals are pending (decision
//!    mimid-1wgh.6.4).
//! 6. The `From` domain must be the domain of the authenticated
//!    committer's user (decision mimid-1wgh.6.9).
//! 7. Room policy must allow the Commit ([`policy::authorize_commit`]).
//! 8. The Commit must include every pending proposal (decision
//!    mimid-1wgh.6.5).
//! 9. The GroupInfo must not embed a ratchet_tree (decision
//!    mimid-1wgh.6.11).
//! 10. The Commit is merged. A full GroupInfo is verified as received; a
//!     PartialGroupInfo is rebuilt into one (decisions mimid-1wgh.4.46,
//!     mimid-1wgh.4.47).
//! 11. In one transaction the Commit is logged, the room's snapshot is
//!     replaced, the old epoch's pending proposals are dropped, and the
//!     fanout is enqueued: the Commit for the member domains before and
//!     after it plus the origin (decision mimid-1wgh.6.17), and the Welcome
//!     for the domains of the users its Add proposals add (decision
//!     mimid-1wgh.6.10), with the hub's own tree as
//!     `RatchetTreeOption::full` (decision mimid-1wgh.6.12).
//!
//! A refused Commit is dropped, and the epoch stays open for the next
//! valid and allowed Commit (decision mimid-1wgh.6.5). A refusal or failure
//! after the merge rebuilds the room from its stored state.
//!
//! For proposals, `proposalOrCommit` and then each `moreProposals` entry:
//!
//! 4. [`Observer::process_proposal`] validates and stores it.
//! 5. The `From` domain must be the domain of `proposalOrCommit`'s sender.
//! 6. Room policy must allow each proposal, with its sender as the actor
//!    ([`policy::authorize_proposal`]).
//! 7. An AppDataUpdate must keep the epoch's pending proposals valid under
//!    mls-extensions-10 §4.7, since they all go into the next Commit
//!    (protocol-06 §3.5) and a committer refuses to commit an invalid one
//!    (decision mimid-1wgh.4.65): its component must be one the hub's
//!    AppDataUpdate logic knows ([`components::is_known_component`]), a
//!    remove needs data present, and no component may get two removes, or
//!    a remove and an update, across the pending proposals and the request
//!    (bead mimid-1wgh.6.73).
//! 8. In one transaction the request is logged, every proposal is stored
//!    as pending with its `hub_accepted_time`, and one FanoutMessage
//!    carrying them all, as received, is enqueued for the member domains
//!    and the origin (protocol-06 §5.5).
//!
//! A refusal after a proposal was stored rebuilds the room from its stored
//! state. Every refusal is `notAllowed` with an `errorDescription`
//! (decision mimid-1wgh.6.55).
//!
//! # Limitations
//!
//! - The `From` checks are consistency checks, not security (decision
//!   mimid-1wgh.6.9).
//! - MLS-invalid messages are answered `notAllowed`; `invalidProposal` is
//!   never sent, since the hub cannot compute the ProposalRef of a proposal
//!   that fails validation (decision mimid-1wgh.6.55).
//! - Only `proposalOrCommit`'s sender is checked against `From`; each
//!   `moreProposals` entry is authorized for its own sender (decision
//!   mimid-1wgh.6.56).
//! - A room whose GroupContext lacks a usable `base_room_policy` refuses
//!   every Commit and proposal. [`Hub::create_room`] already refuses such a
//!   group, so this is defence in depth (decisions mimid-1wgh.6.51,
//!   mimid-1wgh.6.57).
//! - The hub never staples proposals to an external Commit (decision
//!   mimid-1wgh.6.4), so `externalProposals` in its fanout is always
//!   empty.
//! - ponytail: undoing a refused proposal or a failed write rebuilds the
//!   whole room from storage, which costs one GroupInfo verification and
//!   one replay of the pending proposals. Upgrade path: an Observer call
//!   that drops stored proposals.

use std::collections::{BTreeSet, HashSet};
use std::iter;

use mimi_mls::member::Sender;
use mimi_mls::observer::{CommitDetail, Observed, ProposalDetail, ProposalKind as MlsProposal};
use mimi_mls::tls_codec::{Deserialize, Serialize};
use mimi_mls::wire::{MLSMessage, ProposalRef, RatchetTreeOption, RatchetTreePresence, Welcome};
use mimi_protocol::{
    FanoutEvent, FanoutMessage, GroupInfoOption, HandshakeBundle, UpdateRequest, UpdateResult,
    UpdateRoomResponse, Utf8String,
};
use sha2::{Digest, Sha256};

use super::components;
use super::policy::{
    self, AppDataOp, Commit, Committer, Origin, Proposal, ProposalKind, ProposalSender, RoomState,
};
use super::room::GROUP_INFO_MESSAGE_HEADER;
use super::state::{identity_domain, member_domains, room_state};
use super::{Hub, HubError, PendingAppData, Room, restore_room};
use crate::config::Domain;
use crate::store::{EpochSnapshot, EventKind, NewEvent, OutboxEntry};

/// RFC 9420 §6: the MLSMessage header of a Welcome, `version` mls10
/// (0x0001) and `wire_format` mls_welcome (0x0003).
const WELCOME_MESSAGE_HEADER: [u8; 4] = [0x00, 0x01, 0x00, 0x03];

/// mls-extensions-10 §7.2: the suggested `app_ephemeral` ProposalType.
const APP_EPHEMERAL_PROPOSAL_TYPE: u16 = 0x0009;

/// Runs [`Hub::update`].
pub(super) async fn update(
    hub: &Hub,
    room_id: &str,
    from: &Domain,
    request: &[u8],
) -> Result<Vec<u8>, HubError> {
    let mut rooms = hub.rooms.lock().await;
    // A `&Room` must not live across an await: the Observer's MLS store is
    // not `Sync`. The room is looked up again after each await.
    if !rooms.contains_key(room_id) {
        return Err(HubError::NoSuchRoom);
    }
    let decoded =
        UpdateRequest::tls_deserialize_exact(request).map_err(HubError::InvalidRequest)?;
    let hash = Sha256::digest(request);
    let kind = match decoded.bundle {
        HandshakeBundle::Commit { .. } => EventKind::Commit,
        HandshakeBundle::Proposal { .. } => EventKind::Proposal,
    };
    // Decision mimid-1wgh.6.50: retries are answered before any other check.
    if let Some(accepted_at) = hub.store.event_accepted_at(room_id, kind, &hash).await? {
        tracing::debug!(room_id, "update retry answered from the log");
        return success(accepted_at);
    }

    let room = rooms.get_mut(room_id).ok_or(HubError::NoSuchRoom)?;
    let staged = match &decoded.bundle {
        HandshakeBundle::Commit {
            proposal_or_commit,
            welcome,
            group_info_option,
            ..
        } => stage_commit(
            hub,
            room,
            room_id,
            from,
            proposal_or_commit,
            welcome.as_ref(),
            group_info_option,
        ),
        HandshakeBundle::Proposal {
            proposal_or_commit,
            more_proposals,
        } => stage_proposals(hub, room, room_id, from, proposal_or_commit, more_proposals),
    };
    let accepted = match staged {
        Ok(Outcome::Accept(accepted)) => accepted,
        Ok(Outcome::Respond { response, restore }) => {
            if restore {
                restore_room(hub, &mut rooms, room_id).await?;
            }
            return Ok(response);
        }
        Err(error) => {
            restore_after_error(hub, &mut rooms, room_id).await;
            return Err(error);
        }
    };

    let outbox: Vec<_> = accepted
        .outbox
        .iter()
        .map(|(domain, body)| OutboxEntry { domain, body })
        .collect();
    let event = NewEvent {
        room_id,
        epoch: accepted.epoch,
        accepted_at: accepted.accepted_at,
        kind,
        bytes: accepted.message.as_bytes(),
        hash: &hash,
    };
    let written = match &accepted.write {
        Write::Commit {
            group_info,
            ratchet_tree,
            new_epoch,
        } => {
            let snapshot = EpochSnapshot {
                epoch: *new_epoch,
                group_info,
                ratchet_tree,
            };
            hub.store.append_commit(&event, &snapshot, &outbox).await
        }
        Write::Proposals { proposals, .. } => {
            let proposals: Vec<_> = proposals.iter().map(MLSMessage::as_bytes).collect();
            hub.store
                .append_proposals(&event, &proposals, &outbox)
                .await
        }
    };
    let seq = match written {
        Ok(seq) => seq,
        Err(error) => {
            restore_after_error(hub, &mut rooms, room_id).await;
            return Err(error.into());
        }
    };

    let room = rooms.get_mut(room_id).ok_or(HubError::NoSuchRoom)?;
    match accepted.write {
        Write::Commit { new_epoch, .. } => {
            room.pending.clear();
            room.app_data = PendingAppData::default();
            tracing::info!(
                room_id,
                seq,
                epoch = new_epoch,
                destinations = outbox.len(),
                "commit accepted"
            );
        }
        Write::Proposals {
            references,
            app_data,
            ..
        } => {
            let count = references.len();
            room.pending.extend(references);
            room.app_data = app_data;
            tracing::info!(
                room_id,
                seq,
                epoch = accepted.epoch,
                proposals = count,
                destinations = outbox.len(),
                "proposals accepted"
            );
        }
    }
    hub.wake_fanout();
    success(accepted.accepted_at)
}

/// Rebuilds a room after an internal failure, logging a rebuild failure so
/// that the original error is the one returned.
async fn restore_after_error(
    hub: &Hub,
    rooms: &mut std::collections::BTreeMap<String, Room>,
    room_id: &str,
) {
    if let Err(error) = restore_room(hub, rooms, room_id).await {
        tracing::error!(room_id, %error, "room could not be rebuilt; it is unavailable until restart");
    }
}

/// The result of a staging step.
enum Outcome {
    /// Answer with `response`; first rebuild the room if `restore` is set,
    /// because the Observer holds changes that must not stay.
    Respond { response: Vec<u8>, restore: bool },
    /// Write and answer `success`.
    Accept(Accepted),
}

/// What to write for an accepted request.
struct Accepted {
    /// The epoch the message was accepted in.
    epoch: u64,
    accepted_at: u64,
    /// The `proposalOrCommit` message, logged as received.
    message: MLSMessage,
    /// (destination domain, FanoutMessage) pairs, in enqueue order.
    outbox: Vec<(String, Vec<u8>)>,
    write: Write,
}

/// The rows an accepted request writes besides its log event and outbox.
enum Write {
    /// The room's new snapshot.
    Commit {
        new_epoch: u64,
        group_info: Vec<u8>,
        ratchet_tree: Vec<u8>,
    },
    /// The proposals to store as pending, as received, with their
    /// ProposalRefs.
    Proposals {
        proposals: Vec<MLSMessage>,
        references: Vec<ProposalRef>,
        /// The epoch's pending AppDataUpdate operations with these added.
        app_data: PendingAppData,
    },
}

/// Encodes a response.
fn respond(result: UpdateResult, error_description: &str) -> Result<Vec<u8>, HubError> {
    UpdateRoomResponse {
        // The descriptions are fixed strings without NUL.
        error_description: Utf8String::new(error_description).unwrap_or_default(),
        result,
    }
    .tls_serialize_detached()
    .map_err(HubError::Encode)
}

/// Encodes `success`.
fn success(accepted_timestamp: u64) -> Result<Vec<u8>, HubError> {
    respond(UpdateResult::Success { accepted_timestamp }, "")
}

/// Logs why a request is refused and answers `notAllowed` with `reason`
/// (decision mimid-1wgh.6.55).
fn refuse(room_id: &str, reason: &'static str, restore: bool) -> Result<Outcome, HubError> {
    tracing::debug!(room_id, reason, "update refused");
    Ok(Outcome::Respond {
        response: respond(UpdateResult::NotAllowed, reason)?,
        restore,
    })
}

/// Checks the handshake message's group and epoch (step 3).
fn check_epoch(
    room: &Room,
    room_id: &str,
    message: &MLSMessage,
) -> Option<Result<Outcome, HubError>> {
    if message.group_id() != Some(room.observer.group_id()) {
        return Some(refuse(room_id, "group_id is not the room's group", false));
    }
    let current_epoch = room.observer.epoch();
    if message.epoch() != Some(current_epoch) {
        tracing::debug!(room_id, current_epoch, "update for another epoch");
        return Some(
            respond(
                UpdateResult::WrongEpoch { current_epoch },
                "the room is in another epoch",
            )
            .map(|response| Outcome::Respond {
                response,
                restore: false,
            }),
        );
    }
    None
}

/// Runs the Commit steps 3 to 10 of the module documentation.
fn stage_commit(
    hub: &Hub,
    room: &mut Room,
    room_id: &str,
    from: &Domain,
    commit: &MLSMessage,
    welcome: Option<&Welcome>,
    group_info_option: &GroupInfoOption,
) -> Result<Outcome, HubError> {
    if let Some(refused) = check_epoch(room, room_id, commit) {
        return refused;
    }
    let epoch = room.observer.epoch();
    // create_room refuses a room without a valid base_room_policy, so a
    // missing one here is defence in depth (decisions
    // mimid-1wgh.6.51, mimid-1wgh.6.57).
    let state = match room_state(&room.observer) {
        Ok(state) => state,
        Err(error) => {
            tracing::warn!(room_id, %error, "room policy state unusable; commit refused");
            return refuse(room_id, "the room has no usable policy", false);
        }
    };
    let domains_before = member_domains(&room.observer);

    // Decision mimid-1wgh.6.5: MLS validity alone picks the winning Commit.
    match room.observer.process(
        &room.mls_store,
        commit.as_bytes(),
        components::apply_commit_op,
    ) {
        Ok(Observed::Commit(_)) => {}
        Ok(_) => return refuse(room_id, "not a commit", true),
        Err(error) => {
            tracing::debug!(room_id, %error, "commit failed MLS validation");
            return refuse(room_id, "the commit is not valid", false);
        }
    }
    let refused = |room: &mut Room, reason| {
        room.observer.clear_pending_commit();
        refuse(room_id, reason, false)
    };
    let detail = match room.observer.pending_commit_detail() {
        Ok(detail) => detail,
        Err(error) => {
            room.observer.clear_pending_commit();
            return Err(HubError::Mls(error));
        }
    };

    // Decision mimid-1wgh.6.4.
    if detail.committer == Sender::NewMemberCommit && !room.pending.is_empty() {
        return refused(
            room,
            "external commits are refused while proposals are pending",
        );
    }
    // Decision mimid-1wgh.6.9: checked before any write.
    if identity_domain(&detail.committer_identity).as_ref() != Some(from) {
        return refused(room, "From domain is not the committer's domain");
    }
    let summary = match commit_summary(&detail) {
        Ok(summary) => summary,
        Err(reason) => return refused(room, reason),
    };
    if let Err(denied) = policy::authorize_commit(&state, &summary) {
        tracing::debug!(room_id, %denied, "commit refused by room policy");
        return refused(room, "the commit is refused by room policy");
    }
    // Decision mimid-1wgh.6.5.
    let included: HashSet<&ProposalRef> = detail
        .proposals
        .iter()
        .filter_map(|proposal| proposal.reference.as_ref())
        .collect();
    if !room
        .pending
        .iter()
        .all(|pending| included.contains(pending))
    {
        return refused(room, "the commit does not include every pending proposal");
    }
    // Decision mimid-1wgh.6.11.
    let embeds_tree = match group_info_option {
        GroupInfoOption::Full { group_info } => group_info.has_ratchet_tree_extension(),
        GroupInfoOption::Partial { partial_group_info } => matches!(
            partial_group_info.ratchet_tree_presence(),
            RatchetTreePresence::Present | RatchetTreePresence::Added
        ),
    };
    if embeds_tree {
        return refused(room, "the GroupInfo embeds a ratchet_tree");
    }
    // Decision mimid-1wgh.6.10: Welcomes go to the domains of added users.
    let welcome_domains: BTreeSet<String> = detail
        .proposals
        .iter()
        .filter_map(|proposal| match &proposal.proposal {
            MlsProposal::Add { identity, .. } => identity_domain(identity),
            _ => None,
        })
        .map(|domain| domain.as_str().to_owned())
        .collect();

    room.observer
        .merge_pending_commit(&room.mls_store)
        .map_err(HubError::Mls)?;
    let group_info = match group_info_option {
        GroupInfoOption::Full { group_info } => room
            .observer
            .verify_group_info(group_info)
            .map(|()| [&GROUP_INFO_MESSAGE_HEADER[..], group_info.as_bytes()].concat()),
        GroupInfoOption::Partial { partial_group_info } => {
            room.observer.group_info(partial_group_info)
        }
    };
    let group_info = match group_info {
        Ok(group_info) => group_info,
        Err(error) => {
            tracing::debug!(room_id, %error, "GroupInfo does not match the merged commit");
            return refuse(room_id, "the GroupInfo is not valid", true);
        }
    };
    let ratchet_tree = room.observer.ratchet_tree().map_err(HubError::Mls)?;
    let new_epoch = room.observer.epoch();

    // Decision mimid-1wgh.6.17.
    let mut destinations = domains_before;
    destinations.extend(member_domains(&room.observer));
    destinations.insert(from.as_str().to_owned());
    let accepted_at = hub.clock.now_ms();
    let commit_body = FanoutMessage {
        timestamp: accepted_at,
        event: FanoutEvent::Commit {
            message: commit.clone(),
            external_proposals: Vec::new(),
        },
    }
    .tls_serialize_detached()
    .map_err(HubError::Encode)?;
    let mut outbox: Vec<_> = destinations
        .into_iter()
        .map(|domain| (domain, commit_body.clone()))
        .collect();
    if let Some(welcome) = welcome
        && !welcome_domains.is_empty()
    {
        let message = MLSMessage::tls_deserialize_exact(
            [&WELCOME_MESSAGE_HEADER[..], welcome.as_bytes()].concat(),
        )
        .map_err(HubError::Encode)?;
        // Decision mimid-1wgh.6.12: the hub's own tree, whatever the client
        // sent.
        let welcome_body = FanoutMessage {
            timestamp: accepted_at,
            event: FanoutEvent::Welcome {
                message,
                ratchet_tree_option: RatchetTreeOption::full(&ratchet_tree)
                    .map_err(HubError::Encode)?,
            },
        }
        .tls_serialize_detached()
        .map_err(HubError::Encode)?;
        outbox.extend(
            welcome_domains
                .into_iter()
                .map(|domain| (domain, welcome_body.clone())),
        );
    }
    Ok(Outcome::Accept(Accepted {
        epoch,
        accepted_at,
        message: commit.clone(),
        outbox,
        write: Write::Commit {
            new_epoch,
            group_info,
            ratchet_tree,
        },
    }))
}

/// Runs the proposal steps 3 to 6 of the module documentation.
fn stage_proposals(
    hub: &Hub,
    room: &mut Room,
    room_id: &str,
    from: &Domain,
    proposal: &MLSMessage,
    more_proposals: &[MLSMessage],
) -> Result<Outcome, HubError> {
    if let Some(refused) = check_epoch(room, room_id, proposal) {
        return refused;
    }
    let epoch = room.observer.epoch();
    // create_room refuses a room without a valid base_room_policy, so a
    // missing one here is defence in depth (decisions
    // mimid-1wgh.6.51, mimid-1wgh.6.57).
    let state = match room_state(&room.observer) {
        Ok(state) => state,
        Err(error) => {
            tracing::warn!(room_id, %error, "room policy state unusable; proposal refused");
            return refuse(room_id, "the room has no usable policy", false);
        }
    };
    let mut references = Vec::with_capacity(1 + more_proposals.len());
    let mut app_data = room.app_data.clone();
    for (index, message) in iter::once(proposal).chain(more_proposals).enumerate() {
        // Every proposal before this one is stored in the Observer.
        let stored = index > 0;
        let detail = match room
            .observer
            .process_proposal(&room.mls_store, message.as_bytes())
        {
            Ok(detail) => detail,
            Err(error) => {
                tracing::debug!(room_id, index, %error, "proposal failed MLS validation");
                return refuse(room_id, "a proposal is not valid", stored);
            }
        };
        let (sender, kind) = match (proposal_sender(&detail), proposal_kind(&detail.proposal)) {
            (Ok(sender), Ok(kind)) => (sender, kind),
            (Err(reason), _) | (_, Err(reason)) => return refuse(room_id, reason, true),
        };
        // Decisions mimid-1wgh.6.9, mimid-1wgh.6.56: the sender of
        // proposalOrCommit only; checked before any write.
        if index == 0 && sender_domain(&state, &sender) != Some(from.clone()) {
            return refuse(room_id, "From domain is not the proposer's domain", true);
        }
        if let Err(denied) = policy::authorize_proposal(&state, &kind, &sender) {
            tracing::debug!(room_id, index, %denied, "proposal refused by room policy");
            return refuse(room_id, "a proposal is refused by room policy", true);
        }
        // mls-extensions-10 §4.7; decision mimid-1wgh.4.65; bead
        // mimid-1wgh.6.73.
        if let MlsProposal::AppDataUpdate {
            component_id,
            update,
        } = &detail.proposal
        {
            let remove = update.is_none();
            if !components::is_known_component(*component_id) {
                return refuse(
                    room_id,
                    "an AppDataUpdate names a component the hub does not know",
                    true,
                );
            }
            if remove && room.observer.component(*component_id).is_none() {
                return refuse(
                    room_id,
                    "an AppDataUpdate removes data the room does not have",
                    true,
                );
            }
            if app_data.conflicts(*component_id, remove) {
                return refuse(
                    room_id,
                    "an AppDataUpdate conflicts with a pending proposal",
                    true,
                );
            }
            app_data.record(*component_id, remove);
        }
        let Some(reference) = detail.reference else {
            return refuse(room_id, "a proposal has no ProposalRef", true);
        };
        references.push(reference);
    }

    let accepted_at = hub.clock.now_ms();
    // protocol-06 §5.5: the proposals are forwarded as received.
    let body = FanoutMessage {
        timestamp: accepted_at,
        event: FanoutEvent::Proposal {
            message: proposal.clone(),
            more_proposals: more_proposals.to_vec(),
        },
    }
    .tls_serialize_detached()
    .map_err(HubError::Encode)?;
    // Decision mimid-1wgh.6.17.
    let mut destinations = member_domains(&room.observer);
    destinations.insert(from.as_str().to_owned());
    Ok(Outcome::Accept(Accepted {
        epoch,
        accepted_at,
        message: proposal.clone(),
        outbox: destinations
            .into_iter()
            .map(|domain| (domain, body.clone()))
            .collect(),
        write: Write::Proposals {
            proposals: iter::once(proposal)
                .chain(more_proposals)
                .cloned()
                .collect(),
            references,
            app_data,
        },
    }))
}

/// The provider domain of a proposal's sender.
fn sender_domain(state: &RoomState, sender: &ProposalSender) -> Option<Domain> {
    match sender {
        ProposalSender::Member { leaf_index } => state
            .members
            .get(leaf_index)
            .and_then(|identity| identity_domain(identity)),
        ProposalSender::NewMember { user } => identity_domain(user),
        ProposalSender::External { .. } => None,
    }
}

/// Summarizes a staged Commit for room policy.
fn commit_summary(detail: &CommitDetail) -> Result<Commit, &'static str> {
    let committer = match detail.committer {
        Sender::Member(leaf_index) => Committer::Member { leaf_index },
        Sender::NewMemberCommit => Committer::External {
            user: detail.committer_identity.clone(),
        },
        _ => return Err("the commit has an unexpected sender"),
    };
    let proposals = detail
        .proposals
        .iter()
        .map(|proposal| {
            let origin = match proposal.reference {
                Some(_) => Origin::ByReference(proposal_sender(proposal)?),
                None => Origin::Inline,
            };
            Ok(Proposal {
                kind: proposal_kind(&proposal.proposal)?,
                origin,
            })
        })
        .collect::<Result<_, &'static str>>()?;
    Ok(Commit {
        committer,
        path_identity_changed: detail
            .path
            .as_ref()
            .is_some_and(|path| path.identity_changed),
        proposals,
    })
}

/// The sender of a proposal sent on its own.
fn proposal_sender(detail: &ProposalDetail) -> Result<ProposalSender, &'static str> {
    match detail.sender {
        Sender::Member(leaf_index) => Ok(ProposalSender::Member { leaf_index }),
        Sender::External(sender_index) => Ok(ProposalSender::External { sender_index }),
        // A new member proposes only to add itself (RFC 9420 §12.1.8.2).
        Sender::NewMemberProposal => match &detail.proposal {
            MlsProposal::Add { identity, .. } => Ok(ProposalSender::NewMember {
                user: identity.clone(),
            }),
            _ => Err("a new-member proposal is not an Add"),
        },
        _ => Err("a proposal has an unexpected sender"),
    }
}

/// What a proposal does, for room policy.
fn proposal_kind(proposal: &MlsProposal) -> Result<ProposalKind, &'static str> {
    Ok(match proposal {
        MlsProposal::Add { identity, .. } => ProposalKind::Add {
            user: identity.clone(),
        },
        MlsProposal::Update {
            identity_changed, ..
        } => ProposalKind::Update {
            identity_changed: *identity_changed,
        },
        MlsProposal::Remove { removed, .. } => ProposalKind::Remove {
            leaf_index: *removed,
        },
        MlsProposal::PreSharedKey => ProposalKind::PreSharedKey,
        MlsProposal::ReInit => ProposalKind::ReInit,
        MlsProposal::ExternalInit => ProposalKind::ExternalInit,
        MlsProposal::GroupContextExtensions => ProposalKind::GroupContextExtensions,
        MlsProposal::AppDataUpdate {
            component_id,
            update,
        } => ProposalKind::AppDataUpdate {
            component_id: *component_id,
            op: update.clone().map_or(AppDataOp::Remove, AppDataOp::Update),
        },
        MlsProposal::SelfRemove => ProposalKind::SelfRemove,
        MlsProposal::AppEphemeral => ProposalKind::Other {
            proposal_type: APP_EPHEMERAL_PROPOSAL_TYPE,
        },
        MlsProposal::Custom(proposal_type) => ProposalKind::Other {
            proposal_type: *proposal_type,
        },
        _ => return Err("a proposal has an unknown type"),
    })
}
