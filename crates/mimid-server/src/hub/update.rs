//! protocol-07 §5.3 `POST /update/{roomId}`: accept a Commit or proposals,
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
//! 4. [`Observer::process`](mimi_mls::observer::Observer::process) stages it. MLS validity alone decides whether
//!    it can win the epoch (decision mimid-1wgh.6.5); the hub's `apply`
//!    function for AppDataUpdates is [`components::apply_commit_op`]
//!    (decision mimid-1wgh.6.53).
//! 5. An external Commit is refused while proposals are pending (decision
//!    mimid-1wgh.6.4).
//! 6. The `From` domain must be the domain of the authenticated
//!    committer's user (decision mimid-1wgh.6.9).
//! 7. Room policy must allow the Commit ([`policy::authorize_commit`]).
//!    In a fixed-membership room, a Commit that specifies its participants
//!    must not give it the same set of participants as another
//!    fixed-membership room this hub hosts: "Only a single
//!    fixed-membership room can exist for any unique set of participants"
//!    (room-policy-04 §5; decision mimid-1wgh.89). Parent-dependent
//!    rooms are not counted, on either side (decision mimid-1wgh.110).
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
//!     `RatchetTreeOption::full` (decision mimid-1wgh.6.12), whatever the
//!     client sent. A Welcome whose FanoutMessage would then be longer than
//!     a provider takes ([`crate::http::MAX_BODY_LEN`]) goes out with
//!     `RatchetTreeOption::distributionService` instead, and its joiners
//!     fetch the tree with a groupInfo request signed with their new leaf's
//!     key (decision mimid-1wgh.81; `group_info.rs` step 4). If that
//!     FanoutMessage too, or the groupInfo response the joiners would get,
//!     is longer than that, the tree cannot reach them, and the Commit is
//!     refused before anything is written: the room has outgrown the
//!     transport.
//!
//! 12. If the Commit took a user out of the participant list, and a room
//!     hosted here names this one as its `parent_room`, the hub proposes
//!     that user's removal from the child too (room-policy-04 §5),
//!     through `operator.rs`. It cannot do more: it is not a member and
//!     cannot commit (decision mimid-1wgh.111).
//!
//! A refused Commit is dropped, and the epoch stays open for the next
//! valid and allowed Commit (decision mimid-1wgh.6.5). A refusal or failure
//! after the merge rebuilds the room from its stored state.
//!
//! For proposals, `proposalOrCommit` and then each `moreProposals` entry:
//!
//! 4. [`Observer::process_proposal`](mimi_mls::observer::Observer::process_proposal) validates and stores it.
//! 5. The `From` domain must be the domain of `proposalOrCommit`'s sender.
//! 6. Room policy must allow each proposal, with its sender as the actor
//!    ([`policy::authorize_proposal`]).
//! 7. An AppDataUpdate must keep the epoch's pending proposals valid under
//!    mls-extensions-11 §4.7, since they all go into the next Commit
//!    (protocol-07 §3.5) and a committer refuses to commit an invalid one
//!    (decision mimid-1wgh.4.65): its component must be one the hub's
//!    AppDataUpdate logic knows ([`components::is_known_component`]), a
//!    remove needs data present, and no component may get two removes, or
//!    a remove and an update, across the pending proposals and the request
//!    (bead mimid-1wgh.6.73).
//! 8. In one transaction the request is logged, every proposal is stored
//!    as pending with its `hub_accepted_time`, and one FanoutMessage
//!    carrying them all, as received, is enqueued for the member domains
//!    and the origin (protocol-07 §5.5).
//!
//! A refusal after a proposal was stored rebuilds the room from its stored
//! state. Every refusal is `notAllowed` (decision mimid-1wgh.6.55), with
//! the check that failed in `errorDescription` (draft-atwood-jmap-chat-mimi-00
//! §capability and §Room/update, jmap-chat-spec 735503c; clean-room
//! finding C5, amending bead mimid-1wgh.49, which sent it empty). A Commit
//! or proposal that is not valid MLS is told apart from a policy refusal
//! there: its description starts "the commit is not valid MLS" or "a
//! proposal is not valid MLS", followed by the validation error.
//!
//! # Limitations
//!
//! - The `From` checks are consistency checks, not security (decision
//!   mimid-1wgh.6.9).
//! - MLS-invalid messages are answered `notAllowed`, said so only in
//!   `errorDescription`; `invalidProposal` is never sent, since the hub cannot compute the ProposalRef of a proposal
//!   that fails validation (decision mimid-1wgh.6.55).
//! - Only `proposalOrCommit`'s sender is checked against `From`; each
//!   `moreProposals` entry is authorized for its own sender (decision
//!   mimid-1wgh.6.56).
//! - §5's cascade is a proposal, so a user who left the parent is still
//!   in its parent-dependent rooms, and can still derive their exported
//!   secrets, until a member of the child next commits (decision
//!   mimid-1wgh.111). A cascade that fails is logged and dropped: the
//!   parent's Commit is not undone for it.
//! - A room with a malformed policy component refuses every Commit and
//!   proposal; [`Hub::create_room`] already refuses such a group, so this
//!   is defence in depth (decision mimid-1wgh.6.51). A room without a
//!   `base_room_policy` is an open room (decision mimid-1wgh.52).
//! - The hub never staples proposals to an external Commit (decision
//!   mimid-1wgh.6.4), so `externalProposals` in its fanout is always
//!   empty.
//! - The groupInfo response carries the same tree as a `full` Welcome, so
//!   `distributionService` helps only while the Welcome's
//!   `EncryptedGroupSecrets` (about 120 octets per joining client) are
//!   what tips it over the limit; past that, Commits that add members are
//!   refused (decision mimid-1wgh.81). A joiner of a `distributionService`
//!   Welcome gets the tree of the epoch current when it asks, which is
//!   useless to it once the room has moved on.
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

use super::policy::{
    self, AppDataOp, Commit, Committer, Origin, Proposal, ProposalKind, ProposalSender, RoomState,
};
use super::room::{self, GROUP_INFO_MESSAGE_HEADER};
use super::state::{identity_domain, member_domains, room_state};
use super::{Hub, HubError, PendingAppData, Room, group_info, restore_room};
use crate::config::Domain;
use crate::store::{EpochSnapshot, EventKind, NewEvent, OutboxEntry};
use mimi_protocol::components;

/// RFC 9420 §6: the MLSMessage header of a Welcome, `version` mls10
/// (0x0001) and `wire_format` mls_welcome (0x0003).
const WELCOME_MESSAGE_HEADER: [u8; 4] = [0x00, 0x01, 0x00, 0x03];

/// mls-extensions-11 §7.2: the suggested `app_ephemeral` ProposalType.
/// PROVISIONAL: "(suggested)", not IANA-assigned (bead mimid-1wgh.4.76.9).
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

    let fixed_elsewhere = fixed_rooms_elsewhere(&rooms, room_id);
    let parent = parent_participants(&rooms, room_id);
    // room-policy-04 §5's cascade: only a Commit can change who is in
    // this room, and the set is only needed if a room hosted here depends
    // on it as its parent (decision mimid-1wgh.111).
    let children = match kind {
        EventKind::Commit => parent_dependent_children(&rooms, room_id),
        _ => Vec::new(),
    };
    let listed_before = if children.is_empty() {
        BTreeSet::new()
    } else {
        listed_participants(&rooms, room_id)
    };
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
            &fixed_elsewhere,
            parent.as_ref(),
        ),
        HandshakeBundle::Proposal {
            proposal_or_commit,
            more_proposals,
        } => stage_proposals(hub, room, room_id, from, proposal_or_commit, more_proposals),
    };
    let accepted = match staged {
        Ok(Outcome::Accept(accepted)) => *accepted,
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
                name: "commit_accepted",
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
                name: "proposals_accepted",
                room_id,
                seq,
                epoch = accepted.epoch,
                proposals = count,
                destinations = outbox.len(),
                "proposals accepted"
            );
        }
    }
    // room-policy-04 §5: a user who left the parent leaves its
    // parent-dependent rooms too. The hub proposes it; it cannot commit
    // (decision mimid-1wgh.111).
    let departed: Vec<Vec<u8>> = listed_before
        .difference(&listed_participants(&rooms, room_id))
        .cloned()
        .collect();
    let cascade = if departed.is_empty() {
        Vec::new()
    } else {
        cascade_removals(&rooms, &children, &departed)
    };
    drop(rooms);
    hub.wake_fanout();
    // Boxed: this re-enters `update` for the child room, where the
    // proposal path takes no cascade of its own.
    Box::pin(propose_cascade(hub, room_id, cascade)).await;
    success(accepted.accepted_at)
}

/// The users a hosted room's participant list names, empty if the room is
/// not hosted here or its list does not decode.
fn listed_participants(
    rooms: &std::collections::BTreeMap<String, Room>,
    room_id: &str,
) -> BTreeSet<Vec<u8>> {
    rooms
        .get(room_id)
        .and_then(|room| room_state(&room.observer, room_id).ok())
        .map(|state| participant_set(&state.participants))
        .unwrap_or_default()
}

/// The rooms this hub hosts that name `room_id` as their parent
/// (room-policy-04 §5). A parent-dependent room elsewhere is not one this
/// hub can act on, and §5 forbids it anyway: such a room "is always hosted
/// on the same Hub as the parent room".
fn parent_dependent_children(
    rooms: &std::collections::BTreeMap<String, Room>,
    room_id: &str,
) -> Vec<String> {
    rooms
        .iter()
        .filter(|(id, _)| id.as_str() != room_id)
        .filter(|(id, room)| {
            room_state(&room.observer, id).is_ok_and(|state| {
                bool::from(state.base.parent_dependant)
                    && state
                        .base
                        .parent_room
                        .first()
                        .is_some_and(|parent| parent.as_str() == room_id)
            })
        })
        .map(|(id, _)| id.clone())
        .collect()
}

/// For each of `children`, the users among `departed` that it still
/// lists. A child that lists none of them needs nothing.
fn cascade_removals(
    rooms: &std::collections::BTreeMap<String, Room>,
    children: &[String],
    departed: &[Vec<u8>],
) -> Vec<(String, Vec<Vec<u8>>)> {
    children
        .iter()
        .filter_map(|child| {
            let listed = listed_participants(rooms, child);
            let users: Vec<Vec<u8>> = departed
                .iter()
                .filter(|user| listed.contains(*user))
                .cloned()
                .collect();
            (!users.is_empty()).then(|| (child.clone(), users))
        })
        .collect()
}

/// Proposes each cascaded removal, through the same path as an operator's
/// (`operator.rs`), and so with the same caveat: the hub is not a member
/// and cannot commit, so a departed user stays in the child room, and can
/// still derive its exported secrets, until a member of it next commits
/// (decision mimid-1wgh.111; bead mimid-1wgh.37.108.1).
///
/// A failure is logged and dropped. The parent's Commit was accepted
/// already and is not undone by it: §5's cascade is a consequence of that
/// Commit, not a condition on it.
async fn propose_cascade(hub: &Hub, parent_id: &str, cascade: Vec<(String, Vec<Vec<u8>>)>) {
    for (child, users) in cascade {
        for user in users {
            // The proposals are logged by `propose_removal`, with the
            // cause; this logs only a failure, which it does not.
            if let Err(error) = hub
                .propose_removal(
                    &child,
                    &user,
                    false,
                    super::operator::Cause::ParentDependent,
                )
                .await
            {
                tracing::warn!(
                    room_id = %child,
                    parent_id,
                    error = &error as &dyn std::error::Error,
                    "the cascaded removal from a parent-dependent room failed"
                );
            }
        }
    }
}

/// A parent-dependent room's parent, as this hub holds it.
struct ParentRoom {
    /// The parent's participants, for the subset rule of room-policy-04
    /// §5.
    participants: BTreeSet<Vec<u8>>,
}

/// The parent of `room_id`, when `room_id` names a parent-dependent room
/// whose `parent_room` this hub hosts.
///
/// `None` when the room is not parent-dependent, when it names no
/// parent, or when the parent is not a room of this hub: §5 requires a
/// parent-dependent room to be "always hosted on the same Hub as the
/// parent room", so a parent elsewhere is not a parent this hub can
/// check against.
fn parent_participants(
    rooms: &std::collections::BTreeMap<String, Room>,
    room_id: &str,
) -> Option<ParentRoom> {
    let state = rooms
        .get(room_id)
        .and_then(|room| room_state(&room.observer, room_id).ok())?;
    if !bool::from(state.base.parent_dependant) {
        return None;
    }
    let parent_id = state.base.parent_room.first()?.as_str().to_owned();
    let parent = rooms
        .get(&parent_id)
        .and_then(|room| room_state(&room.observer, &parent_id).ok())?;
    Some(ParentRoom {
        participants: participant_set(&parent.participants),
    })
}

/// The participant sets of the fixed-membership rooms this hub hosts
/// other than `room_id`, if `room_id` is a fixed-membership room whose
/// participants are not given yet (its participant list holds one
/// entry); empty otherwise, since only such a room can take new
/// participants (room-policy-04 §5; decision mimid-1wgh.89).
///
/// Parent-dependent rooms are left out of both sides of the comparison:
/// §5's "only a single fixed-membership room can exist for any unique
/// set of participants" does not count them (decision mimid-1wgh.110,
/// proposed as ietf-wg-mimi/mimi-room-policy#59). Counting them would
/// forbid the example §5 itself gives two paragraphs later, a call room
/// among the clients of a Group DM, since such a room has the DM's own
/// participant set; and it would let a chat have one call, ever.
fn fixed_rooms_elsewhere(
    rooms: &std::collections::BTreeMap<String, Room>,
    room_id: &str,
) -> Vec<BTreeSet<Vec<u8>>> {
    let fixed = |id: &str, room: &Room| {
        room_state(&room.observer, id).ok().filter(|state| {
            !state.open
                && bool::from(state.base.fixed_membership)
                && !bool::from(state.base.parent_dependant)
        })
    };
    let being_created = rooms
        .get(room_id)
        .and_then(|room| fixed(room_id, room))
        .is_some_and(|state| state.participants.participants.len() == 1);
    if !being_created {
        return Vec::new();
    }
    rooms
        .iter()
        .filter(|(id, _)| id.as_str() != room_id)
        .filter_map(|(id, room)| fixed(id, room))
        .map(|state| participant_set(&state.participants))
        .collect()
}

/// The users of a participant list, as a set.
fn participant_set(list: &mimi_protocol::ParticipantListData) -> BTreeSet<Vec<u8>> {
    list.participants
        .iter()
        .map(|entry| entry.user.clone())
        .collect()
}

/// Rebuilds a room after an internal failure, logging a rebuild failure so
/// that the original error is the one returned.
async fn restore_after_error(
    hub: &Hub,
    rooms: &mut std::collections::BTreeMap<String, Room>,
    room_id: &str,
) {
    if let Err(error) = restore_room(hub, rooms, room_id).await {
        tracing::error!(
            name: "room_rebuild_failed",
            room_id,
            error = &error as &dyn std::error::Error,
            "room could not be rebuilt; it is unavailable until restart"
        );
    }
}

/// The result of a staging step.
enum Outcome {
    /// Answer with `response`; first rebuild the room if `restore` is set,
    /// because the Observer holds changes that must not stay.
    Respond { response: Vec<u8>, restore: bool },
    /// Write and answer `success`.
    Accept(Box<Accepted>),
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

/// The longest errorDescription the hub sends, in octets; a longer one is
/// cut at a character boundary. INVENTED, NOT FROM SPEC.
const MAX_ERROR_DESCRIPTION_LEN: usize = 1024;

/// Encodes a response with an empty errorDescription.
fn respond(result: UpdateResult) -> Result<Vec<u8>, HubError> {
    respond_with(result, String::new())
}

/// Encodes a response with `description` as its errorDescription: which
/// check failed (clean-room finding C5). A description that is not a
/// valid UTF8String is sent empty.
fn respond_with(result: UpdateResult, mut description: String) -> Result<Vec<u8>, HubError> {
    if description.len() > MAX_ERROR_DESCRIPTION_LEN {
        let mut end = MAX_ERROR_DESCRIPTION_LEN;
        while !description.is_char_boundary(end) {
            end -= 1;
        }
        description.truncate(end);
    }
    UpdateRoomResponse {
        error_description: Utf8String::new(description).unwrap_or_default(),
        result,
    }
    .tls_serialize_detached()
    .map_err(HubError::Encode)
}

/// Encodes `success`.
fn success(accepted_timestamp: u64) -> Result<Vec<u8>, HubError> {
    respond(UpdateResult::Success { accepted_timestamp })
}

/// Logs why a request is refused and answers `notAllowed` (decision
/// mimid-1wgh.6.55) with `reason` as its errorDescription (clean-room
/// finding C5).
fn refuse(room_id: &str, reason: &'static str, restore: bool) -> Result<Outcome, HubError> {
    refuse_because(room_id, reason, reason.to_owned(), restore)
}

/// As [`refuse`], with `detail`, the error that made the check fail,
/// after `reason` in the errorDescription; the metric and the log event
/// keep `reason` alone.
fn refuse_with(
    room_id: &str,
    reason: &'static str,
    detail: &(dyn std::error::Error + 'static),
    restore: bool,
) -> Result<Outcome, HubError> {
    let description = format!("{reason}: {}", crate::jmap::error_chain(detail));
    refuse_because(room_id, reason, description, restore)
}

fn refuse_because(
    room_id: &str,
    reason: &'static str,
    description: String,
    restore: bool,
) -> Result<Outcome, HubError> {
    crate::telemetry::metrics()
        .update_refusals
        .add(1, &[opentelemetry::KeyValue::new("reason", reason)]);
    tracing::debug!(room_id, reason, "update refused");
    Ok(Outcome::Respond {
        response: respond_with(UpdateResult::NotAllowed, description)?,
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
            respond(UpdateResult::WrongEpoch { current_epoch }).map(|response| Outcome::Respond {
                response,
                restore: false,
            }),
        );
    }
    None
}

/// Runs the Commit steps 3 to 10 of the module documentation.
#[expect(
    clippy::too_many_arguments,
    reason = "the parts of one Room/update, each used once"
)]
fn stage_commit(
    hub: &Hub,
    room: &mut Room,
    room_id: &str,
    from: &Domain,
    commit: &MLSMessage,
    welcome: Option<&Welcome>,
    group_info_option: &GroupInfoOption,
    fixed_elsewhere: &[BTreeSet<Vec<u8>>],
    parent: Option<&ParentRoom>,
) -> Result<Outcome, HubError> {
    if let Some(refused) = check_epoch(room, room_id, commit) {
        return refused;
    }
    let epoch = room.observer.epoch();
    // A malformed policy component is refused at creation, so this is
    // defence in depth (decision mimid-1wgh.6.51); a missing one makes an
    // open room (decision mimid-1wgh.52).
    let state = match room_state(&room.observer, room_id) {
        Ok(state) => state,
        Err(error) => {
            tracing::warn!(
                name: "commit_policy_unusable",
                room_id,
                error = &error as &dyn std::error::Error,
                "room policy state unusable; commit refused"
            );
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
            tracing::debug!(
                room_id,
                error = &error as &dyn std::error::Error,
                "commit failed MLS validation"
            );
            // draft-atwood-jmap-chat-mimi-00 §Room/update: not valid MLS,
            // rather than refused by policy (clean-room finding C5).
            return refuse_with(room_id, "the commit is not valid MLS", &error, false);
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
    // Bead mimid-1wgh.52.2: size limits on what the Commit writes.
    for proposal in &summary.proposals {
        if let ProposalKind::AppDataUpdate {
            component_id,
            op: AppDataOp::Update(bytes),
        } = &proposal.kind
            && let Err(too_long) = hub.limits.component(*component_id, bytes, false)
        {
            tracing::debug!(
                room_id,
                error = &too_long as &dyn std::error::Error,
                "commit refused: a field is over the size limit"
            );
            return refused(room, "a field is over this hub's size limit");
        }
    }
    let outcome = match policy::authorize_commit(&state, &summary) {
        Ok(outcome) => outcome,
        Err(denied) => {
            tracing::debug!(
                room_id,
                denied = &denied as &dyn std::error::Error,
                "commit refused by room policy"
            );
            room.observer.clear_pending_commit();
            return refuse_with(
                room_id,
                "the commit is refused by room policy",
                &denied,
                false,
            );
        }
    };
    // room-policy-04 §5: "Only a single fixed-membership room can exist
    // for any unique set of participants"; decision mimid-1wgh.89.
    if let Some(list) = outcome
        .new_data
        .get(&mimi_protocol::component_id::PARTICIPANT_LIST)
        && let Ok(list) = components::decode::<mimi_protocol::ParticipantListData>(
            mimi_protocol::component_id::PARTICIPANT_LIST,
            list,
        )
        && state.participants.participants.len() == 1
        && fixed_elsewhere.contains(&participant_set(&list))
    {
        return refused(
            room,
            "a fixed-membership room with these participants exists already",
        );
    }
    // room-policy-04 §5: a parent-dependent room's participants are a
    // subset of its parent's, and a user removed from the parent is
    // removed from the child. The subset is not a STRICT subset, which
    // is a deliberate departure from -04 as written: decision
    // mimid-1wgh.110, and ietf-wg-mimi/mimi-room-policy#59.
    if bool::from(state.base.parent_dependant)
        && let Some(list) = outcome
            .new_data
            .get(&mimi_protocol::component_id::PARTICIPANT_LIST)
        && let Ok(list) = components::decode::<mimi_protocol::ParticipantListData>(
            mimi_protocol::component_id::PARTICIPANT_LIST,
            list,
        )
    {
        let Some(parent) = parent else {
            return refused(room, "a parent-dependent room's parent is not hosted here");
        };
        if let Err(denied) = crate::hub::policy::parent_dependent_participants(
            &participant_set(&list),
            &parent.participants,
        ) {
            tracing::debug!(
                room_id,
                denied = &denied as &dyn std::error::Error,
                "commit refused: parent-dependent participants"
            );
            return refused(
                room,
                "a parent-dependent room's participants are not a subset of its parent's",
            );
        }
    }
    // Decision mimid-1wgh.4.76.2 (revising mimid-1wgh.6.74): under
    // mls-extensions-11 §5.1 an AppDataUpdate can change safe_aad, so a
    // room that is franked, or must be, stays franked: the epoch the Commit
    // leads to still requires frank_aad.
    let franked_now = match room::is_franked(&room.observer) {
        Ok(franked) => franked,
        Err(error) => {
            room.observer.clear_pending_commit();
            return Err(error);
        }
    };
    if franked_now || hub.requirements.franking {
        let franked_after = match room.observer.pending_required_safe_aad() {
            Ok(required) => {
                required.is_some_and(|ids| ids.contains(&mimi_protocol::component_id::FRANK_AAD))
            }
            Err(error) => {
                room.observer.clear_pending_commit();
                return Err(HubError::Mls(error));
            }
        };
        if !franked_after {
            return refused(room, "the commit stops requiring frank_aad");
        }
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
            tracing::debug!(
                room_id,
                error = &error as &dyn std::error::Error,
                "GroupInfo does not match the merged commit"
            );
            return refuse_with(room_id, "the GroupInfo is not valid", &error, true);
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
        // sent, in the Welcome while it fits (decision mimid-1wgh.81).
        let full = welcome_fanout(
            accepted_at,
            message.clone(),
            RatchetTreeOption::full(&ratchet_tree).map_err(HubError::Encode)?,
        )?;
        let welcome_body = if full.len() <= hub.body_limit {
            full
        } else {
            let by_reference = welcome_fanout(
                accepted_at,
                message,
                RatchetTreeOption::distribution_service(),
            )?;
            let group_info_len =
                group_info::response_len(hub, room_id, &group_info, &ratchet_tree)?;
            if by_reference.len() > hub.body_limit || group_info_len > hub.body_limit {
                tracing::info!(
                    name: "welcome_too_large",
                    room_id,
                    welcome_len = full.len(),
                    welcome_without_tree_len = by_reference.len(),
                    group_info_len,
                    limit = hub.body_limit,
                    "the ratchet tree cannot reach the new members; commit refused"
                );
                return refuse(
                    room_id,
                    "the ratchet tree cannot reach the new members",
                    true,
                );
            }
            tracing::info!(
                name: "welcome_tree_by_reference",
                room_id,
                epoch = new_epoch,
                welcome_len = full.len(),
                group_info_len,
                limit = hub.body_limit,
                "Welcome sent with RatchetTreeOption distributionService"
            );
            by_reference
        };
        outbox.extend(
            welcome_domains
                .into_iter()
                .map(|domain| (domain, welcome_body.clone())),
        );
    }
    Ok(Outcome::Accept(Box::new(Accepted {
        epoch,
        accepted_at,
        message: commit.clone(),
        outbox,
        write: Write::Commit {
            new_epoch,
            group_info,
            ratchet_tree,
        },
    })))
}

/// The encoded Welcome FanoutMessage of `message` with `ratchet_tree_option`
/// (protocol-07 §5.5).
fn welcome_fanout(
    timestamp: u64,
    message: MLSMessage,
    ratchet_tree_option: RatchetTreeOption,
) -> Result<Vec<u8>, HubError> {
    FanoutMessage {
        timestamp,
        event: FanoutEvent::Welcome {
            message,
            ratchet_tree_option,
        },
    }
    .tls_serialize_detached()
    .map_err(HubError::Encode)
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
    // A malformed policy component is refused at creation, so this is
    // defence in depth (decision mimid-1wgh.6.51); a missing one makes an
    // open room (decision mimid-1wgh.52).
    let state = match room_state(&room.observer, room_id) {
        Ok(state) => state,
        Err(error) => {
            tracing::warn!(
                name: "proposal_policy_unusable",
                room_id,
                error = &error as &dyn std::error::Error,
                "room policy state unusable; proposal refused"
            );
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
                tracing::debug!(
                    room_id,
                    index,
                    error = &error as &dyn std::error::Error,
                    "proposal failed MLS validation"
                );
                return refuse_with(room_id, "a proposal is not valid MLS", &error, stored);
            }
        };
        let (sender, kind) = match (proposal_sender(&detail), proposal_kind(&detail.proposal)) {
            (Ok(sender), Ok(kind)) => (sender, kind),
            (Err(reason), _) | (_, Err(reason)) => return refuse(room_id, reason, true),
        };
        // Decisions mimid-1wgh.6.9, mimid-1wgh.6.56: the sender of
        // proposalOrCommit only; checked before any write.
        if index == 0 && sender_domain(hub, &state, &sender) != Some(from.clone()) {
            return refuse(room_id, "From domain is not the proposer's domain", true);
        }
        if let Err(denied) = policy::authorize_proposal(&state, &kind, &sender) {
            tracing::debug!(
                room_id,
                index,
                denied = &denied as &dyn std::error::Error,
                "proposal refused by room policy"
            );
            return refuse_with(
                room_id,
                "a proposal is refused by room policy",
                &denied,
                true,
            );
        }
        // mls-extensions-11 §4.7; decision mimid-1wgh.4.65; bead
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
    // protocol-07 §5.5: the proposals are forwarded as received.
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
    Ok(Outcome::Accept(Box::new(Accepted {
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
    })))
}

/// The provider domain of a proposal's sender. An external sender is this
/// hub: a hosted room's `external_senders` lists only the hub (decision
/// mimid-1wgh.6.46 as amended 2026-11-15).
fn sender_domain(hub: &Hub, state: &RoomState, sender: &ProposalSender) -> Option<Domain> {
    if matches!(sender, ProposalSender::External { .. }) {
        return Some(hub.domain().clone());
    }
    match sender {
        ProposalSender::Member { leaf_index } => {
            state.members.get(leaf_index).and_then(|identity| {
                crate::hub::note_non_user_uri("proposal sender", identity);
                identity_domain(identity)
            })
        }
        ProposalSender::NewMember { user } => {
            crate::hub::note_non_user_uri("new-member proposal sender", user);
            identity_domain(user)
        }
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
        // Decisions mimid-1wgh.4.81.26 (revoked devices) and
        // mimid-1wgh.4.81.37 (members lacking AppDataUpdate in a Commit
        // that changes the record): both are Removes the rules require.
        did_webvh_required_removes: detail
            .did_webvh_required_removes
            .iter()
            .chain(&detail.did_webvh_removes_without_app_data_update)
            .copied()
            .collect(),
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
