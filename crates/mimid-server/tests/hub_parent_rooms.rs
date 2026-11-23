//! room-policy-04 §5's parent-dependent rooms at the hub: the rules it
//! enforces when it is asked to host one, and the cascade when a user
//! leaves the parent (decisions mimid-1wgh.110, mimid-1wgh.111; bead
//! mimid-1wgh.108).
//!
//! Oracle: §5. "The list of participants of the room MUST be a strict
//! subset of the participants of the parent room. If a user leaves or is
//! removed from the parent room, that user is automatically removed from
//! any parent-dependent rooms of that parent. A parent-dependent room is
//! always hosted on the same Hub as the parent room."
//!
//! mimid reads "strict subset" as "subset" (decision mimid-1wgh.110), and
//! does the cascade as a proposal, because the hub is not an MLS member
//! and cannot commit (decision mimid-1wgh.111). Both departures are
//! visible in these tests.

#[allow(dead_code, reason = "each test binary uses part of the helpers")]
mod common;
#[allow(dead_code, reason = "each test binary uses part of the helpers")]
#[path = "common/update.rs"]
mod update;

use mimi_protocol::UpdateResult;
use mimi_protocol::components::apply_commit_op;
use mimid_server::hub::{Hub, HubError};

use common::*;
use update::{
    CAROL, MemberRoom, commit_request, member_group, member_room_with_base, members_list, response,
};

/// The call room, a child of [`ROOM_ID`] on the same hub.
const CHILD_ID: &str = "mimi://a.example/r/call";
/// A room this hub does not host.
const ELSEWHERE: &str = "mimi://a.example/r/elsewhere";

/// The participant list of a hosted room, as users.
async fn listed(hub: &Hub, room_id: &str) -> Vec<Vec<u8>> {
    hub.room_summaries(Some(room_id)).await[0]
        .participants
        .clone()
        .unwrap()
        .into_iter()
        .map(|(user, _)| user)
        .collect()
}

/// Has `room`'s alice commit every proposal pending for `room_id` in
/// `epoch`, and asserts the hub accepts the Commit.
async fn commit_pending(
    store: &mimid_server::store::Store,
    hub: &Hub,
    room: &mut MemberRoom,
    room_id: &str,
    epoch: u64,
) -> usize {
    let proposals = store.pending_proposals(room_id, epoch).await.unwrap();
    for proposal in &proposals {
        room.alice_group
            .process(&room.alice, proposal, apply_commit_op)
            .unwrap();
    }
    let bundle = room
        .alice_group
        .commit(&room.alice, &[], &[], &[], apply_commit_op)
        .unwrap();
    room.alice_group.merge_pending_commit(&room.alice).unwrap();
    let tree = room.alice_group.ratchet_tree().unwrap();
    let answer = hub
        .update(
            room_id,
            &domain(),
            &commit_request(&bundle.commit, None, &bundle.group_info, &tree),
        )
        .await
        .unwrap();
    assert!(
        matches!(response(&answer).0, UpdateResult::Success { .. }),
        "the Commit of the pending proposals is accepted"
    );
    proposals.len()
}

/// A user taken out of the parent is proposed for removal from the child,
/// and is still in it until a member of the child commits: §5's cascade
/// as a non-member hub can do it (decision mimid-1wgh.111).
#[tokio::test]
async fn a_departure_from_the_parent_cascades_into_the_child() {
    let dir = tempfile::tempdir().unwrap();
    let (store, hub) = open_hub(&dir.path().join("mimid.sqlite")).await;
    let mut parent =
        member_room_with_base(&hub, ROOM_ID, b"parent-group", base_room_policy()).await;
    let mut child =
        member_room_with_base(&hub, CHILD_ID, b"child-group", child_room_policy(ROOM_ID)).await;
    assert_eq!(listed(&hub, CHILD_ID).await, [ALICE, BOB]);

    // bob leaves the parent: the operator's removal, committed by alice.
    hub.remove_user(ROOM_ID, BOB, false).await.unwrap();
    commit_pending(&store, &hub, &mut parent, ROOM_ID, 1).await;
    assert_eq!(listed(&hub, ROOM_ID).await, [ALICE], "bob left the parent");

    // The cascade is a proposal in the child, not a removal from it.
    let cascaded = store.pending_proposals(CHILD_ID, 1).await.unwrap();
    assert_eq!(
        cascaded.len(),
        2,
        "bob's one client, and the participant list change"
    );
    assert_eq!(
        listed(&hub, CHILD_ID).await,
        [ALICE, BOB],
        "bob is still in the call room until a member of it commits"
    );

    // And when a member of the child commits, he is gone from it.
    commit_pending(&store, &hub, &mut child, CHILD_ID, 1).await;
    assert_eq!(listed(&hub, CHILD_ID).await, [ALICE]);
    close_hub(store, hub).await;
}

/// A Commit in the parent that takes nobody out proposes nothing in the
/// child: the cascade follows a departure, not every Commit.
#[tokio::test]
async fn a_commit_that_removes_nobody_cascades_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let (store, hub) = open_hub(&dir.path().join("mimid.sqlite")).await;
    let mut parent =
        member_room_with_base(&hub, ROOM_ID, b"parent-group", base_room_policy()).await;
    member_room_with_base(&hub, CHILD_ID, b"child-group", child_room_policy(ROOM_ID)).await;

    // An empty Commit in the parent: the epoch moves, the list does not.
    let bundle = parent
        .alice_group
        .commit(&parent.alice, &[], &[], &[], apply_commit_op)
        .unwrap();
    parent
        .alice_group
        .merge_pending_commit(&parent.alice)
        .unwrap();
    let tree = parent.alice_group.ratchet_tree().unwrap();
    let answer = hub
        .update(
            ROOM_ID,
            &domain(),
            &commit_request(&bundle.commit, None, &bundle.group_info, &tree),
        )
        .await
        .unwrap();
    assert!(matches!(response(&answer).0, UpdateResult::Success { .. }));

    assert!(
        store
            .pending_proposals(CHILD_ID, 1)
            .await
            .unwrap()
            .is_empty(),
        "nothing left the parent, so nothing is proposed in the child"
    );
    assert_eq!(listed(&hub, CHILD_ID).await, [ALICE, BOB]);
    close_hub(store, hub).await;
}

/// §5: a parent-dependent room "is always hosted on the same Hub as the
/// parent room", so this hub refuses to host one whose parent it does not
/// have. Refusing at creation is the point: the room would otherwise be
/// hosted and then have every membership Commit refused.
#[tokio::test]
async fn a_parent_dependent_room_needs_its_parent_on_this_hub() {
    let dir = tempfile::tempdir().unwrap();
    let (store, hub) = open_hub(&dir.path().join("mimid.sqlite")).await;
    let (_room, group_info, tree) = member_group(
        &hub,
        b"orphan-group",
        &members_list(&[ALICE, BOB]),
        child_room_policy(ELSEWHERE),
    );
    let error = hub
        .create_room(CHILD_ID, ALICE, &group_info, &tree)
        .await
        .unwrap_err();
    assert!(
        matches!(&error, HubError::ParentNotHosted { parent_id } if parent_id == ELSEWHERE),
        "{error:?}"
    );
    assert!(store.rooms().await.unwrap().is_empty(), "nothing stored");
    close_hub(store, hub).await;
}

/// §5's subset rule, at creation: a child that lists a user the parent
/// does not is refused.
#[tokio::test]
async fn a_parent_dependent_room_needs_its_participants_in_the_parent() {
    let dir = tempfile::tempdir().unwrap();
    let (store, hub) = open_hub(&dir.path().join("mimid.sqlite")).await;
    member_room_with_base(&hub, ROOM_ID, b"parent-group", base_room_policy()).await;
    let (_room, group_info, tree) = member_group(
        &hub,
        b"wider-group",
        &members_list(&[ALICE, BOB, CAROL]),
        child_room_policy(ROOM_ID),
    );
    let error = hub
        .create_room(CHILD_ID, ALICE, &group_info, &tree)
        .await
        .unwrap_err();
    assert!(
        matches!(error, HubError::NotInParent { outside: 1 }),
        "carol is the one the parent does not list: {error:?}"
    );
    assert_eq!(store.rooms().await.unwrap().len(), 1, "only the parent");
    close_hub(store, hub).await;
}

/// A child whose participants are exactly its parent's is hosted: the
/// subset is not a strict one (decision mimid-1wgh.110), and §5's own
/// example -- a call among everyone in a Group DM -- needs it.
#[tokio::test]
async fn a_child_may_have_the_whole_parent() {
    let dir = tempfile::tempdir().unwrap();
    let (store, hub) = open_hub(&dir.path().join("mimid.sqlite")).await;
    member_room_with_base(&hub, ROOM_ID, b"parent-group", base_room_policy()).await;
    member_room_with_base(&hub, CHILD_ID, b"child-group", child_room_policy(ROOM_ID)).await;
    assert_eq!(listed(&hub, CHILD_ID).await, [ALICE, BOB]);
    close_hub(store, hub).await;
}
