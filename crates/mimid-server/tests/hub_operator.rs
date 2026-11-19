//! Operator remove and ban (bead mimid-1wgh.47.5; decision mimid-1wgh.6.46
//! as amended 2026-11-15): the hub proposes, as the room's external
//! sender, the Remove of a user's clients and the participant_list change;
//! a member commits them; the user is gone, or listed as banned.

#[allow(dead_code, reason = "each test binary uses part of the helpers")]
mod common;
#[allow(dead_code, reason = "each test binary uses part of the helpers")]
#[path = "common/update.rs"]
mod update;

use mimi_protocol::UpdateResult;
use mimi_protocol::components::apply_commit_op;
use mimid_server::hub::HubError;

use common::*;
use update::{commit_request, member_room, response};

/// The room's participant list, as (user, role).
async fn participants(hub: &mimid_server::hub::Hub) -> Vec<(Vec<u8>, u32)> {
    hub.room_summaries(Some(ROOM_ID)).await[0]
        .participants
        .clone()
        .unwrap()
}

/// The hub removes (or bans) bob; alice processes the hub's proposals and
/// commits them; the hub accepts the Commit. Returns the room's members and
/// participants after it.
async fn remove_bob(ban: bool) -> (Vec<(u32, Vec<u8>)>, Vec<(Vec<u8>, u32)>) {
    let dir = tempfile::tempdir().unwrap();
    let (store, hub) = open_hub(&dir.path().join("mimid.sqlite")).await;
    let mut room = member_room(&hub, ROOM_ID, b"operator-group").await;
    assert_eq!(hub.room_summaries(Some(ROOM_ID)).await[0].members.len(), 2);

    let answer = hub.remove_user(ROOM_ID, BOB, ban).await.unwrap();
    assert!(
        matches!(response(&answer).0, UpdateResult::Success { .. }),
        "the hub accepts its own proposals"
    );
    let proposals = store.pending_proposals(ROOM_ID, 1).await.unwrap();
    assert_eq!(proposals.len(), 2, "bob's one client, and the list change");

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
            ROOM_ID,
            &domain(),
            &commit_request(&bundle.commit, None, &bundle.group_info, &tree),
        )
        .await
        .unwrap();
    assert!(
        matches!(response(&answer).0, UpdateResult::Success { .. }),
        "alice's Commit of the hub's proposals is accepted"
    );
    let summary = hub.room_summaries(Some(ROOM_ID)).await.remove(0);
    let after = participants(&hub).await;
    close_hub(store, hub).await;
    (summary.members, after)
}

#[tokio::test]
async fn an_operator_removal_takes_effect_at_the_next_commit() {
    let (members, participants) = remove_bob(false).await;
    assert_eq!(
        members
            .iter()
            .map(|(_, id)| id.as_slice())
            .collect::<Vec<_>>(),
        [ALICE]
    );
    assert_eq!(
        participants
            .iter()
            .map(|(u, _)| u.as_slice())
            .collect::<Vec<_>>(),
        [ALICE]
    );
}

#[tokio::test]
async fn an_operator_ban_leaves_the_user_listed_as_banned() {
    let (members, participants) = remove_bob(true).await;
    assert_eq!(
        members
            .iter()
            .map(|(_, id)| id.as_slice())
            .collect::<Vec<_>>(),
        [ALICE]
    );
    assert!(
        participants.contains(&(BOB.to_vec(), 1)),
        "{participants:?}"
    );
}

#[tokio::test]
async fn only_listed_users_in_hosted_rooms_can_be_removed() {
    let dir = tempfile::tempdir().unwrap();
    let (store, hub) = open_hub(&dir.path().join("mimid.sqlite")).await;
    let _room = member_room(&hub, ROOM_ID, b"operator-refusals").await;
    assert!(matches!(
        hub.remove_user(ROOM_ID, b"mimi://b.example/u/nobody", false)
            .await,
        Err(HubError::NotListed)
    ));
    assert!(matches!(
        hub.remove_user("mimi://a.example/r/elsewhere", BOB, false)
            .await,
        Err(HubError::NoSuchRoom)
    ));
    close_hub(store, hub).await;
}
