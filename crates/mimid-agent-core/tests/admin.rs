//! Room moderation from mimid-agent (bead mimid-90cd; decision
//! mimid-1wgh.62) through a real mimid server: alice hosts a room and is
//! its admin (decision mimid-1wgh.56); bob and carol are members.
//!
//! Oracles:
//!
//! - The hub's room policy (room-policy-04 §8.1.2, §8.1.3): what it
//!   accepts reaches every member; what it refuses (a member kicking,
//!   removing, banning or changing a role) changes nothing, and the hub
//!   still holds the participant list it held before.
//! - The participant list and roles the hub holds after each Commit
//!   (`Hub::room_summaries`), and the leaves each member sees.
//! - MLS agreement among the remaining members (RFC 9420 §8.7), and the
//!   target's own `Event::Left`.
//! - A banned user cannot come back: an invite is refused while banned,
//!   and its new device's GroupInfo request is refused by the hub.

#![forbid(unsafe_code)]

mod common;

use common::{
    ALICE, BOB, CAROL, Server, assert_agreement, catch_up, device, leaves, poll_until, sends,
    server,
};
use mimid_agent_core::{Agent, AgentError, Event, HostOptions};

/// `agent` joins `room` from the invite it got.
async fn accept(agent: &mut Agent, room: &str) {
    let number = poll_until(agent, |e| match e {
        Event::InviteArrived { number } => Some(*number),
        _ => None,
    })
    .await;
    assert_eq!(agent.join(number).unwrap(), room);
}

/// The participant list the hub holds for `room`, as (user, role).
async fn hub_list(server: &Server, room: &str) -> Vec<(String, u32)> {
    server
        .hub
        .room_summaries(Some(room))
        .await
        .remove(0)
        .participants
        .unwrap()
        .into_iter()
        .map(|(user, role)| (String::from_utf8(user).unwrap(), role))
        .collect()
}

fn list(entries: &[(&str, u32)]) -> Vec<(String, u32)> {
    entries.iter().map(|(u, r)| ((*u).to_owned(), *r)).collect()
}

/// `agent` reads Commits until it is out of `room`.
async fn left(agent: &mut Agent, room: &str) {
    poll_until(agent, |e| match e {
        Event::Left { room: r } if r == room => Some(()),
        _ => None,
    })
    .await;
}

fn refused(result: Result<(), AgentError>) {
    assert!(
        matches!(&result, Err(AgentError::Refused { .. })),
        "{result:?}"
    );
}

/// alice's room with bob and carol in it.
async fn room_of_three(server: &Server, dir: &std::path::Path) -> (String, Agent, Agent, Agent) {
    let mut alice = device(server, ALICE, dir, "alice").await;
    let mut bob = device(server, BOB, dir, "bob").await;
    let mut carol = device(server, CAROL, dir, "carol").await;
    for agent in [&mut alice, &mut bob, &mut carol] {
        agent.publish_key_packages(2).await.unwrap();
    }
    let room = alice
        .host_room(&HostOptions::named("moderated"))
        .await
        .unwrap();
    alice.invite(&room, BOB).await.unwrap();
    accept(&mut bob, &room).await;
    alice.invite(&room, CAROL).await.unwrap();
    accept(&mut carol, &room).await;
    catch_up(&mut bob, &alice, &room).await;
    assert_eq!(
        hub_list(server, &room).await,
        list(&[(ALICE, 3), (BOB, 2), (CAROL, 2)])
    );
    // Each records the room as accepted (decision mimid-1wgh.63), so a
    // new device is held back by the group and the hub, not by that.
    for agent in [&mut alice, &mut bob, &mut carol] {
        assert_eq!(agent.join_own_rooms().await.unwrap(), Default::default());
    }
    (room, alice, bob, carol)
}

#[tokio::test]
async fn a_member_cannot_moderate() {
    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path(), &[ALICE, BOB, CAROL]).await;
    let (room, alice, mut bob, carol) = room_of_three(&server, dir.path()).await;
    let epoch = alice.epoch(&room).unwrap();
    refused(bob.kick(&room, CAROL).await);
    refused(bob.remove(&room, CAROL).await);
    refused(bob.ban(&room, CAROL).await);
    refused(bob.change_role(&room, CAROL, 3).await);
    // Nor promote himself: a role change acts on another user.
    assert!(matches!(
        bob.change_role(&room, BOB, 3).await,
        Err(AgentError::Invalid(_))
    ));
    assert_eq!(bob.epoch(&room).unwrap(), epoch);
    assert_eq!(
        hub_list(&server, &room).await,
        list(&[(ALICE, 3), (BOB, 2), (CAROL, 2)])
    );
    assert_agreement(&room, &alice, &bob);
    assert_agreement(&room, &alice, &carol);
}

#[tokio::test]
async fn an_admin_kicks_and_removes() {
    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path(), &[ALICE, BOB, CAROL]).await;
    let (room, mut alice, mut bob, mut carol) = room_of_three(&server, dir.path()).await;

    // A kick removes carol's client and keeps her in the list.
    alice.kick(&room, CAROL).await.unwrap();
    left(&mut carol, &room).await;
    catch_up(&mut bob, &alice, &room).await;
    assert_eq!(
        hub_list(&server, &room).await,
        list(&[(ALICE, 3), (BOB, 2), (CAROL, 2)])
    );
    assert_eq!(
        leaves(&bob, &room),
        [(ALICE.to_owned(), None), (BOB.to_owned(), None)]
    );
    // A kicked user's new device does not come back by external Commit:
    // the group holds no client of hers (decision mimid-1wgh.61 item 3).
    let mut carol2 = device(&server, CAROL, dir.path(), "carol2").await;
    let own = carol2.join_own_rooms().await.unwrap();
    assert!(own.joined.is_empty(), "{own:?}");
    assert_eq!(own.skipped.len(), 1, "{own:?}");

    // A removal takes bob out of the list and the group.
    alice.remove(&room, BOB).await.unwrap();
    left(&mut bob, &room).await;
    assert_eq!(
        hub_list(&server, &room).await,
        list(&[(ALICE, 3), (CAROL, 2)])
    );
    assert_eq!(leaves(&alice, &room), [(ALICE.to_owned(), None)]);

    // A removed user can be invited again.
    alice.invite(&room, BOB).await.unwrap();
    accept(&mut bob, &room).await;
    assert_agreement(&room, &alice, &bob);
    sends(&mut alice, &room, "welcome back", ALICE, &mut [&mut bob]).await;
}

#[tokio::test]
async fn an_admin_bans_unbans_and_changes_roles() {
    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path(), &[ALICE, BOB, CAROL]).await;
    let (room, mut alice, mut bob, mut carol) = room_of_three(&server, dir.path()).await;

    alice.ban(&room, CAROL).await.unwrap();
    left(&mut carol, &room).await;
    catch_up(&mut bob, &alice, &room).await;
    assert_eq!(
        hub_list(&server, &room).await,
        list(&[(ALICE, 3), (BOB, 2), (CAROL, 1)])
    );
    assert_eq!(
        bob.participant_roles(&room).unwrap(),
        list(&[(ALICE, 3), (BOB, 2), (CAROL, 1)])
    );
    // Banned carol cannot be added again, and her new device is refused
    // the GroupInfo by the hub.
    assert!(matches!(
        alice.invite(&room, CAROL).await,
        Err(AgentError::Invalid(_))
    ));
    let mut carol2 = device(&server, CAROL, dir.path(), "carol2").await;
    let own = carol2.join_own_rooms().await.unwrap();
    assert!(own.joined.is_empty(), "{own:?}");
    let [(_, why)] = own.skipped.as_slice() else {
        panic!("{own:?}");
    };
    assert!(why.contains("NotAuthorized"), "{why}");

    // alice makes bob an admin; bob, now holding canUnban, unbans carol.
    alice.change_role(&room, BOB, 3).await.unwrap();
    catch_up(&mut bob, &alice, &room).await;
    bob.unban(&room, CAROL).await.unwrap();
    catch_up(&mut alice, &bob, &room).await;
    assert_eq!(
        hub_list(&server, &room).await,
        list(&[(ALICE, 3), (BOB, 3), (CAROL, 2)])
    );
    // Unbanned, carol is a participant without clients; removed and
    // invited again, she is back.
    bob.remove(&room, CAROL).await.unwrap();
    bob.invite(&room, CAROL).await.unwrap();
    catch_up(&mut alice, &bob, &room).await;
    accept(&mut carol, &room).await;
    assert_agreement(&room, &alice, &carol);
    sends(
        &mut carol,
        &room,
        "back",
        CAROL,
        &mut [&mut alice, &mut bob],
    )
    .await;
}
