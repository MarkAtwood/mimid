//! A user's new device joins the rooms the user is already in (bead
//! mimid-d464; decision mimid-1wgh.61): through a real mimid server, the
//! new device reads the account's Chats, fetches each room's GroupInfo
//! (protocol-07 §5.6) and joins by external Commit.
//!
//! Oracles:
//!
//! - MLS agreement: after the external Commit every member, the new
//!   device included, has the same epoch and epoch authenticator
//!   (RFC 9420 §8.7).
//! - The leaves each member sees: two of alice, one of bob; the
//!   participant list is unchanged (a device is not a participant).
//! - Plaintext equality: the new device's message reaches bob and alice's
//!   first device from alice under the message ID it computed, and bob's
//!   reaches both of alice's devices.
//! - The hub's room policy: in a room whose roles do not hold
//!   `canAddOwnClient` (room-policy-04 §8.1.1) the hub refuses the
//!   GroupInfo. A device does not join by external Commit a room it has
//!   a pending invite to.
//! - did_webvh: a device the user's controller adds to the log joins a
//!   did_webvh room, and bob sees its leaf under alice's SCID.
//! - Leaving (bead mimid-pv2k): with two devices in the room, a leave
//!   removes both; another user's member commits it and the hub accepts.
//! - Acceptance (bead mimid-f2rn; decision mimid-1wgh.63): a new device
//!   does not join a room another device left the invite to pending, and
//!   joins it once a device accepted it; it does not join a room its user
//!   left. The record is the Chat's `privateMetadata` on the real server,
//!   read back with a plain JMAP request.

#![forbid(unsafe_code)]

mod common;

use common::{
    ALICE, BOB, Server, assert_agreement, catch_up, device, device_with, leaves, poll_until,
    roles_without_add_own_client, sends, server,
};
use mimid_agent_core::mls_didwebvh::PublicKey;
use mimid_agent_core::mls_didwebvh::controller::{DidLog, Parameters, UpdateKey};
use mimid_agent_core::{Agent, DidWebvhConfig, Event, HostOptions, RoomStatus};

/// bob joins `room` from the invite alice sent him.
async fn accept(bob: &mut Agent, server: &Server, room: &str) {
    let number = poll_until(bob, server, |e| match e {
        Event::InviteArrived { number } => Some(*number),
        _ => None,
    })
    .await;
    assert_eq!(bob.join(number).unwrap(), room);
}

#[tokio::test]
async fn a_new_device_joins_its_users_room_and_talks() {
    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path(), &[ALICE, BOB]).await;
    let mut a1 = device(&server, ALICE, dir.path(), "a1").await;
    let mut bob = device(&server, BOB, dir.path(), "bob").await;
    a1.publish_key_packages(2).await.unwrap();
    bob.publish_key_packages(2).await.unwrap();

    let room = a1.host_room(&HostOptions::named("planning")).await.unwrap();
    a1.invite(&room, BOB).await.unwrap();
    accept(&mut bob, &server, &room).await;
    sends(
        &mut a1,
        &server,
        &room,
        "before the new device",
        ALICE,
        &mut [&mut bob],
    )
    .await;

    // bob invites alice to a second room and a1 leaves the invite pending:
    // a1 does not join it by external Commit either. This call also
    // records the room a1 made as accepted.
    let pending = bob.host_room(&HostOptions::named("pending")).await.unwrap();
    bob.invite(&pending, ALICE).await.unwrap();
    let invite = poll_until(&mut a1, &server, |e| match e {
        Event::InviteArrived { number } => Some(*number),
        _ => None,
    })
    .await;
    let own = a1.join_own_rooms().await.unwrap();
    assert!(own.joined.is_empty(), "{own:?}");
    assert!(own.failed.is_empty(), "{own:?}");
    let [(skipped, why)] = own.skipped.as_slice() else {
        panic!("{own:?}");
    };
    assert_eq!(skipped, &pending);
    assert!(why.contains("accepted"), "{why}");
    assert_eq!(
        accepted_rooms(&server, ALICE).await,
        std::slice::from_ref(&room)
    );

    // alice's second device: a fresh identity on the same account.
    let mut a2 = device(&server, ALICE, dir.path(), "a2").await;
    // Its first poll reads the account's old Messages: held, not errors.
    assert!(
        a2.poll()
            .await
            .unwrap()
            .iter()
            .all(|e| !matches!(e, Event::Problem { .. } | Event::Message(_)))
    );
    let epoch = a1.epoch(&room).unwrap();
    let outcome = a2.join_own_rooms().await.unwrap();
    // The Add put a1's leaf in the second room's group, but no device of
    // alice accepted it (bead mimid-f2rn): a2 joins only the first.
    assert_eq!(
        outcome.joined,
        std::slice::from_ref(&room),
        "{:?}",
        outcome.failed
    );
    assert!(outcome.failed.is_empty(), "{:?}", outcome.failed);
    let [(skipped, why)] = outcome.skipped.as_slice() else {
        panic!("{outcome:?}");
    };
    assert_eq!(skipped, &pending);
    assert!(why.contains("accepted"), "{why}");
    assert_eq!(a2.epoch(&room).unwrap(), epoch + 1);
    assert!(
        a2.rooms()
            .iter()
            .all(|r| r.uri == room && r.status == RoomStatus::Active)
    );
    // a2 reports the room it joined; nothing it held is a problem.
    poll_until(&mut a2, &server, |e| match e {
        Event::MembersChanged {
            room: r, epoch: e, ..
        } if *r == room => Some(*e),
        _ => None,
    })
    .await;

    // bob reads a2's external Commit with the joiner as its committer
    // (bead mimid-cqof).
    let committer = poll_until(&mut bob, &server, |e| match e {
        Event::MembersChanged {
            room: r,
            epoch: e,
            committer,
            ..
        } if *r == room && *e == epoch + 1 => Some(committer.clone()),
        _ => None,
    })
    .await;
    assert_eq!(committer.as_deref(), Some(ALICE));
    catch_up(&mut bob, &a2, &server, &room).await;
    catch_up(&mut a1, &a2, &server, &room).await;
    assert_agreement(&room, &a1, &bob);
    let two_alices = [
        (ALICE.to_owned(), None),
        (ALICE.to_owned(), None),
        (BOB.to_owned(), None),
    ];
    for member in [&a1, &a2, &bob] {
        assert_eq!(leaves(member, &room), two_alices, "{}", member.user());
        assert_eq!(member.participants(&room).unwrap(), [ALICE, BOB]);
    }

    sends(
        &mut a2,
        &server,
        &room,
        "from the new device",
        ALICE,
        &mut [&mut bob, &mut a1],
    )
    .await;
    sends(
        &mut bob,
        &server,
        &room,
        "hi both",
        BOB,
        &mut [&mut a1, &mut a2],
    )
    .await;
    sends(
        &mut a1,
        &server,
        &room,
        "from the old device",
        ALICE,
        &mut [&mut bob, &mut a2],
    )
    .await;

    // Still nothing more to join.
    let again = a2.join_own_rooms().await.unwrap();
    assert!(
        again.joined.is_empty() && again.failed.is_empty(),
        "{again:?}"
    );

    // a1 accepts the second room; its next call records it, and a2 joins.
    assert_eq!(a1.join(invite).unwrap(), pending);
    catch_up(&mut bob, &a1, &server, &pending).await;
    let own = a1.join_own_rooms().await.unwrap();
    assert!(own.skipped.is_empty() && own.joined.is_empty(), "{own:?}");
    let mut both = vec![room.clone(), pending.clone()];
    both.sort();
    assert_eq!(accepted_rooms(&server, ALICE).await, both);
    let outcome = a2.join_own_rooms().await.unwrap();
    assert_eq!(
        outcome.joined,
        std::slice::from_ref(&pending),
        "{:?}",
        outcome.failed
    );
    catch_up(&mut bob, &a2, &server, &pending).await;
    catch_up(&mut a1, &a2, &server, &pending).await;
    sends(
        &mut bob,
        &server,
        &pending,
        "now both of you",
        BOB,
        &mut [&mut a1, &mut a2],
    )
    .await;

    // Nothing more to join.
    let again = a2.join_own_rooms().await.unwrap();
    assert_eq!(again, Default::default());

    // The new device keeps the room across a restart.
    drop(a2);
    let mut a2 = device(&server, ALICE, dir.path(), "a2").await;
    assert_agreement(&room, &a2, &bob);
    sends(
        &mut bob,
        &server,
        &room,
        "after the restart",
        BOB,
        &mut [&mut a2, &mut a1],
    )
    .await;
}

/// Leaving with two devices in the room removes both (bead mimid-pv2k;
/// room-policy-04 §8.1.2 `canRemoveSelf`): bob commits the proposals, the
/// hub accepts the Commit (bob's epoch moves and alice's devices both see
/// it), and no leaf of alice remains. The record of alice's acceptance
/// goes with it, so a third device does not rejoin (decision
/// mimid-1wgh.63 item 6).
#[tokio::test]
async fn leaving_removes_every_device_of_the_user() {
    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path(), &[ALICE, BOB]).await;
    let mut a1 = device(&server, ALICE, dir.path(), "a1").await;
    let mut bob = device(&server, BOB, dir.path(), "bob").await;
    a1.publish_key_packages(1).await.unwrap();
    bob.publish_key_packages(1).await.unwrap();
    let room = a1.host_room(&HostOptions::named("leaving")).await.unwrap();
    a1.invite(&room, BOB).await.unwrap();
    accept(&mut bob, &server, &room).await;
    assert_eq!(a1.join_own_rooms().await.unwrap(), Default::default());
    let mut a2 = device(&server, ALICE, dir.path(), "a2").await;
    let joined = a2.join_own_rooms().await.unwrap();
    assert_eq!(joined.joined, std::slice::from_ref(&room), "{joined:?}");
    catch_up(&mut bob, &a2, &server, &room).await;
    catch_up(&mut a1, &a2, &server, &room).await;
    let epoch = bob.epoch(&room).unwrap();

    a1.leave(&room).await.unwrap();
    // bob, the only member of another user, commits the leave.
    let (participants, committer) = poll_until(&mut bob, &server, |e| match e {
        Event::MembersChanged {
            room: r,
            participants,
            committer,
            ..
        } if *r == room => Some((participants.clone(), committer.clone())),
        _ => None,
    })
    .await;
    assert_eq!(participants, [BOB]);
    // bob's own Commit names bob.
    assert_eq!(committer.as_deref(), Some(BOB));
    assert_eq!(bob.epoch(&room).unwrap(), epoch + 1);
    assert_eq!(leaves(&bob, &room), [(BOB.to_owned(), None)]);
    for alice in [&mut a1, &mut a2] {
        poll_until(alice, &server, |e| match e {
            Event::Left { room: r } if *r == room => Some(()),
            _ => None,
        })
        .await;
        assert!(
            alice
                .rooms()
                .iter()
                .all(|r| r.uri != room || r.status == RoomStatus::Left)
        );
    }
    sends(&mut bob, &server, &room, "alone now", BOB, &mut []).await;

    // a1 withdraws alice's acceptance; a third device does not join.
    a1.join_own_rooms().await.unwrap();
    assert!(accepted_rooms(&server, ALICE).await.is_empty());
    let mut a3 = device(&server, ALICE, dir.path(), "a3").await;
    let outcome = a3.join_own_rooms().await.unwrap();
    assert!(outcome.joined.is_empty(), "{outcome:?}");
}

#[tokio::test]
async fn the_hub_refuses_a_new_device_without_can_add_own_client() {
    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path(), &[ALICE, BOB]).await;
    let mut a1 = device(&server, ALICE, dir.path(), "a1").await;
    a1.publish_key_packages(1).await.unwrap();
    let options = HostOptions {
        roles: Some(roles_without_add_own_client()),
        ..HostOptions::named("closed")
    };
    let room = a1.host_room(&options).await.unwrap();
    let epoch = a1.epoch(&room).unwrap();
    // Records the room as accepted.
    assert_eq!(a1.join_own_rooms().await.unwrap(), Default::default());

    let mut a2 = device(&server, ALICE, dir.path(), "a2").await;
    let outcome = a2.join_own_rooms().await.unwrap();
    assert!(outcome.joined.is_empty());
    assert!(outcome.failed.is_empty(), "{outcome:?}");
    let [(refused, why)] = outcome.skipped.as_slice() else {
        panic!("{outcome:?}");
    };
    assert_eq!(refused, &room);
    assert!(why.contains("NotAuthorized"), "{why}");
    assert!(a2.rooms().is_empty());
    // The room did not change.
    assert!(a1.poll().await.unwrap().is_empty());
    assert_eq!(a1.epoch(&room).unwrap(), epoch);
}

/// The rooms whose Chat records alice's acceptance, as the server
/// returns them to a plain JMAP Chat/get (draft-ietf-jmap-metadata-05
/// §3.1): the oracle for what the devices wrote.
async fn accepted_rooms(server: &common::Server, user: &str) -> Vec<String> {
    let http = reqwest::Client::new();
    let session: serde_json::Value = serde_json::from_slice(
        &http
            .get(format!("{}/.well-known/jmap", server.base))
            .bearer_auth(&server.tokens[user])
            .send()
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap(),
    )
    .unwrap();
    let account = session["primaryAccounts"]["urn:ietf:params:jmap:chat"]
        .as_str()
        .unwrap()
        .to_owned();
    let body = serde_json::json!({
        "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:chat",
                  "urn:ietf:params:jmap:chat:mimi", "urn:ietf:params:jmap:metadata"],
        "methodCalls": [["Chat/get", {"accountId": account, "ids": null}, "c"]],
    });
    let answer: serde_json::Value = serde_json::from_slice(
        &http
            .post(format!("{}/jmap/api", server.base))
            .bearer_auth(&server.tokens[user])
            .header("content-type", "application/json")
            .body(body.to_string())
            .send()
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap(),
    )
    .unwrap();
    let mut rooms: Vec<String> = answer["methodResponses"][0][1]["list"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|chat| {
            chat["privateMetadata"]["mimid.reviewcommit.com"]
                == serde_json::json!({"accepted": true})
        })
        .map(|chat| chat["roomId"].as_str().unwrap().to_owned())
        .collect();
    rooms.sort();
    rooms
}

fn key(agent: &Agent) -> PublicKey {
    agent.signature_public_key().try_into().unwrap()
}

fn time(s: u32) -> String {
    format!("2026-11-20T12:00:{s:02}Z")
}

#[tokio::test]
async fn a_device_the_log_adds_joins_a_did_webvh_room() {
    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path(), &[ALICE, BOB]).await;
    let none = DidWebvhConfig::default;
    let mut a1 = device_with(&server, ALICE, dir.path(), "a1", none()).await;
    let mut bob = device(&server, BOB, dir.path(), "bob").await;

    // Alice's controller lists a1; a1 takes the credential.
    let signer = UpdateKey::from_seed(&[0x5a; 32]);
    let mut log = DidLog::create_also_known_as(
        "a.example",
        "alice",
        &time(1),
        &Parameters {
            update_keys: Some(vec![signer.multikey()]),
            next_key_hashes: None,
        },
        &signer,
        &[key(&a1)],
        &[ALICE.to_owned()],
    )
    .unwrap();
    let scid = log.verified().scid().to_owned();
    a1.use_did_webvh_credential(log.credential().unwrap())
        .await
        .unwrap();
    a1.publish_key_packages(1).await.unwrap();
    bob.publish_key_packages(1).await.unwrap();

    let room = bob.host_room(&HostOptions::named("mixed")).await.unwrap();
    bob.invite(&room, ALICE).await.unwrap();
    accept(&mut a1, &server, &room).await;
    assert_agreement(&room, &a1, &bob);
    // Records the accepted room.
    assert_eq!(a1.join_own_rooms().await.unwrap(), Default::default());

    // The controller adds a3 to the log; a3 takes it and joins.
    let mut a3 = device_with(&server, ALICE, dir.path(), "a3", none()).await;
    log.append(
        &time(2),
        &Parameters::default(),
        &signer,
        &[key(&a1), key(&a3)],
    )
    .unwrap();
    a3.use_did_webvh_credential(log.credential().unwrap())
        .await
        .unwrap();
    let outcome = a3.join_own_rooms().await.unwrap();
    assert_eq!(
        outcome.joined,
        std::slice::from_ref(&room),
        "{:?}",
        outcome.failed
    );

    catch_up(&mut bob, &a3, &server, &room).await;
    catch_up(&mut a1, &a3, &server, &room).await;
    let alice_leaf = (ALICE.to_owned(), Some(scid.clone()));
    assert_eq!(
        leaves(&bob, &room),
        [alice_leaf.clone(), alice_leaf, (BOB.to_owned(), None)]
    );
    sends(
        &mut a3,
        &server,
        &room,
        "from a3",
        ALICE,
        &mut [&mut bob, &mut a1],
    )
    .await;
    sends(
        &mut bob,
        &server,
        &room,
        "hi a3",
        BOB,
        &mut [&mut a3, &mut a1],
    )
    .await;
}
