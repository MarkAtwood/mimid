//! An agent that was away longer than its server's message retention, or
//! whose server's operator deleted messages by hand (decisions
//! mimid-1wgh.82, mimid-1wgh.83; draft-atwood-jmap-chat-mimi-00
//! §capability `messageRetention`): it missed a Commit the server no
//! longer has, finds that its group fell behind at the next message,
//! rejoins the room by external Commit, reports the lost messages once,
//! and then exchanges messages again. On JMAP and on the live stream.
//!
//! Oracles: the draft's text quoted above (a client away longer "MAY
//! rejoin the room by external join; the application messages it missed
//! are lost to it"); MLS agreement after the rejoin (RFC 9420 §8.7); the
//! plaintexts sent.

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::{
    ALICE, BOB, CAROL, Server, assert_agreement, poll_until, roles_without_add_own_client,
    server_with,
};
use mimid_agent_core::{
    Agent, AgentConfig, Binding, DidWebvhConfig, Event, HostOptions, RoomStatus,
};
use mimid_server::hub::SystemClock;
use mimid_server::jmap::JmapOptions;
use mimid_server::retention::MessageSweeper;

/// The retention the test server states and sweeps by.
const RETENTION: Duration = Duration::from_millis(1500);

async fn device(
    server: &Server,
    user: &'static str,
    dir: &std::path::Path,
    binding: Binding,
) -> Agent {
    Agent::open(AgentConfig {
        server_url: server.base.clone(),
        binding,
        token: server.tokens[user].clone(),
        user_uri: user.to_owned(),
        state_dir: dir.join(user.rsplit('/').next().unwrap()),
        full_tree_hubs: Vec::new(),
        did_webvh: DidWebvhConfig::default(),
    })
    .await
    .unwrap()
}

/// Runs `statements` on the server's database as an operator with the
/// sqlite3 CLI would (foreign keys off), on a thread of its own so the
/// server goes on meanwhile; returns the rows deleted.
async fn by_hand(path: &std::path::Path, statements: &[&'static str]) -> usize {
    let path = path.to_owned();
    let statements = statements.to_vec();
    tokio::task::spawn_blocking(move || {
        let db = rusqlite::Connection::open(path).unwrap();
        db.busy_timeout(Duration::from_secs(10)).unwrap();
        statements
            .iter()
            .map(|statement| db.execute(statement, []).unwrap())
            .sum()
    })
    .await
    .unwrap()
}

/// How the messages bob missed go.
#[derive(Debug, Clone, Copy)]
enum Loss {
    /// The server's sweep, past its retention.
    Sweep,
    /// An operator, by hand, with the server running: a scattered set of
    /// rows, the missed Commit among them, older ones bob had too.
    ByHand,
}

/// Polls `agent` until it reports lost messages in `room`; any other
/// problem fails the test.
///
/// Woken between polls by `server`. A poll that read anything is
/// followed by another at once: one change at the server can take an
/// agent several polls.
async fn lost(agent: &mut Agent, server: &Server, room: &str) -> (Option<u64>, u64) {
    let mut changed = server.changed();
    loop {
        let events = agent.poll().await.unwrap();
        let progressed = !events.is_empty();
        for event in events {
            match event {
                Event::MessagesLost {
                    room: r, from, to, ..
                } if r == room => return (from, to),
                Event::Problem { room, description } => {
                    panic!("problem in {room:?}: {description}")
                }
                _ => {}
            }
        }
        if progressed {
            continue;
        }
        let stream = agent.stream_wake();
        common::look_again(
            &format!("MessagesLost in {room}"),
            &mut changed,
            stream.as_ref(),
        )
        .await;
    }
}

async fn away_past_retention(binding: Binding, loss: Loss) {
    let dir = tempfile::tempdir().unwrap();
    let mut options = JmapOptions::default();
    options.live_stream = true;
    options.message_retention = Some(1);
    let server = server_with(dir.path(), &[ALICE, BOB], options).await;
    let mut alice = device(&server, ALICE, dir.path(), Binding::Jmap).await;
    let mut bob = device(&server, BOB, dir.path(), binding).await;
    bob.publish_key_packages(1).await.unwrap();
    let room = alice
        .host_room(&HostOptions::named("planning"))
        .await
        .unwrap();
    alice.invite(&room, BOB).await.unwrap();
    let number = poll_until(&mut bob, &server, |e| match e {
        Event::InviteArrived { number } => Some(*number),
        _ => None,
    })
    .await;
    bob.join(number).unwrap();
    alice.send_text(&room, "before").await.unwrap();
    let before = poll_until(&mut bob, &server, |e| match e {
        Event::Message(m) => Some(m.accepted_at),
        _ => None,
    })
    .await;
    let epoch = bob.epoch(&room).unwrap();

    // bob is away; alice commits (a new subject) and talks.
    drop(bob);
    alice
        .set_room_subject(&room, "while bob was away")
        .await
        .unwrap();
    alice.send_text(&room, "missed").await.unwrap();
    match loss {
        Loss::Sweep => {
            // The clock is the event: the sweeper deletes what is older
            // than the retention, so the test has to be past it before
            // sweeping. One sleep, not a loop.
            tokio::time::sleep(RETENTION).await;
            let swept =
                MessageSweeper::new(server.store.clone(), Arc::new(SystemClock), RETENTION / 2)
                    .sweep()
                    .await
                    .unwrap();
            assert!(swept.follower > 0 && swept.hub > 0, "{swept:?}");
        }
        Loss::ByHand => {
            // Every Commit, the oldest event, and every third one.
            let deleted = by_hand(
                &dir.path().join("mimid.sqlite"),
                &[
                    "DELETE FROM follower_event WHERE kind = 'commit' \
                     OR seq = (SELECT MIN(seq) FROM follower_event) OR seq % 3 = 0",
                    "DELETE FROM room_event WHERE seq % 2 = 0",
                ],
            )
            .await;
            assert!(deleted > 0);
        }
    }

    // A message of the new epoch reaches bob after he is back: his group
    // is behind, so he rejoins.
    alice.send_text(&room, "after the gap").await.unwrap();
    let mut bob = device(&server, BOB, dir.path(), binding).await;
    let (from, to) = lost(&mut bob, &server, &room).await;
    assert!(from.is_some_and(|from| from >= before), "{from:?} {before}");
    assert!(to >= from.unwrap_or(0));
    assert!(
        bob.epoch(&room).unwrap() > epoch + 1,
        "rejoined at the room's epoch"
    );
    assert_eq!(
        bob.room_subject(&room).unwrap().as_deref(),
        Some("while bob was away"),
        "the rejoined group has the room as it is now"
    );
    // alice takes in bob's external Commit.
    let target = bob.epoch(&room).unwrap();
    poll_until(&mut alice, &server, |e| match e {
        Event::MembersChanged { epoch, .. } if *epoch == target => Some(()),
        _ => None,
    })
    .await;
    assert_agreement(&room, &alice, &bob);

    // And they talk again, both ways.
    alice.send_text(&room, "welcome back").await.unwrap();
    let got = poll_until(&mut bob, &server, |e| match e {
        Event::Message(m) => m.text.clone(),
        _ => None,
    })
    .await;
    assert_eq!(got, "welcome back");
    bob.send_text(&room, "glad to be").await.unwrap();
    let got = poll_until(&mut alice, &server, |e| match e {
        Event::Message(m) => m.text.clone(),
        _ => None,
    })
    .await;
    assert_eq!(got, "glad to be");

    // The gap is reported once: a restart does not report it again.
    drop(bob);
    let mut bob = device(&server, BOB, dir.path(), binding).await;
    for event in bob.poll().await.unwrap() {
        assert!(
            !matches!(event, Event::MessagesLost { .. } | Event::Problem { .. }),
            "{event:?}"
        );
    }
}

#[tokio::test]
async fn an_agent_away_past_the_retention_rejoins_over_jmap() {
    away_past_retention(Binding::Jmap, Loss::Sweep).await;
}

#[tokio::test]
async fn an_agent_away_past_the_retention_rejoins_over_the_stream() {
    away_past_retention(Binding::Stream, Loss::Sweep).await;
}

#[tokio::test]
async fn an_agent_whose_messages_were_deleted_by_hand_rejoins_over_jmap() {
    away_past_retention(Binding::Jmap, Loss::ByHand).await;
}

#[tokio::test]
async fn an_agent_whose_messages_were_deleted_by_hand_rejoins_over_the_stream() {
    away_past_retention(Binding::Stream, Loss::ByHand).await;
}

/// A room whose policy lets no client of a participant in by external
/// Commit (room-policy-04 §8.1.1 `canAddOwnClient` off): bob cannot
/// rejoin, so the room is left, with one problem saying it needs a new
/// invite and one report of the lost messages.
#[tokio::test]
async fn a_room_that_refuses_the_rejoin_is_left_for_a_new_invite() {
    let dir = tempfile::tempdir().unwrap();
    let server = server_with(dir.path(), &[ALICE, BOB, CAROL], JmapOptions::default()).await;
    let mut alice = device(&server, ALICE, dir.path(), Binding::Jmap).await;
    let mut bob = device(&server, BOB, dir.path(), Binding::Jmap).await;
    bob.publish_key_packages(1).await.unwrap();
    let options = HostOptions {
        roles: Some(roles_without_add_own_client()),
        ..HostOptions::named("closed")
    };
    let room = alice.host_room(&options).await.unwrap();
    alice.invite(&room, BOB).await.unwrap();
    let number = poll_until(&mut bob, &server, |e| match e {
        Event::InviteArrived { number } => Some(*number),
        _ => None,
    })
    .await;
    bob.join(number).unwrap();
    bob.poll().await.unwrap();
    drop(bob);
    // A Commit bob misses: carol is added.
    let mut carol = device(&server, CAROL, dir.path(), Binding::Jmap).await;
    carol.publish_key_packages(1).await.unwrap();
    alice.invite(&room, CAROL).await.unwrap();
    by_hand(
        &dir.path().join("mimid.sqlite"),
        &["DELETE FROM follower_event WHERE kind = 'commit'"],
    )
    .await;
    alice.send_text(&room, "after the gap").await.unwrap();

    let mut bob = device(&server, BOB, dir.path(), Binding::Jmap).await;
    let (mut problems, mut lost, mut left) = (Vec::new(), 0, false);
    let mut changed = server.changed();
    while !left {
        let events = bob.poll().await.unwrap();
        let progressed = !events.is_empty();
        for event in events {
            match event {
                Event::Problem { description, .. } => problems.push(description),
                Event::MessagesLost { .. } => lost += 1,
                Event::Left { room: r } if r == room => left = true,
                _ => {}
            }
        }
        if left {
            break;
        }
        if progressed {
            continue;
        }
        let stream = bob.stream_wake();
        common::look_again(
            &format!("bob to be told he is out of {room}"),
            &mut changed,
            stream.as_ref(),
        )
        .await;
    }
    assert_eq!(lost, 1);
    assert_eq!(problems.len(), 1, "{problems:?}");
    assert!(problems[0].contains("needs a new invite"), "{problems:?}");
    let status = bob
        .rooms()
        .into_iter()
        .find(|r| r.uri == room)
        .unwrap()
        .status;
    assert_eq!(status, RoomStatus::Left);
}
