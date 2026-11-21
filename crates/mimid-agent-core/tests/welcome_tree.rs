//! A Welcome too large to carry the room's ratchet tree (decision
//! mimid-1wgh.81; bug mimid-jvde), through a real mimid server: the hub
//! sends it with the RatchetTreeOption `distributionService`, and each
//! invited device fetches the tree with GroupInfo/fetch, over JMAP or over
//! the live stream, joins from the Welcome with it, and talks.
//!
//! The hub's limit is lowered with its test hook
//! (`Hub::with_body_limit`), not by a room of thousands. The limit is one
//! octet under the length of the `full` Welcome in a first run of the same
//! scenario with the real limit; every length in it is fixed, and the test
//! checks that the second run's `full` Welcome would have had that length.
//!
//! Oracles:
//!
//! - The Welcome FanoutMessage bob's provider stored, decoded: `full` with
//!   the hub's tree under the real limit, `distributionService` and no tree
//!   under the lowered one.
//! - MLS agreement after the join (RFC 9420 §8.7): the joined devices
//!   verified the fetched tree against the Welcome's signed GroupInfo.
//! - Plaintext equality both ways, under the sender's message ID.
//! - The room's roles lack `canAddOwnClient`, so the hub's room policy
//!   would refuse bob's GroupInfo/fetch: the devices get the tree because
//!   they hold leaves of the group (`group_info.rs` step 4 of the hub).

#![forbid(unsafe_code)]

mod common;

use std::path::Path;
use std::time::Duration;

use common::{
    ALICE, BOB, Server, assert_agreement, poll_until, roles_without_add_own_client, sends,
    server_limited,
};
use mimi_mls::tls_codec::{Deserialize, Serialize};
use mimi_mls::wire::{RatchetTreeOption, RatchetTreeRepresentation};
use mimi_protocol::{FanoutEvent, FanoutMessage};
use mimid_agent_core::{Agent, AgentConfig, Binding, DidWebvhConfig, Event, HostOptions};
use mimid_server::jmap::JmapOptions;
use mimid_server::store::FanoutKind;

/// bob's devices and how each reaches the server: one Welcome with three
/// `EncryptedGroupSecrets`, which is what makes the `full` Welcome longer
/// than the groupInfo response (see the hub's test hub_welcome_tree.rs).
const BOB_DEVICES: [(&str, Binding); 3] = [
    ("bob1", Binding::Jmap),
    ("bob2", Binding::Stream),
    ("bob3", Binding::Jmap),
];

async fn device_on(
    server: &Server,
    user: &'static str,
    dir: &Path,
    name: &str,
    binding: Binding,
) -> Agent {
    Agent::open(AgentConfig {
        server_url: server.base.clone(),
        binding,
        token: server.tokens[user].clone(),
        user_uri: user.to_owned(),
        state_dir: dir.join(name),
        full_tree_hubs: Vec::new(),
        did_webvh: DidWebvhConfig::default(),
    })
    .await
    .unwrap()
}

/// A server with the live stream and the hub's `limit`, alice, bob's
/// devices, and a room alice hosts and invites bob to.
struct Scene {
    _dir: tempfile::TempDir,
    server: Server,
    alice: Agent,
    bobs: Vec<Agent>,
    room: String,
}

async fn scene(limit: Option<usize>) -> Scene {
    let dir = tempfile::tempdir().unwrap();
    let mut options = JmapOptions::default();
    options.live_stream = true;
    let server = server_limited(dir.path(), &[ALICE, BOB], options, limit).await;
    let mut alice = device_on(&server, ALICE, dir.path(), "alice", Binding::Jmap).await;
    alice.publish_key_packages(1).await.unwrap();
    let mut bobs = Vec::new();
    for (name, binding) in BOB_DEVICES {
        let mut bob = device_on(&server, BOB, dir.path(), name, binding).await;
        bob.publish_key_packages(1).await.unwrap();
        bobs.push(bob);
    }
    let options = HostOptions {
        roles: Some(roles_without_add_own_client()),
        ..HostOptions::named("crowded")
    };
    let room = alice.host_room(&options).await.unwrap();
    alice.invite(&room, BOB).await.unwrap();
    Scene {
        _dir: dir,
        server,
        alice,
        bobs,
        room,
    }
}

/// The Welcome FanoutMessage bob's provider stored for `room`, as stored.
async fn stored_welcome(server: &Server, room: &str) -> Vec<u8> {
    for _ in 0..100 {
        let events = server
            .store
            .follower_events(BOB, room, 0, 100)
            .await
            .unwrap();
        if let Some(welcome) = events.into_iter().find(|e| e.kind == FanoutKind::Welcome) {
            return welcome.bytes;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("no Welcome stored for bob");
}

#[tokio::test]
async fn oversized_welcome_is_joined_with_the_fetched_tree() {
    // The real limit: the Welcome carries the hub's tree.
    let probe = scene(None).await;
    let full = stored_welcome(&probe.server, &probe.room).await;
    let FanoutEvent::Welcome {
        ratchet_tree_option,
        ..
    } = FanoutMessage::tls_deserialize_exact(&full).unwrap().event
    else {
        panic!("not a Welcome");
    };
    assert_eq!(
        ratchet_tree_option.representation(),
        RatchetTreeRepresentation::Full
    );
    let state = probe.server.hub.public_state(&probe.room).await.unwrap();
    assert_eq!(
        ratchet_tree_option.ratchet_tree(),
        Some(state.ratchet_tree.as_slice())
    );
    let full_len = full.len();
    drop(probe);

    // One octet less: the Welcome goes without the tree.
    let Scene {
        _dir,
        server,
        mut alice,
        mut bobs,
        room,
    } = scene(Some(full_len - 1)).await;
    let stored = stored_welcome(&server, &room).await;
    let fanout = FanoutMessage::tls_deserialize_exact(&stored).unwrap();
    let timestamp = fanout.timestamp;
    let FanoutEvent::Welcome {
        message,
        ratchet_tree_option,
    } = fanout.event
    else {
        panic!("not a Welcome");
    };
    assert_eq!(
        ratchet_tree_option.representation(),
        RatchetTreeRepresentation::DistributionService
    );
    let state = server.hub.public_state(&room).await.unwrap();
    let as_full = FanoutMessage {
        timestamp,
        event: FanoutEvent::Welcome {
            message,
            ratchet_tree_option: RatchetTreeOption::full(&state.ratchet_tree).unwrap(),
        },
    }
    .tls_serialize_detached()
    .unwrap();
    assert_eq!(as_full.len(), full_len, "the same lengths as the first run");

    for bob in &mut bobs {
        let number = poll_until(bob, |e| match e {
            Event::InviteArrived { number } => Some(*number),
            _ => None,
        })
        .await;
        assert_eq!(bob.inviter(number).unwrap(), ALICE);
        assert_eq!(bob.join(number).unwrap(), room);
        assert_agreement(&room, bob, &alice);
    }

    let [b1, b2, b3] = bobs.as_mut_slice() else {
        unreachable!()
    };
    sends(
        &mut alice,
        &room,
        "to every device",
        ALICE,
        &mut [&mut *b1, &mut *b2, &mut *b3],
    )
    .await;
    sends(
        b1,
        &room,
        "from bob1",
        BOB,
        &mut [&mut alice, &mut *b2, &mut *b3],
    )
    .await;
    sends(
        b2,
        &room,
        "from bob2 on the stream",
        BOB,
        &mut [&mut alice, &mut *b1, &mut *b3],
    )
    .await;
    sends(
        b3,
        &room,
        "from bob3",
        BOB,
        &mut [&mut alice, &mut *b1, &mut *b2],
    )
    .await;
}
