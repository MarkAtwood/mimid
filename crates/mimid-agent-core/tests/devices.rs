//! A user's devices (draft-atwood-jmap-chat-mimi-00 §Clients,
//! jmap-chat-spec bde5330; bead mimid-e64f.23): alice's second device
//! joins her room by external Commit, which binds its key to her account
//! (a Client record); her first device lists both, forgets the second as
//! lost, and so removes its leaf from the room they share, on JMAP and on
//! the live stream.
//!
//! Oracles: the draft's text ("A client that destroys the record of
//! another of the owner's clients ... removes that client's leaves, with
//! `Room/update`, from the rooms they share"); the devices' own signature
//! keys; bob's view of the room's leaves; MLS agreement after the Commit
//! (RFC 9420 §8.7).

mod common;

use common::{ALICE, BOB, Server, assert_agreement, catch_up, poll_until, server_with};
use mimid_agent_core::{
    Agent, AgentConfig, AgentError, Binding, DidWebvhConfig, Event, HostOptions,
};
use mimid_server::jmap::JmapOptions;

async fn device(
    server: &Server,
    user: &'static str,
    dir: &std::path::Path,
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

async fn a_lost_device_is_forgotten(binding: Binding) {
    let dir = tempfile::tempdir().unwrap();
    let mut options = JmapOptions::default();
    options.live_stream = true;
    let server = server_with(dir.path(), &[ALICE, BOB], options).await;
    let mut a1 = device(&server, ALICE, dir.path(), "a1", binding).await;
    let mut bob = device(&server, BOB, dir.path(), "bob", Binding::Jmap).await;
    a1.publish_key_packages(1).await.unwrap();
    bob.publish_key_packages(1).await.unwrap();
    let room = a1.host_room(&HostOptions::named("r")).await.unwrap();
    a1.invite(&room, BOB).await.unwrap();
    let number = poll_until(&mut bob, &server, |e| match e {
        Event::InviteArrived { number } => Some(*number),
        _ => None,
    })
    .await;
    bob.join(number).unwrap();
    // Records the room as accepted, so a2 joins it.
    a1.join_own_rooms().await.unwrap();

    // a2 joins by external Commit: the server binds its key.
    let mut a2 = device(&server, ALICE, dir.path(), "a2", Binding::Jmap).await;
    a2.poll().await.unwrap();
    let joined = a2.join_own_rooms().await.unwrap();
    assert_eq!(joined.joined, std::slice::from_ref(&room), "{joined:?}");
    catch_up(&mut a1, &a2, &server, &room).await;
    catch_up(&mut bob, &a2, &server, &room).await;
    let devices = a1.devices().await.unwrap();
    assert_eq!(devices.len(), 2, "{devices:?}");
    let own = devices.iter().find(|d| d.this_device).unwrap();
    assert_eq!(own.signature_key, a1.signature_public_key());
    let lost = devices.iter().find(|d| !d.this_device).unwrap().clone();
    assert_eq!(lost.signature_key, a2.signature_public_key());
    assert_eq!(bob.clients(&room).unwrap().len(), 3);

    // This device cannot forget itself.
    assert!(matches!(
        a1.forget_device(&own.id).await,
        Err(AgentError::Invalid(_))
    ));
    let forgotten = a1.forget_device(&lost.id).await.unwrap();
    assert_eq!(forgotten.removed_from, std::slice::from_ref(&room));
    assert!(forgotten.failed.is_empty(), "{forgotten:?}");
    let ids: Vec<String> = a1
        .devices()
        .await
        .unwrap()
        .into_iter()
        .map(|d| d.id)
        .collect();
    assert_eq!(ids, std::slice::from_ref(&own.id));
    catch_up(&mut bob, &a1, &server, &room).await;
    assert_agreement(&room, &a1, &bob);
    // alice is still a participant, with one leaf: a1's.
    let leaves = bob.clients(&room).unwrap();
    assert_eq!(leaves.len(), 2, "{leaves:?}");
    assert!(bob.participants(&room).unwrap().contains(&ALICE.to_owned()));
}

#[tokio::test]
async fn a_lost_device_is_forgotten_over_jmap() {
    a_lost_device_is_forgotten(Binding::Jmap).await;
}

#[tokio::test]
async fn a_lost_device_is_forgotten_over_the_stream() {
    a_lost_device_is_forgotten(Binding::Stream).await;
}
