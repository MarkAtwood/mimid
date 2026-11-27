//! What an embedder that is its own agent needs from agent-core
//! (docs/design/purple-mimi.md §13 step 3a, bead mimid-s4oy.9): a typed
//! error when the provider does not serve the live stream (§7.1), a
//! refusal of another user's token (§7.2), the state directory's lock
//! (§6.2), an explicit close of the stream (§6.4), and declining an
//! invite (§8.11).
//!
//! Oracles: the provider's own configuration (stream off), which user each
//! token was issued to, and the agent's state and errors as documented.

mod common;

use common::{ALICE, BOB, Server, poll_until, server_with};
use mimid_agent_core::{
    Agent, AgentConfig, AgentError, Binding, DATABASE_FILE, DidWebvhConfig, Event, HostOptions,
    LOCK_FILE,
};
use mimid_server::jmap::JmapOptions;

async fn stream_server(dir: &std::path::Path, live_stream: bool) -> Server {
    let mut options = JmapOptions::default();
    options.live_stream = live_stream;
    server_with(dir, &[ALICE, BOB], options).await
}

fn config(
    server: &Server,
    user: &'static str,
    token_of: &'static str,
    state_dir: std::path::PathBuf,
    binding: Binding,
) -> AgentConfig {
    AgentConfig {
        server_url: server.base.clone(),
        binding,
        token: server.tokens[token_of].clone(),
        user_uri: user.to_owned(),
        state_dir,
        full_tree_hubs: Vec::new(),
        did_webvh: DidWebvhConfig::default(),
    }
}

/// §7.1: a provider without `live_stream = true` answers the upgrade with
/// `404`, which is `StreamOff` naming the stream's URL, and nothing is
/// written to the state directory.
#[tokio::test]
async fn a_provider_without_the_stream_is_stream_off() {
    let dir = tempfile::tempdir().unwrap();
    let server = stream_server(dir.path(), false).await;
    let state = dir.path().join("alice");
    match Agent::open(config(
        &server,
        ALICE,
        ALICE,
        state.clone(),
        Binding::Stream,
    ))
    .await
    {
        Err(AgentError::StreamOff { url }) => {
            assert_eq!(
                url,
                format!(
                    "{}{}",
                    server.base.replacen("http", "ws", 1),
                    mimid_live::PATH
                )
            );
        }
        other => panic!("{:?}", other.map(|_| ())),
    }
    assert!(!state.join(DATABASE_FILE).exists(), "no state was made");
    // JMAP still works against it.
    Agent::open(config(&server, ALICE, ALICE, state, Binding::Jmap))
        .await
        .unwrap();
}

/// §7.2: bob's token configured for alice is refused on both bindings,
/// by the hello's and the Session's `userUri`, before any state is made.
#[tokio::test]
async fn another_users_token_is_refused_on_either_binding() {
    let dir = tempfile::tempdir().unwrap();
    let server = stream_server(dir.path(), true).await;
    for binding in [Binding::Jmap, Binding::Stream] {
        let state = dir.path().join(format!("{binding:?}"));
        match Agent::open(config(&server, ALICE, BOB, state.clone(), binding)).await {
            Err(AgentError::WrongUser {
                configured,
                provider,
            }) => {
                assert_eq!((configured.as_str(), provider.as_str()), (ALICE, BOB));
            }
            other => panic!("{binding:?}: {:?}", other.map(|_| ())),
        }
        assert!(!state.join(DATABASE_FILE).exists(), "{binding:?}");
        // The percent-encoding of an unreserved character does not make
        // another user (RFC 3986 §6.2.2.2).
        let mut spelled = config(&server, ALICE, ALICE, state, binding);
        spelled.user_uri = ALICE.replace("alice", "%61lice");
        Agent::open(spelled).await.unwrap();
    }
}

/// §6.2: a second agent on one state directory is refused while the first
/// is open, in the same process; the lock goes with the agent, and the
/// lock file stays.
#[tokio::test]
async fn one_agent_per_state_directory() {
    let dir = tempfile::tempdir().unwrap();
    let server = stream_server(dir.path(), true).await;
    let state = dir.path().join("alice");
    let first = Agent::open(config(&server, ALICE, ALICE, state.clone(), Binding::Jmap))
        .await
        .unwrap();
    let lock = first.state_lock();
    assert!(lock.intact());
    for binding in [Binding::Jmap, Binding::Stream] {
        match Agent::open(config(&server, ALICE, ALICE, state.clone(), binding)).await {
            Err(AgentError::Locked { path }) => assert_eq!(path, state.join(LOCK_FILE)),
            other => panic!("{binding:?}: {:?}", other.map(|_| ())),
        }
    }
    drop(first);
    // A clone of the lock keeps it: an embedder's own connection to the
    // database holds one until it is closed.
    assert!(matches!(
        Agent::open(config(&server, ALICE, ALICE, state.clone(), Binding::Jmap)).await,
        Err(AgentError::Locked { .. })
    ));
    drop(lock);
    let again = Agent::open(config(
        &server,
        ALICE,
        ALICE,
        state.clone(),
        Binding::Stream,
    ))
    .await
    .unwrap();
    assert!(state.join(LOCK_FILE).exists());
    drop(again);
}

/// §6.4: after `close` the stream does not connect again: a call that
/// needs it fails, and the wake-up has stopped.
#[tokio::test]
async fn a_closed_stream_stays_closed() {
    let dir = tempfile::tempdir().unwrap();
    let server = stream_server(dir.path(), true).await;
    let mut alice = Agent::open(config(
        &server,
        ALICE,
        ALICE,
        dir.path().join("alice"),
        Binding::Stream,
    ))
    .await
    .unwrap();
    alice.publish_key_packages(1).await.unwrap();
    alice.poll().await.unwrap();
    // The tasks ending is the event, so awaiting `close` is the
    // assertion: one that never ends hangs here and says so.
    alice.close().await;
    match alice.poll().await {
        Err(AgentError::Stream { detail, .. }) => assert!(detail.contains("closed"), "{detail}"),
        other => panic!("{other:?}"),
    }
    match alice.publish_key_packages(1).await {
        Err(AgentError::Stream { .. }) => {}
        other => panic!("{other:?}"),
    }
    // A second close does nothing.
    alice.close().await;
}

/// §8.11: a declined invite is gone, is not joined, and does not come back
/// after a restart; declining it again is `NoSuchInvite`.
#[tokio::test]
async fn a_declined_invite_is_gone_for_good() {
    let dir = tempfile::tempdir().unwrap();
    let server = stream_server(dir.path(), true).await;
    let open = |user: &'static str| {
        Agent::open(config(
            &server,
            user,
            user,
            dir.path().join(user.rsplit('/').next().unwrap()),
            Binding::Stream,
        ))
    };
    let mut alice = open(ALICE).await.unwrap();
    let mut bob = open(BOB).await.unwrap();
    alice.publish_key_packages(1).await.unwrap();
    bob.publish_key_packages(1).await.unwrap();
    let room = alice
        .host_room(&HostOptions::named("declined"))
        .await
        .unwrap();
    bob.allow(ALICE).await.unwrap();
    alice.invite(&room, BOB).await.unwrap();
    let number = poll_until(&mut bob, &server, |e| match e {
        Event::InviteArrived { number } => Some(*number),
        _ => None,
    })
    .await;
    bob.decline_invite(number).unwrap();
    assert!(bob.invites().is_empty());
    assert!(matches!(
        bob.decline_invite(number),
        Err(AgentError::NoSuchInvite(n)) if n == number
    ));
    assert!(matches!(bob.join(number), Err(AgentError::NoSuchInvite(_))));
    drop(bob);
    let mut bob = open(BOB).await.unwrap();
    // Drain: poll until one reads nothing, so "not back after a
    // restart" is about every poll there is rather than the first
    // three.
    while !bob.poll().await.unwrap().is_empty() {}
    assert!(bob.invites().is_empty(), "not back after a restart");
    assert!(bob.rooms().iter().all(|r| r.uri != room), "not joined");
}
