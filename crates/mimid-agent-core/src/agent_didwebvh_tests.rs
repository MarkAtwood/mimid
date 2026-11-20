//! The fallback of [`Agent::use_did_webvh_credential`] (bead
//! mimid-1wgh.4.81.28 (c)) through a real mimid server: when this device
//! cannot build the Commit that carries its new credential, it sends an
//! Update proposal, the hub accepts it, and another member's agent commits
//! it with the record change.
//!
//! The Commit's failure is injected (`fail_credential_commits`). With the
//! record an `app_data_dictionary` component (decision mimid-1wgh.4.81.33),
//! a pending GroupContextExtensions proposal no longer makes the Commit
//! fail, and what still does (a pending record update for an SCID with no
//! leaf, decision mimid-1wgh.4.65) would make the other member's Commit
//! fail too; mimi-mls's `didwebvh_appdata` tests run the fallback with a
//! pending GroupContextExtensions proposal.
//!
//! Oracles: the did:webvh logs come from `mls_didwebvh::controller`, whose
//! output the mls-didwebvh tests check against an independent verifier;
//! the record bob's group holds after his Commit names the head version
//! the controller wrote; MLS agreement (same epoch and epoch
//! authenticator, RFC 9420 §8.7) between the proposer and the committer.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use mimi_mls::mls_didwebvh::PublicKey;
use mimi_mls::mls_didwebvh::controller::{DidLog, Parameters, UpdateKey};
use mimid_server::config::{BaseUrl, Domain};
use mimid_server::directory::directory;
use mimid_server::follower::Follower;
use mimid_server::follower::key_packages::KeyPackages;
use mimid_server::follower::relay::Relay;
use mimid_server::http::router;
use mimid_server::hub::fanout::Fanout;
use mimid_server::hub::{Clock, Hub, SystemClock};
use mimid_server::jmap::{self, JmapOptions};
use mimid_server::peer::PeerClient;
use mimid_server::store::Store;

use super::{Agent, AgentConfig, Event, HostOptions};
use crate::DidWebvhConfig;

const ALICE: &str = "mimi://a.example/u/alice";
const BOB: &str = "mimi://a.example/u/bob";

/// a.example's stack as `main.rs` wires it; the server's base URL and a
/// token per user.
async fn server(dir: &Path, users: &[&'static str]) -> (String, BTreeMap<&'static str, String>) {
    let domain = Domain::try_from("a.example".to_owned()).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base_text = format!("http://{}", listener.local_addr().unwrap());
    let base = BaseUrl::try_from(base_text.clone()).unwrap();
    let store = Store::open(&dir.join("mimid.sqlite"), &domain)
        .await
        .unwrap();
    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    let peers = || PeerClient::new(&domain, BTreeMap::new()).unwrap();
    let key_packages = Arc::new(KeyPackages::new(
        store.clone(),
        domain.clone(),
        Arc::clone(&clock),
    ));
    let follower = Arc::new(
        Follower::new(domain.clone(), store.clone(), Arc::clone(&clock))
            .with_peers(peers())
            .with_key_packages(Arc::clone(&key_packages)),
    );
    let fanout = Fanout::new(
        store.clone(),
        domain.clone(),
        peers(),
        Arc::clone(&follower),
        Arc::clone(&clock),
    )
    .spawn();
    let hub = Arc::new(
        Hub::open(store.clone(), domain.clone(), Arc::clone(&clock))
            .await
            .unwrap()
            .with_fanout(fanout)
            .with_peers(peers())
            .with_local_key_material(Arc::clone(&key_packages) as _),
    );
    follower
        .set_relay(Relay::new(Arc::clone(&hub), peers()))
        .unwrap();
    let mut tokens = BTreeMap::new();
    for user in users {
        let account = store.create_account(&domain, user, 1).await.unwrap();
        let token = store.issue_token(&account, 2).await.unwrap();
        tokens.insert(*user, token.expose_secret());
    }
    let jmap = jmap::router(
        &base,
        store,
        Arc::clone(&hub),
        Arc::clone(&follower),
        JmapOptions::default(),
    )
    .unwrap();
    let app = router(directory(&base), hub, follower).merge(jmap);
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (base_text, tokens)
}

async fn agent(
    (base, tokens): &(String, BTreeMap<&'static str, String>),
    user: &'static str,
    dir: &Path,
    name: &str,
) -> Agent {
    Agent::open(AgentConfig {
        server_url: base.clone(),
        binding: crate::Binding::Jmap,
        token: tokens[user].clone(),
        user_uri: user.to_owned(),
        state_dir: dir.join(name),
        full_tree_hubs: Vec::new(),
        did_webvh: DidWebvhConfig::default(),
    })
    .await
    .unwrap()
}

fn key(agent: &Agent) -> PublicKey {
    agent.signature_public_key().try_into().unwrap()
}

/// Polls `agent` until `found` picks an event, for up to ten seconds.
/// Problems fail the test.
async fn poll_until<T>(agent: &mut Agent, mut found: impl FnMut(&Event) -> Option<T>) -> T {
    for _ in 0..100 {
        for event in agent.poll().await.unwrap() {
            if let Event::Problem { room, description } = &event {
                panic!("{}: problem in {room:?}: {description}", agent.user());
            }
            if let Some(value) = found(&event) {
                return value;
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("{}: the expected event never came", agent.user());
}

#[tokio::test]
async fn a_credential_that_cannot_be_committed_is_proposed_and_another_member_commits_it() {
    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path(), &[ALICE, BOB]).await;
    let mut alice = agent(&server, ALICE, dir.path(), "alice").await;
    let mut bob = agent(&server, BOB, dir.path(), "bob").await;
    let signer = UpdateKey::from_seed(&[0x5a; 32]);
    let mut log = DidLog::create_also_known_as(
        "a.example",
        "alice",
        "2026-11-20T12:00:01Z",
        &Parameters {
            update_keys: Some(vec![signer.multikey()]),
            next_key_hashes: None,
        },
        &signer,
        &[key(&alice)],
        &[ALICE.to_owned()],
    )
    .unwrap();
    alice
        .use_did_webvh_credential(log.credential().unwrap())
        .await
        .unwrap();
    alice.publish_key_packages(1).await.unwrap();
    bob.publish_key_packages(1).await.unwrap();
    let room = bob.host_room(&HostOptions::named("r")).await.unwrap();
    bob.invite(&room, ALICE).await.unwrap();
    let number = poll_until(&mut alice, |e| match e {
        Event::InviteArrived { number } => Some(*number),
        _ => None,
    })
    .await;
    alice.join(number).unwrap();
    let epoch = bob.epoch(&room).unwrap();

    // alice's controller writes a newer log; her Commit cannot be built.
    log.append(
        "2026-11-20T12:00:02Z",
        &Parameters::default(),
        &signer,
        &[key(&alice)],
    )
    .unwrap();
    alice.fail_credential_commits = true;
    let applied = alice
        .use_did_webvh_credential(log.credential().unwrap())
        .await
        .unwrap();
    assert_eq!(applied.committed, Vec::<String>::new());
    assert_eq!(applied.proposed, std::slice::from_ref(&room));
    assert!(applied.failed.is_empty(), "{applied:?}");
    assert_eq!(applied.version, 2);
    assert_eq!(alice.epoch(&room).unwrap(), epoch, "nothing committed");

    // bob receives the Update proposal and commits it with the record
    // change; the hub accepts it.
    let changed = poll_until(&mut bob, |e| match e {
        Event::MembersChanged { epoch, .. } => Some(*epoch),
        _ => None,
    })
    .await;
    assert_eq!(changed, epoch + 1);
    let heads = bob.members[&room]
        .did_webvh_heads(&bob.identity)
        .unwrap()
        .expect("the room has a did_webvh record");
    let head = heads.get(log.verified().scid()).expect("alice's entry");
    assert_eq!(head.version_id(), log.verified().head_version_id());
    poll_until(&mut alice, |e| match e {
        Event::MembersChanged { epoch: e, .. } if *e == epoch + 1 => Some(()),
        _ => None,
    })
    .await;
    assert_eq!(
        alice.epoch_authenticator(&room).unwrap(),
        bob.epoch_authenticator(&room).unwrap()
    );
}

/// Decision mimid-1wgh.4.81.31: a revocation alice's device cannot commit
/// itself goes out as an Update proposal, and bob, who has no kick
/// permission in the default roles, commits it with the Remove of alice's
/// revoked device. The hub accepts that Remove because alice's own Update
/// in the same Commit vouches for it.
///
/// Oracles: the room's leaves before and after, from bob's MLS state (two
/// alice leaves, then only a1's key); a1 and bob agree on the epoch
/// authenticator; and a2, whose leaf is gone, sees `Left`.
#[tokio::test]
async fn a_revocation_proposed_by_the_user_is_committed_by_another_member() {
    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path(), &[ALICE, BOB]).await;
    let mut a1 = agent(&server, ALICE, dir.path(), "alice1").await;
    let mut a2 = agent(&server, ALICE, dir.path(), "alice2").await;
    let mut bob = agent(&server, BOB, dir.path(), "bob").await;
    let signer = UpdateKey::from_seed(&[0x5b; 32]);
    let mut log = DidLog::create_also_known_as(
        "a.example",
        "alice",
        "2026-11-20T12:00:01Z",
        &Parameters {
            update_keys: Some(vec![signer.multikey()]),
            next_key_hashes: None,
        },
        &signer,
        &[key(&a1), key(&a2)],
        &[ALICE.to_owned()],
    )
    .unwrap();
    for device in [&mut a1, &mut a2] {
        device
            .use_did_webvh_credential(log.credential().unwrap())
            .await
            .unwrap();
        device.publish_key_packages(1).await.unwrap();
    }
    bob.publish_key_packages(1).await.unwrap();
    let room = bob.host_room(&HostOptions::named("r")).await.unwrap();
    bob.invite(&room, ALICE).await.unwrap();
    for device in [&mut a1, &mut a2] {
        let number = poll_until(device, |e| match e {
            Event::InviteArrived { number } => Some(*number),
            _ => None,
        })
        .await;
        device.join(number).unwrap();
    }
    let alice_keys = |bob: &Agent| -> Vec<Option<String>> {
        bob.clients(&room)
            .unwrap()
            .into_iter()
            .filter(|c| c.user == ALICE)
            .map(|c| c.scid)
            .collect()
    };
    assert_eq!(alice_keys(&bob).len(), 2, "both of alice's devices joined");
    let epoch = bob.epoch(&room).unwrap();

    // alice's controller drops a2; a1 cannot commit and proposes instead.
    log.append(
        "2026-11-20T12:00:02Z",
        &Parameters::default(),
        &signer,
        &[key(&a1)],
    )
    .unwrap();
    a1.fail_credential_commits = true;
    let applied = a1
        .use_did_webvh_credential(log.credential().unwrap())
        .await
        .unwrap();
    assert_eq!(applied.proposed, std::slice::from_ref(&room), "{applied:?}");

    // bob commits it, removing a2; the hub accepts it without canKick.
    let changed = poll_until(&mut bob, |e| match e {
        Event::MembersChanged { epoch, .. } => Some(*epoch),
        _ => None,
    })
    .await;
    assert_eq!(changed, epoch + 1);
    assert_eq!(alice_keys(&bob).len(), 1, "a2 was removed");
    poll_until(&mut a1, |e| match e {
        Event::MembersChanged { epoch: e, .. } if *e == epoch + 1 => Some(()),
        _ => None,
    })
    .await;
    assert_eq!(
        a1.epoch_authenticator(&room).unwrap(),
        bob.epoch_authenticator(&room).unwrap()
    );
    poll_until(&mut a2, |e| match e {
        Event::Left { room: left } if *left == room => Some(()),
        _ => None,
    })
    .await;
}
