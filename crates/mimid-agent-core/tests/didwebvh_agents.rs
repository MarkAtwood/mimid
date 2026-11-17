//! draft-atwood-mls-didwebvh-credential-01 through a real mimid server
//! (bead mimid-1wgh.4.81.18): alice has two devices with a `did_webvh`
//! credential, bob a BasicCredential. bob hosts a room on a.example and
//! adds alice; messages flow both ways; alice's controller revokes her
//! second device, her first device's Commit removes it, the hub accepts
//! it, bob sees the change, and the revoked device's next message is
//! refused by the hub.
//!
//! Oracles:
//!
//! - The did:webvh logs come from `mls_didwebvh::controller`, whose output
//!   the mls-didwebvh tests check against an independent did:webvh
//!   verifier. Every expectation about leaves, users and SCIDs follows from
//!   the device keys and the user URI this test puts in those logs.
//! - MLS agreement: after each Commit the members have the same epoch and
//!   epoch authenticator (RFC 9420 §8.7).
//! - Plaintext equality and the frank's signed sender, as in
//!   `two_agents.rs`.
//! - The hub's answers: accepted Commits reach bob; the revoked device's
//!   message is refused (protocol-07 §5.4: its epoch is too old).

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use mimid_agent_core::mls_didwebvh::PublicKey;
use mimid_agent_core::mls_didwebvh::controller::{DidLog, Parameters, UpdateKey};
use mimid_agent_core::{Agent, AgentConfig, AgentError, DidWebvhConfig, Event, HostOptions};
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

const ALICE: &str = "mimi://a.example/u/alice";
const BOB: &str = "mimi://a.example/u/bob";

struct Server {
    base: String,
    tokens: BTreeMap<&'static str, String>,
}

/// a.example's stack as `main.rs` wires it, with the hub enforcing the
/// draft's rules under the suggested code points (the default).
async fn server(dir: &Path, users: &[&'static str]) -> Server {
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
    Server {
        base: base_text,
        tokens,
    }
}

/// An agent for `user` with state in `dir/<name>`. Two devices of one user
/// share the account (and so its Messages) but not their state.
async fn agent(
    server: &Server,
    user: &'static str,
    dir: &Path,
    name: &str,
    did_webvh: DidWebvhConfig,
) -> Agent {
    Agent::open(AgentConfig {
        server_url: server.base.clone(),
        token: server.tokens[user].clone(),
        user_uri: user.to_owned(),
        state_dir: dir.join(name),
        full_tree_hubs: Vec::new(),
        did_webvh,
    })
    .await
    .unwrap()
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

fn assert_agreement(room: &str, a: &Agent, b: &Agent) {
    assert_eq!(a.epoch(room).unwrap(), b.epoch(room).unwrap(), "epoch");
    assert_eq!(
        a.epoch_authenticator(room).unwrap(),
        b.epoch_authenticator(room).unwrap(),
        "epoch authenticator"
    );
}

fn key(agent: &Agent) -> PublicKey {
    agent.signature_public_key().try_into().unwrap()
}

fn time(s: u32) -> String {
    format!("2026-11-20T12:00:{s:02}Z")
}

/// Alice's controller: one update key, her user URI in `alsoKnownAs`.
struct Controller {
    log: DidLog,
    signer: UpdateKey,
}

impl Controller {
    fn create(devices: &[PublicKey]) -> Self {
        let signer = UpdateKey::from_seed(&[0x5a; 32]);
        let log = DidLog::create_also_known_as(
            "a.example",
            "alice",
            &time(1),
            &Parameters {
                update_keys: Some(vec![signer.multikey()]),
                next_key_hashes: None,
            },
            &signer,
            devices,
            &[ALICE.to_owned()],
        )
        .unwrap();
        Self { log, signer }
    }

    fn set_devices(&mut self, n: u32, devices: &[PublicKey]) {
        self.log
            .append(&time(n), &Parameters::default(), &self.signer, devices)
            .unwrap();
    }
}

/// The leaves of `room` as `agent` sees them: (user, SCID), sorted.
fn leaves(agent: &Agent, room: &str) -> Vec<(String, Option<String>)> {
    let mut leaves: Vec<_> = agent
        .clients(room)
        .unwrap()
        .into_iter()
        .map(|c| (c.user, c.scid))
        .collect();
    leaves.sort();
    leaves
}

#[tokio::test]
async fn a_did_webvh_user_with_two_devices_and_a_basic_user_share_a_room_and_revoke() {
    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path(), &[ALICE, BOB]).await;
    let mut a1 = agent(&server, ALICE, dir.path(), "a1", DidWebvhConfig::default()).await;
    let mut a2 = agent(&server, ALICE, dir.path(), "a2", DidWebvhConfig::default()).await;
    let mut bob = agent(&server, BOB, dir.path(), "bob", DidWebvhConfig::default()).await;

    // Alice's controller lists both devices; each takes the credential.
    let mut controller = Controller::create(&[key(&a1), key(&a2)]);
    let scid = controller.log.verified().scid().to_owned();
    a1.use_did_webvh_credential(controller.log.credential().unwrap())
        .await
        .unwrap();
    a2.use_did_webvh_credential(controller.log.credential().unwrap())
        .await
        .unwrap();
    assert_eq!(a1.did_webvh_scid(), Some(scid.as_str()));
    assert_eq!(bob.did_webvh_scid(), None, "bob stays BasicCredential");

    // A log that names another user is not taken.
    let mut stranger = agent(&server, BOB, dir.path(), "bob2", DidWebvhConfig::default()).await;
    let other = Controller::create(&[key(&stranger)]);
    let refused = stranger
        .use_did_webvh_credential(other.log.credential().unwrap())
        .await;
    assert!(
        matches!(refused, Err(AgentError::Invalid(_))),
        "{refused:?}"
    );
    drop(stranger);

    a1.publish_key_packages(2).await.unwrap();
    a2.publish_key_packages(2).await.unwrap();
    bob.publish_key_packages(2).await.unwrap();

    // bob hosts the room and adds alice: KeyMaterial/fetch gives one
    // KeyPackage per device, and the Commit sets the did_webvh record.
    let room = bob.host_room(&HostOptions::named("mixed")).await.unwrap();
    bob.invite(&room, ALICE).await.unwrap();
    assert_eq!(bob.participants(&room).unwrap(), [BOB, ALICE]);
    assert_eq!(bob.pinned_scid(ALICE), Some(scid.as_str()));
    let alice_leaf = (ALICE.to_owned(), Some(scid.clone()));
    let bob_leaf = (BOB.to_owned(), None);
    assert_eq!(
        leaves(&bob, &room),
        [alice_leaf.clone(), alice_leaf.clone(), bob_leaf.clone()]
    );

    for device in [&mut a1, &mut a2] {
        let number = poll_until(device, |e| match e {
            Event::InviteArrived { number } => Some(*number),
            _ => None,
        })
        .await;
        assert_eq!(device.inviter(number).unwrap(), BOB);
        assert_eq!(device.join(number).unwrap(), room);
    }
    assert_agreement(&room, &bob, &a1);
    assert_agreement(&room, &bob, &a2);
    assert_eq!(a1.participants(&room).unwrap(), [BOB, ALICE]);

    // Messages flow both ways; a did_webvh sender is known by its URI.
    let sent = a1.send_text(&room, "hello from a1").await.unwrap();
    let got = poll_until(&mut bob, |e| match e {
        Event::Message(m) => Some(m.clone()),
        _ => None,
    })
    .await;
    assert_eq!(
        (got.sender.as_str(), got.text.as_deref(), got.message_id),
        (ALICE, Some("hello from a1"), sent.message_id)
    );
    let frank = got.frank.expect("the room is franked");
    assert_eq!(frank.context.sender_uri.as_str(), ALICE);
    let sent = bob.send_text(&room, "hi alice").await.unwrap();
    for device in [&mut a1, &mut a2] {
        let got = poll_until(device, |e| match e {
            Event::Message(m) if m.sender == BOB => Some(m.clone()),
            _ => None,
        })
        .await;
        assert_eq!(
            (got.text.as_deref(), got.message_id),
            (Some("hi alice"), sent.message_id)
        );
    }

    // Alice's controller revokes a2. a1 takes the new log; its Commit
    // carries it with the record change and a2's Remove, and the hub
    // accepts it.
    let epoch = bob.epoch(&room).unwrap();
    controller.set_devices(2, &[key(&a1)]);
    a1.use_did_webvh_credential(controller.log.credential().unwrap())
        .await
        .unwrap();
    assert_eq!(a1.epoch(&room).unwrap(), epoch + 1);
    let changed = poll_until(&mut bob, |e| match e {
        Event::MembersChanged { epoch, .. } => Some(*epoch),
        _ => None,
    })
    .await;
    assert_eq!(changed, epoch + 1);
    assert_agreement(&room, &bob, &a1);
    assert_eq!(leaves(&bob, &room), [alice_leaf.clone(), bob_leaf.clone()]);
    assert_eq!(bob.participants(&room).unwrap(), [BOB, ALICE]);

    // a2 has not read the revocation yet and tries to send: the hub
    // refuses it.
    let refused = a2.send_text(&room, "still here?").await;
    assert!(
        matches!(&refused, Err(AgentError::Refused { reason, .. }) if reason == "epochTooOld"),
        "{refused:?}"
    );
    // Once it reads the Commit, a2 knows it is out.
    poll_until(&mut a2, |e| match e {
        Event::Left { room: left } if *left == room => Some(()),
        _ => None,
    })
    .await;

    // The room goes on between a1 and bob.
    let sent = bob.send_text(&room, "bye a2").await.unwrap();
    let got = poll_until(&mut a1, |e| match e {
        Event::Message(m) if m.sender == BOB => Some(m.clone()),
        _ => None,
    })
    .await;
    assert_eq!(got.message_id, sent.message_id);

    // a1 restarts and reloads its did_webvh identity from its state.
    drop(a1);
    let a1 = agent(&server, ALICE, dir.path(), "a1", DidWebvhConfig::default()).await;
    assert_eq!(a1.did_webvh_scid(), Some(scid.as_str()));
    assert_agreement(&room, &bob, &a1);
}

#[tokio::test]
async fn a_device_takes_its_log_from_the_configured_file() {
    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path(), &[ALICE]).await;
    let device = agent(&server, ALICE, dir.path(), "a1", DidWebvhConfig::default()).await;
    let controller = Controller::create(&[key(&device)]);
    drop(device);
    let log_file = dir.path().join("did.jsonl");
    std::fs::write(&log_file, controller.log.did_log()).unwrap();
    let config = DidWebvhConfig {
        log_file: Some(log_file.clone()),
        ..DidWebvhConfig::default()
    };
    let device = agent(&server, ALICE, dir.path(), "a1", config.clone()).await;
    assert_eq!(
        device.did_webvh_scid(),
        Some(controller.log.verified().scid())
    );
    // The same file again is not a change; the agent opens as before.
    drop(device);
    let device = agent(&server, ALICE, dir.path(), "a1", config).await;
    assert_eq!(
        device.did_webvh_scid(),
        Some(controller.log.verified().scid())
    );
}

#[tokio::test]
async fn a_contact_pinned_to_an_scid_cannot_be_added_with_a_basic_credential() {
    // alice once presented a did_webvh credential to bob; later her
    // provider offers a BasicCredential KeyPackage for her. bob refuses to
    // add it (draft §Reference Identifiers; decision mimid-1wgh.4.81.21).
    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path(), &[ALICE, BOB]).await;
    let mut a1 = agent(&server, ALICE, dir.path(), "a1", DidWebvhConfig::default()).await;
    let mut bob = agent(&server, BOB, dir.path(), "bob", DidWebvhConfig::default()).await;
    let controller = Controller::create(&[key(&a1)]);
    a1.use_did_webvh_credential(controller.log.credential().unwrap())
        .await
        .unwrap();
    a1.publish_key_packages(1).await.unwrap();
    bob.publish_key_packages(1).await.unwrap();
    let first = bob.host_room(&HostOptions::named("one")).await.unwrap();
    bob.invite(&first, ALICE).await.unwrap();
    assert!(bob.pinned_scid(ALICE).is_some());

    // A BasicCredential device for alice, as her provider could make.
    let mut basic = agent(
        &server,
        ALICE,
        dir.path(),
        "basic",
        DidWebvhConfig::default(),
    )
    .await;
    basic.publish_key_packages(1).await.unwrap();
    // Only the BasicCredential KeyPackage is left: a1's one was used.
    let second = bob.host_room(&HostOptions::named("two")).await.unwrap();
    let refused = bob.invite(&second, ALICE).await;
    assert!(
        matches!(&refused, Err(AgentError::Invalid(why)) if why.contains("pinned")),
        "{refused:?}"
    );
    assert_eq!(bob.participants(&second).unwrap(), [BOB]);
}
