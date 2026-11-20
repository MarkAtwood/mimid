//! The removal notice (bead mimid-4lp4.4) end to end, through a real hub
//! (bead mimid-vx7s): bob (mimid agent, JMAP) hosts a room on a.example and
//! adds alice's two did:webvh devices and erin's mimid device. erin's
//! second client is a plain OpenMLS client whose leaf lacks the
//! AppDataUpdate proposal type; it joins by external Commit through
//! JMAP's GroupInfo/fetch and Room/update. alice's controller revokes her
//! second device, and her first device's Commit, which changes the
//! did_webvh record, removes that device and erin's plain client
//! (mls-extensions-11 §4.7; decision mimid-1wgh.4.81.37). bob's JMAP Chat
//! then holds exactly one notice naming erin, also when the agent delivers
//! the event again after a crash and a restart, and the hub still lists
//! erin as a participant.
//!
//! The second test puts stock mls-rs (pinned rev, decision
//! mimid-1wgh.4.13) in the plain client's place, with the
//! IdentityProvider an mls-rs application needs for this room
//! (docs/didwebvh-mls-rs.md). mls-rs builds the external Commit from the
//! hub's GroupInfo and tree, the hub accepts it, and mls-rs agrees with
//! bob and alice on the epoch authenticator. The revocation removes it
//! as above, and bob's Chat holds one notice. mls-rs cannot decode the
//! revocation Commit (it has no AppDataUpdate), so it stays in the old
//! epoch and never sees its own removal. Keyed by the BasicCredential
//! identifier alone, as mls-rs's BasicIdentityProvider is, mls-rs refuses
//! to join at all, since erin's mimid device has that identifier too.
//!
//! Why the plain client joins by external Commit: no mimid agent can add
//! it. The agent's KeyMaterial/fetch asks for AppDataUpdate in
//! `required_capabilities` (`mimid-agent-core` `didwebvh.rs`), and each of
//! its Add Commits carries a participant_list AppDataUpdate.
//!
//! Oracles:
//!
//! - The plain client is OpenMLS used directly, with its own capabilities
//!   (no proposal types at all), not mimi-mls; the mls-rs client is
//!   mls-rs, whose verdicts (join refused, Commit undecodable) are its
//!   own, and whose epoch authenticator is compared with the agents'.
//! - The did:webvh log comes from `mls_didwebvh::controller`, whose output
//!   the mls-didwebvh tests check against an independent did:webvh
//!   verifier; which device keys it lists is set by this test.
//! - The hub's own view of the room (`Hub::room_summaries`): its leaves
//!   and its participant_list, read without any agent.
//! - The notice count, read through bob's JMAP Message/query and
//!   Message/get. The replay is a real one: bob's agent state is copied
//!   while the removal event is in its journal and not acknowledged (as
//!   after a crash between storing the notice and acknowledging it), and
//!   put back after the notice is stored; reading that state again
//!   returns the event, and bob's next sync must store nothing more.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jmap_server::{Dispatcher, Id, JmapRequest, State};
use mimi_mls::label::{HpkePrivateKey, SignatureKeyPair as RequestKey};
use mimi_mls::tls_codec::{Deserialize, Serialize, VLBytes};
use mimi_mls::wire::{
    CipherSuite, Credential, GroupInfo, HPKEPublicKey, MLSMessage, RatchetTreeOption,
    SignaturePublicKey,
};
use mimi_protocol::{
    FanoutEvent, FanoutMessage, GroupInfoOption, GroupInfoRequestTbs, GroupInfoResponse,
    HandshakeBundle, Protocol, UpdateRequest,
};
use mimid_agent_core::mls_didwebvh::controller::{DidLog, Parameters, UpdateKey};
use mimid_agent_core::mls_didwebvh::{CodePoints, PublicKey};
use mimid_agent_core::{Agent, AgentConfig, DidWebvhConfig, Event, HostOptions};
use mimid_agent_jmap::{AgentChat, InvitePolicy, Options};
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
use openmls::extensions::{AppDataDictionary, AppDataDictionaryExtension};
use openmls::prelude::{
    Capabilities, Ciphersuite, CredentialType, CredentialWithKey, Extension, ExtensionType,
    Extensions, LeafNodeParameters, MIXED_PLAINTEXT_WIRE_FORMAT_POLICY, MlsGroup,
    MlsGroupJoinConfig, MlsMessageBodyIn, MlsMessageIn, OpenMlsProvider, ProposalType,
    RatchetTreeIn,
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use serde_json::{Value, json};

const ALICE: &str = "mimi://a.example/u/alice";
const BOB: &str = "mimi://a.example/u/bob";
const ERIN: &str = "mimi://a.example/u/erin";

/// RFC 9420 §6: the MLSMessage header of a GroupInfo (mls10, 0x0004).
const GROUP_INFO_HEADER: [u8; 4] = [0x00, 0x01, 0x00, 0x04];
/// mls-extensions-11 §7.5: the `app_components` and `safe_aad` component
/// IDs.
const APP_COMPONENTS: u16 = 0x0001;
const SAFE_AAD: u16 = 0x0002;
/// mls-extensions-11 §4.9: a SafeAAD with no `aad_items`, a zero-length
/// `SafeAADItem aad_items<V>`.
const EMPTY_SAFE_AAD: [u8; 1] = [0x00];
const SUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

struct Server {
    base: String,
    tokens: BTreeMap<&'static str, String>,
    hub: Arc<Hub>,
}

/// a.example's stack as `main.rs` wires it, with the hub enforcing the
/// did:webvh rules under the suggested code points (the default).
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
    let app = router(directory(&base), Arc::clone(&hub), follower).merge(jmap);
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    Server {
        base: base_text,
        tokens,
        hub,
    }
}

async fn agent(server: &Server, user: &'static str, dir: &Path, name: &str) -> Agent {
    Agent::open(AgentConfig {
        server_url: server.base.clone(),
        binding: mimid_agent_core::Binding::Jmap,
        token: server.tokens[user].clone(),
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

fn time(s: u32) -> String {
    format!("2026-11-20T12:00:{s:02}Z")
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

/// Polls `agent` until it is at `epoch` in `room`.
async fn poll_to_epoch(agent: &mut Agent, room: &str, epoch: u64) {
    for _ in 0..100 {
        if agent.epoch(room).unwrap() == epoch {
            return;
        }
        for event in agent.poll().await.unwrap() {
            if let Event::Problem { room, description } = &event {
                panic!("{}: problem in {room:?}: {description}", agent.user());
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("{}: never reached epoch {epoch}", agent.user());
}

/// bob's JMAP account over his agent, with the agent's state and its
/// plaintext store in the agent's database in `dir/bob`.
struct Bob {
    chat: Arc<AgentChat>,
    dispatcher: Dispatcher<()>,
}

impl Bob {
    async fn open(server: &Server, dir: &Path) -> Self {
        let agent = agent(server, BOB, dir, "bob").await;
        let chat = AgentChat::new(
            agent,
            Id::from("bob"),
            Options::default().with_invites(InvitePolicy::Any),
        )
        .persisted()
        .unwrap();
        let chat = Arc::new(chat);
        let mut dispatcher = Dispatcher::new();
        AgentChat::register(&chat, &mut dispatcher);
        Self { chat, dispatcher }
    }

    async fn call(&self, method: &str, mut args: Value) -> Value {
        args["accountId"] = json!(self.chat.account_id().as_ref());
        let request: JmapRequest = serde_json::from_value(json!({
            "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:chat"],
            "methodCalls": [[method, args, "c0"]],
        }))
        .unwrap();
        let response = self
            .dispatcher
            .dispatch(request, (), State::from("0"))
            .await;
        let response = serde_json::to_value(response).unwrap();
        assert_eq!(response["methodResponses"][0][0], method, "{response}");
        response["methodResponses"][0][1].clone()
    }

    /// The Messages in the Chat of `room`.
    async fn messages(&self, room: &str) -> Vec<Value> {
        let chat = self.chat.chat_of_room(room).unwrap();
        let ids = self
            .call(
                "Message/query",
                json!({"filter": {"chatId": chat.as_ref()}}),
            )
            .await["ids"]
            .clone();
        self.call("Message/get", json!({"ids": ids})).await["list"]
            .as_array()
            .unwrap()
            .clone()
    }

    async fn sync(&self) {
        let report = self.chat.sync().await.unwrap();
        assert!(report.problems.is_empty(), "{report:?}");
    }

    /// Syncs until bob's agent is at `epoch` in `room`.
    async fn sync_to_epoch(&self, room: &str, epoch: u64) {
        for _ in 0..100 {
            self.sync().await;
            if self.chat.agent().lock().await.epoch(room).unwrap() == epoch {
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("bob never reached epoch {epoch}");
    }
}

/// A JMAP Chat MIMI account, called over HTTP as any client would.
struct Jmap {
    http: reqwest::Client,
    api: String,
    token: String,
    account: String,
}

impl Jmap {
    async fn open(server: &Server, user: &str) -> Self {
        let http = reqwest::Client::new();
        let token = server.tokens[user].clone();
        let session = http
            .get(format!("{}/.well-known/jmap", server.base))
            .bearer_auth(&token)
            .send()
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap();
        let session: Value = serde_json::from_slice(&session).unwrap();
        let account = session["primaryAccounts"]["urn:ietf:params:jmap:chat:mimi"]
            .as_str()
            .unwrap()
            .to_owned();
        let api = session["apiUrl"].as_str().unwrap().to_owned();
        Self {
            http,
            api,
            token,
            account,
        }
    }

    async fn call(&self, method: &str, mut args: Value) -> Value {
        args["accountId"] = json!(self.account);
        let body = json!({
            "using": [
                "urn:ietf:params:jmap:core",
                "urn:ietf:params:jmap:chat",
                "urn:ietf:params:jmap:chat:mimi",
            ],
            "methodCalls": [[method, args, "c"]],
        });
        let response = self
            .http
            .post(&self.api)
            .bearer_auth(&self.token)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body.to_string())
            .send()
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap();
        let response: Value = serde_json::from_slice(&response).unwrap();
        assert_eq!(response["methodResponses"][0][0], method, "{response}");
        response["methodResponses"][0][1].clone()
    }
}

/// `opaque<V>` (RFC 9420 §2.1.2).
fn vl(bytes: &[u8]) -> Vec<u8> {
    VLBytes::new(bytes.to_vec())
        .tls_serialize_detached()
        .unwrap()
}

/// erin's second client: OpenMLS used directly, with a BasicCredential
/// for erin and capabilities that list no proposal type, so not
/// AppDataUpdate (mls-extensions-11 §7.2.1), as stock mls-rs does not.
struct PlainClient {
    provider: OpenMlsRustCrypto,
    signer: SignatureKeyPair,
}

impl PlainClient {
    fn new() -> Self {
        Self {
            provider: OpenMlsRustCrypto::default(),
            signer: SignatureKeyPair::new(SUITE.signature_algorithm()).unwrap(),
        }
    }

    /// The leaf's capabilities: suite 1, BasicCredential and the did_webvh
    /// credential type the room's other leaves use (RFC 9420 §7.2), the
    /// `app_data_dictionary` extension, and no proposal type.
    fn capabilities() -> Capabilities {
        let capabilities = Capabilities::builder()
            .ciphersuites(vec![SUITE])
            .credentials(vec![
                CredentialType::Basic,
                CredentialType::Other(CodePoints::DEFAULT.credential_type()),
            ])
            .extensions(vec![ExtensionType::AppDataDictionary])
            .proposals(vec![])
            .build();
        assert!(
            !capabilities
                .proposals()
                .contains(&ProposalType::AppDataUpdate)
        );
        capabilities
    }

    /// Joins `room` by external Commit: GroupInfo/fetch (protocol-07 §5.6)
    /// and Room/update, both through erin's JMAP account. Its leaf lists
    /// the components the room's GroupContext requires (mls-extensions-11
    /// §5), copied from the GroupInfo. Returns the hub's `responseCode`.
    async fn join(&self, jmap: &Jmap, room: &str) -> Value {
        let (group_info, tree) = fetch_group_info(jmap, room).await;
        let MlsMessageBodyIn::GroupInfo(group_info) =
            MlsMessageIn::tls_deserialize_exact(&group_info[..])
                .unwrap()
                .extract()
        else {
            panic!("not a GroupInfo");
        };

        // The leaf lists what the GroupContext's app_components and
        // safe_aad name.
        let room_dictionary = group_info
            .group_context()
            .extensions()
            .app_data_dictionary()
            .unwrap()
            .dictionary();
        let mut dictionary = AppDataDictionary::new();
        for id in [APP_COMPONENTS, SAFE_AAD] {
            dictionary.insert(id, room_dictionary.get(&id).unwrap().to_vec());
        }
        let leaf = LeafNodeParameters::builder()
            .with_capabilities(Self::capabilities())
            .with_extensions(
                Extensions::single(Extension::AppDataDictionary(
                    AppDataDictionaryExtension::new(dictionary),
                ))
                .unwrap(),
            )
            .build();

        let mut builder = MlsGroup::external_commit_builder()
            .with_config(
                MlsGroupJoinConfig::builder()
                    .wire_format_policy(MIXED_PLAINTEXT_WIRE_FORMAT_POLICY)
                    .build(),
            )
            // As mimi-mls does (RFC 9420 §7.3; decision mimid-1wgh.4.56).
            .skip_lifetime_validation();
        if let Some(tree) = tree {
            builder =
                builder.with_ratchet_tree(RatchetTreeIn::tls_deserialize_exact(&tree[..]).unwrap());
        }
        let (_group, bundle) = builder
            .build_group(
                &self.provider,
                group_info,
                CredentialWithKey {
                    credential: openmls::prelude::BasicCredential::new(ERIN.as_bytes().to_vec())
                        .into(),
                    signature_key: self.signer.to_public_vec().into(),
                },
            )
            .unwrap()
            .leaf_node_parameters(leaf)
            .load_psks(self.provider.storage())
            .unwrap()
            .create_group_info(true)
            .build(
                self.provider.rand(),
                self.provider.crypto(),
                &self.signer,
                |_| true,
            )
            .unwrap()
            .finalize(&self.provider)
            .unwrap();
        let (commit, _, group_info) = bundle.into_messages();
        submit_external_commit(
            jmap,
            room,
            &commit.tls_serialize_detached().unwrap(),
            &group_info.unwrap().tls_serialize_detached().unwrap(),
        )
        .await
    }
}

/// GroupInfo/fetch (protocol-07 §5.6) for `room` through erin's JMAP
/// account, with a GroupInfoRequest signed by a key of its own. Returns
/// the GroupInfo as an MLSMessage and the ratchet tree, if the hub sent
/// one.
async fn fetch_group_info(jmap: &Jmap, room: &str) -> (Vec<u8>, Option<Vec<u8>>) {
    let (hpke_key, hpke_public) = HpkePrivateKey::generate().unwrap();
    let request_key = RequestKey::generate().unwrap();
    let credential = [&[0x00, 0x01][..], &vl(ERIN.as_bytes())].concat();
    let request = GroupInfoRequestTbs {
        protocol: Protocol::Mls10,
        cipher_suite: CipherSuite::from(0x0001),
        requesting_signature_key: SignaturePublicKey::tls_deserialize_exact(vl(
            request_key.verification_key()
        ))
        .unwrap(),
        requesting_credential: Credential::tls_deserialize_exact(credential).unwrap(),
        group_info_public_key: HPKEPublicKey::tls_deserialize_exact(vl(&hpke_public)).unwrap(),
        joining_code: None,
    }
    .sign(&request_key)
    .unwrap()
    .tls_serialize_detached()
    .unwrap();
    let answer = jmap
        .call(
            "GroupInfo/fetch",
            json!({"roomId": room, "request": URL_SAFE_NO_PAD.encode(request)}),
        )
        .await;
    let response = URL_SAFE_NO_PAD
        .decode(answer["response"].as_str().unwrap())
        .unwrap();
    let GroupInfoResponse::Success(success) =
        GroupInfoResponse::tls_deserialize_exact(&response[..]).unwrap()
    else {
        panic!("GroupInfo/fetch refused: {answer}");
    };
    success.verify().unwrap();
    let tbe = mimi_protocol::decrypt_group_info(
        &hpke_key,
        room.as_bytes(),
        &success.tbs().encrypted_groupinfo_and_tree,
    )
    .unwrap();
    assert!(tbe.pending_proposals.is_empty());
    let group_info = [
        GROUP_INFO_HEADER.as_slice(),
        &tbe.group_info.tls_serialize_detached().unwrap(),
    ]
    .concat();
    let tree = tbe.ratchet_tree_option.ratchet_tree().map(<[u8]>::to_vec);
    (group_info, tree)
}

/// Room/update through erin's JMAP account with an external `commit` and
/// the joiner's `group_info`, both MLSMessages. Returns the hub's
/// `responseCode`.
async fn submit_external_commit(
    jmap: &Jmap,
    room: &str,
    commit: &[u8],
    group_info: &[u8],
) -> Value {
    let request = UpdateRequest {
        bundle: HandshakeBundle::Commit {
            proposal_or_commit: MLSMessage::tls_deserialize_exact(commit).unwrap(),
            welcome: None,
            group_info_option: GroupInfoOption::Full {
                group_info: GroupInfo::tls_deserialize_exact(
                    group_info.strip_prefix(&GROUP_INFO_HEADER).unwrap(),
                )
                .unwrap(),
            },
            ratchet_tree_option: RatchetTreeOption::distribution_service(),
        },
    };
    let answer = jmap
        .call(
            "Room/update",
            json!({
                "roomId": room,
                "request": URL_SAFE_NO_PAD.encode(request.tls_serialize_detached().unwrap()),
            }),
        )
        .await;
    answer["responseCode"].clone()
}

/// How many of the hub's leaves in `room` are erin's BasicCredential
/// clients, and whether its participant_list names erin.
async fn hub_view(hub: &Hub, room: &str) -> (usize, bool) {
    let summary = hub.room_summaries(Some(room)).await.pop().unwrap();
    let leaves = summary
        .members
        .iter()
        .filter(|(_, identity)| identity == ERIN.as_bytes())
        .count();
    let listed = summary
        .participants
        .unwrap()
        .iter()
        .any(|(user, _)| user == ERIN.as_bytes());
    (leaves, listed)
}

/// Copies directory `from` to `to`, which must not exist, with its modes
/// (the agent refuses a state directory others can read).
fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir(to).unwrap();
    std::fs::set_permissions(to, std::fs::metadata(from).unwrap().permissions()).unwrap();
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_dir(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), target).unwrap();
        }
    }
}

/// The RemovedWithoutAppDataUpdate events among `events`.
fn removals(events: &[Event]) -> Vec<(String, String, u64)> {
    events
        .iter()
        .filter_map(|event| match event {
            Event::RemovedWithoutAppDataUpdate { room, user, epoch } => {
                Some((room.clone(), user.clone(), *epoch))
            }
            _ => None,
        })
        .collect()
}

/// a.example with alice's two devices under one controller (a1, a2),
/// erin's mimid device, and bob, whose room they have all joined.
struct Hosted {
    server: Server,
    a1: Agent,
    bob: Bob,
    room: String,
    log: DidLog,
    signer: UpdateKey,
}

async fn hosted(dir: &Path) -> Hosted {
    let server = server(dir, &[ALICE, BOB, ERIN]).await;

    // alice's two devices under one controller.
    let mut a1 = agent(&server, ALICE, dir, "a1").await;
    let mut a2 = agent(&server, ALICE, dir, "a2").await;
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
    let mut e1 = agent(&server, ERIN, dir, "e1").await;
    e1.publish_key_packages(1).await.unwrap();

    // bob hosts the room and adds alice (one KeyPackage per device; the
    // Commit sets the did_webvh record) and erin's mimid device.
    let bob = Bob::open(&server, dir).await;
    let room = {
        let mut agent = bob.chat.agent().lock().await;
        agent.publish_key_packages(1).await.unwrap();
        let room = agent
            .host_room(&HostOptions::named("notice"))
            .await
            .unwrap();
        agent.invite(&room, ALICE).await.unwrap();
        agent.invite(&room, ERIN).await.unwrap();
        room
    };
    bob.sync().await;
    for device in [&mut a1, &mut a2, &mut e1] {
        let number = poll_until(device, |e| match e {
            Event::InviteArrived { number } => Some(*number),
            _ => None,
        })
        .await;
        assert_eq!(device.join(number).unwrap(), room);
    }
    assert_eq!(hub_view(&server.hub, &room).await, (1, true));
    Hosted {
        server,
        a1,
        bob,
        room,
        log,
        signer,
    }
}

/// How many of `agent`'s clients in `room` are erin's.
fn erin_clients(agent: &Agent, room: &str) -> usize {
    agent
        .clients(room)
        .unwrap()
        .into_iter()
        .filter(|c| c.user == ERIN)
        .count()
}

#[tokio::test]
async fn a_revocation_that_removes_a_client_without_app_data_update_posts_one_notice() {
    let dir = tempfile::tempdir().unwrap();
    let Hosted {
        server,
        mut a1,
        bob,
        room,
        mut log,
        signer,
    } = hosted(dir.path()).await;

    // erin's plain client joins by external Commit; the hub accepts it.
    let epoch = server.hub.public_state(&room).await.unwrap().epoch;
    let erin_jmap = Jmap::open(&server, ERIN).await;
    let plain = PlainClient::new();
    assert_eq!(plain.join(&erin_jmap, &room).await, "success");
    assert_eq!(
        server.hub.public_state(&room).await.unwrap().epoch,
        epoch + 1
    );
    assert_eq!(hub_view(&server.hub, &room).await, (2, true));
    // The mimid agents take the external Commit.
    bob.sync_to_epoch(&room, epoch + 1).await;
    assert_eq!(erin_clients(&*bob.chat.agent().lock().await, &room), 2);
    poll_to_epoch(&mut a1, &room, epoch + 1).await;
    assert!(
        bob.messages(&room).await.is_empty(),
        "no notice before the revocation"
    );
    // bob's agent stops here; it reads the revocation below.
    drop(bob);

    // alice's controller revokes a2. a1's Commit changes the record and
    // removes a2 (the rules) and erin's plain client (no AppDataUpdate).
    log.append(&time(2), &Parameters::default(), &signer, &[key(&a1)])
        .unwrap();
    let a1_events = {
        a1.use_did_webvh_credential(log.credential().unwrap())
            .await
            .unwrap();
        a1.poll().await.unwrap()
    };
    let revoked = epoch + 2;
    assert_eq!(a1.epoch(&room).unwrap(), revoked);
    assert_eq!(server.hub.public_state(&room).await.unwrap().epoch, revoked);
    // The hub dropped the client, not the user.
    assert_eq!(hub_view(&server.hub, &room).await, (1, true));
    // The committer is told too.
    assert_eq!(
        removals(&a1_events),
        [(room.clone(), ERIN.to_owned(), revoked)]
    );

    // bob's agent reads the Commit and journals the event, and "crashes"
    // before anything acknowledges it: its state is kept as it is then.
    let found = {
        let mut agent = agent(&server, BOB, dir.path(), "bob").await;
        let mut found = Vec::new();
        for _ in 0..100 {
            let (events, _receipt) = agent.receive().await.unwrap();
            found = removals(&events);
            if !found.is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert_eq!(erin_clients(&agent, &room), 1);
        found
    };
    assert_eq!(found, [(room.clone(), ERIN.to_owned(), revoked)]);
    copy_dir(&dir.path().join("bob"), &dir.path().join("bob-crashed"));

    // bob's agent and JMAP account start again and store the notice.
    let bob = Bob::open(&server, dir.path()).await;
    bob.sync().await;
    let notice = |messages: &[Value]| {
        assert_eq!(messages.len(), 1, "{messages:?}");
        let notice = &messages[0];
        assert_eq!(notice["senderId"], "bob", "from the account");
        assert_eq!(notice["bodyType"], "text/plain");
        let body = notice["body"].as_str().unwrap().to_owned();
        assert!(body.contains(ERIN), "{body}");
        assert!(body.contains("removed"), "{body}");
        assert!(body.contains("AppDataUpdate"), "{body}");
        assert!(!body.contains(ALICE), "{body}");
        body
    };
    let body = notice(&bob.messages(&room).await);
    // A later sync stores nothing more.
    bob.sync().await;
    assert_eq!(notice(&bob.messages(&room).await), body);
    drop(bob);

    // The crash came after the notice was stored and before the event was
    // acknowledged: the agent's state goes back to the copy, so the event
    // comes again.
    std::fs::remove_dir_all(dir.path().join("bob")).unwrap();
    std::fs::rename(dir.path().join("bob-crashed"), dir.path().join("bob")).unwrap();
    {
        let mut agent = agent(&server, BOB, dir.path(), "bob").await;
        let (events, _receipt) = agent.receive().await.unwrap();
        assert_eq!(
            removals(&events),
            [(room.clone(), ERIN.to_owned(), revoked)]
        );
    }
    let bob = Bob::open(&server, dir.path()).await;
    bob.sync().await;
    assert_eq!(notice(&bob.messages(&room).await), body, "still one notice");
    assert_eq!(bob.chat.agent().lock().await.epoch(&room).unwrap(), revoked);
    assert_eq!(hub_view(&server.hub, &room).await, (1, true));
}

// ---- erin's mls-rs client ----

/// erin's second client as stock mls-rs at the pinned rev (decision
/// mimid-1wgh.4.13), with what an mls-rs application needs to share a
/// `did_webvh` room (docs/didwebvh-mls-rs.md): an `IdentityProvider` for
/// credential type 0x0008 and `app_data_dictionary` (0x0006) accepted as
/// an extension type. mls-rs has no AppDataUpdate, so its leaf lists no
/// proposal type beyond the RFC 9420 defaults.
mod erin_mls_rs {
    use mimid_agent_core::mls_didwebvh::{CodePoints, DidWebvhCredential, verify_credential};
    use mls_rs::client_builder::MlsConfig;
    use mls_rs::error::IntoAnyError;
    use mls_rs::extension::ExtensionType;
    use mls_rs::identity::basic::BasicCredential;
    use mls_rs::identity::{Credential, CredentialType, SigningIdentity};
    use mls_rs::time::MlsTime;
    use mls_rs::{CipherSuite, CipherSuiteProvider, Client, CryptoProvider, ExtensionList};
    use mls_rs_crypto_rustcrypto::RustCryptoProvider;

    /// mls-extensions-11 §7.1.1: the app_data_dictionary extension type.
    pub const APP_DATA_DICTIONARY: ExtensionType = ExtensionType::new(0x0006);

    /// Why the provider refuses a credential.
    #[derive(Debug)]
    pub struct Refused(String);

    impl std::fmt::Display for Refused {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str(&self.0)
        }
    }

    impl std::error::Error for Refused {}

    impl IntoAnyError for Refused {
        fn into_dyn_error(self) -> Result<Box<dyn std::error::Error + Send + Sync>, Self> {
            Ok(self.into())
        }
    }

    /// BasicCredential as mls-rs's `BasicIdentityProvider` checks it, and
    /// the `did_webvh` credential with its log verified and the leaf's
    /// `signature_key` authorized by the head (§Log Verification, §Binding
    /// to the LeafNode), as in `crates/mimi-mls/tests/didwebvh_mls_rs.rs`.
    ///
    /// mls-rs indexes leaves by `identity()` and refuses two leaves with
    /// one identity (`DuplicateLeafData`). A `did_webvh` leaf's identity is
    /// its SCID plus its signature key. A BasicCredential leaf's is its
    /// identifier, plus its signature key with `per_leaf`: erin's mimid
    /// device and this client both carry the BasicCredential
    /// `mimi://a.example/u/erin`, and mimid lets one user have several
    /// clients.
    #[derive(Clone, Copy, Debug)]
    pub struct Identities {
        pub per_leaf: bool,
    }

    impl Identities {
        fn did_webvh_scid(signing_identity: &SigningIdentity) -> Result<String, Refused> {
            let Credential::Custom(custom) = &signing_identity.credential else {
                return Err(Refused("not a custom credential".into()));
            };
            if custom.credential_type.raw_value() != CodePoints::DEFAULT.credential_type() {
                return Err(Refused(format!(
                    "credential type {:#06x}",
                    custom.credential_type.raw_value()
                )));
            }
            let credential = DidWebvhCredential::decode(&custom.data)
                .map_err(|e| Refused(format!("DIDWebVHCredential: {e}")))?;
            let log = verify_credential(&credential).map_err(|e| Refused(format!("log: {e}")))?;
            if !log.authorizes(signing_identity.signature_key.as_bytes()) {
                return Err(Refused("signature_key not authorized by the head".into()));
            }
            Ok(log.scid().to_owned())
        }
    }

    impl mls_rs::IdentityProvider for Identities {
        type Error = Refused;

        fn validate_member(
            &self,
            signing_identity: &SigningIdentity,
            _timestamp: Option<MlsTime>,
            _context: mls_rs_core::identity::MemberValidationContext<'_>,
        ) -> Result<(), Self::Error> {
            match &signing_identity.credential {
                Credential::Basic(_) => Ok(()),
                _ => Self::did_webvh_scid(signing_identity).map(|_| ()),
            }
        }

        fn validate_external_sender(
            &self,
            signing_identity: &SigningIdentity,
            _timestamp: Option<MlsTime>,
            _extensions: Option<&ExtensionList>,
        ) -> Result<(), Self::Error> {
            // §Binding to the LeafNode: no did_webvh external sender.
            match &signing_identity.credential {
                Credential::Basic(_) => Ok(()),
                _ => Err(Refused("external sender must be basic".into())),
            }
        }

        fn identity(
            &self,
            signing_identity: &SigningIdentity,
            _extensions: &ExtensionList,
        ) -> Result<Vec<u8>, Self::Error> {
            let mut id = match &signing_identity.credential {
                Credential::Basic(basic) => {
                    let mut id = b"basic:".to_vec();
                    id.extend_from_slice(&basic.identifier);
                    if !self.per_leaf {
                        return Ok(id);
                    }
                    id
                }
                _ => {
                    let mut id = b"did_webvh:".to_vec();
                    id.extend_from_slice(Self::did_webvh_scid(signing_identity)?.as_bytes());
                    id
                }
            };
            id.push(b'/');
            id.extend_from_slice(signing_identity.signature_key.as_bytes());
            Ok(id)
        }

        fn valid_successor(
            &self,
            predecessor: &SigningIdentity,
            successor: &SigningIdentity,
            extensions: &ExtensionList,
        ) -> Result<bool, Self::Error> {
            Ok(self.identity(predecessor, extensions)? == self.identity(successor, extensions)?)
        }

        fn supported_types(&self) -> Vec<CredentialType> {
            vec![
                CredentialType::BASIC,
                CredentialType::new(CodePoints::DEFAULT.credential_type()),
            ]
        }
    }

    /// An mls-rs client for erin with a BasicCredential, suite 1 and the
    /// provider above.
    pub fn client(identities: Identities) -> Client<impl MlsConfig + use<>> {
        let crypto = RustCryptoProvider::default();
        let suite = crypto
            .cipher_suite_provider(CipherSuite::CURVE25519_AES128)
            .unwrap();
        let (secret, public) = suite.signature_key_generate().unwrap();
        let signing_identity = SigningIdentity::new(
            BasicCredential::new(super::ERIN.as_bytes().to_vec()).into_credential(),
            public,
        );
        Client::builder()
            .identity_provider(identities)
            .crypto_provider(crypto)
            .extension_type(APP_DATA_DICTIONARY)
            .signing_identity(signing_identity, secret, CipherSuite::CURVE25519_AES128)
            .build()
    }
}

/// The `app_components` and `safe_aad` entries of the GroupContext's
/// `app_data_dictionary` in `group_info` (an MLSMessage), which a joiner's
/// leaf must list (mls-extensions-11 §5). Read with OpenMLS.
fn required_components(group_info: &[u8]) -> Vec<(u16, Vec<u8>)> {
    let MlsMessageBodyIn::GroupInfo(group_info) = MlsMessageIn::tls_deserialize_exact(group_info)
        .unwrap()
        .extract()
    else {
        panic!("not a GroupInfo");
    };
    let dictionary = group_info
        .group_context()
        .extensions()
        .app_data_dictionary()
        .unwrap()
        .dictionary();
    [APP_COMPONENTS, SAFE_AAD]
        .into_iter()
        .map(|id| (id, dictionary.get(&id).unwrap().to_vec()))
        .collect()
}

/// An AppDataDictionary (mls-extensions-11 §4.6), encoded here:
/// `ComponentData component_data<V>`, each a `uint16 component_id` and
/// `opaque data<V>`, in increasing component_id order.
fn encode_dictionary(entries: &[(u16, Vec<u8>)]) -> Vec<u8> {
    let mut components = Vec::new();
    for (id, data) in entries {
        components.extend_from_slice(&id.to_be_bytes());
        components.extend_from_slice(&vl(data));
    }
    vl(&components)
}

/// Every stored Message of erin's MIMI account, as (id, body).
async fn stored_messages(jmap: &Jmap) -> Vec<(String, Vec<u8>)> {
    let answer = jmap
        .call(
            "Message/get",
            json!({"ids": Value::Null, "properties": ["body"]}),
        )
        .await;
    answer["list"]
        .as_array()
        .unwrap()
        .iter()
        .map(|message| {
            (
                message["id"].as_str().unwrap().to_owned(),
                URL_SAFE_NO_PAD
                    .decode(message["body"].as_str().unwrap())
                    .unwrap(),
            )
        })
        .collect()
}

/// The Commits (MLSMessages) of the FanoutMessages stored in erin's
/// account whose ids are not in `seen`; adds their ids to `seen`.
async fn new_commits(jmap: &Jmap, seen: &mut Vec<String>) -> Vec<Vec<u8>> {
    let mut commits = Vec::new();
    for (id, body) in stored_messages(jmap).await {
        if seen.contains(&id) {
            continue;
        }
        seen.push(id);
        for fanout in FanoutMessage::decode_all(&body).unwrap() {
            if let FanoutEvent::Commit { message, .. } = fanout.event {
                commits.push(message.tls_serialize_detached().unwrap());
            }
        }
    }
    commits
}

#[tokio::test]
async fn a_revocation_removes_an_mls_rs_client_through_a_hub_and_posts_one_notice() {
    let dir = tempfile::tempdir().unwrap();
    let Hosted {
        server,
        mut a1,
        bob,
        room,
        mut log,
        signer,
    } = hosted(dir.path()).await;
    let epoch = server.hub.public_state(&room).await.unwrap().epoch;
    let erin_jmap = Jmap::open(&server, ERIN).await;
    let mut seen: Vec<String> = stored_messages(&erin_jmap)
        .await
        .into_iter()
        .map(|(id, _)| id)
        .collect();

    // mls-rs reads the GroupInfo and tree from the hub. Its leaf lists
    // the components the GroupContext requires.
    let (group_info, tree) = fetch_group_info(&erin_jmap, &room).await;
    let mut leaf = mls_rs::ExtensionList::new();
    leaf.set(mls_rs::Extension::new(
        erin_mls_rs::APP_DATA_DICTIONARY,
        encode_dictionary(&required_components(&group_info)),
    ));
    let external_commit = |client: &mls_rs::Client<_>| {
        let mut builder = client
            .external_commit_builder()
            .unwrap()
            .with_leaf_node_extensions(leaf.clone())
            // The GroupContext lists safe_aad, so authenticated_data must
            // be a SafeAAD (mls-extensions-11 §4.9); mls-rs leaves it
            // empty, which the hub refuses.
            .with_authenticated_data(EMPTY_SAFE_AAD.to_vec());
        if let Some(tree) = &tree {
            builder =
                builder.with_tree_data(mls_rs::group::ExportedTree::from_bytes(tree).unwrap());
        }
        builder.build(mls_rs::MlsMessage::from_bytes(&group_info).unwrap())
    };

    // Keyed by the BasicCredential identifier alone, as mls-rs's
    // BasicIdentityProvider is, mls-rs refuses to join: erin's mimid
    // device already has that identity.
    let by_identifier = erin_mls_rs::client(erin_mls_rs::Identities { per_leaf: false });
    let result = external_commit(&by_identifier);
    assert!(
        matches!(result, Err(mls_rs::error::MlsError::DuplicateLeafData(_))),
        "{:?}",
        result.err()
    );

    // Keyed per leaf, mls-rs builds the external Commit and the hub
    // accepts it.
    let client = erin_mls_rs::client(erin_mls_rs::Identities { per_leaf: true });
    let (group, commit) = external_commit(&client).unwrap();
    let commit = commit.to_bytes().unwrap();
    let joiner_group_info = group
        .group_info_message_allowing_ext_commit(false)
        .unwrap()
        .to_bytes()
        .unwrap();
    assert_eq!(
        submit_external_commit(&erin_jmap, &room, &commit, &joiner_group_info).await,
        "success"
    );
    assert_eq!(group.current_epoch(), epoch + 1);
    assert_eq!(
        server.hub.public_state(&room).await.unwrap().epoch,
        epoch + 1
    );
    assert_eq!(hub_view(&server.hub, &room).await, (2, true));
    // The mimid agents take the external Commit and agree with mls-rs.
    bob.sync_to_epoch(&room, epoch + 1).await;
    {
        let agent = bob.chat.agent().lock().await;
        assert_eq!(erin_clients(&agent, &room), 2);
        assert_eq!(
            agent.epoch_authenticator(&room).unwrap(),
            group.epoch_authenticator().unwrap().as_bytes(),
            "bob and mls-rs disagree"
        );
    }
    poll_to_epoch(&mut a1, &room, epoch + 1).await;
    assert_eq!(
        a1.epoch_authenticator(&room).unwrap(),
        group.epoch_authenticator().unwrap().as_bytes(),
        "a1 and mls-rs disagree"
    );
    assert!(
        bob.messages(&room).await.is_empty(),
        "no notice before the revocation"
    );

    // alice's controller revokes a2. a1's Commit changes the record and
    // removes a2 (the rules) and the mls-rs client (no AppDataUpdate).
    log.append(&time(2), &Parameters::default(), &signer, &[key(&a1)])
        .unwrap();
    a1.use_did_webvh_credential(log.credential().unwrap())
        .await
        .unwrap();
    let a1_events = a1.poll().await.unwrap();
    let revoked = epoch + 2;
    assert_eq!(a1.epoch(&room).unwrap(), revoked);
    assert_eq!(server.hub.public_state(&room).await.unwrap().epoch, revoked);
    // The hub dropped the client, not the user.
    assert_eq!(hub_view(&server.hub, &room).await, (1, true));
    assert_eq!(
        removals(&a1_events),
        [(room.clone(), ERIN.to_owned(), revoked)]
    );

    // bob's JMAP Chat holds exactly one notice naming erin.
    bob.sync_to_epoch(&room, revoked).await;
    assert_eq!(erin_clients(&*bob.chat.agent().lock().await, &room), 1);
    let notice = |messages: &[Value]| {
        assert_eq!(messages.len(), 1, "{messages:?}");
        let body = messages[0]["body"].as_str().unwrap().to_owned();
        assert_eq!(messages[0]["senderId"], "bob", "from the account");
        assert!(body.contains(ERIN), "{body}");
        assert!(body.contains("removed"), "{body}");
        assert!(body.contains("AppDataUpdate"), "{body}");
        body
    };
    let body = notice(&bob.messages(&room).await);
    bob.sync().await;
    assert_eq!(notice(&bob.messages(&room).await), body, "still one notice");

    // The mls-rs client gets the Commit through erin's account (besides
    // its own external Commit) and cannot decode it: mls-rs reads the
    // AppDataUpdate, a proposal type it does not know, as one opaque<V>,
    // and the component ID 0xF013's first byte has the varint prefix
    // RFC 9420 §2.1.2 reserves. It stays in the old epoch and never sees
    // its removal.
    let mut commits = Vec::new();
    for _ in 0..100 {
        commits.extend(new_commits(&erin_jmap, &mut seen).await);
        commits.retain(|c| *c != commit);
        if !commits.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(commits.len(), 1, "the revocation Commit");
    let result = mls_rs::MlsMessage::from_bytes(&commits[0]);
    assert!(
        matches!(&result, Err(mls_rs::error::MlsError::SerializationError(e))
            if format!("{e:?}").contains("InvalidVarIntPrefix(3)")),
        "{result:?}"
    );
    assert_eq!(group.current_epoch(), epoch + 1);
}
