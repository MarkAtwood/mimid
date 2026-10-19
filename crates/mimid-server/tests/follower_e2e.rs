//! Three-provider end-to-end test (bead mimid-1wgh.7.24): a.example hosts
//! the room; a.example, b.example and c.example are full provider stacks
//! on loopback, wired as `main.rs` wires them (`common/providers.rs`).
//! The MLS clients are mimi-mls Members and one mls-rs client, acting as
//! the agent would: they reach the server only through each provider's
//! in-process follower API (relay, KeyPackage upload, events).
//!
//! The scenario follows protocol-06 §3:
//!
//! 1. alice@a creates the room (§3.1).
//! 2. alice fetches bob@b's KeyPackage (a's hub asks b) and adds him; the
//!    Welcome is routed at b by KeyPackageRef (§3.2, §3.3).
//! 3. bob fetches cathy@c's KeyPackage through his relay (b → a → c) and
//!    adds her; his Commit is relayed b → a (§3.3). b's first `/notify` is
//!    refused and its second is stored but answered `503`.
//! 4. cathy sends a message through c (§3.4).
//! 5. b restarts mid-stream: alice sends while b is down.
//! 6. cathy fetches dave@b's mls-rs KeyPackage (c → a → b) and adds him;
//!    the Welcome is routed at b to dave alone.
//! 7. bob sends; dave, the mls-rs client, decrypts.
//! 8. dave proposes removing himself and kicking bob, through b (§3.6).
//! 9. cathy's Commit covers the proposals; bob and dave see their removal
//!    and leave the room at b.
//! 10. cathy's second client joins by external Commit through c (§3.5).
//! 11. bob rejoins with a new client by external Commit through b.
//! 12. alice sends; every current client decrypts.
//!
//! mimi-mls Members can send standalone AppDataUpdate proposals but not
//! standalone Remove proposals, so the member who
//! leaves by proposal is dave, the mls-rs client, who also kicks bob; and
//! the hub lets a committer add another user's client only with a
//! participant list update in the same Commit, which mls-rs cannot make,
//! so every add is a Member's.
//!
//! Oracles:
//!
//! - MLS agreement: at every epoch every member, mimi-mls or mls-rs, has
//!   the same `epoch_authenticator` and exporter output, and the same
//!   ratchet tree as a's hub.
//! - Plaintext equality: every receiver decrypts exactly what was sent,
//!   from the right sender; the mls-rs client decrypts a Member's message.
//! - KeyPackages: each one served through keyMaterial is byte-identical to
//!   the one uploaded, across one or two providers.
//! - Streams: each provider's follower log for the room, read from its
//!   database, is exactly a's outbox for that domain, captured by a
//!   trigger: in hub order, each FanoutMessage once, despite the refused
//!   and lost deliveries and the restart. The origin's echo of bob's Commit
//!   is stored once.
//! - Visibility and paging: each user reads every visible event exactly
//!   once, in order; paging with `after_seq` returns the same events;
//!   events before a user joined are hidden, a Welcome is seen only by the
//!   user it adds, and a rejoin does not resurrect earlier history.
//! - Restart: b's log, KeyPackages and claims survive it.
//! - Log canary: TRACE output for the whole run never shows the hubs'
//!   secrets, the client secrets the test can reach, exporter outputs or
//!   any application plaintext. A Member's private keys are not reachable
//!   through mimi-mls's public API, so they are not checked.

#[allow(dead_code, reason = "each test binary uses part of the helpers")]
mod common;
#[allow(dead_code, reason = "each test binary uses part of the helpers")]
#[path = "common/group_info.rs"]
mod group_info;
#[allow(dead_code, reason = "each test binary uses part of the helpers")]
#[path = "common/key_packages.rs"]
mod key_packages;
#[allow(dead_code, reason = "each test binary uses part of the helpers")]
#[path = "common/providers.rs"]
mod providers;
#[allow(dead_code, reason = "each test binary uses part of the helpers")]
#[path = "common/submit.rs"]
mod submit;
#[allow(dead_code, reason = "each test binary uses part of the helpers")]
#[path = "common/update.rs"]
mod update;

use std::collections::BTreeMap;
use std::time::Duration;

use common::{
    ALICE, BOB, HUB_IDENTITY, ROOM_ID, assert_secret_absent, base_room_policy, capture_logs,
    franking_agent, no_components,
};
use group_info::{GROUP_INFO_HEADER, Requester};
use key_packages::{APP_DATA_DICTIONARY, Ask, DAY, NO_REQUIREMENTS, now_seconds};
use mimi_content::{Disposition, Extensions, MimiContent, NestedPart, Part};
use mimi_mls::member::{AppDataUpdate, ComponentOp, ExternalSender, Incoming, Member};
use mimi_mls::tls_codec::{Deserialize, Serialize};
use mimi_mls::{ErrorSource, Identity, KeyPackageKind};
use mimi_protocol::component_id::{FRANK_AAD, FRANKING_AGENT, PARTICIPANT_LIST};
use mimi_protocol::{
    ClientKeyMaterial, FanoutEvent, FanoutMessage, KeyMaterialResponse, KeyMaterialUserCode,
    ParticipantListData, ParticipantListUpdate, SubmitMessageResponse, SubmitResult, UpdateResult,
    UserRolePair, franking_tag,
};
use mimi_room_policy::component_id::{BASE_ROOM_POLICY, ROLES_LIST};
use mimi_room_policy::{Capability, Role, RoleData, SingleSourceRoleChangeTargets};
use mimid_server::config::{BaseUrl, Domain};
use mimid_server::follower::MAX_EVENTS_PER_PAGE;
use mimid_server::hub::Hub;
use mls_rs::client_builder::MlsConfig;
use mls_rs::extension::ExtensionType;
use mls_rs::group::{CommitEffect, ExportedTree, ReceivedMessage};
use mls_rs::identity::SigningIdentity;
use mls_rs::identity::basic::{BasicCredential, BasicIdentityProvider};
use mls_rs::time::MlsTime;
use mls_rs::{
    CipherSuite, CipherSuiteProvider, Client, CryptoProvider, Extension, ExtensionList, MlsMessage,
};
use mls_rs_crypto_rustcrypto::RustCryptoProvider;
use providers::{Fault, Inbox, Provider, WAIT};

const CATHY: &[u8] = b"mimi://c.example/u/cathy";
/// A user of b.example whose client is an mls-rs client.
const DAVE: &[u8] = b"mimi://b.example/u/dave";

/// Role 2: listed users may add participants and their own clients,
/// remove their own clients, kick and send.
const ROLE_MEMBER: u32 = 2;

/// mls-extensions-10 §4.6 component ids `app_components` (0x0001) and
/// `safe_aad` (0x0002).
const APP_COMPONENTS: u16 = 0x0001;
const SAFE_AAD: u16 = 0x0002;
/// mls-extensions-10 §5 `ComponentsList` naming `frank_aad` (0x0020),
/// hand-encoded: `component_ids<V>` of 2 bytes.
const FRANK_AAD_ONLY: [u8; 3] = [0x02, 0x00, 0x20];
/// `ComponentsList` naming `app_components`, `safe_aad` and `frank_aad`:
/// `component_ids<V>` of 6 bytes.
const MLS_RS_APP_COMPONENTS: [u8; 7] = [0x06, 0x00, 0x01, 0x00, 0x02, 0x00, 0x20];
/// mls-extensions-10 §4.9: a SafeAAD with no items, `aad_items<V>` empty.
const EMPTY_SAFE_AAD: [u8; 1] = [0x00];
/// RFC 9420 §6 MLSMessage header: mls10 (0x0001), mls_key_package (0x0005).
const KEY_PACKAGE_HEADER: [u8; 4] = [0x00, 0x01, 0x00, 0x05];

const EXPORTER_LABEL: &str = "mimid e2e";

fn text(bytes: &[u8]) -> &str {
    std::str::from_utf8(bytes).unwrap()
}

fn memory() -> mimi_mls::Store {
    mimi_mls::Store::open_in_memory().unwrap()
}

/// `ParticipantListData` listing `users` with [`ROLE_MEMBER`], in order.
fn participants(users: &[&[u8]]) -> Vec<u8> {
    ParticipantListData {
        participants: users
            .iter()
            .map(|user| UserRolePair {
                user: user.to_vec(),
                role_index: ROLE_MEMBER,
            })
            .collect(),
    }
    .tls_serialize_detached()
    .unwrap()
}

fn roles_list() -> Vec<u8> {
    let role = |role_index, role_name: &str, role_capabilities, authorized_role_changes| Role {
        role_index,
        role_name: role_name.to_owned(),
        role_description: String::new(),
        role_capabilities,
        minimum_participants_constraint: 0,
        maximum_participants_constraint: None,
        minimum_active_participants_constraint: 0,
        maximum_active_participants_constraint: None,
        authorized_role_changes,
    };
    RoleData {
        roles: vec![
            role(1, "banned", vec![], vec![]),
            role(
                ROLE_MEMBER,
                "member",
                vec![
                    Capability::CAN_ADD_PARTICIPANT,
                    Capability::CAN_ADD_OWN_CLIENT,
                    Capability::CAN_REMOVE_OWN_CLIENT,
                    Capability::CAN_KICK,
                    Capability::CAN_SEND_MESSAGE,
                ],
                vec![SingleSourceRoleChangeTargets {
                    from_role_index: 0,
                    target_role_indexes: vec![ROLE_MEMBER],
                }],
            ),
        ],
    }
    .tls_serialize_detached()
    .unwrap()
}

/// The room's GroupContext components, ascending: Safe AAD requiring
/// `frank_aad`, the hub as `franking_agent`, alice listed, the roles and a
/// base policy.
fn components(hub_key: &[u8; 32]) -> Vec<(u16, Vec<u8>)> {
    let mut components = vec![
        (SAFE_AAD, FRANK_AAD_ONLY.to_vec()),
        (FRANKING_AGENT, franking_agent(hub_key, HUB_IDENTITY)),
        (PARTICIPANT_LIST, participants(&[ALICE])),
        (ROLES_LIST, roles_list()),
        (BASE_ROOM_POLICY, base_room_policy()),
    ];
    components.sort_by_key(|(component_id, _)| *component_id);
    components
}

/// An AppDataUpdate adding `user` to the participant list with
/// [`ROLE_MEMBER`].
fn add_participant(user: &[u8]) -> AppDataUpdate {
    AppDataUpdate::Update {
        component_id: PARTICIPANT_LIST,
        update: ParticipantListUpdate {
            changed_role_participants: vec![],
            removed_indices: vec![],
            added_participants: vec![UserRolePair {
                user: user.to_vec(),
                role_index: ROLE_MEMBER,
            }],
        }
        .tls_serialize_detached()
        .unwrap(),
    }
}

type Applied = Result<Option<Vec<u8>>, ErrorSource>;

/// An `apply` function whose participant list update gives `users`,
/// written out by hand: protocol-06 §7.5 appends added participants.
fn list_becomes(
    users: &'static [&'static [u8]],
) -> impl FnMut(u16, Option<&[u8]>, ComponentOp<'_>) -> Applied {
    move |component_id, _current, op| match (component_id, op) {
        (PARTICIPANT_LIST, ComponentOp::Update(_)) => Ok(Some(participants(users))),
        _ => Err("unexpected AppDataUpdate".into()),
    }
}

/// A MIMI content message (mimi-content-09 §4.1) from `sender` with `salt`
/// and a text body.
fn content(salt: [u8; 16], sender: &[u8], body: &str) -> Vec<u8> {
    MimiContent {
        salt,
        replaces: None,
        topic_id: vec![],
        expires: None,
        in_reply_to: None,
        mimi_extensions: Extensions {
            sender_uri: Some(text(sender).to_owned()),
            room_uri: Some(ROOM_ID.to_owned()),
            other: BTreeMap::new(),
        },
        nested_part: NestedPart {
            disposition: Disposition::RENDER,
            language: String::new(),
            part: Part::Single {
                content_type: "text/plain;charset=utf-8".to_owned(),
                content: body.as_bytes().to_vec(),
            },
        },
    }
    .encode()
    .unwrap()
}

/// An mls-rs client for dave on suite 1, and its signature private key.
fn mls_rs_dave() -> (Client<impl MlsConfig + use<>>, Vec<u8>) {
    let crypto = RustCryptoProvider::default();
    let suite = crypto
        .cipher_suite_provider(CipherSuite::CURVE25519_AES128)
        .unwrap();
    let (secret, public) = suite.signature_key_generate().unwrap();
    let secret_bytes = secret.as_bytes().to_vec();
    let client = Client::builder()
        .identity_provider(BasicIdentityProvider)
        .crypto_provider(crypto)
        .extension_type(ExtensionType::new(APP_DATA_DICTIONARY))
        .key_package_lifetime(Duration::from_secs(DAY))
        .signing_identity(
            SigningIdentity::new(
                BasicCredential::new(DAVE.to_vec()).into_credential(),
                public,
            ),
            secret,
            CipherSuite::CURVE25519_AES128,
        )
        .build();
    (client, secret_bytes)
}

/// dave's bare KeyPackage, valid from a minute ago, whose leaf
/// `app_data_dictionary` (hand-encoded, mls-extensions-10 §4.6, §5) lists
/// `app_components` and `safe_aad`, so that the leaf supports the
/// components the room requires.
fn dave_key_package(client: &Client<impl MlsConfig>) -> Vec<u8> {
    let mut leaf = ExtensionList::new();
    leaf.set(Extension::new(
        ExtensionType::new(APP_DATA_DICTIONARY),
        common::app_data_dictionary(&[
            (APP_COMPONENTS, &MLS_RS_APP_COMPONENTS),
            (SAFE_AAD, &FRANK_AAD_ONLY),
        ]),
    ));
    let message = client
        .generate_key_package_message(
            ExtensionList::new(),
            leaf,
            Some(MlsTime::from_duration_since_epoch(Duration::from_secs(
                now_seconds() - 60,
            ))),
        )
        .unwrap()
        .to_bytes()
        .unwrap();
    message.strip_prefix(&KEY_PACKAGE_HEADER).unwrap().to_vec()
}

/// `requester` fetches `target`'s key material for the room through its
/// provider's relay; the target has one client. Returns its KeyPackage.
async fn key_material(provider: &Provider, requester: &[u8], target: &[u8]) -> Vec<u8> {
    let request = key_packages::request(&Ask {
        requesting_user: text(requester),
        credential_identity: text(requester),
        target_user: text(target),
        room_id: ROOM_ID,
        required_capabilities: NO_REQUIREMENTS,
    });
    let response = provider
        .follower()
        .relay_key_material(&provider.user(requester), &request)
        .await
        .unwrap();
    let response = KeyMaterialResponse::tls_deserialize_exact(&response).unwrap();
    assert_eq!(response.user_status, KeyMaterialUserCode::Success);
    assert_eq!(response.user_uri.as_str(), text(target));
    let [ClientKeyMaterial::Success { key_package, .. }] = response.clients.as_slice() else {
        panic!("one client with a KeyPackage: {:?}", response.clients);
    };
    key_package.tls_serialize_detached().unwrap()
}

/// `user` sends an `UpdateRequest` through its provider's relay; the hub
/// must accept it.
async fn update(provider: &Provider, user: &[u8], request: Vec<u8>) {
    let response = provider
        .follower()
        .relay_update(&provider.user(user), ROOM_ID, &request)
        .await
        .unwrap();
    match update::response(&response) {
        (UpdateResult::Success { .. }, _) => {}
        other => panic!("update refused: {other:?}"),
    }
}

/// `user` submits `message` through its provider's relay; the hub must
/// accept it with a frank.
async fn submit(provider: &Provider, user: &[u8], message: &[u8]) {
    let response = provider
        .follower()
        .relay_submit_message(
            &provider.user(user),
            ROOM_ID,
            &submit::submit_request(message, user),
        )
        .await
        .unwrap();
    let result = SubmitMessageResponse::tls_deserialize_exact(response.as_slice())
        .unwrap()
        .result;
    assert!(
        matches!(result, SubmitResult::Accepted { frank: Some(_), .. }),
        "message not accepted with a frank: {result:?}"
    );
}

/// `identity` encrypts `data` with a `frank_aad` item over it
/// (protocol-06 §5.4.1.1).
fn franked(identity: &Identity, member: &mut Member, data: &[u8], salt: &[u8; 16]) -> Vec<u8> {
    let tag = franking_tag(salt, data);
    member
        .send(identity, data, &[(FRANK_AAD, tag.to_vec())])
        .unwrap()
}

fn mls_bytes(message: &FanoutMessage) -> &[u8] {
    match &message.event {
        FanoutEvent::Commit { message, .. }
        | FanoutEvent::Proposal { message, .. }
        | FanoutEvent::Application { message, .. } => message.as_bytes(),
        FanoutEvent::Welcome { .. } => panic!("a Welcome is not processed"),
    }
}

fn commit_bytes(message: &FanoutMessage) -> &[u8] {
    match &message.event {
        FanoutEvent::Commit { message, .. } => message.as_bytes(),
        other => panic!("not a Commit: {other:?}"),
    }
}

/// A Member processes a Commit and returns its summary.
fn commit(
    identity: &Identity,
    member: &mut Member,
    message: &FanoutMessage,
    apply: impl FnMut(u16, Option<&[u8]>, ComponentOp<'_>) -> Applied,
) -> mimi_mls::member::CommitSummary {
    match member
        .process(identity, commit_bytes(message), apply)
        .unwrap()
    {
        Incoming::Commit(summary) => summary,
        other => panic!("not a Commit: {other:?}"),
    }
}

/// A Member decrypts an application message: `data` from `sender`.
fn assert_decrypts(
    identity: &Identity,
    member: &mut Member,
    message: &FanoutMessage,
    sender: &[u8],
    data: &[u8],
) {
    match member
        .process(identity, mls_bytes(message), no_components)
        .unwrap()
    {
        Incoming::Application {
            sender_identity,
            data: got,
            ..
        } => {
            assert_eq!(sender_identity, sender);
            assert_eq!(got, data);
        }
        other => panic!("not an application message: {other:?}"),
    }
}

fn assert_own_message(identity: &Identity, member: &mut Member, message: &FanoutMessage) {
    assert_eq!(
        member
            .process(identity, mls_bytes(message), no_components)
            .unwrap(),
        Incoming::OwnMessage
    );
}

/// The Welcome a joiner reads: its message and ratchet tree.
fn welcome(message: &FanoutMessage) -> (&[u8], &[u8]) {
    match &message.event {
        FanoutEvent::Welcome {
            message,
            ratchet_tree_option,
        } => (
            message.as_bytes(),
            ratchet_tree_option.ratchet_tree().unwrap(),
        ),
        other => panic!("not a Welcome: {other:?}"),
    }
}

/// Asserts MLS agreement for `epoch` among a's hub and the Members.
/// Returns the common exporter output.
async fn assert_agreement(hub: &Hub, epoch: u64, members: &[(&Identity, &Member)]) -> Vec<u8> {
    let state = hub.public_state(ROOM_ID).await.unwrap();
    assert_eq!(state.epoch, epoch);
    let (first_identity, first) = members[0];
    let exported = first
        .export_secret(first_identity, EXPORTER_LABEL, b"", 32)
        .unwrap();
    for (identity, member) in members {
        let name = String::from_utf8_lossy(identity.identity());
        assert_eq!(member.epoch(), epoch, "{name} epoch");
        assert_eq!(
            member.ratchet_tree().unwrap(),
            state.ratchet_tree,
            "{name} tree"
        );
        assert_eq!(
            member.epoch_authenticator(),
            first.epoch_authenticator(),
            "{name} epoch_authenticator"
        );
        assert_eq!(
            member
                .export_secret(identity, EXPORTER_LABEL, b"", 32)
                .unwrap(),
            exported,
            "{name} exporter"
        );
    }
    exported
}

/// Asserts that the mls-rs client agrees with a's hub and with `peer`, a
/// Member in the same epoch.
async fn assert_mls_rs_agreement<C: MlsConfig>(
    hub: &Hub,
    group: &mls_rs::Group<C>,
    (identity, member): (&Identity, &Member),
) {
    let state = hub.public_state(ROOM_ID).await.unwrap();
    assert_eq!(group.current_epoch(), state.epoch, "mls-rs epoch");
    assert_eq!(group.export_tree().to_bytes().unwrap(), state.ratchet_tree);
    assert_eq!(
        group.epoch_authenticator().unwrap().as_bytes(),
        member.epoch_authenticator(),
        "mls-rs epoch_authenticator"
    );
    assert_eq!(
        group
            .export_secret(EXPORTER_LABEL.as_bytes(), b"", 32)
            .unwrap()
            .as_bytes(),
        member
            .export_secret(identity, EXPORTER_LABEL, b"", 32)
            .unwrap(),
        "mls-rs exporter"
    );
}

/// Every event `inbox`'s user may see now, as seqs, read in one page and
/// in pages of one and of two, which must agree.
async fn visible(provider: &Provider, inbox: &Inbox) -> Vec<u64> {
    let follower = provider.follower();
    let page = |after, limit| async move {
        follower
            .events(&inbox.user, ROOM_ID, after, limit)
            .await
            .unwrap()
            .into_iter()
            .map(|event| event.seq)
            .collect::<Vec<u64>>()
    };
    let all = page(0, MAX_EVENTS_PER_PAGE).await;
    for limit in [1, 2] {
        let mut paged = Vec::new();
        let mut after = 0;
        loop {
            let seqs = page(after, limit).await;
            let Some(&last) = seqs.last() else { break };
            assert!(seqs.len() <= usize::try_from(limit).unwrap());
            paged.extend(seqs);
            after = last;
        }
        assert_eq!(paged, all, "{} paged by {limit}", inbox.user.as_str());
    }
    all
}

/// The seqs of `log` from `from` to `to`, inclusive, except `skip`.
fn seqs_between(log: &[(u64, Vec<u8>)], from: u64, to: u64, skip: &[u64]) -> Vec<u64> {
    log.iter()
        .map(|(seq, _)| *seq)
        .filter(|seq| (from..=to).contains(seq) && !skip.contains(seq))
        .collect()
}

fn peers(others: [&Provider; 2]) -> BTreeMap<Domain, BaseUrl> {
    others
        .iter()
        .map(|provider| (provider.domain.clone(), provider.base.clone()))
        .collect()
}

#[tokio::test]
async fn three_providers_end_to_end() {
    let logs = capture_logs();
    let dir = tempfile::tempdir().unwrap();
    let mut a = Provider::bind("a.example", dir.path()).await;
    let mut b = Provider::bind("b.example", dir.path()).await;
    let mut c = Provider::bind("c.example", dir.path()).await;
    let a_peers = peers([&b, &c]);
    let b_peers = peers([&a, &c]);
    let c_peers = peers([&a, &b]);
    a.boot(&a_peers).await;
    b.boot(&b_peers).await;
    c.boot(&c_peers).await;
    let mut exported = Vec::new();
    let mut plaintexts = Vec::new();

    // Each joining client uploads a KeyPackage to its provider.
    let alice = Identity::generate(ALICE, memory()).unwrap();
    let bob = Identity::generate(BOB, memory()).unwrap();
    let cathy = Identity::generate(CATHY, memory()).unwrap();
    let (dave_client, dave_secret) = mls_rs_dave();
    let bob_key_package = bob.key_package(KeyPackageKind::OneTime).unwrap();
    let cathy_key_package = cathy.key_package(KeyPackageKind::OneTime).unwrap();
    let dave_key_package = dave_key_package(&dave_client);
    for (provider, user, key_package) in [
        (&b, BOB, &bob_key_package),
        (&c, CATHY, &cathy_key_package),
        (&b, DAVE, &dave_key_package),
    ] {
        provider
            .stack()
            .key_packages
            .upload_key_package(&provider.user(user), key_package)
            .await
            .unwrap();
    }

    // Epoch 1: alice creates the room at a. The creator's membership is
    // recorded by the caller of create_room (plan of mimid-1wgh.7), joining
    // from the next event on.
    let hub_key = *a.stack().hub.signature_public_key();
    let senders = [ExternalSender {
        signature_key: hub_key.to_vec(),
        identity: HUB_IDENTITY.to_vec(),
    }];
    let mut alice_group =
        Member::create(&alice, b"e2e-room", &senders, &components(&hub_key)).unwrap();
    let bundle = alice_group
        .commit(&alice, &[], &[], &[], no_components)
        .unwrap();
    alice_group.merge_pending_commit(&alice).unwrap();
    let since = a.stack().store.follower_next_seq().await.unwrap();
    a.stack()
        .hub
        .create_room(
            ROOM_ID,
            ALICE,
            &bundle.group_info,
            &alice_group.ratchet_tree().unwrap(),
        )
        .await
        .unwrap();
    assert!(
        a.stack()
            .store
            .add_follower_member(
                ROOM_ID,
                &a.domain,
                text(ALICE),
                since,
                key_packages::now_ms()
            )
            .await
            .unwrap()
    );
    let mut alice_inbox = Inbox::new(a.user(ALICE), ROOM_ID, 0);
    exported.push(assert_agreement(&a.stack().hub, 1, &[(&alice, &alice_group)]).await);

    // Epoch 2: alice fetches bob's KeyPackage; a's hub asks b for it.
    let key_package = key_material(&a, ALICE, BOB).await;
    assert_eq!(key_package, bob_key_package, "served verbatim, a -> b");
    let bundle = alice_group
        .commit(
            &alice,
            &[&key_package],
            &[],
            &[add_participant(BOB)],
            list_becomes(&[ALICE, BOB]),
        )
        .unwrap();
    alice_group.merge_pending_commit(&alice).unwrap();
    let tree = alice_group.ratchet_tree().unwrap();
    update(
        &a,
        ALICE,
        update::commit_request(
            &bundle.commit,
            bundle.welcome.as_deref(),
            &bundle.group_info,
            &tree,
        ),
    )
    .await;
    assert_eq!(
        commit_bytes(&alice_inbox.next(&a).await),
        bundle.commit,
        "alice's own Commit, fanned out to a in-process"
    );
    // The Welcome is routed to bob by his KeyPackageRef; the Commit that
    // added him came before he joined and is hidden.
    let mut bob_inbox = Inbox::new(b.user(BOB), ROOM_ID, 0);
    let message = bob_inbox.next(&b).await;
    let (welcome_bytes, tree) = welcome(&message);
    let mut bob_group = Member::join_welcome(&bob, welcome_bytes, Some(tree))
        .unwrap()
        .member;
    let bob_joined = bob_inbox.position();
    exported.push(
        assert_agreement(
            &a.stack().hub,
            2,
            &[(&alice, &alice_group), (&bob, &bob_group)],
        )
        .await,
    );

    // Epoch 3: bob fetches cathy's KeyPackage through b's relay (b -> a ->
    // c) and adds her. b refuses the first /notify, and stores the second
    // but answers 503.
    a.drained().await;
    b.script(&[Fault::Refuse, Fault::LoseResponse]);
    let key_package = key_material(&b, BOB, CATHY).await;
    assert_eq!(
        key_package, cathy_key_package,
        "served verbatim, b -> a -> c"
    );
    let bundle = bob_group
        .commit(
            &bob,
            &[&key_package],
            &[],
            &[add_participant(CATHY)],
            list_becomes(&[ALICE, BOB, CATHY]),
        )
        .unwrap();
    bob_group.merge_pending_commit(&bob).unwrap();
    update(
        &b,
        BOB,
        update::commit_request(
            &bundle.commit,
            bundle.welcome.as_deref(),
            &bundle.group_info,
            &bob_group.ratchet_tree().unwrap(),
        ),
    )
    .await;
    let summary = commit(
        &alice,
        &mut alice_group,
        &alice_inbox.next(&a).await,
        list_becomes(&[ALICE, BOB, CATHY]),
    );
    assert_eq!(summary.added, [CATHY.to_vec()]);
    assert_eq!(
        commit_bytes(&bob_inbox.next(&b).await),
        bundle.commit,
        "the origin's echo of bob's Commit"
    );
    let mut cathy_inbox = Inbox::new(c.user(CATHY), ROOM_ID, 0);
    let message = cathy_inbox.next(&c).await;
    let (welcome_bytes, tree) = welcome(&message);
    let mut cathy_group = Member::join_welcome(&cathy, welcome_bytes, Some(tree))
        .unwrap()
        .member;
    let cathy_joined = cathy_inbox.position();
    exported.push(
        assert_agreement(
            &a.stack().hub,
            3,
            &[
                (&alice, &alice_group),
                (&bob, &bob_group),
                (&cathy, &cathy_group),
            ],
        )
        .await,
    );
    a.drained().await;
    assert_eq!(b.faults(), (vec![], 2), "both scripted faults were used");
    let echoes = b
        .raw_log(ROOM_ID)
        .await
        .iter()
        .filter(|(_, bytes)| {
            let message = FanoutMessage::tls_deserialize_exact(bytes).unwrap();
            matches!(&message.event, FanoutEvent::Commit { message, .. }
                if message.as_bytes() == bundle.commit)
        })
        .count();
    assert_eq!(echoes, 1, "the echo is stored once despite the lost 201");

    // cathy sends through c.
    let data = content([1; 16], CATHY, "plaintext-canary-cathy-1");
    let message = franked(&cathy, &mut cathy_group, &data, &[1; 16]);
    submit(&c, CATHY, &message).await;
    assert_decrypts(
        &alice,
        &mut alice_group,
        &alice_inbox.next(&a).await,
        CATHY,
        &data,
    );
    assert_decrypts(
        &bob,
        &mut bob_group,
        &bob_inbox.next(&b).await,
        CATHY,
        &data,
    );
    assert_own_message(&cathy, &mut cathy_group, &cathy_inbox.next(&c).await);
    plaintexts.push((data, "plaintext-canary-cathy-1"));

    // b restarts mid-stream: alice sends while it is down, a's delivery to
    // b fails, and b's log, KeyPackages and claims survive.
    a.drained().await;
    let log_before = b.raw_log(ROOM_ID).await;
    let bob_view_before = visible(&b, &bob_inbox).await;
    assert_eq!(bob_view_before, bob_inbox.read);
    let b_secret = b.stack().store.hub_secret().await.unwrap().unwrap();
    let (_, refused_before) = b.faults();
    b.stop().await;
    let data = content([2; 16], ALICE, "plaintext-canary-alice-1");
    let message = franked(&alice, &mut alice_group, &data, &[2; 16]);
    submit(&a, ALICE, &message).await;
    assert_own_message(&alice, &mut alice_group, &alice_inbox.next(&a).await);
    assert_decrypts(
        &cathy,
        &mut cathy_group,
        &cathy_inbox.next(&c).await,
        ALICE,
        &data,
    );
    tokio::time::timeout(WAIT, async {
        loop {
            let heads = a.stack().store.outbox_heads().await.unwrap();
            if heads
                .iter()
                .any(|head| head.domain.as_str() == "b.example" && head.attempts != 0)
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("a's delivery to b fails while b is down");
    b.boot(&b_peers).await;
    assert_decrypts(
        &bob,
        &mut bob_group,
        &bob_inbox.next(&b).await,
        ALICE,
        &data,
    );
    plaintexts.push((data, "plaintext-canary-alice-1"));
    assert!(
        b.faults().1 > refused_before,
        "a delivery was refused while b was down"
    );
    assert_eq!(
        b.raw_log(ROOM_ID).await[..log_before.len()],
        log_before[..],
        "b's log survived the restart"
    );
    let bob_view = visible(&b, &bob_inbox).await;
    assert_eq!(
        bob_view[..bob_view_before.len()],
        bob_view_before[..],
        "bob still sees his Welcome: his claim survived"
    );
    let dave_entries = b
        .stack()
        .key_packages
        .list_key_packages(&b.user(DAVE))
        .await
        .unwrap();
    assert_eq!(dave_entries.len(), 1, "dave's KeyPackage survived");
    assert_eq!(
        b.stack().store.hub_secret().await.unwrap().unwrap().hub_key,
        b_secret.hub_key
    );

    // Epoch 4: cathy fetches dave's mls-rs KeyPackage through c's relay
    // (c -> a -> b, after b's restart) and adds him. The Welcome is routed
    // at b to dave alone.
    let key_package = key_material(&c, CATHY, DAVE).await;
    assert_eq!(
        key_package, dave_key_package,
        "served verbatim, c -> a -> b"
    );
    let bundle = cathy_group
        .commit(
            &cathy,
            &[&key_package],
            &[],
            &[add_participant(DAVE)],
            list_becomes(&[ALICE, BOB, CATHY, DAVE]),
        )
        .unwrap();
    cathy_group.merge_pending_commit(&cathy).unwrap();
    update(
        &c,
        CATHY,
        update::commit_request(
            &bundle.commit,
            bundle.welcome.as_deref(),
            &bundle.group_info,
            &cathy_group.ratchet_tree().unwrap(),
        ),
    )
    .await;
    for (identity, group, inbox, provider) in [
        (&alice, &mut alice_group, &mut alice_inbox, &a),
        (&bob, &mut bob_group, &mut bob_inbox, &b),
    ] {
        let summary = commit(
            identity,
            group,
            &inbox.next(provider).await,
            list_becomes(&[ALICE, BOB, CATHY, DAVE]),
        );
        assert_eq!(summary.added, [DAVE.to_vec()]);
    }
    assert_eq!(commit_bytes(&cathy_inbox.next(&c).await), bundle.commit);
    let mut dave_inbox = Inbox::new(b.user(DAVE), ROOM_ID, 0);
    let message = dave_inbox.next(&b).await;
    let (welcome_bytes, tree) = welcome(&message);
    let mut dave = dave_client
        .join_group(
            Some(ExportedTree::from_bytes(tree).unwrap()),
            &MlsMessage::from_bytes(welcome_bytes).unwrap(),
            None,
        )
        .unwrap()
        .0;
    let dave_joined = dave_inbox.position();
    bob_inbox.assert_empty(&b).await;
    exported.push(
        assert_agreement(
            &a.stack().hub,
            4,
            &[
                (&alice, &alice_group),
                (&bob, &bob_group),
                (&cathy, &cathy_group),
            ],
        )
        .await,
    );
    assert_mls_rs_agreement(&a.stack().hub, &dave, (&alice, &alice_group)).await;

    // bob sends through b; dave, the mls-rs client, decrypts it too.
    let data = content([3; 16], BOB, "plaintext-canary-bob-1");
    let message = franked(&bob, &mut bob_group, &data, &[3; 16]);
    submit(&b, BOB, &message).await;
    assert_decrypts(
        &alice,
        &mut alice_group,
        &alice_inbox.next(&a).await,
        BOB,
        &data,
    );
    assert_decrypts(
        &cathy,
        &mut cathy_group,
        &cathy_inbox.next(&c).await,
        BOB,
        &data,
    );
    assert_own_message(&bob, &mut bob_group, &bob_inbox.next(&b).await);
    let to_dave = dave_inbox.next(&b).await;
    match dave
        .process_incoming_message(MlsMessage::from_bytes(mls_bytes(&to_dave)).unwrap())
        .unwrap()
    {
        ReceivedMessage::ApplicationMessage(description) => {
            assert_eq!(description.data(), data);
            assert_eq!(description.sender_index, bob_group.own_leaf_index());
        }
        other => panic!("dave expected bob's message: {other:?}"),
    }
    plaintexts.push((data, "plaintext-canary-bob-1"));

    // dave proposes removing himself and kicking bob, through b. The
    // proposals open no epoch.
    let bob_leaf = bob_group.own_leaf_index();
    let dave_leaf = dave.current_member_index();
    let leave = dave
        .propose_remove(dave_leaf, EMPTY_SAFE_AAD.to_vec())
        .unwrap()
        .to_bytes()
        .unwrap();
    let kick = dave
        .propose_remove(bob_leaf, EMPTY_SAFE_AAD.to_vec())
        .unwrap()
        .to_bytes()
        .unwrap();
    update(&b, DAVE, update::proposal_request(&leave, &[&kick])).await;
    for (identity, group, inbox, provider) in [
        (&alice, &mut alice_group, &mut alice_inbox, &a),
        (&bob, &mut bob_group, &mut bob_inbox, &b),
        (&cathy, &mut cathy_group, &mut cathy_inbox, &c),
    ] {
        let message = inbox.next(provider).await;
        let FanoutEvent::Proposal {
            message: first,
            more_proposals,
        } = &message.event
        else {
            panic!("not a proposal fanout: {message:?}");
        };
        assert_eq!(first.as_bytes(), leave);
        for proposal in std::iter::once(first).chain(more_proposals) {
            let incoming = group.process(identity, proposal.as_bytes(), no_components);
            assert!(
                matches!(incoming, Ok(Incoming::Proposal { .. })),
                "{incoming:?}"
            );
        }
    }
    let FanoutEvent::Proposal { message, .. } = dave_inbox.next(&b).await.event else {
        panic!("dave expected his own proposals");
    };
    assert_eq!(message.as_bytes(), leave);
    assert_eq!(a.stack().hub.public_state(ROOM_ID).await.unwrap().epoch, 4);

    // Epoch 5: cathy's Commit covers the proposals. bob and dave see their
    // removal and leave the room at b.
    let bundle = cathy_group
        .commit(&cathy, &[], &[], &[], no_components)
        .unwrap();
    cathy_group.merge_pending_commit(&cathy).unwrap();
    update(
        &c,
        CATHY,
        update::commit_request(
            &bundle.commit,
            None,
            &bundle.group_info,
            &cathy_group.ratchet_tree().unwrap(),
        ),
    )
    .await;
    let mut removed = vec![bob_leaf, dave_leaf];
    removed.sort_unstable();
    let summary = commit(
        &alice,
        &mut alice_group,
        &alice_inbox.next(&a).await,
        no_components,
    );
    let mut got = summary.removed.clone();
    got.sort_unstable();
    assert_eq!(got, removed);
    let summary = commit(
        &bob,
        &mut bob_group,
        &bob_inbox.next(&b).await,
        no_components,
    );
    assert!(summary.self_removed, "bob sees his own removal");
    assert!(!bob_group.is_active());
    let removal = dave_inbox.next(&b).await;
    let received = dave
        .process_incoming_message(MlsMessage::from_bytes(commit_bytes(&removal)).unwrap())
        .unwrap();
    assert!(
        matches!(
            received,
            ReceivedMessage::Commit(ref description)
                if matches!(description.effect, CommitEffect::Removed { .. })
        ),
        "dave sees his own removal: {received:?}"
    );
    assert_eq!(commit_bytes(&cathy_inbox.next(&c).await), bundle.commit);
    let bob_view = visible(&b, &bob_inbox).await;
    let dave_view = visible(&b, &dave_inbox).await;
    assert_eq!(bob_view, bob_inbox.read, "bob read every event he may see");
    assert_eq!(
        dave_view, dave_inbox.read,
        "dave read every event he may see"
    );
    let log = b.raw_log(ROOM_ID).await;
    let last = *bob_inbox.read.last().unwrap();
    assert_eq!(
        bob_view,
        seqs_between(&log, bob_joined, last, &[dave_joined]),
        "bob sees everything from his Welcome on, except dave's Welcome"
    );
    assert_eq!(
        dave_view,
        seqs_between(&log, dave_joined, last, &[]),
        "dave sees nothing from before his Welcome"
    );
    assert!(
        log[0].0 < bob_joined && !bob_view.contains(&log[0].0),
        "the Commit that added bob is hidden from him"
    );
    for (user, inbox) in [(BOB, &bob_inbox), (DAVE, &dave_inbox)] {
        b.follower().leave(&b.user(user), ROOM_ID).await.unwrap();
        assert!(visible(&b, inbox).await.is_empty(), "{} left", text(user));
    }
    exported.push(
        assert_agreement(
            &a.stack().hub,
            5,
            &[(&alice, &alice_group), (&cathy, &cathy_group)],
        )
        .await,
    );

    // Epoch 6: cathy's second client joins by external Commit through c.
    let cathy_requester = Requester::new(CATHY);
    let response = c
        .follower()
        .relay_group_info(&c.user(CATHY), ROOM_ID, &cathy_requester.request(None))
        .await
        .unwrap();
    let served = group_info::open(&a.stack().hub, ROOM_ID, &cathy_requester, &response);
    let cathy2 = Identity::generate(CATHY, memory()).unwrap();
    let join = Member::join_external(
        &cathy2,
        &[&GROUP_INFO_HEADER[..], served.group_info.as_bytes()].concat(),
        served.ratchet_tree_option.ratchet_tree(),
    )
    .unwrap();
    let mut cathy2_group = join.member;
    let mut cathy2_inbox = Inbox::new(c.user(CATHY), ROOM_ID, cathy_inbox.position());
    update(
        &c,
        CATHY,
        update::commit_request(
            &join.commit_bundle.commit,
            None,
            &join.commit_bundle.group_info,
            &cathy2_group.ratchet_tree().unwrap(),
        ),
    )
    .await;
    commit(
        &alice,
        &mut alice_group,
        &alice_inbox.next(&a).await,
        no_components,
    );
    commit(
        &cathy,
        &mut cathy_group,
        &cathy_inbox.next(&c).await,
        no_components,
    );
    assert_eq!(
        commit_bytes(&cathy2_inbox.next(&c).await),
        join.commit_bundle.commit
    );
    exported.push(
        assert_agreement(
            &a.stack().hub,
            6,
            &[
                (&alice, &alice_group),
                (&cathy, &cathy_group),
                (&cathy2, &cathy2_group),
            ],
        )
        .await,
    );

    // Epoch 7: bob rejoins with a new client by external Commit through b.
    // The accepted relayed update makes him a member at b again, from the
    // request on; his earlier history stays hidden.
    let bob_requester = Requester::new(BOB);
    let response = b
        .follower()
        .relay_group_info(&b.user(BOB), ROOM_ID, &bob_requester.request(None))
        .await
        .unwrap();
    let served = group_info::open(&a.stack().hub, ROOM_ID, &bob_requester, &response);
    let bob2 = Identity::generate(BOB, memory()).unwrap();
    let join = Member::join_external(
        &bob2,
        &[&GROUP_INFO_HEADER[..], served.group_info.as_bytes()].concat(),
        served.ratchet_tree_option.ratchet_tree(),
    )
    .unwrap();
    let mut bob2_group = join.member;
    let mut bob2_inbox = Inbox::new(b.user(BOB), ROOM_ID, 0);
    update(
        &b,
        BOB,
        update::commit_request(
            &join.commit_bundle.commit,
            None,
            &join.commit_bundle.group_info,
            &bob2_group.ratchet_tree().unwrap(),
        ),
    )
    .await;
    for (identity, group, inbox, provider) in [
        (&alice, &mut alice_group, &mut alice_inbox, &a),
        (&cathy, &mut cathy_group, &mut cathy_inbox, &c),
        (&cathy2, &mut cathy2_group, &mut cathy2_inbox, &c),
    ] {
        commit(identity, group, &inbox.next(provider).await, no_components);
    }
    assert_eq!(
        commit_bytes(&bob2_inbox.next(&b).await),
        join.commit_bundle.commit,
        "bob's first event after rejoining is his own Commit"
    );
    exported.push(
        assert_agreement(
            &a.stack().hub,
            7,
            &[
                (&alice, &alice_group),
                (&cathy, &cathy_group),
                (&cathy2, &cathy2_group),
                (&bob2, &bob2_group),
            ],
        )
        .await,
    );

    // alice sends; every current client decrypts.
    let data = content([4; 16], ALICE, "plaintext-canary-alice-2");
    let message = franked(&alice, &mut alice_group, &data, &[4; 16]);
    submit(&a, ALICE, &message).await;
    assert_own_message(&alice, &mut alice_group, &alice_inbox.next(&a).await);
    for (identity, group, inbox, provider) in [
        (&cathy, &mut cathy_group, &mut cathy_inbox, &c),
        (&cathy2, &mut cathy2_group, &mut cathy2_inbox, &c),
        (&bob2, &mut bob2_group, &mut bob2_inbox, &b),
    ] {
        assert_decrypts(identity, group, &inbox.next(provider).await, ALICE, &data);
    }
    plaintexts.push((data, "plaintext-canary-alice-2"));

    // Every provider's log is exactly a's outbox for its domain, and each
    // user read exactly what it may see.
    a.drained().await;
    for provider in [&a, &b, &c] {
        let log: Vec<Vec<u8>> = provider
            .raw_log(ROOM_ID)
            .await
            .into_iter()
            .map(|(_, bytes)| bytes)
            .collect();
        let outbox = a.captured_outbox(ROOM_ID, provider.domain.as_str()).await;
        assert!(!outbox.is_empty());
        assert_eq!(
            log,
            outbox,
            "{} log == a's outbox for it",
            provider.domain.as_str()
        );
    }
    for provider in [&b, &c] {
        assert!(
            provider
                .captured_outbox(ROOM_ID, "a.example")
                .await
                .is_empty(),
            "only a hosts the room"
        );
    }
    let a_log = a.raw_log(ROOM_ID).await;
    let alice_view = visible(&a, &alice_inbox).await;
    assert_eq!(alice_view, alice_inbox.read);
    assert_eq!(
        alice_view,
        seqs_between(&a_log, 0, u64::MAX, &[]),
        "alice joined before any event"
    );
    let c_log = c.raw_log(ROOM_ID).await;
    let cathy_view = visible(&c, &cathy_inbox).await;
    assert_eq!(cathy_view, cathy_inbox.read);
    assert_eq!(
        cathy_view,
        seqs_between(&c_log, cathy_joined, u64::MAX, &[])
    );
    assert!(
        c_log[0].0 < cathy_joined,
        "the Commit that added cathy is hidden"
    );
    assert_eq!(
        cathy2_inbox.read[..],
        cathy_view[cathy_view.len() - cathy2_inbox.read.len()..]
    );
    let b_log = b.raw_log(ROOM_ID).await;
    let bob_view = visible(&b, &bob2_inbox).await;
    assert_eq!(bob_view, bob2_inbox.read);
    assert_eq!(
        bob_view,
        b_log[b_log.len() - 2..]
            .iter()
            .map(|(seq, _)| *seq)
            .collect::<Vec<_>>(),
        "after rejoining, bob sees only his Commit and alice's message"
    );

    // The log canary, over the whole run.
    let text = logs.contents();
    for line in [
        "KeyPackage uploaded",
        "keyMaterial served",
        "room created",
        "commit accepted",
        "proposals accepted",
        "application message accepted",
        "GroupInfo served",
        "fanout accepted",
        "fanout delivery failed",
        "user joined followed room",
        "user left followed room",
    ] {
        assert!(text.contains(line), "the capture holds {line:?}");
    }
    for (provider, secret) in [
        ("a", a.stack().store.hub_secret().await.unwrap().unwrap()),
        ("b", b_secret),
        ("c", c.stack().store.hub_secret().await.unwrap().unwrap()),
    ] {
        assert_secret_absent(&text, &secret.signature_private_key, provider);
        assert_secret_absent(&text, &secret.hub_key, provider);
    }
    assert_secret_absent(&text, &dave_secret, "mls-rs client signing key");
    for requester in [&cathy_requester, &bob_requester] {
        assert_secret_absent(
            &text,
            requester.signing.signature_key(),
            "groupInfo requester signing key",
        );
        assert_secret_absent(
            &text,
            &requester.hpke_secret,
            "groupInfo requester HPKE key",
        );
    }
    for secret in &exported {
        assert_secret_absent(&text, secret, "exporter output");
    }
    for (data, canary) in &plaintexts {
        assert_secret_absent(&text, data, "application plaintext");
        assert!(!text.contains(canary), "plaintext {canary:?} logged");
    }
}
