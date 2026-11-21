//! Two providers, clients on JMAP only (bead mimid-1wgh.7.1): a.example
//! hosts the room and b.example follows it, each a full provider stack on
//! loopback (`common/providers.rs`, with the JMAP API mounted as `main.rs`
//! mounts it). The MLS clients are mimi-mls Members, and every request
//! they make goes through their own provider's JMAP API
//! (draft-atwood-jmap-chat-mimi-00): KeyPackage/set, Consent/set,
//! Room/create, KeyMaterial/fetch, Room/update, Room/send, GroupInfo/fetch,
//! and Message/get and Message/changes to read what arrives.
//!
//! The scenario:
//!
//! 1. alice@a and bob@b publish KeyPackages; bob consents to alice.
//! 2. alice creates the room over JMAP (Room/create with `roomId`); epoch 1.
//! 3. alice fetches bob's KeyPackage (KeyMaterial/fetch: a's hub asks b),
//!    adds him (Room/update); bob reads the Welcome from b and joins;
//!    epoch 2.
//! 4. alice and bob each send (Room/send) and each reads the other's
//!    message from their own provider.
//! 5. bob's second client joins by external Commit: GroupInfo/fetch at b
//!    (relayed to a's hub), then Room/update at b; epoch 3.
//! 6. alice leaves (protocol-07 §3.5): her Remove of her own client and the
//!    participant-list update, one Room/update at a; bob commits them by
//!    reference through b; epoch 4. alice sees her removal.
//!
//! Oracles:
//!
//! - MLS agreement: at every epoch every member has the same
//!   `epoch_authenticator`, exporter output and ratchet tree as a's hub.
//! - Plaintext equality: each receiver decrypts exactly what was sent, from
//!   the right sender.
//! - KeyPackages: the one served through KeyMaterial/fetch is the one bob
//!   published.
//! - Removal: alice processes the Commit that removes her and is no
//!   longer active.

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
#[path = "common/update.rs"]
mod update;

use std::collections::{BTreeMap, VecDeque};
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use common::{
    ALICE, BOB, HUB_IDENTITY, ROOM_APP_COMPONENTS, base_room_policy, franking_agent, no_components,
};
use group_info::{GROUP_INFO_HEADER, Requester};
use key_packages::{Ask, NO_REQUIREMENTS};
use mimi_mls::member::{AppDataUpdate, ComponentOp, ExternalSender, Incoming, Member};
use mimi_mls::tls_codec::Serialize;
use mimi_mls::{ErrorSource, Identity, KeyPackageKind};
use mimi_protocol::component_id::{FRANK_AAD, FRANKING_AGENT, PARTICIPANT_LIST};
use mimi_protocol::{
    FanoutEvent, FanoutMessage, ParticipantListData, ParticipantListUpdate, UserRolePair,
    franking_tag,
};
use mimi_room_policy::component_id::{BASE_ROOM_POLICY, ROLES_LIST};
use mimi_room_policy::{Capability, Role, RoleData, SingleSourceRoleChangeTargets};
use mimid_server::config::{BaseUrl, Domain};
use mimid_server::hub::Hub;
use providers::{Provider, WAIT};
use serde_json::{Value, json};

/// Role 2: listed users may add participants and their own clients,
/// leave, and send.
const ROLE_MEMBER: u32 = 2;
/// mls-extensions-11 §4.6 component ids `app_components` and `safe_aad`.
const APP_COMPONENTS: u16 = 0x0001;
const SAFE_AAD: u16 = 0x0002;
/// mls-extensions-11 §5 `ComponentsList` naming `frank_aad` (0x0020).
const FRANK_AAD_ONLY: [u8; 3] = [0x02, 0x00, 0x20];
const EXPORTER_LABEL: &str = "mimid jmap e2e";
const USING: [&str; 3] = [
    "urn:ietf:params:jmap:core",
    "urn:ietf:params:jmap:chat",
    "urn:ietf:params:jmap:chat:mimi",
];

fn text(bytes: &[u8]) -> &str {
    std::str::from_utf8(bytes).unwrap()
}

fn memory() -> mimi_mls::Store {
    mimi_mls::Store::open_in_memory().unwrap()
}

fn now_ms() -> u64 {
    key_packages::now_ms()
}

fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn unb64(value: &Value) -> Vec<u8> {
    URL_SAFE_NO_PAD
        .decode(value.as_str().expect("a base64url string"))
        .unwrap()
}

/// Unpadded lowercase RFC 4648 §6 base32.
fn base32(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
    let (mut out, mut buffer, mut bits) = (String::new(), 0u32, 0);
    for &byte in bytes {
        buffer = (buffer << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(char::from(ALPHABET[((buffer >> bits) & 31) as usize]));
        }
    }
    if bits > 0 {
        out.push(char::from(ALPHABET[((buffer << (5 - bits)) & 31) as usize]));
    }
    out
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

/// Role 1 banned; role 2 may add participants (0 -> 2), add and remove its
/// own clients, leave (2 -> 0) and send.
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
            // An open room (room-policy-04 §8.1.1): anyone may join as a
            // member, which step 9's rejoin uses.
            role(
                0,
                "no_role",
                vec![Capability::CAN_OPEN_JOIN],
                vec![SingleSourceRoleChangeTargets {
                    from_role_index: 0,
                    target_role_indexes: vec![ROLE_MEMBER],
                }],
            ),
            role(1, "banned", vec![], vec![]),
            role(
                ROLE_MEMBER,
                "member",
                vec![
                    Capability::CAN_ADD_PARTICIPANT,
                    Capability::CAN_ADD_OWN_CLIENT,
                    Capability::CAN_REMOVE_OWN_CLIENT,
                    Capability::CAN_REMOVE_SELF,
                    Capability::CAN_SEND_MESSAGE,
                ],
                vec![
                    SingleSourceRoleChangeTargets {
                        from_role_index: 0,
                        target_role_indexes: vec![ROLE_MEMBER],
                    },
                    SingleSourceRoleChangeTargets {
                        from_role_index: ROLE_MEMBER,
                        target_role_indexes: vec![0],
                    },
                ],
            ),
        ],
    }
    .tls_serialize_detached()
    .unwrap()
}

/// The room's GroupContext components, ascending.
fn components(hub_key: &[u8; 32]) -> Vec<(u16, Vec<u8>)> {
    let mut components = vec![
        (APP_COMPONENTS, ROOM_APP_COMPONENTS.to_vec()),
        (SAFE_AAD, FRANK_AAD_ONLY.to_vec()),
        (FRANKING_AGENT, franking_agent(hub_key, HUB_IDENTITY)),
        (PARTICIPANT_LIST, participants(&[ALICE])),
        (ROLES_LIST, roles_list()),
        (BASE_ROOM_POLICY, base_room_policy()),
    ];
    components.sort_by_key(|(component_id, _)| *component_id);
    components
}

type Applied = Result<Option<Vec<u8>>, ErrorSource>;

/// An `apply` function whose participant list update gives `users`.
fn list_becomes(
    users: &'static [&'static [u8]],
) -> impl FnMut(u16, Option<&[u8]>, ComponentOp<'_>) -> Applied {
    move |component_id, _current, op| match (component_id, op) {
        (PARTICIPANT_LIST, ComponentOp::Update(_)) => Ok(Some(participants(users))),
        _ => Err("unexpected AppDataUpdate".into()),
    }
}

fn list_update(removed_indices: Vec<u32>, added: &[&[u8]]) -> AppDataUpdate {
    AppDataUpdate::Update {
        component_id: PARTICIPANT_LIST,
        update: ParticipantListUpdate {
            changed_role_participants: vec![],
            removed_indices,
            added_participants: added
                .iter()
                .map(|user| UserRolePair {
                    user: user.to_vec(),
                    role_index: ROLE_MEMBER,
                })
                .collect(),
        }
        .tls_serialize_detached()
        .unwrap(),
    }
}

/// `identity` encrypts `data` with a `frank_aad` item over it
/// (protocol-07 §5.4.1.1).
fn franked(identity: &Identity, member: &mut Member, data: &[u8]) -> Vec<u8> {
    let salt = mimi_mls::label::random_array::<16>().unwrap();
    let tag = franking_tag(&salt, data);
    member
        .send(identity, data, &[(FRANK_AAD, tag.to_vec())])
        .unwrap()
}

/// One JMAP account at one provider, and what it has read so far.
struct Jmap {
    http: reqwest::Client,
    api: String,
    token: String,
    account: String,
    /// The Message state read up to; `None` before the first read.
    state: Option<String>,
    /// FanoutMessages read but not yet taken.
    queue: VecDeque<FanoutMessage>,
}

impl Jmap {
    /// A new account for `user` at `provider`, with a bearer token.
    async fn open(provider: &Provider, user: &[u8]) -> Self {
        let store = &provider.stack().store;
        let account = store
            .create_account(&provider.domain, text(user), now_ms())
            .await
            .unwrap();
        let token = store.issue_token(&account, now_ms()).await.unwrap();
        Self {
            http: reqwest::Client::new(),
            api: format!(
                "{}/jmap/api",
                provider.base.to_string().trim_end_matches('/')
            ),
            token: token.expose_secret().to_owned(),
            account,
            state: None,
            queue: VecDeque::new(),
        }
    }

    /// One method call; returns the response's name and arguments.
    async fn call(&self, method: &str, mut args: Value) -> (String, Value) {
        args["accountId"] = json!(self.account);
        let body = json!({"using": USING, "methodCalls": [[method, args, "c"]]});
        let response = self
            .http
            .post(&self.api)
            .bearer_auth(&self.token)
            .header("content-type", "application/json")
            .body(body.to_string())
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200, "{method}");
        let body: Value = serde_json::from_slice(&response.bytes().await.unwrap()).unwrap();
        let call = &body["methodResponses"][0];
        (call[0].as_str().unwrap().to_owned(), call[1].clone())
    }

    /// A call that must answer under its own name, not as an error.
    async fn ok(&self, method: &str, args: Value) -> Value {
        let (name, answer) = self.call(method, args).await;
        assert_eq!(name, method, "{method} failed: {answer}");
        answer
    }

    async fn publish(&self, identity: &Identity) -> Vec<u8> {
        let key_package = identity.key_package(KeyPackageKind::OneTime).unwrap();
        let answer = self
            .ok(
                "KeyPackage/set",
                json!({"create": {"k": {"keyPackage": b64(&key_package)}}}),
            )
            .await;
        assert!(answer["created"]["k"].is_object(), "{answer}");
        key_package
    }

    /// Room/update of `request`; the hub must accept it.
    async fn update(&self, room_id: &str, request: &[u8]) {
        let answer = self
            .ok(
                "Room/update",
                json!({"roomId": room_id, "request": b64(request)}),
            )
            .await;
        assert_eq!(answer["responseCode"], "success", "{answer}");
    }

    /// Room/send of `message`; the hub must accept it.
    async fn send(&self, room_id: &str, message: &[u8]) {
        let answer = self
            .ok(
                "Room/send",
                json!({"roomId": room_id, "message": b64(message)}),
            )
            .await;
        assert_eq!(answer["responseCode"], "accepted", "{answer}");
    }

    /// Reads the Messages stored since the last read, oldest first.
    async fn read(&mut self) {
        let ids = match &self.state {
            None => Value::Null,
            Some(since) => {
                let changes = self
                    .ok("Message/changes", json!({"sinceState": since}))
                    .await;
                assert_ne!(changes["hasMoreChanges"], true, "one page is enough");
                self.state = Some(changes["newState"].as_str().unwrap().to_owned());
                let created = changes["created"].as_array().unwrap().clone();
                if created.is_empty() {
                    return;
                }
                Value::Array(created)
            }
        };
        let answer = self
            .ok("Message/get", json!({"ids": ids, "properties": ["body"]}))
            .await;
        if self.state.is_none() {
            self.state = Some(answer["state"].as_str().unwrap().to_owned());
        }
        let mut list = answer["list"].as_array().unwrap().clone();
        // Message ids are ULIDs: their order is the order of storage.
        list.sort_by(|x, y| x["id"].as_str().cmp(&y["id"].as_str()));
        for message in list {
            let body = unb64(&message["body"]);
            self.queue
                .extend(FanoutMessage::decode_all(&body).expect("a FanoutMessage body"));
        }
    }

    /// The next FanoutMessage stored for this account, waiting up to
    /// [`WAIT`] for fanout.
    async fn next(&mut self) -> FanoutMessage {
        let deadline = Instant::now() + WAIT;
        loop {
            if let Some(message) = self.queue.pop_front() {
                return message;
            }
            assert!(Instant::now() < deadline, "nothing arrived");
            self.read().await;
            if self.queue.is_empty() {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }
    }

    /// Asserts nothing more is stored for this account now.
    async fn assert_empty(&mut self) {
        self.read().await;
        assert!(self.queue.is_empty(), "unexpected: {:?}", self.queue);
    }
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

/// Asserts MLS agreement for `epoch` among a's hub and the Members.
async fn assert_agreement(hub: &Hub, room_id: &str, epoch: u64, members: &[(&Identity, &Member)]) {
    let state = hub.public_state(room_id).await.unwrap();
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
}

fn peers(other: &Provider) -> BTreeMap<Domain, BaseUrl> {
    BTreeMap::from([(other.domain.clone(), other.base.clone())])
}

#[tokio::test]
async fn two_providers_over_jmap_only() {
    let dir = tempfile::tempdir().unwrap();
    let mut a = Provider::bind("a.example", dir.path()).await;
    let mut b = Provider::bind("b.example", dir.path()).await;
    let (a_peers, b_peers) = (peers(&b), peers(&a));
    a.boot(&a_peers).await;
    b.boot(&b_peers).await;
    let hub = std::sync::Arc::clone(&a.stack().hub);

    // 1. Accounts, KeyPackages, and bob's consent for alice (sent to a).
    let mut alice_jmap = Jmap::open(&a, ALICE).await;
    let mut bob_jmap = Jmap::open(&b, BOB).await;
    let alice = Identity::generate(ALICE, memory()).unwrap();
    let bob = Identity::generate(BOB, memory()).unwrap();
    alice_jmap.publish(&alice).await;
    let bob_key_package = bob_jmap.publish(&bob).await;
    let consent = bob_jmap
        .ok(
            "Consent/set",
            json!({"create": {"c": {
                "requesterUri": text(ALICE),
                "targetUri": text(BOB),
                "decision": "grant",
            }}}),
        )
        .await;
    assert!(consent["created"]["c"].is_object(), "{consent}");

    // 2. Epoch 1: alice builds the group alone and has a host it.
    let room_id = format!(
        "mimi://a.example/r/{}",
        base32(&mimi_mls::label::random_array::<16>().unwrap())
    );
    let hub_key = *hub.signature_public_key();
    let senders = [ExternalSender {
        signature_key: hub_key.to_vec(),
        identity: HUB_IDENTITY.to_vec(),
    }];
    let group_id = mimi_mls::label::random_array::<16>().unwrap();
    let mut alice_group =
        Member::create(&alice, &group_id, &senders, &components(&hub_key)).unwrap();
    let bundle = alice_group
        .commit(&alice, &[], &[], &[], no_components)
        .unwrap();
    alice_group.merge_pending_commit(&alice).unwrap();
    let created = alice_jmap
        .ok(
            "Room/create",
            json!({
                "roomId": room_id,
                "groupInfo": b64(&bundle.group_info),
                "ratchetTree": b64(&alice_group.ratchet_tree().unwrap()),
            }),
        )
        .await;
    assert_eq!(created["roomId"], room_id.as_str());
    assert_agreement(&hub, &room_id, 1, &[(&alice, &alice_group)]).await;
    alice_jmap.assert_empty().await;

    // 3. Epoch 2: KeyMaterial/fetch at a, which asks b; then the Add.
    let request = key_packages::request(&Ask {
        requesting_user: text(ALICE),
        credential_identity: text(ALICE),
        target_user: text(BOB),
        room_id: &room_id,
        required_capabilities: NO_REQUIREMENTS,
    });
    let material = alice_jmap
        .ok(
            "KeyMaterial/fetch",
            json!({"roomId": room_id, "request": b64(&request)}),
        )
        .await;
    assert_eq!(material["userStatus"], "success", "{material}");
    assert_eq!(material["userUri"], text(BOB));
    let clients = material["clients"].as_array().unwrap();
    assert_eq!(clients.len(), 1, "{material}");
    assert_eq!(clients[0]["clientStatus"], "success");
    let key_package = unb64(&clients[0]["keyPackage"]);
    assert_eq!(key_package, bob_key_package, "served verbatim, a -> b");
    let bundle = alice_group
        .commit(
            &alice,
            &[&key_package],
            &[],
            &[list_update(vec![], &[BOB])],
            list_becomes(&[ALICE, BOB]),
        )
        .unwrap();
    alice_group.merge_pending_commit(&alice).unwrap();
    alice_jmap
        .update(
            &room_id,
            &update::commit_request(
                &bundle.commit,
                bundle.welcome.as_deref(),
                &bundle.group_info,
                &alice_group.ratchet_tree().unwrap(),
            ),
        )
        .await;
    assert_eq!(
        commit_bytes(&alice_jmap.next().await),
        bundle.commit,
        "alice's own Commit is stored for her account"
    );
    let message = bob_jmap.next().await;
    let FanoutEvent::Welcome {
        message: welcome,
        ratchet_tree_option,
    } = &message.event
    else {
        panic!("bob's first Message is not his Welcome: {message:?}");
    };
    let mut bob_group = Member::join_welcome(
        &bob,
        welcome.as_bytes(),
        Some(ratchet_tree_option.ratchet_tree().unwrap()),
    )
    .unwrap()
    .member;
    assert_agreement(
        &hub,
        &room_id,
        2,
        &[(&alice, &alice_group), (&bob, &bob_group)],
    )
    .await;

    // 4. Each sends; each reads the other's message from its own provider.
    let hello = b"hello bob, over JMAP";
    let sent = franked(&alice, &mut alice_group, hello);
    alice_jmap.send(&room_id, &sent).await;
    assert_eq!(mls_bytes(&alice_jmap.next().await), sent, "alice's own");
    assert_decrypts(&bob, &mut bob_group, &bob_jmap.next().await, ALICE, hello);
    let reply = b"hi alice, from b";
    let sent = franked(&bob, &mut bob_group, reply);
    bob_jmap.send(&room_id, &sent).await;
    assert_eq!(mls_bytes(&bob_jmap.next().await), sent, "bob's own");
    assert_decrypts(
        &alice,
        &mut alice_group,
        &alice_jmap.next().await,
        BOB,
        reply,
    );

    // 4. A silent message (draft-atwood-jmap-chat-mimi-00 §Room/send;
    // bead mimid-e64f.20): accepted and stored like any other, and the
    // recipient reads it as before (mimid has no push to skip; its
    // EventSource still reports the new state). A non-Boolean `silent` is
    // invalidArguments.
    let quiet = b"an edit, say";
    let sent = franked(&alice, &mut alice_group, quiet);
    let answer = alice_jmap
        .ok(
            "Room/send",
            json!({"roomId": room_id, "message": b64(&sent), "silent": true}),
        )
        .await;
    assert_eq!(answer["responseCode"], "accepted", "{answer}");
    assert_eq!(mls_bytes(&alice_jmap.next().await), sent, "alice's own");
    assert_decrypts(&bob, &mut bob_group, &bob_jmap.next().await, ALICE, quiet);
    let (name, refused) = alice_jmap
        .call(
            "Room/send",
            json!({"roomId": room_id, "message": b64(&sent), "silent": "yes"}),
        )
        .await;
    assert_eq!(name, "error", "{refused}");
    assert_eq!(refused["type"], "invalidArguments", "{refused}");

    // 4a. maxMlsObjectSize (bead mimid-e64f.18): a message of exactly
    // that many octets passes a's relay as a SubmitMessageRequest and
    // reaches b's /notify as a FanoutMessage, each within the protocol
    // routes' body cap; bob decrypts it. One octet more is refused by
    // Room/send itself.
    let limit = mimid_server::jmap::MAX_MLS_OBJECT_SIZE;
    // The ciphertext's overhead does not depend on the plaintext's length
    // in this range (no padding; the same length-prefix widths), so a
    // probe, never sent, measures it.
    let probe_len = limit - 4096;
    let overhead = franked(&alice, &mut alice_group, &vec![b'p'; probe_len]).len() - probe_len;
    let big = vec![b'x'; limit - overhead];
    let sent = franked(&alice, &mut alice_group, &big);
    assert_eq!(sent.len(), limit, "the message is exactly maxMlsObjectSize");
    alice_jmap.send(&room_id, &sent).await;
    assert_eq!(mls_bytes(&alice_jmap.next().await), sent, "alice's own");
    assert_decrypts(&bob, &mut bob_group, &bob_jmap.next().await, ALICE, &big);
    let (name, refused) = alice_jmap
        .call(
            "Room/send",
            json!({"roomId": room_id, "message": b64(&vec![0; limit + 1])}),
        )
        .await;
    assert_eq!(name, "error", "{refused}");
    assert_eq!(refused["type"], "invalidArguments", "{refused}");
    assert!(
        refused["description"]
            .as_str()
            .is_some_and(|d| d.contains("maxMlsObjectSize")),
        "{refused}"
    );

    // 4b. Decision mimid-1wgh.83: the operators delete messages by hand,
    // not a prefix: a's while it runs, b's while it is stopped, before it
    // starts again. A state from before is cannotCalculateChanges; read
    // from the current state, everything below goes on as before.
    let operator = |path: std::path::PathBuf| async move {
        sqlx::SqlitePool::connect_with(
            sqlx::sqlite::SqliteConnectOptions::new()
                .filename(path)
                .foreign_keys(false),
        )
        .await
        .unwrap()
    };
    let deleting = [
        "DELETE FROM follower_event WHERE seq % 2 = 0 \
         OR seq = (SELECT MAX(seq) FROM follower_event)",
        "DELETE FROM room_event WHERE seq % 2 = 1",
    ];
    let db = operator(a.path.clone()).await;
    for statement in deleting {
        sqlx::query(statement).execute(&db).await.unwrap();
    }
    db.close().await;
    b.stop().await;
    let db = operator(b.path.clone()).await;
    for statement in deleting {
        sqlx::query(statement).execute(&db).await.unwrap();
    }
    db.close().await;
    b.boot(&b_peers).await;
    for jmap in [&mut alice_jmap, &mut bob_jmap] {
        let old = jmap.state.clone().unwrap();
        let (name, refused) = jmap
            .call("Message/changes", json!({"sinceState": old}))
            .await;
        assert_eq!(name, "error", "{refused}");
        assert_eq!(refused["type"], "cannotCalculateChanges", "{refused}");
        let now = jmap.ok("Message/get", json!({"ids": []})).await;
        jmap.state = Some(now["state"].as_str().unwrap().to_owned());
    }

    // 5. Epoch 3: bob's second client joins by external Commit through b.
    let requester = Requester::new(BOB);
    let fetched = bob_jmap
        .ok(
            "GroupInfo/fetch",
            json!({"roomId": room_id, "request": b64(&requester.request(None))}),
        )
        .await;
    assert_eq!(fetched["status"], "success", "{fetched}");
    let served = group_info::open(&hub, &room_id, &requester, &unb64(&fetched["response"]));
    let bob2 = Identity::generate(BOB, memory()).unwrap();
    let join = Member::join_external(
        &bob2,
        &[&GROUP_INFO_HEADER[..], served.group_info.as_bytes()].concat(),
        served.ratchet_tree_option.ratchet_tree(),
    )
    .unwrap();
    let mut bob2_group = join.member;
    bob_jmap
        .update(
            &room_id,
            &update::commit_request(
                &join.commit_bundle.commit,
                None,
                &join.commit_bundle.group_info,
                &bob2_group.ratchet_tree().unwrap(),
            ),
        )
        .await;
    commit(
        &alice,
        &mut alice_group,
        &alice_jmap.next().await,
        no_components,
    );
    // bob's account stores the Commit once, for both his clients; the
    // first processes it, and the second, which sent it, already merged it.
    let stored = bob_jmap.next().await;
    assert_eq!(commit_bytes(&stored), join.commit_bundle.commit);
    commit(&bob, &mut bob_group, &stored, no_components);
    assert_agreement(
        &hub,
        &room_id,
        3,
        &[
            (&alice, &alice_group),
            (&bob, &bob_group),
            (&bob2, &bob2_group),
        ],
    )
    .await;

    // 6. Epoch 4: alice leaves (protocol-07 §3.5): her Remove and the
    // participant-list update, one bundle; bob commits them through b.
    let remove = alice_group.propose_self_remove(&alice).unwrap();
    let leave = alice_group
        .propose_app_data_update(&alice, &list_update(vec![0], &[]))
        .unwrap();
    alice_jmap
        .update(&room_id, &update::proposal_request(&remove, &[&leave]))
        .await;
    let own = alice_jmap.next().await;
    assert!(
        matches!(own.event, FanoutEvent::Proposal { .. }),
        "alice's own proposals: {own:?}"
    );
    let message = bob_jmap.next().await;
    let FanoutEvent::Proposal {
        message: first,
        more_proposals,
    } = &message.event
    else {
        panic!("not a proposal fanout: {message:?}");
    };
    assert_eq!(first.as_bytes(), remove);
    for (identity, group) in [(&bob, &mut bob_group), (&bob2, &mut bob2_group)] {
        for proposal in std::iter::once(first).chain(more_proposals) {
            let incoming = group.process(identity, proposal.as_bytes(), no_components);
            assert!(
                matches!(incoming, Ok(Incoming::Proposal { .. })),
                "{incoming:?}"
            );
        }
    }
    let bundle = bob_group
        .commit(&bob, &[], &[], &[], list_becomes(&[BOB]))
        .unwrap();
    bob_group.merge_pending_commit(&bob).unwrap();
    bob_jmap
        .update(
            &room_id,
            &update::commit_request(
                &bundle.commit,
                None,
                &bundle.group_info,
                &bob_group.ratchet_tree().unwrap(),
            ),
        )
        .await;
    let summary = commit(
        &alice,
        &mut alice_group,
        &alice_jmap.next().await,
        list_becomes(&[BOB]),
    );
    assert!(summary.self_removed, "alice sees her own removal");
    assert!(!alice_group.is_active());
    let stored = bob_jmap.next().await;
    assert_eq!(commit_bytes(&stored), bundle.commit);
    commit(&bob2, &mut bob2_group, &stored, list_becomes(&[BOB]));
    assert_agreement(
        &hub,
        &room_id,
        4,
        &[(&bob, &bob_group), (&bob2, &bob2_group)],
    )
    .await;
    alice_jmap.assert_empty().await;
    bob_jmap.assert_empty().await;

    // 7. alice, removed, unbinds her Chat (draft §Chat.roomId). With no
    // bound Chat her account may send only an external Commit (bead
    // mimid-1wgh.12.46): a proposal is refused before it reaches the hub.
    alice_jmap
        .ok("Room/unbind", json!({"roomId": room_id}))
        .await;
    let refused = |answer: (String, Value)| {
        assert_eq!(answer.0, "error", "{answer:?}");
        assert_eq!(answer.1["type"], "invalidArguments", "{answer:?}");
    };
    refused(
        alice_jmap
            .call(
                "Room/update",
                json!({"roomId": room_id, "request": b64(&update::proposal_request(&remove, &[]))}),
            )
            .await,
    );

    // 8. An external Commit must join as the account's own user: bob's
    // account cannot join a client whose credential names alice.
    let bob_requester = Requester::new(BOB);
    let fetched = bob_jmap
        .ok(
            "GroupInfo/fetch",
            json!({"roomId": room_id, "request": b64(&bob_requester.request(None))}),
        )
        .await;
    let served = group_info::open(&hub, &room_id, &bob_requester, &unb64(&fetched["response"]));
    let impostor = Identity::generate(ALICE, memory()).unwrap();
    let forged = Member::join_external(
        &impostor,
        &[&GROUP_INFO_HEADER[..], served.group_info.as_bytes()].concat(),
        served.ratchet_tree_option.ratchet_tree(),
    )
    .unwrap();
    refused(
        bob_jmap
            .call(
                "Room/update",
                json!({"roomId": room_id, "request": b64(&update::commit_request(
                    &forged.commit_bundle.commit,
                    None,
                    &forged.commit_bundle.group_info,
                    &forged.member.ratchet_tree().unwrap(),
                ))}),
            )
            .await,
    );

    // 9. Epoch 5: alice rejoins the open room with a new client, with no
    // bound Chat (bead mimid-1wgh.12.46): GroupInfo/fetch for a room her
    // account is not in (the hub allows it: role 0 holds canOpenJoin),
    // then an external Commit that also adds her to the participant list
    // (Member::join_external_with, bead mimid-1wgh.4.80), at a. The hub's
    // acceptance binds her Chat again.
    let requester = Requester::new(ALICE);
    let fetched = alice_jmap
        .ok(
            "GroupInfo/fetch",
            json!({"roomId": room_id, "request": b64(&requester.request(None))}),
        )
        .await;
    assert_eq!(fetched["status"], "success", "{fetched}");
    let served = group_info::open(&hub, &room_id, &requester, &unb64(&fetched["response"]));
    let alice2 = Identity::generate(ALICE, memory()).unwrap();
    let join = Member::join_external_with(
        &alice2,
        &[&GROUP_INFO_HEADER[..], served.group_info.as_bytes()].concat(),
        served.ratchet_tree_option.ratchet_tree(),
        &[list_update(vec![], &[ALICE])],
        list_becomes(&[BOB, ALICE]),
    )
    .unwrap();
    let mut alice2_group = join.member;
    alice_jmap
        .update(
            &room_id,
            &update::commit_request(
                &join.commit_bundle.commit,
                None,
                &join.commit_bundle.group_info,
                &alice2_group.ratchet_tree().unwrap(),
            ),
        )
        .await;
    // Chat.roomId is present only while the Chat is bound (draft
    // §Chat.roomId).
    let chats = alice_jmap.ok("Chat/get", json!({"ids": null})).await;
    assert!(
        chats["list"]
            .as_array()
            .unwrap()
            .iter()
            .any(|chat| chat["roomId"] == room_id.as_str()),
        "alice's Chat is bound again: {chats}"
    );
    assert_eq!(
        commit_bytes(&alice_jmap.next().await),
        join.commit_bundle.commit,
        "alice's own external Commit"
    );
    let stored = bob_jmap.next().await;
    assert_eq!(commit_bytes(&stored), join.commit_bundle.commit);
    commit(&bob, &mut bob_group, &stored, list_becomes(&[BOB, ALICE]));
    commit(&bob2, &mut bob2_group, &stored, list_becomes(&[BOB, ALICE]));
    assert_agreement(
        &hub,
        &room_id,
        5,
        &[
            (&alice2, &alice2_group),
            (&bob, &bob_group),
            (&bob2, &bob2_group),
        ],
    )
    .await;

    // bob's next message reaches alice's new client.
    let back = b"welcome back, alice";
    let sent = franked(&bob, &mut bob_group, back);
    bob_jmap.send(&room_id, &sent).await;
    assert_eq!(mls_bytes(&bob_jmap.next().await), sent, "bob's own");
    assert_decrypts(
        &alice2,
        &mut alice2_group,
        &alice_jmap.next().await,
        BOB,
        back,
    );
    alice_jmap.assert_empty().await;
    bob_jmap.assert_empty().await;
}
