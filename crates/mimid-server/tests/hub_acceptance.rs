//! Hub acceptance test (bead mimid-1wgh.6.32): one room's whole life through
//! the HTTP router, with fanout delivered by the real worker to in-process
//! mock followers for b.example, c.example and d.example and to a
//! recording `LocalDelivery` for a.example.
//!
//! alice (a mimi-mls Member) creates the room; adds bob with an inline
//! participant-list update; bob joins from the fanned-out Welcome; alice
//! and bob exchange franked messages; alice adds dave, an mls-rs client;
//! dave proposes kicking bob and removing himself (the proposal arm);
//! alice's Commit covers the pending proposals; carol joins by
//! external Commit after `/groupInfo`; the hub restarts from the same
//! SQLite file with a fanout row still undelivered; alice sends and carol
//! commits; two franked messages are reported.
//!
//! Oracles:
//!
//! - MLS agreement. At every epoch every member, mimi-mls or mls-rs, has
//!   the same `epoch_authenticator` and exporter output; the hub's ratchet
//!   tree equals every member's; the hub's GroupContext is the one the
//!   committer signed in its GroupInfo and the one mls-rs computes.
//! - Fanout streams. What each provider received decodes to exactly the
//!   events the scenario predicts, written out by hand per step from
//!   decisions mimid-1wgh.6.10 and mimid-1wgh.6.17: in hub order, bytes as
//!   sent, nothing missing and nothing extra. The Commit and Welcome of one
//!   step may arrive in either order. Back-to-back deliveries of the same
//!   body (at-least-once retries) are collapsed; the scripted `503` from
//!   c.example must produce one.
//! - Franks verify with mimi-protocol's `verify_server_frank` and
//!   `Frank::verify_integrity`, and members decrypt exactly what was sent.
//! - Log canary: TRACE output for the whole run never shows the hub's
//!   secrets, the client secrets the test can reach, exporter outputs or
//!   any application plaintext. A Member's private keys are not reachable
//!   through mimi-mls's public API, so they are not checked here.

#[allow(dead_code, reason = "each test binary uses part of the helpers")]
mod common;
#[allow(dead_code, reason = "each test binary uses part of the helpers")]
#[path = "common/fanout.rs"]
mod common_fanout;
#[allow(dead_code, reason = "each test binary uses part of the helpers")]
#[path = "common/group_info.rs"]
mod group_info;
#[allow(dead_code, reason = "each test binary uses part of the helpers")]
#[path = "common/submit.rs"]
mod submit;
#[allow(dead_code, reason = "each test binary uses part of the helpers")]
#[path = "common/update.rs"]
mod update;

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode, header};
use common::{
    ALICE, BOB, DOMAIN, FixedClock, HUB_IDENTITY, ROOM_ID, ROOM_ID_ENCODED, app_data_dictionary,
    assert_secret_absent, base_room_policy, capture_logs, close_hub, domain, franking_agent,
    no_components,
};
use common_fanout::{Follower, ManualClock, RecordingLocal, Reply};
use mimi_content::{Disposition, Extensions, MimiContent, NestedPart, Part};
use mimi_mls::member::{AppDataUpdate, ComponentOp, ExternalSender, Incoming, Member};
use mimi_mls::tls_codec::{Deserialize, Serialize};
use mimi_mls::wire::{AppDataDictionary, RatchetTreeRepresentation, SignaturePublicKey};
use mimi_mls::{ErrorSource, Identity, KeyPackageKind};
use mimi_protocol::component_id::{FRANK_AAD, FRANKING_AGENT, PARTICIPANT_LIST};
use mimi_protocol::{
    AbuseReport, AbuseType, AbusiveMessage, FanoutEvent, FanoutMessage, Frank, HubKey,
    IdentifierUri, NotifyRequest, ParticipantListData, ParticipantListUpdate,
    ServerFrankingContext, SubmitMessageResponse, SubmitResult, UpdateResult, UserRolePair,
    franking_tag, verify_server_frank,
};
use mimi_room_policy::component_id::{BASE_ROOM_POLICY, ROLES_LIST};
use mimi_room_policy::{Capability, Role, RoleData, SingleSourceRoleChangeTargets};
use mimid_server::config::{BaseUrl, Domain};
use mimid_server::directory::Directory;
use mimid_server::http::router;
use mimid_server::hub::fanout::{Fanout, FanoutHandle};
use mimid_server::hub::{Hub, PublicState};
use mimid_server::peer::PeerClient;
use mimid_server::store::Store;
use mls_rs::client_builder::MlsConfig;
use mls_rs::extension::ExtensionType;
use mls_rs::group::{CommitEffect, ExportedTree, ReceivedMessage};
use mls_rs::identity::SigningIdentity;
use mls_rs::identity::basic::{BasicCredential, BasicIdentityProvider};
use mls_rs::mls_rs_codec::MlsEncode;
use mls_rs::{CipherSuite, CipherSuiteProvider, Client, CryptoProvider, Extension, ExtensionList};
use mls_rs_crypto_rustcrypto::RustCryptoProvider;
use tower::ServiceExt;
use update::CAROL;

/// The hub's clock before the restart, and after it: later, so that
/// acceptance times keep increasing.
const HUB_START_MS: u64 = 1_800_000_000_000;
const HUB_RESTART_MS: u64 = 1_850_000_000_000;
/// The fanout worker's clock, which only the test moves. It is ahead of
/// every hub time, so a new row is due at once, and a failed row waits
/// until the test moves the clock past its backoff.
const FANOUT_MS: u64 = 1_900_000_000_000;

/// Role 2: listed users may add participants and their own clients,
/// remove their own clients, kick and send.
const ROLE_MEMBER: u32 = 2;

/// A user whose client is an mls-rs client, not listed at first.
const DAVE: &[u8] = b"mimi://d.example/u/dave";

/// mls-extensions-10 §4.6 component ids `app_components` (0x0001) and
/// `safe_aad` (0x0002), and the `app_data_dictionary` extension type.
const APP_COMPONENTS: u16 = 0x0001;
const SAFE_AAD: u16 = 0x0002;
const APP_DATA_DICTIONARY: u16 = 0x0006;
/// mls-extensions-10 §5 `ComponentsList` naming `frank_aad` (0x0020),
/// hand-encoded: `component_ids<V>` of 2 bytes.
const FRANK_AAD_ONLY: [u8; 3] = [0x02, 0x00, 0x20];
/// `ComponentsList` naming `app_components`, `safe_aad` and `frank_aad`:
/// `component_ids<V>` of 6 bytes.
const MLS_RS_APP_COMPONENTS: [u8; 7] = [0x06, 0x00, 0x01, 0x00, 0x02, 0x00, 0x20];
/// mls-extensions-10 §4.9: a SafeAAD with no items, `aad_items<V>` empty.
const EMPTY_SAFE_AAD: [u8; 1] = [0x00];
/// RFC 9420 §6 MLSMessage headers: mls10 (0x0001), then the wire format.
const GROUP_INFO_HEADER: [u8; 4] = [0x00, 0x01, 0x00, 0x04];
const KEY_PACKAGE_HEADER: [u8; 4] = [0x00, 0x01, 0x00, 0x05];

const EXPORTER_LABEL: &str = "mimid acceptance";

fn dom(name: &str) -> Domain {
    Domain::try_from(name.to_owned()).unwrap()
}

fn uri(bytes: &[u8]) -> IdentifierUri {
    IdentifierUri::new(std::str::from_utf8(bytes).unwrap()).unwrap()
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
/// `frank_aad`, the hub as `franking_agent`, alice and carol listed, the
/// roles and a base policy.
fn components(hub_key: &[u8; 32]) -> Vec<(u16, Vec<u8>)> {
    let mut components = vec![
        (SAFE_AAD, FRANK_AAD_ONLY.to_vec()),
        (FRANKING_AGENT, franking_agent(hub_key, HUB_IDENTITY)),
        (PARTICIPANT_LIST, participants(&[ALICE, CAROL])),
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

/// What an `apply` function for [`Member::commit`] and [`Member::process`]
/// returns.
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

/// A MIMI content message (mimi-content-10 §4.1) from `sender` with `salt`
/// and a text body.
fn content(salt: [u8; 16], sender: &[u8], text: &str) -> Vec<u8> {
    MimiContent {
        salt,
        replaces: None,
        topic_id: vec![],
        expires: None,
        in_reply_to: None,
        mimi_extensions: Extensions {
            sender_uri: Some(String::from_utf8(sender.to_vec()).unwrap()),
            room_uri: Some(ROOM_ID.to_owned()),
            other: BTreeMap::new(),
        },
        nested_part: NestedPart {
            disposition: Disposition::RENDER,
            language: String::new(),
            part: Part::Single {
                content_type: "text/plain;charset=utf-8".to_owned(),
                content: text.as_bytes().to_vec(),
            },
        },
    }
    .encode()
    .unwrap()
}

/// An mls-rs client for dave, and its signature private key.
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

/// The leaf `app_data_dictionary` of the mls-rs client, hand-encoded
/// (mls-extensions-10 §4.6, §5): `app_components` and `safe_aad` lists, so
/// that its leaf supports the components the room requires.
fn mls_rs_leaf_extensions() -> ExtensionList {
    let mut extensions = ExtensionList::new();
    extensions.set(Extension::new(
        ExtensionType::new(APP_DATA_DICTIONARY),
        app_data_dictionary(&[
            (APP_COMPONENTS, &MLS_RS_APP_COMPONENTS),
            (SAFE_AAD, &FRANK_AAD_ONLY),
        ]),
    ));
    extensions
}

/// A fanout event reduced to the bytes the test compares.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum Seen {
    Commit {
        timestamp: u64,
        commit: Vec<u8>,
    },
    Welcome {
        timestamp: u64,
        welcome: Vec<u8>,
        tree: Vec<u8>,
    },
    Proposal {
        timestamp: u64,
        proposal: Vec<u8>,
        more: Vec<Vec<u8>>,
    },
    Application {
        timestamp: u64,
        message: Vec<u8>,
        frank: Vec<u8>,
    },
}

fn seen(message: &FanoutMessage) -> Seen {
    let timestamp = message.timestamp;
    match &message.event {
        FanoutEvent::Commit {
            message,
            external_proposals,
        } => {
            assert!(external_proposals.is_empty(), "the hub staples nothing");
            Seen::Commit {
                timestamp,
                commit: message.as_bytes().to_vec(),
            }
        }
        FanoutEvent::Welcome {
            message,
            ratchet_tree_option,
        } => {
            assert_eq!(
                ratchet_tree_option.representation(),
                RatchetTreeRepresentation::Full,
                "decision mimid-1wgh.6.12"
            );
            Seen::Welcome {
                timestamp,
                welcome: message.as_bytes().to_vec(),
                tree: ratchet_tree_option.ratchet_tree().unwrap().to_vec(),
            }
        }
        FanoutEvent::Proposal {
            message,
            more_proposals,
        } => Seen::Proposal {
            timestamp,
            proposal: message.as_bytes().to_vec(),
            more: more_proposals
                .iter()
                .map(|more| more.as_bytes().to_vec())
                .collect(),
        },
        FanoutEvent::Application { message, frank } => Seen::Application {
            timestamp,
            message: message.as_bytes().to_vec(),
            frank: frank
                .as_ref()
                .expect("decision mimid-1wgh.6.3: every message is franked")
                .tls_serialize_detached()
                .unwrap(),
        },
    }
}

/// What each destination provider received.
struct Streams {
    local: RecordingLocal,
    b: Follower,
    c: Follower,
    d: Follower,
}

impl Streams {
    /// Every `/notify` body delivered to `destination`, in order.
    fn bodies(&self, destination: &str) -> Vec<Vec<u8>> {
        let remote = |follower: &Follower, host: &str| -> Vec<Vec<u8>> {
            follower
                .received()
                .into_iter()
                .map(|received| {
                    assert_eq!(received.raw_path, format!("/v1/notify/{ROOM_ID_ENCODED}"));
                    assert_eq!(received.from, ["mimi@a.example"], "protocol-06 §4.1 From");
                    assert_eq!(received.host, [host]);
                    received.body
                })
                .collect()
        };
        match destination {
            DOMAIN => self
                .local
                .attempts()
                .into_iter()
                .map(|(room_id, body)| {
                    assert_eq!(room_id, ROOM_ID);
                    body
                })
                .collect(),
            "b.example" => remote(&self.b, "b.example"),
            "c.example" => remote(&self.c, "c.example"),
            "d.example" => remote(&self.d, "d.example"),
            other => panic!("no stream for {other}"),
        }
    }

    /// The FanoutMessages delivered to `destination`, in order, with
    /// back-to-back deliveries of the same body (at-least-once retries)
    /// collapsed, and the number collapsed.
    fn delivered(&self, destination: &str) -> (Vec<FanoutMessage>, usize) {
        let mut bodies = self.bodies(destination);
        let before = bodies.len();
        bodies.dedup();
        let collapsed = before - bodies.len();
        let messages = bodies
            .iter()
            .flat_map(|body| {
                NotifyRequest::decode(uri(ROOM_ID.as_bytes()), body)
                    .unwrap()
                    .fanout_messages
            })
            .collect();
        (messages, collapsed)
    }

    /// Waits up to ten seconds until `destination` has `count` messages.
    async fn wait(&self, destination: &str, count: usize) -> Vec<FanoutMessage> {
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let (messages, _) = self.delivered(destination);
                if messages.len() >= count {
                    return messages;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("{count} fanout messages reach {destination}"))
    }

    /// The next message on a client's own reading position.
    async fn next(&self, cursor: &mut Cursor) -> FanoutMessage {
        let mut messages = self.wait(cursor.destination, cursor.next + 1).await;
        cursor.next += 1;
        messages.swap_remove(cursor.next - 1)
    }
}

/// One client's reading position in its provider's stream.
struct Cursor {
    destination: &'static str,
    next: usize,
}

impl Cursor {
    fn at(destination: &'static str, next: usize) -> Self {
        Self { destination, next }
    }
}

/// The hub provider: store, hub and fanout worker. The test holds the
/// worker's handle, wakes it after every request, and stops it to model a
/// process exit.
struct Provider {
    store: Store,
    hub: Arc<Hub>,
    worker: FanoutHandle,
}

impl Provider {
    async fn start(
        path: &Path,
        hub_start_ms: u64,
        peers: &BTreeMap<Domain, BaseUrl>,
        local: &RecordingLocal,
        fanout_clock: &Arc<ManualClock>,
    ) -> Self {
        let store = Store::open(path, &domain()).await.unwrap();
        let worker = Fanout::new(
            store.clone(),
            domain(),
            PeerClient::new(&domain(), peers.clone()).unwrap(),
            local.clone(),
            fanout_clock.clone(),
        )
        .spawn();
        let hub = Hub::open(
            store.clone(),
            domain(),
            Arc::new(submit::SteppingClock::new(hub_start_ms)),
        )
        .await
        .unwrap();
        Self {
            store,
            hub: Arc::new(hub),
            worker,
        }
    }

    async fn stop(self) {
        self.worker.stop().await;
        let hub = Arc::into_inner(self.hub).expect("no router holds the hub");
        close_hub(self.store, hub).await;
    }

    /// POSTs `body` to the hub's `/v1/{endpoint}/{roomId}` route with
    /// `From: mimi@{from}`, then wakes the fanout worker.
    async fn post(&self, endpoint: &str, from: &str, body: Vec<u8>) -> (StatusCode, Vec<u8>) {
        let base = BaseUrl::try_from("https://a.example".to_owned()).unwrap();
        let follower = mimid_server::follower::Follower::new(
            domain(),
            self.store.clone(),
            Arc::new(FixedClock(0)),
        );
        let response = router(
            Directory::new(&base),
            Arc::clone(&self.hub),
            Arc::new(follower),
        )
        .oneshot(
            Request::post(format!("/v1/{endpoint}/{ROOM_ID_ENCODED}"))
                .header(header::FROM, format!("mimi@{from}"))
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
        let status = response.status();
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        self.worker.wake();
        (status, body.to_vec())
    }

    /// Sends an `UpdateRequest`; it must succeed. Returns the acceptance
    /// time.
    async fn update(&self, from: &str, request: Vec<u8>) -> u64 {
        let (status, body) = self.post("update", from, request).await;
        assert_eq!(status, StatusCode::OK);
        match update::response(&body) {
            (UpdateResult::Success { accepted_timestamp }, _) => accepted_timestamp,
            other => panic!("update refused: {other:?}"),
        }
    }

    /// Submits `message` from `sender`; it must be accepted with a frank,
    /// which is verified for `tag`. Returns the acceptance time and frank.
    async fn submit(
        &self,
        from: &str,
        sender: &[u8],
        message: &[u8],
        tag: &[u8; 32],
    ) -> (u64, Frank) {
        let (status, body) = self
            .post(
                "submitMessage",
                from,
                submit::submit_request(message, sender),
            )
            .await;
        assert_eq!(status, StatusCode::OK);
        let SubmitResult::Accepted {
            accepted_timestamp,
            frank: Some(frank),
        } = SubmitMessageResponse::tls_deserialize_exact(body.as_slice())
            .unwrap()
            .result
        else {
            panic!("message not accepted with a frank");
        };
        self.verify_frank(&frank, tag, sender, accepted_timestamp)
            .await;
        (accepted_timestamp, frank)
    }

    /// Checks `frank` as a receiver would (protocol-06 §5.4.1.2), with the
    /// hub's public key and the `hub_key` read back from the store.
    async fn verify_frank(
        &self,
        frank: &Frank,
        tag: &[u8; 32],
        sender: &[u8],
        accepted_timestamp: u64,
    ) {
        let context = ServerFrankingContext {
            sender_uri: uri(sender),
            room_uri: uri(ROOM_ID.as_bytes()),
            accepted_timestamp,
        };
        let secret = self.store.hub_secret().await.unwrap().unwrap();
        verify_server_frank(
            &HubKey::new(secret.hub_key),
            tag,
            &context,
            &frank.server_frank,
        )
        .unwrap();
        // RFC 9420 §5.1.1: opaque SignaturePublicKey<V>, 32 bytes.
        let key = [&[0x20][..], self.hub.signature_public_key()].concat();
        let key = SignaturePublicKey::tls_deserialize_exact(&key).unwrap();
        frank.verify_integrity(&key, &context).unwrap();
    }

    async fn state(&self) -> PublicState {
        self.hub.public_state(ROOM_ID).await.unwrap()
    }
}

/// Asserts MLS agreement for `epoch` among the hub and `members`, and that
/// the hub's GroupContext is the one in `group_info`, the GroupInfo the
/// epoch's committer signed. Returns the members' common exporter output.
fn assert_agreement(
    state: &PublicState,
    epoch: u64,
    group_info: &[u8],
    members: &[(&Identity, &Member)],
) -> Vec<u8> {
    assert_eq!(state.epoch, epoch);
    // RFC 9420 §12.4.3: a GroupInfo starts with its GroupContext.
    let body = group_info.strip_prefix(&GROUP_INFO_HEADER).unwrap();
    assert!(
        body.starts_with(&state.group_context),
        "hub GroupContext is the signed one"
    );
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
            "{name} ratchet tree"
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

/// Asserts that the mls-rs client agrees with the hub and with a Member
/// `peer` of the same epoch.
fn assert_mls_rs_agreement<C: MlsConfig>(
    state: &PublicState,
    group: &mls_rs::Group<C>,
    peer: (&Identity, &Member),
) {
    assert_eq!(group.current_epoch(), state.epoch);
    assert_eq!(group.export_tree().to_bytes().unwrap(), state.ratchet_tree);
    assert_eq!(
        group.context().mls_encode_to_vec().unwrap(),
        state.group_context
    );
    assert_eq!(
        group.epoch_authenticator().unwrap().as_bytes(),
        peer.1.epoch_authenticator()
    );
    assert_eq!(
        group
            .export_secret(EXPORTER_LABEL.as_bytes(), b"", 32)
            .unwrap()
            .as_bytes(),
        peer.1
            .export_secret(peer.0, EXPORTER_LABEL, b"", 32)
            .unwrap()
    );
}

/// Processes a Commit, proposal or application message from the fanout
/// stream.
fn process(identity: &Identity, member: &mut Member, message: &FanoutMessage) -> Incoming {
    process_with(identity, member, message, no_components)
}

/// [`process`], with `apply` for the Commit's AppDataUpdates.
fn process_with(
    identity: &Identity,
    member: &mut Member,
    message: &FanoutMessage,
    apply: impl FnMut(u16, Option<&[u8]>, ComponentOp<'_>) -> Applied,
) -> Incoming {
    let bytes = match &message.event {
        FanoutEvent::Commit { message, .. }
        | FanoutEvent::Proposal { message, .. }
        | FanoutEvent::Application { message, .. } => message.as_bytes(),
        FanoutEvent::Welcome { .. } => panic!("a Welcome is not processed"),
    };
    member.process(identity, bytes, apply).unwrap()
}

fn commit_bytes(message: &FanoutMessage) -> &[u8] {
    match &message.event {
        FanoutEvent::Commit { message, .. } => message.as_bytes(),
        other => panic!("not a Commit: {other:?}"),
    }
}

/// Decrypts an application message and checks it is `data` from `sender`
/// with the `frank_aad` item `tag`.
fn assert_decrypts(
    identity: &Identity,
    member: &mut Member,
    message: &FanoutMessage,
    sender: &[u8],
    data: &[u8],
    tag: &[u8; 32],
) {
    match process(identity, member, message) {
        Incoming::Application {
            sender_identity,
            data: got,
            safe_aad,
            ..
        } => {
            assert_eq!(sender_identity, sender);
            assert_eq!(got, data);
            assert_eq!(safe_aad, [(FRANK_AAD, tag.to_vec())]);
        }
        other => panic!("not an application message: {other:?}"),
    }
}

/// Asserts that `delivered` is exactly the `expected` steps, in order; the
/// events of one step may arrive in any order.
fn assert_stream(destination: &str, delivered: &[FanoutMessage], expected: &[Vec<Seen>]) {
    let mut got = delivered.iter().map(seen);
    for (step, events) in expected.iter().enumerate() {
        let mut want = events.clone();
        want.sort();
        let mut have: Vec<Seen> = got.by_ref().take(events.len()).collect();
        have.sort();
        assert_eq!(have, want, "{destination}, expected step {step}");
    }
    let extra: Vec<Seen> = got.collect();
    assert!(extra.is_empty(), "{destination} got more: {extra:?}");
}

/// Waits until the outbox is empty: every row was delivered.
async fn drained(store: &Store) {
    tokio::time::timeout(Duration::from_secs(10), async {
        while !store.outbox_heads().await.unwrap().is_empty() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("every fanout row delivered");
}

#[tokio::test]
async fn room_lifecycle_across_restart() {
    let logs = capture_logs();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("mimid.sqlite");
    // c.example's first delivery fails, so a row is pending at the restart.
    let streams = Streams {
        local: RecordingLocal::default(),
        b: Follower::start(&[]).await,
        c: Follower::start(&[Reply::status(503)]).await,
        d: Follower::start(&[]).await,
    };
    let peers = BTreeMap::from([
        (dom("b.example"), streams.b.base.clone()),
        (dom("c.example"), streams.c.base.clone()),
        (dom("d.example"), streams.d.base.clone()),
    ]);
    let fanout_clock = ManualClock::new(FANOUT_MS);
    let mut provider =
        Provider::start(&path, HUB_START_MS, &peers, &streams.local, &fanout_clock).await;
    let hub_key = *provider.hub.signature_public_key();
    let mut expected: BTreeMap<&str, Vec<Vec<Seen>>> = BTreeMap::new();
    let mut expect = |destinations: &[&'static str], events: Vec<Seen>| {
        for destination in destinations {
            expected
                .entry(destination)
                .or_default()
                .push(events.clone());
        }
    };
    let mut exported = Vec::new();
    let mut plaintexts = Vec::new();

    // Epoch 1: alice creates the room. create_room fans nothing out.
    let alice = Identity::generate(ALICE, mimi_mls::Store::open_in_memory().unwrap()).unwrap();
    let senders = [ExternalSender {
        signature_key: hub_key.to_vec(),
        identity: HUB_IDENTITY.to_vec(),
    }];
    let mut alice_group =
        Member::create(&alice, b"acceptance-room", &senders, &components(&hub_key)).unwrap();
    let bundle = alice_group
        .commit(&alice, &[], &[], &[], no_components)
        .unwrap();
    alice_group.merge_pending_commit(&alice).unwrap();
    provider
        .hub
        .create_room(
            ROOM_ID,
            ALICE,
            &bundle.group_info,
            &alice_group.ratchet_tree().unwrap(),
        )
        .await
        .unwrap();
    exported.push(assert_agreement(
        &provider.state().await,
        1,
        &bundle.group_info,
        &[(&alice, &alice_group)],
    ));
    let mut alice_inbox = Cursor::at(DOMAIN, 0);

    // Epoch 2: alice adds bob and lists him in the same Commit. The Commit
    // goes to a.example and b.example (decision mimid-1wgh.6.17), the
    // Welcome to b.example (decision mimid-1wgh.6.10).
    let bob = Identity::generate(BOB, mimi_mls::Store::open_in_memory().unwrap()).unwrap();
    let key_package = bob.key_package(KeyPackageKind::OneTime).unwrap();
    let bundle = alice_group
        .commit(
            &alice,
            &[&key_package],
            &[],
            &[add_participant(BOB)],
            list_becomes(&[ALICE, CAROL, BOB]),
        )
        .unwrap();
    alice_group.merge_pending_commit(&alice).unwrap();
    let tree = alice_group.ratchet_tree().unwrap();
    let timestamp = provider
        .update(
            "a.example",
            update::commit_request(
                &bundle.commit,
                bundle.welcome.as_deref(),
                &bundle.group_info,
                &tree,
            ),
        )
        .await;
    let commit = Seen::Commit {
        timestamp,
        commit: bundle.commit.clone(),
    };
    expect(&[DOMAIN], vec![commit.clone()]);
    expect(
        &["b.example"],
        vec![
            commit,
            Seen::Welcome {
                timestamp,
                welcome: bundle.welcome.clone().unwrap(),
                tree: tree.clone(),
            },
        ],
    );
    assert_eq!(
        commit_bytes(&streams.next(&mut alice_inbox).await),
        bundle.commit,
        "alice's own Commit, already merged"
    );
    let mut bob_inbox = Cursor::at("b.example", 0);
    let mut bob_group = None;
    for _ in 0..2 {
        let message = streams.next(&mut bob_inbox).await;
        match &message.event {
            FanoutEvent::Welcome {
                message,
                ratchet_tree_option,
            } => {
                let joined = Member::join_welcome(
                    &bob,
                    message.as_bytes(),
                    ratchet_tree_option.ratchet_tree(),
                )
                .unwrap();
                bob_group = Some(joined.member);
            }
            // The Commit that added bob, from before he was a member.
            FanoutEvent::Commit { message, .. } => assert_eq!(message.as_bytes(), bundle.commit),
            other => panic!("unexpected {other:?}"),
        }
    }
    let mut bob_group = bob_group.expect("bob got his Welcome");
    exported.push(assert_agreement(
        &provider.state().await,
        2,
        &bundle.group_info,
        &[(&alice, &alice_group), (&bob, &bob_group)],
    ));
    assert_eq!(
        alice_group.component(PARTICIPANT_LIST),
        Some(participants(&[ALICE, CAROL, BOB]).as_slice())
    );

    // alice and bob exchange franked messages.
    let mut franked = Vec::new();
    for (sender, identity, from, salt, text) in [
        (
            ALICE,
            &alice,
            "a.example",
            [1; 16],
            "plaintext-canary-alice-1",
        ),
        (BOB, &bob, "b.example", [2; 16], "plaintext-canary-bob-1"),
    ] {
        let data = content(salt, sender, text);
        let tag = franking_tag(&salt, &data);
        let group = if sender == ALICE {
            &mut alice_group
        } else {
            &mut bob_group
        };
        let message = group
            .send(identity, &data, &[(FRANK_AAD, tag.to_vec())])
            .unwrap();
        let (timestamp, frank) = provider.submit(from, sender, &message, &tag).await;
        expect(
            &[DOMAIN, "b.example"],
            vec![Seen::Application {
                timestamp,
                message: message.clone(),
                frank: frank.tls_serialize_detached().unwrap(),
            }],
        );
        let to_alice = streams.next(&mut alice_inbox).await;
        let to_bob = streams.next(&mut bob_inbox).await;
        if sender == ALICE {
            assert_eq!(
                process(&alice, &mut alice_group, &to_alice),
                Incoming::OwnMessage
            );
            assert_decrypts(&bob, &mut bob_group, &to_bob, ALICE, &data, &tag);
        } else {
            assert_decrypts(&alice, &mut alice_group, &to_alice, BOB, &data, &tag);
            assert_eq!(process(&bob, &mut bob_group, &to_bob), Incoming::OwnMessage);
        }
        plaintexts.push((data.clone(), text));
        franked.push(AbusiveMessage {
            message_content: data,
            frank,
            accepted_timestamp: timestamp,
        });
    }

    // Epoch 3: alice adds dave, an mls-rs client, and lists him. bob
    // follows with the same participant list update.
    let (dave_client, dave_secret) = mls_rs_dave();
    let key_package = dave_client
        .generate_key_package_message(Default::default(), mls_rs_leaf_extensions(), None)
        .unwrap()
        .to_bytes()
        .unwrap();
    let key_package = key_package.strip_prefix(&KEY_PACKAGE_HEADER).unwrap();
    let bundle = alice_group
        .commit(
            &alice,
            &[key_package],
            &[],
            &[add_participant(DAVE)],
            list_becomes(&[ALICE, CAROL, BOB, DAVE]),
        )
        .unwrap();
    alice_group.merge_pending_commit(&alice).unwrap();
    let tree = alice_group.ratchet_tree().unwrap();
    let timestamp = provider
        .update(
            "a.example",
            update::commit_request(
                &bundle.commit,
                bundle.welcome.as_deref(),
                &bundle.group_info,
                &tree,
            ),
        )
        .await;
    let commit = Seen::Commit {
        timestamp,
        commit: bundle.commit.clone(),
    };
    expect(&[DOMAIN, "b.example"], vec![commit.clone()]);
    expect(
        &["d.example"],
        vec![
            commit,
            Seen::Welcome {
                timestamp,
                welcome: bundle.welcome.clone().unwrap(),
                tree: tree.clone(),
            },
        ],
    );
    assert_eq!(
        commit_bytes(&streams.next(&mut alice_inbox).await),
        bundle.commit
    );
    let Incoming::Commit(summary) = process_with(
        &bob,
        &mut bob_group,
        &streams.next(&mut bob_inbox).await,
        list_becomes(&[ALICE, CAROL, BOB, DAVE]),
    ) else {
        panic!("bob expected alice's Commit");
    };
    assert_eq!(summary.added, [DAVE.to_vec()]);
    assert_eq!(summary.components, [PARTICIPANT_LIST]);
    let mut dave_inbox = Cursor::at("d.example", 0);
    let mut dave = None;
    for _ in 0..2 {
        let message = streams.next(&mut dave_inbox).await;
        match &message.event {
            FanoutEvent::Welcome {
                message,
                ratchet_tree_option,
            } => {
                let tree =
                    ExportedTree::from_bytes(ratchet_tree_option.ratchet_tree().unwrap()).unwrap();
                let welcome = mls_rs::MlsMessage::from_bytes(message.as_bytes()).unwrap();
                dave = Some(
                    dave_client
                        .join_group(Some(tree), &welcome, None)
                        .unwrap()
                        .0,
                );
            }
            // The Commit that added dave, from before he was a member.
            FanoutEvent::Commit { message, .. } => assert_eq!(message.as_bytes(), bundle.commit),
            other => panic!("unexpected {other:?}"),
        }
    }
    let mut dave = dave.expect("dave got his Welcome");
    let state = provider.state().await;
    exported.push(assert_agreement(
        &state,
        3,
        &bundle.group_info,
        &[(&alice, &alice_group), (&bob, &bob_group)],
    ));
    assert_mls_rs_agreement(&state, &dave, (&alice, &alice_group));

    // The proposal arm: dave proposes kicking bob's client and removing
    // his own (canKick, canRemoveOwnClient). The proposals are pending at
    // the hub, open no epoch, and go to the member domains.
    let bob_leaf = bob_group.own_leaf_index();
    let dave_leaf = dave.current_member_index();
    let kick_bob = dave
        .propose_remove(bob_leaf, EMPTY_SAFE_AAD.to_vec())
        .unwrap()
        .to_bytes()
        .unwrap();
    let remove_dave = dave
        .propose_remove(dave_leaf, EMPTY_SAFE_AAD.to_vec())
        .unwrap()
        .to_bytes()
        .unwrap();
    let timestamp = provider
        .update(
            "d.example",
            update::proposal_request(&kick_bob, &[&remove_dave]),
        )
        .await;
    expect(
        &[DOMAIN, "b.example", "d.example"],
        vec![Seen::Proposal {
            timestamp,
            proposal: kick_bob.clone(),
            more: vec![remove_dave.clone()],
        }],
    );
    assert_eq!(provider.state().await.epoch, 3, "proposals open no epoch");
    for (identity, group, inbox) in [
        (&alice, &mut alice_group, &mut alice_inbox),
        (&bob, &mut bob_group, &mut bob_inbox),
    ] {
        let message = streams.next(inbox).await;
        let FanoutEvent::Proposal {
            message: first,
            more_proposals,
        } = &message.event
        else {
            panic!("not a proposal fanout");
        };
        for proposal in std::iter::once(first).chain(more_proposals) {
            let incoming = group.process(identity, proposal.as_bytes(), no_components);
            assert!(
                matches!(incoming, Ok(Incoming::Proposal { .. })),
                "{incoming:?}"
            );
        }
    }
    let FanoutEvent::Proposal { message, .. } = streams.next(&mut dave_inbox).await.event else {
        panic!("dave expected his own proposals");
    };
    assert_eq!(message.as_bytes(), kick_bob);

    // Epoch 4: alice's Commit covers the pending proposals. bob and dave
    // still get it, though b.example and d.example have no member left
    // (decision mimid-1wgh.6.17).
    let bundle = alice_group
        .commit(&alice, &[], &[], &[], no_components)
        .unwrap();
    alice_group.merge_pending_commit(&alice).unwrap();
    let timestamp = provider
        .update(
            "a.example",
            update::commit_request(
                &bundle.commit,
                None,
                &bundle.group_info,
                &alice_group.ratchet_tree().unwrap(),
            ),
        )
        .await;
    expect(
        &[DOMAIN, "b.example", "d.example"],
        vec![Seen::Commit {
            timestamp,
            commit: bundle.commit.clone(),
        }],
    );
    assert_eq!(
        commit_bytes(&streams.next(&mut alice_inbox).await),
        bundle.commit
    );
    let Incoming::Commit(summary) =
        process(&bob, &mut bob_group, &streams.next(&mut bob_inbox).await)
    else {
        panic!("bob expected his removal");
    };
    assert!(summary.self_removed);
    let mut removed = summary.removed.clone();
    removed.sort_unstable();
    let mut both = vec![bob_leaf, dave_leaf];
    both.sort_unstable();
    assert_eq!(removed, both);
    assert!(!bob_group.is_active());
    let removal = streams.next(&mut dave_inbox).await;
    let received = dave
        .process_incoming_message(mls_rs::MlsMessage::from_bytes(commit_bytes(&removal)).unwrap())
        .unwrap();
    assert!(
        matches!(
            received,
            ReceivedMessage::Commit(ref description)
                if matches!(description.effect, CommitEffect::Removed { .. })
        ),
        "dave learns he was removed: {received:?}"
    );
    exported.push(assert_agreement(
        &provider.state().await,
        4,
        &bundle.group_info,
        &[(&alice, &alice_group)],
    ));
    assert_eq!(alice_group.members(), [(0, ALICE.to_vec())]);

    // Epoch 5: carol, listed but not a member, fetches the GroupInfo and
    // joins by external Commit. b.example and d.example get nothing more;
    // c.example, the origin and carol's provider, gets the Commit.
    let requester = group_info::Requester::new(CAROL);
    let (status, response) = provider
        .post("groupInfo", "c.example", requester.request(None))
        .await;
    assert_eq!(status, StatusCode::OK);
    let served = group_info::open(&provider.hub, ROOM_ID, &requester, &response);
    assert!(served.pending_proposals.is_empty());
    let carol = Identity::generate(CAROL, mimi_mls::Store::open_in_memory().unwrap()).unwrap();
    let join = Member::join_external(
        &carol,
        &[&GROUP_INFO_HEADER[..], served.group_info.as_bytes()].concat(),
        served.ratchet_tree_option.ratchet_tree(),
    )
    .unwrap();
    let mut carol_group = join.member;
    let join_bundle = join.commit_bundle;
    let timestamp = provider
        .update(
            "c.example",
            update::commit_request(
                &join_bundle.commit,
                None,
                &join_bundle.group_info,
                &carol_group.ratchet_tree().unwrap(),
            ),
        )
        .await;
    expect(
        &[DOMAIN, "c.example"],
        vec![Seen::Commit {
            timestamp,
            commit: join_bundle.commit.clone(),
        }],
    );
    let Incoming::Commit(_) = process(
        &alice,
        &mut alice_group,
        &streams.next(&mut alice_inbox).await,
    ) else {
        panic!("alice expected carol's external Commit");
    };
    exported.push(assert_agreement(
        &provider.state().await,
        5,
        &join_bundle.group_info,
        &[(&alice, &alice_group), (&carol, &carol_group)],
    ));

    // Restart mid-stream: c.example refused its first delivery, so its row
    // waits for its backoff. The worker and hub stop as on process exit.
    streams.c.wait_for(1).await;
    // The mock answers after signalling arrival, and the worker records the
    // attempt only after `deliver` returns, so wait for that before reading
    // the outbox. Polling on "!= 0" leaves a double count to the assert.
    // The worker logs the failure only after the attempt is committed, and
    // stopping it aborts the task, so also wait for the warning the canary
    // below requires; nothing logs it after the restart.
    tokio::time::timeout(Duration::from_secs(10), async {
        while !provider
            .store
            .outbox_heads()
            .await
            .unwrap()
            .iter()
            .any(|head| head.domain.as_str() == "c.example" && head.attempts != 0)
            || !logs.contents().contains("fanout delivery failed")
        {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("c.example delivery attempt recorded and logged within 10 s");
    let heads = provider.store.outbox_heads().await.unwrap();
    assert_eq!(heads.len(), 1, "{heads:?}");
    assert_eq!(heads[0].domain.as_str(), "c.example");
    assert_eq!(
        (heads[0].attempts, heads[0].next_attempt_at),
        (1, FANOUT_MS + 1_000)
    );
    let before = provider.state().await;
    let stored_secret = provider.store.hub_secret().await.unwrap().unwrap();
    provider.stop().await;
    provider = Provider::start(&path, HUB_RESTART_MS, &peers, &streams.local, &fanout_clock).await;
    assert_eq!(provider.state().await, before, "rebuilt byte-identically");
    assert_eq!(*provider.hub.signature_public_key(), hub_key);
    let heads = provider.store.outbox_heads().await.unwrap();
    assert_eq!(
        (heads.len(), heads[0].attempts, heads[0].next_attempt_at),
        (1, 1, FANOUT_MS + 1_000),
        "the pending row survived"
    );
    fanout_clock.set(FANOUT_MS + 1_000);
    provider.worker.wake();
    let mut carol_inbox = Cursor::at("c.example", 0);
    assert_eq!(
        commit_bytes(&streams.next(&mut carol_inbox).await),
        join_bundle.commit,
        "carol's own Commit, delivered after the restart"
    );

    // alice sends after the restart; carol reads it.
    let salt = [3; 16];
    let text = "plaintext-canary-alice-2";
    let data = content(salt, ALICE, text);
    let tag = franking_tag(&salt, &data);
    let message = alice_group
        .send(&alice, &data, &[(FRANK_AAD, tag.to_vec())])
        .unwrap();
    let (timestamp, frank) = provider.submit("a.example", ALICE, &message, &tag).await;
    assert!(timestamp >= HUB_RESTART_MS);
    expect(
        &[DOMAIN, "c.example"],
        vec![Seen::Application {
            timestamp,
            message: message.clone(),
            frank: frank.tls_serialize_detached().unwrap(),
        }],
    );
    assert_eq!(
        process(
            &alice,
            &mut alice_group,
            &streams.next(&mut alice_inbox).await
        ),
        Incoming::OwnMessage
    );
    assert_decrypts(
        &carol,
        &mut carol_group,
        &streams.next(&mut carol_inbox).await,
        ALICE,
        &data,
        &tag,
    );
    plaintexts.push((data.clone(), text));
    franked.push(AbusiveMessage {
        message_content: data,
        frank,
        accepted_timestamp: timestamp,
    });

    // Epoch 6: carol commits (an UpdatePath only); alice follows.
    let bundle = carol_group
        .commit(&carol, &[], &[], &[], no_components)
        .unwrap();
    carol_group.merge_pending_commit(&carol).unwrap();
    let timestamp = provider
        .update(
            "c.example",
            update::commit_request(
                &bundle.commit,
                None,
                &bundle.group_info,
                &carol_group.ratchet_tree().unwrap(),
            ),
        )
        .await;
    expect(
        &[DOMAIN, "c.example"],
        vec![Seen::Commit {
            timestamp,
            commit: bundle.commit.clone(),
        }],
    );
    let Incoming::Commit(_) = process(
        &alice,
        &mut alice_group,
        &streams.next(&mut alice_inbox).await,
    ) else {
        panic!("alice expected carol's Commit");
    };
    assert_eq!(
        commit_bytes(&streams.next(&mut carol_inbox).await),
        bundle.commit
    );
    exported.push(assert_agreement(
        &provider.state().await,
        6,
        &bundle.group_info,
        &[(&alice, &alice_group), (&carol, &carol_group)],
    ));

    // reportAbuse: bob reports alice's first message, franked before the
    // restart, and carol the one after it. Both are accepted (decision
    // mimid-1wgh.6.65: 200, empty body).
    for (reporter, from, message) in [
        (BOB, "b.example", franked[0].clone()),
        (CAROL, "c.example", franked[2].clone()),
    ] {
        let report = AbuseReport {
            reporting_user: uri(reporter),
            alleged_abuser_uri: uri(ALICE),
            reason_code: AbuseType::RESERVED,
            note: vec![],
            messages: vec![message],
            // mls-extensions-10 §4.6: an empty ComponentData list.
            abuse_extensions: AppDataDictionary::tls_deserialize_exact([0x00]).unwrap(),
        }
        .tls_serialize_detached()
        .unwrap();
        let (status, body) = provider.post("reportAbuse", from, report).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.is_empty(), "protocol-06 §5.9: no response body");
    }

    // Every provider received exactly its predicted stream.
    drained(&provider.store).await;
    for destination in [DOMAIN, "b.example", "c.example", "d.example"] {
        let (delivered, collapsed) = streams.delivered(destination);
        assert_stream(destination, &delivered, &expected[destination]);
        if destination == "c.example" {
            assert!(collapsed >= 1, "the 503 was retried with the same body");
        }
    }

    // The log canary, over the whole run.
    let text = logs.contents();
    for line in [
        "room created",
        "commit accepted",
        "application message accepted",
        "GroupInfo served",
        "abuse report accepted",
        "hub rooms rebuilt",
        "fanout delivery failed",
    ] {
        assert!(text.contains(line), "the capture holds {line:?}");
    }
    assert_secret_absent(
        &text,
        &stored_secret.signature_private_key,
        "hub signing key",
    );
    assert_secret_absent(&text, &stored_secret.hub_key, "hub_key");
    assert_secret_absent(&text, &dave_secret, "mls-rs client signing key");
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
    for secret in &exported {
        assert_secret_absent(&text, secret, "exporter output");
    }
    for (data, canary) in &plaintexts {
        assert_secret_absent(&text, data, "application plaintext");
        assert!(!text.contains(canary), "plaintext {canary:?} logged");
    }

    provider.stop().await;
}
