//! Helpers shared by the hub integration tests: a fixed clock, hub start-up,
//! groups built by mimi-mls Members, encoders for the protocol-06
//! components, and a TRACE-level log capture for secret canaries.

use std::io::Write;
use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock};

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use mimi_mls::member::{ComponentOp, ExternalSender, Member};
use mimi_mls::tls_codec::{Deserialize, Serialize, VLBytes};
use mimi_mls::wire::{Credential, SignaturePublicKey};
use mimi_mls::{ErrorSource, Identity, KeyPackageKind};
use mimi_protocol::{FrankingAgentData, ParticipantListData, UserRolePair, component_id};
use mimi_room_policy::BaseRoomPolicy;
use mimi_room_policy::component_id::BASE_ROOM_POLICY;
use mimid_server::config::Domain;
use mimid_server::hub::{Clock, Hub};
use mimid_server::store::Store;

pub const DOMAIN: &str = "a.example";
pub const ROOM_ID: &str = "mimi://a.example/r/one";
/// [`ROOM_ID`] percent-encoded by hand (RFC 3986 §2.1; decision
/// mimid-1wgh.5.18).
pub const ROOM_ID_ENCODED: &str = "mimi%3A%2F%2Fa.example%2Fr%2Fone";
pub const ALICE: &[u8] = b"mimi://a.example/u/alice";
pub const BOB: &[u8] = b"mimi://b.example/u/bob";
/// The hub's BasicCredential identity, `mimi://<hub domain>` (decision
/// mimid-1wgh.6.35).
pub const HUB_IDENTITY: &[u8] = b"mimi://a.example";

/// A clock stuck at one instant.
pub struct FixedClock(pub u64);

impl Clock for FixedClock {
    fn now_ms(&self) -> u64 {
        self.0
    }
}

pub fn domain() -> Domain {
    Domain::try_from(DOMAIN.to_owned()).unwrap()
}

/// Opens the store at `path` and starts a hub on it.
pub async fn open_hub(path: &Path) -> (Store, Hub) {
    let store = Store::open(path, &domain()).await.unwrap();
    let hub = Hub::open(
        store.clone(),
        domain(),
        Arc::new(FixedClock(1_700_000_000_000)),
    )
    .await
    .unwrap();
    (store, hub)
}

/// Stops a hub and closes its store, as a process exit would.
pub async fn close_hub(store: Store, hub: Hub) {
    drop(hub);
    store.close().await;
}

/// An `apply` function for Commits that carry no AppDataUpdate.
pub fn no_components(
    component_id: u16,
    _current: Option<&[u8]>,
    _op: ComponentOp<'_>,
) -> Result<Option<Vec<u8>>, ErrorSource> {
    Err(format!("unexpected AppDataUpdate for {component_id:#06x}").into())
}

/// `FrankingAgentData` (protocol-06 §5.4.1) for `key`, with a
/// BasicCredential for `identity`.
pub fn franking_agent(key: &[u8; 32], identity: &[u8]) -> Vec<u8> {
    // RFC 9420 §5.1.1: opaque SignaturePublicKey<V>.
    let mut signature_key = vec![0x20];
    signature_key.extend_from_slice(key);
    // RFC 9420 §5.3: CredentialType basic (0x0001), opaque identity<V>.
    let mut credential = vec![0x00, 0x01];
    credential.push(u8::try_from(identity.len()).unwrap());
    credential.extend_from_slice(identity);
    FrankingAgentData {
        franking_signature_key: SignaturePublicKey::tls_deserialize_exact(&signature_key).unwrap(),
        credential: Credential::tls_deserialize_exact(&credential).unwrap(),
    }
    .tls_serialize_detached()
    .unwrap()
}

/// `ParticipantListData` (protocol-06 §7.5) listing `users`, all with role 0.
pub fn participant_list(users: &[&[u8]]) -> Vec<u8> {
    ParticipantListData {
        participants: users
            .iter()
            .map(|user| UserRolePair {
                user: user.to_vec(),
                role_index: 0,
            })
            .collect(),
    }
    .tls_serialize_detached()
    .unwrap()
}

/// A valid `BaseRoomPolicy` (room-policy-04 §5): open membership, multiple
/// devices, no limits. Every hosted room needs one (decision
/// mimid-1wgh.6.57).
pub fn base_room_policy() -> Vec<u8> {
    BaseRoomPolicy {
        fixed_membership: false.into(),
        parent_dependant: false.into(),
        parent_room: vec![],
        multi_device: true.into(),
        max_clients: None,
        max_users: None,
        pseudonyms_allowed: false.into(),
        persistent_room: true.into(),
        discoverable: false.into(),
        policy_component_ids: vec![],
    }
    .tls_serialize_detached()
    .unwrap()
}

/// mls-extensions-10 §4.6 `ComponentData component_data<V>`, the data of an
/// `app_data_dictionary` extension. `entries` must be in ascending order.
pub fn app_data_dictionary(entries: &[(u16, &[u8])]) -> Vec<u8> {
    let mut list = Vec::new();
    for (component_id, data) in entries {
        list.extend(component_id.to_be_bytes());
        list.extend(
            VLBytes::new(data.to_vec())
                .tls_serialize_detached()
                .unwrap(),
        );
    }
    VLBytes::new(list).tls_serialize_detached().unwrap()
}

/// What a test group's GroupContext carries.
pub struct GroupSpec {
    /// Signature keys of the `external_senders` entries.
    pub external_senders: Vec<[u8; 32]>,
    /// The BasicCredential identity of every `external_senders` entry.
    pub sender_identity: Vec<u8>,
    /// The encoded `franking_agent` component, if any.
    pub franking_agent: Option<Vec<u8>>,
    /// The encoded `participant_list` component, if any.
    pub participant_list: Option<Vec<u8>>,
    /// The encoded `base_room_policy` component, if any.
    pub base_room_policy: Option<Vec<u8>>,
}

impl GroupSpec {
    /// A spec that meets every hub rule for `hub`, listing alice and bob.
    pub fn valid_for(hub: &Hub) -> Self {
        let key = *hub.signature_public_key();
        Self {
            external_senders: vec![key],
            sender_identity: HUB_IDENTITY.to_vec(),
            franking_agent: Some(franking_agent(&key, HUB_IDENTITY)),
            participant_list: Some(participant_list(&[ALICE, BOB])),
            base_room_policy: Some(base_room_policy()),
        }
    }
}

/// A group built by mimi-mls Members, ready for `Hub::create_room`.
pub struct BuiltGroup {
    /// The epoch-1 GroupInfo MLSMessage, without a ratchet_tree extension.
    pub group_info: Vec<u8>,
    /// The epoch-1 ratchet tree, as alice's Member exports it.
    pub ratchet_tree: Vec<u8>,
}

/// alice creates `group_id` per `spec` and commits an Add of bob, giving
/// the GroupInfo and tree of epoch 1.
pub fn build_group(spec: &GroupSpec, group_id: &[u8]) -> BuiltGroup {
    let alice = Identity::generate(ALICE, mimi_mls::Store::open_in_memory().unwrap()).unwrap();
    let bob = Identity::generate(BOB, mimi_mls::Store::open_in_memory().unwrap()).unwrap();
    let senders: Vec<_> = spec
        .external_senders
        .iter()
        .map(|key| ExternalSender {
            signature_key: key.to_vec(),
            identity: spec.sender_identity.clone(),
        })
        .collect();
    let mut components = Vec::new();
    if let Some(data) = &spec.franking_agent {
        components.push((component_id::FRANKING_AGENT, data.clone()));
    }
    if let Some(data) = &spec.participant_list {
        components.push((component_id::PARTICIPANT_LIST, data.clone()));
    }
    if let Some(data) = &spec.base_room_policy {
        components.push((BASE_ROOM_POLICY, data.clone()));
    }
    let mut group = Member::create(&alice, group_id, &senders, &components).unwrap();
    let key_package = bob.key_package(KeyPackageKind::OneTime).unwrap();
    let bundle = group
        .commit(&alice, &[&key_package], &[], &[], no_components)
        .unwrap();
    group.merge_pending_commit(&alice).unwrap();
    BuiltGroup {
        group_info: bundle.group_info,
        ratchet_tree: group.ratchet_tree().unwrap(),
    }
}

/// The text of every `tracing` event, at every level, from every thread of
/// this test binary since [`capture_logs`] was first called.
pub struct CapturedLogs(Arc<Mutex<Vec<u8>>>);

impl CapturedLogs {
    pub fn contents(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
    }
}

struct CaptureWriter(Arc<Mutex<Vec<u8>>>);

impl Write for CaptureWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Installs, once per test binary, a global `tracing` subscriber at TRACE
/// that also receives `log` records, and returns its capture.
pub fn capture_logs() -> &'static CapturedLogs {
    static CAPTURE: OnceLock<CapturedLogs> = OnceLock::new();
    CAPTURE.get_or_init(|| {
        let buffer = Arc::new(Mutex::new(Vec::new()));
        let writer = Arc::clone(&buffer);
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_ansi(false)
            .with_writer(move || CaptureWriter(Arc::clone(&writer)))
            .try_init()
            .expect("no other global subscriber in this test binary");
        CapturedLogs(buffer)
    })
}

/// Asserts that `text` contains none of the usual renderings of `secret`:
/// hex in either case, the four base64 alphabets and paddings, and Rust
/// `Debug` of a byte array, with and without brackets.
pub fn assert_secret_absent(text: &str, secret: &[u8], name: &str) {
    let debug = format!("{secret:?}");
    let forms = [
        secret
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>(),
        secret
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect::<String>(),
        STANDARD.encode(secret),
        STANDARD_NO_PAD.encode(secret),
        URL_SAFE.encode(secret),
        URL_SAFE_NO_PAD.encode(secret),
        debug.trim_matches(['[', ']']).to_owned(),
        debug,
    ];
    for form in forms {
        assert!(!text.contains(&form), "{name} appears as {form:?}");
    }
}
