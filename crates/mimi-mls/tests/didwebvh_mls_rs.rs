//! The `did_webvh` credential checked by an independent MLS implementation,
//! mls-rs at the pinned commit (decision mimid-1wgh.4.13), bead
//! mimid-4lp4.2.
//!
//! First, the wire: mls-rs decodes a mimi-mls KeyPackage carrying the
//! credential, re-encodes it byte for byte, and sees a custom credential of
//! type 0x0008 whose data is the draft's DIDWebVHCredential. This is the
//! encoding of decision mimid-1wgh.4.81.8: the structure inside one
//! `opaque<V>`, the only shape mls-rs (and OpenMLS) can carry.
//!
//! Then groups: an mls-rs member (BasicCredential) shares a group with a
//! mimid user, Alice, who has two `did_webvh` devices. Stock mls-rs refuses
//! two leaves with the same identity (`DuplicateLeafData`), so the mls-rs
//! side runs an `IdentityProvider` written here, the one an mls-rs
//! application would write for this draft: it accepts credential type
//! 0x0008, verifies the log and the binding of the leaf's `signature_key`
//! with `mls_didwebvh` (which has no OpenMLS dependency), and gives each
//! device its own identity, the SCID plus the signature key.
//!
//! mls-rs has no AppDataUpdate (mls-extensions-11 §4.7), and mimid carries
//! the `did_webvh_heads` record as an `app_data_dictionary` component
//! changed only by AppDataUpdate (decisions mimid-1wgh.4.81.33,
//! mimid-1wgh.4.81.34). The last tests measure what happens when a Commit
//! has to change the record: mimid removes, in the same Commit, every
//! member whose leaf does not list AppDataUpdate (decision
//! mimid-1wgh.4.81.37), which mls-extensions-11 §4.7 allows, and mls-rs
//! cannot parse that Commit.
//!
//! Oracles: both stacks must derive the same `epoch_authenticator` and
//! exporter secret; mls-rs must accept or refuse as its own code decides;
//! the GroupContext bytes mls-rs holds are compared with hand-encoded
//! mls-extensions-11 §4.6 / §5 values; who is a member, and which SCID and
//! keys the record holds, follow from the keys the test put into each log.

use mimi_mls::didwebvh::DidWebvhError;
use mimi_mls::member::{ComponentOp, Incoming, Member, MemberError};
use mimi_mls::mls_didwebvh::controller::{DidLog, Parameters, UpdateKey};
use mimi_mls::mls_didwebvh::rules::RuleError;
use mimi_mls::mls_didwebvh::{
    CodePoints, DidWebvhCredential, DidWebvhHead, DidWebvhHeads, PublicKey, verify_credential,
};
use mimi_mls::{ErrorSource, Identity, KeyPackageKind, Store};
use mls_rs::client_builder::MlsConfig;
use mls_rs::error::{IntoAnyError, MlsError};
use mls_rs::extension::ExtensionType;
use mls_rs::extension::built_in::RequiredCapabilitiesExt;
use mls_rs::group::proposal::{Proposal, ProposalType};
use mls_rs::group::{CommitEffect, ExportedTree, ReceivedMessage};
use mls_rs::identity::basic::BasicCredential;
use mls_rs::identity::{Credential, CredentialType, SigningIdentity};
use mls_rs::mls_rs_codec::MlsDecode;
use mls_rs::time::MlsTime;
use mls_rs::{
    CipherSuite, CipherSuiteProvider, Client, CryptoProvider, Extension, ExtensionList,
    IdentityProvider, MlsMessage,
};
use mls_rs_crypto_rustcrypto::RustCryptoProvider;

const CP: CodePoints = CodePoints::DEFAULT;

/// RFC 9420 §17.1: ciphersuite 0x0001.
const SUITE_1: CipherSuite = CipherSuite::CURVE25519_AES128;

/// mls-extensions-11 §7.1.1: app_data_dictionary extension type.
const APP_DATA_DICTIONARY: ExtensionType = ExtensionType::new(0x0006);

/// draft-atwood-mls-didwebvh-credential: the `did_webvh` credential type,
/// mimid's default code point (decision mimid-1wgh.4.81.35).
const DID_WEBVH: u16 = 0x0008;

/// mimid's default `did_webvh_heads` component id, private use
/// (mls-extensions-11 §7.5; decision mimid-1wgh.4.81.35).
const HEADS_COMPONENT: u16 = 0xf013;

/// mls-extensions-11 §7.2: AppDataUpdate proposal type.
const APP_DATA_UPDATE: u16 = 0x0008;

/// mls-extensions-11 §7.5: the app_components component.
const APP_COMPONENTS: u16 = 0x0001;

/// mls-extensions-11 §4.6 AppDataDictionary for the mls-rs LeafNode,
/// hand-encoded: its `app_components` list names the record component,
/// which the GroupContext's list names (mls-extensions-11 §5).
const LEAF_LISTS_HEADS: [u8; 7] = [
    0x06, // ComponentData component_data<V>: 6 bytes
    0x00, 0x01, // component_id = app_components
    0x03, // opaque data<V>: 3 bytes
    0x02, //   ComponentsList.component_ids<V>: 2 bytes
    0xf0, 0x13, //   did_webvh_heads
];

const EXPORTER_LABEL: &str = "mimid did_webvh mls-rs";
const EXPORTER_CONTEXT: &[u8] = b"context";

fn device() -> Identity {
    Identity::generate(b"unset", Store::open_in_memory().expect("store")).expect("identity")
}

fn key(identity: &Identity) -> PublicKey {
    identity
        .signature_public_key()
        .try_into()
        .expect("Ed25519 key")
}

fn no_components(
    component_id: u16,
    _current: Option<&[u8]>,
    _op: ComponentOp<'_>,
) -> Result<Option<Vec<u8>>, ErrorSource> {
    Err(format!("unexpected AppDataUpdate for {component_id:#06x}").into())
}

/// A one-entry log for `name` listing `devices`.
fn log(name: &str, seed: u8, devices: &[PublicKey]) -> DidLog {
    let update = UpdateKey::from_seed(&[seed; 32]);
    DidLog::create(
        "example.com",
        name,
        "2026-11-20T11:00:00Z",
        &Parameters {
            update_keys: Some(vec![update.multikey()]),
            next_key_hashes: None,
        },
        &update,
        devices,
    )
    .expect("log")
}

// ---- The mls-rs application's identity provider ----

/// Why the provider refuses a credential.
#[derive(Debug)]
struct Refused(String);

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

/// What an mls-rs application would plausibly write to admit
/// `did_webvh` leaves: BasicCredential as `BasicIdentityProvider` does it,
/// and credential type 0x0008 with the log verified and the leaf's
/// `signature_key` authorized by the head (§Log Verification, §Binding to
/// the LeafNode).
///
/// `identity` is what mls-rs indexes leaves by and must be unique per leaf
/// (mls-rs `tree_index.rs`). With `per_device`, a `did_webvh` leaf's
/// identity is its SCID plus its signature key; without, it is the SCID
/// alone, the draft's "the SCID of the log is the credential's identity"
/// read literally.
#[derive(Clone, Copy, Debug)]
struct DidWebvhIdentityProvider {
    per_device: bool,
}

impl DidWebvhIdentityProvider {
    /// The verified log of a `did_webvh` credential, bound to the leaf's key.
    fn verified(
        signing_identity: &SigningIdentity,
    ) -> Result<mimi_mls::mls_didwebvh::VerifiedLog, Refused> {
        let Credential::Custom(custom) = &signing_identity.credential else {
            return Err(Refused("not a custom credential".into()));
        };
        if custom.credential_type.raw_value() != DID_WEBVH {
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
        Ok(log)
    }

    fn check(signing_identity: &SigningIdentity) -> Result<(), Refused> {
        match &signing_identity.credential {
            Credential::Basic(_) => Ok(()),
            _ => Self::verified(signing_identity).map(|_| ()),
        }
    }
}

impl IdentityProvider for DidWebvhIdentityProvider {
    type Error = Refused;

    fn validate_member(
        &self,
        signing_identity: &SigningIdentity,
        _timestamp: Option<MlsTime>,
        _context: mls_rs_core::identity::MemberValidationContext<'_>,
    ) -> Result<(), Self::Error> {
        Self::check(signing_identity)
    }

    fn validate_external_sender(
        &self,
        signing_identity: &SigningIdentity,
        _timestamp: Option<MlsTime>,
        _extensions: Option<&ExtensionList>,
    ) -> Result<(), Self::Error> {
        // §Binding to the LeafNode: no did_webvh credential in
        // external_senders.
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
        if let Credential::Basic(basic) = &signing_identity.credential {
            let mut id = b"basic:".to_vec();
            id.extend_from_slice(&basic.identifier);
            return Ok(id);
        }
        let log = Self::verified(signing_identity)?;
        let mut id = b"did_webvh:".to_vec();
        id.extend_from_slice(log.scid().as_bytes());
        if self.per_device {
            id.push(b'/');
            id.extend_from_slice(signing_identity.signature_key.as_bytes());
        }
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
        vec![CredentialType::BASIC, CredentialType::new(DID_WEBVH)]
    }
}

// ---- mls-rs helpers ----

/// An mls-rs client with a BasicCredential, the provider above, and
/// app_data_dictionary accepted as an extension type (mls-rs keeps it
/// opaque). With `claims_app_data_update`, its capabilities also list the
/// AppDataUpdate proposal type, which mls-rs cannot process.
fn mls_rs_client(
    name: &[u8],
    provider: DidWebvhIdentityProvider,
    claims_app_data_update: bool,
) -> Client<impl MlsConfig + use<>> {
    let crypto = RustCryptoProvider::default();
    let suite = crypto.cipher_suite_provider(SUITE_1).expect("suite 1");
    let (secret, public) = suite.signature_key_generate().expect("key");
    let signing_identity = SigningIdentity::new(
        BasicCredential::new(name.to_vec()).into_credential(),
        public,
    );
    Client::builder()
        .identity_provider(provider)
        .crypto_provider(crypto)
        .extension_type(APP_DATA_DICTIONARY)
        .custom_proposal_types(claims_app_data_update.then_some(ProposalType::new(APP_DATA_UPDATE)))
        .signing_identity(signing_identity, secret, SUITE_1)
        .build()
}

/// The bare KeyPackage of an mls-rs client whose leaf lists the record
/// component.
fn mls_rs_key_package(client: &Client<impl MlsConfig>) -> Vec<u8> {
    let mut leaf = ExtensionList::new();
    leaf.set(Extension::new(
        APP_DATA_DICTIONARY,
        LEAF_LISTS_HEADS.to_vec(),
    ));
    let bytes = client
        .generate_key_package_message(Default::default(), leaf, None)
        .expect("mls-rs KeyPackage")
        .to_bytes()
        .expect("encode");
    // RFC 9420 §6: version mls10, wire_format mls_key_package.
    assert_eq!(bytes[..4], [0x00, 0x01, 0x00, 0x05]);
    bytes[4..].to_vec()
}

/// RFC 9420 §6: wraps a bare KeyPackage in an MLSMessage.
fn key_package_message(key_package: &[u8]) -> MlsMessage {
    let mut bytes = vec![0x00, 0x01, 0x00, 0x05];
    bytes.extend_from_slice(key_package);
    MlsMessage::from_bytes(&bytes).expect("mls-rs decodes the KeyPackage")
}

fn assert_same_secrets(
    member: &Member,
    identity: &Identity,
    group: &mls_rs::Group<impl MlsConfig>,
) {
    assert_eq!(member.epoch(), group.current_epoch());
    assert_eq!(
        member.epoch_authenticator(),
        group.epoch_authenticator().expect("mls-rs").as_bytes(),
        "epoch_authenticator differs"
    );
    let ours = member
        .export_secret(identity, EXPORTER_LABEL, EXPORTER_CONTEXT, 32)
        .expect("export");
    let theirs = group
        .export_secret(EXPORTER_LABEL.as_bytes(), EXPORTER_CONTEXT, 32)
        .expect("mls-rs export");
    assert_eq!(ours, theirs.as_bytes(), "exporter secret differs");
}

fn mls_rs_receive(group: &mut mls_rs::Group<impl MlsConfig>, bytes: &[u8]) -> ReceivedMessage {
    let message = MlsMessage::from_bytes(bytes).expect("mls-rs decodes the message");
    group
        .process_incoming_message(message)
        .expect("mls-rs accepts the message")
}

fn mls_rs_data(received: ReceivedMessage) -> Vec<u8> {
    match received {
        ReceivedMessage::ApplicationMessage(description) => description.data().to_vec(),
        other => panic!("expected an application message, got {other:?}"),
    }
}

fn mimi_data(incoming: Incoming) -> (u32, Vec<u8>) {
    match incoming {
        Incoming::Application { sender, data, .. } => (sender, data),
        other => panic!("expected an application message, got {other:?}"),
    }
}

/// The entries of a TLS-encoded AppDataDictionary (mls-extensions-11
/// §4.6), parsed here rather than by the code under test. Only one- and
/// two-byte varint lengths, which is all these small groups produce.
fn dictionary_entries(bytes: &[u8]) -> Vec<(u16, Vec<u8>)> {
    fn varint(bytes: &[u8]) -> (usize, usize) {
        match bytes[0] >> 6 {
            0 => (usize::from(bytes[0]), 1),
            1 => (usize::from(bytes[0] & 0x3f) << 8 | usize::from(bytes[1]), 2),
            _ => panic!("length too large for this test"),
        }
    }
    let (total, at) = varint(bytes);
    assert_eq!(at + total, bytes.len(), "trailing bytes");
    let mut rest = &bytes[at..];
    let mut entries = Vec::new();
    while !rest.is_empty() {
        let id = u16::from_be_bytes([rest[0], rest[1]]);
        let (len, prefix) = varint(&rest[2..]);
        let start = 2 + prefix;
        entries.push((id, rest[start..start + len].to_vec()));
        rest = &rest[start + len..];
    }
    entries
}

/// Alice's two devices, both carrying one log.
struct Alice {
    log: DidLog,
    d1: Identity,
    d2: Identity,
}

fn alice() -> Alice {
    let mut d1 = device();
    let mut d2 = device();
    // One log entry lists both devices, so adding device 2 does not change
    // the record.
    let log = log("alice", 3, &[key(&d1), key(&d2)]);
    d1.set_did_webvh_credential(CP, log.credential().expect("credential"))
        .expect("d1");
    d2.set_did_webvh_credential(CP, log.credential().expect("credential"))
        .expect("d2");
    Alice { log, d1, d2 }
}

/// Device 1 creates the group and, in one Commit, adds the mls-rs member
/// Bob and device 2; both join from the Welcome. Leaves: d1 = 0, Bob = 1,
/// d2 = 2. Bob's client is returned, and his join as mls-rs decided it.
fn room(
    alice: &Alice,
    provider: DidWebvhIdentityProvider,
    claims_app_data_update: bool,
) -> (
    Member,
    Member,
    Client<impl MlsConfig + use<>>,
    Result<mls_rs::Group<impl MlsConfig + use<>>, MlsError>,
) {
    let mut a1 = Member::create(&alice.d1, b"room", &[], &[]).expect("create");
    let bob_client = mls_rs_client(b"bob", provider, claims_app_data_update);
    let bob_kp = mls_rs_key_package(&bob_client);
    let d2_kp = alice
        .d2
        .key_package(KeyPackageKind::OneTime)
        .expect("d2 kp");
    let heads_before = a1.component(HEADS_COMPONENT).expect("record").to_vec();
    let bundle = a1
        .commit(&alice.d1, &[&bob_kp, &d2_kp], &[], &[], no_components)
        .expect("add bob and d2");
    a1.merge_pending_commit(&alice.d1).expect("merge");
    // Device 2's log is the recorded one: the Commit changes no record.
    assert_eq!(a1.component(HEADS_COMPONENT), Some(heads_before.as_slice()));
    let tree = a1.ratchet_tree().expect("tree");
    let welcome = bundle.welcome.expect("Welcome");
    let a2 = Member::join_welcome(&alice.d2, &welcome, Some(&tree))
        .expect("d2 joins")
        .member;
    let bob = bob_client
        .join_group(
            Some(ExportedTree::from_bytes(&tree).expect("tree")),
            &MlsMessage::from_bytes(&welcome).expect("Welcome"),
            None,
        )
        .map(|(group, _)| group);
    (a1, a2, bob_client, bob)
}

/// Carol: a new `did_webvh` user with one device.
fn carol() -> (DidLog, Identity) {
    let mut carol = device();
    let carol_log = log("carol", 7, &[key(&carol)]);
    carol
        .set_did_webvh_credential(CP, carol_log.credential().expect("credential"))
        .expect("carol");
    (carol_log, carol)
}

// ---- Tests ----

#[test]
fn mls_rs_reads_the_did_webvh_credential() {
    let mut identity = device();
    let log = log("alice", 3, &[key(&identity)]);
    let credential = log.credential().expect("credential");
    identity
        .set_did_webvh_credential(CP, credential.clone())
        .expect("set");
    let key_package = identity
        .key_package(KeyPackageKind::OneTime)
        .expect("KeyPackage");

    let mut wrapped = vec![0x00, 0x01, 0x00, 0x05];
    wrapped.extend_from_slice(&key_package);
    let message = MlsMessage::from_bytes(&wrapped).expect("mls-rs decodes");
    assert_eq!(message.to_bytes().expect("re-encode"), wrapped);
    let parsed = message.into_key_package().expect("a KeyPackage");
    let Credential::Custom(custom) = &parsed.signing_identity().credential else {
        panic!(
            "not a custom credential: {:?}",
            parsed.signing_identity().credential
        );
    };
    assert_eq!(custom.credential_type.raw_value(), DID_WEBVH);
    let inner = DidWebvhCredential::decode(&custom.data).expect("DIDWebVHCredential");
    assert_eq!(inner, credential);
    assert_eq!(inner.did_log(), log.did_log().as_slice());
    assert!(inner.witness_file().is_empty());
}

/// The answer to bead mimid-4lp4.2: with a per-device identity provider,
/// an mls-rs member shares a group with both of Alice's `did_webvh`
/// devices, exchanges messages with each, and processes a mimid Commit;
/// mimid processes an mls-rs Commit.
#[test]
fn an_mls_rs_member_shares_a_group_with_a_two_device_did_webvh_user() {
    let alice = alice();
    let provider = DidWebvhIdentityProvider { per_device: true };
    let (mut a1, mut a2, _, bob) = room(&alice, provider, false);
    let mut bob = bob.expect("mls-rs joins with two leaves of one SCID");
    assert_same_secrets(&a1, &alice.d1, &bob);
    assert_same_secrets(&a2, &alice.d2, &bob);

    // mls-rs sees both devices as custom 0x0008 credentials of one SCID,
    // with distinct identities.
    let scid = alice.log.verified().scid().to_owned();
    let mut identities = Vec::new();
    for (index, device) in [(0, &alice.d1), (2, &alice.d2)] {
        let member = bob.member_at_index(index).expect("device leaf");
        assert_eq!(
            member.signing_identity.signature_key.as_bytes(),
            device.signature_public_key()
        );
        let Credential::Custom(custom) = &member.signing_identity.credential else {
            panic!("not custom: {:?}", member.signing_identity.credential);
        };
        assert_eq!(custom.credential_type.raw_value(), DID_WEBVH);
        let id = provider
            .identity(&member.signing_identity, &ExtensionList::new())
            .expect("identity");
        assert!(id.starts_with(format!("did_webvh:{scid}/").as_bytes()));
        identities.push(id);
    }
    assert_ne!(identities[0], identities[1]);

    // mimid sees the same: two did_webvh leaves with Alice's SCID.
    assert_eq!(
        a1.did_webvh_members(&alice.d1),
        vec![(0, scid.clone()), (2, scid.clone())]
    );

    // The GroupContext as mls-rs holds it: app_components names the record
    // component (mls-extensions-11 §5), and the record holds Alice's head,
    // authorizing exactly her two device keys.
    let dictionary = &bob
        .context()
        .extensions
        .get(APP_DATA_DICTIONARY)
        .expect("app_data_dictionary")
        .extension_data;
    let entries = dictionary_entries(dictionary);
    assert_eq!(entries.len(), 2);
    assert_eq!(
        entries[0],
        (
            APP_COMPONENTS,
            vec![
                0x02, // ComponentsList.component_ids<V>: 2 bytes
                0xf0, 0x13, // did_webvh_heads
            ]
        )
    );
    assert_eq!(entries[1].0, HEADS_COMPONENT);
    let heads = DidWebvhHeads::decode(&entries[1].1).expect("DIDWebVHHeads");
    assert_eq!(heads.heads().len(), 1);
    let head = heads.get(&scid).expect("Alice's entry");
    let mut keys = vec![
        alice.d1.signature_public_key().to_vec(),
        alice.d2.signature_public_key().to_vec(),
    ];
    keys.sort();
    let recorded: Vec<Vec<u8>> = head.authorized_keys().iter().map(|k| k.to_vec()).collect();
    assert_eq!(recorded, keys);

    // Application messages: each device to Bob, Bob to each device.
    for (member, identity, text) in [
        (&mut a1, &alice.d1, b"from d1".as_slice()),
        (&mut a2, &alice.d2, b"from d2".as_slice()),
    ] {
        let message = member.send(identity, text, &[]).expect("send");
        assert_eq!(mls_rs_data(mls_rs_receive(&mut bob, &message)), text);
    }
    let message = bob
        .encrypt_application_message(b"from bob", Vec::new())
        .expect("mls-rs encrypts")
        .to_bytes()
        .expect("encode");
    for (member, identity) in [(&mut a1, &alice.d1), (&mut a2, &alice.d2)] {
        let (sender, data) = mimi_data(
            member
                .process(identity, &message, no_components)
                .expect("process"),
        );
        assert_eq!((sender, data.as_slice()), (1, b"from bob".as_slice()));
    }

    // A Commit by device 2 (an UpdatePath, no record change).
    let bundle = a2
        .commit(&alice.d2, &[], &[], &[], no_components)
        .expect("d2 commits");
    a2.merge_pending_commit(&alice.d2).expect("merge");
    a1.process(&alice.d1, &bundle.commit, no_components)
        .expect("d1 processes");
    let ReceivedMessage::Commit(_) = mls_rs_receive(&mut bob, &bundle.commit) else {
        panic!("mls-rs expected a Commit");
    };
    assert_same_secrets(&a1, &alice.d1, &bob);
    assert_same_secrets(&a2, &alice.d2, &bob);

    // A Commit by mls-rs (an UpdatePath).
    let output = bob.commit(Vec::new()).expect("mls-rs commits");
    bob.apply_pending_commit().expect("apply");
    let commit = output.commit_message.to_bytes().expect("encode");
    for (member, identity) in [(&mut a1, &alice.d1), (&mut a2, &alice.d2)] {
        let incoming = member
            .process(identity, &commit, no_components)
            .expect("mimid processes the mls-rs Commit");
        assert!(matches!(incoming, Incoming::Commit(_)), "{incoming:?}");
    }
    assert_same_secrets(&a1, &alice.d1, &bob);
    assert_same_secrets(&a2, &alice.d2, &bob);
}

/// mls-rs adds Alice's second device itself. Its log is the recorded one,
/// so the Commit needs no record change and mimid accepts it.
#[test]
fn mls_rs_adds_the_second_device() {
    let alice = alice();
    let mut a1 = Member::create(&alice.d1, b"room", &[], &[]).expect("create");
    let bob_client = mls_rs_client(b"bob", DidWebvhIdentityProvider { per_device: true }, false);
    let bundle = a1
        .commit(
            &alice.d1,
            &[&mls_rs_key_package(&bob_client)],
            &[],
            &[],
            no_components,
        )
        .expect("add bob");
    a1.merge_pending_commit(&alice.d1).expect("merge");
    let tree = a1.ratchet_tree().expect("tree");
    let (mut bob, _) = bob_client
        .join_group(
            Some(ExportedTree::from_bytes(&tree).expect("tree")),
            &MlsMessage::from_bytes(&bundle.welcome.expect("Welcome")).expect("Welcome"),
            None,
        )
        .expect("bob joins");

    let output = bob
        .commit_builder()
        .add_member(key_package_message(
            &alice.d2.key_package(KeyPackageKind::OneTime).expect("kp"),
        ))
        .expect("mls-rs admits device 2")
        .build()
        .expect("mls-rs commits");
    bob.apply_pending_commit().expect("apply");
    let incoming = a1
        .process(
            &alice.d1,
            &output.commit_message.to_bytes().expect("encode"),
            no_components,
        )
        .expect("mimid accepts the mls-rs Add of device 2");
    assert!(matches!(incoming, Incoming::Commit(_)), "{incoming:?}");
    let a2 = Member::join_welcome(
        &alice.d2,
        &output.welcome_messages[0].to_bytes().expect("encode"),
        None,
    )
    .expect("d2 joins from the mls-rs Welcome")
    .member;
    assert_same_secrets(&a1, &alice.d1, &bob);
    assert_same_secrets(&a2, &alice.d2, &bob);
    let scid = alice.log.verified().scid().to_owned();
    assert_eq!(
        a2.did_webvh_members(&alice.d2),
        vec![(0, scid.clone()), (2, scid)]
    );
}

/// The draft's "the SCID of the log is the credential's identity", used as
/// the mls-rs identity, makes mls-rs refuse the second device exactly as it
/// refuses two BasicCredentials with one name.
#[test]
fn an_identity_provider_keyed_by_scid_alone_refuses_the_second_device() {
    let alice = alice();
    let (_a1, _a2, _, bob) = room(
        &alice,
        DidWebvhIdentityProvider { per_device: false },
        false,
    );
    match bob {
        Err(MlsError::DuplicateLeafData(index)) => assert_eq!(index, 0),
        Err(other) => panic!("expected DuplicateLeafData, got {other:?}"),
        Ok(_) => panic!("mls-rs joined a tree with two leaves of one identity"),
    }
}

/// Device 1 revokes device 2 while Bob, whose mls-rs leaf does not list
/// the AppDataUpdate proposal type, is in the group. RFC 9420 §12.2
/// requires every member to support every proposal type in a Commit, and
/// mls-extensions-11 §4.7 exempts members the Commit removes, so the
/// revocation Commit also removes Bob (decision mimid-1wgh.4.81.37). Dave,
/// a mimid member, follows the Commit; Bob cannot parse it.
#[test]
fn a_revocation_removes_an_mls_rs_member_without_app_data_update() {
    let mut alice = alice();
    let (mut a1, mut a2, _, bob) =
        room(&alice, DidWebvhIdentityProvider { per_device: true }, false);
    let mut bob = bob.expect("bob joins");

    // Dave, a BasicCredential mimid member that applies the did_webvh
    // rules: adding him changes no record,
    // and Bob processes the Commit.
    let mut dave =
        Identity::generate(b"dave", Store::open_in_memory().expect("store")).expect("dave");
    dave.support_did_webvh(CP);
    let bundle = a1
        .commit(
            &alice.d1,
            &[&dave.key_package(KeyPackageKind::OneTime).expect("kp")],
            &[],
            &[],
            no_components,
        )
        .expect("d1 adds dave");
    assert!(bundle.removed_without_app_data_update.is_empty());
    a1.merge_pending_commit(&alice.d1).expect("merge");
    a2.process(&alice.d2, &bundle.commit, no_components)
        .expect("d2 processes");
    mls_rs_receive(&mut bob, &bundle.commit);
    let mut dave_member = Member::join_welcome(
        &dave,
        &bundle.welcome.expect("Welcome"),
        Some(&a1.ratchet_tree().expect("tree")),
    )
    .expect("dave joins")
    .member;
    assert_same_secrets(&a1, &alice.d1, &bob);

    // Revoking device 2: Alice's log gains an entry listing device 1 only,
    // and device 1 takes it (§Revoking a Device). The caller asks for no
    // Remove; Member::commit adds device 2 (the rules) and Bob (no
    // AppDataUpdate).
    revoke_d2(&mut alice);
    let bob_epoch = bob.current_epoch();
    let bundle = a1
        .commit(&alice.d1, &[], &[], &[], no_components)
        .expect("revocation");
    assert_eq!(bundle.removed_without_app_data_update, vec![1]);
    a1.merge_pending_commit(&alice.d1).expect("merge");

    // Dave follows the Commit and learns why Bob left.
    let Incoming::Commit(summary) = dave_member
        .process(&dave, &bundle.commit, no_components)
        .expect("dave processes")
    else {
        panic!("not a Commit");
    };
    let mut removed = summary.removed.clone();
    removed.sort_unstable();
    assert_eq!(removed, vec![1, 2]);
    assert_eq!(summary.removed_without_app_data_update, vec![1]);
    assert!(!summary.self_removed);
    assert_eq!(a1.epoch(), dave_member.epoch());
    assert_eq!(a1.epoch_authenticator(), dave_member.epoch_authenticator());
    assert_eq!(
        a1.export_secret(&alice.d1, EXPORTER_LABEL, EXPORTER_CONTEXT, 32)
            .expect("export"),
        dave_member
            .export_secret(&dave, EXPORTER_LABEL, EXPORTER_CONTEXT, 32)
            .expect("export")
    );
    assert_eq!(
        dave_member.ratchet_tree().expect("tree"),
        a1.ratchet_tree().expect("tree")
    );
    let heads = a1
        .did_webvh_heads(&alice.d1)
        .expect("heads")
        .expect("record");
    let head = heads.get(alice.log.verified().scid()).expect("alice");
    assert!(head.authorizes(&key(&alice.d1)));
    assert!(!head.authorizes(&key(&alice.d2)));

    // Device 2 sees its own removal.
    let Incoming::Commit(summary) = a2
        .process(&alice.d2, &bundle.commit, no_components)
        .expect("d2 sees the Commit")
    else {
        panic!("not a Commit");
    };
    assert!(summary.self_removed);
    assert_eq!(summary.removed_without_app_data_update, vec![1]);

    // Bob cannot parse the Commit that removes him: it carries the
    // AppDataUpdate of component 0xF013, which mls-rs decodes as one
    // opaque<V> whose length prefix 0b11 RFC 9420 §2.1.2 reserves (see
    // mls_rs_cannot_process_a_commit_that_changes_the_record). He stays in
    // the old epoch and learns of his removal only from what follows.
    let result = MlsMessage::from_bytes(&bundle.commit);
    assert!(
        matches!(result, Err(MlsError::SerializationError(_))),
        "{result:?}"
    );
    assert_eq!(bob.current_epoch(), bob_epoch);
    let message = a1
        .send(&alice.d1, b"after the revocation", &[])
        .expect("send");
    let result = bob.process_incoming_message(MlsMessage::from_bytes(&message).expect("decode"));
    assert!(matches!(result, Err(MlsError::EpochNotFound)), "{result:?}");
    let (_, data) = mimi_data(
        dave_member
            .process(&dave, &message, no_components)
            .expect("dave decrypts"),
    );
    assert_eq!(data, b"after the revocation");
}

/// The Update-proposal fallback (decision mimid-1wgh.4.81.31): Alice's
/// log revokes device 1, so device 2 hands the new log over in an Update
/// proposal and Dave, another mimid member, commits it. Dave's Commit sets
/// the record, removes device 1 (the rules) and Bob (no AppDataUpdate).
#[test]
fn another_members_commit_of_a_revocation_removes_an_mls_rs_member() {
    let mut alice = alice();
    let (mut a1, mut a2, _, bob) =
        room(&alice, DidWebvhIdentityProvider { per_device: true }, false);
    let mut bob = bob.expect("bob joins");
    let mut dave =
        Identity::generate(b"dave", Store::open_in_memory().expect("store")).expect("dave");
    dave.support_did_webvh(CP);
    let bundle = a1
        .commit(
            &alice.d1,
            &[&dave.key_package(KeyPackageKind::OneTime).expect("kp")],
            &[],
            &[],
            no_components,
        )
        .expect("d1 adds dave");
    a1.merge_pending_commit(&alice.d1).expect("merge");
    a2.process(&alice.d2, &bundle.commit, no_components)
        .expect("d2 processes");
    mls_rs_receive(&mut bob, &bundle.commit);
    let mut dave_member = Member::join_welcome(
        &dave,
        &bundle.welcome.expect("Welcome"),
        Some(&a1.ratchet_tree().expect("tree")),
    )
    .expect("dave joins")
    .member;

    // Alice's log gains an entry listing device 2 only; device 2 takes it.
    let update = UpdateKey::from_seed(&[3; 32]);
    alice
        .log
        .append(
            "2026-11-20T11:00:01Z",
            &Parameters {
                update_keys: Some(vec![update.multikey()]),
                next_key_hashes: None,
            },
            &update,
            &[key(&alice.d2)],
        )
        .expect("append");
    alice
        .d2
        .set_did_webvh_credential(CP, alice.log.credential().expect("credential"))
        .expect("d2 takes v2");
    let proposal = a2
        .propose_credential_update(&alice.d2)
        .expect("Update proposal");
    dave_member
        .process(&dave, &proposal, no_components)
        .expect("dave stores the Update");
    a1.process(&alice.d1, &proposal, no_components)
        .expect("d1 stores the Update");
    let bundle = dave_member
        .commit(&dave, &[], &[], &[], no_components)
        .expect("dave commits the revocation");
    assert_eq!(bundle.removed_without_app_data_update, vec![1]);
    dave_member.merge_pending_commit(&dave).expect("merge");

    let Incoming::Commit(summary) = a2
        .process(&alice.d2, &bundle.commit, no_components)
        .expect("d2 processes")
    else {
        panic!("not a Commit");
    };
    let mut removed = summary.removed.clone();
    removed.sort_unstable();
    assert_eq!(removed, vec![0, 1]);
    assert_eq!(summary.removed_without_app_data_update, vec![1]);
    assert!(!summary.self_removed);
    assert_eq!(a2.epoch(), dave_member.epoch());
    assert_eq!(a2.epoch_authenticator(), dave_member.epoch_authenticator());
    assert_eq!(
        a2.export_secret(&alice.d2, EXPORTER_LABEL, EXPORTER_CONTEXT, 32)
            .expect("export"),
        dave_member
            .export_secret(&dave, EXPORTER_LABEL, EXPORTER_CONTEXT, 32)
            .expect("export")
    );
    let Incoming::Commit(summary) = a1
        .process(&alice.d1, &bundle.commit, no_components)
        .expect("d1 sees the Commit")
    else {
        panic!("not a Commit");
    };
    assert!(summary.self_removed);
    let result = MlsMessage::from_bytes(&bundle.commit);
    assert!(
        matches!(result, Err(MlsError::SerializationError(_))),
        "{result:?}"
    );
}

/// Device 1 adds Carol, a new `did_webvh` user, while Bob (no
/// AppDataUpdate) is in the group: the Commit that adds Carol's entry to
/// the record also removes Bob. Bob rejoins afterwards with a fresh
/// KeyPackage, which changes no record.
#[test]
fn adding_a_new_did_webvh_user_removes_an_mls_rs_member_without_app_data_update() {
    let alice = alice();
    let (mut a1, mut a2, bob_client, bob) =
        room(&alice, DidWebvhIdentityProvider { per_device: true }, false);
    let bob = bob.expect("bob joins");
    let bob_epoch = bob.current_epoch();

    let (carol_log, carol) = carol();
    let bundle = a1
        .commit(
            &alice.d1,
            &[&carol.key_package(KeyPackageKind::OneTime).expect("kp")],
            &[],
            &[],
            no_components,
        )
        .expect("d1 adds carol");
    assert_eq!(bundle.removed_without_app_data_update, vec![1]);
    a1.merge_pending_commit(&alice.d1).expect("merge");
    let Incoming::Commit(summary) = a2
        .process(&alice.d2, &bundle.commit, no_components)
        .expect("d2 processes")
    else {
        panic!("not a Commit");
    };
    assert_eq!(summary.removed, vec![1]);
    assert_eq!(summary.removed_without_app_data_update, vec![1]);
    assert!(!summary.self_removed);
    let carol_member = Member::join_welcome(
        &carol,
        &bundle.welcome.expect("Welcome"),
        Some(&a1.ratchet_tree().expect("tree")),
    )
    .expect("carol joins")
    .member;
    for (member, identity) in [(&a2, &alice.d2), (&carol_member, &carol)] {
        assert_eq!(member.epoch(), a1.epoch());
        assert_eq!(member.epoch_authenticator(), a1.epoch_authenticator());
        assert_eq!(
            member
                .export_secret(identity, EXPORTER_LABEL, EXPORTER_CONTEXT, 32)
                .expect("export"),
            a1.export_secret(&alice.d1, EXPORTER_LABEL, EXPORTER_CONTEXT, 32)
                .expect("export")
        );
    }
    assert!(
        a1.did_webvh_heads(&alice.d1)
            .expect("heads")
            .expect("record")
            .get(carol_log.verified().scid())
            .is_some()
    );
    // Bob cannot parse the Commit (as in the revocation test).
    let result = MlsMessage::from_bytes(&bundle.commit);
    assert!(
        matches!(result, Err(MlsError::SerializationError(_))),
        "{result:?}"
    );
    assert_eq!(bob.current_epoch(), bob_epoch);

    // Bob rejoins: an Add of a fresh KeyPackage changes no record.
    let bundle = a1
        .commit(
            &alice.d1,
            &[&mls_rs_key_package(&bob_client)],
            &[],
            &[],
            no_components,
        )
        .expect("re-add bob");
    assert!(bundle.removed_without_app_data_update.is_empty());
    a1.merge_pending_commit(&alice.d1).expect("merge");
    a2.process(&alice.d2, &bundle.commit, no_components)
        .expect("d2 processes");
    let (bob, _) = bob_client
        .join_group(
            Some(ExportedTree::from_bytes(&a1.ratchet_tree().expect("tree")).expect("tree")),
            &MlsMessage::from_bytes(&bundle.welcome.expect("Welcome")).expect("Welcome"),
            None,
        )
        .expect("bob joins again");
    assert_same_secrets(&a1, &alice.d1, &bob);
    assert_same_secrets(&a2, &alice.d2, &bob);
}

/// A Commit that changes no record removes nobody, Bob included, and mls-rs
/// processes it; a Commit that removes Bob on purpose but changes no record
/// does not report him as removed for lacking AppDataUpdate.
#[test]
fn a_commit_without_a_record_change_removes_nobody() {
    let alice = alice();
    let (mut a1, mut a2, _, bob) =
        room(&alice, DidWebvhIdentityProvider { per_device: true }, false);
    let mut bob = bob.expect("bob joins");

    let bundle = a2
        .commit(&alice.d2, &[], &[], &[], no_components)
        .expect("d2 commits");
    assert!(bundle.removed_without_app_data_update.is_empty());
    a2.merge_pending_commit(&alice.d2).expect("merge");
    let Incoming::Commit(summary) = a1
        .process(&alice.d1, &bundle.commit, no_components)
        .expect("d1 processes")
    else {
        panic!("not a Commit");
    };
    assert!(summary.removed.is_empty());
    mls_rs_receive(&mut bob, &bundle.commit);
    assert_same_secrets(&a1, &alice.d1, &bob);
    assert_same_secrets(&a2, &alice.d2, &bob);

    let bundle = a1
        .commit(&alice.d1, &[], &[1], &[], no_components)
        .expect("d1 removes bob");
    assert!(bundle.removed_without_app_data_update.is_empty());
    a1.merge_pending_commit(&alice.d1).expect("merge");
    let Incoming::Commit(summary) = a2
        .process(&alice.d2, &bundle.commit, no_components)
        .expect("d2 processes")
    else {
        panic!("not a Commit");
    };
    assert_eq!(summary.removed, vec![1]);
    assert!(summary.removed_without_app_data_update.is_empty());
    // mls-rs processes its own removal.
    let received = mls_rs_receive(&mut bob, &bundle.commit);
    let ReceivedMessage::Commit(description) = received else {
        panic!("expected a Commit, got {received:?}");
    };
    assert!(
        matches!(description.effect, CommitEffect::Removed { .. }),
        "{:?}",
        description.effect
    );
}

/// Alice's log gains an entry listing device 1 only, and device 1 takes it
/// (§Revoking a Device).
fn revoke_d2(alice: &mut Alice) {
    let update = UpdateKey::from_seed(&[3; 32]);
    alice
        .log
        .append(
            "2026-11-20T11:00:01Z",
            &Parameters {
                update_keys: Some(vec![update.multikey()]),
                next_key_hashes: None,
            },
            &update,
            &[key(&alice.d1)],
        )
        .expect("append");
    alice
        .d1
        .set_did_webvh_credential(CP, alice.log.credential().expect("credential"))
        .expect("d1 takes v2");
}

/// If the mls-rs application lists the AppDataUpdate proposal type anyway,
/// mimid builds the Commit that adds Carol and changes the record, and
/// mls-rs cannot parse it: Bob is left behind until he is added again.
#[test]
fn mls_rs_cannot_process_a_commit_that_changes_the_record() {
    let alice = alice();
    let (mut a1, mut a2, bob_client, bob) =
        room(&alice, DidWebvhIdentityProvider { per_device: true }, true);
    let mut bob = bob.expect("bob joins");
    let bob_epoch = bob.current_epoch();

    let (carol_log, carol) = carol();
    let bundle = a1
        .commit(
            &alice.d1,
            &[&carol.key_package(KeyPackageKind::OneTime).expect("kp")],
            &[],
            &[],
            no_components,
        )
        .expect("d1 adds carol");
    // Bob claims AppDataUpdate, so the Commit does not remove him.
    assert!(bundle.removed_without_app_data_update.is_empty());
    a1.merge_pending_commit(&alice.d1).expect("merge");
    a2.process(&alice.d2, &bundle.commit, no_components)
        .expect("d2 processes");
    let heads = a1
        .did_webvh_heads(&alice.d1)
        .expect("heads")
        .expect("record");
    assert!(heads.get(carol_log.verified().scid()).is_some());

    // mls-extensions-11 §4.7 AppDataUpdate inside the Commit, hand-encoded
    // header: proposal_type app_data_update (0x0008), component_id
    // did_webvh_heads, op update (1).
    let header = [0x00, 0x08, 0xf0, 0x13, 0x01];
    let at = bundle
        .commit
        .windows(header.len())
        .position(|w| w == header)
        .expect("the Commit carries an AppDataUpdate for the record");
    let result = MlsMessage::from_bytes(&bundle.commit);
    assert!(
        matches!(result, Err(MlsError::SerializationError(_))),
        "{result:?}"
    );
    // mls-rs decodes an unknown proposal type as one opaque<V>. Here its
    // length would start with 0xf0, whose two-bit prefix 0b11 RFC 9420
    // §2.1.2 reserves, so the proposal decoder itself fails.
    let mut proposal = &bundle.commit[at..];
    let decoded = Proposal::mls_decode(&mut proposal);
    assert!(
        matches!(
            decoded,
            Err(mls_rs::mls_rs_codec::Error::InvalidVarIntPrefix(3))
        ),
        "{decoded:?}"
    );

    // Bob stays in the old epoch and cannot read the group any more.
    assert_eq!(bob.current_epoch(), bob_epoch);
    let message = a1.send(&alice.d1, b"after carol", &[]).expect("send");
    let message = MlsMessage::from_bytes(&message).expect("decode");
    let result = bob.process_incoming_message(message);
    assert!(matches!(result, Err(MlsError::EpochNotFound)), "{result:?}");

    // The way back: remove Bob's stale leaf and add a fresh KeyPackage in
    // one Commit, which changes no record.
    let bundle = a1
        .commit(
            &alice.d1,
            &[&mls_rs_key_package(&bob_client)],
            &[1],
            &[],
            no_components,
        )
        .expect("re-add bob");
    a1.merge_pending_commit(&alice.d1).expect("merge");
    a2.process(&alice.d2, &bundle.commit, no_components)
        .expect("d2 processes");
    let (bob, _) = bob_client
        .join_group(
            Some(ExportedTree::from_bytes(&a1.ratchet_tree().expect("tree")).expect("tree")),
            &MlsMessage::from_bytes(&bundle.welcome.expect("Welcome")).expect("Welcome"),
            None,
        )
        .expect("bob joins again");
    assert_same_secrets(&a1, &alice.d1, &bob);
    assert_same_secrets(&a2, &alice.d2, &bob);
}

/// The other direction: mls-rs adds a new `did_webvh` user but cannot set
/// the record, having no AppDataUpdate, and mimid refuses the Commit
/// (§Expected Heads). Writing the record through a GroupContextExtensions
/// proposal instead, the only GroupContext change RFC 9420 gives mls-rs, is
/// refused too: mls-extensions-11 §4.7 lets a GCE change any extension
/// except `app_data_dictionary`.
#[test]
fn mimid_refuses_an_mls_rs_commit_that_needs_a_record_change() {
    let alice = alice();
    let (mut a1, mut a2, _, bob) =
        room(&alice, DidWebvhIdentityProvider { per_device: true }, false);
    let mut bob = bob.expect("bob joins");
    let (carol_log, carol) = carol();
    let carol_kp = carol.key_package(KeyPackageKind::OneTime).expect("kp");

    // A plain Add: the record lacks Carol's entry (§Expected Heads).
    let output = bob
        .commit_builder()
        .add_member(key_package_message(&carol_kp))
        .expect("mls-rs admits carol")
        .build()
        .expect("mls-rs commits");
    let result = a1.process(
        &alice.d1,
        &output.commit_message.to_bytes().expect("encode"),
        no_components,
    );
    assert!(
        matches!(
            result,
            Err(MemberError::DidWebvh(DidWebvhError::Rule(
                RuleError::ExtensionMismatch { .. }
            )))
        ),
        "{result:?}"
    );
    bob.clear_pending_commit();

    // The same Add with a GCE that writes the record mimid would write:
    // Alice's and Carol's heads, in the same app_data_dictionary. Device 2
    // judges it, since device 1 marked itself out of sync after the
    // refused Commit.
    let mut heads = DidWebvhHeads::new();
    heads.insert(DidWebvhHead::from_log(alice.log.verified()));
    heads.insert(DidWebvhHead::from_log(carol_log.verified()));
    let heads = heads.encode().expect("encode");
    let heads_len = u16::try_from(heads.len()).expect("small");
    assert!(heads_len < 0x4000);
    // mls-extensions-11 §4.6 AppDataDictionary, hand-encoded.
    let mut dictionary = vec![
        0x00, 0x01, // component_id = app_components
        0x03, // opaque data<V>: 3 bytes
        0x02, 0xf0, 0x13, //   ComponentsList [did_webvh_heads]
        0xf0, 0x13, // component_id = did_webvh_heads
    ];
    dictionary.extend_from_slice(&(0x4000 | heads_len).to_be_bytes()); // data<V>
    dictionary.extend_from_slice(&heads);
    let dictionary_len = u16::try_from(dictionary.len()).expect("small");
    assert!(dictionary_len < 0x4000);
    let mut encoded = (0x4000 | dictionary_len).to_be_bytes().to_vec(); // component_data<V>
    encoded.extend_from_slice(&dictionary);
    let mut extensions = bob.context().extensions.clone();
    extensions.set(Extension::new(APP_DATA_DICTIONARY, encoded));
    // OpenMLS refuses a GCE whose extensions are not all in
    // required_capabilities (feedback item 23), so list app_data_dictionary
    // there, to reach the record check itself.
    extensions
        .set_from(RequiredCapabilitiesExt::new(
            vec![APP_DATA_DICTIONARY],
            Vec::new(),
            Vec::new(),
        ))
        .expect("required_capabilities");
    let output = bob
        .commit_builder()
        .add_member(key_package_message(&carol_kp))
        .expect("mls-rs admits carol")
        .set_group_context_ext(extensions)
        .expect("mls-rs sets the GroupContext")
        .build()
        .expect("mls-rs commits");
    let result = a2.process(
        &alice.d2,
        &output.commit_message.to_bytes().expect("encode"),
        no_components,
    );
    // mls-extensions-11 §4.7, as OpenMLS enforces it.
    assert!(
        matches!(result, Err(MemberError::Process(_)))
            && format!("{result:?}").contains("CannotUpdateDictionaryDirectly"),
        "{result:?}"
    );
    // Neither attempt changed mimid's group.
    assert!(a1.out_of_sync().is_some());
    assert_eq!(a1.epoch(), bob.current_epoch());
    assert_eq!(a2.epoch(), bob.current_epoch());
    assert!(
        a2.did_webvh_heads(&alice.d2)
            .expect("heads")
            .expect("record")
            .get(carol_log.verified().scid())
            .is_none()
    );
}
