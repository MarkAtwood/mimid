//! mls-extensions editor's copy (PR #110) rule 3: the LeafNode of a
//! standalone Update proposal is checked on receipt against the current
//! GroupContext (decision mimid-krmn.7).
//!
//! Oracle: a plain OpenMLS client (dave), which enforces no component rules,
//! joins a group that requires app component 0x0004 with a leaf listing it,
//! then proposes an Update whose leaf does not list it. The ComponentsLists
//! are hand-encoded.

#![forbid(unsafe_code)]

use mimi_mls::member::{ComponentOp, Incoming, Member, MemberError};
use mimi_mls::observer::{Observed, Observer, ObserverError, ObserverStart};
use mimi_mls::tls_codec::{Deserialize, Serialize};
use mimi_mls::{ErrorSource, Identity, Store};
use openmls::extensions::{AppDataDictionary, AppDataDictionaryExtension};
use openmls::prelude::{
    BasicCredential, Capabilities, Ciphersuite, CredentialType, CredentialWithKey,
    Extension as OpenMlsExtension, ExtensionType as OpenMlsExtensionType,
    Extensions as OpenMlsExtensions, KeyPackage, LeafNodeParameters, MlsGroup, MlsGroupJoinConfig,
    MlsMessageBodyIn, MlsMessageIn, PURE_PLAINTEXT_WIRE_FORMAT_POLICY,
    ProposalType as OpenMlsProposalType, RatchetTreeIn, StagedWelcome,
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;

/// mls-extensions-10 §4.6 / §5 component ids.
const APP_COMPONENTS: u16 = 0x0001;
const SAFE_AAD: u16 = 0x0002;

/// ComponentsList [0x0004] (last_resort_key_package): the GroupContext
/// `app_components` requirement, and dave's first `app_components` list.
const LIST_0004: [u8; 3] = [
    0x02, // ComponentID component_ids<V>: 2 bytes
    0x00, 0x04, // ComponentID 0x0004
];

/// ComponentsList [0x8001]: dave's `app_components` list after the Update,
/// without 0x0004.
const LIST_8001: [u8; 3] = [
    0x02, // ComponentID component_ids<V>: 2 bytes
    0x80, 0x01, // ComponentID 0x8001
];

/// ComponentsList [0x0020] (frank_aad): the GroupContext `safe_aad`
/// requirement, and dave's `safe_aad` list.
const LIST_0020: [u8; 3] = [
    0x02, // ComponentID component_ids<V>: 2 bytes
    0x00, 0x20, // ComponentID 0x0020
];

const DAVE: &[u8] = b"mimi://d.example/u/dave";

fn identity(name: &[u8]) -> Identity {
    Identity::generate(name, Store::open_in_memory().expect("in-memory store"))
        .expect("generate identity")
}

fn no_components(
    component_id: u16,
    _current: Option<&[u8]>,
    _op: ComponentOp<'_>,
) -> Result<Option<Vec<u8>>, ErrorSource> {
    Err(format!("unexpected AppDataUpdate for {component_id:#06x}").into())
}

/// dave's LeafNode extensions: an app_data_dictionary whose `app_components`
/// list is `app_components` and whose `safe_aad` list is [0x0020].
fn dave_leaf_extensions(app_components: &[u8]) -> OpenMlsExtensions<openmls::prelude::LeafNode> {
    let mut dictionary = AppDataDictionary::new();
    dictionary.insert(APP_COMPONENTS, app_components.to_vec());
    dictionary.insert(SAFE_AAD, LIST_0020.to_vec());
    OpenMlsExtensions::single(OpenMlsExtension::AppDataDictionary(
        AppDataDictionaryExtension::new(dictionary),
    ))
    .expect("leaf extensions")
}

struct Dave {
    group: MlsGroup,
    provider: OpenMlsRustCrypto,
    signer: SignatureKeyPair,
}

/// alice (mimi-mls, leaf 0) creates a group whose GroupContext requires app
/// component 0x0004 and Safe AAD component 0x0020, and adds dave (plain
/// OpenMLS, leaf 1), whose leaf lists both. Returns the parties at epoch 1
/// and alice's GroupInfo and tree for epoch 1.
fn alice_and_dave() -> (Identity, Member, Dave, Vec<u8>, Vec<u8>) {
    let alice = identity(b"alice");
    let mut member = Member::create(
        &alice,
        b"room-k4",
        &[],
        &[
            (APP_COMPONENTS, LIST_0004.to_vec()),
            (SAFE_AAD, LIST_0020.to_vec()),
        ],
    )
    .expect("create");

    let provider = OpenMlsRustCrypto::default();
    let suite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    let signer = SignatureKeyPair::new(suite.signature_algorithm()).expect("key");
    let credential_with_key = CredentialWithKey {
        credential: BasicCredential::new(DAVE.to_vec()).into(),
        signature_key: signer.to_public_vec().into(),
    };
    let capabilities = Capabilities::builder()
        .ciphersuites(vec![suite])
        .credentials(vec![CredentialType::Basic])
        .extensions(vec![OpenMlsExtensionType::AppDataDictionary])
        .proposals(vec![OpenMlsProposalType::AppDataUpdate])
        .build();
    let key_package = KeyPackage::builder()
        .leaf_node_capabilities(capabilities)
        .leaf_node_extensions(dave_leaf_extensions(&LIST_0004))
        .build(suite, &provider, &signer, credential_with_key)
        .expect("OpenMLS KeyPackage")
        .key_package()
        .tls_serialize_detached()
        .expect("encode");
    let concat = |_: u16, _: Option<&[u8]>, _: ComponentOp<'_>| -> Result<_, ErrorSource> {
        Err("no AppDataUpdate expected".into())
    };
    let bundle = member
        .commit(&alice, &[&key_package], &[], &[], concat)
        .expect("commit Add");
    member.merge_pending_commit(&alice).expect("merge");
    let tree = member.ratchet_tree().expect("tree");

    let welcome = MlsMessageIn::tls_deserialize_exact(bundle.welcome.expect("Welcome"))
        .expect("decode Welcome");
    let MlsMessageBodyIn::Welcome(welcome) = welcome.extract() else {
        panic!("not a Welcome");
    };
    let config = MlsGroupJoinConfig::builder()
        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .build();
    let group = StagedWelcome::build_from_welcome(&provider, &config, welcome)
        .expect("Welcome")
        .with_ratchet_tree(RatchetTreeIn::tls_deserialize_exact(&tree).expect("tree"))
        .build()
        .expect("stage")
        .into_group(&provider)
        .expect("join");
    (
        alice,
        member,
        Dave {
            group,
            provider,
            signer,
        },
        bundle.group_info,
        tree,
    )
}

/// dave proposes an Update whose leaf `app_components` list is
/// `app_components`; returns the TLS-encoded MLSMessage.
fn dave_update(dave: &mut Dave, app_components: &[u8]) -> Vec<u8> {
    dave_update_with(dave, dave_leaf_extensions(app_components))
}

/// dave proposes an Update whose leaf extensions are `extensions`; returns
/// the TLS-encoded MLSMessage.
fn dave_update_with(
    dave: &mut Dave,
    extensions: OpenMlsExtensions<openmls::prelude::LeafNode>,
) -> Vec<u8> {
    let leaf = LeafNodeParameters::builder()
        .with_extensions(extensions)
        .build();
    let (message, _) = dave
        .group
        .propose_self_update(&dave.provider, &dave.signer, leaf)
        .expect("OpenMLS proposes an Update");
    message.tls_serialize_detached().expect("encode")
}

#[test]
fn update_proposal_whose_leaf_lacks_a_required_component_is_refused() {
    let (alice, mut member, mut dave, group_info, tree) = alice_and_dave();
    let store = Store::open_in_memory().expect("store");
    let ObserverStart { mut observer, .. } =
        Observer::from_group_info(&store, &group_info, Some(&tree)).expect("Observer");
    let update = dave_update(&mut dave, &LIST_8001);

    let received = member.process(&alice, &update, no_components);
    assert!(
        matches!(received, Err(MemberError::MissingAppComponent(0x0004))),
        "{received:?}"
    );
    // Nothing is stored: a stored proposal would block sending until a
    // Commit covers it (OpenMLS).
    member
        .send(&alice, b"still usable", &[])
        .expect("no proposal is pending");

    let processed = observer.process_proposal(&store, &update);
    assert!(
        matches!(processed, Err(ObserverError::MissingAppComponent(0x0004))),
        "{processed:?}"
    );
    let observed = observer.process(&store, &update, no_components);
    assert!(
        matches!(observed, Err(ObserverError::MissingAppComponent(0x0004))),
        "{observed:?}"
    );
}

/// mls-extensions-11 §5: a LeafNode is invalid if its app_data_dictionary
/// holds an entry for a component (other than app_components and safe_aad)
/// that its own app_components list does not name. dave's Update leaf keeps
/// the required lists but holds state for 0x8001, which it lists only in
/// the second case.
#[test]
fn update_proposal_whose_leaf_holds_an_unlisted_entry_is_refused() {
    // ComponentsList [0x0004, 0x8001], hand-encoded.
    const LIST_0004_8001: [u8; 5] = [
        0x04, // ComponentID component_ids<V>: 4 bytes
        0x00, 0x04, // ComponentID 0x0004
        0x80, 0x01, // ComponentID 0x8001
    ];
    for (app_components, valid) in [(&LIST_0004[..], false), (&LIST_0004_8001[..], true)] {
        let (alice, mut member, mut dave, group_info, tree) = alice_and_dave();
        let store = Store::open_in_memory().expect("store");
        let ObserverStart { mut observer, .. } =
            Observer::from_group_info(&store, &group_info, Some(&tree)).expect("Observer");
        let mut dictionary = AppDataDictionary::new();
        dictionary.insert(APP_COMPONENTS, app_components.to_vec());
        dictionary.insert(SAFE_AAD, LIST_0020.to_vec());
        dictionary.insert(0x8001, b"x".to_vec());
        let extensions = OpenMlsExtensions::single(OpenMlsExtension::AppDataDictionary(
            AppDataDictionaryExtension::new(dictionary),
        ))
        .expect("leaf extensions");
        let update = dave_update_with(&mut dave, extensions);

        let received = member.process(&alice, &update, no_components);
        let processed = observer.process_proposal(&store, &update);
        if valid {
            let received = received.expect("0x8001 is listed");
            assert!(
                matches!(received, Incoming::Proposal { .. }),
                "{received:?}"
            );
            processed.expect("0x8001 is listed");
        } else {
            assert!(
                matches!(received, Err(MemberError::LeafComponentNotListed(0x8001))),
                "{received:?}"
            );
            // Nothing is stored: a stored proposal would block sending
            // until a Commit covers it (OpenMLS).
            member
                .send(&alice, b"still usable", &[])
                .expect("no proposal is pending");
            assert!(
                matches!(
                    processed,
                    Err(ObserverError::LeafComponentNotListed(0x8001))
                ),
                "{processed:?}"
            );
        }
    }
}

#[test]
fn update_proposal_whose_leaf_keeps_the_required_components_is_stored() {
    let (alice, mut member, mut dave, group_info, tree) = alice_and_dave();
    let store = Store::open_in_memory().expect("store");
    let ObserverStart { mut observer, .. } =
        Observer::from_group_info(&store, &group_info, Some(&tree)).expect("Observer");
    let update = dave_update(&mut dave, &LIST_0004);

    let received = member
        .process(&alice, &update, no_components)
        .expect("the leaf keeps 0x0004");
    assert!(
        matches!(received, Incoming::Proposal { .. }),
        "{received:?}"
    );
    let observed = observer
        .process(&store, &update, no_components)
        .expect("the leaf keeps 0x0004");
    assert!(
        matches!(observed, Observed::Proposal { .. }),
        "{observed:?}"
    );
}
