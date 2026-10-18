//! The `op` and `update` bytes of AppDataUpdate proposals (mls-extensions-10
//! §4.7) in [`ProposalKind::AppDataUpdate`], from
//! [`Observer::process_proposal`] and [`Observer::pending_commit_detail`]
//! (bead mimid-1wgh.6.54).
//!
//! mls-rs at the pinned commit (decision mimid-1wgh.4.13) has no
//! AppDataUpdate support, so it cannot build or check these proposals. The
//! oracles are instead:
//! - the expected `update` bytes and `op`, written by hand in each test;
//! - the AppDataUpdate proposal, hand-encoded from the §4.7 TLS
//!   presentation language and located inside each message the Observer is
//!   given, so the bytes reported are the bytes on the wire.
//!
//! Inline proposals come from a `mimi_mls::member::Member` Commit.
//! `Member` cannot send a standalone AppDataUpdate proposal (see its
//! `# Limitations`), so standalone proposals come from a plain OpenMLS
//! client, not from `mimi_mls`; the Member then commits them by reference.

use mimi_mls::member::{ComponentOp, Incoming, Member, Sender};
use mimi_mls::observer::{Observed, Observer, ObserverStart, ProposalDetail, ProposalKind};
use mimi_mls::tls_codec::{Deserialize, Serialize};
use mimi_mls::{ErrorSource, Identity, Store};
use openmls::messages::proposals::AppDataUpdateOperation;
use openmls::prelude::{
    BasicCredential, Capabilities, Ciphersuite, CredentialType, CredentialWithKey, ExtensionType,
    KeyPackage, MlsGroup, MlsGroupJoinConfig, MlsMessageBodyIn, MlsMessageIn,
    PURE_PLAINTEXT_WIRE_FORMAT_POLICY, ProposalType, RatchetTreeIn, StagedWelcome,
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;

/// mls-extensions-10 §7.5: private-use component ids, for tests only.
const LOG: u16 = 0x8001;
const META: u16 = 0x8002;

const DAVE: &[u8] = b"mimi://d.example/u/dave";

/// Accepts every update: the new data is the concatenation of the current
/// data and the updates.
fn accept_all(
    _component_id: u16,
    current: Option<&[u8]>,
    op: ComponentOp<'_>,
) -> Result<Option<Vec<u8>>, ErrorSource> {
    Ok(match op {
        ComponentOp::Update(updates) => {
            let mut data = current.unwrap_or_default().to_vec();
            for update in updates {
                data.extend_from_slice(update);
            }
            Some(data)
        }
        ComponentOp::Remove => None,
    })
}

/// RFC 9420 §12.1 `Proposal` with `proposal_type = app_data_update
/// (0x0008)`, holding the mls-extensions-10 §4.7 `AppDataUpdate` with
/// `op = update (1)`.
fn update_proposal(component_id: u16, update: &[u8]) -> Vec<u8> {
    assert!(update.len() < 64, "one-byte varint length only");
    let [hi, lo] = component_id.to_be_bytes();
    let mut bytes = vec![
        0x00,
        0x08, // Proposal.proposal_type = app_data_update
        hi,
        lo,                 // AppDataUpdate.component_id
        0x01,               // AppDataUpdate.op = update
        update.len() as u8, // opaque update<V>
    ];
    bytes.extend_from_slice(update);
    bytes
}

/// As [`update_proposal`], with `op = remove (2)` and an empty body.
fn remove_proposal(component_id: u16) -> Vec<u8> {
    let [hi, lo] = component_id.to_be_bytes();
    vec![
        0x00, 0x08, // Proposal.proposal_type = app_data_update
        hi, lo,   // AppDataUpdate.component_id
        0x02, // AppDataUpdate.op = remove
    ]
}

/// RFC 9420 §12.4: `proposal` inside a `ProposalOrRef` with `type =
/// proposal (1)`, as a Commit carries it inline.
fn inline(proposal: Vec<u8>) -> Vec<u8> {
    let mut bytes = vec![0x01]; // ProposalOrRef.type = proposal
    bytes.extend(proposal);
    bytes
}

fn assert_contains(haystack: &[u8], needle: &[u8], case: &str) {
    assert!(
        haystack.windows(needle.len()).any(|w| w == needle),
        "{case}: hand-encoded AppDataUpdate not found"
    );
}

/// The AppDataUpdate proposals in `proposals`, as `(sender, has reference,
/// component_id, update)`, in order.
fn app_data_updates(proposals: &[ProposalDetail]) -> Vec<(Sender, bool, u16, Option<Vec<u8>>)> {
    proposals
        .iter()
        .filter_map(|detail| match &detail.proposal {
            ProposalKind::AppDataUpdate {
                component_id,
                update,
            } => Some((
                detail.sender,
                detail.reference.is_some(),
                *component_id,
                update.clone(),
            )),
            _ => None,
        })
        .collect()
}

/// A plain OpenMLS client that supports AppDataUpdate.
struct OpenMlsClient {
    group: MlsGroup,
    provider: OpenMlsRustCrypto,
    signer: SignatureKeyPair,
}

/// alice (mimi-mls, leaf 0) creates a group with `LOG` data `b"v0"` and
/// `META` data `b"m0"`, and adds dave (plain OpenMLS, leaf 1). The Observer
/// starts from the GroupInfo of that Commit, in epoch 1.
fn setup() -> (Identity, Member, OpenMlsClient, Store, Observer) {
    let alice = Identity::generate(b"alice", Store::open_in_memory().expect("store"))
        .expect("generate identity");
    let mut member = Member::create(
        &alice,
        b"room-app-data",
        &[],
        &[(LOG, b"v0".to_vec()), (META, b"m0".to_vec())],
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
        .extensions(vec![ExtensionType::AppDataDictionary])
        .proposals(vec![ProposalType::AppDataUpdate])
        .build();
    let key_package = KeyPackage::builder()
        .leaf_node_capabilities(capabilities)
        .build(suite, &provider, &signer, credential_with_key)
        .expect("OpenMLS KeyPackage")
        .key_package()
        .tls_serialize_detached()
        .expect("encode");

    let bundle = member
        .commit(&alice, &[&key_package], &[], &[], accept_all)
        .expect("commit Add");
    member.merge_pending_commit(&alice).expect("merge");
    let tree = member.ratchet_tree().expect("tree");

    let store = Store::open_in_memory().expect("store");
    let ObserverStart { observer, .. } =
        Observer::from_group_info(&store, &bundle.group_info, Some(&tree))
            .expect("from_group_info");
    assert_eq!(observer.epoch(), 1);

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
    let dave = OpenMlsClient {
        group,
        provider,
        signer,
    };
    (alice, member, dave, store, observer)
}

#[test]
fn inline_update_and_remove_carry_op_and_bytes() {
    let (alice, mut member, _dave, store, mut observer) = setup();
    let bundle = member
        .commit(
            &alice,
            &[],
            &[],
            &[
                mimi_mls::member::AppDataUpdate::Update {
                    component_id: LOG,
                    update: b"+a".to_vec(),
                },
                mimi_mls::member::AppDataUpdate::Remove { component_id: META },
            ],
            accept_all,
        )
        .expect("commit AppDataUpdate");
    member.merge_pending_commit(&alice).expect("merge");
    assert_contains(
        &bundle.commit,
        &inline(update_proposal(LOG, b"+a")),
        "inline update",
    );
    assert_contains(
        &bundle.commit,
        &inline(remove_proposal(META)),
        "inline remove",
    );

    let observed = observer
        .process(&store, &bundle.commit, accept_all)
        .expect("Observer stages the Commit");
    assert!(matches!(observed, Observed::Commit(_)), "{observed:?}");
    let detail = observer.pending_commit_detail().expect("detail");
    assert_eq!(
        app_data_updates(&detail.proposals),
        vec![
            (Sender::Member(0), false, LOG, Some(b"+a".to_vec())),
            (Sender::Member(0), false, META, None),
        ]
    );
    observer.merge_pending_commit(&store).expect("merge");
    assert_eq!(observer.component(LOG), Some(&b"v0+a"[..]));
    assert_eq!(observer.component(META), None);
}

#[test]
fn standalone_update_and_remove_carry_op_and_bytes() {
    let (alice, mut member, mut dave, store, mut observer) = setup();

    // An empty update is still `op = update`, not a remove.
    let cases = [
        (
            LOG,
            AppDataUpdateOperation::Update(b"+d".to_vec().into()),
            update_proposal(LOG, b"+d"),
            Some(b"+d".to_vec()),
        ),
        (
            LOG,
            AppDataUpdateOperation::Update(Vec::new().into()),
            update_proposal(LOG, b""),
            Some(Vec::new()),
        ),
        (
            META,
            AppDataUpdateOperation::Remove,
            remove_proposal(META),
            None,
        ),
    ];
    let mut references = Vec::new();
    for (component_id, operation, encoded, expected) in cases {
        let (message, openmls_ref) = dave
            .group
            .propose_app_data_update(&dave.provider, &dave.signer, component_id, operation)
            .expect("OpenMLS proposes");
        let message = message.tls_serialize_detached().expect("encode");
        assert_contains(&message, &encoded, "standalone proposal");

        let detail = observer
            .process_proposal(&store, &message)
            .expect("Observer stores the proposal");
        assert_eq!(detail.sender, Sender::Member(1));
        assert_eq!(
            detail.proposal,
            ProposalKind::AppDataUpdate {
                component_id,
                update: expected,
            }
        );
        // Both ProposalRefs are computed by OpenMLS, so this checks only
        // that the Observer reports the stored proposal's reference.
        let reference = detail.reference.expect("a ProposalRef");
        assert_eq!(
            reference.as_bytes(),
            openmls_ref.tls_serialize_detached().expect("encode")
        );
        references.push(reference);

        let incoming = member
            .process(&alice, &message, accept_all)
            .expect("Member stores the proposal");
        assert!(
            matches!(incoming, Incoming::Proposal { .. }),
            "{incoming:?}"
        );
    }

    // alice commits both by reference.
    let bundle = member
        .commit(&alice, &[], &[], &[], accept_all)
        .expect("commit by reference");
    member.merge_pending_commit(&alice).expect("merge");
    let observed = observer
        .process(&store, &bundle.commit, accept_all)
        .expect("Observer stages the Commit");
    assert!(matches!(observed, Observed::Commit(_)), "{observed:?}");
    let detail = observer.pending_commit_detail().expect("detail");
    // RFC 9420 §12.4 leaves the order of by-reference proposals to the
    // committer, so they are compared sorted.
    let mut found = app_data_updates(&detail.proposals);
    found.sort_by(|a, b| (a.2, &a.3).cmp(&(b.2, &b.3)));
    assert_eq!(
        found,
        vec![
            (Sender::Member(1), true, LOG, Some(Vec::new())),
            (Sender::Member(1), true, LOG, Some(b"+d".to_vec())),
            (Sender::Member(1), true, META, None),
        ]
    );
    let mut committed: Vec<_> = detail
        .proposals
        .iter()
        .filter_map(|p| p.reference.clone())
        .collect();
    committed.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
    references.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
    assert_eq!(committed, references);

    observer.merge_pending_commit(&store).expect("merge");
    assert_eq!(observer.component(LOG), Some(&b"v0+d"[..]));
    assert_eq!(observer.component(META), None);
    assert_eq!(observer.component(LOG), member.component(LOG));
}
