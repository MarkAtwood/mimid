//! AppDataUpdate (mls-extensions-10 §4.7) through `mimi_mls::member::Member`.
//!
//! mls-rs at the pinned commit (decision mimid-1wgh.4.13) has no
//! AppDataUpdate support, so it cannot process these Commits. The oracles
//! are instead:
//! - the AppDataUpdate proposal bytes, hand-encoded from the §4.7 TLS
//!   presentation language and located inside each Commit;
//! - an mls-rs client that joins after the updates: the GroupContext
//!   `app_data_dictionary` it decodes must equal hand-encoded §4.6 bytes,
//!   and its `epoch_authenticator` must equal the mimi-mls members'.

use std::cell::RefCell;

use mimi_mls::member::{AppDataUpdate, ComponentOp, Incoming, Member, MemberError, WelcomeJoin};
use mimi_mls::{ErrorSource, Identity, KeyPackageKind, Store};
use mls_rs::extension::ExtensionType;
use mls_rs::group::ExportedTree;
use mls_rs::identity::SigningIdentity;
use mls_rs::identity::basic::{BasicCredential, BasicIdentityProvider};
use mls_rs::{CipherSuite, CipherSuiteProvider, Client, CryptoProvider, MlsMessage};
use mls_rs_crypto_rustcrypto::RustCryptoProvider;

/// RFC 9420 §17.1: ciphersuite 0x0001.
const SUITE_1: CipherSuite = CipherSuite::CURVE25519_AES128;

/// mls-extensions-10 §7.1.1: app_data_dictionary extension type.
const APP_DATA_DICTIONARY: ExtensionType = ExtensionType::new(0x0006);

/// mls-extensions-10 §7.5: private-use component ids, for tests only.
const LOG: u16 = 0x8001;
const META: u16 = 0x8002;
const ABSENT: u16 = 0x8003;

fn identity(name: &[u8]) -> Identity {
    Identity::generate(name, Store::open_in_memory().expect("in-memory store"))
        .expect("generate identity")
}

fn mls_rs_client(name: &[u8]) -> Client<impl mls_rs::client_builder::MlsConfig> {
    let crypto = RustCryptoProvider::default();
    let suite = crypto.cipher_suite_provider(SUITE_1).expect("suite 1");
    let (secret, public) = suite.signature_key_generate().expect("key");
    let signing_identity = SigningIdentity::new(
        BasicCredential::new(name.to_vec()).into_credential(),
        public,
    );
    Client::builder()
        .identity_provider(BasicIdentityProvider)
        .crypto_provider(crypto)
        .extension_type(APP_DATA_DICTIONARY)
        .signing_identity(signing_identity, secret, SUITE_1)
        .build()
}

/// What an `apply` function returns.
type ApplyResult = Result<Option<Vec<u8>>, ErrorSource>;

/// One call of a test component handler.
#[derive(Debug, PartialEq, Eq)]
enum Call {
    Update(u16, Option<Vec<u8>>, Vec<Vec<u8>>),
    Remove(u16, Vec<u8>),
}

/// A test-only component semantics: `LOG` and `META` data is the
/// concatenation of every update applied so far. An update `b"bad"` and any
/// other component are rejected. Every call is recorded.
fn handler(
    calls: &RefCell<Vec<Call>>,
) -> impl FnMut(u16, Option<&[u8]>, ComponentOp<'_>) -> ApplyResult + '_ {
    move |component_id, current, op| {
        if component_id != LOG && component_id != META {
            return Err(format!("unknown component {component_id:#06x}").into());
        }
        match op {
            ComponentOp::Update(updates) => {
                calls.borrow_mut().push(Call::Update(
                    component_id,
                    current.map(<[u8]>::to_vec),
                    updates.iter().map(|u| u.to_vec()).collect(),
                ));
                if updates.contains(&b"bad".as_slice()) {
                    return Err("bad update".into());
                }
                let mut data = current.unwrap_or_default().to_vec();
                for update in updates {
                    data.extend_from_slice(update);
                }
                Ok(Some(data))
            }
            ComponentOp::Remove => {
                calls.borrow_mut().push(Call::Remove(
                    component_id,
                    current.unwrap_or_default().to_vec(),
                ));
                Ok(None)
            }
        }
    }
}

/// Accepts every update, so the committer can propose what the receiver's
/// handler then rejects.
fn accept_all(
    _component_id: u16,
    _current: Option<&[u8]>,
    op: ComponentOp<'_>,
) -> Result<Option<Vec<u8>>, ErrorSource> {
    Ok(match op {
        ComponentOp::Update(updates) => Some(updates.concat()),
        ComponentOp::Remove => None,
    })
}

/// RFC 9420 §12.4 `ProposalOrRef` with `type = proposal (1)`, holding a
/// `Proposal` with `proposal_type = app_data_update (0x0008)` and the
/// mls-extensions-10 §4.7 `AppDataUpdate` with `op = update (1)`.
fn inline_update_proposal(component_id: u16, update: &[u8]) -> Vec<u8> {
    assert!(update.len() < 64, "one-byte varint length only");
    let [hi, lo] = component_id.to_be_bytes();
    let mut bytes = vec![
        0x01, // ProposalOrRef.type = proposal
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

/// As [`inline_update_proposal`], with `op = remove (2)` and an empty body.
fn inline_remove_proposal(component_id: u16) -> Vec<u8> {
    let [hi, lo] = component_id.to_be_bytes();
    vec![0x01, 0x00, 0x08, hi, lo, 0x02]
}

fn position(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn commit_summary(incoming: Incoming) -> mimi_mls::member::CommitSummary {
    match incoming {
        Incoming::Commit(summary) => summary,
        other => panic!("expected a Commit, got {other:?}"),
    }
}

/// alice and carol, both mimi-mls, alone in a group at epoch 1: alice
/// creates it and adds carol from her KeyPackage.
fn two_mimi_members() -> (Identity, Member, Identity, Member) {
    let alice = identity(b"alice");
    let carol = identity(b"carol");
    let mut alice_group = Member::create(&alice, b"room-app-data", &[], &[]).expect("create");
    let carol_key_package = carol
        .key_package(KeyPackageKind::OneTime)
        .expect("KeyPackage");
    let calls = RefCell::new(Vec::new());
    let bundle = alice_group
        .commit(&alice, &[&carol_key_package], &[], &[], handler(&calls))
        .expect("add carol");
    alice_group.merge_pending_commit(&alice).expect("merge");
    let WelcomeJoin {
        member: carol_group,
        ..
    } = Member::join_welcome(
        &carol,
        &bundle.welcome.expect("Welcome"),
        Some(&alice_group.ratchet_tree().expect("tree")),
    )
    .expect("carol joins");
    assert!(calls.borrow().is_empty());
    assert_eq!(alice_group.epoch(), 1);
    assert_eq!(
        alice_group.epoch_authenticator(),
        carol_group.epoch_authenticator()
    );
    (alice, alice_group, carol, carol_group)
}

#[test]
fn app_data_updates_apply_in_commit_order_and_reach_new_joiners() {
    let (alice, mut alice_group, carol, mut carol_group) = two_mimi_members();
    assert_eq!(alice_group.component(LOG), None);

    // One update to a component with no data yet.
    let alice_calls = RefCell::new(Vec::new());
    let carol_calls = RefCell::new(Vec::new());
    let bundle = alice_group
        .commit(
            &alice,
            &[],
            &[],
            &[AppDataUpdate::Update {
                component_id: LOG,
                update: b"one".to_vec(),
            }],
            handler(&alice_calls),
        )
        .expect("commit AppDataUpdate");
    assert!(
        position(&bundle.commit, &inline_update_proposal(LOG, b"one")).is_some(),
        "hand-encoded AppDataUpdate not found in the Commit"
    );
    let summary = commit_summary(
        carol_group
            .process(&carol, &bundle.commit, handler(&carol_calls))
            .expect("carol processes"),
    );
    assert_eq!(summary.components, vec![LOG]);
    assert_eq!(summary.epoch, 2);
    assert_eq!(
        *carol_calls.borrow(),
        vec![Call::Update(LOG, None, vec![b"one".to_vec()])]
    );
    assert_eq!(*alice_calls.borrow(), *carol_calls.borrow());
    // The hub echoes alice's own Commit back to her.
    let summary = commit_summary(
        alice_group
            .process(&alice, &bundle.commit, handler(&alice_calls))
            .expect("own Commit"),
    );
    assert_eq!(summary.components, vec![LOG]);
    assert_eq!(alice_group.component(LOG), Some(b"one".as_slice()));
    assert_eq!(carol_group.component(LOG), Some(b"one".as_slice()));
    assert_eq!(
        alice_group.epoch_authenticator(),
        carol_group.epoch_authenticator()
    );

    // Several updates to one component arrive in Commit order; a second
    // component is created in the same Commit.
    carol_calls.borrow_mut().clear();
    let bundle = alice_group
        .commit(
            &alice,
            &[],
            &[],
            &[
                AppDataUpdate::Update {
                    component_id: META,
                    update: b"meta".to_vec(),
                },
                AppDataUpdate::Update {
                    component_id: LOG,
                    update: b"a".to_vec(),
                },
                AppDataUpdate::Update {
                    component_id: LOG,
                    update: b"b".to_vec(),
                },
            ],
            handler(&RefCell::new(Vec::new())),
        )
        .expect("commit");
    let a = position(&bundle.commit, &inline_update_proposal(LOG, b"a")).expect("update a");
    let b = position(&bundle.commit, &inline_update_proposal(LOG, b"b")).expect("update b");
    assert!(a < b, "updates keep their order in the Commit");
    assert!(position(&bundle.commit, &inline_update_proposal(META, b"meta")).is_some());
    alice_group.merge_pending_commit(&alice).expect("merge");
    let summary = commit_summary(
        carol_group
            .process(&carol, &bundle.commit, handler(&carol_calls))
            .expect("carol processes"),
    );
    assert_eq!(summary.components, vec![LOG, META]);
    assert_eq!(
        *carol_calls.borrow(),
        vec![
            Call::Update(
                LOG,
                Some(b"one".to_vec()),
                vec![b"a".to_vec(), b"b".to_vec()]
            ),
            Call::Update(META, None, vec![b"meta".to_vec()]),
        ]
    );
    assert_eq!(carol_group.component(LOG), Some(b"oneab".as_slice()));
    assert_eq!(carol_group.component(META), Some(b"meta".as_slice()));
    assert_eq!(alice_group.component(META), Some(b"meta".as_slice()));
    assert_eq!(
        alice_group.epoch_authenticator(),
        carol_group.epoch_authenticator()
    );

    // Remove.
    carol_calls.borrow_mut().clear();
    let bundle = alice_group
        .commit(
            &alice,
            &[],
            &[],
            &[AppDataUpdate::Remove { component_id: META }],
            handler(&RefCell::new(Vec::new())),
        )
        .expect("commit remove");
    assert!(position(&bundle.commit, &inline_remove_proposal(META)).is_some());
    alice_group.merge_pending_commit(&alice).expect("merge");
    carol_group
        .process(&carol, &bundle.commit, handler(&carol_calls))
        .expect("carol processes");
    assert_eq!(
        *carol_calls.borrow(),
        vec![Call::Remove(META, b"meta".to_vec())]
    );
    assert_eq!(carol_group.component(META), None);
    assert_eq!(alice_group.component(META), None);
    assert_eq!(
        alice_group.epoch_authenticator(),
        carol_group.epoch_authenticator()
    );

    // An mls-rs client joins and decodes the resulting GroupContext.
    let eve_client = mls_rs_client(b"eve");
    let eve_key_package = eve_client
        .generate_key_package_message(Default::default(), Default::default(), None)
        .expect("KeyPackage")
        .to_bytes()
        .expect("encode");
    let bundle = alice_group
        .commit(
            &alice,
            &[&eve_key_package[4..]],
            &[],
            &[],
            handler(&RefCell::new(Vec::new())),
        )
        .expect("add eve");
    alice_group.merge_pending_commit(&alice).expect("merge");
    carol_group
        .process(&carol, &bundle.commit, handler(&carol_calls))
        .expect("carol processes");
    let welcome = MlsMessage::from_bytes(&bundle.welcome.expect("Welcome")).expect("decode");
    let tree = ExportedTree::from_bytes(&alice_group.ratchet_tree().expect("tree")).expect("tree");
    let (eve, _) = eve_client
        .join_group(Some(tree), &welcome, None)
        .expect("eve joins");
    // mls-extensions-10 §4.6 AppDataDictionary, hand-encoded.
    let expected_dictionary = [
        0x08, // ComponentData component_data<V>: 8 bytes
        0x80, 0x01, // component_id = LOG
        0x05, // opaque data<V>: 5 bytes
        b'o', b'n', b'e', b'a', b'b',
    ];
    assert_eq!(
        eve.context()
            .extensions
            .get(APP_DATA_DICTIONARY)
            .expect("app_data_dictionary")
            .extension_data,
        expected_dictionary
    );
    let eve_authenticator = eve.epoch_authenticator().expect("mls-rs");
    assert_eq!(
        alice_group.epoch_authenticator(),
        eve_authenticator.as_bytes()
    );
    assert_eq!(
        carol_group.epoch_authenticator(),
        eve_authenticator.as_bytes()
    );
}

#[test]
fn invalid_proposal_lists_are_refused_and_group_stays_usable() {
    let (alice, mut alice_group, carol, mut carol_group) = two_mimi_members();
    let calls = RefCell::new(Vec::new());
    let bundle = alice_group
        .commit(
            &alice,
            &[],
            &[],
            &[AppDataUpdate::Update {
                component_id: LOG,
                update: b"one".to_vec(),
            }],
            handler(&calls),
        )
        .expect("commit");
    alice_group.merge_pending_commit(&alice).expect("merge");
    carol_group
        .process(&carol, &bundle.commit, handler(&calls))
        .expect("carol processes");
    let epoch = alice_group.epoch();

    // §4.7: removing state that is not present.
    let result = alice_group.commit(
        &alice,
        &[],
        &[],
        &[AppDataUpdate::Remove {
            component_id: ABSENT,
        }],
        accept_all,
    );
    assert!(
        matches!(result, Err(MemberError::InvalidAppDataUpdate(ABSENT))),
        "{result:?}"
    );

    // §4.7: an update and a remove for the same component.
    let result = alice_group.commit(
        &alice,
        &[],
        &[],
        &[
            AppDataUpdate::Remove { component_id: LOG },
            AppDataUpdate::Update {
                component_id: LOG,
                update: b"x".to_vec(),
            },
        ],
        accept_all,
    );
    assert!(
        matches!(result, Err(MemberError::InvalidAppDataUpdate(LOG))),
        "{result:?}"
    );

    // §4.7: two removes for the same component.
    let result = alice_group.commit(
        &alice,
        &[],
        &[],
        &[
            AppDataUpdate::Remove { component_id: LOG },
            AppDataUpdate::Remove { component_id: LOG },
        ],
        accept_all,
    );
    assert!(
        matches!(result, Err(MemberError::InvalidAppDataUpdate(LOG))),
        "{result:?}"
    );

    // §4.7: a component the application does not know.
    let result = alice_group.commit(
        &alice,
        &[],
        &[],
        &[AppDataUpdate::Update {
            component_id: ABSENT,
            update: b"x".to_vec(),
        }],
        handler(&calls),
    );
    assert!(
        matches!(
            result,
            Err(MemberError::AppDataRejected {
                component_id: ABSENT,
                ..
            })
        ),
        "{result:?}"
    );

    // An apply function that answers an update with "remove".
    let result = alice_group.commit(
        &alice,
        &[],
        &[],
        &[AppDataUpdate::Update {
            component_id: LOG,
            update: b"x".to_vec(),
        }],
        |_, _, _| Ok::<_, ErrorSource>(None),
    );
    assert!(
        matches!(result, Err(MemberError::InvalidAppDataUpdate(LOG))),
        "{result:?}"
    );

    assert_eq!(alice_group.epoch(), epoch, "refused Commits change nothing");
    assert_eq!(alice_group.component(LOG), Some(b"one".as_slice()));
    let message = alice_group
        .send(&alice, b"still usable", &[])
        .expect("send");
    let incoming = carol_group
        .process(&carol, &message, handler(&calls))
        .expect("carol decrypts");
    assert!(
        matches!(incoming, Incoming::Application { ref data, .. } if data == b"still usable"),
        "{incoming:?}"
    );
}

#[test]
fn receiver_rejection_keeps_group_state() {
    let (alice, mut alice_group, carol, mut carol_group) = two_mimi_members();
    let calls = RefCell::new(Vec::new());
    let bundle = alice_group
        .commit(
            &alice,
            &[],
            &[],
            &[AppDataUpdate::Update {
                component_id: LOG,
                update: b"bad".to_vec(),
            }],
            accept_all,
        )
        .expect("alice's handler accepts");
    let epoch = carol_group.epoch();
    let authenticator = carol_group.epoch_authenticator().to_vec();

    let result = carol_group.process(&carol, &bundle.commit, handler(&calls));
    assert!(
        matches!(
            result,
            Err(MemberError::AppDataRejected {
                component_id: LOG,
                ..
            })
        ),
        "{result:?}"
    );
    assert_eq!(carol_group.epoch(), epoch);
    assert_eq!(carol_group.epoch_authenticator(), authenticator);
    assert_eq!(carol_group.component(LOG), None);
    assert!(carol_group.is_active());

    // The hub rejected the Commit too; alice discards it and goes on.
    alice_group.clear_pending_commit(&alice).expect("clear");
    let message = alice_group.send(&alice, b"after", &[]).expect("send");
    let incoming = carol_group
        .process(&carol, &message, handler(&calls))
        .expect("carol decrypts");
    assert!(
        matches!(incoming, Incoming::Application { ref data, .. } if data == b"after"),
        "{incoming:?}"
    );
}
