//! [`Observer::propose_app_data_update`]: the hub, as the group's external
//! sender (RFC 9420 §12.1.8.1), proposes an AppDataUpdate
//! (mls-extensions-10 §4.7, proposal type 0x0008; External: Y, §7.2.1).
//!
//! Oracles:
//! - the whole `MLSMessage`, hand-encoded from RFC 9420 §6 and §12.1 and
//!   mls-extensions-10 §4.7, with RFC 9420 §2.1.2 length prefixes;
//! - the signature, verified with the hub's public key over a FramedContentTBS
//!   built by hand (RFC 9420 §6.1: no GroupContext for an external sender);
//! - the ProposalRef, recomputed from RFC 9420 §5.2 with mls-rs's SHA-256
//!   (decision mimid-1wgh.4.13) and compared with the reference the Commit
//!   uses;
//! - two mimi-mls Members (OpenMLS `MlsGroup`, not the `PublicGroup` and
//!   external-proposal code under test) that receive the proposal, commit
//!   it by reference, and must reach the same component data and
//!   `epoch_authenticator`.
//!
//! mls-rs at the pinned commit has no AppDataUpdate support (see
//! `member_app_data_update.rs`), so it cannot be the receiver.

use mimi_mls::label::{self, SignatureKeyPair};
use mimi_mls::member::{
    AppDataUpdate, ComponentOp, ExternalSender, Incoming, Member, Sender, WelcomeJoin,
};
use mimi_mls::observer::{Observed, Observer, ObserverError, ObserverStart, ProposalKind};
use mimi_mls::{ErrorSource, Identity, KeyPackageKind, Store};
use mls_rs::{CipherSuite, CipherSuiteProvider, CryptoProvider};
use mls_rs_crypto_rustcrypto::RustCryptoProvider;

/// RFC 9420 §17.1: ciphersuite 0x0001.
const SUITE_1: CipherSuite = CipherSuite::CURVE25519_AES128;

/// mls-extensions-10 §7.5: private-use component ids, for tests only.
const LOG: u16 = 0x8001;
const META: u16 = 0x8002;
const ABSENT: u16 = 0x8003;
/// First of five components used for the length-boundary updates.
const BOUNDARY_BASE: u16 = 0x8010;

/// mls-extensions-10 §7.5: the safe_aad component.
const SAFE_AAD: u16 = 0x0002;

const GROUP_ID: &[u8] = b"room-hub";

/// RFC 9420 §6.1: the SignWithLabel label of a FramedContent signature.
const FRAMED_CONTENT_LABEL: &str = "FramedContentTBS";

/// `update` lengths at each RFC 9420 §2.1.2 variable-length prefix
/// boundary, with the prefix written by hand.
const LENGTH_BOUNDARIES: [(usize, &[u8]); 5] = [
    (0, &[0x00]),                       // 1-byte form, smallest
    (63, &[0x3f]),                      // 1-byte form, largest
    (64, &[0x40, 0x40]),                // 2-byte form, smallest
    (16383, &[0x7f, 0xff]),             // 2-byte form, largest
    (16384, &[0x80, 0x00, 0x40, 0x00]), // 4-byte form, smallest
];

fn identity(name: &[u8]) -> Identity {
    Identity::generate(name, Store::open_in_memory().expect("in-memory store"))
        .expect("generate identity")
}

/// Test component semantics: the data of a known component is its current
/// data followed by every update; other components are rejected.
fn concat(
    component_id: u16,
    current: Option<&[u8]>,
    op: ComponentOp<'_>,
) -> Result<Option<Vec<u8>>, ErrorSource> {
    let known = component_id == LOG
        || component_id == META
        || (BOUNDARY_BASE..BOUNDARY_BASE + 5).contains(&component_id);
    if !known {
        return Err(format!("unknown component {component_id:#06x}").into());
    }
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

/// RFC 9420 §2.1.2 variable-length vector length prefix.
fn varint(len: usize) -> Vec<u8> {
    match len {
        0..=0x3f => vec![len as u8],
        0x40..=0x3fff => (0x4000 | len as u16).to_be_bytes().to_vec(),
        _ => (0x8000_0000 | len as u32).to_be_bytes().to_vec(),
    }
}

fn position(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// The group's members, its Observer, and the hub key that is entry 0 of
/// `external_senders`.
struct Room {
    alice: Identity,
    alice_group: Member,
    carol: Identity,
    carol_group: Member,
    store: Store,
    observer: Observer,
    hub: SignatureKeyPair,
}

/// alice and carol (mimi-mls) in epoch 1 of a group whose GroupContext
/// lists the hub as external sender 0 and holds `components`, and an
/// Observer started from the GroupInfo of the Commit that added carol.
fn room(components: &[(u16, Vec<u8>)]) -> Room {
    let hub = SignatureKeyPair::generate().expect("hub key");
    let senders = [ExternalSender {
        signature_key: hub.verification_key().to_vec(),
        identity: b"hub".to_vec(),
    }];
    room_with(&senders, components, hub)
}

fn room_with(
    senders: &[ExternalSender],
    components: &[(u16, Vec<u8>)],
    hub: SignatureKeyPair,
) -> Room {
    let alice = identity(b"alice");
    let carol = identity(b"carol");
    let mut alice_group = Member::create(&alice, GROUP_ID, senders, components).expect("create");
    let carol_key_package = carol
        .key_package(KeyPackageKind::OneTime)
        .expect("KeyPackage");
    let bundle = alice_group
        .commit(&alice, &[&carol_key_package], &[], &[], concat)
        .expect("add carol");
    alice_group.merge_pending_commit(&alice).expect("merge");
    let tree = alice_group.ratchet_tree().expect("tree");
    let WelcomeJoin {
        member: carol_group,
        ..
    } = Member::join_welcome(&carol, &bundle.welcome.expect("Welcome"), Some(&tree))
        .expect("carol joins");
    let store = Store::open_in_memory().expect("store");
    let ObserverStart { observer, .. } =
        Observer::from_group_info(&store, &bundle.group_info, Some(&tree))
            .expect("from_group_info");
    assert_eq!(observer.epoch(), 1);
    Room {
        alice,
        alice_group,
        carol,
        carol_group,
        store,
        observer,
        hub,
    }
}

impl Room {
    /// carol commits every stored proposal by reference; the Observer and
    /// alice process the Commit and everyone merges it. Returns the
    /// Observer's view of the Commit's proposals.
    fn carol_commits(&mut self) -> Vec<mimi_mls::observer::ProposalDetail> {
        let bundle = self
            .carol_group
            .commit(&self.carol, &[], &[], &[], concat)
            .expect("carol commits by reference");
        let observed = self
            .observer
            .process(&self.store, &bundle.commit, concat)
            .expect("Observer stages the Commit");
        assert!(matches!(observed, Observed::Commit(_)), "{observed:?}");
        let detail = self.observer.pending_commit_detail().expect("detail");
        self.observer
            .merge_pending_commit(&self.store)
            .expect("Observer merges");
        self.carol_group
            .merge_pending_commit(&self.carol)
            .expect("carol merges");
        let incoming = self
            .alice_group
            .process(&self.alice, &bundle.commit, concat)
            .expect("alice processes");
        assert!(matches!(incoming, Incoming::Commit(_)), "{incoming:?}");
        assert_eq!(
            self.alice_group.epoch_authenticator(),
            self.carol_group.epoch_authenticator()
        );
        detail.proposals
    }

    /// Both members store the hub's proposal as one from external sender 0.
    fn deliver(&mut self, message: &[u8]) {
        for (who, group) in [
            (&self.alice, &mut self.alice_group),
            (&self.carol, &mut self.carol_group),
        ] {
            let incoming = group
                .process(who, message, concat)
                .expect("member stores the hub's proposal");
            assert_eq!(
                incoming,
                Incoming::Proposal {
                    sender: Sender::External(0)
                }
            );
        }
    }

    /// Asserts that the Observer stored no proposal: carol's next Commit,
    /// which covers every proposal carol stored (none), is staged with no
    /// proposals. The Commit is then dropped everywhere.
    fn assert_nothing_stored(&mut self) {
        let before = self.observer.group_context().expect("context");
        let bundle = self
            .carol_group
            .commit(&self.carol, &[], &[], &[], concat)
            .expect("carol commits");
        self.observer
            .process(&self.store, &bundle.commit, concat)
            .expect("Observer stages the Commit");
        let detail = self.observer.pending_commit_detail().expect("detail");
        assert!(detail.proposals.is_empty(), "{:?}", detail.proposals);
        self.observer.clear_pending_commit();
        self.carol_group
            .clear_pending_commit(&self.carol)
            .expect("carol clears");
        assert_eq!(self.observer.group_context().expect("context"), before);
    }
}

/// RFC 9420 §5.2 `RefHash("MLS 1.0 Proposal Reference", AuthenticatedContent)`
/// as a TLS-encoded `HashReference`, computed with mls-rs's SHA-256. For a
/// PublicMessage from an external sender, the AuthenticatedContent
/// (`wire_format`, `content`, `auth`) is the `MLSMessage` after its
/// `version`.
fn proposal_ref(message: &[u8]) -> Vec<u8> {
    let label = b"MLS 1.0 Proposal Reference";
    let value = &message[2..];
    let mut input = varint(label.len());
    input.extend_from_slice(label);
    input.extend(varint(value.len()));
    input.extend_from_slice(value);
    let suite = RustCryptoProvider::default()
        .cipher_suite_provider(SUITE_1)
        .expect("suite 1");
    let hash = suite.hash(&input).expect("SHA-256");
    [vec![0x20], hash].concat() // opaque HashReference<V>: 32 bytes
}

#[test]
fn hub_update_matches_hand_encoding_and_is_committed_by_reference() {
    let mut room = room(&[(LOG, b"v0".to_vec())]);
    let message = room
        .observer
        .propose_app_data_update(
            &room.store,
            room.hub.signature_key(),
            0,
            &AppDataUpdate::Update {
                component_id: LOG,
                update: b"h1".to_vec(),
            },
        )
        .expect("hub proposes");

    // RFC 9420 §6 MLSMessage carrying a PublicMessage; its FramedContent is
    // also the FramedContentTBS (§6.1) without a GroupContext.
    let tbs: Vec<u8> = [
        &[0x00, 0x01][..],         // ProtocolVersion version = mls10
        &[0x00, 0x01],             // WireFormat wire_format = mls_public_message
        &[0x08],                   // opaque group_id<V>: 8 bytes
        GROUP_ID,                  //   "room-hub"
        &1u64.to_be_bytes(),       // uint64 epoch = 1
        &[0x02],                   // SenderType sender_type = external
        &[0x00, 0x00, 0x00, 0x00], // uint32 sender_index = 0
        &[0x00],                   // opaque authenticated_data<V>: empty
        &[0x02],                   // ContentType content_type = proposal
        &[0x00, 0x08],             // ProposalType proposal_type = app_data_update
        &[0x80, 0x01],             // ComponentID component_id = LOG
        &[0x01],                   // AppDataUpdateOperation op = update
        &[0x02, b'h', b'1'],       // opaque update<V>: "h1"
    ]
    .concat();
    // FramedContentAuthData: opaque signature<V> of 64 bytes, and no
    // confirmation_tag for a proposal. No membership_tag for an external
    // sender.
    assert_eq!(message.len(), tbs.len() + 2 + 64);
    assert_eq!(&message[..tbs.len()], tbs.as_slice());
    assert_eq!(&message[tbs.len()..tbs.len() + 2], &[0x40, 0x40]);
    label::verify_with_label(
        room.hub.verification_key(),
        FRAMED_CONTENT_LABEL,
        &tbs,
        &message[tbs.len() + 2..],
    )
    .expect("hub signature over the hand-built FramedContentTBS");

    room.deliver(&message);
    let proposals = room.carol_commits();
    assert_eq!(proposals.len(), 1);
    let detail = &proposals[0];
    assert_eq!(detail.sender, Sender::External(0));
    assert_eq!(
        detail.reference.as_ref().map(|r| r.as_bytes().to_vec()),
        Some(proposal_ref(&message)),
        "the Commit does not reference the hub's proposal"
    );
    assert_eq!(
        detail.proposal,
        ProposalKind::AppDataUpdate {
            component_id: LOG,
            update: Some(b"h1".to_vec()),
        }
    );
    for data in [
        room.observer.component(LOG),
        room.alice_group.component(LOG),
        room.carol_group.component(LOG),
    ] {
        assert_eq!(data, Some(&b"v0h1"[..]));
    }
    assert_eq!(room.observer.epoch(), 2);
}

#[test]
fn hub_updates_at_length_boundaries_are_committed_by_reference() {
    let mut room = room(&[]);
    let mut expected = Vec::new();
    for (i, (len, prefix)) in (0u16..).zip(LENGTH_BOUNDARIES) {
        let component_id = BOUNDARY_BASE + i;
        let update = vec![b'a' + i as u8; len];
        let message = room
            .observer
            .propose_app_data_update(
                &room.store,
                room.hub.signature_key(),
                0,
                &AppDataUpdate::Update {
                    component_id,
                    update: update.clone(),
                },
            )
            .expect("hub proposes");
        // RFC 9420 §12.1 Proposal: proposal_type, then the §4.7 body.
        let body = [
            &[0x00, 0x08][..],
            &component_id.to_be_bytes(),
            &[0x01],
            prefix,
            &update,
        ]
        .concat();
        assert!(
            position(&message, &body).is_some(),
            "hand-encoded AppDataUpdate of {len} bytes not found"
        );
        room.deliver(&message);
        expected.push((component_id, update));
    }
    let proposals = room.carol_commits();
    assert_eq!(proposals.len(), expected.len());
    for (component_id, update) in &expected {
        assert_eq!(room.observer.component(*component_id), Some(&update[..]));
        assert_eq!(room.alice_group.component(*component_id), Some(&update[..]));
        assert_eq!(room.carol_group.component(*component_id), Some(&update[..]));
    }
}

#[test]
fn hub_remove_needs_existing_data() {
    let mut room = room(&[(META, b"m0".to_vec())]);

    // §4.7: a remove of state that is not present is invalid, and is not
    // built or stored.
    let result = room.observer.propose_app_data_update(
        &room.store,
        room.hub.signature_key(),
        0,
        &AppDataUpdate::Remove {
            component_id: ABSENT,
        },
    );
    assert!(
        matches!(result, Err(ObserverError::InvalidAppDataUpdate(ABSENT))),
        "{result:?}"
    );
    room.assert_nothing_stored();

    let message = room
        .observer
        .propose_app_data_update(
            &room.store,
            room.hub.signature_key(),
            0,
            &AppDataUpdate::Remove { component_id: META },
        )
        .expect("hub proposes remove");
    let body = [
        0x00, 0x08, // ProposalType proposal_type = app_data_update
        0x80, 0x02, // ComponentID component_id = META
        0x02, // AppDataUpdateOperation op = remove, struct{}
    ];
    assert!(position(&message, &body).is_some());
    room.deliver(&message);
    let proposals = room.carol_commits();
    assert_eq!(
        proposals[0].proposal,
        ProposalKind::AppDataUpdate {
            component_id: META,
            update: None,
        }
    );
    assert_eq!(room.observer.component(META), None);
    assert_eq!(room.alice_group.component(META), None);
    assert_eq!(room.carol_group.component(META), None);
}

#[test]
fn wrong_signature_key_or_sender_index_is_refused_and_nothing_is_stored() {
    let mut room = room(&[]);
    let update = AppDataUpdate::Update {
        component_id: LOG,
        update: b"x".to_vec(),
    };

    // A well-formed key that is not external_senders[0]'s: the Observer's
    // own verification refuses the proposal.
    let other = SignatureKeyPair::generate().expect("key");
    let result =
        room.observer
            .propose_app_data_update(&room.store, other.signature_key(), 0, &update);
    assert!(
        matches!(result, Err(ObserverError::Process(_))),
        "{result:?}"
    );

    // Malformed private keys: empty, one byte short, one byte long.
    let long = [room.hub.signature_key(), &[0x00]].concat();
    for key in [&[][..], &room.hub.signature_key()[..31], &long] {
        let result = room
            .observer
            .propose_app_data_update(&room.store, key, 0, &update);
        assert!(result.is_err(), "{}-byte key accepted", key.len());
    }

    // No external_senders entry at the index.
    for index in [1, u32::MAX] {
        let result = room.observer.propose_app_data_update(
            &room.store,
            room.hub.signature_key(),
            index,
            &update,
        );
        assert!(
            matches!(result, Err(ObserverError::Propose(_))),
            "{result:?}"
        );
    }
    room.assert_nothing_stored();

    // No external_senders extension at all.
    let hub = SignatureKeyPair::generate().expect("hub key");
    let mut bare = room_with(&[], &[], hub);
    let result =
        bare.observer
            .propose_app_data_update(&bare.store, bare.hub.signature_key(), 0, &update);
    assert!(
        matches!(result, Err(ObserverError::Propose(_))),
        "{result:?}"
    );
    bare.assert_nothing_stored();
}

#[test]
fn hub_update_in_safe_aad_group_carries_empty_safe_aad_and_is_committed() {
    // A GroupContext safe_aad (0x0002) with an empty ComponentsList turns
    // on SafeAAD framing (mls-extensions-10 §4.9).
    let mut room = room(&[(SAFE_AAD, vec![0x00]), (LOG, b"v0".to_vec())]);
    let message = room
        .observer
        .propose_app_data_update(
            &room.store,
            room.hub.signature_key(),
            0,
            &AppDataUpdate::Update {
                component_id: LOG,
                update: b"h1".to_vec(),
            },
        )
        .expect("hub proposes");

    // As in hub_update_matches_hand_encoding_and_is_committed_by_reference,
    // but the authenticated_data is the §4.9 SafeAAD with no items.
    let tbs: Vec<u8> = [
        &[0x00, 0x01][..],         // ProtocolVersion version = mls10
        &[0x00, 0x01],             // WireFormat wire_format = mls_public_message
        &[0x08],                   // opaque group_id<V>: 8 bytes
        GROUP_ID,                  //   "room-hub"
        &1u64.to_be_bytes(),       // uint64 epoch = 1
        &[0x02],                   // SenderType sender_type = external
        &[0x00, 0x00, 0x00, 0x00], // uint32 sender_index = 0
        &[0x01],                   // opaque authenticated_data<V>: 1 byte
        &[0x00],                   //   SafeAADItem aad_items<V>: empty
        &[0x02],                   // ContentType content_type = proposal
        &[0x00, 0x08],             // ProposalType proposal_type = app_data_update
        &[0x80, 0x01],             // ComponentID component_id = LOG
        &[0x01],                   // AppDataUpdateOperation op = update
        &[0x02, b'h', b'1'],       // opaque update<V>: "h1"
    ]
    .concat();
    assert_eq!(message.len(), tbs.len() + 2 + 64);
    assert_eq!(&message[..tbs.len()], tbs.as_slice());
    assert_eq!(&message[tbs.len()..tbs.len() + 2], &[0x40, 0x40]);
    label::verify_with_label(
        room.hub.verification_key(),
        FRAMED_CONTENT_LABEL,
        &tbs,
        &message[tbs.len() + 2..],
    )
    .expect("hub signature over the hand-built FramedContentTBS");

    room.deliver(&message);
    // carol_commits also requires alice's and carol's epoch_authenticator
    // to match.
    let proposals = room.carol_commits();
    assert_eq!(proposals.len(), 1);
    assert_eq!(proposals[0].sender, Sender::External(0));
    assert_eq!(
        proposals[0]
            .reference
            .as_ref()
            .map(|r| r.as_bytes().to_vec()),
        Some(proposal_ref(&message))
    );
    for data in [
        room.observer.component(LOG),
        room.alice_group.component(LOG),
        room.carol_group.component(LOG),
    ] {
        assert_eq!(data, Some(&b"v0h1"[..]));
    }
    assert_eq!(room.observer.epoch(), 2);
}

#[test]
fn pending_commit_blocks_proposing() {
    let mut room = room(&[]);
    let bundle = room
        .carol_group
        .commit(&room.carol, &[], &[], &[], concat)
        .expect("carol commits");
    room.observer
        .process(&room.store, &bundle.commit, concat)
        .expect("Observer stages the Commit");
    let result = room.observer.propose_app_data_update(
        &room.store,
        room.hub.signature_key(),
        0,
        &AppDataUpdate::Update {
            component_id: LOG,
            update: b"x".to_vec(),
        },
    );
    assert!(
        matches!(result, Err(ObserverError::PendingCommit)),
        "{result:?}"
    );
}

#[test]
fn members_reject_a_tampered_hub_proposal() {
    let mut room = room(&[]);
    let message = room
        .observer
        .propose_app_data_update(
            &room.store,
            room.hub.signature_key(),
            0,
            &AppDataUpdate::Update {
                component_id: LOG,
                update: b"h1".to_vec(),
            },
        )
        .expect("hub proposes");
    let update_at = position(&message, b"h1").expect("update bytes");
    // The update byte, the sender_index, and the last signature byte.
    let sender_index_at = 2 + 2 + 1 + GROUP_ID.len() + 8 + 1 + 3;
    for at in [update_at, sender_index_at, message.len() - 1] {
        let mut tampered = message.clone();
        tampered[at] ^= 0x01;
        let result = room.carol_group.process(&room.carol, &tampered, concat);
        assert!(result.is_err(), "byte {at} flipped: {result:?}");
    }
    // The untampered proposal is still accepted afterwards.
    room.deliver(&message);
    room.carol_commits();
    assert_eq!(room.carol_group.component(LOG), Some(&b"h1"[..]));
}
