//! Rooms without franking and without a base_room_policy (decision
//! mimid-1wgh.52, bead mimid-1wgh.53): a hub whose operator allows open
//! rooms (`require_room_policy = false`; bead mimid-jf20) hosts them, accepts their
//! messages unfranked, accepts abuse reports in them with the messages
//! unverified, and authorizes them as open rooms. Groups are built with
//! mimi-mls Members; the hub's answers are decoded with mimi-protocol.

#[allow(dead_code, reason = "each test binary uses part of the helpers")]
mod common;
#[allow(dead_code, reason = "each test binary uses part of the helpers")]
#[path = "common/submit.rs"]
mod submit;
#[allow(dead_code, reason = "each test binary uses part of the helpers")]
#[path = "common/update.rs"]
mod update;

use mimi_mls::member::{AppDataUpdate, ExternalSender, Member};
use mimi_mls::tls_codec::{Deserialize, Serialize};
use mimi_mls::wire::CipherSuite;
use mimi_mls::{Identity, KeyPackageKind};
use mimi_protocol::component_id::PARTICIPANT_LIST;
use mimi_protocol::components::apply_commit_op;
use mimi_protocol::{
    AbuseReport, AbuseType, AbusiveMessage, Frank, ParticipantListUpdate, SubmitMessageResponse,
    SubmitResult, UpdateResult, UserRolePair,
};
use mimid_server::config::Domain;
use mimid_server::hub::Hub;

use common::*;
use submit::submit_request;
use update::{commit_request, members_list, response};

const CAROL: &[u8] = b"mimi://a.example/u/carol";

fn a() -> Domain {
    Domain::try_from("a.example".to_owned()).unwrap()
}

/// alice creates a room with only the hub as external sender and a
/// participant list listing alice and bob with role 2: no Safe AAD, no
/// franking_agent, no roles, no base_room_policy. She adds bob, and the
/// hub hosts the room at epoch 1. Returns alice and bob with their groups.
async fn plain_room(hub: &Hub) -> (Identity, Member, Identity, Member) {
    let alice = Identity::generate(ALICE, mimi_mls::Store::open_in_memory().unwrap()).unwrap();
    let bob = Identity::generate(BOB, mimi_mls::Store::open_in_memory().unwrap()).unwrap();
    let senders = [ExternalSender {
        signature_key: hub.signature_public_key().to_vec(),
        identity: HUB_IDENTITY.to_vec(),
    }];
    let components = [
        // app_components naming participant_list only.
        (APP_COMPONENTS, vec![0x02, 0x00, 0x22]),
        (
            PARTICIPANT_LIST,
            members_list(&[ALICE, BOB])
                .tls_serialize_detached()
                .unwrap(),
        ),
    ];
    let mut group = Member::create(&alice, b"plain-room", &senders, &components).unwrap();
    let key_package = bob.key_package(KeyPackageKind::OneTime).unwrap();
    let bundle = group
        .commit(&alice, &[&key_package], &[], &[], no_components)
        .unwrap();
    group.merge_pending_commit(&alice).unwrap();
    let tree = group.ratchet_tree().unwrap();
    hub.create_room(ROOM_ID, ALICE, &bundle.group_info, &tree)
        .await
        .expect("a room without franking or policy is hosted");
    let bob_group = Member::join_welcome(&bob, bundle.welcome.as_deref().unwrap(), Some(&tree))
        .unwrap()
        .member;
    (alice, group, bob, bob_group)
}

#[tokio::test]
async fn a_message_is_accepted_unfranked() {
    let dir = tempfile::tempdir().unwrap();
    let (store, hub) = open_hub_allowing_open_rooms(&dir.path().join("mimid.sqlite")).await;
    let (alice, mut group, _, _) = plain_room(&hub).await;
    let message = group.send(&alice, b"no frank here", &[]).unwrap();
    let answer = hub
        .submit_message(ROOM_ID, &a(), &submit_request(&message, ALICE))
        .await
        .unwrap();
    let answer = SubmitMessageResponse::tls_deserialize_exact(&answer[..]).unwrap();
    assert!(
        matches!(answer.result, SubmitResult::Accepted { frank: None, .. }),
        "{answer:?}"
    );
    close_hub(store, hub).await;
}

#[tokio::test]
async fn an_abuse_report_is_accepted_with_its_messages_unverified() {
    let dir = tempfile::tempdir().unwrap();
    let (store, hub) = open_hub_allowing_open_rooms(&dir.path().join("mimid.sqlite")).await;
    let logs = capture_logs();
    let _room = plain_room(&hub).await;
    // A frank that could never verify: there is nothing to verify it
    // against in a room without franking.
    let report = AbuseReport {
        reporting_user: mimi_protocol::IdentifierUri::new("mimi://b.example/u/bob").unwrap(),
        alleged_abuser_uri: mimi_protocol::IdentifierUri::new("mimi://a.example/u/alice").unwrap(),
        reason_code: AbuseType(1),
        note: b"unverified".to_vec(),
        messages: vec![AbusiveMessage {
            message_content: b"something rude".to_vec(),
            frank: Frank {
                server_frank: [0x55; 32],
                franking_signature_ciphersuite: CipherSuite::tls_deserialize_exact([0x00, 0x01])
                    .unwrap(),
                franking_integrity_signature: vec![0x01; 64],
            },
            accepted_timestamp: 1,
        }],
        abuse_extensions: mimi_mls::wire::AppDataDictionary::new(&[]).unwrap(),
    }
    .tls_serialize_detached()
    .unwrap();
    hub.report_abuse(
        ROOM_ID,
        &Domain::try_from("b.example".to_owned()).unwrap(),
        &report,
    )
    .await
    .expect("accepted");
    let text = logs.contents();
    assert!(
        text.lines()
            .any(|line| line.contains("abuse report accepted")
                && line.split_whitespace().any(|field| field == "verified=0")
                && line.split_whitespace().any(|field| field == "unverified=1")),
        "accepted and logged as unverified"
    );
    close_hub(store, hub).await;
}

#[tokio::test]
async fn an_open_room_takes_an_add_from_a_participant() {
    let dir = tempfile::tempdir().unwrap();
    let (store, hub) = open_hub_allowing_open_rooms(&dir.path().join("mimid.sqlite")).await;
    let (alice, mut group, _, _) = plain_room(&hub).await;
    let carol = Identity::generate(CAROL, mimi_mls::Store::open_in_memory().unwrap()).unwrap();
    let key_package = carol.key_package(KeyPackageKind::OneTime).unwrap();
    let list_update = AppDataUpdate::Update {
        component_id: PARTICIPANT_LIST,
        update: ParticipantListUpdate {
            changed_role_participants: vec![],
            removed_indices: vec![],
            added_participants: vec![UserRolePair {
                user: CAROL.to_vec(),
                role_index: 2,
            }],
        }
        .tls_serialize_detached()
        .unwrap(),
    };
    let bundle = group
        .commit(
            &alice,
            &[&key_package],
            &[],
            &[list_update],
            apply_commit_op,
        )
        .unwrap();
    let tree = group.ratchet_tree().unwrap();
    let answer = hub
        .update(
            ROOM_ID,
            &a(),
            &commit_request(
                &bundle.commit,
                bundle.welcome.as_deref(),
                &bundle.group_info,
                &tree,
            ),
        )
        .await
        .unwrap();
    assert!(
        matches!(response(&answer).0, UpdateResult::Success { .. }),
        "{:?}",
        response(&answer)
    );
    close_hub(store, hub).await;
}

#[tokio::test]
async fn an_open_room_takes_a_leave_committed_by_reference() {
    // protocol-07 §3.5 as mimid-chat now sends it: bob's own Remove and the
    // participant-list update, one proposal bundle; alice commits both by
    // reference with nothing of her own.
    let dir = tempfile::tempdir().unwrap();
    let (store, hub) = open_hub_allowing_open_rooms(&dir.path().join("mimid.sqlite")).await;
    let (alice, mut group, bob, mut bob_group) = plain_room(&hub).await;
    let remove = bob_group.propose_self_remove(&bob).unwrap();
    let list_update = bob_group
        .propose_app_data_update(
            &bob,
            &AppDataUpdate::Update {
                component_id: PARTICIPANT_LIST,
                update: ParticipantListUpdate {
                    changed_role_participants: vec![],
                    removed_indices: vec![1],
                    added_participants: vec![],
                }
                .tls_serialize_detached()
                .unwrap(),
            },
        )
        .unwrap();
    let b = Domain::try_from("b.example".to_owned()).unwrap();
    let answer = hub
        .update(
            ROOM_ID,
            &b,
            &update::proposal_request(&remove, &[&list_update]),
        )
        .await
        .unwrap();
    assert!(
        matches!(response(&answer).0, UpdateResult::Success { .. }),
        "proposals: {:?}",
        response(&answer)
    );
    for message in [&remove, &list_update] {
        group.process(&alice, message, apply_commit_op).unwrap();
    }
    let bundle = group
        .commit(&alice, &[], &[], &[], apply_commit_op)
        .unwrap();
    let tree = group.ratchet_tree().unwrap();
    let answer = hub
        .update(
            ROOM_ID,
            &a(),
            &commit_request(&bundle.commit, None, &bundle.group_info, &tree),
        )
        .await
        .unwrap();
    assert!(
        matches!(response(&answer).0, UpdateResult::Success { .. }),
        "commit: {:?}",
        response(&answer)
    );
    group.merge_pending_commit(&alice).unwrap();
    assert_eq!(group.members().len(), 1);
    close_hub(store, hub).await;
}
