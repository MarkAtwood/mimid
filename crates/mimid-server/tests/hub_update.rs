//! protocol-06 §5.3 update endpoint tests (mimid-1wgh.6.27). MLS validity
//! is judged against mls-rs clients; room policy flows that need
//! AppDataUpdates use mimi-mls Members.

#[allow(dead_code, reason = "each test binary uses part of the helpers")]
mod common;
#[allow(dead_code, reason = "each test binary uses part of the helpers")]
#[path = "common/fanout.rs"]
mod common_fanout;
#[allow(dead_code, reason = "each test binary uses part of the helpers")]
#[path = "common/update.rs"]
mod update;

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use common::*;
use common_fanout::RecordingLocal;
use mimi_mls::member::{AppDataUpdate, ComponentOp, Member};
use mimi_mls::tls_codec::{Deserialize, Serialize};
use mimi_mls::wire::{MLSMessage, RatchetTreeRepresentation};
use mimi_mls::{ErrorSource, Identity, KeyPackageKind};
use mimi_protocol::component_id::PARTICIPANT_LIST;
use mimi_protocol::{
    FanoutEvent, FanoutMessage, ParticipantListUpdate, UpdateResult, UserRolePair,
};
use mimid_server::hub::fanout::Fanout;
use mimid_server::hub::{Hub, HubError};
use mimid_server::peer::PeerClient;
use mimid_server::store::Store;
use mls_rs::mls_rs_codec::MlsEncode;
use update::*;

const NOW: u64 = 1_700_000_000_000;

fn from(domain: &str) -> mimid_server::config::Domain {
    mimid_server::config::Domain::try_from(domain.to_owned()).unwrap()
}

fn a() -> mimid_server::config::Domain {
    from("a.example")
}

fn b() -> mimid_server::config::Domain {
    from("b.example")
}

fn success() -> UpdateResult {
    UpdateResult::Success {
        accepted_timestamp: NOW,
    }
}

/// Decodes one outbox body: a single FanoutMessage.
fn fanout(body: &[u8]) -> FanoutMessage {
    FanoutMessage::tls_deserialize_exact(body).unwrap()
}

/// alice and bob (mls-rs) commit in the same epoch at once. The hub accepts
/// exactly one; the other gets wrongEpoch, and the hub's tree and
/// GroupContext equal the winner's, byte for byte. The Commit is enqueued
/// for both member domains (decision mimid-1wgh.6.17).
#[tokio::test]
async fn concurrent_commits_one_wins_and_tree_matches_mls_rs() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("mimid.sqlite");
    let (store, hub) = open_hub(&path).await;
    let mut room = mls_rs_room(&hub, ROOM_ID, b"group-race").await;
    let alice = prepare_commit(&mut room.alice);
    let bob = prepare_commit(&mut room.bob);

    let (alice_domain, bob_domain) = (a(), b());
    let (alice_response, bob_response) = tokio::join!(
        hub.update(ROOM_ID, &alice_domain, &alice.request),
        hub.update(ROOM_ID, &bob_domain, &bob.request),
    );
    let results = [
        response(&alice_response.unwrap()).0,
        response(&bob_response.unwrap()).0,
    ];
    let wrong_epoch = UpdateResult::WrongEpoch { current_epoch: 2 };
    let (winner, commit) = match results {
        [ref first, ref second] if *first == success() && *second == wrong_epoch => {
            (&alice.applied, &alice.commit)
        }
        [ref first, ref second] if *first == wrong_epoch && *second == success() => {
            (&bob.applied, &bob.commit)
        }
        other => panic!("not exactly one success and one wrongEpoch: {other:?}"),
    };

    let state = hub.public_state(ROOM_ID).await.unwrap();
    assert_eq!(state.epoch, 2);
    assert_eq!(state.ratchet_tree, winner.export_tree().to_bytes().unwrap());
    assert_eq!(
        state.group_context,
        winner.context().mls_encode_to_vec().unwrap()
    );

    let db = connect(&path).await;
    assert_eq!(counts(&db).await, (1, 2, 0));
    let rows = outbox(&db).await;
    let domains: Vec<_> = rows.iter().map(|(domain, _)| domain.as_str()).collect();
    assert_eq!(domains, ["a.example", "b.example"]);
    for (_, body) in &rows {
        let message = fanout(body);
        assert_eq!(message.timestamp, NOW);
        let FanoutEvent::Commit {
            message,
            external_proposals,
        } = message.event
        else {
            panic!("not a commit fanout");
        };
        assert_eq!(message.as_bytes(), commit.as_slice(), "commit as received");
        assert!(external_proposals.is_empty());
    }
    let snapshot = &store.rooms().await.unwrap()[0];
    assert_eq!(snapshot.epoch, 2);
    assert_eq!(snapshot.ratchet_tree, state.ratchet_tree);
    db.close().await;
    close_hub(store, hub).await;
}

/// A retried Commit gets the same response and writes nothing, even after
/// its epoch has ended (decision mimid-1wgh.6.50).
#[tokio::test]
async fn commit_retry_gets_same_response_and_writes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("mimid.sqlite");
    let (store, hub) = open_hub(&path).await;
    let mut room = mls_rs_room(&hub, ROOM_ID, b"group-retry").await;
    let commit = prepare_commit(&mut room.alice);
    let first = hub.update(ROOM_ID, &a(), &commit.request).await.unwrap();
    assert_eq!(response(&first).0, success());
    let db = connect(&path).await;
    let before = counts(&db).await;
    let again = hub.update(ROOM_ID, &b(), &commit.request).await.unwrap();
    assert_eq!(again, first, "byte-identical, even with another From");
    assert_eq!(counts(&db).await, before);
    db.close().await;
    close_hub(store, hub).await;
}

/// A Commit whose From domain is not the committer's is refused before any
/// write, and the epoch stays open for it (decision mimid-1wgh.6.9).
#[tokio::test]
async fn envelope_mismatch_is_refused_before_any_write() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("mimid.sqlite");
    let (store, hub) = open_hub(&path).await;
    let mut room = mls_rs_room(&hub, ROOM_ID, b"group-envelope").await;
    let commit = prepare_commit(&mut room.bob);
    let db = connect(&path).await;
    let before = counts(&db).await;

    let refused = hub.update(ROOM_ID, &a(), &commit.request).await.unwrap();
    assert_not_allowed(&refused, "From domain is not the committer's domain");
    assert_eq!(counts(&db).await, before, "row counts unchanged");
    assert_eq!(hub.public_state(ROOM_ID).await.unwrap().epoch, 1);

    let accepted = hub.update(ROOM_ID, &b(), &commit.request).await.unwrap();
    assert_eq!(response(&accepted).0, success());
    db.close().await;
    close_hub(store, hub).await;
}

/// A Commit with a tampered signature fails MLS validation: nothing is
/// written and the epoch is unchanged.
#[tokio::test]
async fn tampered_commit_signature_writes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("mimid.sqlite");
    let (store, hub) = open_hub(&path).await;
    let mut room = mls_rs_room(&hub, ROOM_ID, b"group-tamper").await;
    let prepared = prepare_commit(&mut room.alice);

    // RFC 9420 §6.2: a member's PublicMessage carrying a commit ends with
    // `opaque signature<V>` (64 bytes for Ed25519), then `MAC
    // confirmation_tag` and `MAC membership_tag` (32 bytes each for suite
    // 1), each with a one-byte length.
    let mut commit = prepared.commit.clone();
    let len = commit.len();
    assert_eq!(commit[len - 33], 0x20, "membership_tag length");
    assert_eq!(commit[len - 66], 0x20, "confirmation_tag length");
    assert_eq!(commit[len - 131], 0x40, "signature length");
    commit[len - 67] ^= 0x01; // last signature byte
    let group_info = prepared
        .applied
        .group_info_message(false)
        .unwrap()
        .to_bytes()
        .unwrap();
    let tree = prepared.applied.export_tree().to_bytes().unwrap();
    let request = commit_request(&commit, None, &group_info, &tree);

    let db = connect(&path).await;
    let before = counts(&db).await;
    let before_state = hub.public_state(ROOM_ID).await.unwrap();
    let refused = hub.update(ROOM_ID, &a(), &request).await.unwrap();
    assert_not_allowed(&refused, "the commit is not valid");
    assert_eq!(counts(&db).await, before);
    assert_eq!(hub.public_state(ROOM_ID).await.unwrap(), before_state);
    db.close().await;
    close_hub(store, hub).await;
}

/// An `apply` for alice's Commit adding carol: the participant list after
/// the update, written out independently of the hub.
fn add_carol_apply(
    component_id: u16,
    _current: Option<&[u8]>,
    op: ComponentOp<'_>,
) -> Result<Option<Vec<u8>>, ErrorSource> {
    match (component_id, op) {
        (PARTICIPANT_LIST, ComponentOp::Update(_)) => Ok(Some(
            members_list(&[ALICE, BOB, CAROL])
                .tls_serialize_detached()
                .unwrap(),
        )),
        _ => Err("unexpected AppDataUpdate".into()),
    }
}

fn add_carol_update() -> AppDataUpdate {
    AppDataUpdate::Update {
        component_id: PARTICIPANT_LIST,
        update: ParticipantListUpdate {
            changed_role_participants: vec![],
            removed_indices: vec![],
            added_participants: vec![UserRolePair {
                user: CAROL.to_vec(),
                role_index: ROLE_MEMBER,
            }],
        }
        .tls_serialize_detached()
        .unwrap(),
    }
}

/// An MLS-valid Commit that room policy refuses (alice adds carol's client
/// without adding carol to the participant list) enqueues nothing and
/// leaves the epoch open: alice's next, allowed Commit wins it (decision
/// mimid-1wgh.6.5).
#[tokio::test]
async fn policy_denied_commit_leaves_epoch_open() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("mimid.sqlite");
    let (store, hub) = open_hub(&path).await;
    let mut room = member_room(&hub, ROOM_ID, b"group-policy").await;
    let carol = Identity::generate(CAROL, mimi_mls::Store::open_in_memory().unwrap()).unwrap();
    let key_package = carol.key_package(KeyPackageKind::OneTime).unwrap();
    let denied = room
        .alice_group
        .commit(&room.alice, &[&key_package], &[], &[], no_components)
        .unwrap();
    let tree = room.alice_group.ratchet_tree().unwrap();
    let request = commit_request(
        &denied.commit,
        denied.welcome.as_deref(),
        &denied.group_info,
        &tree,
    );
    let db = connect(&path).await;
    let before = counts(&db).await;
    let refused = hub.update(ROOM_ID, &a(), &request).await.unwrap();
    assert_not_allowed(&refused, "the commit is refused by room policy");
    assert_eq!(counts(&db).await, before, "no outbox row, no log row");
    assert_eq!(hub.public_state(ROOM_ID).await.unwrap().epoch, 1);

    room.alice_group.clear_pending_commit(&room.alice).unwrap();
    let allowed = room
        .alice_group
        .commit(
            &room.alice,
            &[&key_package],
            &[],
            &[add_carol_update()],
            add_carol_apply,
        )
        .unwrap();
    room.alice_group.merge_pending_commit(&room.alice).unwrap();
    let tree = room.alice_group.ratchet_tree().unwrap();
    let request = commit_request(
        &allowed.commit,
        allowed.welcome.as_deref(),
        &allowed.group_info,
        &tree,
    );
    let accepted = hub.update(ROOM_ID, &a(), &request).await.unwrap();
    assert_eq!(response(&accepted).0, success());
    let state = hub.public_state(ROOM_ID).await.unwrap();
    assert_eq!(state.epoch, 2);
    assert_eq!(state.ratchet_tree, tree);
    db.close().await;
    close_hub(store, hub).await;
}

/// alice's Commit adding carol fans the Welcome out to carol's domain only,
/// with the hub's tree as `RatchetTreeOption::full` (decisions
/// mimid-1wgh.6.10, mimid-1wgh.6.12); carol joins from it. The Commit goes
/// to every member domain before and after, and the hub wakes the fanout
/// worker, which delivers the own-domain row at once.
#[tokio::test]
async fn welcome_goes_to_added_users_domains_with_full_tree() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("mimid.sqlite");
    let store = Store::open(&path, &domain()).await.unwrap();
    let clock = Arc::new(FixedClock(NOW));
    let local = RecordingLocal::default();
    let worker = Fanout::new(
        store.clone(),
        domain(),
        PeerClient::new(&domain(), BTreeMap::new()).unwrap(),
        local.clone(),
        clock.clone(),
    )
    .spawn();
    let hub = Hub::open(store.clone(), domain(), clock)
        .await
        .unwrap()
        .with_fanout(worker);
    let mut room = member_room(&hub, ROOM_ID, b"group-welcome").await;
    let carol = Identity::generate(CAROL, mimi_mls::Store::open_in_memory().unwrap()).unwrap();
    let key_package = carol.key_package(KeyPackageKind::OneTime).unwrap();
    let bundle = room
        .alice_group
        .commit(
            &room.alice,
            &[&key_package],
            &[],
            &[add_carol_update()],
            add_carol_apply,
        )
        .unwrap();
    room.alice_group.merge_pending_commit(&room.alice).unwrap();
    let tree = room.alice_group.ratchet_tree().unwrap();
    let request = commit_request(
        &bundle.commit,
        bundle.welcome.as_deref(),
        &bundle.group_info,
        &tree,
    );
    let accepted = hub.update(ROOM_ID, &a(), &request).await.unwrap();
    assert_eq!(response(&accepted).0, success());
    let state = hub.public_state(ROOM_ID).await.unwrap();
    assert_eq!(state.ratchet_tree, tree);

    // The own-domain Commit row is delivered without waiting for a timer.
    tokio::time::timeout(Duration::from_secs(10), async {
        while local.attempts().is_empty() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("fanout worker woken");
    let (room_id, body) = &local.attempts()[0];
    assert_eq!(room_id, ROOM_ID);
    assert!(matches!(fanout(body).event, FanoutEvent::Commit { .. }));

    // The worker deletes the own-domain row only after `deliver` returns,
    // so wait for that before reading the outbox.
    let db = connect(&path).await;
    tokio::time::timeout(Duration::from_secs(10), async {
        while outbox(&db).await.iter().any(|(d, _)| d == DOMAIN) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("own-domain outbox row delivered");

    // Rows for unconfigured peers stay queued (parked).
    let rows = outbox(&db).await;
    let mut commits = Vec::new();
    let mut welcomes = Vec::new();
    for (domain, body) in &rows {
        match fanout(body).event {
            FanoutEvent::Commit { message, .. } => {
                assert_eq!(message.as_bytes(), bundle.commit.as_slice());
                commits.push(domain.clone());
            }
            FanoutEvent::Welcome {
                message,
                ratchet_tree_option,
            } => {
                assert_eq!(message.as_bytes(), bundle.welcome.as_deref().unwrap());
                assert_eq!(
                    ratchet_tree_option.representation(),
                    RatchetTreeRepresentation::Full
                );
                assert_eq!(ratchet_tree_option.ratchet_tree(), Some(tree.as_slice()));
                welcomes.push((domain.clone(), message, tree.clone()));
            }
            other => panic!("unexpected fanout {other:?}"),
        }
    }
    assert_eq!(commits, ["b.example", "c.example"]);
    assert_eq!(welcomes.len(), 1);
    let (welcome_domain, welcome, welcome_tree) = welcomes.remove(0);
    assert_eq!(welcome_domain, "c.example");

    let joined = Member::join_welcome(&carol, welcome.as_bytes(), Some(&welcome_tree))
        .unwrap()
        .member;
    assert_eq!(joined.epoch(), state.epoch);
    assert_eq!(joined.ratchet_tree().unwrap(), state.ratchet_tree);
    db.close().await;
    drop(hub);
    store.close().await;
}

/// bob (mls-rs) proposes an Update. alice's Commit that leaves it out is
/// refused; once alice includes it by reference, it is accepted and the
/// pending proposal is dropped (decision mimid-1wgh.6.5).
#[tokio::test]
async fn commit_missing_pending_proposal_is_not_allowed() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("mimid.sqlite");
    let (store, hub) = open_hub(&path).await;
    let mut room = mls_rs_room(&hub, ROOM_ID, b"group-pending").await;
    let proposal = room
        .bob
        .propose_update(EMPTY_SAFE_AAD.to_vec())
        .unwrap()
        .to_bytes()
        .unwrap();
    let accepted = hub
        .update(ROOM_ID, &b(), &proposal_request(&proposal, &[]))
        .await
        .unwrap();
    assert_eq!(response(&accepted).0, success());

    let db = connect(&path).await;
    let mut without = room.alice.clone();
    let omitting = prepare_commit(&mut without);
    let before = counts(&db).await;
    let refused = hub.update(ROOM_ID, &a(), &omitting.request).await.unwrap();
    assert_not_allowed(
        &refused,
        "the commit does not include every pending proposal",
    );
    assert_eq!(counts(&db).await, before);

    room.alice
        .process_incoming_message(mls_rs::MlsMessage::from_bytes(&proposal).unwrap())
        .unwrap();
    let including = prepare_commit(&mut room.alice);
    let accepted = hub.update(ROOM_ID, &a(), &including.request).await.unwrap();
    assert_eq!(response(&accepted).0, success());
    assert_eq!(
        counts(&db).await.2,
        0,
        "pending proposals of epoch 1 dropped"
    );
    assert_eq!(
        hub.public_state(ROOM_ID).await.unwrap().ratchet_tree,
        including.applied.export_tree().to_bytes().unwrap()
    );
    db.close().await;
    close_hub(store, hub).await;
}

/// Proposals are stored as pending with their hub acceptance time and fanned
/// out in one FanoutMessage, `moreProposals` exactly as received.
#[tokio::test]
async fn proposals_are_stored_and_fanned_out_verbatim() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("mimid.sqlite");
    let (store, hub) = open_hub(&path).await;
    let mut room = mls_rs_room(&hub, ROOM_ID, b"group-proposals").await;
    let bobs = room
        .bob
        .propose_update(EMPTY_SAFE_AAD.to_vec())
        .unwrap()
        .to_bytes()
        .unwrap();
    let alices = room
        .alice
        .propose_update(EMPTY_SAFE_AAD.to_vec())
        .unwrap()
        .to_bytes()
        .unwrap();
    let request = proposal_request(&bobs, &[&alices]);

    let db = connect(&path).await;
    let refused = hub.update(ROOM_ID, &a(), &request).await.unwrap();
    assert_not_allowed(&refused, "From domain is not the proposer's domain");
    assert_eq!(counts(&db).await, (0, 0, 0));

    let accepted = hub.update(ROOM_ID, &b(), &request).await.unwrap();
    assert_eq!(response(&accepted).0, success());
    let pending: Vec<(i64, Vec<u8>, i64)> = sqlx::query_as(
        "SELECT epoch, proposal, hub_accepted_time FROM pending_proposal ORDER BY seq",
    )
    .fetch_all(&db)
    .await
    .unwrap();
    let now = i64::try_from(NOW).unwrap();
    assert_eq!(pending, [(1, bobs.clone(), now), (1, alices.clone(), now)]);
    let rows = outbox(&db).await;
    assert_eq!(rows.len(), 2);
    for (_, body) in &rows {
        let FanoutEvent::Proposal {
            message,
            more_proposals,
        } = fanout(body).event
        else {
            panic!("not a proposal fanout");
        };
        assert_eq!(message.as_bytes(), bobs.as_slice());
        let more: Vec<_> = more_proposals.iter().map(MLSMessage::as_bytes).collect();
        assert_eq!(more, [alices.as_slice()]);
    }
    db.close().await;
    close_hub(store, hub).await;
}

/// While bob's proposal is pending, carol's external Commit is refused
/// (decision mimid-1wgh.6.4). Once it is committed, carol's external
/// Commit for the new epoch is accepted.
#[tokio::test]
async fn external_commit_refused_while_proposals_pending() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("mimid.sqlite");
    let (store, hub) = open_hub(&path).await;
    let mut room = mls_rs_room(&hub, ROOM_ID, b"group-external").await;
    let proposal = room
        .bob
        .propose_update(EMPTY_SAFE_AAD.to_vec())
        .unwrap()
        .to_bytes()
        .unwrap();
    let accepted = hub
        .update(ROOM_ID, &b(), &proposal_request(&proposal, &[]))
        .await
        .unwrap();
    assert_eq!(response(&accepted).0, success());

    let external = |alice: &mls_rs::Group<_>, carol: &mls_rs::Client<_>| {
        let group_info = alice.group_info_message_allowing_ext_commit(false).unwrap();
        let (joined, commit) = carol
            .external_commit_builder()
            .unwrap()
            .with_tree_data(alice.export_tree().into_owned())
            .with_leaf_node_extensions(mls_rs_leaf_extensions())
            .with_authenticated_data(EMPTY_SAFE_AAD.to_vec())
            .build(group_info)
            .unwrap();
        let group_info = joined
            .group_info_message(false)
            .unwrap()
            .to_bytes()
            .unwrap();
        let tree = joined.export_tree().to_bytes().unwrap();
        commit_request(&commit.to_bytes().unwrap(), None, &group_info, &tree)
    };
    let c = from("c.example");
    let db = connect(&path).await;
    let before = counts(&db).await;
    let refused = hub
        .update(ROOM_ID, &c, &external(&room.alice, &room.carol))
        .await
        .unwrap();
    assert_not_allowed(
        &refused,
        "external commits are refused while proposals are pending",
    );
    assert_eq!(counts(&db).await, before);

    room.alice
        .process_incoming_message(mls_rs::MlsMessage::from_bytes(&proposal).unwrap())
        .unwrap();
    let commit = prepare_commit(&mut room.alice);
    let accepted = hub.update(ROOM_ID, &a(), &commit.request).await.unwrap();
    assert_eq!(response(&accepted).0, success());
    let joined = hub
        .update(ROOM_ID, &c, &external(&commit.applied, &room.carol))
        .await
        .unwrap();
    assert_eq!(response(&joined).0, success());
    assert_eq!(hub.public_state(ROOM_ID).await.unwrap().epoch, 3);
    db.close().await;
    close_hub(store, hub).await;
}

/// A Commit whose GroupInfo embeds a ratchet_tree is refused, and the
/// epoch stays open: the same Commit with a GroupInfo without the tree is
/// accepted (decision mimid-1wgh.6.11).
#[tokio::test]
async fn group_info_with_ratchet_tree_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("mimid.sqlite");
    let (store, hub) = open_hub(&path).await;
    let mut room = mls_rs_room(&hub, ROOM_ID, b"group-tree").await;
    let prepared = prepare_commit(&mut room.alice);
    let with_tree = prepared
        .applied
        .group_info_message(true)
        .unwrap()
        .to_bytes()
        .unwrap();
    let tree = prepared.applied.export_tree().to_bytes().unwrap();
    let request = commit_request(&prepared.commit, None, &with_tree, &tree);
    let db = connect(&path).await;
    let refused = hub.update(ROOM_ID, &a(), &request).await.unwrap();
    assert_not_allowed(&refused, "the GroupInfo embeds a ratchet_tree");
    assert_eq!(counts(&db).await, (0, 0, 0));

    let accepted = hub.update(ROOM_ID, &a(), &prepared.request).await.unwrap();
    assert_eq!(response(&accepted).0, success());
    let snapshot = &store.rooms().await.unwrap()[0];
    let stored = snapshot.group_info.clone();
    assert_eq!(
        stored,
        prepared
            .applied
            .group_info_message(false)
            .unwrap()
            .to_bytes()
            .unwrap(),
        "stored GroupInfo is the one received, without a tree"
    );
    db.close().await;
    close_hub(store, hub).await;
}

/// create_room refuses a GroupInfo that embeds a ratchet_tree (decision
/// mimid-1wgh.6.11), and stores nothing.
#[tokio::test]
async fn create_room_refuses_group_info_with_ratchet_tree() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("mimid.sqlite");
    let (store, hub) = open_hub(&path).await;
    let other = mls_rs_room(&hub, ROOM_ID, b"group-source").await;
    let with_tree = other
        .alice
        .group_info_message(true)
        .unwrap()
        .to_bytes()
        .unwrap();
    let tree = other.alice.export_tree().to_bytes().unwrap();
    close_hub(store, hub).await;

    // A fresh hub, where the group is not hosted yet.
    let fresh = tempfile::tempdir().unwrap();
    let (store, hub) = open_hub(&fresh.path().join("mimid.sqlite")).await;
    let error = hub
        .create_room(ROOM_ID, ALICE, &with_tree, &tree)
        .await
        .unwrap_err();
    assert!(
        matches!(error, HubError::GroupInfoHasRatchetTree),
        "{error:?}"
    );
    assert!(store.rooms().await.unwrap().is_empty());
    close_hub(store, hub).await;
}

/// A write that fails after the Commit was merged leaves the hub's
/// in-memory state equal to the stored snapshot, and the epoch open: the
/// same request succeeds once the store works again.
#[tokio::test]
async fn failure_after_merge_restores_stored_state() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("mimid.sqlite");
    let (store, hub) = open_hub(&path).await;
    let mut room = mls_rs_room(&hub, ROOM_ID, b"group-failure").await;
    let prepared = prepare_commit(&mut room.alice);
    let before = hub.public_state(ROOM_ID).await.unwrap();

    let db = connect(&path).await;
    sqlx::query(
        "CREATE TRIGGER fail_outbox BEFORE INSERT ON outbox \
         BEGIN SELECT RAISE(ABORT, 'injected failure'); END",
    )
    .execute(&db)
    .await
    .unwrap();
    let error = hub
        .update(ROOM_ID, &a(), &prepared.request)
        .await
        .unwrap_err();
    assert!(matches!(error, HubError::Store(_)), "{error:?}");
    assert_eq!(counts(&db).await, (0, 0, 0));
    let after = hub.public_state(ROOM_ID).await.unwrap();
    assert_eq!(after, before, "in-memory state is the stored state");
    let snapshot = &store.rooms().await.unwrap()[0];
    assert_eq!(snapshot.epoch, after.epoch);
    assert_eq!(snapshot.ratchet_tree, after.ratchet_tree);

    sqlx::query("DROP TRIGGER fail_outbox")
        .execute(&db)
        .await
        .unwrap();
    let accepted = hub.update(ROOM_ID, &a(), &prepared.request).await.unwrap();
    assert_eq!(response(&accepted).0, success());
    assert_eq!(
        hub.public_state(ROOM_ID).await.unwrap().ratchet_tree,
        prepared.applied.export_tree().to_bytes().unwrap()
    );
    db.close().await;
    close_hub(store, hub).await;
}

/// After a restart, stored pending proposals are replayed (decision
/// mimid-1wgh.6.6): a Commit omitting bob's proposal is still refused, and
/// one including it by reference is accepted.
#[tokio::test]
async fn restart_replays_pending_proposals() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("mimid.sqlite");
    let (store, hub) = open_hub(&path).await;
    let mut room = mls_rs_room(&hub, ROOM_ID, b"group-replay").await;
    let proposal = room
        .bob
        .propose_update(EMPTY_SAFE_AAD.to_vec())
        .unwrap()
        .to_bytes()
        .unwrap();
    let accepted = hub
        .update(ROOM_ID, &b(), &proposal_request(&proposal, &[]))
        .await
        .unwrap();
    assert_eq!(response(&accepted).0, success());
    close_hub(store, hub).await;

    let (store, hub) = open_hub(&path).await;
    let mut without = room.alice.clone();
    let omitting = prepare_commit(&mut without);
    let refused = hub.update(ROOM_ID, &a(), &omitting.request).await.unwrap();
    assert_not_allowed(
        &refused,
        "the commit does not include every pending proposal",
    );

    room.alice
        .process_incoming_message(mls_rs::MlsMessage::from_bytes(&proposal).unwrap())
        .unwrap();
    let including = prepare_commit(&mut room.alice);
    let accepted = hub.update(ROOM_ID, &a(), &including.request).await.unwrap();
    assert_eq!(response(&accepted).0, success());
    assert_eq!(
        hub.public_state(ROOM_ID).await.unwrap().ratchet_tree,
        including.applied.export_tree().to_bytes().unwrap()
    );
    close_hub(store, hub).await;
}

/// Every `tracing` event at TRACE, through accepted and refused proposals
/// and Commits and a restart, is free of the hub's signing key and
/// `hub_key`.
#[tokio::test]
async fn trace_logs_never_contain_hub_secrets() {
    let logs = capture_logs();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("mimid.sqlite");
    let (store, hub) = open_hub(&path).await;
    let mut room = mls_rs_room(&hub, ROOM_ID, b"group-canary").await;
    let proposal = room
        .bob
        .propose_update(EMPTY_SAFE_AAD.to_vec())
        .unwrap()
        .to_bytes()
        .unwrap();
    let request = proposal_request(&proposal, &[]);
    hub.update(ROOM_ID, &a(), &request).await.unwrap();
    hub.update(ROOM_ID, &b(), &request).await.unwrap();
    close_hub(store, hub).await;
    let (store, hub) = open_hub(&path).await;
    let mut without = room.alice.clone();
    hub.update(ROOM_ID, &a(), &prepare_commit(&mut without).request)
        .await
        .unwrap();
    room.alice
        .process_incoming_message(mls_rs::MlsMessage::from_bytes(&proposal).unwrap())
        .unwrap();
    let accepted = hub
        .update(ROOM_ID, &a(), &prepare_commit(&mut room.alice).request)
        .await
        .unwrap();
    assert_eq!(response(&accepted).0, success());

    let secret = store.hub_secret().await.unwrap().unwrap();
    let text = logs.contents();
    assert!(text.contains("commit accepted"), "capture works: {text}");
    assert!(text.contains("update refused"), "capture works: {text}");
    assert_secret_absent(&text, &secret.signature_private_key, "signing key");
    assert_secret_absent(&text, &secret.hub_key, "hub_key");
    close_hub(store, hub).await;
}

/// An `apply` for a Commit changing `safe_aad`: the new list is the update
/// itself (an empty ComponentsList here), and a remove removes it.
fn safe_aad_apply(
    component_id: u16,
    _current: Option<&[u8]>,
    op: ComponentOp<'_>,
) -> Result<Option<Vec<u8>>, ErrorSource> {
    match (component_id, op) {
        (SAFE_AAD, ComponentOp::Update(updates)) => Ok(updates.last().map(|u| u.to_vec())),
        (SAFE_AAD, ComponentOp::Remove) => Ok(None),
        _ => Err("unexpected AppDataUpdate".into()),
    }
}

/// A Commit that drops frank_aad from the room's required Safe AAD
/// components, by an AppDataUpdate of `safe_aad` to an empty list or by
/// removing it, is refused and changes nothing (bead mimid-1wgh.6.74). The
/// hub's AppDataUpdate logic knows only the components it tracks, so any
/// change to `safe_aad` is refused (hub/components.rs apply_commit_op).
#[tokio::test]
async fn commit_dropping_frank_aad_from_safe_aad_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("mimid.sqlite");
    let (store, hub) = open_hub(&path).await;
    let mut room = member_room(&hub, ROOM_ID, b"group-safe-aad").await;
    let db = connect(&path).await;
    for (case, update) in [
        (
            "update to an empty list",
            AppDataUpdate::Update {
                component_id: SAFE_AAD,
                // ComponentsList with an empty component_ids<V>.
                update: vec![0x00],
            },
        ),
        (
            "remove",
            AppDataUpdate::Remove {
                component_id: SAFE_AAD,
            },
        ),
    ] {
        let bundle = room
            .alice_group
            .commit(&room.alice, &[], &[], &[update], safe_aad_apply)
            .unwrap();
        let tree = room.alice_group.ratchet_tree().unwrap();
        let request = commit_request(&bundle.commit, None, &bundle.group_info, &tree);
        let before = counts(&db).await;
        let before_state = hub.public_state(ROOM_ID).await.unwrap();
        let refused = hub.update(ROOM_ID, &a(), &request).await.unwrap();
        // The hub's AppDataUpdate logic does not know safe_aad, so the
        // Commit fails MLS processing (hub/components.rs apply_commit_op).
        assert_eq!(
            response(&refused),
            (
                UpdateResult::NotAllowed,
                "the commit is not valid".to_owned()
            ),
            "{case}"
        );
        assert_eq!(counts(&db).await, before, "{case}");
        assert_eq!(
            hub.public_state(ROOM_ID).await.unwrap(),
            before_state,
            "{case}"
        );
        room.alice_group.clear_pending_commit(&room.alice).unwrap();
    }
    db.close().await;
    close_hub(store, hub).await;
}
