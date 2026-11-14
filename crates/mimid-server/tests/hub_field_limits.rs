//! Size limits on fields the hub receives (bead mimid-1wgh.52.2): a room
//! whose components hold a field over the limit is not hosted, and a
//! Commit that writes one is refused. The same group or Commit under the
//! default limits is accepted, so the limit is what refuses it.

#[allow(dead_code, reason = "each test binary uses part of the helpers")]
mod common;
#[allow(dead_code, reason = "each test binary uses part of the helpers")]
#[path = "common/update.rs"]
mod update;

use mimi_mls::member::{AppDataUpdate, ExternalSender, Member};
use mimi_mls::tls_codec::Serialize;
use mimi_mls::{Identity, KeyPackageKind};
use mimi_protocol::component_id::PARTICIPANT_LIST;
use mimi_protocol::{ParticipantListUpdate, UpdateResult, UserRolePair};
use mimid_server::config::Domain;
use mimid_server::hub::components::apply_commit_op;
use mimid_server::hub::{Hub, HubError};
use mimid_server::limits::FieldLimits;

use common::*;
use update::{commit_request, members_list, response};

/// 26 octets: one over the low URI limit below.
const CAROLYN: &[u8] = b"mimi://a.example/u/carolyn";

/// URIs of at most 25 octets: alice and bob (24) fit, carolyn does not.
fn low() -> FieldLimits {
    FieldLimits {
        uri: 25,
        ..FieldLimits::default()
    }
}

fn a() -> Domain {
    Domain::try_from("a.example".to_owned()).unwrap()
}

/// alice's group for an open room listing `listed`, with bob added.
fn group(hub: &Hub, alice: &Identity, listed: &[&[u8]]) -> (Member, Vec<u8>, Vec<u8>) {
    let bob = Identity::generate(BOB, mimi_mls::Store::open_in_memory().unwrap()).unwrap();
    let senders = [ExternalSender {
        signature_key: hub.signature_public_key().to_vec(),
        identity: HUB_IDENTITY.to_vec(),
    }];
    let components = [
        (APP_COMPONENTS, vec![0x02, 0x00, 0x22]),
        (
            PARTICIPANT_LIST,
            members_list(listed).tls_serialize_detached().unwrap(),
        ),
    ];
    let mut group = Member::create(alice, b"limits-room", &senders, &components).unwrap();
    let key_package = bob.key_package(KeyPackageKind::OneTime).unwrap();
    let bundle = group
        .commit(alice, &[&key_package], &[], &[], no_components)
        .unwrap();
    group.merge_pending_commit(alice).unwrap();
    let tree = group.ratchet_tree().unwrap();
    (group, bundle.group_info, tree)
}

#[tokio::test]
async fn a_room_listing_an_over_long_uri_is_not_hosted() {
    let dir = tempfile::tempdir().unwrap();
    let (store, hub) = open_hub(&dir.path().join("mimid.sqlite")).await;
    let hub = hub.with_limits(low());
    let alice = Identity::generate(ALICE, mimi_mls::Store::open_in_memory().unwrap()).unwrap();
    let (_, group_info, tree) = group(&hub, &alice, &[ALICE, BOB, CAROLYN]);
    let refused = hub.create_room(ROOM_ID, ALICE, &group_info, &tree).await;
    assert!(
        matches!(refused, Err(HubError::FieldTooLong(ref e)) if e.len == 26 && e.limit == 25),
        "{refused:?}"
    );
    close_hub(store, hub).await;
}

/// alice adds carolyn: her client and her participant-list entry.
async fn add_carolyn(limits: FieldLimits) -> UpdateResult {
    let dir = tempfile::tempdir().unwrap();
    let (store, hub) = open_hub(&dir.path().join("mimid.sqlite")).await;
    let hub = hub.with_limits(limits);
    let alice = Identity::generate(ALICE, mimi_mls::Store::open_in_memory().unwrap()).unwrap();
    let (mut group, group_info, tree) = group(&hub, &alice, &[ALICE, BOB]);
    hub.create_room(ROOM_ID, ALICE, &group_info, &tree)
        .await
        .unwrap();
    let carolyn = Identity::generate(CAROLYN, mimi_mls::Store::open_in_memory().unwrap()).unwrap();
    let key_package = carolyn.key_package(KeyPackageKind::OneTime).unwrap();
    let list_update = AppDataUpdate::Update {
        component_id: PARTICIPANT_LIST,
        update: ParticipantListUpdate {
            changed_role_participants: vec![],
            removed_indices: vec![],
            added_participants: vec![UserRolePair {
                user: CAROLYN.to_vec(),
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
    close_hub(store, hub).await;
    response(&answer).0
}

#[tokio::test]
async fn a_commit_writing_an_over_long_uri_is_refused() {
    assert!(matches!(
        add_carolyn(FieldLimits::default()).await,
        UpdateResult::Success { .. }
    ));
    let logs = capture_logs();
    assert!(matches!(add_carolyn(low()).await, UpdateResult::NotAllowed));
    assert!(
        logs.contents()
            .lines()
            .any(|line| line.contains("over the size limit")),
        "refused for the limit"
    );
}
