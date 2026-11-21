//! The out-of-band ratchet tree of decision mimid-1wgh.81: a Welcome whose
//! FanoutMessage with the hub's tree as `RatchetTreeOption::full` would be
//! longer than the hub's body limit goes out with `distributionService`,
//! and its joiners fetch the tree with a groupInfo request signed with
//! their new leaf's key (protocol-07 §5.5, §5.6;
//! draft-ietf-mls-ratchet-tree-options-02 §3).
//!
//! The limit is lowered with [`Hub::with_body_limit`], the test hook, not
//! by building a room whose tree is megabytes. The lengths that pick the
//! limit come from a first run of the same scenario with the real limit:
//! every length in it is fixed (Ed25519 and X25519 keys, signatures and
//! HPKE outputs, 16-octet group ids), so a second run with fresh keys has
//! the same lengths, and the test checks that it does.
//!
//! Oracles: the FanoutMessage as decoded from the outbox; the joiners'
//! mimi-mls Members, which verify the fetched tree against the Welcome's
//! signed GroupInfo (RFC 9420 §12.4.3.1) and must reach the epoch and tree
//! of the hub; mls-rs's suite-1 crypto opening the groupInfo responses
//! (`common/group_info.rs`).

#[allow(dead_code, reason = "each test binary uses part of the helpers")]
mod common;
#[allow(dead_code, reason = "each test binary uses part of the helpers")]
#[path = "common/group_info.rs"]
mod group_info;
#[allow(dead_code, reason = "each test binary uses part of the helpers")]
#[path = "common/update.rs"]
mod update;

use std::path::Path;
use std::sync::Arc;

use common::*;
use group_info::*;
use mimi_mls::member::{AppDataUpdate, ComponentOp, ExternalSender, Member};
use mimi_mls::tls_codec::{Deserialize, Serialize, VLBytes};
use mimi_mls::wire::{RatchetTreeRepresentation, SignaturePublicKey};
use mimi_mls::{ErrorSource, Identity, KeyPackageKind};
use mimi_protocol::component_id::PARTICIPANT_LIST;
use mimi_protocol::{
    FanoutEvent, FanoutMessage, ParticipantListUpdate, UpdateResult, UserRolePair,
};
use mimi_room_policy::component_id::ROLES_LIST;
use mimi_room_policy::{Capability, Role, RoleData, SingleSourceRoleChangeTargets};
use mimid_server::config::Domain;
use mimid_server::hub::{Hub, HubError};
use mimid_server::store::Store;
use update::*;

const NOW: u64 = 1_700_000_000_000;

/// The clients carol brings: one Welcome with this many
/// `EncryptedGroupSecrets`. The groupInfo response carries the same tree as
/// a `full` Welcome, so only the secrets (about 118 octets each) make the
/// Welcome the longer of the two. With one client the groupInfo response
/// is the longer (1198 octets against 1117), and the tree could not go out
/// of band at all; with four, 1936 against 2209.
const CAROL_CLIENTS: usize = 4;

fn from(domain: &str) -> Domain {
    Domain::try_from(domain.to_owned()).unwrap()
}

/// Roles as `update::roles_list`, but `member` lacks `canAddOwnClient`, so
/// room policy lets no participant fetch the GroupInfo: only holding a
/// leaf does (decision mimid-1wgh.81).
fn roles_without_add_own_client() -> Vec<u8> {
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

fn add_carol_apply(
    component_id: u16,
    _current: Option<&[u8]>,
    op: ComponentOp<'_>,
) -> Result<Option<Vec<u8>>, ErrorSource> {
    match (component_id, op) {
        (PARTICIPANT_LIST, ComponentOp::Update(_)) => Ok(Some(
            members_list(&[ALICE, CAROL])
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

/// One run: a hub with `limit` (the real one if `None`) hosts alice's room
/// with the roles of [`roles_without_add_own_client`], and alice sends one
/// Commit adding carol's [`CAROL_CLIENTS`] clients.
struct Run {
    _dir: tempfile::TempDir,
    path: std::path::PathBuf,
    store: Store,
    hub: Hub,
    carol: Vec<Identity>,
    /// The hub's answer to the Commit.
    result: UpdateResult,
    /// The Welcome as alice made it.
    welcome: Vec<u8>,
    /// alice's tree after her Commit.
    tree: Vec<u8>,
    /// The Welcome FanoutMessage with the tree as `full`, and with
    /// `distributionService`, encoded as the hub encodes them.
    full_len: usize,
    by_reference_len: usize,
}

async fn run(limit: Option<usize>) -> Run {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("mimid.sqlite");
    let store = Store::open(&path, &domain()).await.unwrap();
    let mut hub = Hub::open(store.clone(), domain(), Arc::new(FixedClock(NOW)))
        .await
        .unwrap();
    if let Some(limit) = limit {
        hub = hub.with_body_limit(limit);
    }

    let alice = Identity::generate(ALICE, mimi_mls::Store::open_in_memory().unwrap()).unwrap();
    let senders = [ExternalSender {
        signature_key: hub.signature_public_key().to_vec(),
        identity: HUB_IDENTITY.to_vec(),
    }];
    let mut components = components(&hub, &members_list(&[ALICE]));
    for (id, data) in &mut components {
        if *id == ROLES_LIST {
            *data = roles_without_add_own_client();
        }
    }
    // 16 octets, as a Room/create group ID.
    let group_id = b"group-tree-16oct";
    let mut alice_group = Member::create(&alice, group_id, &senders, &components).unwrap();
    let bundle = alice_group
        .commit(&alice, &[], &[], &[], no_components)
        .unwrap();
    alice_group.merge_pending_commit(&alice).unwrap();
    let tree = alice_group.ratchet_tree().unwrap();
    hub.create_room(ROOM_ID, ALICE, &bundle.group_info, &tree)
        .await
        .unwrap();

    let carol: Vec<Identity> = (0..CAROL_CLIENTS)
        .map(|_| Identity::generate(CAROL, mimi_mls::Store::open_in_memory().unwrap()).unwrap())
        .collect();
    let key_packages: Vec<Vec<u8>> = carol
        .iter()
        .map(|client| client.key_package(KeyPackageKind::OneTime).unwrap())
        .collect();
    let adds: Vec<&[u8]> = key_packages.iter().map(Vec::as_slice).collect();
    let bundle = alice_group
        .commit(&alice, &adds, &[], &[add_carol_update()], add_carol_apply)
        .unwrap();
    alice_group.merge_pending_commit(&alice).unwrap();
    let tree = alice_group.ratchet_tree().unwrap();
    let welcome = bundle.welcome.clone().unwrap();
    let request = commit_request(&bundle.commit, Some(&welcome), &bundle.group_info, &tree);
    let (result, _) = response(
        &hub.update(ROOM_ID, &from("a.example"), &request)
            .await
            .unwrap(),
    );

    let fanout_len = |option| {
        FanoutMessage {
            timestamp: NOW,
            event: FanoutEvent::Welcome {
                message: mimi_mls::wire::MLSMessage::tls_deserialize_exact(&welcome).unwrap(),
                ratchet_tree_option: option,
            },
        }
        .tls_serialize_detached()
        .unwrap()
        .len()
    };
    let full_len = fanout_len(mimi_mls::wire::RatchetTreeOption::full(&tree).unwrap());
    let by_reference_len = fanout_len(mimi_mls::wire::RatchetTreeOption::distribution_service());
    Run {
        _dir: dir,
        path,
        store,
        hub,
        carol,
        result,
        welcome,
        tree,
        full_len,
        by_reference_len,
    }
}

/// The Welcome FanoutMessage the hub enqueued, decoded.
async fn welcome_fanout(path: &Path) -> (String, FanoutMessage) {
    let db = connect(path).await;
    let rows = outbox(&db).await;
    db.close().await;
    let mut welcomes: Vec<_> = rows
        .into_iter()
        .map(|(domain, body)| (domain, FanoutMessage::tls_deserialize_exact(&body).unwrap()))
        .filter(|(_, message)| matches!(message.event, FanoutEvent::Welcome { .. }))
        .collect();
    assert_eq!(welcomes.len(), 1, "one Welcome, for c.example");
    welcomes.remove(0)
}

/// A groupInfo request from `client`, signed with its identity's key, the
/// key of the leaf the Commit made for it.
fn leaf_request(client: &Identity, requester: &Requester) -> Vec<u8> {
    let mut tbs = requester.tbs(None);
    tbs.requesting_signature_key = SignaturePublicKey::tls_deserialize_exact(
        VLBytes::new(client.signature_public_key().to_vec())
            .tls_serialize_detached()
            .unwrap(),
    )
    .unwrap();
    tbs.sign(client).unwrap().tls_serialize_detached().unwrap()
}

/// The length of the groupInfo response carol's first client gets in a
/// run whose Commit was accepted.
async fn group_info_len(run: &Run) -> usize {
    let requester = Requester::new(CAROL);
    run.hub
        .group_info(
            ROOM_ID,
            &from("c.example"),
            &leaf_request(&run.carol[0], &requester),
        )
        .await
        .unwrap()
        .len()
}

/// With the real limit, the Welcome goes `full` (decision mimid-1wgh.6.12),
/// and the lengths of the scenario are what the other tests take them to
/// be: a groupInfo response shorter than the `full` Welcome, and a Welcome
/// without the tree shorter still.
#[tokio::test]
async fn real_limit_sends_full_tree() {
    let run = run(None).await;
    assert_eq!(
        run.result,
        UpdateResult::Success {
            accepted_timestamp: NOW
        }
    );
    let (domain, fanout) = welcome_fanout(&run.path).await;
    assert_eq!(domain, "c.example");
    let FanoutEvent::Welcome {
        ratchet_tree_option,
        ..
    } = fanout.event
    else {
        unreachable!()
    };
    assert_eq!(
        ratchet_tree_option.representation(),
        RatchetTreeRepresentation::Full
    );
    assert_eq!(
        ratchet_tree_option.ratchet_tree(),
        Some(run.tree.as_slice())
    );
    let group_info_len = group_info_len(&run).await;
    assert!(
        run.by_reference_len < group_info_len && group_info_len < run.full_len,
        "Welcome without tree {} < groupInfo response {group_info_len} < full Welcome {}",
        run.by_reference_len,
        run.full_len
    );
    close_hub(run.store, run.hub).await;
}

/// A limit exactly the `full` Welcome's length still sends it `full`.
#[tokio::test]
async fn welcome_at_the_limit_keeps_full_tree() {
    let probe = run(None).await;
    let full_len = probe.full_len;
    close_hub(probe.store, probe.hub).await;

    let run = run(Some(full_len)).await;
    assert_eq!(run.full_len, full_len, "the lengths do not change");
    let (_, fanout) = welcome_fanout(&run.path).await;
    let FanoutEvent::Welcome {
        ratchet_tree_option,
        ..
    } = fanout.event
    else {
        unreachable!()
    };
    assert_eq!(
        ratchet_tree_option.representation(),
        RatchetTreeRepresentation::Full
    );
    close_hub(run.store, run.hub).await;
}

/// One octet under the `full` Welcome's length: the Commit is accepted,
/// the Welcome goes to c.example with `distributionService` and no tree,
/// and each of carol's clients fetches the GroupInfo and tree with a
/// request signed with its leaf key, although room policy would refuse
/// carol (her role lacks `canAddOwnClient`), and joins from the Welcome
/// with it. A request claiming carol with a key of no leaf is refused:
/// the tree goes only to a holder of a leaf, or to whom room policy
/// allows.
#[tokio::test]
async fn oversized_welcome_goes_by_reference_and_joiners_fetch_the_tree() {
    let probe = run(None).await;
    let (full_len, by_reference_len) = (probe.full_len, probe.by_reference_len);
    let probe_group_info_len = group_info_len(&probe).await;
    close_hub(probe.store, probe.hub).await;

    let run = run(Some(full_len - 1)).await;
    assert_eq!(
        (run.full_len, run.by_reference_len),
        (full_len, by_reference_len),
        "the lengths do not change between runs"
    );
    assert_eq!(
        run.result,
        UpdateResult::Success {
            accepted_timestamp: NOW
        }
    );
    let (domain, fanout) = welcome_fanout(&run.path).await;
    assert_eq!(domain, "c.example");
    let encoded = fanout.tls_serialize_detached().unwrap();
    assert_eq!(encoded.len(), by_reference_len);
    assert!(encoded.len() < full_len);
    let FanoutEvent::Welcome {
        message,
        ratchet_tree_option,
    } = fanout.event
    else {
        unreachable!()
    };
    assert_eq!(message.as_bytes(), run.welcome.as_slice(), "as received");
    assert_eq!(
        ratchet_tree_option.representation(),
        RatchetTreeRepresentation::DistributionService
    );
    assert_eq!(ratchet_tree_option.ratchet_tree(), None);

    let state = run.hub.public_state(ROOM_ID).await.unwrap();
    for client in &run.carol {
        let requester = Requester::new(CAROL);
        let response = run
            .hub
            .group_info(
                ROOM_ID,
                &from("c.example"),
                &leaf_request(client, &requester),
            )
            .await
            .unwrap();
        assert_eq!(response.len(), probe_group_info_len);
        assert!(response.len() < full_len);
        let tbe = open(&run.hub, ROOM_ID, &requester, &response);
        let tree = tbe.ratchet_tree_option.ratchet_tree().unwrap();
        assert_eq!(tree, run.tree.as_slice());
        let joined = Member::join_welcome(client, &run.welcome, Some(tree))
            .unwrap()
            .member;
        assert_eq!(joined.epoch(), state.epoch);
        assert_eq!(joined.ratchet_tree().unwrap(), state.ratchet_tree);
    }

    // carol's identity with a key of no leaf: room policy decides, and
    // her role lacks canAddOwnClient.
    let impostor = Requester::new(CAROL);
    let response = run
        .hub
        .group_info(ROOM_ID, &from("c.example"), &impostor.request(None))
        .await
        .unwrap();
    assert_not_authorized(ROOM_ID, &response);
    // A leaf's key under another identity is not that leaf's holder.
    let requester = Requester::new(ALICE);
    let mut tbs = requester.tbs(None);
    tbs.requesting_signature_key = SignaturePublicKey::tls_deserialize_exact(
        VLBytes::new(run.carol[0].signature_public_key().to_vec())
            .tls_serialize_detached()
            .unwrap(),
    )
    .unwrap();
    let request = tbs
        .sign(&run.carol[0])
        .unwrap()
        .tls_serialize_detached()
        .unwrap();
    let response = run
        .hub
        .group_info(ROOM_ID, &from("a.example"), &request)
        .await
        .unwrap();
    assert_not_authorized(ROOM_ID, &response);
    close_hub(run.store, run.hub).await;
}

/// A limit under the groupInfo response's length: the tree can reach the
/// joiners neither way, so the Commit is refused (`notAllowed`), nothing
/// is enqueued, and the epoch stays open.
#[tokio::test]
async fn tree_that_fits_no_response_refuses_the_commit() {
    let probe = run(None).await;
    let group_info_len = group_info_len(&probe).await;
    let by_reference_len = probe.by_reference_len;
    close_hub(probe.store, probe.hub).await;
    assert!(by_reference_len < group_info_len);

    let run = run(Some(group_info_len - 1)).await;
    assert_eq!(run.result, UpdateResult::NotAllowed);
    let db = connect(&run.path).await;
    assert!(outbox(&db).await.is_empty(), "nothing enqueued");
    db.close().await;
    let state = run.hub.public_state(ROOM_ID).await.unwrap();
    assert_eq!(state.epoch, 1, "the epoch stays open");
    close_hub(run.store, run.hub).await;
}

/// A groupInfo response longer than the limit is not sent: the hub answers
/// [`HubError::GroupInfoTooLarge`]. Here the limit is lowered on a hub
/// whose room was made with the real one, as when pending proposals grow
/// the response after the Commit.
#[tokio::test]
async fn group_info_longer_than_the_limit_is_refused() {
    let probe = run(None).await;
    let group_info_len = group_info_len(&probe).await;
    let Run {
        _dir,
        store,
        hub,
        carol,
        ..
    } = probe;
    drop(hub);
    let hub = Hub::open(store.clone(), domain(), Arc::new(FixedClock(NOW)))
        .await
        .unwrap()
        .with_body_limit(group_info_len - 1);
    let requester = Requester::new(CAROL);
    let error = hub
        .group_info(
            ROOM_ID,
            &from("c.example"),
            &leaf_request(&carol[0], &requester),
        )
        .await
        .unwrap_err();
    assert!(
        matches!(error, HubError::GroupInfoTooLarge { len } if len == group_info_len),
        "{error:?}"
    );
    close_hub(store, hub).await;
}
