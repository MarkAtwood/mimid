//! protocol-06 §5.6 groupInfo endpoint tests (mimid-1wgh.6.30). Responses
//! are checked with mls-rs's suite-1 crypto, and the GroupInfo and tree
//! they carry must let a mimi-mls Member and an mls-rs client build an
//! external Commit that the hub's `/update` accepts.

#[allow(dead_code, reason = "each test binary uses part of the helpers")]
mod common;
#[allow(dead_code, reason = "each test binary uses part of the helpers")]
#[path = "common/group_info.rs"]
mod group_info;
#[allow(dead_code, reason = "each test binary uses part of the helpers")]
#[path = "common/update.rs"]
mod update;

use common::*;
use group_info::*;
use mimi_mls::member::Member;
use mimi_mls::tls_codec::Serialize;
use mimi_mls::wire::RatchetTreeRepresentation;
use mimi_mls::{Identity, label};
use mimid_server::config::Domain;
use mimid_server::hub::HubError;
use update::*;

const NOW: u64 = 1_700_000_000_000;
const DAVE: &[u8] = b"mimi://d.example/u/dave";

fn from(domain: &str) -> Domain {
    Domain::try_from(domain.to_owned()).unwrap()
}

/// A new client of bob, a listed participant whose role holds
/// `canAddOwnClient`, gets the room's GroupInfo, tree and (no) pending
/// proposals, and joins with a mimi-mls Member by external Commit, which
/// `/update` accepts. Nothing is written by the groupInfo request.
#[tokio::test]
async fn participant_client_joins_with_member() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("mimid.sqlite");
    let (store, hub) = open_hub(&path).await;
    member_room(&hub, ROOM_ID, b"group-gi-member").await;
    let db = connect(&path).await;
    let before = counts(&db).await;

    let requester = Requester::new(BOB);
    let response = hub
        .group_info(ROOM_ID, &from("b.example"), &requester.request(None))
        .await
        .unwrap();
    assert_eq!(counts(&db).await, before, "groupInfo writes nothing");
    let tbe = open(&hub, ROOM_ID, &requester, &response);

    let stored = store.room(ROOM_ID).await.unwrap().unwrap();
    assert_eq!(
        tbe.group_info.as_bytes(),
        &stored.group_info[GROUP_INFO_HEADER.len()..],
        "the stored GroupInfo, without its MLSMessage header"
    );
    assert!(!tbe.group_info.has_ratchet_tree_extension());
    assert_eq!(
        tbe.ratchet_tree_option.representation(),
        RatchetTreeRepresentation::Full
    );
    let tree = tbe.ratchet_tree_option.ratchet_tree().unwrap();
    assert_eq!(tree, hub.public_state(ROOM_ID).await.unwrap().ratchet_tree);
    assert!(tbe.pending_proposals.is_empty());

    let bob2 = Identity::generate(BOB, mimi_mls::Store::open_in_memory().unwrap()).unwrap();
    let group_info = [&GROUP_INFO_HEADER[..], tbe.group_info.as_bytes()].concat();
    let join = Member::join_external(&bob2, &group_info, Some(tree)).unwrap();
    let request = commit_request(
        &join.commit_bundle.commit,
        None,
        &join.commit_bundle.group_info,
        &join.member.ratchet_tree().unwrap(),
    );
    let accepted = hub
        .update(ROOM_ID, &from("b.example"), &request)
        .await
        .unwrap();
    assert_accepted(&accepted);
    assert_eq!(hub.public_state(ROOM_ID).await.unwrap().epoch, 2);
    db.close().await;
    close_hub(store, hub).await;
}

/// Asserts that an `UpdateRoomResponse` is `success` at [`NOW`].
fn assert_accepted(bytes: &[u8]) {
    assert_eq!(
        response(bytes),
        (
            mimi_protocol::UpdateResult::Success {
                accepted_timestamp: NOW
            },
            String::new()
        )
    );
}

/// alice (mls-rs) commits a GroupInfo that allows external Commits. carol,
/// listed but not a member, fetches it and joins as an mls-rs client from
/// the served GroupInfo and tree alone; `/update` accepts the Commit.
#[tokio::test]
async fn listed_user_joins_with_mls_rs() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("mimid.sqlite");
    let (store, hub) = open_hub(&path).await;
    let mut room = mls_rs_room(&hub, ROOM_ID, b"group-gi-mls-rs").await;
    let output = room.alice.commit_builder().build().unwrap();
    room.alice.apply_pending_commit().unwrap();
    let request = commit_request(
        &output.commit_message.to_bytes().unwrap(),
        None,
        &room
            .alice
            .group_info_message_allowing_ext_commit(false)
            .unwrap()
            .to_bytes()
            .unwrap(),
        &room.alice.export_tree().to_bytes().unwrap(),
    );
    let accepted = hub
        .update(ROOM_ID, &from("a.example"), &request)
        .await
        .unwrap();
    assert_accepted(&accepted);

    let requester = Requester::new(CAROL);
    let response = hub
        .group_info(ROOM_ID, &from("c.example"), &requester.request(None))
        .await
        .unwrap();
    let tbe = open(&hub, ROOM_ID, &requester, &response);
    let group_info = mls_rs::MlsMessage::from_bytes(
        &[&GROUP_INFO_HEADER[..], tbe.group_info.as_bytes()].concat(),
    )
    .unwrap();
    let tree =
        mls_rs::group::ExportedTree::from_bytes(tbe.ratchet_tree_option.ratchet_tree().unwrap())
            .unwrap();
    let (joined, commit) = room
        .carol
        .external_commit_builder()
        .unwrap()
        .with_tree_data(tree)
        .build(group_info)
        .unwrap();
    let request = commit_request(
        &commit.to_bytes().unwrap(),
        None,
        &joined
            .group_info_message(false)
            .unwrap()
            .to_bytes()
            .unwrap(),
        &joined.export_tree().to_bytes().unwrap(),
    );
    let accepted = hub
        .update(ROOM_ID, &from("c.example"), &request)
        .await
        .unwrap();
    assert_accepted(&accepted);
    assert_eq!(hub.public_state(ROOM_ID).await.unwrap().epoch, 3);
    close_hub(store, hub).await;
}

/// The current epoch's pending proposals are served in hub order with
/// their hub acceptance time, as received.
#[tokio::test]
async fn pending_proposals_are_included() {
    let dir = tempfile::tempdir().unwrap();
    let (store, hub) = open_hub(&dir.path().join("mimid.sqlite")).await;
    let mut room = mls_rs_room(&hub, ROOM_ID, b"group-gi-pending").await;
    let bobs = room.bob.propose_update(vec![]).unwrap().to_bytes().unwrap();
    let alices = room
        .alice
        .propose_update(vec![])
        .unwrap()
        .to_bytes()
        .unwrap();
    let accepted = hub
        .update(
            ROOM_ID,
            &from("b.example"),
            &proposal_request(&bobs, &[&alices]),
        )
        .await
        .unwrap();
    assert_accepted(&accepted);

    let requester = Requester::new(CAROL);
    let response = hub
        .group_info(ROOM_ID, &from("c.example"), &requester.request(None))
        .await
        .unwrap();
    let tbe = open(&hub, ROOM_ID, &requester, &response);
    let pending: Vec<_> = tbe
        .pending_proposals
        .iter()
        .map(|p| (p.proposal.as_bytes().to_vec(), p.hub_accepted_time))
        .collect();
    assert_eq!(pending, [(bobs, NOW), (alices, NOW)]);
    close_hub(store, hub).await;
}

/// An unlisted user gets notAuthorized when role 0 lacks `canOpenJoin`
/// and no preauthorization matches, and success when either allows it.
#[tokio::test]
async fn unlisted_user_needs_open_join_or_preauthorization() {
    let dir = tempfile::tempdir().unwrap();
    let (store, hub) = open_hub(&dir.path().join("mimid.sqlite")).await;
    let dave = Requester::new(DAVE);
    let d = from("d.example");

    member_room(&hub, ROOM_ID, b"group-gi-closed").await;
    let refused = hub
        .group_info(ROOM_ID, &d, &dave.request(None))
        .await
        .unwrap();
    assert_not_authorized(ROOM_ID, &refused);

    for (room_id, group_id, join) in [
        ("mimi://a.example/r/open", &b"group-gi-open"[..], Join::Open),
        (
            "mimi://a.example/r/preauth",
            b"group-gi-preauth",
            Join::Preauthorized,
        ),
    ] {
        joinable_room(&hub, room_id, group_id, join).await;
        let response = hub
            .group_info(room_id, &d, &dave.request(None))
            .await
            .unwrap();
        let tbe = open(&hub, room_id, &dave, &response);
        assert!(tbe.pending_proposals.is_empty(), "{room_id}");
    }
    close_hub(store, hub).await;
}

/// A `From` domain other than the requesting credential's domain is
/// refused (decision mimid-1wgh.6.9), and so is a credential identity that
/// names no domain.
#[tokio::test]
async fn from_must_match_credential_domain() {
    let dir = tempfile::tempdir().unwrap();
    let (store, hub) = open_hub(&dir.path().join("mimid.sqlite")).await;
    member_room(&hub, ROOM_ID, b"group-gi-from").await;
    let bob = Requester::new(BOB);
    for domain in ["a.example", "c.example", "bb.example"] {
        let refused = hub
            .group_info(ROOM_ID, &from(domain), &bob.request(None))
            .await
            .unwrap();
        assert_not_authorized(ROOM_ID, &refused);
    }
    for identity in [&b"bob"[..], b"https://b.example/u/bob", b"mimi:///u/bob"] {
        let requester = Requester::new(identity);
        let refused = hub
            .group_info(ROOM_ID, &from("b.example"), &requester.request(None))
            .await
            .unwrap();
        assert_not_authorized(ROOM_ID, &refused);
    }
    let accepted = hub
        .group_info(ROOM_ID, &from("b.example"), &bob.request(None))
        .await
        .unwrap();
    open(&hub, ROOM_ID, &bob, &accepted);
    close_hub(store, hub).await;
}

/// A request carrying a joining code is refused, even from a participant
/// that may otherwise fetch the GroupInfo (decision mimid-1wgh.6.13).
#[tokio::test]
async fn joining_code_is_not_authorized() {
    let dir = tempfile::tempdir().unwrap();
    let (store, hub) = open_hub(&dir.path().join("mimid.sqlite")).await;
    member_room(&hub, ROOM_ID, b"group-gi-code").await;
    let bob = Requester::new(BOB);
    for code in [&b"code"[..], b""] {
        let refused = hub
            .group_info(ROOM_ID, &from("b.example"), &bob.request(Some(code)))
            .await
            .unwrap();
        assert_not_authorized(ROOM_ID, &refused);
    }
    close_hub(store, hub).await;
}

/// A request whose signature does not verify over the received bytes is
/// refused: a flipped signature or TBS byte, or a signature by another key.
#[tokio::test]
async fn bad_request_signature_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let (store, hub) = open_hub(&dir.path().join("mimid.sqlite")).await;
    member_room(&hub, ROOM_ID, b"group-gi-sig").await;
    let bob = Requester::new(BOB);
    let b = from("b.example");
    let good = bob.request(None);

    let mut bad_signature = good.clone();
    *bad_signature.last_mut().unwrap() ^= 0x01;
    // protocol (1 byte), cipher_suite (2), then requestingSignatureKey<V>
    // (1 + 32): byte 10 is inside the key.
    let mut bad_tbs = good.clone();
    bad_tbs[10] ^= 0x01;
    let other = label::SignatureKeyPair::generate().unwrap();
    let wrong_key = bob
        .tbs(None)
        .sign(other.signature_key())
        .unwrap()
        .tls_serialize_detached()
        .unwrap();
    for request in [bad_signature, bad_tbs, wrong_key] {
        let refused = hub.group_info(ROOM_ID, &b, &request).await.unwrap();
        assert_not_authorized(ROOM_ID, &refused);
    }
    let accepted = hub.group_info(ROOM_ID, &b, &good).await.unwrap();
    open(&hub, ROOM_ID, &bob, &accepted);
    close_hub(store, hub).await;
}

/// An unhosted room is NoSuchRoom (404, decision mimid-1wgh.6.8), checked
/// before decoding; an undecodable body for a hosted room is
/// InvalidRequest (400), including trailing bytes.
#[tokio::test]
async fn unknown_room_and_undecodable_request() {
    let dir = tempfile::tempdir().unwrap();
    let (store, hub) = open_hub(&dir.path().join("mimid.sqlite")).await;
    member_room(&hub, ROOM_ID, b"group-gi-errors").await;
    let bob = Requester::new(BOB);
    let b = from("b.example");
    for body in [bob.request(None), vec![0]] {
        let error = hub
            .group_info("mimi://a.example/r/nope", &b, &body)
            .await
            .unwrap_err();
        assert!(matches!(error, HubError::NoSuchRoom), "{error:?}");
    }
    let mut trailing = bob.request(None);
    trailing.push(0);
    for body in [vec![], vec![0], trailing] {
        let error = hub.group_info(ROOM_ID, &b, &body).await.unwrap_err();
        assert!(matches!(error, HubError::InvalidRequest(_)), "{error:?}");
    }
    close_hub(store, hub).await;
}

/// No secret reaches the logs at TRACE: not the hub's signing or franking
/// key, nor the requester's signing or HPKE private key.
#[tokio::test]
async fn log_canary() {
    let logs = capture_logs();
    let dir = tempfile::tempdir().unwrap();
    let (store, hub) = open_hub(&dir.path().join("mimid.sqlite")).await;
    member_room(&hub, ROOM_ID, b"group-gi-canary").await;
    let bob = Requester::new(BOB);
    let b = from("b.example");
    let accepted = hub
        .group_info(ROOM_ID, &b, &bob.request(None))
        .await
        .unwrap();
    open(&hub, ROOM_ID, &bob, &accepted);
    let refused = hub
        .group_info(ROOM_ID, &b, &bob.request(Some(b"code")))
        .await
        .unwrap();
    assert_not_authorized(ROOM_ID, &refused);
    let refused = hub
        .group_info(ROOM_ID, &from("c.example"), &bob.request(None))
        .await
        .unwrap();
    assert_not_authorized(ROOM_ID, &refused);

    let text = logs.contents();
    assert!(text.contains("GroupInfo served"), "the capture works");
    let secret = store.hub_secret().await.unwrap().unwrap();
    assert_secret_absent(&text, &secret.signature_private_key, "hub signing key");
    assert_secret_absent(&text, &secret.hub_key, "hub franking key");
    assert_secret_absent(&text, bob.signing.signature_key(), "requester signing key");
    assert_secret_absent(&text, &bob.hpke_secret, "requester HPKE key");
    close_hub(store, hub).await;
}
