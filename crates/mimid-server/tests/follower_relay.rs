//! Relay of local users' requests to rooms' hubs (bead mimid-1wgh.7.20;
//! decisions mimid-1wgh.7.5, mimid-1wgh.7.13, mimid-1wgh.7.16).
//!
//! Oracles:
//!
//! - a mock hub (axum, in-process) that records the request bytes and the
//!   `From`, `Host` and `Content-Type` headers, and answers with responses
//!   hand-encoded from the protocol-06 structs, which the relay must
//!   return byte for byte;
//! - a real hub A, in-process for its own domain's users and over loopback
//!   HTTP for another provider's: a retry of an accepted request gets the
//!   same response bytes from the hub (decision mimid-1wgh.6.50, and the
//!   update retry rule in `hub/update.rs`), so the relayed response must
//!   equal the hub's answer to the same bytes sent directly.

#[allow(dead_code, reason = "each test binary uses part of the helpers")]
mod common;
#[allow(dead_code, reason = "each test binary uses part of the helpers")]
#[path = "common/group_info.rs"]
mod group_info;
#[allow(dead_code, reason = "each test binary uses part of the helpers")]
#[path = "common/relay.rs"]
mod relay;
#[allow(dead_code, reason = "each test binary uses part of the helpers")]
#[path = "common/submit.rs"]
mod submit;
#[allow(dead_code, reason = "each test binary uses part of the helpers")]
#[path = "common/update.rs"]
mod update;

use std::collections::BTreeMap;
use std::sync::Arc;

use common::*;
use group_info::Requester;
use mimi_mls::Identity;
use mimi_mls::label::SignatureKeyPair;
use mimi_mls::member::Member;
use mimi_mls::tls_codec::{Deserialize, Serialize};
use mimi_mls::wire::{CipherSuite, Credential, RequiredCapabilities, SignaturePublicKey};
use mimi_protocol::{
    GroupInfoResponse, IdentifierUri, KeyMaterialRequestTbs, KeyMaterialResponse, Protocol,
    SubmitMessageResponse, SubmitResult, UpdateResult, UpdateRoomResponse,
};
use mimid_server::config::{BaseUrl, Domain};
use mimid_server::directory::Directory;
use mimid_server::follower::relay::{LocalUser, Relay, RelayError};
use mimid_server::http::{MAX_BODY_LEN, router};
use mimid_server::hub::Hub;
use mimid_server::peer::{PeerClient, PeerError};
use relay::MockHub;
use tempfile::TempDir;

/// Another user of b.example.
const EVE: &[u8] = b"mimi://b.example/u/eve";
/// A room hosted by the mock hub at c.example.
const MOCK_ROOM: &str = "mimi://c.example/r/mock";
/// [`MOCK_ROOM`] percent-encoded by hand (RFC 3986 §2.1; decision
/// mimid-1wgh.5.18).
const MOCK_ROOM_ENCODED: &str = "mimi%3A%2F%2Fc.example%2Fr%2Fmock";
/// A keyMaterial target at a fourth provider.
const CATHY: &str = "mimi://d.example/u/cathy";
const CATHY_ENCODED: &str = "mimi%3A%2F%2Fd.example%2Fu%2Fcathy";

fn domain_of(name: &str) -> Domain {
    Domain::try_from(name.to_owned()).unwrap()
}

fn user(provider: &str, uri: &[u8]) -> LocalUser {
    LocalUser::authenticated(&domain_of(provider), std::str::from_utf8(uri).unwrap()).unwrap()
}

fn bob() -> LocalUser {
    user("b.example", BOB)
}

/// `opaque<V>` holding `bytes` (RFC 9420 §2.1.2), for fewer than 64 bytes.
fn opaque(bytes: &[u8]) -> Vec<u8> {
    assert!(bytes.len() < 64, "one-byte varint length");
    [vec![u8::try_from(bytes.len()).unwrap()], bytes.to_vec()].concat()
}

/// A hub for `provider` on a fresh store, with a fixed clock.
async fn hub_for(provider: &str) -> (TempDir, Arc<Hub>) {
    let dir = tempfile::tempdir().unwrap();
    let store =
        mimid_server::store::Store::open(&dir.path().join("mimid.sqlite"), &domain_of(provider))
            .await
            .unwrap();
    let hub = Hub::open(
        store,
        domain_of(provider),
        Arc::new(FixedClock(1_700_000_000_000)),
    )
    .await
    .unwrap();
    (dir, Arc::new(hub))
}

/// b.example's relay, whose peer map lists c.example at `mock`.
async fn relay_to(mock: &MockHub) -> (TempDir, Relay) {
    let (dir, hub) = hub_for("b.example").await;
    let peers = PeerClient::new(
        &domain_of("b.example"),
        BTreeMap::from([(domain_of("c.example"), mock.base.clone())]),
    )
    .unwrap();
    (dir, Relay::new(hub, peers))
}

/// bob's own group, with no hub: an UpdateRequest carrying his UpdatePath
/// Commit, and a PrivateMessage he sent before it.
fn bob_requests() -> (Vec<u8>, Vec<u8>) {
    let identity = Identity::generate(BOB, mimi_mls::Store::open_in_memory().unwrap()).unwrap();
    let mut group = Member::create(&identity, b"relay-mock", &[], &[]).unwrap();
    let message = group.send(&identity, b"relayed text", &[]).unwrap();
    let bundle = group
        .commit(&identity, &[], &[], &[], no_components)
        .unwrap();
    group.merge_pending_commit(&identity).unwrap();
    let update = update::commit_request(
        &bundle.commit,
        None,
        &bundle.group_info,
        &group.ratchet_tree().unwrap(),
    );
    (update, message)
}

/// A KeyMaterialRequest (protocol-06 §5.2) from `requesting_user` with a
/// BasicCredential for `credential`, for [`CATHY`] in `room_id`, signed
/// with a fresh Ed25519 key.
fn key_material_request(
    requesting_user: &[u8],
    credential: &[u8],
    room_id: IdentifierUri,
) -> Vec<u8> {
    let pair = SignatureKeyPair::generate().unwrap();
    // RFC 9420 §5.1.1, §5.3 (basic = 1), §11.1 (three empty lists), §17.1.
    let key = SignaturePublicKey::tls_deserialize_exact(opaque(pair.verification_key())).unwrap();
    let credential =
        Credential::tls_deserialize_exact([&[0x00, 0x01][..], &opaque(credential)].concat())
            .unwrap();
    let uri = |bytes: &[u8]| IdentifierUri::new(std::str::from_utf8(bytes).unwrap()).unwrap();
    KeyMaterialRequestTbs {
        protocol: Protocol::Mls10,
        requesting_user: uri(requesting_user),
        target_user: uri(CATHY.as_bytes()),
        room_id,
        acceptable_ciphersuites: vec![CipherSuite::tls_deserialize_exact([0x00, 0x01]).unwrap()],
        required_capabilities: RequiredCapabilities::tls_deserialize_exact([0x00, 0x00, 0x00])
            .unwrap(),
        requester_signature_key: key,
        requester_credential: credential,
    }
    .sign(pair.signature_key())
    .unwrap()
    .tls_serialize_detached()
    .unwrap()
}

fn mock_room() -> IdentifierUri {
    IdentifierUri::new(MOCK_ROOM).unwrap()
}

/// `UpdateRoomResponse` notAllowed (protocol-06 §5.3), hand-encoded:
/// responseCode 2, then an empty errorDescription.
const UPDATE_NOT_ALLOWED: [u8; 2] = [0x02, 0x00];
/// `SubmitMessageResponse` epochTooOld (protocol-06 §5.4), hand-encoded:
/// protocol mls10 (1), statusCode 2, currentEpoch 42 as a uint64.
const SUBMIT_EPOCH_TOO_OLD: [u8; 10] = [0x01, 0x02, 0, 0, 0, 0, 0, 0, 0, 0x2a];

/// `GroupInfoResponse` notAuthorized (protocol-06 §5.6) for [`MOCK_ROOM`],
/// hand-encoded: version mls10, room_id<V>, status 2.
fn group_info_not_authorized() -> Vec<u8> {
    [&[0x01][..], &opaque(MOCK_ROOM.as_bytes()), &[0x02]].concat()
}

/// `KeyMaterialResponse` noConsent (protocol-06 §5.2) for [`CATHY`],
/// hand-encoded: protocol mls10 (1), userStatus noConsent (5), userUri,
/// empty clients.
fn key_material_no_consent() -> Vec<u8> {
    [&[0x01, 0x05][..], &opaque(CATHY.as_bytes()), &[0x00]].concat()
}

#[test]
fn hand_encoded_responses_decode() {
    // The hand encodings agree with mimi-protocol's decoders, so the
    // relay's response check accepts them.
    assert_eq!(
        UpdateRoomResponse::tls_deserialize_exact(UPDATE_NOT_ALLOWED)
            .unwrap()
            .result,
        UpdateResult::NotAllowed
    );
    assert_eq!(
        SubmitMessageResponse::tls_deserialize_exact(SUBMIT_EPOCH_TOO_OLD)
            .unwrap()
            .result,
        SubmitResult::EpochTooOld { current_epoch: 42 }
    );
    GroupInfoResponse::tls_deserialize_exact(group_info_not_authorized()).unwrap();
    KeyMaterialResponse::tls_deserialize_exact(key_material_no_consent()).unwrap();
}

#[test]
fn local_user_must_be_of_this_provider() {
    let b = domain_of("b.example");
    assert_eq!(
        LocalUser::authenticated(&b, "mimi://b.example/u/bob")
            .unwrap()
            .as_str(),
        "mimi://b.example/u/bob"
    );
    for uri in [
        "mimi://c.example/u/bob",
        "mimi:///u/bob",
        "https://b.example/u/bob",
        "mimi://eve@b.example/u/bob",
        "",
    ] {
        assert!(
            matches!(
                LocalUser::authenticated(&b, uri),
                Err(RelayError::NotLocalUser)
            ),
            "{uri}"
        );
    }
}

/// Which relay method a case calls.
#[derive(Clone, Copy, Debug)]
enum Endpoint {
    Update,
    SubmitMessage,
    GroupInfo,
    KeyMaterial,
}

async fn call(
    relay: &Relay,
    endpoint: Endpoint,
    user: &LocalUser,
    room_id: &str,
    request: &[u8],
) -> Result<Vec<u8>, RelayError> {
    match endpoint {
        Endpoint::Update => relay.relay_update(user, room_id, request).await,
        Endpoint::SubmitMessage => relay.relay_submit_message(user, room_id, request).await,
        Endpoint::GroupInfo => relay.relay_group_info(user, room_id, request).await,
        Endpoint::KeyMaterial => relay.relay_key_material(user, request).await,
    }
}

#[tokio::test]
async fn remote_requests_and_responses_cross_verbatim() {
    let (update, message) = bob_requests();
    let cases = [
        (
            Endpoint::Update,
            update,
            UPDATE_NOT_ALLOWED.to_vec(),
            format!("/v1/update/{MOCK_ROOM_ENCODED}"),
        ),
        (
            Endpoint::SubmitMessage,
            submit::submit_request(&message, BOB),
            SUBMIT_EPOCH_TOO_OLD.to_vec(),
            format!("/v1/submitMessage/{MOCK_ROOM_ENCODED}"),
        ),
        (
            Endpoint::GroupInfo,
            Requester::new(BOB).request(None),
            group_info_not_authorized(),
            format!("/v1/groupInfo/{MOCK_ROOM_ENCODED}"),
        ),
        (
            Endpoint::KeyMaterial,
            key_material_request(BOB, BOB, mock_room()),
            key_material_no_consent(),
            format!("/v1/keyMaterial/{CATHY_ENCODED}"),
        ),
    ];
    for (endpoint, request, reply, path) in cases {
        let mock = MockHub::start(200, reply.clone()).await;
        let (_dir, relay) = relay_to(&mock).await;
        let response = call(&relay, endpoint, &bob(), MOCK_ROOM, &request)
            .await
            .unwrap();
        assert_eq!(response, reply, "{endpoint:?}: response as received");
        let received = mock.received();
        assert_eq!(received.len(), 1, "{endpoint:?}: one request");
        let received = &received[0];
        assert_eq!(received.raw_path, path, "{endpoint:?}: path");
        assert_eq!(received.body, request, "{endpoint:?}: body as given");
        assert_eq!(received.from, ["mimi@b.example"], "protocol-06 §4.1 From");
        assert_eq!(received.host, ["c.example"], "protocol-06 §4.1 Host");
        assert_eq!(received.content_type, ["application/octet-stream"]);
    }
}

#[tokio::test]
async fn wrong_identity_is_refused_before_any_request() {
    let (_, message) = bob_requests();
    let cases = [
        (
            Endpoint::SubmitMessage,
            submit::submit_request(&message, EVE),
            "sendingUri",
        ),
        (
            Endpoint::KeyMaterial,
            key_material_request(EVE, BOB, mock_room()),
            "requestingUser",
        ),
        (
            Endpoint::KeyMaterial,
            key_material_request(BOB, EVE, mock_room()),
            "requesterCredential",
        ),
        (
            Endpoint::GroupInfo,
            Requester::new(EVE).request(None),
            "requestingCredential",
        ),
    ];
    for (endpoint, request, expected) in cases {
        let mock = MockHub::start(200, Vec::new()).await;
        let (_dir, relay) = relay_to(&mock).await;
        let error = call(&relay, endpoint, &bob(), MOCK_ROOM, &request)
            .await
            .unwrap_err();
        assert!(
            matches!(error, RelayError::WrongIdentity { field } if field == expected),
            "{endpoint:?}: {error:?}"
        );
        mock.assert_untouched(expected);
    }
}

#[tokio::test]
async fn bad_requests_are_refused_before_any_request() {
    let mock = MockHub::start(200, Vec::new()).await;
    let (_dir, relay) = relay_to(&mock).await;
    let oversized = vec![0; MAX_BODY_LEN + 1];
    for endpoint in [
        Endpoint::Update,
        Endpoint::SubmitMessage,
        Endpoint::GroupInfo,
        Endpoint::KeyMaterial,
    ] {
        let error = call(&relay, endpoint, &bob(), MOCK_ROOM, &oversized)
            .await
            .unwrap_err();
        assert!(
            matches!(error, RelayError::RequestTooLarge),
            "{endpoint:?}: {error:?}"
        );
        let error = call(&relay, endpoint, &bob(), MOCK_ROOM, &[0xff])
            .await
            .unwrap_err();
        assert!(
            matches!(error, RelayError::InvalidRequest(_)),
            "{endpoint:?}: {error:?}"
        );
    }

    let (update, _) = bob_requests();
    for room_id in ["https://c.example/r/mock", "mimi:///r/mock", ""] {
        let error = relay
            .relay_update(&bob(), room_id, &update)
            .await
            .unwrap_err();
        assert!(
            matches!(error, RelayError::InvalidRoomId),
            "{room_id}: {error:?}"
        );
    }
    let no_room = key_material_request(BOB, BOB, IdentifierUri::default());
    let error = relay
        .relay_key_material(&bob(), &no_room)
        .await
        .unwrap_err();
    assert!(matches!(error, RelayError::InvalidRoomId), "{error:?}");
    mock.assert_untouched("bad requests");

    // A room whose hub is not a configured peer.
    let error = relay
        .relay_update(&bob(), "mimi://z.example/r/elsewhere", &update)
        .await
        .unwrap_err();
    assert!(
        matches!(error, RelayError::Peer(PeerError::UnknownPeer(ref domain)) if domain.as_str() == "z.example"),
        "{error:?}"
    );
    mock.assert_untouched("unknown hub");
}

#[tokio::test]
async fn bad_hub_responses_are_typed_errors() {
    let (_, message) = bob_requests();
    let request = submit::submit_request(&message, BOB);

    let oversized = MockHub::start(200, vec![0; MAX_BODY_LEN + 1]).await;
    let (_dir, relay) = relay_to(&oversized).await;
    let error = relay
        .relay_submit_message(&bob(), MOCK_ROOM, &request)
        .await
        .unwrap_err();
    assert!(
        matches!(error, RelayError::Peer(PeerError::ResponseTooLarge)),
        "{error:?}"
    );

    let trailing = [&SUBMIT_EPOCH_TOO_OLD[..], &[0x00]].concat();
    for (reply, case) in [
        (trailing, "trailing byte"),
        (vec![0x01, 0x03], "undefined statusCode"),
        (Vec::new(), "empty"),
        (UPDATE_NOT_ALLOWED.to_vec(), "another endpoint's response"),
    ] {
        let mock = MockHub::start(200, reply).await;
        let (_dir, relay) = relay_to(&mock).await;
        let error = relay
            .relay_submit_message(&bob(), MOCK_ROOM, &request)
            .await
            .unwrap_err();
        assert!(
            matches!(error, RelayError::InvalidResponse(_)),
            "{case}: {error:?}"
        );
        assert_eq!(mock.received().len(), 1, "{case}");
    }

    let refusing = MockHub::start(503, SUBMIT_EPOCH_TOO_OLD.to_vec()).await;
    let (_dir, relay) = relay_to(&refusing).await;
    let error = relay
        .relay_submit_message(&bob(), MOCK_ROOM, &request)
        .await
        .unwrap_err();
    assert!(
        matches!(
            error,
            RelayError::Peer(PeerError::Rejected { status: 503, .. })
        ),
        "{error:?}"
    );
}

#[tokio::test]
async fn own_domain_submit_goes_to_the_in_process_hub() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("mimid.sqlite");
    let (_store, hub) = submit::open_stepping_hub(&path, 1_800_000_000_000).await;
    let mut alice = submit::create_room(&hub, ROOM_ID, b"group-relay").await;
    let hub = Arc::new(hub);
    // The peer map lists a.example at a mock, so any HTTP request for the
    // room would reach it.
    let mock = MockHub::start(200, Vec::new()).await;
    let peers =
        PeerClient::new(&domain(), BTreeMap::from([(domain(), mock.base.clone())])).unwrap();
    let relay = Relay::new(Arc::clone(&hub), peers);
    let db = submit::inspect(&path).await;
    let before = submit::row_counts(&db).await;

    let (message, _) = alice.franked(b"own domain", &[7; 16]);
    let request = submit::submit_request(&message, ALICE);
    let response = relay
        .relay_submit_message(&user(DOMAIN, ALICE), ROOM_ID, &request)
        .await
        .unwrap();

    let decoded = SubmitMessageResponse::tls_deserialize_exact(response.as_slice()).unwrap();
    assert!(
        matches!(decoded.result, SubmitResult::Accepted { .. }),
        "{decoded:?}"
    );
    let after = submit::row_counts(&db).await;
    assert_eq!(after.0, before.0 + 1, "the hub logged the message");
    mock.assert_untouched("own-domain relay");
    // Sent directly with this provider's domain as From, the same bytes get
    // the same response: a retry of an accepted request.
    let direct = hub
        .submit_message(ROOM_ID, &domain(), &request)
        .await
        .unwrap();
    assert_eq!(response, direct);

    // alice cannot send as bob, even to her own provider's hub.
    let as_bob = submit::submit_request(&message, BOB);
    let error = relay
        .relay_submit_message(&user(DOMAIN, ALICE), ROOM_ID, &as_bob)
        .await
        .unwrap_err();
    assert!(
        matches!(
            error,
            RelayError::WrongIdentity {
                field: "sendingUri"
            }
        ),
        "{error:?}"
    );
    assert_eq!(submit::row_counts(&db).await, after, "nothing written");
}

#[tokio::test]
async fn remote_update_reaches_a_real_hub_over_http() {
    // Hub A, served over loopback HTTP.
    let (_dir_a, hub_a) = hub_for(DOMAIN).await;
    let mut room = update::member_room(&hub_a, ROOM_ID, b"group-relay-http").await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = BaseUrl::try_from(format!("http://{}", listener.local_addr().unwrap())).unwrap();
    let app = router(Directory::new(&base), Arc::clone(&hub_a));
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    // Provider B relays bob's UpdatePath Commit to A.
    let (_dir_b, hub_b) = hub_for("b.example").await;
    let peers =
        PeerClient::new(&domain_of("b.example"), BTreeMap::from([(domain(), base)])).unwrap();
    let relay = Relay::new(hub_b, peers);
    let bundle = room
        .bob_group
        .commit(&room.bob, &[], &[], &[], no_components)
        .unwrap();
    room.bob_group.merge_pending_commit(&room.bob).unwrap();
    let request = update::commit_request(
        &bundle.commit,
        None,
        &bundle.group_info,
        &room.bob_group.ratchet_tree().unwrap(),
    );
    let response = relay.relay_update(&bob(), ROOM_ID, &request).await.unwrap();

    let (result, _) = update::response(&response);
    assert!(matches!(result, UpdateResult::Success { .. }), "{result:?}");
    assert_eq!(hub_a.public_state(ROOM_ID).await.unwrap().epoch, 2);
    // A retry of the accepted request, sent directly with b.example as
    // From, gets the same bytes.
    let direct = hub_a
        .update(ROOM_ID, &domain_of("b.example"), &request)
        .await
        .unwrap();
    assert_eq!(response, direct);
}

#[tokio::test]
async fn relay_logs_no_bodies() {
    let logs = capture_logs();
    let (update, message) = bob_requests();
    let cases = [
        (Endpoint::Update, update, UPDATE_NOT_ALLOWED.to_vec()),
        (
            Endpoint::SubmitMessage,
            submit::submit_request(&message, BOB),
            SUBMIT_EPOCH_TOO_OLD.to_vec(),
        ),
        (
            Endpoint::GroupInfo,
            Requester::new(BOB).request(None),
            group_info_not_authorized(),
        ),
        (
            Endpoint::KeyMaterial,
            key_material_request(BOB, BOB, mock_room()),
            key_material_no_consent(),
        ),
    ];
    let mut bodies = vec![message];
    for (endpoint, request, reply) in cases {
        let mock = MockHub::start(200, reply.clone()).await;
        let (_dir, relay) = relay_to(&mock).await;
        call(&relay, endpoint, &bob(), MOCK_ROOM, &request)
            .await
            .unwrap();
        // A refused request is logged too; update checks no identity.
        if !matches!(endpoint, Endpoint::Update) {
            let refused = call(
                &relay,
                endpoint,
                &user("b.example", EVE),
                MOCK_ROOM,
                &request,
            )
            .await;
            assert!(refused.is_err(), "{endpoint:?}");
        }
        bodies.push(request);
        bodies.push(reply);
    }
    let text = logs.contents();
    assert!(
        text.contains("request relayed"),
        "the canary sees relay events"
    );
    assert!(text.contains("relay refused"), "the canary sees refusals");
    // Bodies of a few bytes would match unrelated log text by chance, so
    // only bodies of 16 bytes or more are searched for.
    for (index, body) in bodies.iter().enumerate().filter(|(_, b)| b.len() >= 16) {
        assert_secret_absent(&text, body, &format!("body {index}"));
    }
}
