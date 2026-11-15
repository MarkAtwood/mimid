//! The mimi-protocol #190 extension points on keyMaterial (bead
//! mimid-1wgh.55.5), both ways: a peer configured with
//! `WireProfile::Extensions190` sends and gets that encoding, the client's
//! signed request passes through unchanged, and mimid's own code keeps
//! speaking protocol-07.
//!
//! Oracle: the draft's field order (ietf-wg-mimi/mimi-protocol PR #220):
//! `key_material_request_extensions` after the request signature,
//! `client_key_material_extensions` after each `clientUri`; the protocol-07
//! answers are those of follower_routes.rs (a `targetUser` that is not
//! the path's gets `noConsent`).

#![forbid(unsafe_code)]

#[allow(dead_code, reason = "each test binary uses part of the helpers")]
mod common;

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::{Body, Bytes, to_bytes};
use axum::extract::State;
use axum::http::{Request, StatusCode, header};
use axum::routing::{get, post};
use common::*;
use mimi_mls::label::SignatureKeyPair;
use mimi_mls::tls_codec::{Deserialize, Serialize};
use mimi_mls::wire::{
    AppDataDictionary, CipherSuite, Credential, RequiredCapabilities, SignaturePublicKey,
};
use mimi_protocol::{
    ClientKeyMaterial, IdentifierUri, KeyMaterialRequest, KeyMaterialRequestTbs,
    KeyMaterialResponse, KeyMaterialUserCode, Protocol, WireProfile,
};
use mimid_server::config::{BaseUrl, Domain};
use mimid_server::directory::directory;
use mimid_server::follower::Follower;
use mimid_server::http::router;
use mimid_server::peer::PeerClient;
use tower::ServiceExt;

const CATHY: &str = "mimi://c.example/u/cathy";

fn opaque(bytes: &[u8]) -> Vec<u8> {
    [vec![u8::try_from(bytes.len()).unwrap()], bytes.to_vec()].concat()
}

fn uri(text: &str) -> IdentifierUri {
    IdentifierUri::new(text).unwrap()
}

/// One component, id 0x8001, data "r1".
fn ext() -> AppDataDictionary {
    AppDataDictionary::new(&[(0x8001, b"r1")]).unwrap()
}

fn b_example() -> Domain {
    Domain::try_from("b.example".to_owned()).unwrap()
}

/// A KeyMaterialRequest from bob at b.example for cathy, signed with a
/// fresh Ed25519 key.
fn request() -> KeyMaterialRequest {
    let pair = SignatureKeyPair::generate().unwrap();
    let key = SignaturePublicKey::tls_deserialize_exact(opaque(pair.verification_key())).unwrap();
    let credential =
        Credential::tls_deserialize_exact([&[0x00, 0x01][..], &opaque(BOB)].concat()).unwrap();
    KeyMaterialRequestTbs {
        protocol: Protocol::Mls10,
        requesting_user: uri(std::str::from_utf8(BOB).unwrap()),
        target_user: uri(CATHY),
        room_id: uri(ROOM_ID),
        acceptable_ciphersuites: vec![CipherSuite::tls_deserialize_exact([0x00, 0x01]).unwrap()],
        required_capabilities: RequiredCapabilities::tls_deserialize_exact([0x00, 0x00, 0x00])
            .unwrap(),
        requester_signature_key: key,
        requester_credential: credential,
    }
    .sign(&pair)
    .unwrap()
}

/// Posts `body` as b.example to `/v1/keyMaterial/not-a-user-uri` on a
/// provider that speaks the #190 profile to b.example.
async fn post_as_b(body: Vec<u8>) -> (StatusCode, Bytes) {
    let dir = tempfile::tempdir().unwrap();
    let (store, hub) = open_hub(&dir.path().join("mimid.sqlite")).await;
    let hub = hub.with_wire_profiles(BTreeMap::from([(b_example(), WireProfile::Extensions190)]));
    let base = BaseUrl::try_from("https://mimi.a.example".to_owned()).unwrap();
    let follower = Follower::new(domain(), store.clone(), Arc::new(FixedClock(0)));
    let request = Request::post("/v1/keyMaterial/not-a-user-uri")
        .header(header::FROM, "mimi@b.example")
        .body(Body::from(body))
        .unwrap();
    let response = router(directory(&base), Arc::new(hub), Arc::new(follower))
        .oneshot(request)
        .await
        .unwrap();
    let status = response.status();
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    store.close().await;
    (status, body)
}

#[tokio::test]
async fn the_provider_speaks_a_peers_profile_on_key_material() {
    let request = request();
    // The #190 encoding, with a component mimid does not know: the hub's
    // protocol-07 answer (noConsent), re-encoded in the peer's profile.
    let body = request.encode(WireProfile::Extensions190, &ext()).unwrap();
    let (status, answer) = post_as_b(body).await;
    assert_eq!(status, StatusCode::OK);
    let (response, extensions) =
        KeyMaterialResponse::decode(WireProfile::Extensions190, &answer).unwrap();
    assert_eq!(response.user_status, KeyMaterialUserCode::NoConsent);
    assert!(extensions.is_empty());

    // protocol-07 bytes from that peer lack the dictionary.
    let (status, body) = post_as_b(request.tls_serialize_detached().unwrap()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(problem_kind(&body), "undecodable-request");
}

/// What the fake peer saw.
#[derive(Clone)]
struct Peer {
    seen: Arc<Mutex<Vec<Vec<u8>>>>,
    answer: Vec<u8>,
}

async fn record(State(peer): State<Peer>, body: Bytes) -> Vec<u8> {
    peer.seen.lock().unwrap().push(body.to_vec());
    peer.answer.clone()
}

/// A peer at b.example answering every keyMaterial request with `answer`.
async fn start(answer: Vec<u8>) -> (String, Arc<Mutex<Vec<Vec<u8>>>>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let directory = format!("{{\"keyMaterial\": \"{base}/v1/keyMaterial/{{targetUser}}\"}}");
    let seen = Arc::new(Mutex::new(Vec::new()));
    let app = Router::new()
        .route(
            "/.well-known/mimi-protocol-directory",
            get(move || async move { directory }),
        )
        .route("/v1/keyMaterial/{user}", post(record))
        .with_state(Peer {
            seen: Arc::clone(&seen),
            answer,
        });
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (base, seen)
}

#[tokio::test]
async fn the_peer_client_speaks_a_peers_profile_on_key_material() {
    let request = request();
    let plain = request.tls_serialize_detached().unwrap();
    // partialSuccess with no client that has key material: a §5.2
    // departure (Haven's DIV-13) that the requester's lenient decoder
    // reads, so the translation must pass it through unchanged.
    let response = |exhausted: &str| KeyMaterialResponse {
        protocol: Protocol::Mls10,
        user_status: KeyMaterialUserCode::PartialSuccess,
        user_uri: uri(CATHY),
        clients: vec![ClientKeyMaterial::KeyMaterialExhausted {
            client_uri: uri(exhausted),
        }],
    };
    let divergent = response("mimi://c.example/u/cathy/1");
    // Built by hand, since the strict encoders refuse it: protocol-07
    // and #190 bytes of the same response, the latter with an extension
    // on the client.
    let client = |extensions: &[u8]| {
        let c = &divergent.clients[0];
        [
            c.client_status().tls_serialize_detached().unwrap(),
            c.client_uri().tls_serialize_detached().unwrap(),
            extensions.to_vec(),
        ]
        .concat()
    };
    let whole = |client: Vec<u8>| {
        [
            divergent.protocol.tls_serialize_detached().unwrap(),
            divergent.user_status.tls_serialize_detached().unwrap(),
            divergent.user_uri.tls_serialize_detached().unwrap(),
            opaque(&client),
        ]
        .concat()
    };
    let draft07 = whole(client(&[]));
    let extensions190 = whole(client(&[0x05, 0x80, 0x01, 0x02, b'r', b'1']));
    for (profile, sent, answer) in [
        (WireProfile::Draft07, plain.clone(), draft07.clone()),
        (
            WireProfile::Extensions190,
            [plain.clone(), vec![0x00]].concat(),
            extensions190,
        ),
    ] {
        let (base, seen) = start(answer).await;
        let client = PeerClient::new(
            &domain(),
            BTreeMap::from([(b_example(), BaseUrl::try_from(base).unwrap())]),
        )
        .unwrap()
        .with_wire_profiles(BTreeMap::from([(b_example(), profile)]));
        let got = client
            .key_material(&b_example(), CATHY, plain.clone())
            .await
            .unwrap();
        // The peer gets the client's signed request with its encoding's
        // field after the signature; the caller gets protocol-07 back,
        // with the departure intact for its lenient decoder.
        assert_eq!(seen.lock().unwrap().as_slice(), [sent], "{profile:?}");
        assert_eq!(got, draft07, "{profile:?}");
        let (_, divergence) = KeyMaterialResponse::decode_for_requester(&got).unwrap();
        assert!(divergence.is_some(), "{profile:?}");
    }
}
