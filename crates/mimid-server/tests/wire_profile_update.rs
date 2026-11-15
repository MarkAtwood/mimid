//! The mimi-protocol #190 extension points on update requests and
//! responses (bead mimid-1wgh.55.5), both ways: a peer configured with
//! `WireProfile::Extensions190` gets and sends that encoding, and mimid's
//! own code keeps speaking protocol-07.
//!
//! Oracle: the joint IETF 127 vector jt-mls-02 (an UpdateRequest a hub
//! accepts from the setup's room; fixtures/joint-ietf127/mls-vectors.json)
//! as the protocol-07 bytes, and the draft's field order (PR #220): the
//! `update_extensions` dictionary after the bundle, the
//! `update_response_extensions` dictionary after `errorDescription`.

#![forbid(unsafe_code)]

#[allow(dead_code, reason = "each test binary uses part of the helpers")]
mod common;

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::Bytes;
use axum::extract::State;
use axum::routing::{get, post};
use common::*;
use mimi_mls::tls_codec::{Deserialize, Serialize};
use mimi_mls::wire::AppDataDictionary;
use mimi_protocol::{UpdateRequest, UpdateResult, UpdateRoomResponse, Utf8String, WireProfile};
use mimid_server::config::{BaseUrl, Domain};
use mimid_server::hub::{Hub, HubError};
use mimid_server::peer::PeerClient;
use mimid_server::store::{Store, StoredHubSecret};
use serde_json::Value;

const VECTORS: &str = include_str!("fixtures/joint-ietf127/mls-vectors.json");

fn vectors() -> Value {
    serde_json::from_str(VECTORS).unwrap()
}

fn unhex(value: &Value) -> Vec<u8> {
    let text = value.as_str().unwrap();
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

/// jt-mls-02's UpdateRequest, protocol-07 bytes.
fn jt_mls_02() -> Vec<u8> {
    let file = vectors();
    let v = file["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["id"] == "jt-mls-02")
        .unwrap()
        .clone();
    unhex(&v["hex"])
}

/// One component, id 0x8001, data "r1".
fn ext() -> AppDataDictionary {
    AppDataDictionary::new(&[(0x8001, b"r1")]).unwrap()
}

fn a_example() -> Domain {
    Domain::try_from("a.example".to_owned()).unwrap()
}

/// The vectors' hub, hosting their room, speaking `profiles`.
async fn hub(path: &std::path::Path, profiles: BTreeMap<Domain, WireProfile>) -> (Store, Hub) {
    let setup = vectors()["setup"].clone();
    let store = Store::open(path, &domain()).await.unwrap();
    let key = |name: &str| <[u8; 32]>::try_from(unhex(&setup[name])).unwrap();
    let wanted = StoredHubSecret {
        signature_private_key: key("hub_signature_private_key"),
        signature_public_key: key("hub_signature_public_key"),
        hub_key: key("hub_franking_key"),
    };
    store
        .hub_secret_or_insert(|| Ok::<_, mimid_server::store::StoreError>(wanted))
        .await
        .unwrap();
    let hub = Hub::open(
        store.clone(),
        domain(),
        Arc::new(FixedClock(1_700_000_000_000)),
    )
    .await
    .unwrap()
    .with_wire_profiles(profiles);
    hub.create_room(
        setup["room"].as_str().unwrap(),
        setup["creator"].as_str().unwrap().as_bytes(),
        &unhex(&setup["group_info"]),
        &unhex(&setup["ratchet_tree"]),
    )
    .await
    .unwrap();
    (store, hub)
}

#[tokio::test]
async fn the_hub_speaks_a_peers_profile_on_update() {
    let dir = tempfile::tempdir().unwrap();
    let profiles = BTreeMap::from([(a_example(), WireProfile::Extensions190)]);
    let (store, hub) = hub(&dir.path().join("mimid.sqlite"), profiles).await;
    let room = vectors()["setup"]["room"].as_str().unwrap().to_owned();
    let request = UpdateRequest::tls_deserialize_exact(&jt_mls_02()[..]).unwrap();

    // protocol-07 bytes from a peer on the #190 profile lack the
    // dictionary: refused as not decoding.
    let error = hub
        .update(&room, &a_example(), &jt_mls_02())
        .await
        .unwrap_err();
    assert!(matches!(error, HubError::InvalidRequest(_)), "{error:?}");

    // The #190 encoding, with a component the hub does not know: accepted,
    // and the response in the same encoding, with no extensions.
    let body = request.encode(WireProfile::Extensions190, &ext()).unwrap();
    let answer = hub.update(&room, &a_example(), &body).await.unwrap();
    let (response, extensions) =
        UpdateRoomResponse::decode(WireProfile::Extensions190, &answer).unwrap();
    assert!(
        matches!(response.result, UpdateResult::Success { .. }),
        "{response:?}"
    );
    assert!(extensions.is_empty());
    close_hub(store, hub).await;
}

/// What the fake peer saw, and answers.
#[derive(Clone)]
struct Peer {
    seen: Arc<Mutex<Vec<Vec<u8>>>>,
    answer: Vec<u8>,
}

async fn record(State(peer): State<Peer>, body: Bytes) -> Vec<u8> {
    peer.seen.lock().unwrap().push(body.to_vec());
    peer.answer.clone()
}

/// A peer hub at b.example answering every update with `answer`.
async fn start(answer: Vec<u8>) -> (String, Arc<Mutex<Vec<Vec<u8>>>>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let directory = format!("{{\"update\": \"{base}/v1/update/{{roomId}}\"}}");
    let seen = Arc::new(Mutex::new(Vec::new()));
    let app = Router::new()
        .route(
            "/.well-known/mimi-protocol-directory",
            get(move || async move { directory }),
        )
        .route("/v1/update/{room}", post(record))
        .with_state(Peer {
            seen: Arc::clone(&seen),
            answer,
        });
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (base, seen)
}

#[tokio::test]
async fn the_peer_client_speaks_a_peers_profile_on_update() {
    let b = Domain::try_from("b.example".to_owned()).unwrap();
    let response = UpdateRoomResponse {
        error_description: Utf8String::default(),
        result: UpdateResult::Success {
            accepted_timestamp: 1_700_000_000_000,
        },
    };
    let plain = jt_mls_02();
    let request = UpdateRequest::tls_deserialize_exact(&plain[..]).unwrap();
    for (profile, sent, answer) in [
        (
            WireProfile::Draft07,
            plain.clone(),
            response.tls_serialize_detached().unwrap(),
        ),
        (
            WireProfile::Extensions190,
            request
                .encode(WireProfile::Extensions190, &AppDataDictionary::default())
                .unwrap(),
            response.encode(WireProfile::Extensions190, &ext()).unwrap(),
        ),
    ] {
        let (base, seen) = start(answer).await;
        let client = PeerClient::new(
            &a_example(),
            BTreeMap::from([(b.clone(), BaseUrl::try_from(base).unwrap())]),
        )
        .unwrap()
        .with_wire_profiles(BTreeMap::from([(b.clone(), profile)]));
        let got = client
            .update(&b, "mimi://b.example/r/one", plain.clone())
            .await
            .unwrap();
        // The peer gets its encoding; the caller gets protocol-07 back.
        assert_eq!(seen.lock().unwrap().as_slice(), [sent], "{profile:?}");
        assert_eq!(
            got,
            response.tls_serialize_detached().unwrap(),
            "{profile:?}"
        );
    }
}
