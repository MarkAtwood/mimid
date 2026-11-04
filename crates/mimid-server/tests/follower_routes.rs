//! Routing of the follower endpoints (bead mimid-1wgh.7.18): `/v1/notify`
//! and keyMaterial for users of this provider in rooms hosted elsewhere
//! reach the follower, and keyMaterial for anyone else, or for a room
//! hosted here, reaches the hub (decision mimid-1wgh.7.27).
//!
//! The provider hosts no rooms, so the two paths answer a decodable
//! keyMaterial request differently: the hub with `404` (protocol-07 §5.2
//! step order in `hub/key_material.rs`), the follower stub with `501`.

#[allow(dead_code, reason = "each test binary uses part of the helpers")]
mod common;

use std::sync::Arc;

use axum::body::{Body, Bytes, to_bytes};
use axum::http::{Request, StatusCode, header};
use common::*;
use mimi_mls::label::SignatureKeyPair;
use mimi_mls::tls_codec::{Deserialize, Serialize};
use mimi_mls::wire::{CipherSuite, Credential, RequiredCapabilities, SignaturePublicKey};
use mimi_protocol::{
    IdentifierUri, KeyMaterialRequestTbs, KeyMaterialResponse, KeyMaterialUserCode, Protocol,
};
use mimid_server::config::BaseUrl;
use mimid_server::directory::directory;
use mimid_server::follower::Follower;
use mimid_server::http::router;
use tower::ServiceExt;

/// A user of this provider.
const ALICE_ENCODED: &str = "mimi%3A%2F%2Fa.example%2Fu%2Falice";
/// A user of another provider.
const CATHY: &str = "mimi://c.example/u/cathy";
const CATHY_ENCODED: &str = "mimi%3A%2F%2Fc.example%2Fu%2Fcathy";
const DEN: &str = "mimi://b.example/r/den";
const DEN_ENCODED: &str = "mimi%3A%2F%2Fb.example%2Fr%2Fden";

/// `opaque<V>` holding `bytes` (RFC 9420 §2.1.2), for fewer than 64 bytes.
fn opaque(bytes: &[u8]) -> Vec<u8> {
    [vec![u8::try_from(bytes.len()).unwrap()], bytes.to_vec()].concat()
}

/// A KeyMaterialRequest from bob at b.example for `target_user` in
/// `room_id`, signed with a fresh Ed25519 key.
fn key_material_request(target_user: &str, room_id: &str) -> Vec<u8> {
    let pair = SignatureKeyPair::generate().unwrap();
    // RFC 9420 §5.1.1, §5.3 (basic = 1), §11.1 (three empty lists), §17.1.
    let key = SignaturePublicKey::tls_deserialize_exact(opaque(pair.verification_key())).unwrap();
    let credential =
        Credential::tls_deserialize_exact([&[0x00, 0x01][..], &opaque(BOB)].concat()).unwrap();
    let uri = |bytes: &[u8]| IdentifierUri::new(std::str::from_utf8(bytes).unwrap()).unwrap();
    KeyMaterialRequestTbs {
        protocol: Protocol::Mls10,
        requesting_user: uri(BOB),
        target_user: uri(target_user.as_bytes()),
        room_id: uri(room_id.as_bytes()),
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

/// Posts `body` to `path`, with `From: <from>` if given, on the router of a
/// fresh provider for [`DOMAIN`] hosting no rooms.
async fn post(path: &str, from: Option<&str>, body: Vec<u8>) -> (StatusCode, Bytes) {
    let dir = tempfile::tempdir().unwrap();
    let (store, hub) = open_hub(&dir.path().join("mimid.sqlite")).await;
    let base = BaseUrl::try_from("https://mimi.a.example".to_owned()).unwrap();
    let mut request = Request::post(path);
    if let Some(from) = from {
        request = request.header(header::FROM, from);
    }
    let follower = Follower::new(domain(), store.clone(), Arc::new(FixedClock(0)));
    let response = router(directory(&base), Arc::new(hub), Arc::new(follower))
        .oneshot(request.body(Body::from(body)).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    store.close().await;
    (status, body)
}

/// The follower refuses the request: the provider has no configured peers
/// (decision mimid-1wgh.7.4).
#[tokio::test]
async fn notify_reaches_the_follower() {
    let path = format!("/v1/notify/{DEN_ENCODED}");
    let (status, body) = post(&path, Some("mimi@b.example"), Vec::new()).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body, "source provider is not a configured peer");
}

#[tokio::test]
async fn notify_without_from_is_400() {
    let path = format!("/v1/notify/{DEN_ENCODED}");
    let (status, _) = post(&path, None, Vec::new()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn key_material_for_a_local_user_in_a_room_hosted_elsewhere_reaches_the_follower() {
    let path = format!("/v1/keyMaterial/{ALICE_ENCODED}");
    let request = key_material_request("mimi://a.example/u/alice", DEN);
    let (status, body) = post(&path, Some("mimi@b.example"), request).await;
    assert_eq!(status, StatusCode::NOT_IMPLEMENTED);
    assert_eq!(body, "keyMaterial for local users is not implemented");
}

#[tokio::test]
async fn key_material_for_a_local_user_in_a_room_hosted_here_reaches_the_hub() {
    let path = format!("/v1/keyMaterial/{ALICE_ENCODED}");
    let request = key_material_request("mimi://a.example/u/alice", ROOM_ID);
    let (status, body) = post(&path, Some("mimi@b.example"), request).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body, "no such room");
}

#[tokio::test]
async fn undecodable_key_material_for_a_local_user_is_400() {
    let path = format!("/v1/keyMaterial/{ALICE_ENCODED}");
    let mut request = key_material_request("mimi://a.example/u/alice", ROOM_ID);
    request.push(0x00);
    let (status, body) = post(&path, Some("mimi@b.example"), request).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body, "undecodable request");
}

#[tokio::test]
async fn key_material_for_a_remote_user_reaches_the_hub() {
    let path = format!("/v1/keyMaterial/{CATHY_ENCODED}");
    let (status, body) = post(
        &path,
        Some("mimi@b.example"),
        key_material_request(CATHY, ROOM_ID),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body, "no such room");
}

/// A `targetUser` naming no domain is the hub's to refuse: it answers
/// `noConsent` because the path is not the request's `targetUser`.
#[tokio::test]
async fn key_material_for_a_non_user_reaches_the_hub() {
    let (status, body) = post(
        "/v1/keyMaterial/not-a-user-uri",
        Some("mimi@b.example"),
        key_material_request(CATHY, ROOM_ID),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let response = KeyMaterialResponse::tls_deserialize_exact(&body[..]).unwrap();
    assert_eq!(response.user_status, KeyMaterialUserCode::NoConsent);
    assert!(response.clients.is_empty());
}
