//! The local control listener's routes (crate::local; beads mimid-1wgh.47
//! and mimid-1wgh.12.4). Groups come from the common `build_group` helper,
//! which builds them with mimi-mls Members; each refusal is one rule of
//! `Hub::create_room`, already covered in hub_foundation.rs, seen here
//! through its HTTP mapping.

#[allow(dead_code, reason = "each test binary uses part of the helpers")]
mod common;

use std::sync::Arc;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode, header};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use common::*;
use mimid_server::hub::Hub;
use mimid_server::local::router;
use tower::ServiceExt;

async fn call(app: &Router, request: Request<Body>) -> (StatusCode, Vec<u8>) {
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let body = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
    (status, body.to_vec())
}

fn create(room_id: &str, group_info: &[u8], tree: &[u8]) -> Request<Body> {
    let body = serde_json::json!({
        "roomId": room_id,
        "creator": std::str::from_utf8(ALICE).unwrap(),
        "groupInfo": URL_SAFE_NO_PAD.encode(group_info),
        "ratchetTree": URL_SAFE_NO_PAD.encode(tree),
    });
    Request::post("/local/v1/rooms")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

async fn fixture() -> (tempfile::TempDir, Arc<Hub>, Router) {
    let dir = tempfile::tempdir().unwrap();
    let (_store, hub) = open_hub(&dir.path().join("mimid.sqlite")).await;
    let hub = Arc::new(hub);
    let app = router(Arc::clone(&hub));
    (dir, hub, app)
}

#[tokio::test]
async fn hub_sender_names_the_hub_key_and_domain() {
    let (_dir, hub, app) = fixture().await;
    let (status, body) = call(
        &app,
        Request::get("/local/v1/hub-sender")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        URL_SAFE_NO_PAD
            .decode(value["signatureKey"].as_str().unwrap())
            .unwrap(),
        hub.signature_public_key()
    );
    assert_eq!(value["identity"], "mimi://a.example");
}

#[tokio::test]
async fn a_valid_group_is_hosted_and_a_second_create_conflicts() {
    let (_dir, hub, app) = fixture().await;
    let group = build_group(&GroupSpec::valid_for(&hub), b"group-one");
    let (status, body) = call(
        &app,
        create(ROOM_ID, &group.group_info, &group.ratchet_tree),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["roomId"], ROOM_ID);
    hub.public_state(ROOM_ID)
        .await
        .expect("the hub hosts the room");

    let (status, body) = call(
        &app,
        create(ROOM_ID, &group.group_info, &group.ratchet_tree),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(problem_kind(&body), "room-exists");
}

#[tokio::test]
async fn a_group_the_hub_refuses_is_422() {
    let (_dir, hub, app) = fixture().await;
    let mut spec = GroupSpec::valid_for(&hub);
    spec.franking_agent = None;
    let group = build_group(&spec, b"group-one");
    let (status, body) = call(
        &app,
        create(ROOM_ID, &group.group_info, &group.ratchet_tree),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(problem_kind(&body), "group-refused");
    assert!(hub.public_state(ROOM_ID).await.is_err(), "nothing hosted");
}

#[tokio::test]
async fn a_room_under_another_domain_or_bad_base64_is_400() {
    let (_dir, hub, app) = fixture().await;
    let group = build_group(&GroupSpec::valid_for(&hub), b"group-one");
    let (status, body) = call(
        &app,
        create(
            "mimi://b.example/r/one",
            &group.group_info,
            &group.ratchet_tree,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(problem_kind(&body), "invalid-room-id");

    let body = serde_json::json!({
        "roomId": ROOM_ID,
        "creator": "mimi://a.example/u/alice",
        "groupInfo": "not base64url!",
        "ratchetTree": "",
    });
    let (status, body) = call(
        &app,
        Request::post("/local/v1/rooms")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(problem_kind(&body), "undecodable-request");
}
