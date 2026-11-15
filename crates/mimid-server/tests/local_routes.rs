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
    let (store, hub) = open_hub(&dir.path().join("mimid.sqlite")).await;
    let hub = Arc::new(hub);
    let app = router(Arc::clone(&hub), store, None);
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

/// Decision 2 of bead mimid-1wgh.47: with `local_token` set, a call needs
/// `Authorization: Bearer <token>`; without one, or with another, it is a
/// 401 problem.
#[tokio::test]
async fn a_configured_local_token_is_required() {
    let dir = tempfile::tempdir().unwrap();
    let (store, hub) = common::open_hub(&dir.path().join("mimid.sqlite")).await;
    let token = "x".repeat(mimid_server::local::MIN_LOCAL_TOKEN_LEN);
    let app = router(
        Arc::new(hub),
        store,
        Some(mimid_server::local::LocalToken::try_from(token.clone()).unwrap()),
    );
    let call = |authorization: Option<String>| {
        let app = app.clone();
        async move {
            let mut request = axum::http::Request::get("/local/v1/hub-sender");
            if let Some(value) = authorization {
                request = request.header(axum::http::header::AUTHORIZATION, value);
            }
            tower::ServiceExt::oneshot(app, request.body(axum::body::Body::empty()).unwrap())
                .await
                .unwrap()
                .status()
        }
    };
    use axum::http::StatusCode;
    assert_eq!(call(None).await, StatusCode::UNAUTHORIZED);
    assert_eq!(
        call(Some(format!("Bearer {token}y"))).await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(call(Some(token.clone())).await, StatusCode::UNAUTHORIZED);
    assert_eq!(call(Some(format!("Bearer {token}"))).await, StatusCode::OK);
}

/// Bead mimid-1wgh.47.2: the room list and one room's summary, read from
/// the hub's view of the group; a room not hosted here is 404.
#[tokio::test]
async fn hosted_rooms_are_listed_and_read() {
    let (_dir, hub, app) = fixture().await;
    let get = |path: String| Request::get(path).body(Body::empty()).unwrap();
    let (status, body) = call(&app, get("/local/v1/rooms".into())).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&body).unwrap(),
        serde_json::json!({"rooms": []})
    );

    let group = build_group(&GroupSpec::valid_for(&hub), b"group-one");
    assert_eq!(
        call(
            &app,
            create(ROOM_ID, &group.group_info, &group.ratchet_tree)
        )
        .await
        .0,
        StatusCode::CREATED
    );
    let (status, body) = call(&app, get("/local/v1/rooms".into())).await;
    assert_eq!(status, StatusCode::OK);
    let list: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let room = &list["rooms"][0];
    assert_eq!(room["roomId"], ROOM_ID);
    assert_eq!(room["groupId"], URL_SAFE_NO_PAD.encode(b"group-one"));
    assert_eq!(room["epoch"], 1);
    let alice = std::str::from_utf8(ALICE).unwrap();
    assert!(
        room["members"]
            .as_array()
            .unwrap()
            .iter()
            .any(|member| member["identity"] == alice),
        "{room}"
    );
    assert!(
        room["participants"]
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p["user"] == alice),
        "{room}"
    );

    let encoded = ROOM_ID.replace(':', "%3A").replace('/', "%2F");
    let (status, body) = call(&app, get(format!("/local/v1/rooms/{encoded}"))).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&body).unwrap(),
        *room
    );
    let (status, body) = call(
        &app,
        get("/local/v1/rooms/mimi%3A%2F%2Fa.example%2Fr%2Fnone".into()),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(problem_kind(&body), "no-such-room");
}

/// Bead mimid-1wgh.47.3: a local user's JMAP account is created, listed,
/// and given a bearer token that the store then accepts; a foreign or
/// repeated user and a token for a user without an account are refused.
#[tokio::test]
async fn accounts_and_tokens_are_issued_for_local_users() {
    let dir = tempfile::tempdir().unwrap();
    let (store, hub) = open_hub(&dir.path().join("mimid.sqlite")).await;
    let app = router(Arc::new(hub), store.clone(), None);
    let alice = std::str::from_utf8(ALICE).unwrap();
    let json = |method: &str, path: &str, body: Option<serde_json::Value>| {
        let mut request = Request::builder().method(method).uri(path);
        if body.is_some() {
            request = request.header(header::CONTENT_TYPE, "application/json");
        }
        request
            .body(body.map_or_else(Body::empty, |b| Body::from(b.to_string())))
            .unwrap()
    };
    let (status, body) = call(
        &app,
        json(
            "POST",
            "/local/v1/users",
            Some(serde_json::json!({"user": alice})),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let created: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(created["user"], alice);
    let account_id = created["accountId"].as_str().unwrap().to_owned();

    let (status, body) = call(
        &app,
        json(
            "POST",
            "/local/v1/users",
            Some(serde_json::json!({"user": alice})),
        ),
    )
    .await;
    assert_eq!(
        (status, problem_kind(&body)),
        (StatusCode::CONFLICT, "account-exists".to_owned())
    );
    let (status, body) = call(
        &app,
        json(
            "POST",
            "/local/v1/users",
            Some(serde_json::json!({"user": "mimi://b.example/u/bob"})),
        ),
    )
    .await;
    assert_eq!(
        (status, problem_kind(&body)),
        (StatusCode::BAD_REQUEST, "not-local-user".to_owned())
    );

    let (status, body) = call(&app, json("GET", "/local/v1/users", None)).await;
    assert_eq!(status, StatusCode::OK);
    let list: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(list["users"][0]["user"], alice);
    assert_eq!(list["users"][0]["accountId"], account_id);
    assert_eq!(list["users"].as_array().unwrap().len(), 1);

    let encoded = alice.replace(':', "%3A").replace('/', "%2F");
    let (status, body) = call(
        &app,
        json("POST", &format!("/local/v1/users/{encoded}/tokens"), None),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let token: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let token = mimid_server::store::BearerToken::parse(token["token"].as_str().unwrap()).unwrap();
    assert_eq!(
        store
            .account_for_token(&token)
            .await
            .unwrap()
            .map(|owner| owner.account_id),
        Some(account_id)
    );

    let (status, body) = call(
        &app,
        json(
            "POST",
            "/local/v1/users/mimi%3A%2F%2Fa.example%2Fu%2Fnobody/tokens",
            None,
        ),
    )
    .await;
    assert_eq!(
        (status, problem_kind(&body)),
        (StatusCode::NOT_FOUND, "no-such-user".to_owned())
    );
}

/// Bead mimid-1wgh.47.4: held consent requests and updates are listed,
/// requests first, `room` null for any room.
#[tokio::test]
async fn held_consent_is_listed() {
    use mimid_server::store::{ConsentDecision, ConsentKey, ReceivedConsent};
    let dir = tempfile::tempdir().unwrap();
    let (store, hub) = open_hub(&dir.path().join("mimid.sqlite")).await;
    let app = router(Arc::new(hub), store.clone(), None);
    let received = |at| ReceivedConsent {
        entry: vec![1, 2, 3],
        from_domain: "b.example".to_owned(),
        received_at: at,
    };
    store
        .put_consent_request(
            &ConsentKey {
                requester_uri: "mimi://b.example/u/bob",
                target_uri: "mimi://a.example/u/alice",
                room_id: None,
            },
            &received(10),
        )
        .await
        .unwrap();
    store
        .put_consent_update(
            &ConsentKey {
                requester_uri: "mimi://b.example/u/bob",
                target_uri: "mimi://a.example/u/alice",
                room_id: Some("mimi://b.example/r/den"),
            },
            ConsentDecision::Grant,
            &received(20),
        )
        .await
        .unwrap();
    let (status, body) = call(
        &app,
        Request::get("/local/v1/consent")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&body).unwrap(),
        serde_json::json!({"consent": [
            {"requester": "mimi://b.example/u/bob", "target": "mimi://a.example/u/alice",
             "room": null, "decision": null, "from": "b.example", "receivedAt": 10},
            {"requester": "mimi://b.example/u/bob", "target": "mimi://a.example/u/alice",
             "room": "mimi://b.example/r/den", "decision": "grant", "from": "b.example", "receivedAt": 20},
        ]})
    );
}

/// Bead mimid-1wgh.47.6: `mimid admin` drives a real listener: it creates a
/// user and issues a token, presents the configured token, and reports a
/// refusal with its status and problem type.
#[tokio::test]
async fn the_admin_cli_drives_a_running_listener() {
    use mimid_server::admin::{AdminError, run};
    use mimid_server::local::LocalToken;
    let dir = tempfile::tempdir().unwrap();
    let (store, hub) = open_hub(&dir.path().join("mimid.sqlite")).await;
    let token = LocalToken::try_from("k".repeat(mimid_server::local::MIN_LOCAL_TOKEN_LEN)).unwrap();
    let app = router(Arc::new(hub), store, Some(token.clone()));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let args = |list: &[&str]| list.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
    let alice = std::str::from_utf8(ALICE).unwrap();

    let created = run(Some(addr), Some(&token), &args(&["add-user", alice]))
        .await
        .unwrap();
    assert!(created.contains("accountId"), "{created}");
    let issued = run(Some(addr), Some(&token), &args(&["token", alice]))
        .await
        .unwrap();
    assert!(issued.contains("\"token\""), "{issued}");
    let users = run(Some(addr), Some(&token), &args(&["users"]))
        .await
        .unwrap();
    assert!(users.contains(alice), "{users}");

    match run(Some(addr), None, &args(&["users"])).await {
        Err(AdminError::Refused { status: 401, body }) => assert!(body.contains("unauthorized")),
        other => panic!("{other:?}"),
    }
    match run(Some(addr), Some(&token), &args(&["add-user", alice])).await {
        Err(AdminError::Refused { status: 409, .. }) => {}
        other => panic!("{other:?}"),
    }
    assert!(matches!(
        run(None, None, &args(&["users"])).await,
        Err(AdminError::NoListener)
    ));
}
