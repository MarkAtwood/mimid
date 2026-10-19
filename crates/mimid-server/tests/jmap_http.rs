//! The JMAP HTTP surface (mimid-1wgh.11.2): the Session, the API endpoint,
//! its request limits, authentication on every route, and a TRACE-level
//! log canary.
//!
//! Oracles: the expected Session is written out by hand from RFC 8620 §2
//! and draft-atwood-jmap-chat-00 §3 / draft-atwood-jmap-chat-mimi-00 §3
//! (jmap-chat-spec cefc217), with limits computed by hand in comments; the
//! hub's ExternalSender is encoded by hand from RFC 9420 §5.1.1, §5.3 and
//! §12.1.8.1; the problem bodies are written out from RFC 8620 §3.6.1 and
//! RFC 7807.

#[allow(dead_code, reason = "each test binary uses part of the helpers")]
mod common;

use std::sync::Arc;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{HeaderMap, Request, StatusCode, header};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use common::{FixedClock, assert_secret_absent, capture_logs, domain, open_hub};
use mimid_server::config::BaseUrl;
use mimid_server::follower::Follower;
use mimid_server::jmap::api::MAX_SIZE_REQUEST;
use mimid_server::jmap::{self, JmapOptions};
use mimid_server::store::{BearerToken, Store};
use serde_json::{Value, json};
use tower::ServiceExt;

const ALICE: &str = "mimi://a.example/u/alice";
const BOB: &str = "mimi://a.example/u/bob";
const BASE_URL: &str = "https://mimi.a.example";

/// base64url of the bytes 0..32: well formed, never issued.
const NEVER_ISSUED: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";

struct Fixture {
    _dir: tempfile::TempDir,
    store: Store,
    app: Router,
    hub_key: [u8; 32],
    alice_id: String,
    alice_token: BearerToken,
    bob_id: String,
    bob_token: BearerToken,
}

async fn fixture_with(options: JmapOptions) -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let (store, hub) = open_hub(&dir.path().join("mimid.sqlite")).await;
    let alice_id = store.create_account(&domain(), ALICE, 1).await.unwrap();
    let alice_token = store.issue_token(&alice_id, 2).await.unwrap();
    let bob_id = store.create_account(&domain(), BOB, 3).await.unwrap();
    let bob_token = store.issue_token(&bob_id, 4).await.unwrap();
    let hub_key = *hub.signature_public_key();
    let follower = Follower::new(domain(), store.clone(), Arc::new(FixedClock(5)));
    let app = jmap::router(
        &BaseUrl::try_from(BASE_URL.to_owned()).unwrap(),
        store.clone(),
        Arc::new(hub),
        Arc::new(follower),
        options,
    )
    .unwrap();
    Fixture {
        _dir: dir,
        store,
        app,
        hub_key,
        alice_id,
        alice_token,
        bob_id,
        bob_token,
    }
}

async fn fixture() -> Fixture {
    fixture_with(JmapOptions::default()).await
}

fn bearer(token: &BearerToken) -> String {
    format!("Bearer {}", token.expose_secret())
}

async fn send(app: &Router, request: Request<Body>) -> (StatusCode, HeaderMap, Vec<u8>) {
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    (status, headers, body.to_vec())
}

async fn get_session(
    app: &Router,
    authorization: Option<&str>,
) -> (StatusCode, HeaderMap, Vec<u8>) {
    let mut request = Request::get("/.well-known/jmap");
    if let Some(value) = authorization {
        request = request.header(header::AUTHORIZATION, value);
    }
    send(app, request.body(Body::empty()).unwrap()).await
}

/// POSTs `body` to `/jmap/api` as `application/json`.
async fn post_api(
    app: &Router,
    authorization: Option<&str>,
    body: Vec<u8>,
) -> (StatusCode, HeaderMap, Vec<u8>) {
    let mut request = Request::post("/jmap/api").header(header::CONTENT_TYPE, "application/json");
    if let Some(value) = authorization {
        request = request.header(header::AUTHORIZATION, value);
    }
    send(app, request.body(Body::from(body)).unwrap()).await
}

fn json_of(body: &[u8]) -> Value {
    serde_json::from_slice(body).unwrap()
}

/// A request of `calls` `Core/echo` calls.
fn echo_request(calls: usize) -> Value {
    let calls: Vec<Value> = (0..calls)
        .map(|i| json!(["Core/echo", {"hello": true, "n": i}, format!("c{i}")]))
        .collect();
    json!({"using": ["urn:ietf:params:jmap:core"], "methodCalls": calls})
}

/// Asserts an RFC 8620 §3.6.1 problem response.
fn assert_problem((status, headers, body): (StatusCode, HeaderMap, Vec<u8>), expected: Value) {
    assert_eq!(status, StatusCode::BAD_REQUEST, "{expected}");
    assert_eq!(
        headers.get(header::CONTENT_TYPE).unwrap(),
        "application/problem+json"
    );
    assert_eq!(json_of(&body), expected);
}

fn assert_unauthorized((status, headers, body): (StatusCode, HeaderMap, Vec<u8>), case: &str) {
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{case}");
    assert_eq!(
        headers.get(header::WWW_AUTHENTICATE).unwrap(),
        "Bearer",
        "{case}"
    );
    assert_eq!(
        json_of(&body),
        json!({"type": "about:blank", "title": "Unauthorized", "status": 401}),
        "{case}"
    );
}

/// The hub's ExternalSender (RFC 9420 §12.1.8.1), encoded by hand.
fn hub_sender(key: &[u8; 32]) -> Vec<u8> {
    let mut sender = Vec::new();
    // §5.1.1 SignaturePublicKey: opaque signature_key<V>, a one-octet
    // varint length 0x20 and the 32-octet Ed25519 key.
    sender.push(0x20);
    sender.extend_from_slice(key);
    // §5.3 Credential: credential_type basic = 0x0001, then opaque
    // identity<V>: length 0x10 (16) and "mimi://a.example" (decision
    // mimid-1wgh.6.35).
    sender.extend_from_slice(&[0x00, 0x01, 0x10]);
    sender.extend_from_slice(b"mimi://a.example");
    sender
}

/// The Session `account_id` (the user `user_uri`) should see, minus
/// `state`, written from RFC 8620 §2 and the drafts.
fn expected_session(
    account_id: &str,
    user_uri: &str,
    hub_key: &[u8; 32],
    max_key_packages: u64,
) -> Value {
    json!({
        "capabilities": {
            "urn:ietf:params:jmap:core": {
                // No blobs.
                "maxSizeUpload": 0,
                "maxConcurrentUpload": 0,
                // base64 of 4 MiB: 4 * ceil(4194304 / 3) = 4 * 1398102
                // = 5592408, plus the 65536-octet envelope allowance.
                "maxSizeRequest": 5_657_944,
                "maxConcurrentRequests": 4,
                "maxCallsInRequest": 16,
                "maxObjectsInGet": 500,
                "maxObjectsInSet": 500,
                "collationAlgorithms": []
            },
            // draft-atwood-jmap-chat-00 L229.
            "urn:ietf:params:jmap:chat": {},
            // draft-atwood-jmap-chat-mimi-00 L148.
            "urn:ietf:params:jmap:chat:mimi": {}
        },
        "accounts": {
            account_id: {
                "name": user_uri,
                "isPersonal": true,
                "isReadOnly": false,
                "accountCapabilities": {
                    // draft-atwood-jmap-chat-00 L231-248.
                    "urn:ietf:params:jmap:chat": {
                        // Unpadded base64 of 4 MiB:
                        // ceil(4194304 * 4 / 3) = 5592406.
                        "maxBodyBytes": 5_592_406,
                        "maxAttachmentBytes": 0,
                        "maxAttachmentsPerMessage": 0,
                        // Base L245 with mimi-00 L169, L420, L430.
                        "supportedBodyTypes": ["application/mimi-fanout"],
                        "supportsThreads": false
                    },
                    // draft-atwood-jmap-chat-mimi-00 L150-167.
                    "urn:ietf:params:jmap:chat:mimi": {
                        "userUri": user_uri,
                        "roomIdPrefix": "mimi://a.example/r/",
                        "hubSender": URL_SAFE_NO_PAD.encode(hub_sender(hub_key)),
                        "cipherSuites": [1],
                        "maxKeyPackages": max_key_packages
                    }
                }
            }
        },
        "primaryAccounts": {
            "urn:ietf:params:jmap:chat": account_id,
            "urn:ietf:params:jmap:chat:mimi": account_id
        },
        "username": user_uri,
        "apiUrl": "https://mimi.a.example/jmap/api",
        "downloadUrl": "https://mimi.a.example/jmap/download/{accountId}/{blobId}/{name}?accept={type}",
        "uploadUrl": "https://mimi.a.example/jmap/upload/{accountId}/",
        "eventSourceUrl": "https://mimi.a.example/jmap/eventsource?types={types}&closeafter={closeafter}&ping={ping}",
        // draft-atwood-jmap-chat-00 L258.
        "ownerUserId": user_uri
    })
}

/// Splits `state` off a Session, checking it is a non-empty string.
fn take_state(session: &mut Value) -> String {
    let state = session
        .as_object_mut()
        .unwrap()
        .remove("state")
        .expect("Session has a state");
    let state = state.as_str().unwrap().to_owned();
    assert!(!state.is_empty());
    state
}

#[tokio::test]
async fn session_matches_the_drafts_for_each_account() {
    let f = fixture().await;
    for (token, id, user) in [
        (&f.alice_token, &f.alice_id, ALICE),
        (&f.bob_token, &f.bob_id, BOB),
    ] {
        let (status, headers, body) = get_session(&f.app, Some(&bearer(token))).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            headers.get(header::CONTENT_TYPE).unwrap(),
            "application/json"
        );
        // RFC 8620 §2 recommends this.
        assert_eq!(
            headers.get(header::CACHE_CONTROL).unwrap(),
            "no-cache, no-store, must-revalidate"
        );
        let mut session = json_of(&body);
        take_state(&mut session);
        assert_eq!(
            session,
            // Mark's default maxKeyPackages (mimid-1wgh.11.2).
            expected_session(id, user, &f.hub_key, 97),
            "{user}"
        );
    }
    f.store.close().await;
}

#[tokio::test]
async fn max_key_packages_comes_from_the_options() {
    let mut options = JmapOptions::default();
    options.max_key_packages = 7;
    let f = fixture_with(options).await;
    let (_, _, body) = get_session(&f.app, Some(&bearer(&f.alice_token))).await;
    let mut session = json_of(&body);
    take_state(&mut session);
    assert_eq!(session, expected_session(&f.alice_id, ALICE, &f.hub_key, 7));
    f.store.close().await;
}

#[tokio::test]
async fn hub_sender_is_the_external_sender_encoding() {
    let dir = tempfile::tempdir().unwrap();
    let (store, hub) = open_hub(&dir.path().join("mimid.sqlite")).await;
    assert_eq!(
        hub.hub_sender().unwrap(),
        hub_sender(hub.signature_public_key())
    );
    common::close_hub(store, hub).await;
}

#[tokio::test]
async fn echo_round_trips_with_the_session_state() {
    let f = fixture().await;
    let (_, _, body) = get_session(&f.app, Some(&bearer(&f.alice_token))).await;
    let state = take_state(&mut json_of(&body));
    let (status, headers, body) = post_api(
        &f.app,
        Some(&bearer(&f.alice_token)),
        serde_json::to_vec(&echo_request(2)).unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        headers.get(header::CONTENT_TYPE).unwrap(),
        "application/json"
    );
    // RFC 8620 §3.4 and §4.
    assert_eq!(
        json_of(&body),
        json!({
            "methodResponses": [
                ["Core/echo", {"hello": true, "n": 0}, "c0"],
                ["Core/echo", {"hello": true, "n": 1}, "c1"]
            ],
            "sessionState": state
        })
    );
    f.store.close().await;
}

#[tokio::test]
async fn unimplemented_methods_answer_unknown_method() {
    let f = fixture().await;
    let request = json!({
        "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:chat"],
        "methodCalls": [["Chat/get", {"accountId": f.alice_id}, "c1"]]
    });
    let (status, _, body) = post_api(
        &f.app,
        Some(&bearer(&f.alice_token)),
        serde_json::to_vec(&request).unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    // RFC 8620 §3.6.2.
    assert_eq!(
        json_of(&body)["methodResponses"],
        json!([["error", {"type": "unknownMethod"}, "c1"]])
    );
    f.store.close().await;
}

#[tokio::test]
async fn unknown_capability_is_refused() {
    let f = fixture().await;
    let request = json!({
        "using": ["urn:ietf:params:jmap:core", "https://example.com/apis/foobar"],
        "methodCalls": [["Core/echo", {}, "c1"]]
    });
    assert_problem(
        post_api(
            &f.app,
            Some(&bearer(&f.alice_token)),
            serde_json::to_vec(&request).unwrap(),
        )
        .await,
        json!({
            "type": "urn:ietf:params:jmap:error:unknownCapability",
            "status": 400,
            "detail": "https://example.com/apis/foobar"
        }),
    );
    f.store.close().await;
}

#[tokio::test]
async fn every_route_refuses_missing_and_wrong_tokens() {
    let f = fixture().await;
    let never_issued = format!("Bearer {NEVER_ISSUED}");
    let revoked = f.store.issue_token(&f.alice_id, 10).await.unwrap();
    assert!(f.store.revoke_token(&revoked, 11).await.unwrap());
    let revoked = bearer(&revoked);
    for authorization in [None, Some(never_issued.as_str()), Some(revoked.as_str())] {
        let case = format!("{authorization:?}");
        assert_unauthorized(get_session(&f.app, authorization).await, &case);
        assert_unauthorized(
            post_api(
                &f.app,
                authorization,
                serde_json::to_vec(&echo_request(1)).unwrap(),
            )
            .await,
            &case,
        );
    }
    f.store.close().await;
}

/// Decision mimid-1wgh.12.36: a request of exactly `maxSizeRequest` octets
/// is served; one octet more is refused.
#[tokio::test]
async fn body_limit_is_max_size_request() {
    let f = fixture().await;
    let mut body = serde_json::to_vec(&echo_request(1)).unwrap();
    // JSON allows trailing whitespace (RFC 8259 §2).
    body.resize(MAX_SIZE_REQUEST, b' ');
    let (status, _, _) = post_api(&f.app, Some(&bearer(&f.alice_token)), body.clone()).await;
    assert_eq!(status, StatusCode::OK, "exactly at the limit");
    body.push(b' ');
    assert_problem(
        post_api(&f.app, Some(&bearer(&f.alice_token)), body).await,
        json!({
            "type": "urn:ietf:params:jmap:error:limit",
            "status": 400,
            "limit": "maxSizeRequest"
        }),
    );
    f.store.close().await;
}

#[tokio::test]
async fn too_many_method_calls_are_refused() {
    let f = fixture().await;
    let token = bearer(&f.alice_token);
    let (status, _, _) = post_api(
        &f.app,
        Some(&token),
        serde_json::to_vec(&echo_request(16)).unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "16 calls");
    assert_problem(
        post_api(
            &f.app,
            Some(&token),
            serde_json::to_vec(&echo_request(17)).unwrap(),
        )
        .await,
        json!({
            "type": "urn:ietf:params:jmap:error:limit",
            "status": 400,
            "limit": "maxCallsInRequest"
        }),
    );
    f.store.close().await;
}

/// A request whose `Core/echo` argument nests `extra` arrays: the request
/// object, `methodCalls`, the Invocation and the arguments make four
/// levels, so the depth is `4 + extra`.
fn nested_request(extra: usize) -> Vec<u8> {
    format!(
        r#"{{"using":["urn:ietf:params:jmap:core"],"methodCalls":[["Core/echo",{{"a":{}{}}},"c1"]]}}"#,
        "[".repeat(extra),
        "]".repeat(extra)
    )
    .into_bytes()
}

#[tokio::test]
async fn deep_nesting_is_refused() {
    let f = fixture().await;
    let token = bearer(&f.alice_token);
    // MAX_REQUEST_DEPTH is 32.
    let (status, _, _) = post_api(&f.app, Some(&token), nested_request(28)).await;
    assert_eq!(status, StatusCode::OK, "depth 32");
    let not_json = json!({"type": "urn:ietf:params:jmap:error:notJSON", "status": 400});
    assert_problem(
        post_api(&f.app, Some(&token), nested_request(29)).await,
        not_json.clone(),
    );
    // Far past serde_json's own recursion limit of 128.
    assert_problem(
        post_api(&f.app, Some(&token), nested_request(10_000)).await,
        not_json,
    );
    f.store.close().await;
}

#[tokio::test]
async fn malformed_requests_are_refused() {
    let f = fixture().await;
    let token = bearer(&f.alice_token);
    let not_json = json!({"type": "urn:ietf:params:jmap:error:notJSON", "status": 400});
    let not_request = json!({"type": "urn:ietf:params:jmap:error:notRequest", "status": 400});
    for (case, body, expected) in [
        ("not JSON", b"{".to_vec(), &not_json),
        ("trailing bytes", b"{}x".to_vec(), &not_json),
        (
            "invalid UTF-8",
            b"{\"using\":[\"\xff\"],\"methodCalls\":[]}".to_vec(),
            &not_json,
        ),
        (
            "lone surrogate",
            br#"{"using":["\ud800"],"methodCalls":[]}"#.to_vec(),
            &not_json,
        ),
        (
            "not a Request",
            br#"{"using":5,"methodCalls":[]}"#.to_vec(),
            &not_request,
        ),
        ("no methodCalls", br#"{"using":[]}"#.to_vec(), &not_request),
        (
            "short Invocation",
            br#"{"using":[],"methodCalls":[["Core/echo",{}]]}"#.to_vec(),
            &not_request,
        ),
    ] {
        let response = post_api(&f.app, Some(&token), body).await;
        assert_eq!(json_of(&response.2), *expected, "{case}");
        assert_problem(response, expected.clone());
    }

    // RFC 8620 §3.1: the request must be application/json.
    for content_type in [None, Some("text/plain"), Some("application/jsonx")] {
        let mut request = Request::post("/jmap/api").header(header::AUTHORIZATION, &token);
        if let Some(value) = content_type {
            request = request.header(header::CONTENT_TYPE, value);
        }
        let body = Body::from(serde_json::to_vec(&echo_request(1)).unwrap());
        assert_problem(
            send(&f.app, request.body(body).unwrap()).await,
            not_json.clone(),
        );
    }
    f.store.close().await;
}

#[tokio::test]
async fn upload_and_download_answer_404() {
    let f = fixture().await;
    let token = bearer(&f.alice_token);
    let upload = Request::post(format!("/jmap/upload/{}/", f.alice_id))
        .header(header::AUTHORIZATION, &token)
        .body(Body::from("blob"))
        .unwrap();
    assert_eq!(send(&f.app, upload).await.0, StatusCode::NOT_FOUND);
    let download = Request::get(format!(
        "/jmap/download/{}/b1/name?accept=text/plain",
        f.alice_id
    ))
    .header(header::AUTHORIZATION, &token)
    .body(Body::empty())
    .unwrap();
    assert_eq!(send(&f.app, download).await.0, StatusCode::NOT_FOUND);
    f.store.close().await;
}

/// Every `tracing` event at TRACE, over Session and API requests accepted
/// and refused, is free of the tokens.
#[tokio::test]
async fn trace_logs_never_contain_tokens() {
    let logs = capture_logs();
    let f = fixture().await;
    let alice = bearer(&f.alice_token);
    assert_eq!(get_session(&f.app, Some(&alice)).await.0, StatusCode::OK);
    let echo = serde_json::to_vec(&echo_request(1)).unwrap();
    assert_eq!(
        post_api(&f.app, Some(&alice), echo.clone()).await.0,
        StatusCode::OK
    );
    let unknown = json!({"using": ["urn:x"], "methodCalls": []});
    let refused = post_api(&f.app, Some(&alice), serde_json::to_vec(&unknown).unwrap()).await;
    assert_eq!(refused.0, StatusCode::BAD_REQUEST);
    let padded = format!("Bearer {}=", f.alice_token.expose_secret());
    assert_unauthorized(post_api(&f.app, Some(&padded), echo).await, "padded");

    let text = logs.contents();
    assert!(
        text.contains("jmap request authenticated"),
        "capture works: {text}"
    );
    assert!(
        text.contains("jmap request refused"),
        "capture works: {text}"
    );
    for token in [&f.alice_token, &f.bob_token] {
        let raw = URL_SAFE_NO_PAD.decode(token.expose_secret()).unwrap();
        assert_secret_absent(&text, &raw, "token");
    }
    f.store.close().await;
}
