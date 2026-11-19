//! JMAP blobs and the asset server (bead mimid-1wgh.14, stage 1): upload
//! and download (RFC 8620 §6.1, §6.2), the unauthenticated `/assets`
//! route, and `/jmap/asset` for this server's own asset URLs.
//!
//! Oracles: the downloaded and served bytes equal the uploaded ones
//! octet for octet; the upload response's fields are those RFC 8620 §6.1
//! names, with `size` the body's length; status codes and problem bodies
//! are those RFC 8620 §6 and RFC 7807 call for, as the module
//! documentation of `mimid_server::jmap::blobs` maps them.

#[allow(dead_code, reason = "each test binary uses part of the helpers")]
mod common;

use std::sync::Arc;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{HeaderMap, Request, StatusCode, header};
use common::{FixedClock, domain, open_hub};
use mimid_server::config::BaseUrl;
use mimid_server::follower::Follower;
use mimid_server::jmap::blobs::MAX_BLOB_LEN;
use mimid_server::jmap::{self, JmapOptions};
use mimid_server::store::{BearerToken, Store};
use serde_json::{Value, json};
use tower::ServiceExt;

const ALICE: &str = "mimi://a.example/u/alice";
const BOB: &str = "mimi://a.example/u/bob";
const BASE_URL: &str = "https://mimi.a.example";

/// Every octet value, then some: an opaque "ciphertext".
fn ciphertext() -> Vec<u8> {
    (0..=255u8).chain(0..=255u8).rev().collect()
}

struct Fixture {
    _dir: tempfile::TempDir,
    store: Store,
    app: Router,
    alice_id: String,
    alice_token: BearerToken,
    bob_id: String,
    bob_token: BearerToken,
}

async fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let (store, hub) = open_hub(&dir.path().join("mimid.sqlite")).await;
    let alice_id = store.create_account(&domain(), ALICE, 1).await.unwrap();
    let alice_token = store.issue_token(&alice_id, 2).await.unwrap();
    let bob_id = store.create_account(&domain(), BOB, 3).await.unwrap();
    let bob_token = store.issue_token(&bob_id, 4).await.unwrap();
    let follower = Follower::new(domain(), store.clone(), Arc::new(FixedClock(5)));
    let app = jmap::router(
        &BaseUrl::try_from(BASE_URL.to_owned()).unwrap(),
        store.clone(),
        Arc::new(hub),
        Arc::new(follower),
        JmapOptions::default(),
    )
    .unwrap();
    Fixture {
        _dir: dir,
        store,
        app,
        alice_id,
        alice_token,
        bob_id,
        bob_token,
    }
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

/// Uploads `body` as `content_type` to `account_id`'s upload URL with
/// `token`.
async fn upload(
    app: &Router,
    token: &BearerToken,
    account_id: &str,
    content_type: Option<&str>,
    body: Vec<u8>,
) -> (StatusCode, HeaderMap, Vec<u8>) {
    let mut request = Request::post(format!("/jmap/upload/{account_id}/"))
        .header(header::AUTHORIZATION, bearer(token));
    if let Some(content_type) = content_type {
        request = request.header(header::CONTENT_TYPE, content_type);
    }
    send(app, request.body(Body::from(body)).unwrap()).await
}

async fn get(
    app: &Router,
    uri: &str,
    token: Option<&BearerToken>,
) -> (StatusCode, HeaderMap, Vec<u8>) {
    let mut request = Request::get(uri);
    if let Some(token) = token {
        request = request.header(header::AUTHORIZATION, bearer(token));
    }
    send(app, request.body(Body::empty()).unwrap()).await
}

fn json_of(body: &[u8]) -> Value {
    serde_json::from_slice(body).unwrap()
}

/// Uploads [`ciphertext`] as alice and returns its blob id.
async fn alice_uploads(f: &Fixture) -> String {
    let (status, _, body) = upload(
        &f.app,
        &f.alice_token,
        &f.alice_id,
        Some("application/octet-stream"),
        ciphertext(),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    json_of(&body)["blobId"].as_str().unwrap().to_owned()
}

fn assert_problem(
    (status, headers, body): (StatusCode, HeaderMap, Vec<u8>),
    want: StatusCode,
    want_body: &Value,
) {
    assert_eq!(status, want, "{want_body}");
    assert_eq!(
        headers.get(header::CONTENT_TYPE).unwrap(),
        "application/problem+json"
    );
    assert_eq!(&json_of(&body), want_body);
}

fn not_found() -> Value {
    json!({"type": "about:blank", "title": "Not Found", "status": 404})
}

#[tokio::test]
async fn an_upload_downloads_back_byte_for_byte() {
    let f = fixture().await;
    let (status, headers, body) = upload(
        &f.app,
        &f.alice_token,
        &f.alice_id,
        Some("image/png"),
        ciphertext(),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(
        headers.get(header::CONTENT_TYPE).unwrap(),
        "application/json"
    );
    let response = json_of(&body);
    let blob_id = response["blobId"].as_str().unwrap().to_owned();
    // 16 random octets, unpadded base64url.
    assert_eq!(blob_id.len(), 22);
    assert!(
        blob_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    );
    assert_eq!(
        response,
        json!({
            "accountId": f.alice_id,
            "blobId": blob_id,
            "type": "image/png",
            "size": 512
        })
    );

    let (status, headers, body) = get(
        &f.app,
        &format!(
            "/jmap/download/{}/{blob_id}/cat%20pic.png?accept=image/png",
            f.alice_id
        ),
        Some(&f.alice_token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, ciphertext());
    assert_eq!(headers.get(header::CONTENT_TYPE).unwrap(), "image/png");
    // RFC 8620 §6.2: the name, as the filename.
    assert_eq!(
        headers.get(header::CONTENT_DISPOSITION).unwrap(),
        "attachment; filename*=UTF-8''cat%20pic.png"
    );
    assert_eq!(headers.get("x-content-type-options").unwrap(), "nosniff");
    assert_eq!(
        headers.get(header::CACHE_CONTROL).unwrap(),
        "private, immutable, max-age=31536000"
    );

    // Without `accept`, the uploaded type; an upload without a type is
    // application/octet-stream.
    let (_, headers, _) = get(
        &f.app,
        &format!("/jmap/download/{}/{blob_id}/x", f.alice_id),
        Some(&f.alice_token),
    )
    .await;
    assert_eq!(headers.get(header::CONTENT_TYPE).unwrap(), "image/png");
    let (_, _, body) = upload(&f.app, &f.alice_token, &f.alice_id, None, b"".to_vec()).await;
    assert_eq!(json_of(&body)["type"], "application/octet-stream");
    assert_eq!(json_of(&body)["size"], 0);
    f.store.close().await;
}

#[tokio::test]
async fn another_account_cannot_download_or_upload_as_alice() {
    let f = fixture().await;
    let blob_id = alice_uploads(&f).await;
    // Bob, through his own account: the blob is not his (RFC 8620 §6.1).
    assert_problem(
        get(
            &f.app,
            &format!("/jmap/download/{}/{blob_id}/x", f.bob_id),
            Some(&f.bob_token),
        )
        .await,
        StatusCode::NOT_FOUND,
        &not_found(),
    );
    // Bob, naming alice's account.
    assert_problem(
        get(
            &f.app,
            &format!("/jmap/download/{}/{blob_id}/x", f.alice_id),
            Some(&f.bob_token),
        )
        .await,
        StatusCode::NOT_FOUND,
        &not_found(),
    );
    assert_problem(
        upload(&f.app, &f.bob_token, &f.alice_id, None, b"x".to_vec()).await,
        StatusCode::NOT_FOUND,
        &not_found(),
    );
    // No token at all.
    let (status, _, _) = get(
        &f.app,
        &format!("/jmap/download/{}/{blob_id}/x", f.alice_id),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let request = Request::post(format!("/jmap/upload/{}/", f.alice_id))
        .body(Body::from("x"))
        .unwrap();
    assert_eq!(send(&f.app, request).await.0, StatusCode::UNAUTHORIZED);
    // Unknown and malformed ids.
    for id in ["AAECAwQFBgcICQoLDA0ODw", "nope", "AAECAwQFBgcICQoLDA0ODx"] {
        assert_problem(
            get(
                &f.app,
                &format!("/jmap/download/{}/{id}/x", f.alice_id),
                Some(&f.alice_token),
            )
            .await,
            StatusCode::NOT_FOUND,
            &not_found(),
        );
    }
    f.store.close().await;
}

#[tokio::test]
async fn an_upload_at_the_cap_is_stored_and_one_past_it_is_413() {
    let f = fixture().await;
    let (status, _, body) = upload(
        &f.app,
        &f.alice_token,
        &f.alice_id,
        None,
        vec![7; MAX_BLOB_LEN],
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(json_of(&body)["size"], 16 * 1024 * 1024);
    assert_problem(
        upload(
            &f.app,
            &f.alice_token,
            &f.alice_id,
            None,
            vec![7; MAX_BLOB_LEN + 1],
        )
        .await,
        StatusCode::PAYLOAD_TOO_LARGE,
        &json!({
            "type": "urn:ietf:params:jmap:error:limit",
            "status": 413,
            "limit": "maxSizeUpload"
        }),
    );
    f.store.close().await;
}

#[tokio::test]
async fn assets_serve_without_auth_and_404_an_unknown_id() {
    let f = fixture().await;
    let blob_id = alice_uploads(&f).await;
    let (status, headers, body) = get(&f.app, &format!("/assets/{blob_id}"), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, ciphertext());
    assert_eq!(
        headers.get(header::CONTENT_TYPE).unwrap(),
        "application/octet-stream"
    );
    assert_eq!(headers.get("x-content-type-options").unwrap(), "nosniff");
    assert!(
        headers
            .keys()
            .all(|name| !name.as_str().starts_with("access-control-")),
        "no CORS headers: {headers:?}"
    );
    for id in [
        "AAECAwQFBgcICQoLDA0ODw",
        "short",
        "AAECAwQFBgcICQoLDA0ODw==",
    ] {
        assert_problem(
            get(&f.app, &format!("/assets/{id}"), None).await,
            StatusCode::NOT_FOUND,
            &not_found(),
        );
    }
    f.store.close().await;
}

#[tokio::test]
async fn the_session_advertises_the_asset_urls_and_upload_limits() {
    let f = fixture().await;
    let (status, _, body) = get(&f.app, "/.well-known/jmap", Some(&f.alice_token)).await;
    assert_eq!(status, StatusCode::OK);
    let session = json_of(&body);
    // draft-atwood-jmap-chat-mimi-00 §Account-Level Capability Object.
    let mimi =
        &session["accounts"][&f.alice_id]["accountCapabilities"]["urn:ietf:params:jmap:chat:mimi"];
    assert_eq!(mimi["assetUrl"], "https://mimi.a.example/assets/{blobId}");
    assert_eq!(
        mimi["assetDownloadUrl"],
        format!(
            "https://mimi.a.example/jmap/asset/{}?room={{roomId}}&url={{url}}",
            f.alice_id
        )
    );
    assert_eq!(
        session["capabilities"]["urn:ietf:params:jmap:core"]["maxSizeUpload"],
        16 * 1024 * 1024
    );
    f.store.close().await;
}
