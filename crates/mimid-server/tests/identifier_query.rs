//! The protocol-07 §5.8 identifierQuery endpoint, received:
//! `POST /v1/identifierQuery/{domain}`.
//!
//! Policy (decisions mimid-1wgh.7.38, mimid-1wgh.7.39): only exact `handle`
//! queries are answered, and a local user's handle is its mimi:// URI. An
//! empty query is `forbidden`, any other search type `unsupportedField`,
//! and every decodable request gets `200` with an IdentifierResponse
//! (decision mimid-1wgh.7.40).
//!
//! Oracles: the Haven-encoded fixture `identifier_request.bin` (from
//! `crates/mimi-protocol/tests/fixtures/haven`, see its PROVENANCE: one
//! `handle` element "alice" and one `vcardField` EMAIL element), and
//! requests and responses hand-encoded from the §5.8 TLS presentation
//! language with byte-by-byte comments.

#![forbid(unsafe_code)]

#[allow(dead_code, reason = "each test binary uses part of the helpers")]
mod common;

use std::sync::Arc;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode, header};
use common::FixedClock;
use mimid_server::config::{BaseUrl, Domain};
use mimid_server::directory::directory;
use mimid_server::follower::Follower;
use mimid_server::http::router;
use mimid_server::hub::Hub;
use mimid_server::store::{NewKeyPackage, Store};
use tempfile::TempDir;
use tower::ServiceExt;

/// `handle` "alice" AND `vcardField` EMAIL "alice@a.example", encoded by
/// Haven's mimi-core.
const HAVEN_REQUEST: &[u8] =
    include_bytes!("../../mimi-protocol/tests/fixtures/haven/identifier_request.bin");

const BOB: &str = "mimi://b.example/u/bob";
const PATH: &str = "/v1/identifierQuery/b.example";
const FROM_A: Option<&str> = Some("mimi@a.example");

/// IdentifierRequest: one `handle` element for `mimi://b.example/u/bob`.
const HANDLE_BOB: &[u8] = &[
    0x18, // query_elements<V>: 24 bytes
    0x01, // searchType = handle(1); no select arm
    0x16, // searchValue<V>: 22 bytes
    b'm', b'i', b'm', b'i', b':', b'/', b'/', b'b', b'.', b'e', b'x', b'a', b'm', b'p', b'l', b'e',
    b'/', b'u', b'/', b'b', b'o', b'b', // "mimi://b.example/u/bob"
    0x00, // id_request_extensions: component_data<V> empty
];

/// IdentifierRequest: `handle` bob AND `handle` carol (AND semantics).
const HANDLE_BOB_AND_CAROL: &[u8] = &[
    0x32, // query_elements<V>: 50 bytes
    0x01, // searchType = handle(1)
    0x16, // searchValue<V>: 22 bytes
    b'm', b'i', b'm', b'i', b':', b'/', b'/', b'b', b'.', b'e', b'x', b'a', b'm', b'p', b'l', b'e',
    b'/', b'u', b'/', b'b', b'o', b'b', // "mimi://b.example/u/bob"
    0x01, // searchType = handle(1)
    0x18, // searchValue<V>: 24 bytes
    b'm', b'i', b'm', b'i', b':', b'/', b'/', b'b', b'.', b'e', b'x', b'a', b'm', b'p', b'l', b'e',
    b'/', b'u', b'/', b'c', b'a', b'r', b'o', b'l', // "mimi://b.example/u/carol"
    0x00, // id_request_extensions: empty
];

/// IdentifierRequest: one `nick` element "bob".
const NICK_BOB: &[u8] = &[
    0x05, // query_elements<V>: 5 bytes
    0x02, // searchType = nick(2); no select arm
    0x03, b'b', b'o', b'b', // searchValue<V>: "bob"
    0x00, // id_request_extensions: empty
];

/// IdentifierRequest with no query elements (decodes per decision
/// mimid-1wgh.5.73).
const EMPTY: &[u8] = &[
    0x00, // query_elements<V>: empty
    0x00, // id_request_extensions: empty
];

/// IdentifierResponse `success` with uri = [`mimi://b.example/u/bob`].
const SUCCESS_BOB: &[u8] = &[
    0x00, // responseCode = success(0)
    0x17, // uri<V>: 23 bytes
    0x16, // IdentifierUri: opaque uri<V>, 22 bytes
    b'm', b'i', b'm', b'i', b':', b'/', b'/', b'b', b'.', b'e', b'x', b'a', b'm', b'p', b'l', b'e',
    b'/', b'u', b'/', b'b', b'o', b'b', // "mimi://b.example/u/bob"
    0x00, // foundProfiles<V>: empty
    0x00, // id_response_extensions: empty
];

/// IdentifierResponse with `code` and no results.
fn no_results(code: u8) -> Vec<u8> {
    vec![
        code, // responseCode
        0x00, // uri<V>: empty
        0x00, // foundProfiles<V>: empty
        0x00, // id_response_extensions: empty
    ]
}

/// notFound(1).
const NOT_FOUND: u8 = 1;
/// forbidden(3).
const FORBIDDEN: u8 = 3;
/// unsupportedField(4).
const UNSUPPORTED_FIELD: u8 = 4;

struct Provider {
    _dir: TempDir,
    app: Router,
}

/// A provider for `domain`, with a client for each of `local_users`.
async fn provider(domain: &str, local_users: &[&str]) -> Provider {
    let dir = tempfile::tempdir().unwrap();
    let domain = Domain::try_from(domain.to_owned()).unwrap();
    let store = Store::open(&dir.path().join("mimid.sqlite"), &domain)
        .await
        .unwrap();
    for (n, user) in local_users.iter().enumerate() {
        // Creates the user's client; the store does not inspect the bytes.
        store
            .insert_key_package(&NewKeyPackage {
                client_id: &format!("{user}/client"),
                user_uri: user,
                reference: &[u8::try_from(n).unwrap(); 32],
                bytes: b"key package",
                last_resort: true,
                not_after: 4_000_000_000,
            })
            .await
            .unwrap();
    }
    let clock = Arc::new(FixedClock(1_700_000_000_000));
    let hub = Hub::open(store.clone(), domain.clone(), clock.clone())
        .await
        .unwrap();
    let follower = Follower::new(domain.clone(), store, clock);
    let base = BaseUrl::try_from(format!("https://mimi.{domain}")).unwrap();
    let app = router(directory(&base), Arc::new(hub), Arc::new(follower));
    Provider { _dir: dir, app }
}

async fn post(app: &Router, path: &str, from: Option<&str>, body: &[u8]) -> (StatusCode, Vec<u8>) {
    let mut request = Request::post(path);
    if let Some(from) = from {
        request = request.header(header::FROM, from);
    }
    let response = app
        .clone()
        .oneshot(request.body(Body::from(body.to_vec())).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let body = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
    (status, body.to_vec())
}

#[tokio::test]
async fn exact_handle_of_a_local_user_is_found() {
    let b = provider("b.example", &[BOB]).await;
    assert_eq!(
        post(&b.app, PATH, FROM_A, HANDLE_BOB).await,
        (StatusCode::OK, SUCCESS_BOB.to_vec())
    );
}

#[tokio::test]
async fn handle_without_a_known_local_user_is_not_found() {
    // bob has no client here (decision mimid-1wgh.7.36's notion of known).
    let b = provider("b.example", &["mimi://b.example/u/carol"]).await;
    assert_eq!(
        post(&b.app, PATH, FROM_A, HANDLE_BOB).await,
        (StatusCode::OK, no_results(NOT_FOUND))
    );
    // Two different handles cannot both match one user (AND semantics).
    let b = provider("b.example", &[BOB, "mimi://b.example/u/carol"]).await;
    assert_eq!(
        post(&b.app, PATH, FROM_A, HANDLE_BOB_AND_CAROL).await,
        (StatusCode::OK, no_results(NOT_FOUND))
    );
    // A user URI under another provider is never a local user.
    let a = provider("a.example", &[BOB]).await;
    assert_eq!(
        post(
            &a.app,
            "/v1/identifierQuery/a.example",
            Some("mimi@b.example"),
            HANDLE_BOB
        )
        .await,
        (StatusCode::OK, no_results(NOT_FOUND))
    );
}

/// IdentifierRequest: one `handle` element for the provider URI
/// `mimi://b.example`.
const HANDLE_PROVIDER: &[u8] = &[
    0x12, // query_elements<V>: 18 bytes
    0x01, // searchType = handle(1); no select arm
    0x10, // searchValue<V>: 16 bytes
    b'm', b'i', b'm', b'i', b':', b'/', b'/', b'b', b'.', b'e', b'x', b'a', b'm', b'p', b'l', b'e',
    // "mimi://b.example"
    0x00, // id_request_extensions: empty
];

/// IdentifierRequest: one `handle` element for the room URI
/// `mimi://b.example/r/bob`.
const HANDLE_ROOM: &[u8] = &[
    0x18, // query_elements<V>: 24 bytes
    0x01, // searchType = handle(1); no select arm
    0x16, // searchValue<V>: 22 bytes
    b'm', b'i', b'm', b'i', b':', b'/', b'/', b'b', b'.', b'e', b'x', b'a', b'm', b'p', b'l', b'e',
    b'/', b'r', b'/', b'b', b'o', b'b', // "mimi://b.example/r/bob"
    0x00, // id_request_extensions: empty
];

#[tokio::test]
async fn handle_that_is_not_a_user_uri_is_not_found() {
    // protocol-07 §2.1; decision mimid-1wgh.6.76: only mimi://<domain>/u/<id>
    // names a user. A client row under another URI type (one written before
    // that decision) does not make it a user; §5.8 notFound.
    let b = provider("b.example", &["mimi://b.example", "mimi://b.example/r/bob"]).await;
    for body in [HANDLE_PROVIDER, HANDLE_ROOM] {
        assert_eq!(
            post(&b.app, PATH, FROM_A, body).await,
            (StatusCode::OK, no_results(NOT_FOUND))
        );
    }
}

#[tokio::test]
async fn other_search_types_are_unsupported_and_empty_is_forbidden() {
    let b = provider("b.example", &[BOB]).await;
    assert_eq!(
        post(&b.app, PATH, FROM_A, NICK_BOB).await,
        (StatusCode::OK, no_results(UNSUPPORTED_FIELD))
    );
    // Haven's request carries a vcardField element next to its handle.
    assert_eq!(
        post(&b.app, PATH, FROM_A, HAVEN_REQUEST).await,
        (StatusCode::OK, no_results(UNSUPPORTED_FIELD))
    );
    assert_eq!(
        post(&b.app, PATH, FROM_A, EMPTY).await,
        (StatusCode::OK, no_results(FORBIDDEN))
    );
}

#[tokio::test]
async fn malformed_requests_are_bad_requests() {
    let b = provider("b.example", &[BOB]).await;
    // No From header, or a malformed one.
    assert_eq!(
        post(&b.app, PATH, None, HANDLE_BOB).await.0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        post(&b.app, PATH, Some("a.example"), HANDLE_BOB).await.0,
        StatusCode::BAD_REQUEST
    );
    // The path names another provider (decision mimid-1wgh.7.40).
    assert_eq!(
        post(&b.app, "/v1/identifierQuery/c.example", FROM_A, HANDLE_BOB)
            .await
            .0,
        StatusCode::BAD_REQUEST
    );
    // Undecodable: truncated, and with a trailing byte.
    assert_eq!(
        post(&b.app, PATH, FROM_A, &HANDLE_BOB[..10]).await.0,
        StatusCode::BAD_REQUEST
    );
    let mut trailing = HANDLE_BOB.to_vec();
    trailing.push(0x00);
    assert_eq!(
        post(&b.app, PATH, FROM_A, &trailing).await.0,
        StatusCode::BAD_REQUEST
    );
}
