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

// ---- Unicode stress (bead mimid-1wgh.54, third slice) ----
//
// §5.8 says a `handle` "matches exactly" and does not say whether that is
// byte equality or URI equivalence (RFC 3986 §6.2.2). mimid compares bytes:
// these tests pin that down, so a change to it is a decision, not an
// accident. The Big List of Naughty Strings is the one vendored for
// mimi-content (PROVENANCE there).

const BLNS: &str = include_str!("../../mimi-content/tests/fixtures/blns/blns.base64.txt");

fn naughty() -> Vec<Vec<u8>> {
    BLNS.lines()
        .filter(|line| !line.trim().is_empty() && !line.starts_with('#'))
        .map(|line| base64(line.trim()))
        .collect()
}

/// Standard base64 with padding (RFC 4648 §4), enough for the fixture.
fn base64(text: &str) -> Vec<u8> {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let (mut bits, mut count, mut out) = (0u32, 0, Vec::new());
    for c in text.bytes().take_while(|&c| c != b'=') {
        let value = ALPHABET.iter().position(|&a| a == c).expect("base64");
        bits = (bits << 6) | u32::try_from(value).unwrap();
        count += 6;
        if count >= 8 {
            count -= 8;
            out.push(u8::try_from((bits >> count) & 0xff).unwrap());
        }
    }
    out
}

/// RFC 9420 §2.1.2 variable-length vector of `bytes`.
fn vl(bytes: &[u8]) -> Vec<u8> {
    let len = bytes.len();
    let mut out = if len < 0x40 {
        vec![u8::try_from(len).unwrap()]
    } else {
        (u16::try_from(len).unwrap() | 0x4000)
            .to_be_bytes()
            .to_vec()
    };
    out.extend_from_slice(bytes);
    out
}

/// IdentifierRequest: one element of `search_type` (with no select arm)
/// for `value`, and no extensions.
fn query(search_type: u8, value: &[u8]) -> Vec<u8> {
    let mut element = vec![search_type];
    element.extend(vl(value));
    let mut request = vl(&element);
    request.push(0x00); // id_request_extensions: empty
    request
}

/// IdentifierResponse `success` with the one URI `uri`.
fn success(uri: &str) -> Vec<u8> {
    let mut out = vec![0x00]; // responseCode = success(0)
    out.extend(vl(&vl(uri.as_bytes())));
    out.extend([0x00, 0x00]); // foundProfiles, id_response_extensions
    out
}

/// handle(1).
const HANDLE: u8 = 1;

/// `é`, a user id outside ASCII, percent-encoded from NFC (U+00E9).
const EMILE_NFC: &str = "mimi://b.example/u/%C3%A9mile";

/// A user id with an `i`, for the Turkish case mappings.
const IRIS: &str = "mimi://b.example/u/iris";

#[tokio::test]
async fn no_naughty_string_is_a_handle_or_breaks_the_query() {
    let b = provider("b.example", &[BOB, EMILE_NFC]).await;
    for entry in naughty() {
        assert_eq!(
            post(&b.app, PATH, FROM_A, &query(HANDLE, &entry)).await,
            (StatusCode::OK, no_results(NOT_FOUND)),
            "{entry:02x?}"
        );
        // The same text inside a user URI of this provider.
        let mut uri = b"mimi://b.example/u/".to_vec();
        uri.extend(&entry);
        assert_eq!(
            post(&b.app, PATH, FROM_A, &query(HANDLE, &uri)).await,
            (StatusCode::OK, no_results(NOT_FOUND)),
            "{entry:02x?}"
        );
    }
}

#[tokio::test]
async fn a_handle_matches_only_the_same_bytes() {
    let b = provider("b.example", &[BOB, EMILE_NFC, IRIS]).await;
    assert_eq!(
        post(&b.app, PATH, FROM_A, &query(HANDLE, IRIS.as_bytes())).await,
        (StatusCode::OK, success(IRIS))
    );
    assert_eq!(
        post(&b.app, PATH, FROM_A, &query(HANDLE, EMILE_NFC.as_bytes())).await,
        (StatusCode::OK, success(EMILE_NFC))
    );
    for other in [
        // The same URI under RFC 3986 §6.2.2.1: hex digits in lowercase.
        "mimi://b.example/u/%c3%a9mile",
        // The same URI under §6.2.2.1: scheme and host in uppercase.
        "MIMI://b.example/u/%C3%A9mile",
        "mimi://B.EXAMPLE/u/%C3%A9mile",
        // The same text in NFD: e and U+0301 COMBINING ACUTE ACCENT.
        "mimi://b.example/u/e%CC%81mile",
        // Not percent-encoded, so not a URI.
        "mimi://b.example/u/\u{e9}mile",
        // Case in the path is significant (RFC 3986 §6.2.2.1).
        "mimi://b.example/u/%C3%89MILE",
        "mimi://b.example/u/BOB",
        // iris with a Turkish dotted capital I (U+0130), a dotless small i
        // (U+0131), and a plain capital I: what a Turkish-locale case
        // mapping of "iris" or "IRIS" gives.
        "mimi://b.example/u/%C4%B0ris",
        "mimi://b.example/u/%C4%B1ris",
        "mimi://b.example/u/Iris",
    ] {
        assert_eq!(
            post(&b.app, PATH, FROM_A, &query(HANDLE, other.as_bytes())).await,
            (StatusCode::OK, no_results(NOT_FOUND)),
            "{other}"
        );
    }
}
