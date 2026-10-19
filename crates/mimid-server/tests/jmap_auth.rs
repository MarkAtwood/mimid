//! JMAP bearer-token authentication (mimid-1wgh.11.1): the [`Account`]
//! extractor behind a minimal test route, the `accountId` check, `Debug`
//! redaction and a TRACE-level log canary.
//!
//! Oracles: the expected `401` response is written out from RFC 7807 and
//! RFC 9110; malformed tokens are derived by hand from valid ones so that a
//! lenient base64 decoder would accept them.

#[allow(dead_code, reason = "each test binary uses part of the helpers")]
mod common;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::extract::Path;
use axum::http::{HeaderValue, Request, StatusCode, header};
use axum::routing::get;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use common::{assert_secret_absent, capture_logs, domain};
use mimid_server::jmap::auth::{Account, AccountNotFound, Authenticator};
use mimid_server::store::{BearerToken, Store};
use tower::ServiceExt;

const ALICE: &str = "mimi://a.example/u/alice";
const BOB: &str = "mimi://a.example/u/bob";

/// base64url of the bytes 0..32: well formed, never issued.
const NEVER_ISSUED: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";

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
    let store = Store::open(&dir.path().join("mimid.sqlite"), &domain())
        .await
        .unwrap();
    let alice_id = store.create_account(&domain(), ALICE, 1).await.unwrap();
    let alice_token = store.issue_token(&alice_id, 2).await.unwrap();
    let bob_id = store.create_account(&domain(), BOB, 3).await.unwrap();
    let bob_token = store.issue_token(&bob_id, 4).await.unwrap();
    let app = Router::new()
        .route(
            "/whoami",
            get(|account: Account| async move {
                format!("{} {}", account.account_id(), account.user().as_str())
            }),
        )
        .route(
            "/check/{account_id}",
            get(
                |account: Account, Path(account_id): Path<String>| async move {
                    match account.check_account_id(&account_id) {
                        Ok(()) => "ok",
                        Err(AccountNotFound) => AccountNotFound::TYPE,
                    }
                },
            ),
        )
        .with_state(Authenticator::new(store.clone(), domain()));
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

/// Sends GET `uri` with these `Authorization` header values.
async fn get_with(
    app: &Router,
    uri: &str,
    authorization: &[HeaderValue],
) -> (StatusCode, axum::http::HeaderMap, String) {
    let mut request = Request::get(uri).body(Body::empty()).unwrap();
    for value in authorization {
        request
            .headers_mut()
            .append(header::AUTHORIZATION, value.clone());
    }
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    (status, headers, String::from_utf8(body.to_vec()).unwrap())
}

async fn whoami(app: &Router, authorization: &str) -> (StatusCode, axum::http::HeaderMap, String) {
    get_with(
        app,
        "/whoami",
        &[HeaderValue::from_str(authorization).unwrap()],
    )
    .await
}

fn bearer(token: &BearerToken) -> String {
    format!("Bearer {}", token.expose_secret())
}

/// RFC 7807 problem details with status 401 and an RFC 9110 §11.6.1
/// challenge.
fn assert_unauthorized(
    (status, headers, body): (StatusCode, axum::http::HeaderMap, String),
    case: &str,
) {
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{case}");
    assert_eq!(
        headers.get(header::CONTENT_TYPE).unwrap(),
        "application/problem+json",
        "{case}"
    );
    assert_eq!(
        headers.get(header::WWW_AUTHENTICATE).unwrap(),
        "Bearer",
        "{case}"
    );
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&body).unwrap(),
        serde_json::json!({"type": "about:blank", "title": "Unauthorized", "status": 401}),
        "{case}"
    );
}

#[tokio::test]
async fn valid_token_authenticates_its_own_account() {
    let f = fixture().await;
    let (status, _, body) = whoami(&f.app, &bearer(&f.alice_token)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, format!("{} {ALICE}", f.alice_id));
    let (status, _, body) = whoami(&f.app, &bearer(&f.bob_token)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, format!("{} {BOB}", f.bob_id));
    // RFC 9110 §11.1: the scheme is case-insensitive.
    let lower = format!("bearer {}", f.alice_token.expose_secret());
    let (status, _, body) = whoami(&f.app, &lower).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, format!("{} {ALICE}", f.alice_id));
    f.store.close().await;
}

#[tokio::test]
async fn missing_header_is_rejected() {
    let f = fixture().await;
    assert_unauthorized(get_with(&f.app, "/whoami", &[]).await, "no header");
    f.store.close().await;
}

#[tokio::test]
async fn wrong_token_is_rejected() {
    let f = fixture().await;
    assert_unauthorized(
        whoami(&f.app, &format!("Bearer {NEVER_ISSUED}")).await,
        "never issued",
    );
    let other_store_dir = tempfile::tempdir().unwrap();
    let other = Store::open(&other_store_dir.path().join("mimid.sqlite"), &domain())
        .await
        .unwrap();
    let id = other.create_account(&domain(), ALICE, 1).await.unwrap();
    let foreign = other.issue_token(&id, 2).await.unwrap();
    assert_unauthorized(
        whoami(&f.app, &bearer(&foreign)).await,
        "issued by another store",
    );
    other.close().await;
    f.store.close().await;
}

#[tokio::test]
async fn revoked_token_is_rejected() {
    let f = fixture().await;
    assert!(f.store.revoke_token(&f.alice_token, 10).await.unwrap());
    assert_unauthorized(whoami(&f.app, &bearer(&f.alice_token)).await, "revoked");
    let (status, _, _) = whoami(&f.app, &bearer(&f.bob_token)).await;
    assert_eq!(status, StatusCode::OK, "bob's token is unaffected");
    f.store.close().await;
}

/// The base64url alphabet (RFC 4648 §5), in value order.
const BASE64URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn base64url_value(c: u8) -> u8 {
    BASE64URL.iter().position(|&a| a == c).unwrap() as u8
}

/// Decodes base64url, ignoring trailing bits, as a lenient decoder would.
fn lenient_decode(text: &str) -> Vec<u8> {
    let mut bits = 0u32;
    let mut count = 0;
    let mut out = Vec::new();
    for c in text.bytes() {
        bits = (bits << 6) | u32::from(base64url_value(c));
        count += 6;
        if count >= 8 {
            count -= 8;
            out.push((bits >> count) as u8);
            bits &= (1 << count) - 1;
        }
    }
    out
}

#[tokio::test]
async fn malformed_headers_are_rejected() {
    let f = fixture().await;
    let token = f.alice_token.expose_secret();
    // 43 characters carry 258 bits; a lenient decoder ignores the last two.
    let mut trailing = token.clone().into_bytes();
    trailing[42] = BASE64URL[usize::from(base64url_value(trailing[42]) | 1)];
    let trailing = String::from_utf8(trailing).unwrap();
    assert_eq!(
        lenient_decode(&trailing),
        URL_SAFE_NO_PAD.decode(&token).unwrap(),
        "the case differs only in trailing bits"
    );

    let cases = [
        ("no scheme", token.clone()),
        ("Basic scheme", format!("Basic {token}")),
        ("scheme only", "Bearer".to_owned()),
        ("empty token", "Bearer ".to_owned()),
        ("two spaces", format!("Bearer  {token}")),
        ("padded", format!("Bearer {token}=")),
        ("too short", format!("Bearer {}", &token[..42])),
        ("too long", format!("Bearer {token}A")),
        ("bad character", format!("Bearer {}!", &token[..42])),
        ("non-zero trailing bits", format!("Bearer {trailing}")),
    ];
    for (case, value) in cases {
        assert_unauthorized(whoami(&f.app, &value).await, case);
    }

    let header = HeaderValue::from_str(&bearer(&f.alice_token)).unwrap();
    assert_unauthorized(
        get_with(&f.app, "/whoami", &[header.clone(), header]).await,
        "two Authorization headers",
    );
    let mut non_ascii = bearer(&f.alice_token).into_bytes();
    non_ascii.push(0xff);
    assert_unauthorized(
        get_with(
            &f.app,
            "/whoami",
            &[HeaderValue::from_bytes(&non_ascii).unwrap()],
        )
        .await,
        "non-ASCII header",
    );
    f.store.close().await;
}

/// A token in the standard base64 alphabet (`+`, `/`) is refused even when
/// it spells the same bytes as a valid base64url token.
#[tokio::test]
async fn standard_alphabet_is_rejected() {
    let f = fixture().await;
    // About 75% of random tokens contain `-` or `_`; issue until one does.
    let mut token = None;
    for now in 100..200 {
        let candidate = f.store.issue_token(&f.alice_id, now).await.unwrap();
        if candidate.expose_secret().contains(['-', '_']) {
            token = Some(candidate);
            break;
        }
    }
    let token = token.expect("a token containing - or _");
    let (status, _, _) = whoami(&f.app, &bearer(&token)).await;
    assert_eq!(status, StatusCode::OK, "control");
    let standard = token.expose_secret().replace('-', "+").replace('_', "/");
    assert_unauthorized(
        whoami(&f.app, &format!("Bearer {standard}")).await,
        "standard alphabet",
    );
    f.store.close().await;
}

#[tokio::test]
async fn account_id_check_rejects_other_accounts() {
    let f = fixture().await;
    let alice = HeaderValue::from_str(&bearer(&f.alice_token)).unwrap();
    let (status, _, body) = get_with(
        &f.app,
        &format!("/check/{}", f.alice_id),
        std::slice::from_ref(&alice),
    )
    .await;
    assert_eq!((status, body.as_str()), (StatusCode::OK, "ok"));
    let (status, _, body) = get_with(&f.app, &format!("/check/{}", f.bob_id), &[alice]).await;
    assert_eq!((status, body.as_str()), (StatusCode::OK, "accountNotFound"));
    assert_eq!(AccountNotFound::TYPE, "accountNotFound");
    f.store.close().await;
}

#[tokio::test]
async fn token_debug_is_redacted() {
    let f = fixture().await;
    let raw = URL_SAFE_NO_PAD
        .decode(f.alice_token.expose_secret())
        .unwrap();
    let authenticator = Authenticator::new(f.store.clone(), domain());
    for text in [
        format!("{:?}", f.alice_token),
        format!("{:#?}", f.alice_token),
        format!("{authenticator:?}"),
    ] {
        assert_secret_absent(&text, &raw, "token");
    }
    assert_eq!(format!("{:?}", f.alice_token), "BearerToken(<redacted>)");
    f.store.close().await;
}

/// Every `tracing` event at TRACE, over issuing, authenticating (accepted
/// and refused) and revoking, is free of the token.
#[tokio::test]
async fn trace_logs_never_contain_tokens() {
    let logs = capture_logs();
    let f = fixture().await;
    let (status, _, _) = whoami(&f.app, &bearer(&f.alice_token)).await;
    assert_eq!(status, StatusCode::OK);
    let malformed = format!("Bearer {}=", f.alice_token.expose_secret());
    assert_unauthorized(whoami(&f.app, &malformed).await, "padded");
    assert!(f.store.revoke_token(&f.alice_token, 10).await.unwrap());
    assert_unauthorized(whoami(&f.app, &bearer(&f.alice_token)).await, "revoked");

    let text = logs.contents();
    assert!(
        text.contains("jmap request authenticated"),
        "capture works: {text}"
    );
    assert!(
        text.contains("jmap authentication refused"),
        "capture works: {text}"
    );
    for token in [&f.alice_token, &f.bob_token] {
        let raw = URL_SAFE_NO_PAD.decode(token.expose_secret()).unwrap();
        assert_secret_absent(&text, &raw, "token");
    }
    f.store.close().await;
}
