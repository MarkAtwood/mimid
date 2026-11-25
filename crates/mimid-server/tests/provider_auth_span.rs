//! Every provider-authentication outcome opens a span (bead
//! mimid-1wgh.46.20.1.1): a refusal most of all, because on an interop day
//! the refusals are the interesting events, and
//! [`provider_auth::check`](mimid_server::provider_auth::check) is layered
//! outside the router's `http_request` span, so a refused request returns
//! before any other span is entered.
//!
//! Oracle: the span must be at INFO, since a server started with no
//! `RUST_LOG` filters at `info` and would otherwise export no trace of the
//! refusal at all, and it must name the peer, the endpoint, the outcome and
//! — for a refusal — the reason, so a trace says which peer was turned away
//! and why.
//!
//! The DEBUG events of `check` are unchanged and still carry the same
//! facts: a correct refusal stays out of a production log at `info`
//! (bead mimid-bfzm, tests/refusal_logging.rs). What this adds is the
//! span, which goes to a collector rather than to the log.
//!
//! Offline: the middleware is called directly, with no listener.

#![forbid(unsafe_code)]

#[allow(dead_code, reason = "each test binary uses part of the helpers")]
#[path = "common/logging.rs"]
mod logging;

use std::sync::Arc;

use axum::body::Body;
use axum::http::{HeaderMap, HeaderValue, Method, Request, StatusCode, Uri, header};
use axum::routing::post;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use logging::SpanCapture;
use mimid_server::config::BaseUrl;
use mimid_server::httpsig::SigningKey;
use mimid_server::hub::SystemClock;
use mimid_server::provider_auth::{self, ProviderAuth, ProviderAuthConfig, RequestSigner};
use tower::ServiceExt;

/// b.example, which checks; a.example, which sends.
const BASE: &str = "http://b.example";
const PATH: &str = "/v1/identifierQuery/a.example";
const BODY: &[u8] = b"an identifierQuery body";

/// a.example's key, seed 0x0a * 32, selector "a1".
fn a_signer() -> RequestSigner {
    RequestSigner::new(SigningKey::from_seed(&[0x0a; 32]), "a1".to_owned())
}

/// b.example's configuration trusting a.example's key, with DNS and DANE
/// off so the only mechanism is the trust list and the test needs no
/// resolver.
fn trusting_a() -> String {
    format!(
        "dns_keys = false\ndane = false\n[peers.\"a.example\"]\nkeys = {{ \"a1\" = \"{}\" }}\n",
        STANDARD.encode(a_signer().public_key().to_bytes())
    )
}

/// Sends one POST to [`PATH`] through `check` with `auth`'s configuration,
/// signed by a.example if `signed`, and answers with the status.
async fn send(auth: &str, signed: bool) -> StatusCode {
    let base = BaseUrl::try_from(BASE.to_owned()).unwrap();
    let config: ProviderAuthConfig = toml::from_str(auth).unwrap();
    // A signature's `created` is real time, so the check reads the system
    // clock, as the server's does.
    let check = Arc::new(ProviderAuth::new(&config, &base, Arc::new(SystemClock)));
    let app = axum::Router::new()
        .route(PATH, post(|| async { StatusCode::OK }))
        .layer(axum::middleware::from_fn_with_state(
            check,
            provider_auth::check,
        ));

    let mut headers = HeaderMap::new();
    headers.insert(header::FROM, HeaderValue::from_static("mimi@a.example"));
    if signed {
        let uri: Uri = format!("{BASE}{PATH}").parse().unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        a_signer()
            .sign(
                &Method::POST,
                &uri,
                &mut headers,
                BODY,
                i64::try_from(now).unwrap(),
            )
            .unwrap();
    }
    let mut request = Request::post(PATH).body(Body::from(BODY)).unwrap();
    *request.headers_mut() = headers;
    app.oneshot(request).await.unwrap().status()
}

/// A request whose source does not authenticate is refused with `403` and
/// leaves an INFO span naming the peer, the endpoint and the reason.
#[tokio::test]
async fn a_refusal_opens_a_span_at_info() {
    let spans = SpanCapture::start("info");
    assert_eq!(send(&trusting_a(), false).await, StatusCode::FORBIDDEN);

    let span = spans.only("provider_auth");
    assert_eq!(span.level, tracing::Level::INFO, "{span:?}");
    assert_eq!(span.field("peer"), Some("a.example"), "{span:?}");
    assert_eq!(span.field("endpoint"), Some("identifierQuery"), "{span:?}");
    assert_eq!(span.field("outcome"), Some("refused"), "{span:?}");
    assert_eq!(span.field("mechanism"), None, "{span:?}");
    // The reason is the one the DEBUG event carries: a trace of a refused
    // interop exchange has to say why, not only that.
    assert!(
        span.field("reason").is_some_and(|why| !why.is_empty()),
        "a refusal span must say why: {span:?}"
    );
}

/// An authenticated request opens the same span, with the mechanism that
/// authenticated it and no reason.
#[tokio::test]
async fn an_authenticated_request_opens_the_span_with_its_mechanism() {
    let spans = SpanCapture::start("info");
    assert_eq!(send(&trusting_a(), true).await, StatusCode::OK);

    let span = spans.only("provider_auth");
    assert_eq!(span.level, tracing::Level::INFO, "{span:?}");
    assert_eq!(span.field("peer"), Some("a.example"), "{span:?}");
    assert_eq!(span.field("outcome"), Some("authenticated"), "{span:?}");
    assert_eq!(span.field("mechanism"), Some("trust_list"), "{span:?}");
    assert_eq!(span.field("reason"), None, "{span:?}");
}

/// A failure in observe mode is let through, and its span says so, so a
/// rollout can be read off the traces and not only off the one INFO event
/// per peer per start.
#[tokio::test]
async fn an_observed_failure_opens_the_span_too() {
    let spans = SpanCapture::start("info");
    let auth = "dns_keys = false\ndane = false\n[peers.\"a.example\"]\nmode = \"observe\"\n";
    assert_eq!(send(auth, false).await, StatusCode::OK);

    let span = spans.only("provider_auth");
    assert_eq!(span.field("outcome"), Some("observed"), "{span:?}");
    assert!(span.field("reason").is_some(), "{span:?}");
}

/// A body past `MAX_BODY_LEN` is refused by this layer before any
/// mechanism runs, and that refusal is in the span too: it is a peer
/// sending something this server will not read, which is exactly the kind
/// of event an interop day needs to see.
#[tokio::test]
async fn an_oversized_body_is_refused_inside_the_span() {
    let spans = SpanCapture::start("info");
    let base = BaseUrl::try_from(BASE.to_owned()).unwrap();
    let config: ProviderAuthConfig = toml::from_str(&trusting_a()).unwrap();
    let check = Arc::new(ProviderAuth::new(&config, &base, Arc::new(SystemClock)));
    let app = axum::Router::new()
        .route(PATH, post(|| async { StatusCode::OK }))
        .layer(axum::middleware::from_fn_with_state(
            check,
            provider_auth::check,
        ));

    let too_much = vec![0u8; mimid_server::http::MAX_BODY_LEN + 1];
    let mut request = Request::post(PATH).body(Body::from(too_much)).unwrap();
    request
        .headers_mut()
        .insert(header::FROM, HeaderValue::from_static("mimi@a.example"));
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);

    let span = spans.only("provider_auth");
    assert_eq!(span.field("outcome"), Some("refused"), "{span:?}");
    assert_eq!(
        span.field("reason"),
        Some("request body too large"),
        "{span:?}"
    );
}

/// A request that `check` passes through untouched opens no span: a
/// non-`/v1/` path, and a `/v1/` request with no usable `From` header,
/// which its handler refuses with `400` inside its own
/// `protocol_request` span.
#[tokio::test]
async fn a_request_check_does_not_judge_opens_no_span() {
    let spans = SpanCapture::start("info");
    let base = BaseUrl::try_from(BASE.to_owned()).unwrap();
    let config: ProviderAuthConfig = toml::from_str(&trusting_a()).unwrap();
    let check = Arc::new(ProviderAuth::new(&config, &base, Arc::new(SystemClock)));
    let app = axum::Router::new()
        .route(PATH, post(|| async { StatusCode::OK }))
        .route("/.well-known/mimi", axum::routing::get(|| async { "{}" }))
        .layer(axum::middleware::from_fn_with_state(
            check,
            provider_auth::check,
        ));

    for request in [
        Request::get("/.well-known/mimi")
            .body(Body::empty())
            .unwrap(),
        Request::post(PATH).body(Body::from(BODY)).unwrap(),
    ] {
        assert_eq!(
            app.clone().oneshot(request).await.unwrap().status(),
            StatusCode::OK
        );
    }
    assert!(
        spans.named("provider_auth").is_empty(),
        "{:?}",
        spans.named("provider_auth")
    );
}
