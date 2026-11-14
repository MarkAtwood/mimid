//! Peer clock checks (crate::peer_clock), end to end: a fake peer whose
//! `Date` header is off by a minute, called through a real `PeerClient`,
//! and a request with an old `Date` through the request middleware.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use axum::Router;
use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode, header};
use axum::response::IntoResponse;
use axum::routing::{any, get};
use mimid_server::config::{BaseUrl, Domain};
use mimid_server::peer::PeerClient;
use mimid_server::peer_clock::{self, PeerClocks};
use tower::ServiceExt;

const TOLERANCE: Duration = Duration::from_secs(5);

fn domain(name: &str) -> Domain {
    Domain::try_from(name.to_owned()).unwrap()
}

/// A peer answering every request `202` with `Date` set `offset` seconds
/// from now (negative: behind), recording the `Date` each request carried.
async fn start(offset: i64) -> (String, Arc<Mutex<Vec<Option<String>>>>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let directory =
        format!("{{\"requestConsent\": \"{base}/v1/requestConsent/{{targetDomain}}\"}}");
    let dates = Arc::new(Mutex::new(Vec::new()));
    let seen = Arc::clone(&dates);
    let app = Router::new()
        .route(
            "/.well-known/mimi-protocol-directory",
            get(move || async move { directory }),
        )
        .fallback(any(move |headers: HeaderMap| {
            let seen = Arc::clone(&seen);
            async move {
                seen.lock().unwrap().push(
                    headers
                        .get(header::DATE)
                        .map(|v| v.to_str().unwrap().to_owned()),
                );
                let now = SystemTime::now();
                let date = if offset >= 0 {
                    now + Duration::from_secs(offset.unsigned_abs())
                } else {
                    now - Duration::from_secs(offset.unsigned_abs())
                };
                (
                    StatusCode::ACCEPTED,
                    [(header::DATE, httpdate::fmt_http_date(date))],
                )
                    .into_response()
            }
        }));
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (base, dates)
}

async fn call(offset: i64) -> (Arc<PeerClocks>, Arc<Mutex<Vec<Option<String>>>>) {
    let (base, dates) = start(offset).await;
    let b = domain("b.example");
    let clocks = PeerClocks::new([b.clone()], TOLERANCE);
    let client = PeerClient::new(
        &domain("a.example"),
        BTreeMap::from([(b.clone(), BaseUrl::try_from(base).unwrap())]),
    )
    .unwrap()
    .with_clocks(Arc::clone(&clocks));
    client.request_consent(&b, b"entry".to_vec()).await.unwrap();
    (clocks, dates)
}

#[tokio::test]
async fn a_peer_a_minute_behind_is_flagged() {
    let (clocks, _) = call(-60).await;
    assert!(clocks.is_skewed(&domain("b.example")));
}

#[tokio::test]
async fn a_peer_a_minute_ahead_is_flagged() {
    let (clocks, _) = call(60).await;
    assert!(clocks.is_skewed(&domain("b.example")));
}

#[tokio::test]
async fn a_peer_in_step_is_not_flagged_and_sees_our_date() {
    let (clocks, dates) = call(0).await;
    assert!(!clocks.is_skewed(&domain("b.example")));
    // Every request mimid sent carried a Date of its own.
    let dates = dates.lock().unwrap();
    assert!(!dates.is_empty());
    assert!(dates.iter().all(|d| {
        d.as_deref()
            .is_some_and(|d| httpdate::parse_http_date(d).is_ok())
    }));
}

#[tokio::test]
async fn the_middleware_checks_a_configured_peers_request_date() {
    let b = domain("b.example");
    let clocks = PeerClocks::new([b.clone()], TOLERANCE);
    let app = Router::new()
        .route("/", any(|| async { StatusCode::OK }))
        .layer(axum::middleware::from_fn_with_state(
            Arc::clone(&clocks),
            peer_clock::check_request,
        ));
    let old = httpdate::fmt_http_date(SystemTime::now() - Duration::from_secs(60));
    let send = |from: &str, date: &str| {
        Request::get("/")
            .header(header::FROM, from)
            .header(header::DATE, date)
            .body(Body::empty())
            .unwrap()
    };
    // Someone not configured: ignored.
    let response = app
        .clone()
        .oneshot(send("mimi@c.example", &old))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(!clocks.is_skewed(&domain("c.example")));
    // The configured peer, a minute behind: flagged, and still served.
    let response = app
        .clone()
        .oneshot(send("mimi@b.example", &old))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(clocks.is_skewed(&b));
    // Back in step: cleared.
    let now = httpdate::fmt_http_date(SystemTime::now());
    app.oneshot(send("mimi@b.example", &now)).await.unwrap();
    assert!(!clocks.is_skewed(&b));
}
