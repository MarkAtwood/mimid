//! Log volume of refused requests (bead mimid-bfzm): a flood of requests
//! that the server correctly refuses, through the HTTP router, produces
//! DEBUG events only, so a production log at `RUST_LOG=info` stays quiet
//! however many arrive.

#[allow(dead_code, reason = "each test binary uses part of the helpers")]
mod common;
#[allow(dead_code, reason = "each test binary uses part of the helpers")]
#[path = "common/logging.rs"]
mod logging;
#[allow(dead_code, reason = "each test binary uses part of the helpers")]
#[path = "common/update.rs"]
mod update;

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use common::*;
use logging::JsonCapture;
use mimid_server::config::BaseUrl;
use mimid_server::directory::directory;
use mimid_server::follower::Follower;
use mimid_server::http::router;
use tower::ServiceExt;
use update::{mls_rs_room, prepare_commit};

/// How many times each refused request is sent.
const ROUNDS: usize = 5;

#[tokio::test]
async fn refused_requests_log_only_at_debug() {
    let dir = tempfile::tempdir().unwrap();
    let (store, hub) = open_hub(&dir.path().join("mimid.sqlite")).await;
    let mut room = mls_rs_room(&hub, ROOM_ID, b"group-refusals").await;
    // bob's Commit, sent with a From domain that is not bob's: MLS-valid
    // but refused with notAllowed (decision mimid-1wgh.6.9).
    let mismatched = prepare_commit(&mut room.bob).request;
    // A follower with no configured peers refuses every /notify and
    // consent entry as not from a peer (decisions mimid-1wgh.7.4,
    // mimid-1wgh.7.41).
    let follower = Follower::new(domain(), store, Arc::new(FixedClock(0)));
    let base = BaseUrl::try_from("https://a.example".to_owned()).unwrap();
    let app = router(directory(&base), Arc::new(hub), Arc::new(follower));
    let encoded = ROOM_ID_ENCODED;
    let unknown = "mimi%3A%2F%2Fa.example%2Fr%2Fnone";
    let requests: [(String, Option<&str>, Vec<u8>, StatusCode); 10] = [
        (
            format!("/v1/update/{encoded}"),
            Some("a.example"),
            mismatched,
            StatusCode::OK,
        ),
        (
            format!("/v1/update/{encoded}"),
            Some("b.example"),
            vec![0xff],
            StatusCode::BAD_REQUEST,
        ),
        (
            format!("/v1/update/{unknown}"),
            Some("b.example"),
            vec![0xff],
            StatusCode::NOT_FOUND,
        ),
        (
            format!("/v1/submitMessage/{encoded}"),
            None,
            vec![0xff],
            StatusCode::BAD_REQUEST,
        ),
        (
            format!("/v1/groupInfo/{encoded}"),
            Some("b.example"),
            vec![0xff],
            StatusCode::BAD_REQUEST,
        ),
        (
            "/v1/keyMaterial/mimi%3A%2F%2Fa.example%2Fu%2Falice".to_owned(),
            Some("b.example"),
            vec![0xff],
            StatusCode::BAD_REQUEST,
        ),
        (
            format!("/v1/notify/{encoded}"),
            Some("b.example"),
            vec![0xff],
            StatusCode::FORBIDDEN,
        ),
        (
            "/v1/requestConsent/a.example".to_owned(),
            Some("b.example"),
            vec![0xff],
            StatusCode::FORBIDDEN,
        ),
        (
            "/v1/identifierQuery/b.example".to_owned(),
            Some("b.example"),
            vec![0xff],
            StatusCode::BAD_REQUEST,
        ),
        (
            format!("/v1/reportAbuse/{encoded}"),
            Some("b.example"),
            vec![0xff],
            StatusCode::BAD_REQUEST,
        ),
    ];

    let capture = JsonCapture::start();
    for _ in 0..ROUNDS {
        for (path, from, body, expected) in &requests {
            let mut request = Request::post(path.as_str());
            if let Some(from) = from {
                request = request.header(header::FROM, format!("mimi@{from}"));
            }
            let response = app
                .clone()
                .oneshot(request.body(Body::from(body.clone())).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), *expected, "{path} from {from:?}");
        }
    }

    let lines = capture.lines();
    // Each request logs at least its completion; the refusals are visible
    // at DEBUG, so the capture is not vacuous.
    assert!(lines.len() >= ROUNDS * requests.len(), "{lines:#?}");
    let refused = lines
        .iter()
        .filter(|line| {
            line["message"]
                .as_str()
                .is_some_and(|message| message.contains("refused"))
        })
        .count();
    assert!(refused >= ROUNDS * requests.len(), "{lines:#?}");
    assert_eq!(capture.above_debug(), Vec::<serde_json::Value>::new());
}
