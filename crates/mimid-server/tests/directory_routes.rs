//! Every endpoint the served directory advertises is routed (protocol-06
//! §5.1; decision mimid-1wgh.5.75: an absent key means the endpoint is not
//! offered, so the directory must not list one that answers `404`).
//!
//! Oracle: the full HTTP router, given a fallback that answers
//! `418 I'm a teapot` for unmatched paths. Each advertised URL is posted to
//! with an empty body; a routed endpoint may refuse it (even with its own
//! `404` for an unknown room), but must not reach the fallback or answer
//! `405 Method Not Allowed`.

#![forbid(unsafe_code)]

#[allow(dead_code, reason = "each test binary uses part of the helpers")]
mod common;

use std::sync::Arc;

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode, header};
use common::FixedClock;
use mimi_protocol::Directory as ParsedDirectory;
use mimid_server::config::BaseUrl;
use mimid_server::directory::{DIRECTORY_PATH, Directory};
use mimid_server::follower::Follower;
use mimid_server::http::router;
use tower::ServiceExt;

const BASE: &str = "https://mimi.a.example";

#[tokio::test]
async fn every_advertised_endpoint_is_routed() {
    let dir = tempfile::tempdir().unwrap();
    let (store, hub) = common::open_hub(&dir.path().join("mimid.sqlite")).await;
    let follower = Follower::new(common::domain(), store, Arc::new(FixedClock(0)));
    let app = router(
        Directory::new(&BaseUrl::try_from(BASE.to_owned()).unwrap()),
        Arc::new(hub),
        Arc::new(follower),
    )
    .fallback(|| async { StatusCode::IM_A_TEAPOT });

    let response = app
        .clone()
        .oneshot(Request::get(DIRECTORY_PATH).body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
    // The served document is a valid protocol-06 §5.1 directory.
    serde_json::from_slice::<ParsedDirectory>(&body).unwrap();
    let document: serde_json::Value = serde_json::from_slice(&body).unwrap();

    let endpoints = document.as_object().unwrap();
    assert!(!endpoints.is_empty());
    for (name, template) in endpoints {
        let template = template.as_str().unwrap();
        let path = template.strip_prefix(BASE).unwrap();
        // Fill the one `{...}` placeholder with a dummy segment.
        let path = match (path.find('{'), path.find('}')) {
            (Some(open), Some(close)) => format!("{}x{}", &path[..open], &path[close + 1..]),
            _ => path.to_owned(),
        };
        let status = app
            .clone()
            .oneshot(
                Request::post(&path)
                    .header(header::FROM, "mimi@b.example")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap()
            .status();
        assert!(
            status != StatusCode::IM_A_TEAPOT && status != StatusCode::METHOD_NOT_ALLOWED,
            "{name} ({path}) answered {status}"
        );
    }
}
