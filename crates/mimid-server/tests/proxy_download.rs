//! protocol-07 §5.10.2 proxyDownload (bead mimid-1wgh.8): the hub fetches
//! an asset at a peer's asset host for a peer, and refuses everything that
//! would make it an open proxy.
//!
//! Oracle: an HTTPS asset server at assets.b.example (fixtures/tls
//! `assets.pem`, issued by the fixture CA) serving known bytes; the
//! directory and status codes §5.10.2 and mimid's mapping give
//! (crate::http proxy_download).

#![forbid(unsafe_code)]

#[allow(dead_code, reason = "each test binary uses part of the helpers")]
mod common;

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode, header};
use axum::routing::get;
use common::*;
use mimid_server::config::{BaseUrl, Domain};
use mimid_server::directory::directory;
use mimid_server::follower::Follower;
use mimid_server::http::router;
use mimid_server::peer::PeerClient;
use mimid_server::tls::{self, TlsConfig};
use tower::ServiceExt;

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/tls");
const ASSET: &[u8] = b"\x89PNG not really, but bytes";

fn b_example() -> Domain {
    Domain::try_from("b.example".to_owned()).unwrap()
}

/// An HTTPS asset server for assets.b.example on loopback: `/a/1` is the
/// asset, `/missing` answers 404.
async fn asset_server() -> SocketAddr {
    let config = tls::server_config(&TlsConfig {
        cert: format!("{FIXTURES}/assets.pem").into(),
        key: format!("{FIXTURES}/assets.key").into(),
    })
    .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = Router::new()
        .route(
            "/a/1",
            get(|| async { ([(header::CONTENT_TYPE, "image/png")], ASSET) }),
        )
        .route("/missing", get(|| async { StatusCode::NOT_FOUND }));
    tokio::spawn(tls::serve(listener, config, app, std::future::pending()));
    addr
}

/// The router of a.example's hub with b.example as its peer, fetching with
/// a client that trusts the fixture CA and finds assets.b.example at
/// `addr`.
async fn hub_router(addr: SocketAddr) -> (Router, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let (store, hub) = open_hub(&dir.path().join("mimid.sqlite")).await;
    let ca = std::fs::read(format!("{FIXTURES}/ca.pem")).unwrap();
    let client = reqwest::Client::builder()
        .tls_certs_only([reqwest::Certificate::from_pem(&ca).unwrap()])
        .resolve("assets.b.example", addr)
        .redirect(reqwest::redirect::Policy::none())
        .https_only(true)
        .build()
        .unwrap();
    let peers = PeerClient::new(
        &domain(),
        BTreeMap::from([(
            b_example(),
            BaseUrl::try_from("https://mimi.b.example".to_owned()).unwrap(),
        )]),
    )
    .unwrap();
    let hub = hub.with_peers(peers).with_asset_client(client);
    let base = BaseUrl::try_from("https://mimi.a.example".to_owned()).unwrap();
    let follower = Follower::new(domain(), store, Arc::new(FixedClock(0)));
    (
        router(directory(&base), Arc::new(hub), Arc::new(follower)),
        dir,
    )
}

/// `GET /v1/proxyDownload/{downloadUrl}` from `from`, the URL
/// percent-encoded as the level-1 template expands it.
async fn get_asset(app: &Router, from: &str, url: &str) -> (StatusCode, Option<String>, Vec<u8>) {
    let encoded: String = url
        .bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect();
    let response = app
        .clone()
        .oneshot(
            Request::get(format!("/v1/proxyDownload/{encoded}"))
                .header(header::FROM, from)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let content_type = response
        .headers()
        .get(header::CONTENT_TYPE)
        .map(|v| v.to_str().unwrap().to_owned());
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    (status, content_type, body.to_vec())
}

#[tokio::test]
async fn a_peer_gets_a_peer_hosted_asset_through_the_hub() {
    let addr = asset_server().await;
    let (app, _dir) = hub_router(addr).await;
    let url = format!("https://assets.b.example:{}/a/1", addr.port());
    let (status, content_type, body) = get_asset(&app, "mimi@b.example", &url).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(content_type.as_deref(), Some("image/png"));
    assert_eq!(body, ASSET);
}

#[tokio::test]
async fn the_hub_is_not_an_open_proxy() {
    let addr = asset_server().await;
    let (app, _dir) = hub_router(addr).await;
    let port = addr.port();
    for (from, url, want) in [
        // Not a peer.
        (
            "mimi@c.example",
            format!("https://assets.b.example:{port}/a/1"),
            StatusCode::FORBIDDEN,
        ),
        // Not https, an IP literal, not a peer's host.
        (
            "mimi@b.example",
            format!("http://assets.b.example:{port}/a/1"),
            StatusCode::FORBIDDEN,
        ),
        (
            "mimi@b.example",
            format!("https://127.0.0.1:{port}/a/1"),
            StatusCode::FORBIDDEN,
        ),
        (
            "mimi@b.example",
            "https://c.example/a/1".to_owned(),
            StatusCode::FORBIDDEN,
        ),
        // A peer's host whose asset is missing: the asset provider failed.
        (
            "mimi@b.example",
            format!("https://assets.b.example:{port}/missing"),
            StatusCode::BAD_GATEWAY,
        ),
    ] {
        let (status, _, _) = get_asset(&app, from, &url).await;
        assert_eq!(status, want, "{from} {url}");
    }
}

#[tokio::test]
async fn the_directory_lists_proxy_download() {
    let base = BaseUrl::try_from("https://mimi.a.example".to_owned()).unwrap();
    let directory = directory(&base);
    assert_eq!(
        directory.proxy_download.unwrap().to_string(),
        "https://mimi.a.example/v1/proxyDownload/{downloadUrl}"
    );
}
