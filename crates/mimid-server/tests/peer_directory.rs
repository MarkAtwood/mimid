//! A peer directory without some protocol-07 §5.1 endpoints (decision
//! mimid-1wgh.5.75): calling an endpoint the peer does not offer fails
//! with [`PeerError::NotOffered`] and sends nothing.
//!
//! Oracle: the directory is written by hand in the shape Haven's mimi-hubd
//! serves (havenmessenger/interop 2c14e62), which omits `groupInfo` and
//! `proxyDownload`.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use axum::Router;
use axum::extract::State;
use axum::routing::{any, get};
use mimid_server::config::{BaseUrl, Domain};
use mimid_server::peer::{PeerClient, PeerError};

#[tokio::test]
async fn endpoint_absent_from_the_directory_is_not_offered() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let directory = format!(
        r#"{{"keyMaterial": "{base}/mimi/pl/keyMaterial/{{targetUser}}",
            "update": "{base}/mimi/pl/update/{{roomId}}",
            "notify": "{base}/mimi/pl/notify",
            "submitMessage": "{base}/mimi/pl/submitMessage/{{recipient}}",
            "requestConsent": "{base}/mimi/pl/requestConsent/{{targetDomain}}",
            "updateConsent": "{base}/mimi/pl/updateConsent/{{requesterDomain}}",
            "identifierQuery": "{base}/mimi/pl/identifierQuery",
            "reportAbuse": "{base}/mimi/pl/reportAbuse/{{roomId}}",
            "unsupported": {{"groupInfo_external_commit_join": "DIV-1"}}}}"#
    );
    let other_requests = Arc::new(AtomicUsize::new(0));
    let app = Router::new()
        .route(
            "/.well-known/mimi-protocol-directory",
            get(move || async move { directory }),
        )
        .fallback(any(|State(count): State<Arc<AtomicUsize>>| async move {
            count.fetch_add(1, Ordering::SeqCst);
            axum::http::StatusCode::NOT_FOUND
        }))
        .with_state(other_requests.clone());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let peer = Domain::try_from("haven.example".to_owned()).unwrap();
    let client = PeerClient::new(
        &Domain::try_from("b.example".to_owned()).unwrap(),
        BTreeMap::from([(peer.clone(), BaseUrl::try_from(base).unwrap())]),
    )
    .unwrap();
    let result = client
        .group_info(&peer, "mimi://haven.example/r/room", vec![0x00])
        .await;
    assert!(
        matches!(
            result,
            Err(PeerError::NotOffered {
                endpoint: "groupInfo"
            })
        ),
        "{result:?}"
    );
    assert_eq!(other_requests.load(Ordering::SeqCst), 0);
}
