//! Outbound protocol-07 §5.7 consent requests from [`PeerClient`].
//!
//! Oracle: a local HTTP server with a hand-written directory, which records
//! each request's method, path, `From` header and body. The bodies are the
//! Haven-encoded ConsentEntry fixtures, sent byte for byte.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::Bytes;
use axum::extract::{OriginalUri, State};
use axum::http::{HeaderMap, Method, StatusCode, header};
use axum::routing::{any, get};
use mimid_server::config::{BaseUrl, Domain};
use mimid_server::peer::{PeerClient, PeerError};

const REQUEST: &[u8] =
    include_bytes!("../../mimi-protocol/tests/fixtures/haven/consent_request.bin");
const GRANT: &[u8] = include_bytes!("../../mimi-protocol/tests/fixtures/haven/consent_grant.bin");

/// One request the server saw: method, path, `From` values, body.
type Seen = (Method, String, Vec<String>, Vec<u8>);

#[derive(Clone)]
struct Peer {
    seen: Arc<Mutex<Vec<Seen>>>,
    status: StatusCode,
}

async fn record(
    State(peer): State<Peer>,
    method: Method,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    body: Bytes,
) -> StatusCode {
    let from = headers
        .get_all(header::FROM)
        .iter()
        .map(|value| value.to_str().unwrap().to_owned())
        .collect();
    peer.seen
        .lock()
        .unwrap()
        .push((method, uri.path().to_owned(), from, body.to_vec()));
    peer.status
}

/// Starts a peer whose directory lists the given consent keys, answering
/// `status` to every other request. Returns its base URL and request log.
async fn start(status: StatusCode, keys: &[(&str, &str)]) -> (String, Arc<Mutex<Vec<Seen>>>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let fields: Vec<String> = keys
        .iter()
        .map(|(name, path)| format!("\"{name}\": \"{base}/v1/{path}\""))
        .collect();
    let directory = format!("{{{}}}", fields.join(", "));
    let seen = Arc::new(Mutex::new(Vec::new()));
    let app = Router::new()
        .route(
            "/.well-known/mimi-protocol-directory",
            get(move || async move { directory }),
        )
        .fallback(any(record))
        .with_state(Peer {
            seen: Arc::clone(&seen),
            status,
        });
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (base, seen)
}

const CONSENT_KEYS: &[(&str, &str)] = &[
    ("requestConsent", "requestConsent/{targetDomain}"),
    ("updateConsent", "updateConsent/{requesterDomain}"),
];

fn client(peer: &Domain, base: String) -> PeerClient {
    PeerClient::new(
        &Domain::try_from("a.example".to_owned()).unwrap(),
        BTreeMap::from([(peer.clone(), BaseUrl::try_from(base).unwrap())]),
    )
    .unwrap()
}

#[tokio::test]
async fn consent_requests_go_to_the_peer_domain_paths_byte_for_byte() {
    // protocol-07 §5.7: an accepted entry is answered 202 (decision
    // mimid-1wgh.7.42).
    let (base, seen) = start(StatusCode::ACCEPTED, CONSENT_KEYS).await;
    let peer = Domain::try_from("b.example".to_owned()).unwrap();
    let client = client(&peer, base);

    client
        .request_consent(&peer, REQUEST.to_vec())
        .await
        .unwrap();
    client.update_consent(&peer, GRANT.to_vec()).await.unwrap();

    let seen = seen.lock().unwrap();
    assert_eq!(
        *seen,
        [
            (
                Method::POST,
                "/v1/requestConsent/b.example".to_owned(),
                vec!["mimi@a.example".to_owned()],
                REQUEST.to_vec()
            ),
            (
                Method::POST,
                "/v1/updateConsent/b.example".to_owned(),
                vec!["mimi@a.example".to_owned()],
                GRANT.to_vec()
            ),
        ]
    );
}

#[tokio::test]
async fn any_status_but_202_is_rejected() {
    // protocol-07 §5.7: the answer is usually 202; 404 or a 500-class code
    // means not accepted, and so does -06's 201 (decision mimid-1wgh.7.42).
    for status in [
        StatusCode::OK,
        StatusCode::CREATED,
        StatusCode::NOT_FOUND,
        StatusCode::SERVICE_UNAVAILABLE,
    ] {
        let (base, _) = start(status, CONSENT_KEYS).await;
        let peer = Domain::try_from("b.example".to_owned()).unwrap();
        let client = client(&peer, base);
        let result = client.request_consent(&peer, REQUEST.to_vec()).await;
        assert!(
            matches!(result, Err(PeerError::Rejected { status: s, .. }) if s == status.as_u16()),
            "{status}: {result:?}"
        );
    }
}

#[tokio::test]
async fn consent_endpoint_absent_from_the_directory_is_not_offered() {
    let (base, seen) = start(
        StatusCode::CREATED,
        &[("requestConsent", "requestConsent/{targetDomain}")],
    )
    .await;
    let peer = Domain::try_from("b.example".to_owned()).unwrap();
    let client = client(&peer, base);
    let result = client.update_consent(&peer, GRANT.to_vec()).await;
    assert!(
        matches!(
            result,
            Err(PeerError::NotOffered {
                endpoint: "updateConsent"
            })
        ),
        "{result:?}"
    );
    assert!(seen.lock().unwrap().is_empty());
}
