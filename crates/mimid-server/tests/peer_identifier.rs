//! Outbound protocol-07 §5.8 identifierQuery from [`PeerClient`].
//!
//! Oracle: a local HTTP server with a hand-written directory, which records
//! each request's method, path, `From` header and body and answers a fixed
//! status and body. The request body is the Haven-encoded fixture
//! `identifier_request.bin`, the response body Haven's
//! `identifier_response_success.bin`, both sent and returned byte for byte.

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
    include_bytes!("../../mimi-protocol/tests/fixtures/haven/identifier_request.bin");
const RESPONSE: &[u8] =
    include_bytes!("../../mimi-protocol/tests/fixtures/haven/identifier_response_success.bin");

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
) -> (StatusCode, &'static [u8]) {
    let from = headers
        .get_all(header::FROM)
        .iter()
        .map(|value| value.to_str().unwrap().to_owned())
        .collect();
    peer.seen
        .lock()
        .unwrap()
        .push((method, uri.path().to_owned(), from, body.to_vec()));
    (peer.status, RESPONSE)
}

/// Starts a peer whose directory lists `keys`, answering `status` and
/// [`RESPONSE`] to every other request. Returns its base URL and request
/// log.
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

const IDENTIFIER_KEY: &[(&str, &str)] = &[("identifierQuery", "identifierQuery/{domain}")];

fn client(peer: &Domain, base: String) -> PeerClient {
    PeerClient::new(
        &Domain::try_from("a.example".to_owned()).unwrap(),
        BTreeMap::from([(peer.clone(), BaseUrl::try_from(base).unwrap())]),
    )
    .unwrap()
}

#[tokio::test]
async fn query_goes_to_the_peer_domain_path_and_returns_the_body() {
    let (base, seen) = start(StatusCode::OK, IDENTIFIER_KEY).await;
    let peer = Domain::try_from("b.example".to_owned()).unwrap();
    let client = client(&peer, base);

    let response = client
        .identifier_query(&peer, REQUEST.to_vec())
        .await
        .unwrap();
    assert_eq!(response, RESPONSE);
    assert_eq!(
        *seen.lock().unwrap(),
        [(
            Method::POST,
            "/v1/identifierQuery/b.example".to_owned(),
            vec!["mimi@a.example".to_owned()],
            REQUEST.to_vec()
        )]
    );
}

#[tokio::test]
async fn any_status_but_200_is_rejected() {
    for status in [
        StatusCode::CREATED,
        StatusCode::NOT_FOUND,
        StatusCode::SERVICE_UNAVAILABLE,
    ] {
        let (base, _) = start(status, IDENTIFIER_KEY).await;
        let peer = Domain::try_from("b.example".to_owned()).unwrap();
        let client = client(&peer, base);
        let result = client.identifier_query(&peer, REQUEST.to_vec()).await;
        assert!(
            matches!(result, Err(PeerError::Rejected { status: s, .. }) if s == status.as_u16()),
            "{status}: {result:?}"
        );
    }
}

#[tokio::test]
async fn identifier_query_absent_from_the_directory_is_not_offered() {
    let (base, seen) = start(StatusCode::OK, &[("notify", "notify/{roomId}")]).await;
    let peer = Domain::try_from("b.example".to_owned()).unwrap();
    let client = client(&peer, base);
    let result = client.identifier_query(&peer, REQUEST.to_vec()).await;
    assert!(
        matches!(
            result,
            Err(PeerError::NotOffered {
                endpoint: "identifierQuery"
            })
        ),
        "{result:?}"
    );
    assert!(seen.lock().unwrap().is_empty());
}
