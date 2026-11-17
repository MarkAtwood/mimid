//! `GET /jmap/asset/{accountId}?room=&url=` (bead mimid-1wgh.14; INVENTED,
//! NOT FROM SPEC): a user's fetch of an attachment from any provider.
//!
//! - Two providers on loopback: the asset is uploaded at a.example, which
//!   hosts the room; bob at b.example, a member of the room, fetches it
//!   through his own provider, which asks a.example's hub with a signed
//!   protocol-07 §5.10.2 proxyDownload. a.example enforces provider
//!   authentication with b.example's key.
//! - One provider that is the room's hub, fetching a peer-hosted asset
//!   from an HTTPS asset server (fixtures/tls `assets.pem`) itself.
//! - This server's own asset URL, served from its store.
//!
//! Oracles: the bytes fetched equal the bytes uploaded or served, octet
//! for octet; refusals carry the status and problem type the hub's
//! proxyDownload route uses (`crate::http`): 403 `asset-refused`, 404
//! `no-such-room` / `no-such-asset`.

#![forbid(unsafe_code)]

#[allow(dead_code, reason = "each test binary uses part of the helpers")]
mod common;

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use axum::http::header;
use axum::routing::get;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use common::FixedClock;
use mimid_server::config::{BaseUrl, Domain};
use mimid_server::directory::directory;
use mimid_server::follower::Follower;
use mimid_server::http::{PROBLEM_TYPE_PREFIX, router};
use mimid_server::httpsig::SigningKey;
use mimid_server::hub::{Clock, Hub, SystemClock};
use mimid_server::jmap::{self, JmapOptions};
use mimid_server::peer::PeerClient;
use mimid_server::provider_auth::{self, ProviderAuth, ProviderAuthConfig, RequestSigner};
use mimid_server::store::{BearerToken, Store};
use mimid_server::tls::{self, TlsConfig};
use serde_json::Value;
use tempfile::TempDir;

const ROOM: &str = "mimi://a.example/r/one";
const OTHER_ROOM: &str = "mimi://a.example/r/two";
const ALICE: &str = "mimi://a.example/u/alice";
const BOB: &str = "mimi://b.example/u/bob";
const CAROL: &str = "mimi://b.example/u/carol";
const NOW: u64 = 1_700_000_000_000;
const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/tls");
/// What the HTTPS asset server at assets.b.example serves at `/a/1`.
const PEER_ASSET: &[u8] = b"\x00\x01peer-hosted ciphertext\xff";

fn domain(name: &str) -> Domain {
    Domain::try_from(name.to_owned()).unwrap()
}

/// An opaque "ciphertext": every octet value.
fn ciphertext() -> Vec<u8> {
    (0..=255u8).collect()
}

/// b.example's request-signing key, seed 0x0b * 32, selector "b1".
fn b_signer() -> Arc<RequestSigner> {
    Arc::new(RequestSigner::new(
        SigningKey::from_seed(&[0x0b; 32]),
        "b1".to_owned(),
    ))
}

/// A provider on a loopback port: its store, base URL and one JMAP user.
struct Provider {
    _dir: TempDir,
    store: Store,
    base: String,
    account_id: String,
    token: BearerToken,
}

/// Binds a loopback listener and returns it with its `http://` base URL.
async fn bind() -> (tokio::net::TcpListener, String) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    (listener, base)
}

/// Starts the provider `own` on `listener` at `base`, as `main.rs` wires
/// it: the protocol routes (behind provider authentication with
/// `auth`, if given) and the JMAP routes, with `peers` as its peer map,
/// `signer` signing its peer requests, and `user` as a JMAP account. The
/// hub fetches assets with `asset_client`, if given.
async fn start(
    own: &str,
    (listener, base): (tokio::net::TcpListener, String),
    peers: BTreeMap<Domain, BaseUrl>,
    signer: Option<Arc<RequestSigner>>,
    auth: Option<&str>,
    user: &str,
    asset_client: Option<reqwest::Client>,
) -> Provider {
    let dir = tempfile::tempdir().unwrap();
    let own = domain(own);
    let store = Store::open(&dir.path().join("mimid.sqlite"), &own)
        .await
        .unwrap();
    let base_url = BaseUrl::try_from(base.clone()).unwrap();
    let clock: Arc<dyn Clock> = Arc::new(FixedClock(NOW));
    let peer_client = || {
        let client = PeerClient::new(&own, peers.clone()).unwrap();
        match &signer {
            Some(signer) => client.with_signer(Arc::clone(signer)),
            None => client,
        }
    };
    let mut hub = Hub::open(store.clone(), own.clone(), Arc::clone(&clock))
        .await
        .unwrap()
        .with_peers(peer_client())
        .with_base_url(base_url.clone());
    if let Some(client) = asset_client {
        hub = hub.with_asset_client(client);
    }
    let hub = Arc::new(hub);
    let follower =
        Arc::new(Follower::new(own.clone(), store.clone(), clock).with_peers(peer_client()));
    let mut protocol = router(
        directory(&base_url),
        Arc::clone(&hub),
        Arc::clone(&follower),
    );
    if let Some(auth) = auth {
        let config: ProviderAuthConfig = toml::from_str(auth).unwrap();
        // Signatures carry real time, so the check uses the system clock.
        let check = Arc::new(ProviderAuth::new(&config, &base_url, Arc::new(SystemClock)));
        protocol = protocol.layer(axum::middleware::from_fn_with_state(
            check,
            provider_auth::check,
        ));
    }
    let jmap = jmap::router(
        &base_url,
        store.clone(),
        hub,
        follower,
        JmapOptions::default(),
    )
    .unwrap();
    let app = protocol.merge(jmap);
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let account_id = store.create_account(&own, user, 1).await.unwrap();
    let token = store.issue_token(&account_id, 2).await.unwrap();
    Provider {
        _dir: dir,
        store,
        base,
        account_id,
        token,
    }
}

/// Percent-encodes everything but RFC 3986 unreserved characters.
fn encode(value: &str) -> String {
    value
        .bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
                char::from(b).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}

/// `user`'s GET of `url` through `provider`'s `/jmap/asset` for `room`:
/// the status, the response headers and the body.
async fn fetch(
    provider: &Provider,
    account_id: &str,
    token: &BearerToken,
    room: &str,
    url: &str,
) -> (u16, reqwest::header::HeaderMap, Vec<u8>) {
    let response = reqwest::Client::new()
        .get(format!(
            "{}/jmap/asset/{account_id}?room={}&url={}",
            provider.base,
            encode(room),
            encode(url)
        ))
        .bearer_auth(token.expose_secret())
        .send()
        .await
        .unwrap();
    let status = response.status().as_u16();
    let headers = response.headers().clone();
    (status, headers, response.bytes().await.unwrap().to_vec())
}

/// Uploads `bytes` as `provider`'s user and returns the blob id.
async fn upload(provider: &Provider, bytes: Vec<u8>) -> String {
    let response = reqwest::Client::new()
        .post(format!(
            "{}/jmap/upload/{}/",
            provider.base, provider.account_id
        ))
        .bearer_auth(provider.token.expose_secret())
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .body(bytes)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 201);
    let body: Value = serde_json::from_slice(&response.bytes().await.unwrap()).unwrap();
    body["blobId"].as_str().unwrap().to_owned()
}

/// Asserts a refusal with the protocol routes' problem type `kind`.
fn assert_refused(
    (status, _, body): (u16, reqwest::header::HeaderMap, Vec<u8>),
    want: u16,
    kind: &str,
) {
    assert_eq!(status, want, "{}", String::from_utf8_lossy(&body));
    let body: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body["type"], format!("{PROBLEM_TYPE_PREFIX}{kind}"));
    assert_eq!(body["status"], want);
}

fn assert_octets((status, headers, body): (u16, reqwest::header::HeaderMap, Vec<u8>), want: &[u8]) {
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
    assert_eq!(body, want);
    assert_eq!(
        headers.get(header::CONTENT_TYPE).unwrap(),
        "application/octet-stream"
    );
    assert_eq!(headers.get("x-content-type-options").unwrap(), "nosniff");
}

/// a.example (the hub, enforcing provider authentication with b's key)
/// and b.example, signing with `b_signer` if `signed`.
async fn two_providers(signed: bool) -> (Provider, Provider) {
    let (a_listener, a_base) = bind().await;
    let (b_listener, b_base) = bind().await;
    let trusting_b = format!(
        "[peers.\"b.example\"]\nkeys = {{ \"b1\" = \"{}\" }}\n",
        STANDARD.encode(b_signer().public_key().to_bytes())
    );
    let a = start(
        "a.example",
        (a_listener, a_base),
        BTreeMap::from([(
            domain("b.example"),
            BaseUrl::try_from(b_base.clone()).unwrap(),
        )]),
        None,
        Some(&trusting_b),
        ALICE,
        None,
    )
    .await;
    let b = start(
        "b.example",
        (b_listener, b_base),
        BTreeMap::from([(
            domain("a.example"),
            BaseUrl::try_from(a.base.clone()).unwrap(),
        )]),
        signed.then(b_signer),
        None,
        BOB,
        None,
    )
    .await;
    // bob is a member of a.example's room, as b.example's follower
    // records it.
    b.store
        .add_follower_member(ROOM, &domain("a.example"), BOB, 0, NOW)
        .await
        .unwrap();
    (a, b)
}

#[tokio::test]
async fn a_member_fetches_an_asset_through_the_peer_hub() {
    let (a, b) = two_providers(true).await;
    let blob_id = upload(&a, ciphertext()).await;
    let url = format!("{}/assets/{blob_id}", a.base);
    assert_octets(
        fetch(&b, &b.account_id, &b.token, ROOM, &url).await,
        &ciphertext(),
    );

    // a.example's own asset URL naming no blob: its 404 passes through.
    let missing = format!("{}/assets/AAECAwQFBgcICQoLDA0ODw", a.base);
    assert_refused(
        fetch(&b, &b.account_id, &b.token, ROOM, &missing).await,
        404,
        "no-such-asset",
    );
    // Not a peer's asset host: the hub refuses, not an open proxy.
    assert_refused(
        fetch(&b, &b.account_id, &b.token, ROOM, "https://c.example/x").await,
        403,
        "asset-refused",
    );
    // A room b.example does not follow, and a user who is not a member:
    // nothing is asked of the hub.
    assert_refused(
        fetch(&b, &b.account_id, &b.token, OTHER_ROOM, &url).await,
        404,
        "no-such-room",
    );
    let carol_id = b
        .store
        .create_account(&domain("b.example"), CAROL, 3)
        .await
        .unwrap();
    let carol_token = b.store.issue_token(&carol_id, 4).await.unwrap();
    assert_refused(
        fetch(&b, &carol_id, &carol_token, ROOM, &url).await,
        404,
        "no-such-room",
    );
    // bob's token, carol's account.
    let (status, _, _) = fetch(&b, &carol_id, &b.token, ROOM, &url).await;
    assert_eq!(status, 404);
    // No token.
    let response = reqwest::get(format!(
        "{}/jmap/asset/{}?room={}&url={}",
        b.base,
        b.account_id,
        encode(ROOM),
        encode(&url)
    ))
    .await
    .unwrap();
    assert_eq!(response.status().as_u16(), 401);
}

#[tokio::test]
async fn the_peer_hub_refuses_an_unsigned_proxy_download() {
    // b.example does not sign, and a.example enforces: the proxyDownload
    // never reaches a.example's hub.
    let (a, b) = two_providers(false).await;
    let blob_id = upload(&a, ciphertext()).await;
    let url = format!("{}/assets/{blob_id}", a.base);
    let (status, _, body) = fetch(&b, &b.account_id, &b.token, ROOM, &url).await;
    assert_eq!(status, 403, "{}", String::from_utf8_lossy(&body));
}

/// An HTTPS asset server for assets.b.example on loopback: `/a/1` is
/// [`PEER_ASSET`].
async fn asset_server() -> SocketAddr {
    let config = tls::server_config(&TlsConfig {
        cert: format!("{FIXTURES}/assets.pem").into(),
        key: format!("{FIXTURES}/assets.key").into(),
    })
    .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = Router::new().route(
        "/a/1",
        get(|| async { ([(header::CONTENT_TYPE, "text/html")], PEER_ASSET) }),
    );
    tokio::spawn(tls::serve(listener, config, app, std::future::pending()));
    addr
}

#[tokio::test]
async fn the_hub_fetches_a_peer_hosted_asset_for_its_own_member() {
    let addr = asset_server().await;
    let ca = std::fs::read(format!("{FIXTURES}/ca.pem")).unwrap();
    let client = reqwest::Client::builder()
        .tls_certs_only([reqwest::Certificate::from_pem(&ca).unwrap()])
        .resolve("assets.b.example", addr)
        .redirect(reqwest::redirect::Policy::none())
        .https_only(true)
        .build()
        .unwrap();
    let a = start(
        "a.example",
        bind().await,
        BTreeMap::from([(
            domain("b.example"),
            BaseUrl::try_from("https://mimi.b.example".to_owned()).unwrap(),
        )]),
        None,
        None,
        ALICE,
        Some(client),
    )
    .await;
    a.store
        .add_follower_member(ROOM, &domain("a.example"), ALICE, 0, NOW)
        .await
        .unwrap();
    let url = format!("https://assets.b.example:{}/a/1", addr.port());
    // Served as octets, whatever type the asset server claimed.
    assert_octets(
        fetch(&a, &a.account_id, &a.token, ROOM, &url).await,
        PEER_ASSET,
    );
    // hub::assets::check_url's refusals.
    for url in [
        format!("http://assets.b.example:{}/a/1", addr.port()),
        format!("https://127.0.0.1:{}/a/1", addr.port()),
        "https://c.example/a/1".to_owned(),
    ] {
        assert_refused(
            fetch(&a, &a.account_id, &a.token, ROOM, &url).await,
            403,
            "asset-refused",
        );
    }
    // The asset provider answers 404: it failed.
    assert_refused(
        fetch(
            &a,
            &a.account_id,
            &a.token,
            ROOM,
            &format!("https://assets.b.example:{}/missing", addr.port()),
        )
        .await,
        502,
        "asset-provider-failed",
    );
}

#[tokio::test]
async fn an_own_asset_url_is_served_from_the_store_for_any_room() {
    let a = start(
        "a.example",
        bind().await,
        BTreeMap::new(),
        None,
        None,
        ALICE,
        None,
    )
    .await;
    let blob_id = upload(&a, ciphertext()).await;
    // The blob id is the capability: no room membership is needed.
    let url = format!("{}/assets/{blob_id}", a.base);
    assert_octets(
        fetch(&a, &a.account_id, &a.token, OTHER_ROOM, &url).await,
        &ciphertext(),
    );
    assert_refused(
        fetch(
            &a,
            &a.account_id,
            &a.token,
            OTHER_ROOM,
            &format!("{}/assets/AAECAwQFBgcICQoLDA0ODw", a.base),
        )
        .await,
        404,
        "no-such-asset",
    );
}
