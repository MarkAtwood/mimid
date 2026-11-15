//! PKIX client certificates end to end (bead mimid-75nk.5): b.example
//! serves the protocol router over its own TLS listener ([`tls::serve`])
//! behind [`provider_auth::check`], enforcing, with the TLS test CA as a
//! PKIX anchor and no other mechanism. A peer presenting the test client
//! certificate (SAN `a.example`) is a.example on every request it sends;
//! without a certificate, or sending as another domain, it is refused.
//!
//! Oracle: the `202` of an accepted requestConsent (protocol-07 §5.7) and
//! the entry stored in b.example's database; the `403` of a refusal
//! (draft-atwood-mimi-provider-auth-00 §11); the test certificates in
//! `fixtures/tls`, made by its `make.sh`.

#![forbid(unsafe_code)]

#[allow(dead_code, reason = "each test binary uses part of the helpers")]
mod common;

use std::collections::BTreeMap;
use std::sync::Arc;

use common::FixedClock;
use mimid_server::config::{BaseUrl, Domain};
use mimid_server::directory::directory;
use mimid_server::follower::Follower;
use mimid_server::http::router;
use mimid_server::hub::{Clock, Hub, SystemClock};
use mimid_server::peer::PeerClient;
use mimid_server::provider_auth::{self, PkixCertificates, ProviderAuth, ProviderAuthConfig};
use mimid_server::store::{ConsentKey, NewKeyPackage, Store};
use mimid_server::tls::{self, TlsConfig};
use tempfile::TempDir;

/// A Haven-encoded requestConsent `request` from alice@a.example to
/// bob@b.example, room `mimi://a.example/r/room1`.
const REQUEST: &[u8] =
    include_bytes!("../../mimi-protocol/tests/fixtures/haven/consent_request.bin");

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/tls");

const SCOPE: ConsentKey<'static> = ConsentKey {
    requester_uri: "mimi://a.example/u/alice",
    target_uri: "mimi://b.example/u/bob",
    room_id: Some("mimi://a.example/r/room1"),
};

fn domain(name: &str) -> Domain {
    Domain::try_from(name.to_owned()).unwrap()
}

fn pem(name: &str) -> Vec<u8> {
    std::fs::read(format!("{FIXTURES}/{name}")).unwrap()
}

struct Target {
    _dir: TempDir,
    store: Store,
    base: String,
}

/// b.example over TLS, trusting the test CA for PKIX client certificates.
async fn target() -> Target {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("mimid.sqlite"), &domain("b.example"))
        .await
        .unwrap();
    store
        .insert_key_package(&NewKeyPackage {
            client_id: "mimi://b.example/u/bob/client",
            user_uri: "mimi://b.example/u/bob",
            reference: &[1; 32],
            bytes: b"key package",
            last_resort: true,
            not_after: 4_000_000_000,
        })
        .await
        .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!(
        "https://127.0.0.1:{}",
        listener.local_addr().unwrap().port()
    );
    let base_url = BaseUrl::try_from(base.clone()).unwrap();
    let clock = Arc::new(FixedClock(1_700_000_000_000));
    let hub = Hub::open(store.clone(), domain("b.example"), clock.clone())
        .await
        .unwrap();
    let peers = BTreeMap::from([(
        domain("a.example"),
        BaseUrl::try_from("http://127.0.0.1:9".to_owned()).unwrap(),
    )]);
    let follower = Follower::new(domain("b.example"), store.clone(), clock)
        .with_peers(PeerClient::new(&domain("b.example"), peers).unwrap());
    let config: ProviderAuthConfig = toml::from_str(&format!(
        "dns_keys = false\npkix_anchors = [\"{FIXTURES}/ca.pem\"]\n"
    ))
    .unwrap();
    // Certificates are checked against real time.
    let system: Arc<dyn Clock> = Arc::new(SystemClock);
    let pkix = PkixCertificates::new(&config).unwrap().unwrap();
    let check = Arc::new(ProviderAuth::new(&config, &base_url, system).with_pkix(pkix));
    let app = router(directory(&base_url), Arc::new(hub), Arc::new(follower)).layer(
        axum::middleware::from_fn_with_state(check, provider_auth::check),
    );
    let tls = tls::server_config(&TlsConfig {
        cert: format!("{FIXTURES}/server.pem").into(),
        key: format!("{FIXTURES}/server.key").into(),
    })
    .unwrap();
    tokio::spawn(tls::serve(listener, tls, app, std::future::pending()));
    Target {
        _dir: dir,
        store,
        base,
    }
}

fn client(identity: bool) -> reqwest::Client {
    let ca = reqwest::Certificate::from_pem(&pem("ca.pem")).unwrap();
    let mut builder = reqwest::Client::builder().tls_certs_only([ca]);
    if identity {
        let both = [pem("client.pem"), pem("client.key")].concat();
        builder = builder.identity(reqwest::Identity::from_pem(&both).unwrap());
    }
    builder.build().unwrap()
}

/// POSTs the requestConsent as `from`; the status.
async fn send(client: &reqwest::Client, b: &Target, from: &str) -> u16 {
    client
        .post(format!("{}/v1/requestConsent/b.example", b.base))
        .header("From", format!("mimi@{from}"))
        .header("Content-Type", "application/mimi-protocol")
        .body(REQUEST.to_vec())
        .send()
        .await
        .unwrap()
        .status()
        .as_u16()
}

#[tokio::test]
async fn a_client_certificate_from_a_trusted_anchor_authenticates_its_domain() {
    let b = target().await;
    assert_eq!(send(&client(true), &b, "a.example").await, 202);
    assert!(b.store.consent_request(&SCOPE).await.unwrap().is_some());
}

#[tokio::test]
async fn without_a_certificate_or_as_another_domain_the_request_is_refused() {
    let b = target().await;
    assert_eq!(send(&client(false), &b, "a.example").await, 403);
    // The certificate names a.example only: the same connection cannot
    // send as c.example.
    let with = client(true);
    assert_eq!(send(&with, &b, "c.example").await, 403);
    assert!(b.store.consent_request(&SCOPE).await.unwrap().is_none());
    // And the same client is still a.example afterwards.
    assert_eq!(send(&with, &b, "a.example").await, 202);
}
