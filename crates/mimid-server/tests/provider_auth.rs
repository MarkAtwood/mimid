//! Provider authentication end to end (bead mimid-75nk.1): b.example
//! serves the protocol router behind [`provider_auth::check`], and
//! a.example's [`PeerClient`] sends it a requestConsent over HTTP. A
//! request signed with a key b.example trusts for a.example is accepted;
//! an unsigned one, or one signed with another key, is `403` unless
//! a.example is in observe mode.
//!
//! Oracle: the `202` of an accepted requestConsent (protocol-07 §5.7), the
//! entry stored in b.example's database, and the `403` problem with its
//! `Accept-Signature` (draft-atwood-mimi-provider-auth-00 §11).

#![forbid(unsafe_code)]

#[allow(dead_code, reason = "each test binary uses part of the helpers")]
mod common;

use std::collections::BTreeMap;
use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use common::FixedClock;
use mimid_server::config::{BaseUrl, Domain};
use mimid_server::directory::directory;
use mimid_server::follower::Follower;
use mimid_server::http::router;
use mimid_server::httpsig::SigningKey;
use mimid_server::hub::{Clock, Hub, SystemClock};
use mimid_server::peer::{PeerClient, PeerError};
use mimid_server::provider_auth::{
    self, BoxFuture, DnssecStatus, ProviderAuth, ProviderAuthConfig, RequestSigner, TxtAnswer,
    TxtLookupError, TxtResolver,
};
use mimid_server::store::{ConsentKey, NewKeyPackage, Store};
use tempfile::TempDir;

/// A Haven-encoded requestConsent `request`: requester alice@a.example,
/// target bob@b.example, room `mimi://a.example/r/room1`.
const REQUEST: &[u8] =
    include_bytes!("../../mimi-protocol/tests/fixtures/haven/consent_request.bin");

/// The fixture's requester and target: the request goes from a.example
/// (alice's provider, the signer) to b.example (bob's, the checker).
const ALICE: &str = "mimi://a.example/u/alice";
const BOB: &str = "mimi://b.example/u/bob";
const ROOM1: &str = "mimi://a.example/r/room1";

fn domain(name: &str) -> Domain {
    Domain::try_from(name.to_owned()).unwrap()
}

/// b.example, the target's provider, listening on a local port behind the
/// provider-authentication check with `auth`, with bob as a local user
/// and a.example as a configured peer.
struct Target {
    _dir: TempDir,
    store: Store,
    base: String,
}

async fn target(auth: &str) -> Target {
    target_with_dns(auth, None).await
}

/// [`target`], with DNS key records from `dns`.
async fn target_with_dns(auth: &str, dns: Option<Arc<dyn TxtResolver>>) -> Target {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("mimid.sqlite"), &domain("b.example"))
        .await
        .unwrap();
    store
        .insert_key_package(&NewKeyPackage {
            client_id: "mimi://b.example/u/bob/client",
            user_uri: BOB,
            signature_key: b"signature key",
            reference: &[1; 32],
            bytes: b"key package",
            last_resort: true,
            not_after: 4_000_000_000,
        })
        .await
        .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
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
    let config: ProviderAuthConfig = toml::from_str(auth).unwrap();
    // Signatures carry real time, so the check uses the system clock.
    let system: Arc<dyn Clock> = Arc::new(SystemClock);
    let mut check = ProviderAuth::new(&config, &base_url, system);
    if let Some(dns) = dns {
        check = check.with_dns(dns);
    }
    let check = Arc::new(check);
    let app = router(directory(&base_url), Arc::new(hub), Arc::new(follower)).layer(
        axum::middleware::from_fn_with_state(check, provider_auth::check),
    );
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    Target {
        _dir: dir,
        store,
        base,
    }
}

/// a.example's key, seed 0x0a * 32, selector "a1".
fn a_signer() -> Arc<RequestSigner> {
    Arc::new(RequestSigner::new(
        SigningKey::from_seed(&[0x0a; 32]),
        "a1".to_owned(),
    ))
}

fn a_key() -> String {
    STANDARD.encode(a_signer().public_key().to_bytes())
}

/// a.example's peer client toward `target`, signing with `signer`.
fn a_client(target: &Target, signer: Option<Arc<RequestSigner>>) -> PeerClient {
    let peers = BTreeMap::from([(
        domain("b.example"),
        BaseUrl::try_from(target.base.clone()).unwrap(),
    )]);
    let client = PeerClient::new(&domain("a.example"), peers).unwrap();
    match signer {
        Some(signer) => client.with_signer(signer),
        None => client,
    }
}

const SCOPE: ConsentKey<'static> = ConsentKey {
    requester_uri: ALICE,
    target_uri: BOB,
    room_id: Some(ROOM1),
};

fn trusting_a() -> String {
    format!(
        "[peers.\"a.example\"]\nkeys = {{ \"a1\" = \"{}\" }}\n",
        a_key()
    )
}

#[tokio::test]
async fn a_signed_request_from_a_trusted_key_is_accepted() {
    let b = target(&trusting_a()).await;
    a_client(&b, Some(a_signer()))
        .request_consent(&domain("b.example"), REQUEST.to_vec())
        .await
        .unwrap();
    assert!(b.store.consent_request(&SCOPE).await.unwrap().is_some());
}

#[tokio::test]
async fn unsigned_or_wrongly_signed_requests_are_refused_when_enforcing() {
    let b = target(&trusting_a()).await;
    let other = Arc::new(RequestSigner::new(
        SigningKey::from_seed(&[0x0b; 32]),
        "a1".to_owned(),
    ));
    for signer in [None, Some(other)] {
        let error = a_client(&b, signer)
            .request_consent(&domain("b.example"), REQUEST.to_vec())
            .await
            .unwrap_err();
        assert!(
            matches!(error, PeerError::Rejected { status: 403, .. }),
            "{error:?}"
        );
    }
    assert!(b.store.consent_request(&SCOPE).await.unwrap().is_none());
}

#[tokio::test]
async fn observe_mode_accepts_an_unsigned_request() {
    let b = target("[peers.\"a.example\"]\nmode = \"observe\"\n").await;
    a_client(&b, None)
        .request_consent(&domain("b.example"), REQUEST.to_vec())
        .await
        .unwrap();
    assert!(b.store.consent_request(&SCOPE).await.unwrap().is_some());
}

#[tokio::test]
async fn the_directory_is_not_authenticated() {
    // Enforcing with no keys at all: the directory still answers, which
    // the peer client needs before it can send anything.
    let b = target("").await;
    let response = reqwest::get(format!("{}/.well-known/mimi-protocol-directory", b.base))
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
}

#[tokio::test]
async fn a_refusal_is_403_with_accept_signature_and_a_problem_body() {
    let b = target(&trusting_a()).await;
    let response = reqwest::Client::new()
        .post(format!("{}/v1/requestConsent/b.example", b.base))
        .header("From", "mimi@a.example")
        .header("Content-Type", "application/mimi-protocol")
        .body(REQUEST.to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 403);
    // RFC 9110 §15.5.2: no 401, so no WWW-Authenticate either.
    assert!(response.headers().get("www-authenticate").is_none());
    assert_eq!(
        response.headers()["accept-signature"],
        provider_auth::ACCEPT_SIGNATURE
    );
    // The value is an RFC 9651 dictionary naming the profile.
    assert_eq!(
        provider_auth::ACCEPT_SIGNATURE,
        r#"mimi=("@method" "@target-uri" "content-digest" "from");created;tag="mimi";alg="ed25519""#
    );
    assert_eq!(
        response.headers()["content-type"],
        "application/problem+json"
    );
    let body: serde_json::Value = serde_json::from_slice(&response.bytes().await.unwrap()).unwrap();
    assert_eq!(body["status"], 403);
    assert!(
        body["type"]
            .as_str()
            .unwrap()
            .ends_with(":provider-authentication")
    );
}

/// DNS holding a.example's key at `a1._mimi.a.example.`.
struct ADns;

impl TxtResolver for ADns {
    fn txt<'a>(&'a self, name: &'a str) -> BoxFuture<'a, Result<TxtAnswer, TxtLookupError>> {
        let answer = if name == "a1._mimi.a.example." {
            Ok(TxtAnswer {
                records: vec![(a_signer().dns_record().into_bytes(), DnssecStatus::Secure)],
            })
        } else {
            Err(TxtLookupError::NoRecords)
        };
        Box::pin(std::future::ready(answer))
    }
}

#[tokio::test]
async fn a_request_signed_with_a_dns_published_key_is_accepted() {
    // No trust list: the key comes from a1._mimi.a.example.
    let b = target_with_dns("", Some(Arc::new(ADns))).await;
    a_client(&b, Some(a_signer()))
        .request_consent(&domain("b.example"), REQUEST.to_vec())
        .await
        .unwrap();
    assert!(b.store.consent_request(&SCOPE).await.unwrap().is_some());

    // A selector with no record is refused.
    let b = target_with_dns("", Some(Arc::new(ADns))).await;
    let other = Arc::new(RequestSigner::new(
        SigningKey::from_seed(&[0x0a; 32]),
        "a2".to_owned(),
    ));
    let error = a_client(&b, Some(other))
        .request_consent(&domain("b.example"), REQUEST.to_vec())
        .await
        .unwrap_err();
    assert!(
        matches!(error, PeerError::Rejected { status: 403, .. }),
        "{error:?}"
    );
}
