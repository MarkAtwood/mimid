//! The protocol-07 §5.7 consent endpoints, received:
//! `POST /v1/requestConsent/{targetDomain}` and
//! `POST /v1/updateConsent/{requesterDomain}` (decision mimid-1wgh.5.16).
//!
//! Oracles: ConsentEntry bodies encoded by Haven's mimi-core (fixtures
//! `consent_request.bin` and `consent_grant.bin` from
//! `crates/mimi-protocol/tests/fixtures/haven`, see its PROVENANCE), and
//! copies of them with the `consentOperation` byte (offset 0) edited by
//! hand. Both fixtures name requester `mimi://a.example/u/alice` and target
//! `mimi://b.example/u/bob`; `consent_request.bin` is scoped to room
//! `mimi://a.example/r/room1`, `consent_grant.bin` to any room.
//!
//! A requestConsent goes to the target's provider (b.example) from the
//! requester's (a.example); an updateConsent goes the other way (§5.7).
//! Entries are stored, not enforced (decision mimid-1wgh.7.35); an unknown
//! local user is `404` (decision mimid-1wgh.7.36); an operation or domain
//! violation is `400` (decision mimid-1wgh.7.37).

#![forbid(unsafe_code)]

#[allow(dead_code, reason = "each test binary uses part of the helpers")]
mod common;

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use common::FixedClock;
use mimid_server::config::{BaseUrl, Domain};
use mimid_server::directory::directory;
use mimid_server::follower::Follower;
use mimid_server::http::router;
use mimid_server::hub::Hub;
use mimid_server::peer::PeerClient;
use mimid_server::store::{ConsentDecision, ConsentKey, NewKeyPackage, Store};
use tempfile::TempDir;
use tower::ServiceExt;

/// `request`, requester alice@a.example, target bob@b.example, room
/// `mimi://a.example/r/room1`, no extensions.
const REQUEST: &[u8] =
    include_bytes!("../../mimi-protocol/tests/fixtures/haven/consent_request.bin");
/// `grant`, requester alice@a.example, target bob@b.example, any room, one
/// KeyPackage, one extension.
const GRANT: &[u8] = include_bytes!("../../mimi-protocol/tests/fixtures/haven/consent_grant.bin");

/// protocol-07 §5.7 `ConsentOperation` values.
const CANCEL: u8 = 0;
const REVOKE: u8 = 3;

const ALICE: &str = "mimi://a.example/u/alice";
const BOB: &str = "mimi://b.example/u/bob";
const ROOM1: &str = "mimi://a.example/r/room1";

/// `entry` with its `consentOperation` (offset 0) replaced by `operation`.
/// `REQUEST` has no `select (consentOperation)` arm, so turning it into
/// `cancel` or `revoke` leaves the rest of the encoding valid.
fn with_operation(entry: &[u8], operation: u8) -> Vec<u8> {
    let mut edited = entry.to_vec();
    edited[0] = operation;
    edited
}

struct Provider {
    _dir: TempDir,
    store: Store,
    app: Router,
}

/// A provider for `domain`, with a client for each of `local_users`.
/// A provider for `domain` whose configured peers are `peers`: consent
/// entries are accepted only from them (decision mimid-1wgh.7.41).
async fn provider(domain: &str, local_users: &[&str], peers: &[&str]) -> Provider {
    let dir = tempfile::tempdir().unwrap();
    let domain = Domain::try_from(domain.to_owned()).unwrap();
    let store = Store::open(&dir.path().join("mimid.sqlite"), &domain)
        .await
        .unwrap();
    for (n, user) in local_users.iter().enumerate() {
        // Creates the user's client; the store does not inspect the bytes.
        store
            .insert_key_package(&NewKeyPackage {
                client_id: &format!("{user}/client"),
                user_uri: user,
                reference: &[u8::try_from(n).unwrap(); 32],
                bytes: b"key package",
                last_resort: true,
                not_after: 4_000_000_000,
            })
            .await
            .unwrap();
    }
    let clock = Arc::new(FixedClock(1_700_000_000_000));
    let hub = Hub::open(store.clone(), domain.clone(), clock.clone())
        .await
        .unwrap();
    let peers = peers
        .iter()
        .map(|peer| {
            (
                Domain::try_from((*peer).to_owned()).unwrap(),
                BaseUrl::try_from(format!("https://mimi.{peer}")).unwrap(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let follower = Follower::new(domain.clone(), store.clone(), clock)
        .with_peers(PeerClient::new(&domain, peers).unwrap());
    let base = BaseUrl::try_from(format!("https://mimi.{domain}")).unwrap();
    let app = router(directory(&base), Arc::new(hub), Arc::new(follower));
    Provider {
        _dir: dir,
        store,
        app,
    }
}

async fn post(app: &Router, path: &str, from: Option<&str>, body: &[u8]) -> StatusCode {
    let mut request = Request::post(path);
    if let Some(from) = from {
        request = request.header(header::FROM, from);
    }
    app.clone()
        .oneshot(request.body(Body::from(body.to_vec())).unwrap())
        .await
        .unwrap()
        .status()
}

/// The scope of `REQUEST` (and of its cancel and revoke copies).
const ROOM1_SCOPE: ConsentKey<'static> = ConsentKey {
    requester_uri: ALICE,
    target_uri: BOB,
    room_id: Some(ROOM1),
};
/// The scope of `GRANT`.
const ANY_ROOM_SCOPE: ConsentKey<'static> = ConsentKey {
    requester_uri: ALICE,
    target_uri: BOB,
    room_id: None,
};

const REQUEST_CONSENT: &str = "/v1/requestConsent/b.example";
const UPDATE_CONSENT: &str = "/v1/updateConsent/a.example";
const FROM_A: Option<&str> = Some("mimi@a.example");
const FROM_B: Option<&str> = Some("mimi@b.example");

#[tokio::test]
async fn request_is_accepted_and_cancel_is_accepted_with_or_without_a_match() {
    let b = provider("b.example", &[BOB], &["a.example"]).await;
    assert_eq!(
        post(&b.app, REQUEST_CONSENT, FROM_A, REQUEST).await,
        StatusCode::CREATED
    );
    // Decision mimid-1wgh.7.35: stored as received.
    let stored = b
        .store
        .consent_request(&ROOM1_SCOPE)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.entry, REQUEST);
    assert_eq!(stored.from_domain, "a.example");
    assert_eq!(stored.received_at, 1_700_000_000_000);
    // Another scope is untouched.
    assert_eq!(
        b.store.consent_request(&ANY_ROOM_SCOPE).await.unwrap(),
        None
    );

    let cancel = with_operation(REQUEST, CANCEL);
    assert_eq!(
        post(&b.app, REQUEST_CONSENT, FROM_A, &cancel).await,
        StatusCode::CREATED
    );
    assert_eq!(b.store.consent_request(&ROOM1_SCOPE).await.unwrap(), None);
    // §5.7: a cancel with no matching request is still 201.
    assert_eq!(
        post(&b.app, REQUEST_CONSENT, FROM_A, &cancel).await,
        StatusCode::CREATED
    );
}

#[tokio::test]
async fn grant_and_revoke_are_accepted() {
    let a = provider("a.example", &[ALICE], &["b.example"]).await;
    assert_eq!(
        post(&a.app, UPDATE_CONSENT, FROM_B, GRANT).await,
        StatusCode::CREATED
    );
    let (decision, stored) = a
        .store
        .consent_update(&ANY_ROOM_SCOPE)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(decision, ConsentDecision::Grant);
    assert_eq!(stored.entry, GRANT);
    assert_eq!(stored.from_domain, "b.example");

    let revoke = with_operation(REQUEST, REVOKE);
    assert_eq!(
        post(&a.app, UPDATE_CONSENT, FROM_B, &revoke).await,
        StatusCode::CREATED
    );
    let (decision, stored) = a.store.consent_update(&ROOM1_SCOPE).await.unwrap().unwrap();
    assert_eq!(decision, ConsentDecision::Revoke);
    assert_eq!(stored.entry, revoke);
    // The grant for any room is a different scope and stays.
    let (decision, _) = a
        .store
        .consent_update(&ANY_ROOM_SCOPE)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(decision, ConsentDecision::Grant);

    // A later grant for the room scope replaces the revoke.
    let regrant = with_operation(&revoke, 2);
    // `grant` has a `clientKeyPackages<V>` arm (§5.7): insert an empty
    // vector (length 0x00) before the trailing `consent_extensions`.
    let regrant = [
        &regrant[..regrant.len() - 1],
        &[0x00],
        &regrant[regrant.len() - 1..],
    ]
    .concat();
    assert_eq!(
        post(&a.app, UPDATE_CONSENT, FROM_B, &regrant).await,
        StatusCode::CREATED
    );
    let (decision, stored) = a.store.consent_update(&ROOM1_SCOPE).await.unwrap().unwrap();
    assert_eq!(decision, ConsentDecision::Grant);
    assert_eq!(stored.entry, regrant);
}

#[tokio::test]
async fn operation_for_the_other_endpoint_is_refused() {
    // Decision mimid-1wgh.7.37: requestConsent carries request or cancel,
    // updateConsent grant or revoke (§5.7).
    let b = provider("b.example", &[BOB], &["a.example"]).await;
    let revoke = with_operation(REQUEST, REVOKE);
    assert_eq!(
        post(&b.app, REQUEST_CONSENT, FROM_A, &revoke).await,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        post(&b.app, REQUEST_CONSENT, FROM_A, GRANT).await,
        StatusCode::BAD_REQUEST
    );
    let a = provider("a.example", &[ALICE], &["b.example"]).await;
    assert_eq!(
        post(&a.app, UPDATE_CONSENT, FROM_B, REQUEST).await,
        StatusCode::BAD_REQUEST
    );
    let cancel = with_operation(REQUEST, CANCEL);
    assert_eq!(
        post(&a.app, UPDATE_CONSENT, FROM_B, &cancel).await,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(b.store.consent_request(&ROOM1_SCOPE).await.unwrap(), None);
    assert_eq!(a.store.consent_update(&ROOM1_SCOPE).await.unwrap(), None);
    assert_eq!(a.store.consent_update(&ANY_ROOM_SCOPE).await.unwrap(), None);
}

#[tokio::test]
async fn uri_and_path_domains_must_match_the_providers() {
    // §5.7: for requestConsent the targetUri is in the receiving provider's
    // domain and the requesterUri in the sending provider's; reversed for
    // updateConsent. Decision mimid-1wgh.7.37.
    // c.example is a configured peer, so these reach the §5.7 checks.
    let b = provider("b.example", &[BOB], &["a.example", "c.example"]).await;
    let refused = [
        // The From domain is not the requester's.
        (REQUEST_CONSENT, Some("mimi@c.example"), REQUEST),
        // No From header, or a malformed one.
        (REQUEST_CONSENT, None, REQUEST),
        (REQUEST_CONSENT, Some("a.example"), REQUEST),
        // The path names another provider.
        ("/v1/requestConsent/c.example", FROM_A, REQUEST),
        // The path is not a domain at all.
        ("/v1/requestConsent/B.EXAMPLE", FROM_A, REQUEST),
    ];
    for (path, from, body) in refused {
        assert_eq!(
            post(&b.app, path, from, body).await,
            StatusCode::BAD_REQUEST,
            "{path} {from:?}"
        );
    }
    assert_eq!(b.store.consent_request(&ROOM1_SCOPE).await.unwrap(), None);
    // a.example receiving a requestConsent from a peer: the target is not
    // its user.
    let a = provider("a.example", &[ALICE], &["b.example", "c.example"]).await;
    assert_eq!(
        post(&a.app, "/v1/requestConsent/a.example", FROM_B, REQUEST).await,
        StatusCode::BAD_REQUEST
    );
    // b.example receiving an updateConsent from a peer: the requester is
    // not its user.
    assert_eq!(
        post(&b.app, "/v1/updateConsent/b.example", FROM_A, GRANT).await,
        StatusCode::BAD_REQUEST
    );
    // updateConsent whose From (a peer) is not the target's domain.
    assert_eq!(
        post(&a.app, UPDATE_CONSENT, Some("mimi@c.example"), GRANT).await,
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn unknown_local_user_is_not_found() {
    // Decision mimid-1wgh.7.36: a user with no client is unknown, even if
    // another user of the provider has one.
    let b = provider("b.example", &["mimi://b.example/u/carol"], &["a.example"]).await;
    assert_eq!(
        post(&b.app, REQUEST_CONSENT, FROM_A, REQUEST).await,
        StatusCode::NOT_FOUND
    );
    assert_eq!(b.store.consent_request(&ROOM1_SCOPE).await.unwrap(), None);
    let a = provider("a.example", &[], &["b.example"]).await;
    assert_eq!(
        post(&a.app, UPDATE_CONSENT, FROM_B, GRANT).await,
        StatusCode::NOT_FOUND
    );
    assert_eq!(a.store.consent_update(&ANY_ROOM_SCOPE).await.unwrap(), None);
}

#[tokio::test]
async fn undecodable_body_is_refused() {
    let b = provider("b.example", &[BOB], &["a.example"]).await;
    for body in [
        &REQUEST[..REQUEST.len() - 1],
        &[REQUEST, &[0]].concat()[..],
        b"",
    ] {
        assert_eq!(
            post(&b.app, REQUEST_CONSENT, FROM_A, body).await,
            StatusCode::BAD_REQUEST
        );
    }
}

#[tokio::test]
async fn entries_from_a_non_peer_or_this_provider_are_forbidden() {
    // Decision mimid-1wgh.7.41: consent entries are accepted only from
    // configured peers, as /notify is (decision mimid-1wgh.7.4).
    let b = provider("b.example", &[BOB], &["c.example"]).await;
    assert_eq!(
        post(&b.app, REQUEST_CONSENT, FROM_A, REQUEST).await,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        post(&b.app, REQUEST_CONSENT, FROM_B, REQUEST).await,
        StatusCode::FORBIDDEN
    );
    assert_eq!(b.store.consent_request(&ROOM1_SCOPE).await.unwrap(), None);
}
