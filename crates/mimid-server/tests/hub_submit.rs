//! protocol-06 §5.4 submitMessage at the hub (bead mimid-1wgh.6.29).
//!
//! The messages come from a mimi-mls Member. Franks are checked with
//! mimi-protocol's `verify_server_frank` and `Frank::verify_integrity`,
//! which are tested against fixtures there, using the hub's public key and
//! the `hub_key` read back from the store.

#[allow(dead_code, reason = "each test binary uses part of the helpers")]
mod common;
#[allow(dead_code, reason = "each test binary uses part of the helpers")]
#[path = "common/submit.rs"]
mod submit;

use std::sync::Arc;

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode, header};
use common::*;
use mimi_mls::tls_codec::{Deserialize, Serialize};
use mimi_mls::wire::SignaturePublicKey;
use mimi_protocol::{
    FanoutEvent, FanoutMessage, Frank, HubKey, IdentifierUri, ServerFrankingContext,
    SubmitMessageResponse, SubmitResult, verify_server_frank,
};
use mimid_server::config::{BaseUrl, Domain};
use mimid_server::directory::directory;
use mimid_server::follower::Follower;
use mimid_server::http::router;
use mimid_server::hub::{Hub, HubError};
use mimid_server::store::Store;
use sqlx::SqlitePool;
use submit::*;
use tower::ServiceExt;

const START_MS: u64 = 1_800_000_000_000;

fn from(domain: &str) -> Domain {
    Domain::try_from(domain.to_owned()).unwrap()
}

fn decode(response: &[u8]) -> SubmitResult {
    let decoded = SubmitMessageResponse::tls_deserialize_exact(response).unwrap();
    // Decode, then re-encode byte-identically.
    assert_eq!(decoded.tls_serialize_detached().unwrap(), response);
    decoded.result
}

/// A hub at `START_MS` with one room alice created.
struct Fixture {
    _dir: tempfile::TempDir,
    store: Store,
    hub: Hub,
    db: SqlitePool,
    alice: Sender,
}

async fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("mimid.sqlite");
    let (store, hub) = open_stepping_hub(&path, START_MS).await;
    let alice = create_room(&hub, ROOM_ID, b"group-submit").await;
    let db = inspect(&path).await;
    Fixture {
        _dir: dir,
        store,
        hub,
        db,
        alice,
    }
}

impl Fixture {
    async fn submit(&self, request: &[u8], from_domain: &str) -> SubmitResult {
        decode(
            &self
                .hub
                .submit_message(ROOM_ID, &from(from_domain), request)
                .await
                .unwrap(),
        )
    }

    /// Checks `frank` as a receiver and the hub itself would, for a message
    /// from `sender` accepted at `accepted_timestamp`.
    async fn verify_frank(
        &self,
        frank: &Frank,
        franking_tag: &[u8; 32],
        sender: &[u8],
        accepted_timestamp: u64,
    ) {
        let context = ServerFrankingContext {
            sender_uri: IdentifierUri::new(std::str::from_utf8(sender).unwrap()).unwrap(),
            room_uri: IdentifierUri::new(ROOM_ID).unwrap(),
            accepted_timestamp,
        };
        let secret = self.store.hub_secret().await.unwrap().unwrap();
        verify_server_frank(
            &HubKey::new(secret.hub_key),
            franking_tag,
            &context,
            &frank.server_frank,
        )
        .unwrap();
        // RFC 9420 §5.1.1: opaque SignaturePublicKey<V>, 32 bytes.
        let key = [&[0x20][..], self.hub.signature_public_key()].concat();
        let key = SignaturePublicKey::tls_deserialize_exact(&key).unwrap();
        frank.verify_integrity(&key, &context).unwrap();
        assert_eq!(u16::from(frank.franking_signature_ciphersuite), 1);
    }

    async fn close(self) {
        self.db.close().await;
        drop(self.hub);
        self.store.close().await;
    }
}

#[tokio::test]
async fn accepted_message_is_franked_logged_and_enqueued_verbatim() {
    let mut f = fixture().await;
    let (message, tag) = f.alice.franked(b"hello room", &[7; 16]);
    let result = f
        .submit(&submit_request(&message, ALICE), "a.example")
        .await;
    let SubmitResult::Accepted {
        accepted_timestamp,
        frank: Some(frank),
    } = result
    else {
        panic!("not accepted with a frank: {result:?}");
    };
    // create_room read the clock once, at START_MS.
    assert_eq!(accepted_timestamp, START_MS + 1000);
    f.verify_frank(&frank, &tag, ALICE, accepted_timestamp)
        .await;

    let events: Vec<(String, i64, i64, String, Vec<u8>)> = sqlx::query_as(
        "SELECT room_id, epoch, accepted_at, kind, bytes FROM room_event ORDER BY seq",
    )
    .fetch_all(&f.db)
    .await
    .unwrap();
    assert_eq!(
        events,
        [(
            ROOM_ID.to_owned(),
            1,
            i64::try_from(accepted_timestamp).unwrap(),
            "application".to_owned(),
            message.clone()
        )]
    );

    let outbox: Vec<(String, String, Vec<u8>)> =
        sqlx::query_as("SELECT room_id, domain, body FROM outbox ORDER BY domain")
            .fetch_all(&f.db)
            .await
            .unwrap();
    let domains: Vec<_> = outbox
        .iter()
        .map(|(_, domain, _)| domain.as_str())
        .collect();
    // alice's and bob's providers; the origin a.example is alice's.
    assert_eq!(domains, ["a.example", "b.example"]);
    for (room_id, _, body) in &outbox {
        assert_eq!(room_id, ROOM_ID);
        let fanout = FanoutMessage::tls_deserialize_exact(body).unwrap();
        assert_eq!(fanout.tls_serialize_detached().unwrap(), *body);
        assert_eq!(fanout.timestamp, accepted_timestamp);
        let FanoutEvent::Application {
            message: forwarded,
            frank: forwarded_frank,
        } = fanout.event
        else {
            panic!("not an application fanout");
        };
        assert_eq!(forwarded.as_bytes(), message.as_slice());
        assert_eq!(forwarded_frank.as_ref(), Some(&frank));
    }
    f.close().await;
}

#[tokio::test]
async fn resubmission_returns_the_identical_response_and_writes_nothing() {
    let mut f = fixture().await;
    let (message, tag) = f.alice.franked(b"once", &[1; 16]);
    let request = submit_request(&message, ALICE);
    let first = f
        .hub
        .submit_message(ROOM_ID, &from("a.example"), &request)
        .await
        .unwrap();
    let counts = row_counts(&f.db).await;
    assert_eq!(counts, (1, 2));

    // The clock has moved on; a recomputed frank would differ.
    let again = f
        .hub
        .submit_message(ROOM_ID, &from("a.example"), &request)
        .await
        .unwrap();
    assert_eq!(again, first);
    assert_eq!(row_counts(&f.db).await, counts);
    let SubmitResult::Accepted {
        accepted_timestamp,
        frank: Some(frank),
    } = decode(&again)
    else {
        panic!("not accepted");
    };
    assert_eq!(accepted_timestamp, START_MS + 1000);
    f.verify_frank(&frank, &tag, ALICE, accepted_timestamp)
        .await;

    // A different message is a new event.
    let (other, _) = f.alice.franked(b"twice", &[2; 16]);
    let result = f.submit(&submit_request(&other, ALICE), "a.example").await;
    assert!(
        matches!(result, SubmitResult::Accepted { .. }),
        "{result:?}"
    );
    assert_eq!(row_counts(&f.db).await, (2, 4));
    f.close().await;
}

#[tokio::test]
async fn senders_room_policy_refuses_are_not_allowed() {
    let mut f = fixture().await;
    for (sender, origin) in [
        (MALLORY, "c.example"), // not in the participant list
        (EVE, "b.example"),     // banned
        (MUTED, "a.example"),   // role without canSendMessage
    ] {
        let (message, _) = f.alice.franked(b"hi", &[3; 16]);
        let result = f.submit(&submit_request(&message, sender), origin).await;
        assert_eq!(
            result,
            SubmitResult::NotAllowed,
            "{}",
            String::from_utf8_lossy(sender)
        );
    }
    assert_eq!(row_counts(&f.db).await, (0, 0));
    f.close().await;
}

#[tokio::test]
async fn from_domain_mismatch_is_refused_before_any_write() {
    let mut f = fixture().await;
    let (message, _) = f.alice.franked(b"first", &[4; 16]);
    let result = f
        .submit(&submit_request(&message, ALICE), "a.example")
        .await;
    assert!(
        matches!(result, SubmitResult::Accepted { .. }),
        "{result:?}"
    );
    let counts = row_counts(&f.db).await;

    let (message, _) = f.alice.franked(b"second", &[5; 16]);
    for origin in ["b.example", "c.example"] {
        let result = f.submit(&submit_request(&message, ALICE), origin).await;
        assert_eq!(result, SubmitResult::NotAllowed, "From mimi@{origin}");
        assert_eq!(row_counts(&f.db).await, counts);
    }
    // A sendingUri that is not a mimi:// user URI has no domain to match.
    let result = f
        .submit(
            &submit_request(&message, b"https://a.example/u/alice"),
            "a.example",
        )
        .await;
    assert_eq!(result, SubmitResult::NotAllowed);
    assert_eq!(row_counts(&f.db).await, counts);
    f.close().await;
}

#[tokio::test]
async fn message_without_frank_aad_is_not_allowed() {
    let mut f = fixture().await;
    // An empty SafeAAD: the group uses Safe AAD, but no frank_aad item.
    let message = f
        .alice
        .member
        .send(&f.alice.identity, b"unfranked", &[])
        .unwrap();
    let result = f
        .submit(&submit_request(&message, ALICE), "a.example")
        .await;
    assert_eq!(result, SubmitResult::NotAllowed);
    // A frank_aad item of the wrong length (protocol-06 §5.4.1: 32 bytes).
    let message = f
        .alice
        .member
        .send(
            &f.alice.identity,
            b"short tag",
            &[(mimi_protocol::component_id::FRANK_AAD, vec![0; 31])],
        )
        .unwrap();
    let result = f
        .submit(&submit_request(&message, ALICE), "a.example")
        .await;
    assert_eq!(result, SubmitResult::NotAllowed);
    assert_eq!(row_counts(&f.db).await, (0, 0));
    f.close().await;
}

#[tokio::test]
async fn epoch_rules() {
    let mut f = fixture().await;
    let old = f.alice.epoch0_message.clone();
    let result = f.submit(&submit_request(&old, ALICE), "a.example").await;
    assert_eq!(result, SubmitResult::EpochTooOld { current_epoch: 1 });

    // alice moves to epoch 2 without telling the hub.
    f.alice
        .member
        .commit(&f.alice.identity, &[], &[], &[], no_components)
        .unwrap();
    f.alice
        .member
        .merge_pending_commit(&f.alice.identity)
        .unwrap();
    assert_eq!(f.alice.member.epoch(), 2);
    let (newer, _) = f.alice.franked(b"from the future", &[6; 16]);
    let result = f.submit(&submit_request(&newer, ALICE), "a.example").await;
    assert_eq!(result, SubmitResult::NotAllowed);
    assert_eq!(row_counts(&f.db).await, (0, 0));
    f.close().await;
}

#[tokio::test]
async fn message_for_another_group_is_refused() {
    let f = fixture().await;
    // Another hosted room's group, at the same epoch 1.
    let mut other = create_room(&f.hub, "mimi://a.example/r/two", b"group-other").await;
    let (message, _) = other.franked(b"wrong room", &[8; 16]);
    let result = f
        .submit(&submit_request(&message, ALICE), "a.example")
        .await;
    assert_eq!(result, SubmitResult::NotAllowed);
    assert_eq!(row_counts(&f.db).await, (0, 0));
    f.close().await;
}

#[tokio::test]
async fn undecodable_request_or_unknown_room_is_an_error() {
    let mut f = fixture().await;
    let (message, _) = f.alice.franked(b"x", &[9; 16]);
    let request = submit_request(&message, ALICE);
    for bad in [
        vec![],
        request[..request.len() - 1].to_vec(),
        [&request[..], &[0]].concat(),
        submit_request(&message, b"mimi://a.example/u/alice")
            .into_iter()
            .enumerate()
            .map(|(i, b)| if i == 0 { 2 } else { b }) // protocol 2 is undefined
            .collect(),
    ] {
        let err = f
            .hub
            .submit_message(ROOM_ID, &from("a.example"), &bad)
            .await
            .unwrap_err();
        assert!(matches!(err, HubError::InvalidRequest(_)), "{err:?}");
    }
    let err = f
        .hub
        .submit_message("mimi://a.example/r/nope", &from("a.example"), &request)
        .await
        .unwrap_err();
    assert!(matches!(err, HubError::NoSuchRoom), "{err:?}");
    assert_eq!(row_counts(&f.db).await, (0, 0));
    f.close().await;
}

async fn post(
    (hub, follower): (&Arc<Hub>, &Arc<Follower>),
    room: &str,
    from: Option<&str>,
    body: Vec<u8>,
) -> (StatusCode, Vec<u8>) {
    let base = BaseUrl::try_from("https://mimi.a.example".to_owned()).unwrap();
    let app = router(directory(&base), Arc::clone(hub), Arc::clone(follower));
    let mut request = Request::post(format!("/v1/submitMessage/{room}"));
    if let Some(from) = from {
        request = request.header(header::FROM, from);
    }
    let response = app
        .oneshot(request.body(Body::from(body)).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    (status, body.to_vec())
}

#[tokio::test]
async fn http_route_maps_results() {
    let mut f = fixture().await;
    let (message, tag) = f.alice.franked(b"over http", &[10; 16]);
    let request = submit_request(&message, ALICE);
    let hub = Arc::new(f.hub);
    let follower = Arc::new(Follower::new(
        domain(),
        f.store.clone(),
        Arc::new(FixedClock(0)),
    ));

    let (status, body) = post(
        (&hub, &follower),
        ROOM_ID_ENCODED,
        Some("mimi@a.example"),
        request.clone(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let SubmitResult::Accepted {
        accepted_timestamp,
        frank: Some(frank),
    } = decode(&body)
    else {
        panic!("not accepted");
    };

    // The retry is answered from the log, before the From check.
    let (status, body) = post(
        (&hub, &follower),
        ROOM_ID_ENCODED,
        Some("mimi@b.example"),
        request.clone(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        decode(&body),
        SubmitResult::Accepted {
            accepted_timestamp,
            frank: Some(frank.clone()),
        }
    );

    // A refusal is a protocol result.
    let (refused, _) = f.alice.franked(b"refused over http", &[13; 16]);
    let (status, body) = post(
        (&hub, &follower),
        ROOM_ID_ENCODED,
        Some("mimi@b.example"),
        submit_request(&refused, ALICE),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(decode(&body), SubmitResult::NotAllowed);

    let (status, _) = post(
        (&hub, &follower),
        ROOM_ID_ENCODED,
        Some("mimi@a.example"),
        vec![1, 2, 3],
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = post((&hub, &follower), ROOM_ID_ENCODED, None, request.clone()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = post(
        (&hub, &follower),
        "mimi%3A%2F%2Fa.example%2Fr%2Fnope",
        Some("mimi@a.example"),
        request,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    f.hub = Arc::into_inner(hub).unwrap();
    f.verify_frank(&frank, &tag, ALICE, accepted_timestamp)
        .await;
    assert_eq!(row_counts(&f.db).await, (1, 2));
    f.close().await;
}

/// Every `tracing` event at TRACE, across accepted, retried and refused
/// submissions, is free of the hub's signing key and `hub_key`.
#[tokio::test]
async fn trace_logs_never_contain_hub_secrets() {
    let logs = capture_logs();
    let mut f = fixture().await;
    let (message, _) = f.alice.franked(b"canary", &[11; 16]);
    let request = submit_request(&message, ALICE);
    for origin in ["a.example", "a.example", "b.example"] {
        f.hub
            .submit_message(ROOM_ID, &from(origin), &request)
            .await
            .unwrap();
    }
    let (message, _) = f.alice.franked(b"refused", &[12; 16]);
    f.submit(&submit_request(&message, MUTED), "a.example")
        .await;
    let old = f.alice.epoch0_message.clone();
    f.submit(&submit_request(&old, ALICE), "a.example").await;

    let secret = f.store.hub_secret().await.unwrap().unwrap();
    let text = logs.contents();
    assert!(
        text.contains("application message accepted"),
        "capture works: {text}"
    );
    assert!(
        text.contains("submitMessage refused"),
        "capture works: {text}"
    );
    assert_secret_absent(&text, &secret.signature_private_key, "signing key");
    assert_secret_absent(&text, &secret.hub_key, "hub_key");
    f.close().await;
}
