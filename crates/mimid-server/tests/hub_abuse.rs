//! protocol-06 §5.9 reportAbuse at the hub (bead mimid-1wgh.6.31; decision
//! mimid-1wgh.21).
//!
//! Genuine franks come from the hub's own submitMessage path (bead
//! mimid-1wgh.6.29), on PrivateMessages a mimi-mls Member encrypted around
//! MIMI content. Forged franks are built with mimi-protocol's
//! `server_frank` and `FrankingIntegrityTbs::sign` using a wrong `hub_key`
//! or a wrong signing key, so each of the two checks is shown to bite on
//! its own.

#[allow(dead_code, reason = "each test binary uses part of the helpers")]
mod common;
#[allow(dead_code, reason = "each test binary uses part of the helpers")]
#[path = "common/submit.rs"]
mod submit;

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode, header};
use common::*;
use mimi_content::{Disposition, Extensions, MimiContent, NestedPart, Part};
use mimi_mls::label::SignatureKeyPair;
use mimi_mls::tls_codec::{Deserialize, Serialize};
use mimi_mls::wire::AppDataDictionary;
use mimi_protocol::{
    AbuseReport, AbuseType, AbusiveMessage, Frank, FrankingIntegrityTbs, HubKey, IdentifierUri,
    ServerFrankingContext, SubmitMessageResponse, SubmitResult, franking_tag, server_frank,
};
use mimid_server::config::{BaseUrl, Domain};
use mimid_server::directory::Directory;
use mimid_server::follower::Follower;
use mimid_server::http::router;
use mimid_server::hub::{Hub, HubError};
use mimid_server::store::Store;
use submit::*;
use tower::ServiceExt;

const START_MS: u64 = 1_800_000_000_000;
/// Text that must never reach the log.
const BODY_CANARY: &str = "abusive-body-canary-7f3a91";
const NOTE_CANARY: &str = "report-note-canary-c04e5d";

fn from(domain: &str) -> Domain {
    Domain::try_from(domain.to_owned()).unwrap()
}

/// A MIMI content message (mimi-content-09 §4.1) from alice in [`ROOM_ID`]
/// with `salt` and a text body.
fn content(salt: [u8; 16], text: &str) -> Vec<u8> {
    content_with(salt, text, Some(ALICE), Some(ROOM_ID.as_bytes()))
}

fn content_with(
    salt: [u8; 16],
    text: &str,
    sender_uri: Option<&[u8]>,
    room_uri: Option<&[u8]>,
) -> Vec<u8> {
    let uri = |bytes: Option<&[u8]>| bytes.map(|b| String::from_utf8(b.to_vec()).unwrap());
    MimiContent {
        salt,
        replaces: None,
        topic_id: vec![],
        expires: None,
        in_reply_to: None,
        mimi_extensions: Extensions {
            sender_uri: uri(sender_uri),
            room_uri: uri(room_uri),
            other: BTreeMap::new(),
        },
        nested_part: NestedPart {
            disposition: Disposition::RENDER,
            language: String::new(),
            part: Part::Single {
                content_type: "text/plain;charset=utf-8".to_owned(),
                content: text.as_bytes().to_vec(),
            },
        },
    }
    .encode()
    .unwrap()
}

/// A hub at `START_MS` with one room alice created.
struct Fixture {
    _dir: tempfile::TempDir,
    store: Store,
    hub: Arc<Hub>,
    alice: Sender,
}

async fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let (store, hub) = open_stepping_hub(&dir.path().join("mimid.sqlite"), START_MS).await;
    let alice = create_room(&hub, ROOM_ID, b"group-abuse").await;
    Fixture {
        _dir: dir,
        store,
        hub: Arc::new(hub),
        alice,
    }
}

impl Fixture {
    /// alice sends `data` franked with `salt` through submitMessage; returns
    /// the AbusiveMessage a reporter would build from it.
    async fn send(&mut self, data: &[u8], salt: [u8; 16]) -> AbusiveMessage {
        let (message, _) = self.alice.franked(data, &salt);
        let response = self
            .hub
            .submit_message(ROOM_ID, &from(DOMAIN), &submit_request(&message, ALICE))
            .await
            .unwrap();
        let SubmitResult::Accepted {
            accepted_timestamp,
            frank: Some(frank),
        } = SubmitMessageResponse::tls_deserialize_exact(response.as_slice())
            .unwrap()
            .result
        else {
            panic!("message accepted with a frank");
        };
        AbusiveMessage {
            message_content: data.to_vec(),
            frank,
            accepted_timestamp,
        }
    }

    async fn report(&self, messages: Vec<AbusiveMessage>) -> Result<Vec<u8>, HubError> {
        self.hub
            .report_abuse(ROOM_ID, &from("b.example"), &encode(messages))
            .await
    }

    async fn post(&self, room_encoded: &str, body: Vec<u8>) -> (StatusCode, Vec<u8>) {
        let base = BaseUrl::try_from("https://a.example".to_owned()).unwrap();
        let follower = Follower::new(domain(), self.store.clone(), Arc::new(FixedClock(0)));
        let response = router(
            Directory::new(&base),
            Arc::clone(&self.hub),
            Arc::new(follower),
        )
        .oneshot(
            Request::post(format!("/v1/reportAbuse/{room_encoded}"))
                .header(header::FROM, "mimi@b.example")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
        let status = response.status();
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        (status, body.to_vec())
    }

    /// The hub's franking HMAC key and Ed25519 private key, from the store.
    async fn secrets(&self) -> ([u8; 32], [u8; 32]) {
        let stored = self.store.hub_secret().await.unwrap().unwrap();
        (stored.hub_key, stored.signature_private_key)
    }
}

/// An AbuseReport from bob about alice carrying `messages`.
fn encode(messages: Vec<AbusiveMessage>) -> Vec<u8> {
    AbuseReport {
        reporting_user: IdentifierUri::new("mimi://b.example/u/bob").unwrap(),
        alleged_abuser_uri: IdentifierUri::new("mimi://a.example/u/alice").unwrap(),
        reason_code: AbuseType::RESERVED,
        note: NOTE_CANARY.as_bytes().to_vec(),
        messages,
        // mls-extensions-10 §4.6: an empty ComponentData list.
        abuse_extensions: AppDataDictionary::tls_deserialize_exact([0x00]).unwrap(),
    }
    .tls_serialize_detached()
    .unwrap()
}

/// The context alice's content asserts for a message accepted at
/// `accepted_timestamp`.
fn context(accepted_timestamp: u64) -> ServerFrankingContext {
    ServerFrankingContext {
        sender_uri: IdentifierUri::new(std::str::from_utf8(ALICE).unwrap()).unwrap(),
        room_uri: IdentifierUri::new(ROOM_ID).unwrap(),
        accepted_timestamp,
    }
}

/// A frank over `data` signed with `signing_key` after an HMAC with
/// `hub_key`.
fn forge(
    genuine: &AbusiveMessage,
    salt: &[u8; 16],
    hub_key: [u8; 32],
    signing_key: &[u8],
) -> Frank {
    let context = context(genuine.accepted_timestamp);
    let tag = franking_tag(salt, &genuine.message_content);
    FrankingIntegrityTbs {
        server_frank: server_frank(&HubKey::new(hub_key), &tag, &context).unwrap(),
        franking_signature_ciphersuite: genuine.frank.franking_signature_ciphersuite,
        context,
    }
    .sign(signing_key)
    .unwrap()
}

fn assert_refused(result: Result<Vec<u8>, HubError>, index: usize, name: &str) {
    match result {
        Err(HubError::UnverifiedAbusiveMessage { index: got }) => {
            assert_eq!(got, index, "{name}");
        }
        other => panic!("{name}: {other:?}"),
    }
}

#[tokio::test]
async fn genuine_franks_are_accepted() {
    let mut f = fixture().await;
    let first = f.send(&content([1; 16], "first"), [1; 16]).await;
    let second = f.send(&content([2; 16], "second"), [2; 16]).await;
    assert_eq!(f.report(vec![first.clone(), second]).await.unwrap(), b"");
    assert_eq!(f.report(vec![]).await.unwrap(), b"", "no messages");

    let (status, body) = f.post(ROOM_ID_ENCODED, encode(vec![first])).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.is_empty(), "§5.9: no response body");
}

#[tokio::test]
async fn forged_or_tampered_franks_are_refused() {
    let mut f = fixture().await;
    let salt = [3; 16];
    let genuine = f.send(&content(salt, "genuine"), salt).await;
    let (hub_key, signing_key) = f.secrets().await;
    // The test's own forgery with the real secrets reproduces the hub's
    // frank, so the forgeries below differ only in the key named.
    assert_eq!(forge(&genuine, &salt, hub_key, &signing_key), genuine.frank);

    let other = SignatureKeyPair::generate().unwrap();
    let with = |frank: Frank| AbusiveMessage {
        frank,
        ..genuine.clone()
    };
    let mut flipped = genuine.frank.clone();
    flipped.server_frank[0] ^= 0x01;
    let mut bad_signature = genuine.frank.clone();
    bad_signature.franking_integrity_signature[0] ^= 0x01;
    let cases = [
        ("server_frank flipped", with(flipped)),
        ("signature flipped", with(bad_signature)),
        (
            "right server_frank, wrong signing key",
            with(forge(&genuine, &salt, hub_key, other.signature_key())),
        ),
        (
            "wrong hub_key, right signing key",
            with(forge(&genuine, &salt, [0x5a; 32], &signing_key)),
        ),
        (
            "accepted_timestamp changed",
            AbusiveMessage {
                accepted_timestamp: genuine.accepted_timestamp + 1,
                ..genuine.clone()
            },
        ),
        (
            "content changed",
            AbusiveMessage {
                message_content: content(salt, "altered"),
                ..genuine.clone()
            },
        ),
        (
            "sender changed",
            AbusiveMessage {
                message_content: content_with(
                    salt,
                    "genuine",
                    Some(b"mimi://b.example/u/bob"),
                    Some(ROOM_ID.as_bytes()),
                ),
                ..genuine.clone()
            },
        ),
        (
            "no senderUri",
            AbusiveMessage {
                message_content: content_with(salt, "genuine", None, Some(ROOM_ID.as_bytes())),
                ..genuine.clone()
            },
        ),
        (
            "no roomUri",
            AbusiveMessage {
                message_content: content_with(salt, "genuine", Some(ALICE), None),
                ..genuine.clone()
            },
        ),
        (
            "not MIMI content",
            AbusiveMessage {
                message_content: b"not cbor".to_vec(),
                ..genuine.clone()
            },
        ),
    ];
    for (name, message) in cases {
        assert_refused(f.report(vec![message.clone()]).await, 0, name);
        assert_refused(
            f.report(vec![genuine.clone(), message]).await,
            1,
            &format!("{name}, second"),
        );
    }

    let mut flipped = genuine.frank.clone();
    flipped.server_frank[31] ^= 0x80;
    let (status, _) = f.post(ROOM_ID_ENCODED, encode(vec![with(flipped)])).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn unknown_room_and_undecodable_report() {
    let f = fixture().await;
    let (status, _) = f
        .post("mimi%3A%2F%2Fa.example%2Fr%2Fnope", encode(vec![]))
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = f
        .post(ROOM_ID_ENCODED, [encode(vec![]), vec![0x00]].concat())
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(matches!(
        f.hub
            .report_abuse(ROOM_ID, &from("b.example"), &[0x00])
            .await,
        Err(HubError::InvalidRequest(_))
    ));
}

/// Neither the hub's secrets nor the reported content or note reach the
/// log, at any level.
#[tokio::test]
async fn log_canary() {
    let logs = capture_logs();
    let mut f = fixture().await;
    let salt = [4; 16];
    let data = content(salt, BODY_CANARY);
    let genuine = f.send(&data, salt).await;
    f.report(vec![genuine.clone()]).await.unwrap();
    let mut flipped = genuine.frank.clone();
    flipped.server_frank[0] ^= 0x01;
    assert_refused(
        f.report(vec![AbusiveMessage {
            frank: flipped,
            ..genuine.clone()
        }])
        .await,
        0,
        "canary",
    );

    let text = logs.contents();
    assert!(text.contains("abuse report accepted"), "outcome logged");
    assert!(text.contains("abuse report refused"), "outcome logged");
    let (hub_key, signing_key) = f.secrets().await;
    assert_secret_absent(&text, &hub_key, "hub_key");
    assert_secret_absent(&text, &signing_key, "signature private key");
    assert_secret_absent(&text, &genuine.frank.server_frank, "server_frank");
    assert_secret_absent(&text, &data, "message_content");
    assert!(!text.contains(BODY_CANARY), "message body logged");
    assert!(!text.contains(NOTE_CANARY), "note logged");
}
