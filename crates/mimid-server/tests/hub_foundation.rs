//! Hub foundation (mimid-1wgh.6.25): room creation rules, restart from the
//! stored snapshot, secret handling and HTTP framing.
//!
//! Oracles: alice's mimi-mls Member (a different code path from the hub's
//! Observer) and mls-rs (an independent MLS implementation, decision
//! mimid-1wgh.4.13) supply the expected ratchet tree and GroupContext bytes.

mod common;

use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::body::{Body, Bytes, to_bytes};
use axum::http::{Method, Request, StatusCode, header};
use common::*;
use mimi_protocol::component_id;
use mimid_server::config::BaseUrl;
use mimid_server::directory::Directory;
use mimid_server::http::{MAX_BODY_LEN, router};
use mimid_server::hub::{Hub, HubError};
use mls_rs::client_builder::MlsConfig;
use mls_rs::crypto::SignaturePublicKey;
use mls_rs::extension::ExtensionType;
use mls_rs::extension::built_in::ExternalSendersExt;
use mls_rs::identity::SigningIdentity;
use mls_rs::identity::basic::{BasicCredential, BasicIdentityProvider};
use mls_rs::mls_rs_codec::MlsEncode;
use mls_rs::time::MlsTime;
use mls_rs::{CipherSuite, CipherSuiteProvider, Client, CryptoProvider, Extension, ExtensionList};
use mls_rs_crypto_rustcrypto::RustCryptoProvider;
use tower::ServiceExt;

/// RFC 9420 §17.1: ciphersuite 0x0001.
const SUITE_1: CipherSuite = CipherSuite::CURVE25519_AES128;
/// mls-extensions-10 §4.6: the `app_data_dictionary` extension type.
const APP_DATA_DICTIONARY: ExtensionType = ExtensionType::new(0x0006);
/// 2000-01-01T00:00:00Z. The expired KeyPackage is valid for one day from
/// here.
const EXPIRED_NOT_BEFORE: u64 = 946_684_800;
const ONE_DAY: Duration = Duration::from_secs(24 * 60 * 60);

async fn create_valid_room(hub: &Hub, room_id: &str, group_id: &[u8]) {
    let group = build_group(&GroupSpec::valid_for(hub), group_id);
    hub.create_room(room_id, ALICE, &group.group_info, &group.ratchet_tree)
        .await
        .unwrap();
}

#[tokio::test]
async fn restart_rebuilds_identical_public_state() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("mimid.sqlite");
    let (store, hub) = open_hub(&path).await;
    let group = build_group(&GroupSpec::valid_for(&hub), b"group-restart");
    hub.create_room(ROOM_ID, ALICE, &group.group_info, &group.ratchet_tree)
        .await
        .unwrap();
    let before = hub.public_state(ROOM_ID).await.unwrap();
    assert_eq!(before.epoch, 1);
    assert_eq!(before.ratchet_tree, group.ratchet_tree, "Member's tree");
    let key = *hub.signature_public_key();
    close_hub(store, hub).await;

    let (store, hub) = open_hub(&path).await;
    assert_eq!(*hub.signature_public_key(), key, "hub key reloaded");
    let after = hub.public_state(ROOM_ID).await.unwrap();
    assert_eq!(after.group_context, before.group_context);
    assert_eq!(after.ratchet_tree, before.ratchet_tree);
    assert_eq!(after.epoch, before.epoch);

    let rooms = store.rooms().await.unwrap();
    assert_eq!(rooms.len(), 1);
    assert_eq!(rooms[0].room_id, ROOM_ID);
    assert_eq!(rooms[0].group_id, b"group-restart");
    assert_eq!(rooms[0].group_info, group.group_info, "stored as received");
    assert_eq!(
        rooms[0].ratchet_tree, group.ratchet_tree,
        "stored as received"
    );
    assert_eq!(rooms[0].created_at, 1_700_000_000_000, "injected clock");
    close_hub(store, hub).await;
}

/// An mls-rs client on suite 1 for `name` that accepts the
/// `app_data_dictionary` extension, whose KeyPackages last `lifetime`.
fn mls_rs_client(name: &[u8], lifetime: Duration) -> Client<impl MlsConfig + use<>> {
    let crypto = RustCryptoProvider::default();
    let suite = crypto.cipher_suite_provider(SUITE_1).unwrap();
    let (secret, public) = suite.signature_key_generate().unwrap();
    Client::builder()
        .identity_provider(BasicIdentityProvider)
        .crypto_provider(crypto)
        .extension_type(APP_DATA_DICTIONARY)
        .key_package_lifetime(lifetime)
        .signing_identity(
            SigningIdentity::new(
                BasicCredential::new(name.to_vec()).into_credential(),
                public,
            ),
            secret,
            SUITE_1,
        )
        .build()
}

/// mls-rs builds a mimid room whose tree holds a leaf whose lifetime ended
/// on 2000-01-02 (RFC 9420 §7.3). The hub accepts it, and after a restart
/// still agrees with mls-rs byte for byte: rebuilding skips the lifetime
/// check (decisions mimid-1wgh.4.38, mimid-1wgh.6.6).
#[tokio::test]
async fn room_with_expired_leaf_loads_after_restart() {
    const CAROL: &[u8] = b"mimi://b.example/u/carol";
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("mimid.sqlite");
    let (store, hub) = open_hub(&path).await;
    let key = *hub.signature_public_key();

    let mut context_extensions = ExtensionList::new();
    context_extensions
        .set_from(ExternalSendersExt::new(vec![SigningIdentity::new(
            BasicCredential::new(HUB_IDENTITY.to_vec()).into_credential(),
            SignaturePublicKey::from(key.to_vec()),
        )]))
        .unwrap();
    context_extensions.set(Extension::new(
        APP_DATA_DICTIONARY,
        app_data_dictionary(&[
            (
                component_id::FRANKING_AGENT,
                &franking_agent(&key, HUB_IDENTITY),
            ),
            (
                component_id::PARTICIPANT_LIST,
                &participant_list(&[ALICE, CAROL]),
            ),
        ]),
    ));
    let mut alice = mls_rs_client(ALICE, 84 * ONE_DAY)
        .create_group(context_extensions, Default::default(), None)
        .unwrap();
    let carol_key_package = mls_rs_client(CAROL, ONE_DAY)
        .generate_key_package_message(
            Default::default(),
            Default::default(),
            Some(MlsTime::from(EXPIRED_NOT_BEFORE)),
        )
        .unwrap();
    let not_after = carol_key_package
        .as_key_package()
        .unwrap()
        .expiration()
        .unwrap()
        .seconds_since_epoch();
    assert_eq!(
        not_after,
        EXPIRED_NOT_BEFORE + ONE_DAY.as_secs(),
        "expired leaf"
    );
    alice
        .commit_builder()
        .commit_time(MlsTime::from(EXPIRED_NOT_BEFORE + 60))
        .add_member(carol_key_package)
        .unwrap()
        .build()
        .unwrap();
    alice.apply_pending_commit().unwrap();
    let group_info = alice.group_info_message(false).unwrap().to_bytes().unwrap();
    let tree = alice.export_tree().to_bytes().unwrap();
    let expected_context = alice.context().mls_encode_to_vec().unwrap();

    hub.create_room(ROOM_ID, ALICE, &group_info, &tree)
        .await
        .unwrap();
    let before = hub.public_state(ROOM_ID).await.unwrap();
    assert_eq!(before.group_context, expected_context);
    assert_eq!(before.ratchet_tree, tree);
    close_hub(store, hub).await;

    let (store, hub) = open_hub(&path).await;
    let after = hub.public_state(ROOM_ID).await.unwrap();
    assert_eq!(after.epoch, alice.current_epoch());
    assert_eq!(after.group_context, expected_context);
    assert_eq!(after.ratchet_tree, tree);
    close_hub(store, hub).await;
}

/// Builds a group per `spec`, offers it to a fresh hub with `creator`, and
/// returns the error. Checks that nothing was stored.
async fn rejected(spec: impl FnOnce(&Hub) -> GroupSpec, creator: &[u8]) -> HubError {
    let dir = tempfile::tempdir().unwrap();
    let (store, hub) = open_hub(&dir.path().join("mimid.sqlite")).await;
    let group = build_group(&spec(&hub), b"group-rejected");
    let err = hub
        .create_room(ROOM_ID, creator, &group.group_info, &group.ratchet_tree)
        .await
        .unwrap_err();
    assert!(store.rooms().await.unwrap().is_empty(), "nothing stored");
    assert!(matches!(
        hub.public_state(ROOM_ID).await,
        Err(HubError::NoSuchRoom)
    ));
    close_hub(store, hub).await;
    err
}

#[tokio::test]
async fn create_room_rejects_wrong_external_senders() {
    let other = [0x42; 32];
    for senders in [vec![], vec![other], vec![[0; 32]]] {
        let err = rejected(
            |hub| GroupSpec {
                external_senders: senders.clone(),
                ..GroupSpec::valid_for(hub)
            },
            ALICE,
        )
        .await;
        assert!(matches!(err, HubError::WrongExternalSenders), "{err:?}");
    }
    // The hub's key under another credential (decision mimid-1wgh.6.35).
    for identity in [&b"mimi://b.example"[..], b"a.example", b"hub.example"] {
        let err = rejected(
            |hub| GroupSpec {
                sender_identity: identity.to_vec(),
                ..GroupSpec::valid_for(hub)
            },
            ALICE,
        )
        .await;
        assert!(matches!(err, HubError::WrongExternalSenders), "{err:?}");
    }
    // The hub's key plus a follower's (protocol-06 §7.4 MAY; decision
    // mimid-1wgh.4.21 allows only the hub in v1).
    let err = rejected(
        |hub| GroupSpec {
            external_senders: vec![*hub.signature_public_key(), other],
            ..GroupSpec::valid_for(hub)
        },
        ALICE,
    )
    .await;
    assert!(matches!(err, HubError::WrongExternalSenders), "{err:?}");
}

#[tokio::test]
async fn create_room_rejects_missing_or_wrong_franking_agent() {
    let err = rejected(
        |hub| GroupSpec {
            franking_agent: None,
            ..GroupSpec::valid_for(hub)
        },
        ALICE,
    )
    .await;
    assert!(matches!(err, HubError::MissingFrankingAgent), "{err:?}");

    let err = rejected(
        |hub| GroupSpec {
            franking_agent: Some(franking_agent(&[0x42; 32], HUB_IDENTITY)),
            ..GroupSpec::valid_for(hub)
        },
        ALICE,
    )
    .await;
    assert!(matches!(err, HubError::WrongFrankingAgent), "{err:?}");

    // The hub's key under another credential (decision mimid-1wgh.6.35).
    for identity in [&b"mimi://b.example"[..], b"a.example", b"mimi://a.example/"] {
        let err = rejected(
            |hub| GroupSpec {
                franking_agent: Some(franking_agent(hub.signature_public_key(), identity)),
                ..GroupSpec::valid_for(hub)
            },
            ALICE,
        )
        .await;
        assert!(matches!(err, HubError::WrongFrankingAgent), "{err:?}");
    }

    let err = rejected(
        |hub| GroupSpec {
            franking_agent: Some(vec![0x20, 0x01]),
            ..GroupSpec::valid_for(hub)
        },
        ALICE,
    )
    .await;
    assert!(matches!(err, HubError::WrongFrankingAgent), "{err:?}");
}

#[tokio::test]
async fn create_room_rejects_creator_not_in_participant_list() {
    let err = rejected(GroupSpec::valid_for, b"mimi://a.example/u/dave").await;
    assert!(matches!(err, HubError::CreatorNotListed), "{err:?}");
}

#[tokio::test]
async fn create_room_rejects_member_not_in_participant_list() {
    let err = rejected(
        |hub| GroupSpec {
            participant_list: Some(participant_list(&[ALICE])),
            ..GroupSpec::valid_for(hub)
        },
        ALICE,
    )
    .await;
    assert!(
        matches!(err, HubError::MemberNotListed { leaf_index: 1 }),
        "{err:?}"
    );
}

#[tokio::test]
async fn create_room_rejects_missing_or_malformed_participant_list() {
    let err = rejected(
        |hub| GroupSpec {
            participant_list: None,
            ..GroupSpec::valid_for(hub)
        },
        ALICE,
    )
    .await;
    assert!(matches!(err, HubError::MissingParticipantList), "{err:?}");

    let mut trailing = participant_list(&[ALICE, BOB]);
    trailing.push(0x00);
    let err = rejected(
        |hub| GroupSpec {
            participant_list: Some(trailing),
            ..GroupSpec::valid_for(hub)
        },
        ALICE,
    )
    .await;
    assert!(
        matches!(err, HubError::InvalidParticipantList(_)),
        "{err:?}"
    );
}

#[tokio::test]
async fn create_room_rejects_bad_ids_and_duplicates() {
    let dir = tempfile::tempdir().unwrap();
    let (store, hub) = open_hub(&dir.path().join("mimid.sqlite")).await;
    let group = build_group(&GroupSpec::valid_for(&hub), b"group-dup");
    let create = |room_id: &'static str| {
        hub.create_room(room_id, ALICE, &group.group_info, &group.ratchet_tree)
    };
    assert!(matches!(
        create("mimi://b.example/r/one").await,
        Err(HubError::ForeignRoom)
    ));
    assert!(matches!(create("").await, Err(HubError::InvalidRoomId)));
    create(ROOM_ID).await.unwrap();
    assert!(matches!(create(ROOM_ID).await, Err(HubError::RoomExists)));
    assert!(matches!(
        create("mimi://a.example/r/two").await,
        Err(HubError::GroupExists)
    ));
    let err = hub
        .create_room("mimi://a.example/r/three", ALICE, b"\x00\x01", &[])
        .await
        .unwrap_err();
    assert!(matches!(err, HubError::InvalidGroupInfo(_)), "{err:?}");
    assert_eq!(store.rooms().await.unwrap().len(), 1);
    close_hub(store, hub).await;
}

#[tokio::test]
async fn hub_and_stored_secret_debug_redact_secrets() {
    let dir = tempfile::tempdir().unwrap();
    let (store, hub) = open_hub(&dir.path().join("mimid.sqlite")).await;
    let secret = store.hub_secret().await.unwrap().unwrap();
    for text in [
        format!("{hub:?}"),
        format!("{secret:?}"),
        format!("{hub:#?}"),
    ] {
        assert_secret_absent(&text, &secret.signature_private_key, "signing key");
        assert_secret_absent(&text, &secret.hub_key, "hub_key");
    }
    close_hub(store, hub).await;
}

/// Every `tracing` event at TRACE, from create_room through a restart and
/// a stub request, is free of the hub's signing key and `hub_key`.
#[tokio::test]
async fn trace_logs_never_contain_hub_secrets() {
    let logs = capture_logs();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("mimid.sqlite");
    let (store, hub) = open_hub(&path).await;
    create_valid_room(&hub, ROOM_ID, b"group-canary").await;
    close_hub(store, hub).await;
    let (store, hub) = open_hub(&path).await;
    let hub = Arc::new(hub);
    let (status, _, _) = send(
        &app(Arc::clone(&hub)),
        Method::POST,
        &format!("/v1/update/{ROOM_ID_ENCODED}"),
        Some("mimi@b.example"),
        vec![1, 2, 3],
    )
    .await;
    assert_eq!(status, StatusCode::NOT_IMPLEMENTED);

    let secret = store.hub_secret().await.unwrap().unwrap();
    let text = logs.contents();
    assert!(text.contains("room created"), "capture works: {text}");
    assert!(text.contains("hub rooms rebuilt"), "capture works: {text}");
    assert!(
        text.contains("TRACE") || text.contains("DEBUG"),
        "verbose levels captured"
    );
    assert_secret_absent(&text, &secret.signature_private_key, "signing key");
    assert_secret_absent(&text, &secret.hub_key, "hub_key");
    drop(hub);
    store.close().await;
}

fn app(hub: Arc<Hub>) -> Router {
    let base = BaseUrl::try_from("https://mimi.a.example".to_owned()).unwrap();
    router(Directory::new(&base), hub)
}

async fn send(
    app: &Router,
    method: Method,
    uri: &str,
    from: Option<&str>,
    body: Vec<u8>,
) -> (StatusCode, Option<String>, Bytes) {
    let mut request = Request::builder().method(method).uri(uri);
    if let Some(from) = from {
        request = request.header(header::FROM, from);
    }
    let response = app
        .clone()
        .oneshot(request.body(Body::from(body)).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let content_type = response
        .headers()
        .get(header::CONTENT_TYPE)
        .map(|value| value.to_str().unwrap().to_owned());
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    (status, content_type, body)
}

#[tokio::test]
async fn http_routes_stubs_and_status_mapping() {
    let dir = tempfile::tempdir().unwrap();
    let (store, hub) = open_hub(&dir.path().join("mimid.sqlite")).await;
    create_valid_room(&hub, ROOM_ID, b"group-http").await;
    let hub = Arc::new(hub);
    let app = app(Arc::clone(&hub));
    let from = Some("mimi@b.example");

    for (endpoint, name) in [
        ("update", "update"),
        ("submitMessage", "submitMessage"),
        ("groupInfo", "groupInfo"),
        ("reportAbuse", "reportAbuse"),
    ] {
        let uri = format!("/v1/{endpoint}/{ROOM_ID_ENCODED}");
        let (status, _, body) = send(&app, Method::POST, &uri, from, vec![0]).await;
        assert_eq!(status, StatusCode::NOT_IMPLEMENTED, "{uri}");
        assert_eq!(body, format!("{name} is not implemented"), "{uri}");

        let unknown = format!("/v1/{endpoint}/mimi%3A%2F%2Fa.example%2Fr%2Fnope");
        let (status, _, _) = send(&app, Method::POST, &unknown, from, vec![0]).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{unknown}");

        let (status, _, _) = send(&app, Method::POST, &uri, None, vec![0]).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{uri} without From");

        let (status, _, _) = send(&app, Method::GET, &uri, from, vec![]).await;
        assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED, "{uri}");
    }

    let (status, _, body) = send(
        &app,
        Method::POST,
        "/v1/keyMaterial/mimi%3A%2F%2Fa.example%2Fu%2Falice",
        from,
        vec![0],
    )
    .await;
    assert_eq!(status, StatusCode::NOT_IMPLEMENTED);
    assert_eq!(body, "keyMaterial is not implemented");

    // The unencoded URI spans several path segments and matches no route.
    let (status, _, _) = send(
        &app,
        Method::POST,
        "/v1/update/mimi://a.example/r/one",
        from,
        vec![0],
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    // Invalid UTF-8 after percent-decoding.
    let (status, _, _) = send(&app, Method::POST, "/v1/update/%FF", from, vec![0]).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // The directory is still served.
    let (status, content_type, _) = send(
        &app,
        Method::GET,
        "/.well-known/mimi-protocol-directory",
        None,
        vec![],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(content_type.as_deref(), Some("application/json"));
    drop(app);
    drop(hub);
    store.close().await;
}

#[tokio::test]
async fn http_body_cap_is_enforced() {
    let dir = tempfile::tempdir().unwrap();
    let (store, hub) = open_hub(&dir.path().join("mimid.sqlite")).await;
    create_valid_room(&hub, ROOM_ID, b"group-cap").await;
    let hub = Arc::new(hub);
    let app = app(Arc::clone(&hub));
    let uri = format!("/v1/update/{ROOM_ID_ENCODED}");
    let from = Some("mimi@b.example");

    let (status, _, _) = send(&app, Method::POST, &uri, from, vec![0; MAX_BODY_LEN]).await;
    assert_eq!(status, StatusCode::NOT_IMPLEMENTED, "at the cap");
    let (status, _, _) = send(&app, Method::POST, &uri, from, vec![0; MAX_BODY_LEN + 1]).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE, "past the cap");
    let unknown = "/v1/submitMessage/mimi%3A%2F%2Fa.example%2Fr%2Fnope";
    let (status, _, _) = send(&app, Method::POST, unknown, from, vec![0; MAX_BODY_LEN + 1]).await;
    assert_eq!(
        status,
        StatusCode::PAYLOAD_TOO_LARGE,
        "cap applies before lookup"
    );
    drop(app);
    drop(hub);
    store.close().await;
}
