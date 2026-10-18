//! protocol-06 §5.2 keyMaterial proxied by the hub (bead mimid-1wgh.6.31;
//! decision mimid-1wgh.6.20).
//!
//! The oracle is a mock target provider served by axum in-process. Its
//! response is hand-assembled from the §5.2 struct around a KeyPackage that
//! mls-rs generated, and the hub must relay it byte for byte. Refusals are
//! compared with a hand-encoded `noConsent` response.

#[allow(dead_code, reason = "each test binary uses part of the helpers")]
mod common;
#[allow(dead_code, reason = "each test binary uses part of the helpers")]
#[path = "common/update.rs"]
mod update;

use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::{Body, Bytes, to_bytes};
use axum::extract::State;
use axum::http::{HeaderMap, Request, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use common::*;
use mimi_mls::label::SignatureKeyPair;
use mimi_mls::member::{ExternalSender, Member};
use mimi_mls::tls_codec::{Deserialize, Serialize};
use mimi_mls::wire::{CipherSuite, Credential, RequiredCapabilities, SignaturePublicKey};
use mimi_mls::{Identity, KeyPackageKind};
use mimi_protocol::component_id::{FRANKING_AGENT, PARTICIPANT_LIST};
use mimi_protocol::{
    ClientKeyMaterial, IdentifierUri, KeyMaterialRequest, KeyMaterialRequestTbs,
    KeyMaterialResponse, KeyMaterialUserCode, ParticipantListData, Protocol, UserRolePair,
};
use mimi_room_policy::component_id::{BASE_ROOM_POLICY, ROLES_LIST};
use mimi_room_policy::{Capability, Role, RoleData};
use mimid_server::config::{BaseUrl, Domain};
use mimid_server::directory::Directory;
use mimid_server::follower::Follower;
use mimid_server::http::router;
use mimid_server::hub::{Hub, HubError};
use mimid_server::peer::{PeerClient, PeerError};
use tower::ServiceExt;

/// A listed user whose role holds `canAddParticipant`; a member.
const ADDER: &[u8] = BOB;
/// A listed user whose role lacks `canAddParticipant`.
const PLAIN: &[u8] = b"mimi://b.example/u/dave";
/// A user not in the participant list.
const STRANGER: &[u8] = b"mimi://b.example/u/mallory";
/// The target user, at the mock provider.
const CATHY: &str = "mimi://c.example/u/cathy";
/// [`CATHY`] percent-encoded by hand (RFC 3986 §2.1; decision
/// mimid-1wgh.5.18).
const CATHY_ENCODED: &str = "mimi%3A%2F%2Fc.example%2Fu%2Fcathy";
const TARGET_DOMAIN: &str = "c.example";

const ROLE_ADDER: u32 = 2;
const ROLE_PLAIN: u32 = 3;

fn domain_of(name: &str) -> Domain {
    Domain::try_from(name.to_owned()).unwrap()
}

/// RFC 9420 §2.1.2 variable-length vector header for `len` bytes.
fn varint(len: usize) -> Vec<u8> {
    match len {
        0..=63 => vec![u8::try_from(len).unwrap()],
        64..=16383 => (u16::try_from(len).unwrap() | 0x4000)
            .to_be_bytes()
            .to_vec(),
        _ => (u32::try_from(len).unwrap() | 0x8000_0000)
            .to_be_bytes()
            .to_vec(),
    }
}

/// `opaque<V>` holding `bytes`.
fn opaque(bytes: &[u8]) -> Vec<u8> {
    [varint(bytes.len()), bytes.to_vec()].concat()
}

/// The hand-encoded `noConsent` response for `user` (protocol-06 §5.2):
/// protocol mls10 (1), userStatus noConsent (5), userUri, empty clients.
fn no_consent(user: &str) -> Vec<u8> {
    [&[0x01, 0x05][..], &opaque(user.as_bytes()), &[0x00]].concat()
}

fn role(role_index: u32, role_name: &str, role_capabilities: Vec<Capability>) -> Role {
    Role {
        role_index,
        role_name: role_name.to_owned(),
        role_description: String::new(),
        role_capabilities,
        minimum_participants_constraint: 0,
        maximum_participants_constraint: None,
        minimum_active_participants_constraint: 0,
        maximum_active_participants_constraint: None,
        authorized_role_changes: vec![],
    }
}

/// alice creates a room listing alice and bob as adders, dave as plain,
/// adds bob, and hosts it on `hub` as [`ROOM_ID`].
async fn create_room(hub: &Hub) {
    let key = *hub.signature_public_key();
    let alice = Identity::generate(ALICE, mimi_mls::Store::open_in_memory().unwrap()).unwrap();
    let bob = Identity::generate(BOB, mimi_mls::Store::open_in_memory().unwrap()).unwrap();
    let roles = RoleData {
        roles: vec![
            role(1, "banned", vec![]),
            role(
                ROLE_ADDER,
                "adder",
                vec![
                    Capability::CAN_ADD_PARTICIPANT,
                    Capability::CAN_SEND_MESSAGE,
                ],
            ),
            role(ROLE_PLAIN, "plain", vec![Capability::CAN_SEND_MESSAGE]),
        ],
    };
    let entry = |user: &[u8], role_index| UserRolePair {
        user: user.to_vec(),
        role_index,
    };
    let participants = ParticipantListData {
        participants: vec![
            entry(ALICE, ROLE_ADDER),
            entry(ADDER, ROLE_ADDER),
            entry(PLAIN, ROLE_PLAIN),
        ],
    };
    let components = [
        (FRANKING_AGENT, franking_agent(&key, HUB_IDENTITY)),
        (
            PARTICIPANT_LIST,
            participants.tls_serialize_detached().unwrap(),
        ),
        (ROLES_LIST, roles.tls_serialize_detached().unwrap()),
        (BASE_ROOM_POLICY, base_room_policy()),
    ];
    let senders = [ExternalSender {
        signature_key: key.to_vec(),
        identity: HUB_IDENTITY.to_vec(),
    }];
    let mut member = Member::create(&alice, b"group-key-material", &senders, &components).unwrap();
    let key_package = bob.key_package(KeyPackageKind::OneTime).unwrap();
    let bundle = member
        .commit(&alice, &[&key_package], &[], &[], no_components)
        .unwrap();
    member.merge_pending_commit(&alice).unwrap();
    hub.create_room(
        ROOM_ID,
        ALICE,
        &bundle.group_info,
        &member.ratchet_tree().unwrap(),
    )
    .await
    .unwrap();
}

/// What a keyMaterial request asserts.
struct Ask<'a> {
    requesting_user: &'a [u8],
    credential_identity: &'a [u8],
    target_user: &'a str,
    room_id: &'a str,
}

impl Default for Ask<'_> {
    fn default() -> Self {
        Self {
            requesting_user: ADDER,
            credential_identity: ADDER,
            target_user: CATHY,
            room_id: ROOM_ID,
        }
    }
}

/// A KeyMaterialRequest signed with a fresh Ed25519 key, the scheme of
/// suite 1 (decision mimid-1wgh.5.61).
fn request(ask: &Ask<'_>) -> Vec<u8> {
    let pair = SignatureKeyPair::generate().unwrap();
    // RFC 9420 §5.1.1, §5.3 (basic = 1), §11.1 (three empty lists), §17.1.
    let key = SignaturePublicKey::tls_deserialize_exact(opaque(pair.verification_key())).unwrap();
    let credential = Credential::tls_deserialize_exact(
        [&[0x00, 0x01][..], &opaque(ask.credential_identity)].concat(),
    )
    .unwrap();
    let uri = |bytes: &[u8]| IdentifierUri::new(std::str::from_utf8(bytes).unwrap()).unwrap();
    KeyMaterialRequestTbs {
        protocol: Protocol::Mls10,
        requesting_user: uri(ask.requesting_user),
        target_user: uri(ask.target_user.as_bytes()),
        room_id: uri(ask.room_id.as_bytes()),
        acceptable_ciphersuites: vec![CipherSuite::tls_deserialize_exact([0x00, 0x01]).unwrap()],
        required_capabilities: RequiredCapabilities::tls_deserialize_exact([0x00, 0x00, 0x00])
            .unwrap(),
        requester_signature_key: key,
        requester_credential: credential,
    }
    .sign(pair.signature_key())
    .unwrap()
    .tls_serialize_detached()
    .unwrap()
}

/// A bare KeyPackage (RFC 9420 §10) that mls-rs generated for cathy.
fn mls_rs_key_package() -> Vec<u8> {
    let message = update::mls_rs_client(CATHY.as_bytes())
        .generate_key_package_message(Default::default(), Default::default(), None)
        .unwrap()
        .to_bytes()
        .unwrap();
    // RFC 9420 §6: version mls10 (0x0001), wire_format mls_key_package (0x0005).
    assert_eq!(message[..4], [0x00, 0x01, 0x00, 0x05]);
    message[4..].to_vec()
}

/// A `success` KeyMaterialResponse for cathy with one client, hand-assembled
/// from the protocol-06 §5.2 structs.
fn success_response(key_package: &[u8]) -> Vec<u8> {
    let client = [
        &[0x00][..],                                  // clientStatus success
        &opaque(b"mimi://c.example/u/cathy/c/phone"), // clientUri
        key_package,                                  // keyPackage
    ]
    .concat();
    [
        &[0x01, 0x00][..],         // protocol mls10, userStatus success
        &opaque(CATHY.as_bytes()), // userUri
        &opaque(&client),          // clients<V>
    ]
    .concat()
}

/// A reply the mock provider gives to one keyMaterial request.
#[derive(Clone)]
struct Reply {
    status: StatusCode,
    body: Vec<u8>,
}

/// One keyMaterial request the mock provider received.
#[derive(Debug, Clone)]
struct Received {
    raw_path: String,
    from: Vec<String>,
    host: Vec<String>,
    content_type: Vec<String>,
    body: Vec<u8>,
}

#[derive(Clone)]
struct ProviderState {
    directory: Arc<String>,
    replies: Arc<Mutex<VecDeque<Reply>>>,
    received: Arc<Mutex<Vec<Received>>>,
}

/// The target provider: serves a hand-written §5.1 directory and answers
/// keyMaterial requests from its script.
struct Provider {
    base: BaseUrl,
    state: ProviderState,
}

impl Provider {
    async fn start(replies: Vec<Reply>) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let directory = r#"{
          "keyMaterial": "BASE/v1/keyMaterial/{targetUser}",
          "update": "BASE/v1/update/{roomId}",
          "notify": "BASE/v1/notify/{roomId}",
          "submitMessage": "BASE/v1/submitMessage/{roomId}",
          "groupInfo": "BASE/v1/groupInfo/{roomId}",
          "requestConsent": "BASE/v1/requestConsent/{targetDomain}",
          "updateConsent": "BASE/v1/updateConsent/{requesterDomain}",
          "identifierQuery": "BASE/v1/identifierQuery/{domain}",
          "reportAbuse": "BASE/v1/reportAbuse/{roomId}",
          "proxyDownload": "BASE/v1/proxyDownload/{downloadUrl}"
        }"#
        .replace("BASE", &base);
        let state = ProviderState {
            directory: Arc::new(directory),
            replies: Arc::new(Mutex::new(replies.into())),
            received: Arc::default(),
        };
        let app = Router::new()
            .route("/.well-known/mimi-protocol-directory", get(serve_directory))
            .route("/v1/keyMaterial/{targetUser}", post(serve_key_material))
            .with_state(state.clone());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        Self {
            base: BaseUrl::try_from(base).unwrap(),
            state,
        }
    }

    fn received(&self) -> Vec<Received> {
        self.state.received.lock().unwrap().clone()
    }
}

async fn serve_directory(State(state): State<ProviderState>) -> Response {
    (
        [(header::CONTENT_TYPE, "application/json")],
        state.directory.as_str().to_owned(),
    )
        .into_response()
}

fn values(headers: &HeaderMap, name: header::HeaderName) -> Vec<String> {
    headers
        .get_all(name)
        .iter()
        .map(|v| v.to_str().unwrap().to_owned())
        .collect()
}

async fn serve_key_material(
    State(state): State<ProviderState>,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    state.received.lock().unwrap().push(Received {
        raw_path: uri.path().to_owned(),
        from: values(&headers, header::FROM),
        host: values(&headers, header::HOST),
        content_type: values(&headers, header::CONTENT_TYPE),
        body: body.to_vec(),
    });
    let reply = state.replies.lock().unwrap().pop_front().unwrap();
    (reply.status, reply.body).into_response()
}

/// A hub hosting [`ROOM_ID`] that reaches `provider` as `c.example`.
struct Fixture {
    _dir: tempfile::TempDir,
    hub: Arc<Hub>,
    follower: Arc<Follower>,
    provider: Provider,
}

async fn fixture(replies: Vec<Reply>) -> Fixture {
    let provider = Provider::start(replies).await;
    let dir = tempfile::tempdir().unwrap();
    let (store, hub) = open_hub(&dir.path().join("mimid.sqlite")).await;
    let follower = Follower::new(domain(), store, Arc::new(FixedClock(0)));
    let peers = BTreeMap::from([(domain_of(TARGET_DOMAIN), provider.base.clone())]);
    let hub = hub.with_peers(PeerClient::new(&domain(), peers).unwrap());
    create_room(&hub).await;
    Fixture {
        _dir: dir,
        hub: Arc::new(hub),
        follower: Arc::new(follower),
        provider,
    }
}

impl Fixture {
    async fn ask(&self, from: &str, body: &[u8]) -> Result<Vec<u8>, HubError> {
        self.hub.key_material(CATHY, &domain_of(from), body).await
    }

    /// Sends `body` through the HTTP router as `mimi@<from>`.
    async fn post(&self, target_encoded: &str, from: &str, body: Vec<u8>) -> (StatusCode, Bytes) {
        let base = BaseUrl::try_from("https://a.example".to_owned()).unwrap();
        let response = router(
            Directory::new(&base),
            Arc::clone(&self.hub),
            Arc::clone(&self.follower),
        )
        .oneshot(
            Request::post(format!("/v1/keyMaterial/{target_encoded}"))
                .header(header::FROM, format!("mimi@{from}"))
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
        let status = response.status();
        (
            status,
            to_bytes(response.into_body(), usize::MAX).await.unwrap(),
        )
    }
}

fn ok(body: Vec<u8>) -> Reply {
    Reply {
        status: StatusCode::OK,
        body,
    }
}

#[tokio::test]
async fn response_is_relayed_verbatim() {
    let key_package = mls_rs_key_package();
    let response = success_response(&key_package);
    // The protocol codec agrees with the hand assembly: decode, compare,
    // re-encode byte-identically.
    let decoded = KeyMaterialResponse::tls_deserialize_exact(response.as_slice()).unwrap();
    assert_eq!(decoded.user_status, KeyMaterialUserCode::Success);
    assert_eq!(decoded.user_uri.as_str(), CATHY);
    let [
        ClientKeyMaterial::Success {
            key_package: kp, ..
        },
    ] = decoded.clients.as_slice()
    else {
        panic!("one successful client");
    };
    assert_eq!(kp.as_bytes(), key_package);
    assert_eq!(decoded.tls_serialize_detached().unwrap(), response);

    let f = fixture(vec![ok(response.clone()), ok(response.clone())]).await;
    let body = request(&Ask::default());
    assert_eq!(f.ask("b.example", &body).await.unwrap(), response);

    let received = f.provider.received();
    assert_eq!(received.len(), 1);
    assert_eq!(
        received[0].raw_path,
        format!("/v1/keyMaterial/{CATHY_ENCODED}")
    );
    assert_eq!(received[0].body, body, "request forwarded as received");
    assert_eq!(received[0].from, ["mimi@a.example"]);
    assert_eq!(received[0].host, [TARGET_DOMAIN]);
    assert_eq!(received[0].content_type, ["application/octet-stream"]);

    let (status, relayed) = f.post(CATHY_ENCODED, "b.example", body).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(relayed, response);
}

#[tokio::test]
async fn requester_mismatches_are_refused_with_no_consent() {
    let f = fixture(vec![]).await;
    let cases = [
        (
            "requestingUser is not the credential identity",
            Ask {
                credential_identity: PLAIN,
                ..Ask::default()
            },
            "b.example",
        ),
        (
            "requestingUser impersonates an adder",
            Ask {
                requesting_user: ADDER,
                credential_identity: STRANGER,
                ..Ask::default()
            },
            "b.example",
        ),
        (
            "From is not the requester's domain",
            Ask::default(),
            "c.example",
        ),
        ("From is the hub's own domain", Ask::default(), DOMAIN),
        (
            "targetUser is not the path's",
            Ask {
                target_user: "mimi://c.example/u/carl",
                ..Ask::default()
            },
            "b.example",
        ),
    ];
    for (name, ask, from) in cases {
        let response = f.ask(from, &request(&ask)).await.unwrap();
        assert_eq!(response, no_consent(CATHY), "{name}");
        // Decode, then re-encode byte-identically.
        let decoded = KeyMaterialResponse::tls_deserialize_exact(response.as_slice()).unwrap();
        assert_eq!(
            decoded.tls_serialize_detached().unwrap(),
            response,
            "{name}"
        );
    }
    assert!(f.provider.received().is_empty(), "nothing forwarded");
}

#[tokio::test]
async fn tampered_signature_is_refused() {
    let f = fixture(vec![]).await;
    let mut body = request(&Ask::default());
    let last = body.len() - 1;
    body[last] ^= 0x01;
    assert!(KeyMaterialRequest::tls_deserialize_exact(body.as_slice()).is_ok());
    assert_eq!(f.ask("b.example", &body).await.unwrap(), no_consent(CATHY));
    assert!(f.provider.received().is_empty());
}

#[tokio::test]
async fn requester_without_can_add_participant_is_refused() {
    let f = fixture(vec![]).await;
    for user in [PLAIN, STRANGER] {
        let ask = Ask {
            requesting_user: user,
            credential_identity: user,
            ..Ask::default()
        };
        let response = f.ask("b.example", &request(&ask)).await.unwrap();
        assert_eq!(response, no_consent(CATHY), "{user:?}");
    }
    assert!(f.provider.received().is_empty());
}

#[tokio::test]
async fn unknown_or_absent_room_is_404() {
    let f = fixture(vec![]).await;
    for room_id in ["mimi://a.example/r/nope", ""] {
        let ask = Ask {
            room_id,
            ..Ask::default()
        };
        let result = f.ask("b.example", &request(&ask)).await;
        assert!(matches!(result, Err(HubError::NoSuchRoom)), "{room_id:?}");
        let (status, _) = f.post(CATHY_ENCODED, "b.example", request(&ask)).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{room_id:?}");
    }
    assert!(f.provider.received().is_empty());
}

#[tokio::test]
async fn local_target_is_not_implemented() {
    let f = fixture(vec![]).await;
    let alice = std::str::from_utf8(ALICE).unwrap();
    let ask = Ask {
        target_user: alice,
        ..Ask::default()
    };
    let result = f
        .hub
        .key_material(alice, &domain_of("b.example"), &request(&ask))
        .await;
    assert!(
        matches!(result, Err(HubError::NotImplemented(_))),
        "{result:?}"
    );
    let (status, body) = f
        .post(
            "mimi%3A%2F%2Fa.example%2Fu%2Falice",
            "b.example",
            request(&ask),
        )
        .await;
    assert_eq!(status, StatusCode::NOT_IMPLEMENTED);
    assert_eq!(body, "keyMaterial for local users is not implemented");
    assert!(f.provider.received().is_empty());
}

#[tokio::test]
async fn undecodable_request_is_400() {
    let f = fixture(vec![]).await;
    let mut body = request(&Ask::default());
    body.push(0x00);
    assert!(matches!(
        f.ask("b.example", &body).await,
        Err(HubError::InvalidRequest(_))
    ));
    let (status, _) = f.post(CATHY_ENCODED, "b.example", body).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn target_provider_failures_are_502() {
    let undecodable = [success_response(&mls_rs_key_package()), vec![0x00]].concat();
    let f = fixture(vec![
        Reply {
            status: StatusCode::SERVICE_UNAVAILABLE,
            body: vec![],
        },
        ok(undecodable.clone()),
        ok(undecodable),
    ])
    .await;
    let result = f.ask("b.example", &request(&Ask::default())).await;
    assert!(
        matches!(
            result,
            Err(HubError::Peer(PeerError::Rejected { status: 503, .. }))
        ),
        "{result:?}"
    );
    let result = f.ask("b.example", &request(&Ask::default())).await;
    assert!(
        matches!(result, Err(HubError::InvalidPeerResponse(_))),
        "{result:?}"
    );
    let (status, _) = f
        .post(CATHY_ENCODED, "b.example", request(&Ask::default()))
        .await;
    assert_eq!(status, StatusCode::BAD_GATEWAY);
}

#[tokio::test]
async fn hub_without_peer_client_cannot_forward() {
    let dir = tempfile::tempdir().unwrap();
    let (_store, hub) = open_hub(&dir.path().join("mimid.sqlite")).await;
    create_room(&hub).await;
    let result = hub
        .key_material(CATHY, &domain_of("b.example"), &request(&Ask::default()))
        .await;
    assert!(
        matches!(result, Err(HubError::Peer(PeerError::UnknownPeer(_)))),
        "{result:?}"
    );
}
