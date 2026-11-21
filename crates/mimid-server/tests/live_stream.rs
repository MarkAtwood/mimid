//! The live stream's route (docs/design/binary-live-stream.md): the
//! switch, the hello and its token check (the stream's row of the
//! AGENTS.md boundary table: a wrong identity is refused), the limits and
//! hostile frames, and the requests that need no MLS group. Scenarios with
//! groups run through agents in crates/mimid-agent-core/tests/bindings.rs.
//!
//! Oracles: the expected messages are written out from the note's CDDL
//! and §5.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use mimid_live::{
    AckResult, ClientHello, ClientMessage, ErrorMessage, Op, OpKind, ProviderMessage, Request, code,
};
use mimid_server::config::{BaseUrl, Domain};
use mimid_server::directory::directory;
use mimid_server::follower::Follower;
use mimid_server::follower::key_packages::KeyPackages;
use mimid_server::follower::relay::Relay;
use mimid_server::http::router;
use mimid_server::hub::fanout::Fanout;
use mimid_server::hub::{Clock, Hub, SystemClock};
use mimid_server::jmap::{self, JmapOptions};
use mimid_server::peer::PeerClient;
use mimid_server::store::{BearerToken, Store};
use tokio_tungstenite::tungstenite::Message;

const ALICE: &str = "mimi://a.example/u/alice";

type Socket =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

struct Server {
    _dir: tempfile::TempDir,
    base: String,
    store: Store,
    token: BearerToken,
}

/// a.example's stack as main.rs wires it, with the live stream `on` or
/// off, and Alice's account.
async fn server(on: bool) -> Server {
    let dir = tempfile::tempdir().unwrap();
    let domain = Domain::try_from("a.example".to_owned()).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base_text = format!("http://{}", listener.local_addr().unwrap());
    let base = BaseUrl::try_from(base_text.clone()).unwrap();
    let store = Store::open(&dir.path().join("mimid.sqlite"), &domain)
        .await
        .unwrap();
    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    let peers = || PeerClient::new(&domain, BTreeMap::new()).unwrap();
    let key_packages = Arc::new(KeyPackages::new(
        store.clone(),
        domain.clone(),
        Arc::clone(&clock),
    ));
    let follower = Arc::new(
        Follower::new(domain.clone(), store.clone(), Arc::clone(&clock))
            .with_peers(peers())
            .with_key_packages(Arc::clone(&key_packages)),
    );
    let fanout = Fanout::new(
        store.clone(),
        domain.clone(),
        peers(),
        Arc::clone(&follower),
        Arc::clone(&clock),
    )
    .spawn();
    let hub = Arc::new(
        Hub::open(store.clone(), domain.clone(), Arc::clone(&clock))
            .await
            .unwrap()
            .with_fanout(fanout)
            .with_peers(peers())
            .with_local_key_material(Arc::clone(&key_packages) as _),
    );
    follower
        .set_relay(Relay::new(Arc::clone(&hub), peers()))
        .unwrap();
    let account = store.create_account(&domain, ALICE, 1).await.unwrap();
    let token = store.issue_token(&account, 2).await.unwrap();
    let mut options = JmapOptions::default();
    options.live_stream = on;
    let jmap = jmap::router(
        &base,
        store.clone(),
        Arc::clone(&hub),
        Arc::clone(&follower),
        options,
    )
    .unwrap();
    let app = router(directory(&base), hub, follower).merge(jmap);
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    Server {
        _dir: dir,
        base: base_text,
        store,
        token,
    }
}

impl Server {
    fn url(&self) -> String {
        format!(
            "{}{}",
            self.base.replacen("http", "ws", 1),
            mimid_live::PATH
        )
    }

    async fn connect(&self) -> Socket {
        tokio_tungstenite::connect_async(self.url())
            .await
            .unwrap()
            .0
    }

    /// A connection after a successful hello.
    async fn open(&self) -> Socket {
        let mut socket = self.connect().await;
        send(&mut socket, &hello(&self.token.expose_secret())).await;
        match receive(&mut socket, None).await {
            Some(ProviderMessage::Hello(hello)) => {
                assert_eq!(hello.user_uri, ALICE);
                assert_eq!(hello.room_id_prefix, "mimi://a.example/r/");
                assert_eq!(
                    hello.max_message_bytes,
                    mimid_live::MAX_MESSAGE_BYTES as u64
                );
                // findings log F10, bead mimid-e64f.18: 4 MiB less 64 KiB,
                // as the JMAP capability states it.
                assert_eq!(hello.max_mls_object_size, Some(4_128_768));
            }
            other => panic!("no ProviderHello: {other:?}"),
        }
        socket
    }
}

fn hello(token: &str) -> ClientMessage {
    ClientMessage::Hello(ClientHello {
        versions: vec![1],
        token: token.to_owned(),
        extra: Vec::new(),
    })
}

fn request(id: u64, op: Op) -> ClientMessage {
    ClientMessage::Request(Request {
        v: 1,
        id,
        op,
        extra: Vec::new(),
    })
}

async fn send(socket: &mut Socket, message: &ClientMessage) {
    socket
        .send(Message::Binary(message.encode().into()))
        .await
        .unwrap();
}

/// The next message, decoding an `Ack` as `kind`; `None` once the
/// provider closed.
async fn receive(socket: &mut Socket, kind: Option<OpKind>) -> Option<ProviderMessage> {
    loop {
        let frame = tokio::time::timeout(Duration::from_secs(10), socket.next())
            .await
            .expect("the provider answers in time");
        match frame {
            None | Some(Ok(Message::Close(_))) | Some(Err(_)) => return None,
            Some(Ok(Message::Binary(bytes))) => {
                return Some(ProviderMessage::decode(&bytes, |_| kind).unwrap());
            }
            Some(Ok(_)) => {}
        }
    }
}

/// The next message is an `Error` of `code` for `id`, and, if `closed`,
/// the connection then ends.
async fn expect_error(socket: &mut Socket, id: Option<u64>, code: &str, closed: bool) {
    match receive(socket, None).await {
        Some(ProviderMessage::Error(ErrorMessage {
            id: got, code: c, ..
        })) => {
            assert_eq!((got, c.as_str()), (id, code));
        }
        other => panic!("expected Error {code}, got {other:?}"),
    }
    if closed {
        assert!(receive(socket, None).await.is_none(), "closed after {code}");
    }
}

#[tokio::test]
async fn the_route_exists_only_when_switched_on() {
    let off = server(false).await;
    let refused = tokio_tungstenite::connect_async(off.url()).await;
    match refused {
        Err(tokio_tungstenite::tungstenite::Error::Http(response)) => {
            assert_eq!(response.status(), 404);
        }
        other => panic!("expected 404, got {:?}", other.map(|_| ())),
    }
    let on = server(true).await;
    on.open().await;
}

/// The Session lists the stream under its vendor capability, with the
/// URL the stream answers at, only with the stream on (Mark 2026-11-21 on
/// decision mimid-1wgh.77), and a request may name it in `using` only
/// then. The stream itself needs no Session: the other tests here never
/// read one.
#[tokio::test]
async fn the_session_lists_the_stream_only_when_switched_on() {
    let client = reqwest::Client::new();
    for on in [true, false] {
        let server = server(on).await;
        let session = client
            .get(format!("{}/.well-known/jmap", server.base))
            .bearer_auth(server.token.expose_secret())
            .send()
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap();
        let session: serde_json::Value = serde_json::from_slice(&session).unwrap();
        let capability = &session["capabilities"][mimid_live::SESSION_CAPABILITY];
        let api = client
            .post(format!("{}/jmap/api", server.base))
            .bearer_auth(server.token.expose_secret())
            .header("content-type", "application/json")
            .body(
                serde_json::json!({
                    "using": ["urn:ietf:params:jmap:core", mimid_live::SESSION_CAPABILITY],
                    "methodCalls": [],
                })
                .to_string(),
            )
            .send()
            .await
            .unwrap();
        if on {
            assert_eq!(
                capability,
                &serde_json::json!({"url": server.url()}),
                "{session}"
            );
            assert_eq!(
                mimid_live::SESSION_CAPABILITY,
                "tag:reviewcommit.com,2026:mimid:live"
            );
            // The advertised URL is the one the stream answers at.
            let url = capability["url"].as_str().unwrap().to_owned();
            let (mut socket, _) = tokio_tungstenite::connect_async(url).await.unwrap();
            send(&mut socket, &hello(&server.token.expose_secret())).await;
            assert!(matches!(
                receive(&mut socket, None).await,
                Some(ProviderMessage::Hello(_))
            ));
            assert_eq!(api.status(), 200);
        } else {
            assert!(capability.is_null(), "{session}");
            assert_eq!(api.status(), 400);
            let problem: serde_json::Value =
                serde_json::from_slice(&api.bytes().await.unwrap()).unwrap();
            assert_eq!(
                problem["type"],
                "urn:ietf:params:jmap:error:unknownCapability"
            );
        }
    }
}

#[tokio::test]
async fn a_wrong_malformed_or_revoked_token_is_refused_alike() {
    let server = server(true).await;
    // Never issued, and well formed.
    for token in [
        "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
        "not a token",
        "",
    ] {
        let mut socket = server.connect().await;
        send(&mut socket, &hello(token)).await;
        expect_error(&mut socket, None, code::UNAUTHORIZED, true).await;
    }
    // Revoked while connected: the next request is refused.
    let mut socket = server.open().await;
    send(&mut socket, &request(1, Op::ListChats)).await;
    assert!(matches!(
        receive(&mut socket, Some(OpKind::ListChats)).await,
        Some(ProviderMessage::Ack(_))
    ));
    assert!(server.store.revoke_token(&server.token, 3).await.unwrap());
    send(&mut socket, &request(2, Op::ListChats)).await;
    expect_error(&mut socket, None, code::UNAUTHORIZED, true).await;
    // And on a new connection.
    let mut socket = server.connect().await;
    send(&mut socket, &hello(&server.token.expose_secret())).await;
    expect_error(&mut socket, None, code::UNAUTHORIZED, true).await;
}

#[tokio::test]
async fn the_hello_comes_first_and_once() {
    let server = server(true).await;
    let mut socket = server.connect().await;
    send(&mut socket, &request(1, Op::ListChats)).await;
    expect_error(&mut socket, None, code::BAD_MESSAGE, true).await;

    let mut socket = server.connect().await;
    let mut hello = hello(&server.token.expose_secret());
    if let ClientMessage::Hello(h) = &mut hello {
        h.versions = vec![2, 3];
    }
    send(&mut socket, &hello).await;
    expect_error(&mut socket, None, code::UNSUPPORTED_VERSION, true).await;

    let mut socket = server.open().await;
    send(&mut socket, &self::hello(&server.token.expose_secret())).await;
    expect_error(&mut socket, None, code::BAD_MESSAGE, true).await;
}

#[tokio::test]
async fn a_text_frame_closes_the_connection() {
    let server = server(true).await;
    let mut socket = server.open().await;
    socket.send(Message::Text("{}".into())).await.unwrap();
    expect_error(&mut socket, None, code::BAD_MESSAGE, true).await;
}

#[tokio::test]
async fn frames_past_the_limits_are_refused_and_at_them_accepted() {
    let server = server(true).await;
    // An Upload at maxMessageBytes is read; one byte more is tooLarge.
    let upload = |len: usize| {
        let empty = request(
            1,
            Op::Upload {
                data: Vec::new(),
                media_type: None,
            },
        )
        .encode()
        .len();
        // The bstr head grows from 1 to 5 bytes for this length.
        request(
            1,
            Op::Upload {
                data: vec![0; len - empty - 4],
                media_type: None,
            },
        )
    };
    let mut socket = server.open().await;
    let at = upload(mimid_live::MAX_MESSAGE_BYTES);
    assert_eq!(at.encode().len(), mimid_live::MAX_MESSAGE_BYTES);
    send(&mut socket, &at).await;
    // The store's own limit (16 MiB) refuses it, as JMAP's upload would.
    expect_error(&mut socket, Some(1), "tooLarge", false).await;
    send(&mut socket, &upload(mimid_live::MAX_MESSAGE_BYTES + 1)).await;
    expect_error(&mut socket, None, code::TOO_LARGE, true).await;

    // Any other request is held to maxRequestBytes.
    let mut socket = server.open().await;
    let send_of = |len: usize| {
        let empty = request(
            2,
            Op::Send {
                room: "mimi://a.example/r/x".to_owned(),
                message: Vec::new(),
            },
        )
        .encode()
        .len();
        request(
            2,
            Op::Send {
                room: "mimi://a.example/r/x".to_owned(),
                message: vec![0; len - empty - 4],
            },
        )
    };
    let at = send_of(mimid_live::MAX_REQUEST_BYTES);
    assert_eq!(at.encode().len(), mimid_live::MAX_REQUEST_BYTES);
    send(&mut socket, &at).await;
    // Read and checked as Room/send checks it: no Chat for that room.
    expect_error(&mut socket, Some(2), "invalidArguments", false).await;
    send(&mut socket, &send_of(mimid_live::MAX_REQUEST_BYTES + 1)).await;
    expect_error(&mut socket, None, code::TOO_LARGE, true).await;

    // A message one octet over maxMlsObjectSize fits the frame limit and
    // is refused by Room/send's own check (bead mimid-e64f.18).
    let mut socket = server.open().await;
    let over = request(
        3,
        Op::Send {
            room: "mimi://a.example/r/x".to_owned(),
            message: vec![0; mimid_server::jmap::MAX_MLS_OBJECT_SIZE + 1],
        },
    );
    send(&mut socket, &over).await;
    match receive(&mut socket, None).await {
        Some(ProviderMessage::Error(ErrorMessage {
            id: Some(3),
            code,
            detail,
            ..
        })) => {
            assert_eq!(code, "invalidArguments");
            assert!(
                detail.is_some_and(|d| d.contains("maxMlsObjectSize")),
                "the size check, not the Chat check, refused it"
            );
        }
        other => panic!("expected Error invalidArguments, got {other:?}"),
    }
}

#[tokio::test]
async fn a_request_that_does_not_decode_is_bad_message_with_its_id() {
    let server = server(true).await;
    let mut socket = server.open().await;
    // {"t": "Teleport", "v": 1, "id": 5}
    let mut frame = vec![0xa3, 0x61, b't', 0x68];
    frame.extend(b"Teleport");
    frame.extend([0x61, b'v', 0x01, 0x62, b'i', b'd', 0x05]);
    socket.send(Message::Binary(frame.into())).await.unwrap();
    expect_error(&mut socket, Some(5), code::BAD_MESSAGE, false).await;
    // A duplicate key: no id is trusted.
    let frame = vec![0xa2, 0x61, b'v', 0x01, 0x61, b'v', 0x01];
    socket.send(Message::Binary(frame.into())).await.unwrap();
    expect_error(&mut socket, None, code::BAD_MESSAGE, false).await;
    // The connection still works.
    send(&mut socket, &request(6, Op::ListConsent)).await;
    assert!(matches!(
        receive(&mut socket, Some(OpKind::ListConsent)).await,
        Some(ProviderMessage::Ack(_))
    ));
}

#[tokio::test]
async fn subscribe_without_messages_gives_the_jmap_state() {
    let server = server(true).await;
    let mut socket = server.open().await;
    send(
        &mut socket,
        &request(
            1,
            Op::Subscribe {
                since: None,
                after: None,
            },
        ),
    )
    .await;
    let state = match receive(&mut socket, Some(OpKind::Subscribe)).await {
        Some(ProviderMessage::Ack(ack)) => match ack.result {
            AckResult::Subscribe { state } => state,
            other => panic!("{other:?}"),
        },
        other => panic!("{other:?}"),
    };
    // The Message state of a fresh account, s.m (projection.rs).
    assert_eq!(state, "0.0");
    send(
        &mut socket,
        &request(
            2,
            Op::Subscribe {
                since: None,
                after: None,
            },
        ),
    )
    .await;
    expect_error(&mut socket, Some(2), code::BAD_MESSAGE, false).await;

    // findings log F12: `after` is for a Subscribe without `since`.
    let mut socket = server.open().await;
    send(
        &mut socket,
        &request(
            1,
            Op::Subscribe {
                since: Some(state.clone()),
                after: Some(std::collections::BTreeMap::new()),
            },
        ),
    )
    .await;
    expect_error(&mut socket, Some(1), code::BAD_MESSAGE, false).await;

    // A state that does not parse, or one ahead of the account's.
    for since in ["x", "9.9"] {
        let mut socket = server.open().await;
        send(
            &mut socket,
            &request(
                1,
                Op::Subscribe {
                    since: Some(since.to_owned()),
                    after: None,
                },
            ),
        )
        .await;
        expect_error(&mut socket, Some(1), code::CANNOT_RESUME, false).await;
    }
}

#[tokio::test]
async fn requests_are_answered_by_the_jmap_core_functions() {
    let server = server(true).await;
    let mut socket = server.open().await;
    send(&mut socket, &request(1, Op::ListKeyPackages)).await;
    match receive(&mut socket, Some(OpKind::ListKeyPackages)).await {
        Some(ProviderMessage::Ack(ack)) => assert!(matches!(
            ack.result,
            AckResult::ListKeyPackages { ref key_packages, .. } if key_packages.is_empty()
        )),
        other => panic!("{other:?}"),
    }
    // KeyPackage/set create of something that is no KeyPackage:
    // invalidProperties naming keyPackage, the same SetError.
    send(
        &mut socket,
        &request(
            2,
            Op::PublishKeyPackage {
                key_package: vec![1, 2, 3],
                last_resort: None,
            },
        ),
    )
    .await;
    match receive(&mut socket, None).await {
        Some(ProviderMessage::Error(error)) => {
            assert_eq!(error.code, "invalidProperties");
            assert_eq!(error.properties, Some(vec!["keyPackage".to_owned()]));
        }
        other => panic!("{other:?}"),
    }
    // Consent/set create with neither URI the account's: invalidProperties.
    send(
        &mut socket,
        &request(
            3,
            Op::CreateConsent {
                requester_uri: "mimi://b.example/u/x".to_owned(),
                target_uri: "mimi://c.example/u/y".to_owned(),
                room: None,
                requested: None,
                decision: None,
            },
        ),
    )
    .await;
    match receive(&mut socket, None).await {
        Some(ProviderMessage::Error(error)) => assert_eq!(error.code, "invalidProperties"),
        other => panic!("{other:?}"),
    }
    // A room the account has no Chat for.
    send(
        &mut socket,
        &request(
            4,
            Op::Unbind {
                room: "mimi://a.example/r/x".to_owned(),
            },
        ),
    )
    .await;
    expect_error(&mut socket, Some(4), "invalidArguments", false).await;
    send(
        &mut socket,
        &request(
            5,
            Op::FetchAsset {
                room: "mimi://a.example/r/x".to_owned(),
                url: "https://b.example/a".to_owned(),
            },
        ),
    )
    .await;
    expect_error(&mut socket, Some(5), code::NOT_FOUND, false).await;
    // An upload comes back at the asset URL.
    send(
        &mut socket,
        &request(
            6,
            Op::Upload {
                data: b"sealed".to_vec(),
                media_type: None,
            },
        ),
    )
    .await;
    match receive(&mut socket, Some(OpKind::Upload)).await {
        Some(ProviderMessage::Ack(ack)) => match ack.result {
            AckResult::Upload { url, size, blob_id } => {
                assert_eq!(size, 6);
                assert_eq!(url, format!("{}/assets/{blob_id}", server.base));
            }
            other => panic!("{other:?}"),
        },
        other => panic!("{other:?}"),
    }
}
