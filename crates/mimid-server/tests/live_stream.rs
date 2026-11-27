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
    dir: tempfile::TempDir,
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
    options.message_retention = Some(3600);
    // Two KeyMaterial/fetch calls, then one an hour (bead mimid-e64f.21).
    options.key_material_limit = Some(mimid_server::jmap::rate::RateLimit {
        burst: 2,
        refill_ms: 3_600_000,
    });
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
        dir,
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
                // Decision mimid-1wgh.82: as the options give it.
                assert_eq!(hello.message_retention, Some(3600));
                // Bead mimid-e64f.22: the default maxClients.
                assert_eq!(hello.max_clients, Some(10));
                // Clean-room finding C4: 365 days and an hour, as the JMAP
                // capability states it.
                assert_eq!(hello.max_key_package_lifetime, Some(31_539_600));
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
/// The socket is the event: `next` is an await on the connection, so
/// the reactor wakes this when a frame arrives. No deadline, so a
/// provider that never answers hangs the test rather than failing it on
/// a loaded machine.
async fn receive(socket: &mut Socket, kind: Option<OpKind>) -> Option<ProviderMessage> {
    loop {
        let frame = socket.next().await;
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

/// Bead mimid-v9co: revoking a token by its id closes the connections it
/// opened at once, with `Error` `unauthorized`, even an idle one with no
/// request to refuse; a connection of another token of the same user
/// stays open.
#[tokio::test]
async fn revoking_a_token_by_id_closes_its_idle_connections() {
    let server = server(true).await;
    let account = server
        .store
        .account_for_token(&server.token)
        .await
        .unwrap()
        .unwrap();
    let other = server
        .store
        .issue_named_token(&account.account_id, Some("other"), 3)
        .await
        .unwrap();
    let mut first = server.open().await;
    let mut second = server.open().await;
    let mut kept = server.connect().await;
    send(&mut kept, &hello(&other.token.expose_secret())).await;
    assert!(matches!(
        receive(&mut kept, None).await,
        Some(ProviderMessage::Hello(_))
    ));

    assert_eq!(
        server
            .store
            .revoke_token_id(&account.token_id, 4)
            .await
            .unwrap(),
        mimid_server::store::TokenRevocation::Revoked
    );
    expect_error(&mut first, None, code::UNAUTHORIZED, true).await;
    expect_error(&mut second, None, code::UNAUTHORIZED, true).await;
    send(&mut kept, &request(1, Op::ListChats)).await;
    assert!(matches!(
        receive(&mut kept, Some(OpKind::ListChats)).await,
        Some(ProviderMessage::Ack(_))
    ));
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
                silent: None,
            },
        )
        .encode()
        .len();
        request(
            2,
            Op::Send {
                room: "mimi://a.example/r/x".to_owned(),
                message: vec![0; len - empty - 4],
                silent: None,
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
            silent: None,
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
    // The Message state of a fresh account, s.m.g (projection.rs).
    assert_eq!(state, "0.0.0");
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
    for since in ["x", "9.9", "9.9.9", "0.0.1"] {
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

/// Decision mimid-1wgh.83: after an operator deletes Messages by hand, a
/// Subscribe from a position before the deletion is `cannotResume`, and
/// one without a position, or from the new one, replays what is left.
#[tokio::test]
async fn subscribe_from_before_a_deletion_cannot_resume() {
    use mimid_server::store::{FanoutKind, NewFanout};
    use sha2::{Digest, Sha256};
    const DEN: &str = "mimi://c.example/r/den";
    let server = server(true).await;
    let c = Domain::try_from("c.example".to_owned()).unwrap();
    assert!(
        server
            .store
            .add_follower_member(DEN, &c, ALICE, 1, 1)
            .await
            .unwrap()
    );
    for i in 0..3u8 {
        let bytes = [b'm', i];
        let hash: [u8; 32] = Sha256::digest(bytes).into();
        let mut sender_msg_id = [0; 16];
        sender_msg_id[6..].copy_from_slice(&hash[..10]);
        server
            .store
            .append_fanout(
                DEN,
                &c,
                2,
                &[NewFanout {
                    bytes: &bytes,
                    hash,
                    message_hash: Sha256::digest([b"inner ", &bytes[..]].concat()).into(),
                    sender_msg_id,
                    hub_timestamp: 2,
                    kind: FanoutKind::Application,
                    group_id: None,
                    welcome_refs: Vec::new(),
                }],
            )
            .await
            .unwrap();
    }
    let subscribe = |since: Option<String>| request(1, Op::Subscribe { since, after: None });
    let mut socket = server.open().await;
    send(&mut socket, &subscribe(None)).await;
    let (all, before) = replay(&mut socket).await;
    assert_eq!(all.len(), 3);

    let db = sqlx::SqlitePool::connect_with(
        sqlx::sqlite::SqliteConnectOptions::new()
            .filename(server.dir.path().join("mimid.sqlite"))
            .foreign_keys(false),
    )
    .await
    .unwrap();
    sqlx::query("DELETE FROM follower_event WHERE message_id = ?")
        .bind(&all[1])
        .execute(&db)
        .await
        .unwrap();
    db.close().await;

    let mut socket = server.open().await;
    send(&mut socket, &subscribe(Some(before))).await;
    expect_error(&mut socket, Some(1), code::CANNOT_RESUME, false).await;
    let mut socket = server.open().await;
    send(&mut socket, &subscribe(None)).await;
    let (left, now) = replay(&mut socket).await;
    assert_eq!(left, [all[0].clone(), all[2].clone()]);
    let mut socket = server.open().await;
    send(&mut socket, &subscribe(Some(now))).await;
    let (none, _) = replay(&mut socket).await;
    assert!(none.is_empty());
}

/// The `Deliver`s of a Subscribe's replay, by Message id, and its `Ack`'s
/// state.
async fn replay(socket: &mut Socket) -> (Vec<String>, String) {
    let mut delivered = Vec::new();
    loop {
        match receive(socket, Some(OpKind::Subscribe)).await {
            Some(ProviderMessage::Deliver(deliver)) => delivered.push(deliver.message_id),
            Some(ProviderMessage::Ack(ack)) => match ack.result {
                AckResult::Subscribe { state } => return (delivered, state),
                other => panic!("{other:?}"),
            },
            other => panic!("{other:?}"),
        }
    }
}

/// Bead mimid-e64f.21: past the account's KeyMaterial/fetch limit, both
/// bindings answer `rateLimited` with `retryAfter`, from one bucket the
/// account shares between them. Oracle: draft-atwood-jmap-chat-mimi-00
/// §capability (jmap-chat-spec 43ee02c) and the limit the server was
/// given (2, then one an hour).
#[tokio::test]
async fn key_material_over_the_limit_is_rate_limited_on_both_bindings() {
    let server = server(true).await;
    let client = reqwest::Client::new();
    let session: serde_json::Value = client
        .get(format!("{}/.well-known/jmap", server.base))
        .bearer_auth(server.token.expose_secret())
        .send()
        .await
        .unwrap()
        .bytes()
        .await
        .map(|b| serde_json::from_slice(&b).unwrap())
        .unwrap();
    let account = session["primaryAccounts"]["urn:ietf:params:jmap:chat:mimi"].clone();
    let fetch = || async {
        let answer: serde_json::Value = client
            .post(format!("{}/jmap/api", server.base))
            .bearer_auth(server.token.expose_secret())
            .header("content-type", "application/json")
            .body(
                serde_json::json!({
                    "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:chat:mimi"],
                    "methodCalls": [["KeyMaterial/fetch", {
                        "accountId": account,
                        "roomId": "mimi://a.example/r/x",
                        "request": "AAAA",
                    }, "c"]],
                })
                .to_string(),
            )
            .send()
            .await
            .unwrap()
            .bytes()
            .await
            .map(|b| serde_json::from_slice(&b).unwrap())
            .unwrap();
        answer["methodResponses"][0].clone()
    };
    // Within the limit, the call is checked as before.
    for _ in 0..2 {
        let answer = fetch().await;
        assert_eq!(answer[1]["type"], "invalidArguments", "{answer}");
    }
    let answer = fetch().await;
    assert_eq!(answer[0], "error", "{answer}");
    assert_eq!(answer[1]["type"], "rateLimited", "{answer}");
    let retry_after = answer[1]["retryAfter"].as_u64().unwrap();
    assert!((3599..=3600).contains(&retry_after), "{answer}");

    let mut socket = server.open().await;
    send(
        &mut socket,
        &request(
            7,
            Op::FetchKeyMaterial {
                room: "mimi://a.example/r/x".to_owned(),
                request: vec![0; 3],
            },
        ),
    )
    .await;
    match receive(&mut socket, Some(OpKind::FetchKeyMaterial)).await {
        Some(ProviderMessage::Error(error)) => {
            assert_eq!(error.id, Some(7));
            assert_eq!(error.code, code::RATE_LIMITED);
            assert!(
                error
                    .retry_after
                    .is_some_and(|s| (3599..=3600).contains(&s))
            );
        }
        other => panic!("{other:?}"),
    }
}
