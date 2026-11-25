//! A whole call negotiation between two agents, driven only through JMAP
//! (bead mimid-1wgh.114.10; draft-atwood-jmap-vtc-00 and
//! draft-atwood-jmap-vtc-wss-00).
//!
//! Every layer between the store and a client is new here: the ephemeral
//! subscription, the WebSocket, the SDP fragment codec, the capability. A
//! browser demo exercises all of them at once, by hand, and reports "no
//! audio"; this reports which one.
//!
//! What it does not cover, and cannot: the media. No browser, no WebRTC,
//! no DTLS-SRTP. It proves the negotiation a call needs, not that a call
//! sounds like anything — that is bead mimid-1wgh.114.9's page.
//!
//! Oracles: draft-atwood-jmap-vtc-00 §Account-Level Capability Object,
//! §Optional Binding Fields (`mimiRoomId`), §`VTCCall/signal`,
//! §`VTCCall/exportMediaSecret`; draft-atwood-jmap-vtc-wss-00
//! §`VTCStreamEnable` and §`VTCCallSignal`; room-policy-04 §5 for the
//! call room being parent-dependent on the chat's.
//!
//! The candidate assertion is on the `RTCIceCandidateInit` **object**, not
//! on the SDP fragment the wire carries it in. The fragment is the
//! agent's own codec (`vtc_backend::candidate_fragment` and
//! `vtc_stream::candidate_of`); what a client is owed is the object it
//! gave, back unchanged.
//!
//! Offline: two daemons and a test provider in this process.

#![forbid(unsafe_code)]

mod common;

use common::{ALICE, BOB, Client, Running, config, server};
use futures_util::{SinkExt, StreamExt};
use serde_json::{Value, json};
use tokio_tungstenite::tungstenite::Message;

/// How long a pushed event is waited for before the test fails. Generous:
/// a signal crosses two daemons' sync loops and a provider.
const PATIENCE: std::time::Duration = std::time::Duration::from_secs(15);

/// alice's or bob's configuration with the VTC surface on.
fn with_vtc(
    server: &common::Server,
    user: &'static str,
    dir: &std::path::Path,
    invites: &str,
) -> mimid_agent::Config {
    let mut config = config(server, user, dir, invites);
    config.jmap.vtc = true;
    config
}

/// A JMAP WebSocket on the agent's plain listener, authenticated by the
/// same bearer credential as the HTTP routes: the credential is on the
/// request that upgrades, so the socket is authenticated from its first
/// frame (RFC 8887 §4, and the agent takes no token in the subprotocol).
struct Socket(
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
);

impl Socket {
    async fn open(daemon: &Running) -> Self {
        let url = daemon.base().replacen("http://", "ws://", 1) + "/jmap/ws";
        let request = tokio_tungstenite::tungstenite::http::Request::builder()
            .uri(&url)
            .header(
                "Host",
                url.trim_start_matches("ws://").split('/').next().unwrap(),
            )
            .header("Connection", "Upgrade")
            .header("Upgrade", "websocket")
            .header("Sec-WebSocket-Version", "13")
            .header(
                "Sec-WebSocket-Key",
                tokio_tungstenite::tungstenite::handshake::client::generate_key(),
            )
            .header("Sec-WebSocket-Protocol", "jmap")
            .header("Authorization", format!("Bearer {}", daemon.token()))
            .body(())
            .unwrap();
        let (socket, _) = tokio_tungstenite::connect_async(request).await.unwrap();
        Self(socket)
    }

    async fn send(&mut self, frame: &Value) {
        self.0
            .send(Message::Text(frame.to_string().into()))
            .await
            .unwrap();
    }

    /// `VTCStreamEnable` for every call this user takes part in and every
    /// event type: `callIds` and `eventTypes` absent both mean "all"
    /// (draft-atwood-jmap-vtc-wss-00 §`VTCStreamEnable`).
    async fn enable(&mut self) {
        self.send(&json!({"@type": "VTCStreamEnable"})).await;
    }

    /// The next frame whose `@type` is `want` and that `accept` likes,
    /// within [`PATIENCE`].
    ///
    /// Frames of other types are skipped rather than failed on: the
    /// socket also carries whatever else the connection says, and a test
    /// that broke on an unrelated frame would be testing frame order.
    async fn until(&mut self, want: &str, accept: impl Fn(&Value) -> bool) -> Value {
        let deadline = tokio::time::Instant::now() + PATIENCE;
        loop {
            let frame = tokio::time::timeout_at(deadline, self.0.next())
                .await
                .unwrap_or_else(|_| panic!("no {want} within {PATIENCE:?}"))
                .expect("the socket closed")
                .unwrap();
            let Message::Text(text) = frame else {
                continue;
            };
            let value: Value = serde_json::from_str(&text).unwrap();
            assert_ne!(
                value["@type"],
                json!("RequestError"),
                "the socket refused a frame: {value}"
            );
            if value["@type"] == json!(want) && accept(&value) {
                return value;
            }
        }
    }

    /// The next `VTCCallSignal` that this account did not send.
    ///
    /// A sender sees its own signals on its own socket: the store records
    /// a sent signal as a change like any other, so the pump delivers it
    /// back. That is worth knowing — a client MUST ignore a signal whose
    /// `participantId` is its own, or it would apply its own offer as an
    /// answer — and `participantId` is what it filters on.
    async fn signal_from_other(&mut self, me: &str) -> Value {
        let me = me.to_owned();
        self.until("VTCCallSignal", move |value| {
            value["participantId"] != json!(me)
        })
        .await
    }
}

/// The VTC capability URI, which a request must name in `using` for any
/// VTC method.
fn vtc() -> &'static str {
    mimid_agent_jmap::vtc::CAPABILITY
}

/// One `VTCCall/signal` call.
async fn signal(client: &Client, call: &str, args: Value) {
    let mut arguments = json!({"callId": call});
    for (key, value) in args.as_object().unwrap() {
        arguments[key] = value.clone();
    }
    let answer = client
        .call_using(&[vtc()], "VTCCall/signal", arguments)
        .await;
    assert!(
        answer.get("type").is_none(),
        "the signal was refused: {answer}"
    );
}

/// Oracle: the bead's eight steps. Each assertion names which layer it
/// is about, so a failure says where the negotiation broke.
#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn two_agents_negotiate_a_call_and_export_the_same_media_secret() {
    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path(), &[ALICE, BOB]).await;
    let alice = Running::start(&with_vtc(&server, ALICE, dir.path(), "from-allowed")).await;
    let bob = Running::start(&with_vtc(&server, BOB, dir.path(), "any")).await;
    let a = alice.client().await;
    let b = bob.client().await;

    // 1. The capability, on both Sessions: the properties a client reads
    //    before it offers a call at all.
    for (who, client) in [("alice", &a), ("bob", &b)] {
        let session = &client.session;
        assert_eq!(session["capabilities"][vtc()], json!({}), "{who}");
        let account = &session["accounts"][&client.account]["accountCapabilities"][vtc()];
        assert_eq!(account["supportsMimiCalls"], json!(true), "{who}");
        assert_eq!(account["supportsMimiKeyedCalls"], json!(true), "{who}");
        assert!(
            !account["iceServers"].as_array().unwrap().is_empty(),
            "{who} needs relays to gather candidates"
        );
        // The socket is how a signal arrives; without it a client could
        // send an offer and never hear an answer.
        assert!(
            session["capabilities"][jmap_websocket::CAPABILITY]["url"]
                .as_str()
                .is_some_and(|url| url.ends_with("/jmap/ws")),
            "{who} must be told where the socket is: {session}"
        );
    }

    // 2. A chat between them, bob joining at his next sync.
    let mut b_chats = b.events().await;
    let contact = a.create("ChatContact", json!({"identity": BOB})).await["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let chat = a
        .create(
            "Chat",
            json!({"kind": "group", "name": "calls", "memberIds": [contact]}),
        )
        .await;
    let chat_a = chat["id"].as_str().unwrap().to_owned();
    let chat_room = chat["roomId"].as_str().unwrap().to_owned();
    b_chats.until_changed("Chat").await;
    let chats = b.get("Chat", None).await;
    assert_eq!(chats.len(), 1, "{chats:?}");
    assert_eq!(chats[0]["roomId"], json!(chat_room));
    // The id bob's client already has for alice. `participantId` on a
    // signal is a JMAP Id, so it is this and not her user URI, and a
    // client correlates a signal to a chat member by it.
    let alice_to_bob = chats[0]["members"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["id"].as_str().unwrap().to_owned())
        .find(|id| *id != b.account)
        .unwrap_or_else(|| panic!("alice should be a member: {chats:?}"));

    // 3. alice starts the call. Its room is the call's own, not the
    //    chat's: the exported secret belongs to a whole group, so a call
    //    keyed from the chat's room would be readable by every member of
    //    the chat (decision mimid-1wgh.113).
    let created = a
        .call_using(
            &[vtc()],
            "VTCCall/set",
            json!({"create": {"k": {
                "callType": "room",
                "mediaTypes": ["audio"],
                "chatId": chat_a,
            }}}),
        )
        .await;
    assert!(
        created["notCreated"]
            .as_object()
            .is_none_or(|m| m.is_empty()),
        "{created}"
    );
    let call = created["created"]["k"].clone();
    let call_a = call["id"].as_str().unwrap().to_owned();
    let call_room = call["mimiRoomId"]
        .as_str()
        .unwrap_or_else(|| panic!("the call needs a room of its own: {call}"))
        .to_owned();
    assert_ne!(
        call_room, chat_room,
        "the call room must not be the chat's room"
    );
    // room-policy-04 §5: the call room is parent-dependent on the
    // chat's, which is what makes leaving the chat able to cascade and
    // what keeps the call's membership its own.
    let parent = {
        let state = alice.store.state();
        let key = state
            .room_of_uri(&call_room)
            .unwrap_or_else(|| panic!("alice should be in {call_room}"))
            .clone();
        state.rooms[&key].parent.clone()
    };
    assert_eq!(
        parent.as_deref(),
        Some(chat_room.as_str()),
        "the call room's parent must be the chat's room"
    );

    // 4. Both open the socket and subscribe. bob subscribes before any
    //    signal is sent, as a client joining a call does.
    let mut a_socket = Socket::open(&alice).await;
    let mut b_socket = Socket::open(&bob).await;
    a_socket.enable().await;
    b_socket.enable().await;

    // 5. alice offers; bob must receive it, byte for byte.
    const OFFER: &str = "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\nm=audio 9 UDP/TLS/RTP/SAVPF 111\r\na=mid:0\r\n";
    signal(&a, &call_a, json!({"signal": "offer", "sdp": OFFER})).await;
    let got = b_socket.signal_from_other(&b.account).await;
    assert_eq!(got["sdp"], json!(OFFER), "the offer must arrive unchanged");
    assert_eq!(got["signal"], json!("offer"), "{got}");
    // The sender is the authenticated MLS sender the store recorded, not
    // anything alice asserted.
    assert_eq!(got["participantId"], json!(alice_to_bob), "{got}");
    let call_b = got["callId"].as_str().unwrap().to_owned();

    // 6. bob answers; alice receives it, likewise unchanged.
    const ANSWER: &str = "v=0\r\no=- 2 1 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\nm=audio 9 UDP/TLS/RTP/SAVPF 111\r\na=mid:0\r\n";
    signal(&b, &call_b, json!({"signal": "answer", "sdp": ANSWER})).await;
    let got = a_socket.signal_from_other(&a.account).await;
    assert_eq!(
        got["sdp"],
        json!(ANSWER),
        "the answer must arrive unchanged"
    );
    assert_eq!(got["signal"], json!("answer"), "{got}");
    // alice sees bob by the id her own client has for him.
    assert!(
        got["participantId"]
            .as_str()
            .is_some_and(|id| !id.is_empty()),
        "{got}"
    );

    // 7. A candidate each way. This is the assertion that would have
    //    caught the bug of 2026-11-23, where a candidate went out with no
    //    payload at all and everything compiled, linted and passed.
    let candidate = json!({
        "candidate": "candidate:1 1 udp 2130706431 192.0.2.1 54321 typ host",
        "sdpMid": "0",
    });
    signal(
        &a,
        &call_a,
        json!({"signal": "candidate", "candidate": candidate}),
    )
    .await;
    let got = b_socket.signal_from_other(&b.account).await;
    assert_eq!(got["signal"], json!("candidate"), "{got}");
    assert_eq!(
        got["candidate"]["candidate"], candidate["candidate"],
        "the candidate line must arrive unchanged: {got}"
    );
    assert_eq!(
        got["candidate"]["sdpMid"], candidate["sdpMid"],
        "the media description it belongs to must survive: {got}"
    );
    assert_eq!(got["sdp"], Value::Null, "a candidate carries no sdp: {got}");

    // 8. Both export the media secret: the same bytes for the same
    //    epoch, which is draft-atwood-mimi-calls §4.3's keying claim
    //    proved over the wire rather than in the store.
    let mine = a
        .call_using(
            &[vtc()],
            "VTCCall/exportMediaSecret",
            json!({"callId": call_a}),
        )
        .await;
    let theirs = b
        .call_using(
            &[vtc()],
            "VTCCall/exportMediaSecret",
            json!({"callId": call_b}),
        )
        .await;
    assert_eq!(mine["epoch"], theirs["epoch"], "{mine} vs {theirs}");
    assert!(
        mine["mediaSecret"].as_str().is_some_and(|s| !s.is_empty()),
        "{mine}"
    );
    assert_eq!(
        mine["mediaSecret"], theirs["mediaSecret"],
        "both sides of a call must derive the same secret"
    );

    // An epoch the call is not in is refused rather than answered with a
    // secret nobody else is using, so a client cannot key media for an
    // epoch that has ended without noticing. It is a method-level error,
    // so the raw post is what reads it.
    let stale = mine["epoch"].as_u64().unwrap() + 1;
    let (status, answer) = a
        .post(&json!({
            "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:chat", vtc()],
            "methodCalls": [[
                "VTCCall/exportMediaSecret",
                {"accountId": a.account, "callId": call_a, "epoch": stale},
                "c0",
            ]],
        }))
        .await;
    assert_eq!(status, 200, "{answer}");
    let refused = &answer["methodResponses"][0];
    assert_eq!(refused[0], json!("error"), "{answer}");
    assert_eq!(refused[1]["type"], json!("stateMismatch"), "{answer}");
    // It says which epoch the call is in, so the client can ask again.
    assert!(
        refused[1]["description"]
            .as_str()
            .is_some_and(|text| text.contains(&mine["epoch"].to_string())),
        "the refusal should name the current epoch: {answer}"
    );

    alice.stop().await;
    bob.stop().await;
}
