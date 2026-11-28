//! The two bindings side by side (docs/design/binary-live-stream.md §7;
//! bead mimid-e64f.5): the two-agent scenario of two_agents.rs runs over
//! JMAP, over the live stream, and with one agent on each, against one
//! server that serves both, and what the agents report must be the same.
//! Then what only the stream has to get right: no gap and no duplicate
//! across reconnects, a membership change while subscribed, a wrong
//! token.
//!
//! Oracles:
//!
//! - The JMAP run: the scenario's own assertions are those of
//!   two_agents.rs, and its record is what the stream run must equal.
//! - MLS agreement after each Commit (RFC 9420 §8.7).
//! - For the membership change, JMAP's own `Message/changes` from the
//!   positions the stream gave (note §5.5).

mod common;

use common::{ALICE, BOB, Server, assert_agreement, poll_until, server_with};
use futures_util::{SinkExt, StreamExt};
use mimid_agent_core::{
    Agent, AgentConfig, AgentError, Binding, DidWebvhConfig, Event, HostOptions,
};
use mimid_live::{AckResult, ClientHello, ClientMessage, Op, OpKind, ProviderMessage, Request};
use mimid_server::jmap::JmapOptions;
use serde_json::{Value, json};
use tokio_tungstenite::tungstenite::Message;

async fn stream_server(dir: &std::path::Path) -> Server {
    let mut options = JmapOptions::default();
    options.live_stream = true;
    server_with(dir, &[ALICE, BOB], options).await
}

async fn device(
    server: &Server,
    user: &'static str,
    dir: &std::path::Path,
    binding: Binding,
) -> Agent {
    Agent::open(AgentConfig {
        server_url: server.base.clone(),
        binding,
        token: server.tokens[user].clone(),
        user_uri: user.to_owned(),
        state_dir: dir.join(user.rsplit('/').next().unwrap()),
        full_tree_hubs: Vec::new(),
        did_webvh: DidWebvhConfig::default(),
    })
    .await
    .unwrap()
}

/// What the scenario saw, without ids, room URIs or times.
#[derive(Debug, Default, PartialEq, Eq)]
struct Record(Vec<String>);

impl Record {
    fn note(&mut self, line: impl Into<String>) {
        self.0.push(line.into());
    }
}

/// The scenario of two_agents.rs::two_agents_chat_through_their_server,
/// with alice on `a` and bob on `b`, recording what each reports.
async fn scenario(a: Binding, b: Binding) -> Record {
    let dir = tempfile::tempdir().unwrap();
    let server = stream_server(dir.path()).await;
    let mut record = Record::default();
    let mut alice = device(&server, ALICE, dir.path(), a).await;
    let mut bob = device(&server, BOB, dir.path(), b).await;
    alice.publish_key_packages(2).await.unwrap();
    bob.publish_key_packages(2).await.unwrap();
    record.note(format!(
        "bob outstanding {}",
        bob.key_packages_outstanding()
    ));

    let room = alice
        .host_room(&HostOptions::named("planning"))
        .await
        .unwrap();
    record.note(format!("hosted {:?}", alice.participants(&room).unwrap()));

    bob.deny(ALICE).await.unwrap();
    let refused = alice.invite(&room, BOB).await;
    record.note(format!("invite while refused: {}", short(&refused)));
    bob.allow(ALICE).await.unwrap();
    let mut consents: Vec<String> = bob
        .consents()
        .await
        .unwrap()
        .into_iter()
        .map(|r| {
            format!(
                "{} -> {} {:?} {}",
                r.requester, r.target, r.decision, r.requested
            )
        })
        .collect();
    consents.sort();
    record.note(format!("bob's consents {consents:?}"));
    alice.invite(&room, BOB).await.unwrap();
    record.note(format!(
        "after invite {:?}",
        alice.participants(&room).unwrap()
    ));

    let number = poll_until(&mut bob, &server, |e| match e {
        Event::InviteArrived { number } => Some(*number),
        _ => None,
    })
    .await;
    record.note(format!("inviter {}", bob.inviter(number).unwrap()));
    assert_eq!(bob.join(number).unwrap(), room);
    // findings log F9: KeyPackage/changes on JMAP, ListKeyPackages on the
    // stream, the same count.
    bob.refresh_key_packages().await.unwrap();
    record.note(format!(
        "bob joined: {:?}, name {:?}, outstanding {}",
        bob.participants(&room).unwrap(),
        bob.room_name(&room).unwrap(),
        bob.key_packages_outstanding()
    ));
    assert_agreement(&room, &alice, &bob);
    record.note(format!("epoch {}", alice.epoch(&room).unwrap()));

    for alice_sends in [true, false] {
        let (from, to, text) = if alice_sends {
            (&mut alice, &mut bob, "hello bob")
        } else {
            (&mut bob, &mut alice, "hi alice")
        };
        let sent = from.send_text(&room, text).await.unwrap();
        let got = poll_until(to, &server, |e| match e {
            Event::Message(m) => Some(m.clone()),
            _ => None,
        })
        .await;
        assert_eq!(
            (got.message_id, got.accepted_at),
            (sent.message_id, sent.accepted_at)
        );
        record.note(format!(
            "{} got {:?} from {}, franked {}",
            to.user(),
            got.text,
            got.sender,
            got.frank.is_some()
        ));
    }
    // Neither sees its own message come back.
    record.note(format!(
        "alice's own: {}",
        alice
            .poll()
            .await
            .unwrap()
            .iter()
            .filter(|e| matches!(e, Event::Message(_)))
            .count()
    ));

    // bob restarts, and a message received but not acknowledged comes
    // again.
    drop(bob);
    let mut bob = device(&server, BOB, dir.path(), b).await;
    record.note(format!(
        "bob's rooms after restart {:?}",
        bob.rooms().iter().map(|r| r.status).collect::<Vec<_>>()
    ));
    let sent = alice
        .send_text(&room, "do not lose me")
        .await
        .unwrap()
        .message_id;
    let mut changed = server.changed();
    loop {
        let (events, receipt) = bob.receive().await.unwrap();
        if events
            .iter()
            .any(|e| matches!(e, Event::Message(m) if m.message_id == sent))
        {
            drop(receipt);
            break;
        }
        let progressed = !events.is_empty();
        bob.acknowledge(receipt).unwrap();
        if progressed {
            continue;
        }
        let stream = bob.stream_wake();
        common::look_again(
            "the message bob must not lose",
            &mut changed,
            stream.as_ref(),
        )
        .await;
    }
    drop(bob);
    let mut bob = device(&server, BOB, dir.path(), b).await;
    let (events, receipt) = bob.receive().await.unwrap();
    record.note(format!("again: {:?}", texts(&events)));
    bob.acknowledge(receipt).unwrap();

    alice.leave(&room).await.unwrap();
    let after = poll_until(&mut bob, &server, |e| match e {
        Event::MembersChanged { participants, .. } => Some(participants.clone()),
        _ => None,
    })
    .await;
    record.note(format!("after alice left {after:?}"));
    poll_until(&mut alice, &server, |e| match e {
        Event::Left { room: left } if *left == room => Some(()),
        _ => None,
    })
    .await;
    record.note(format!("alice {:?}", alice.rooms()[0].status));
    record.note(format!(
        "send after leaving: {}",
        short(&alice.send_text(&room, "gone").await.map(drop))
    ));
    record
}

fn texts(events: &[Event]) -> Vec<Option<String>> {
    events
        .iter()
        .filter_map(|e| match e {
            Event::Message(m) => Some(m.text.clone()),
            _ => None,
        })
        .collect()
}

/// An outcome without the room URI.
fn short<T>(result: &Result<T, AgentError>) -> String {
    match result {
        Ok(_) => "ok".to_owned(),
        Err(AgentError::NoKeyMaterial { code, .. }) => format!("no key material {code:?}"),
        Err(AgentError::NoSuchRoom(_)) => "no such room".to_owned(),
        Err(error) => format!("{error}"),
    }
}

#[tokio::test]
async fn the_two_agent_scenario_agrees_over_both_bindings() {
    let jmap = scenario(Binding::Jmap, Binding::Jmap).await;
    let stream = scenario(Binding::Stream, Binding::Stream).await;
    assert_eq!(stream, jmap);
    let mixed = scenario(Binding::Jmap, Binding::Stream).await;
    assert_eq!(mixed, jmap);
    // The record is the scenario's, not empty.
    assert!(jmap.0.len() > 15, "{jmap:?}");
    assert!(
        jmap.0
            .contains(&"after alice left [\"mimi://a.example/u/bob\"]".to_owned())
    );
    assert_eq!(
        jmap.0.last().map(String::as_str),
        Some("send after leaving: no such room")
    );
}

/// A wrong token: the stream refuses it at the hello, as JMAP at the
/// Session.
#[tokio::test]
async fn a_wrong_token_is_refused_on_either_binding() {
    let dir = tempfile::tempdir().unwrap();
    let server = stream_server(dir.path()).await;
    for binding in [Binding::Jmap, Binding::Stream] {
        let opened = Agent::open(AgentConfig {
            server_url: server.base.clone(),
            binding,
            token: "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8".to_owned(),
            user_uri: ALICE.to_owned(),
            state_dir: dir.path().join(format!("{binding:?}")),
            full_tree_hubs: Vec::new(),
            did_webvh: DidWebvhConfig::default(),
        })
        .await;
        match (binding, opened) {
            (Binding::Jmap, Err(AgentError::Status { status: 401, .. })) => {}
            (Binding::Stream, Err(AgentError::Method { kind, .. })) if kind == "unauthorized" => {}
            (binding, other) => panic!("{binding:?}: {:?}", other.map(|_| ())),
        }
    }
}

/// Messages sent while the stream agent is closed arrive once when it
/// opens again, and a crash before the position is saved gets the same
/// Messages again, once.
#[tokio::test]
async fn no_gap_and_no_duplicate_across_reconnects() {
    let dir = tempfile::tempdir().unwrap();
    let server = stream_server(dir.path()).await;
    let mut alice = device(&server, ALICE, dir.path(), Binding::Jmap).await;
    let mut bob = device(&server, BOB, dir.path(), Binding::Stream).await;
    bob.publish_key_packages(1).await.unwrap();
    let room = alice.host_room(&HostOptions::named("r")).await.unwrap();
    alice.invite(&room, BOB).await.unwrap();
    let number = poll_until(&mut bob, &server, |e| match e {
        Event::InviteArrived { number } => Some(*number),
        _ => None,
    })
    .await;
    bob.join(number).unwrap();
    bob.poll().await.unwrap();

    drop(bob);
    for text in ["one", "two", "three"] {
        alice.send_text(&room, text).await.unwrap();
    }
    let mut bob = device(&server, BOB, dir.path(), Binding::Stream).await;
    let mut got = Vec::new();
    let mut changed = server.changed();
    while got.len() < 3 {
        let events = bob.poll().await.unwrap();
        let progressed = !events.is_empty();
        got.extend(texts(&events));
        if got.len() >= 3 {
            break;
        }
        if progressed {
            continue;
        }
        let stream = bob.stream_wake();
        common::look_again("all three messages", &mut changed, stream.as_ref()).await;
    }
    assert_eq!(
        got,
        ["one", "two", "three"].map(|t| Some(t.to_owned())),
        "each once, in order"
    );

    // Received, not acknowledged, connection gone: the next agent on the
    // same state resubscribes from the saved position and gets it again,
    // once.
    alice.send_text(&room, "four").await.unwrap();
    let mut changed = server.changed();
    loop {
        let (events, receipt) = bob.receive().await.unwrap();
        if texts(&events).contains(&Some("four".to_owned())) {
            drop(receipt);
            break;
        }
        let progressed = !events.is_empty();
        bob.acknowledge(receipt).unwrap();
        if progressed {
            continue;
        }
        let stream = bob.stream_wake();
        common::look_again("the fourth message", &mut changed, stream.as_ref()).await;
    }
    drop(bob);
    let mut bob = device(&server, BOB, dir.path(), Binding::Stream).await;
    assert_eq!(texts(&bob.poll().await.unwrap()), [Some("four".to_owned())]);
    alice.send_text(&room, "five").await.unwrap();
    let mut later = Vec::new();
    let mut changed = server.changed();
    while later.is_empty() {
        let events = bob.poll().await.unwrap();
        let progressed = !events.is_empty();
        later.extend(texts(&events));
        if !later.is_empty() {
            break;
        }
        if progressed {
            continue;
        }
        let stream = bob.stream_wake();
        common::look_again(
            "the message after the restart",
            &mut changed,
            stream.as_ref(),
        )
        .await;
    }
    assert_eq!(later, [Some("five".to_owned())]);
}

type Socket =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

/// The socket is the event: `next` is an await on the connection, so
/// the reactor wakes this when a frame arrives. No deadline, so a
/// provider that never answers hangs the test rather than failing it on
/// a loaded machine.
async fn next(socket: &mut Socket, kind: Option<OpKind>) -> ProviderMessage {
    loop {
        let frame = socket.next().await.expect("open").unwrap();
        if let Message::Binary(bytes) = frame {
            return ProviderMessage::decode(&bytes, |_| kind).unwrap();
        }
    }
}

/// JMAP `Message/changes` from `since` for `token`'s account: the ids
/// created and the new state.
async fn jmap_changes(server: &Server, token: &str, since: &str) -> (Vec<String>, String) {
    let http = reqwest::Client::new();
    let session: Value = http
        .get(format!("{}/.well-known/jmap", server.base))
        .bearer_auth(token)
        .send()
        .await
        .unwrap()
        .text()
        .await
        .map(|text| serde_json::from_str(&text).unwrap())
        .unwrap();
    let account = session["primaryAccounts"]["urn:ietf:params:jmap:chat:mimi"]
        .as_str()
        .unwrap()
        .to_owned();
    let answer: Value = http
        .post(format!("{}/jmap/api", server.base))
        .bearer_auth(token)
        .header("Content-Type", "application/json")
        .body(
            json!({
                "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:chat"],
                "methodCalls": [["Message/changes", {"accountId": account, "sinceState": since}, "c"]],
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap()
        .text()
        .await
        .map(|text| serde_json::from_str(&text).unwrap())
        .unwrap();
    let changes = &answer["methodResponses"][0][1];
    (
        changes["created"]
            .as_array()
            .unwrap()
            .iter()
            .map(|id| id.as_str().unwrap().to_owned())
            .collect(),
        changes["newState"].as_str().unwrap().to_owned(),
    )
}

/// Bob subscribes before he is in any room. Alice invites him: the
/// Welcome, which makes a membership and so Messages visible, arrives
/// over the open subscription, and each position the stream gives is a
/// state JMAP's Message/changes accepts and agrees with (findings F1).
#[tokio::test]
async fn a_membership_change_while_subscribed() {
    let dir = tempfile::tempdir().unwrap();
    let server = stream_server(dir.path()).await;
    let mut alice = device(&server, ALICE, dir.path(), Binding::Jmap).await;
    let mut bob = device(&server, BOB, dir.path(), Binding::Jmap).await;
    bob.publish_key_packages(1).await.unwrap();
    drop(bob);

    let url = format!(
        "{}{}",
        server.base.replacen("http", "ws", 1),
        mimid_live::PATH
    );
    let (mut socket, _) = tokio_tungstenite::connect_async(url).await.unwrap();
    let hello = ClientMessage::Hello(ClientHello {
        versions: vec![mimid_live::VERSION],
        token: server.tokens[BOB].clone(),
        keepalive: Some(mimid_live::Keepalive::default()),
        extra: Vec::new(),
    });
    socket
        .send(Message::Binary(hello.encode().into()))
        .await
        .unwrap();
    assert!(matches!(
        next(&mut socket, None).await,
        ProviderMessage::Hello(_)
    ));
    let subscribe = ClientMessage::Request(Request {
        v: mimid_live::VERSION,
        id: 1,
        op: Op::Subscribe {
            since: None,
            after: None,
        },
        extra: Vec::new(),
    });
    socket
        .send(Message::Binary(subscribe.encode().into()))
        .await
        .unwrap();
    let start = match next(&mut socket, Some(OpKind::Subscribe)).await {
        ProviderMessage::Ack(ack) => match ack.result {
            AckResult::Subscribe { state } => state,
            other => panic!("{other:?}"),
        },
        other => panic!("{other:?}"),
    };

    let room = alice.host_room(&HostOptions::named("r")).await.unwrap();
    alice.invite(&room, BOB).await.unwrap();
    alice.send_text(&room, "welcome").await.unwrap();

    // Delivers and Positions until bob has seen the Welcome and the
    // message, two Messages, and a Position after the last of them.
    let mut delivered = Vec::new();
    let mut position = None;
    while delivered.len() < 2 || position.is_none() {
        match next(&mut socket, None).await {
            ProviderMessage::Deliver(d) => {
                delivered.push(d.message_id);
                position = None;
            }
            ProviderMessage::Position(p) => position = Some(p.state),
            ProviderMessage::Changed(_) => {}
            other => panic!("{other:?}"),
        }
    }
    let position = position.unwrap();
    // JMAP, from where the stream started, lists exactly what it
    // delivered, in the same order, and has nothing past the stream's
    // last position.
    let token = &server.tokens[BOB];
    let (created, state) = jmap_changes(&server, token, &start).await;
    assert_eq!(created, delivered);
    assert_eq!(state, position);
    assert_eq!(
        jmap_changes(&server, token, &position).await,
        (Vec::new(), position.clone())
    );
}

/// Findings log F12, on both bindings: an agent whose saved Message state
/// the provider cannot follow (here written ahead of the account's, as a
/// database restored from elsewhere would be) gets `cannotCalculateChanges`
/// on JMAP and `cannotResume` on the stream, and then reads only the
/// Messages after the last one it handled in each Chat: what it handled
/// does not come again, the new message comes once, and MLS reports no
/// Problem (`poll_until` fails on one).
#[tokio::test]
async fn a_lost_message_state_resumes_after_the_last_handled_message() {
    for binding in [Binding::Jmap, Binding::Stream] {
        let dir = tempfile::tempdir().unwrap();
        let server = stream_server(dir.path()).await;
        let mut alice = device(&server, ALICE, dir.path(), Binding::Jmap).await;
        let mut bob = device(&server, BOB, dir.path(), binding).await;
        bob.publish_key_packages(1).await.unwrap();
        let room = alice.host_room(&HostOptions::named("r")).await.unwrap();
        alice.invite(&room, BOB).await.unwrap();
        let number = poll_until(&mut bob, &server, |e| match e {
            Event::InviteArrived { number } => Some(*number),
            _ => None,
        })
        .await;
        bob.join(number).unwrap();
        alice.send_text(&room, "before").await.unwrap();
        poll_until(&mut bob, &server, |e| match e {
            Event::Message(m) if m.text.as_deref() == Some("before") => Some(()),
            _ => None,
        })
        .await;

        drop(bob);
        let database = rusqlite::Connection::open(
            dir.path().join("bob").join(mimid_agent_core::DATABASE_FILE),
        )
        .unwrap();
        let changed = database
            .execute(
                "UPDATE agent_state SET record = json_set(record, '$.message_state', '99999.99')",
                [],
            )
            .unwrap();
        assert_eq!(changed, 1);
        drop(database);
        alice.send_text(&room, "after").await.unwrap();
        let mut bob = device(&server, BOB, dir.path(), binding).await;
        let mut got = Vec::new();
        let mut woken = server.changed();
        while got.is_empty() {
            let events = bob.poll().await.unwrap();
            for event in &events {
                if let Event::Problem { description, .. } = event {
                    panic!("{binding:?}: {description}");
                }
            }
            let progressed = !events.is_empty();
            got.extend(texts(&events));
            if !got.is_empty() {
                break;
            }
            if progressed {
                continue;
            }
            let stream = bob.stream_wake();
            common::look_again(
                &format!("{binding:?}: the message after the gap"),
                &mut woken,
                stream.as_ref(),
            )
            .await;
        }
        assert_eq!(got, [Some("after".to_owned())], "{binding:?}");
    }
}
