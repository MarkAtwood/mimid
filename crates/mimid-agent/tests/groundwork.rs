//! The store groundwork for more front ends (epic mimid-qqtk;
//! docs/design/client-survey.md §1.3; docs/design/marmot-bridge.md §5 P1
//! to P3) through both front ends of two daemons on one in-process mimid
//! server: alice's JMAP client and IRC connection, and bob's IRC
//! connection.
//!
//! Oracles: draft-atwood-jmap-chat-00 §Message (`replyTo`, `reactions`)
//! and §Chat (`kind`), the IRCv3 `+draft/reply` and `+draft/react` client
//! tags, and docs/design/agent-frontends.md §7.25 onwards, each written
//! out here by hand; the exact text each side sent.

#![forbid(unsafe_code)]

mod common;

use common::irc::{Irc, Msg};
use common::{ALICE, BOB, Running, config, server};
use mimid_agent::Config;
use mimid_agent::config::IrcSetting;
use serde_json::{Value, json};

const ALICE_NICK: &str = "alice-a";
const ALICE_MASK: &str = "alice-a!alice@a.example";
const BOB_NICK: &str = "bob-a";
const BOB_MASK: &str = "bob-a!bob@a.example";

/// The caps a full client asks for.
const ALL_CAPS: [&str; 3] = ["message-tags", "server-time", "echo-message"];

/// `config` with `[irc]` on a free loopback port.
fn with_irc(mut config: Config) -> Config {
    config.irc = Some(IrcSetting {
        listen: "127.0.0.1:0".parse().unwrap(),
        ..IrcSetting::default()
    });
    config
}

/// Waits for the JOIN of `channel` by `mask` and the burst after it.
async fn joined(irc: &mut Irc, mask: &str, channel: &str) {
    irc.until(&format!("JOIN {channel}"), |m| {
        m.command == "JOIN" && m.source == mask && m.params[0] == channel
    })
    .await;
    irc.until_command("366").await;
}

/// Two daemons with JMAP and IRC, both in `#lobby`, which alice hosts;
/// alice's IRC with every cap, bob's with `bob_caps`.
struct Pair {
    alice: Running,
    bob: Running,
    a: Irc,
    b: Irc,
    _dir: tempfile::TempDir,
}

async fn pair(bob_caps: &[&str]) -> Pair {
    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path(), &[ALICE, BOB]).await;
    let alice = Running::start(&with_irc(config(&server, ALICE, dir.path(), "any"))).await;
    let bob = Running::start(&with_irc(config(&server, BOB, dir.path(), "any"))).await;
    let (mut a, _) = Irc::register(alice.irc.unwrap(), &alice.token(), "alice", &ALL_CAPS).await;
    let (mut b, _) = Irc::register(bob.irc.unwrap(), &bob.token(), "bob", bob_caps).await;
    a.send("JOIN #lobby").await;
    joined(&mut a, ALICE_MASK, "#lobby").await;
    a.send(&format!("INVITE {BOB} #lobby")).await;
    a.until_command("341").await;
    joined(&mut b, BOB_MASK, "#lobby").await;
    a.until("bob's JOIN", |m| {
        m.command == "JOIN" && m.source == BOB_MASK
    })
    .await;
    Pair {
        alice,
        bob,
        a,
        b,
        _dir: dir,
    }
}

impl Pair {
    async fn stop(self) {
        drop((self.a, self.b));
        self.bob.stop().await;
        self.alice.stop().await;
    }
}

/// The first PRIVMSG from `mask` whose text is `text`.
async fn privmsg(irc: &mut Irc, mask: &str, text: &str) -> Msg {
    irc.until(text, |m| {
        m.command == "PRIVMSG" && m.source == mask && m.text() == text
    })
    .await
}

/// The Message of `client`'s only Chat whose body is `body`, waiting for
/// it.
async fn message_with_body(client: &common::Client, body: &str) -> Value {
    for _ in 0..100 {
        let chats = client.get("Chat", None).await;
        if let Some(chat) = chats.first() {
            let chat = chat["id"].as_str().unwrap().to_owned();
            if let Some(m) = client
                .messages(&chat)
                .await
                .into_iter()
                .find(|m| m["body"] == json!(body))
            {
                return m;
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    panic!("no Message {body:?}");
}

/// Oracle: draft-atwood-jmap-chat-00 §Message `replyTo` ("the
/// receiver-assigned `id` of the Message this replies to"); the IRCv3
/// `+draft/reply` client tag (the msgid replied to); the IRC custom of
/// addressing a line `nick: text` (docs/design/agent-frontends.md §7.25).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn replies_through_jmap_and_irc() {
    let mut p = pair(&["message-tags"]).await;
    p.b.send("PRIVMSG #lobby :question?").await;
    let asked = privmsg(&mut p.a, BOB_MASK, "question?").await;
    let jmap = p.alice.client().await;
    let question = message_with_body(&jmap, "question?").await;
    assert_eq!(question["senderMsgId"], json!(asked.tags["msgid"]));

    // JMAP replyTo goes out as inReplyTo; bob's IRC sees it addressed to
    // him, with +draft/reply naming his message.
    let created = jmap
        .create(
            "Message",
            json!({"chatId": question["chatId"], "body": "answer",
                   "replyTo": question["id"], "sentAt": "2026-11-21T12:00:00Z"}),
        )
        .await;
    let answer = privmsg(&mut p.b, ALICE_MASK, &format!("{BOB_NICK}: answer")).await;
    assert_eq!(answer.tags["+draft/reply"], asked.tags["msgid"]);
    let echo = privmsg(&mut p.a, ALICE_MASK, &format!("{BOB_NICK}: answer")).await;
    assert_eq!(echo.tags["+draft/reply"], asked.tags["msgid"]);
    let stored = jmap
        .get("Message", Some(vec![created["id"].as_str().unwrap()]))
        .await;
    assert_eq!(stored[0]["replyTo"], question["id"]);

    // bob replies from IRC with +draft/reply, having addressed alice
    // himself: the line is not addressed twice, and JMAP has replyTo.
    let target = answer.tags["msgid"].clone();
    p.b.send(&format!(
        "@+draft/reply={target} PRIVMSG #lobby :{ALICE_NICK}: thanks"
    ))
    .await;
    let thanks = privmsg(&mut p.a, BOB_MASK, &format!("{ALICE_NICK}: thanks")).await;
    assert_eq!(thanks.tags["+draft/reply"], target);
    let thanks = message_with_body(&jmap, &format!("{ALICE_NICK}: thanks")).await;
    assert_eq!(thanks["replyTo"], created["id"]);

    // A replyTo naming no Message of the Chat is refused, and nothing is
    // sent.
    let refused = jmap
        .call(
            "Message/set",
            json!({"create": {"k": {"chatId": question["chatId"], "body": "lost",
                   "replyTo": "nosuchmessage", "sentAt": "2026-11-21T12:00:00Z"}}}),
        )
        .await;
    assert!(refused["notCreated"]["k"].is_object(), "{refused}");
    p.stop().await;
}
