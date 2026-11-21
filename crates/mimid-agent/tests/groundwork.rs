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

/// Polls `client`'s Message `id` until `done` holds for it.
async fn until_message(client: &common::Client, id: &str, done: impl Fn(&Value) -> bool) -> Value {
    for _ in 0..100 {
        let got = client.get("Message", Some(vec![id])).await;
        if let Some(m) = got.first()
            && done(m)
        {
            return m.clone();
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    panic!("Message {id} never got there");
}

/// Oracle: draft-atwood-jmap-chat-00 §Reaction and §Adding and Removing
/// Reactions (`reactions/<senderReactionId>`, `emoji`, `senderId`); the
/// IRCv3 `+draft/react` and `+draft/reply` client tags on TAGMSG;
/// docs/design/agent-frontends.md §7.27 for the ACTION lines without
/// message-tags and for `+draft/unreact`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reactions_through_jmap_and_irc() {
    let mut p = pair(&["message-tags"]).await;
    // A second IRC connection of alice's, without message-tags.
    let (mut plain, _) = Irc::register(p.alice.irc.unwrap(), &p.alice.token(), "alice", &[]).await;
    p.a.send("PRIVMSG #lobby :vote").await;
    let vote = privmsg(&mut p.b, ALICE_MASK, "vote").await;
    let msgid = vote.tags["msgid"].clone();

    // bob reacts from IRC.
    p.b.send(&format!(
        "@+draft/react=👍;+draft/reply={msgid} TAGMSG #lobby"
    ))
    .await;
    let tagged =
        p.a.until("bob's reaction", |m| {
            m.command == "TAGMSG" && m.source == BOB_MASK
        })
        .await;
    assert_eq!(tagged.params, ["#lobby"]);
    assert_eq!(tagged.tags["+draft/react"], "👍");
    assert_eq!(tagged.tags["+draft/reply"], msgid);
    let action = plain
        .until("bob's reaction as ACTION", |m| {
            m.command == "PRIVMSG" && m.source == BOB_MASK
        })
        .await;
    assert_eq!(
        action.params,
        [
            "#lobby",
            &format!("\x01ACTION reacted 👍 to {ALICE_NICK}\x01")
        ]
    );

    // alice's JMAP client sees it, and reacts and takes it back.
    let jmap = p.alice.client().await;
    let message = message_with_body(&jmap, "vote").await;
    let id = message["id"].as_str().unwrap().to_owned();
    let seen = until_message(&jmap, &id, |m| {
        m["reactions"].as_object().is_some_and(|r| r.len() == 1)
    })
    .await;
    let (_, bobs) = seen["reactions"]
        .as_object()
        .unwrap()
        .iter()
        .next()
        .unwrap();
    assert_eq!(bobs["emoji"], json!("👍"));
    assert_ne!(bobs["senderId"], json!(jmap.account));
    let reaction_id = "01HF7YAT01041061050R3GG28B";
    let answer = jmap
        .call(
            "Message/set",
            json!({"update": {&id: {format!("reactions/{reaction_id}"): {"emoji": "❤"}}}}),
        )
        .await;
    assert!(answer["updated"].get(&id).is_some(), "{answer}");
    let heart =
        p.b.until("alice's reaction", |m| {
            m.command == "TAGMSG" && m.source == ALICE_MASK
        })
        .await;
    assert_eq!(heart.tags["+draft/react"], "❤");
    assert_eq!(heart.tags["+draft/reply"], msgid);
    let stored = jmap.get("Message", Some(vec![&id])).await;
    assert_eq!(stored[0]["reactions"][reaction_id]["emoji"], json!("❤"));
    assert_eq!(
        stored[0]["reactions"][reaction_id]["senderId"],
        json!(jmap.account)
    );
    let answer = jmap
        .call(
            "Message/set",
            json!({"update": {&id: {format!("reactions/{reaction_id}"): null}}}),
        )
        .await;
    assert!(answer["updated"].get(&id).is_some(), "{answer}");
    let gone =
        p.b.until("alice's unreaction", |m| {
            m.command == "TAGMSG" && m.tags.contains_key("+draft/unreact")
        })
        .await;
    assert_eq!(gone.tags["+draft/unreact"], "❤");

    // bob takes his back from IRC.
    p.b.send(&format!(
        "@+draft/unreact=👍;+draft/reply={msgid} TAGMSG #lobby"
    ))
    .await;
    let action = plain
        .until("bob's unreaction as ACTION", |m| {
            m.command == "PRIVMSG" && m.source == BOB_MASK && m.text().contains("took back")
        })
        .await;
    assert_eq!(
        action.params,
        [
            "#lobby",
            &format!("\x01ACTION took back 👍 from {ALICE_NICK}\x01")
        ]
    );
    until_message(&jmap, &id, |m| {
        m["reactions"].as_object().is_none_or(|r| r.is_empty())
    })
    .await;
    drop(plain);
    p.stop().await;
}

/// `{"src": "abcd", "uri": "nostr:npub1x", "name": "Bob"}`, the
/// `mimid-on-behalf-of` value of docs/design/marmot-bridge.md §3.2,
/// encoded by hand.
const ON_BEHALF_OF: [u8; 36] = [
    0xa3, 0x63, b's', b'r', b'c', 0x64, b'a', b'b', b'c', b'd', 0x63, b'u', b'r', b'i', 0x6c, b'n',
    b'o', b's', b't', b'r', b':', b'n', b'p', b'u', b'b', b'1', b'x', 0x64, b'n', b'a', b'm', b'e',
    0x63, b'B', b'o', b'b',
];

/// Oracle: docs/design/marmot-bridge.md §3.2 ("only as 'Bob (via
/// marmot-bridge)', never as a sender in its own right") and
/// docs/design/agent-frontends.md §7.28: IRC shows `Bob (via bob-a):`
/// unless the text starts with the name; JMAP carries the entry in
/// `mimid.invalid:onBehalfOf`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn on_behalf_of_through_jmap_and_irc() {
    use mimid_agent_store::action::SendOptions;
    use mimid_agent_store::record::ON_BEHALF_OF_KEY;
    let mut p = pair(&["message-tags"]).await;
    let room = p
        .bob
        .store
        .state()
        .rooms
        .values()
        .next()
        .unwrap()
        .key
        .clone();
    let mut options = SendOptions::new();
    options.extensions.insert(
        mimi_content::ExtensionKey::Text(ON_BEHALF_OF_KEY.to_owned()),
        mimi_content::RawValue::new(&ON_BEHALF_OF).unwrap(),
    );
    for text in ["sounds good", "Bob (npub1x, via bridge): prefixed"] {
        let key = p.bob.store.new_key();
        p.bob
            .store
            .send_message(key, &room, text, &[], &options)
            .await
            .unwrap();
        p.bob.store.save().await.unwrap();
    }
    privmsg(
        &mut p.a,
        BOB_MASK,
        &format!("Bob (via {BOB_NICK}): sounds good"),
    )
    .await;
    privmsg(&mut p.a, BOB_MASK, "Bob (npub1x, via bridge): prefixed").await;
    let jmap = p.alice.client().await;
    let message = message_with_body(&jmap, "sounds good").await;
    assert_eq!(
        message["mimid.invalid:onBehalfOf"],
        json!({"uri": "nostr:npub1x", "name": "Bob", "src": "abcd"})
    );
    assert_ne!(message["senderId"], json!(jmap.account));
    p.stop().await;
}
