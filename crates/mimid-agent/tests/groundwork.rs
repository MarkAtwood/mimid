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

/// Oracle: draft-atwood-jmap-chat-00 §Chat (`kind` "direct", `contactId`
/// "the ChatContact.id of the other participant") and §Creating a Direct
/// Chat (`alreadyExists` with `existingId`); docs/design/agent-frontends.md
/// §7.29.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn direct_chats_over_jmap() {
    let p = pair(&["message-tags"]).await;
    let alice = p.alice.client().await;
    let bob = p.bob.client().await;
    let contacts = alice.get("ChatContact", None).await;
    let bob_contact = contacts
        .iter()
        .find(|c| c["identity"] == json!(BOB))
        .unwrap()["id"]
        .clone();
    let created = alice
        .create("Chat", json!({"kind": "direct", "contactId": bob_contact}))
        .await;
    let id = created["id"].as_str().unwrap().to_owned();
    let chat = alice.get("Chat", Some(vec![&id])).await;
    assert_eq!(chat[0]["kind"], json!("direct"));
    assert_eq!(chat[0]["contactId"], bob_contact);
    assert!(chat[0]["roomId"].as_str().unwrap().starts_with("mimi://"));
    let again = alice
        .call(
            "Chat/set",
            json!({"create": {"k": {"kind": "direct", "contactId": bob_contact}}}),
        )
        .await;
    assert_eq!(again["notCreated"]["k"]["type"], json!("alreadyExists"));
    assert_eq!(again["notCreated"]["k"]["existingId"], json!(id));

    // bob's daemon joins it (invites = "any") and shows it direct too.
    let mut seen = None;
    for _ in 0..100 {
        seen = bob
            .get("Chat", None)
            .await
            .into_iter()
            .find(|c| c["roomId"] == chat[0]["roomId"]);
        if seen.is_some() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    let seen = seen.expect("bob has the Chat");
    assert_eq!(seen["kind"], json!("direct"));
    let alice_contact = bob
        .get("ChatContact", None)
        .await
        .into_iter()
        .find(|c| c["identity"] == json!(ALICE))
        .unwrap()["id"]
        .clone();
    assert_eq!(seen["contactId"], alice_contact);
    p.stop().await;
}

/// Bead mimid-2vcw, option B, JMAP Chat's half (docs/design/
/// agent-frontends.md §7.29): `Chat/set` destroy of a direct Chat
/// succeeds without leaving the room; the Chat and its Messages go and
/// stay gone across syncs, and the other user's next message makes a new
/// direct Chat of the same room holding only that message.
#[tokio::test]
async fn destroying_a_direct_chat_hides_it_until_the_next_message() {
    let p = pair(&["message-tags"]).await;
    let alice = p.alice.client().await;
    let bob = p.bob.client().await;
    let bob_contact = alice
        .get("ChatContact", None)
        .await
        .into_iter()
        .find(|c| c["identity"] == json!(BOB))
        .unwrap()["id"]
        .clone();
    let id = alice
        .create("Chat", json!({"kind": "direct", "contactId": bob_contact}))
        .await["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let room = alice.get("Chat", Some(vec![&id])).await[0]["roomId"].clone();
    let bob_chat = async || {
        for _ in 0..100 {
            if let Some(chat) = bob
                .get("Chat", None)
                .await
                .into_iter()
                .find(|c| c["roomId"] == room)
            {
                return chat["id"].as_str().unwrap().to_owned();
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        panic!("bob never had the Chat");
    };
    let bob_id = bob_chat().await;
    let say = async |body: &str| {
        bob.create(
            "Message",
            json!({"chatId": bob_id, "body": body, "sentAt": "2026-11-22T12:00:00Z"}),
        )
        .await;
    };
    let alice_chat = async |body: &str| {
        for _ in 0..100 {
            for chat in alice.get("Chat", None).await {
                if chat["roomId"] == room
                    && let Some(id) = chat["id"].as_str()
                    && alice
                        .messages(id)
                        .await
                        .iter()
                        .any(|m| m["body"] == json!(body))
                {
                    return id.to_owned();
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        panic!("alice never saw {body}");
    };
    say("before").await;
    assert_eq!(alice_chat("before").await, id);

    let destroyed = alice.call("Chat/set", json!({"destroy": [id]})).await;
    assert_eq!(destroyed["destroyed"], json!([id]), "{destroyed}");
    // Several of the daemon's syncs (every 100 ms) bring nothing back.
    tokio::time::sleep(std::time::Duration::from_millis(600)).await;
    assert!(
        alice
            .get("Chat", None)
            .await
            .iter()
            .all(|c| c["roomId"] != room),
        "hidden"
    );
    assert!(
        p.alice
            .store
            .agent()
            .lock()
            .await
            .rooms()
            .iter()
            .any(|r| r.uri == room.as_str().unwrap()
                && r.status == mimid_agent_core::RoomStatus::Active),
        "not left"
    );
    // bob's side is untouched.
    assert_eq!(bob.messages(&bob_id).await.len(), 1);

    say("after").await;
    let back = alice_chat("after").await;
    assert_ne!(back, id, "a new Chat");
    let chat = alice.get("Chat", Some(vec![&back])).await;
    assert_eq!(chat[0]["kind"], json!("direct"));
    assert_eq!(chat[0]["contactId"], bob_contact);
    let bodies: Vec<Value> = alice
        .messages(&back)
        .await
        .into_iter()
        .map(|m| m["body"].clone())
        .collect();
    assert_eq!(bodies, [json!("after")]);
    p.stop().await;
}

/// Oracle: docs/design/agent-frontends.md §7.30 and
/// mimid_agent_store::links: a link gives the attachment's octets with no
/// bearer token, with the attachment's media type, `nosniff`, `sandbox`
/// and `no-store`; a link with another MAC, blob or expiry, an expired
/// one, or one to a message deleted here, is 404; the Host check comes
/// first (421), and only GET goes without the bearer token.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn attachment_links_give_one_file_until_they_expire() {
    use mimid_agent_store::links::DEFAULT_LINK_LIFETIME;
    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path(), &[ALICE]).await;
    let alice = Running::start(&config(&server, ALICE, dir.path(), "any")).await;
    let jmap = alice.client().await;
    let chat = jmap
        .create(
            "Chat",
            json!({"kind": "group", "name": "files", "memberIds": []}),
        )
        .await["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let content = b"%PDF-1.7 not really".to_vec();
    let url = jmap.session["uploadUrl"]
        .as_str()
        .unwrap()
        .replace("{accountId}", &jmap.account);
    let uploaded = jmap
        .http
        .post(url)
        .bearer_auth(alice.token())
        .header("content-type", "application/pdf")
        .body(content.clone())
        .send()
        .await
        .unwrap()
        .bytes()
        .await
        .unwrap();
    let uploaded: Value = serde_json::from_slice(&uploaded).unwrap();
    let blob = uploaded["blobId"].as_str().unwrap().to_owned();
    let sent = jmap
        .create(
            "Message",
            json!({"chatId": chat, "body": "the report", "sentAt": "2026-11-21T12:00:00Z",
                   "attachments": [{"blobId": blob, "filename": "report é.pdf",
                   "contentType": "application/pdf", "size": content.len(),
                   "sha256": blob.strip_prefix('s').unwrap()}]}),
        )
        .await;
    let message = sent["id"].as_str().unwrap().to_owned();

    let store = &alice.store;
    let link = store
        .attachment_link(&message, &blob, DEFAULT_LINK_LIFETIME)
        .expect("a link");
    let base = alice.base();
    assert!(
        link.starts_with(&format!("{base}/attachment/{blob}/")),
        "{link}"
    );
    assert!(link.ends_with("/report%20%C3%A9.pdf"), "{link}");
    let http = reqwest::Client::new();
    let got = http.get(&link).send().await.unwrap();
    assert_eq!(got.status(), 200);
    assert_eq!(got.headers()["content-type"], "application/pdf");
    assert_eq!(got.headers()["x-content-type-options"], "nosniff");
    assert_eq!(got.headers()["content-security-policy"], "sandbox");
    assert_eq!(got.headers()["cache-control"], "no-store");
    assert_eq!(got.bytes().await.unwrap().to_vec(), content);

    // Another MAC, another expiry, an expired link: 404.
    let parts: Vec<&str> = link.rsplitn(4, '/').collect();
    let (name, mac, expires) = (parts[0], parts[1], parts[2]);
    let prefix = format!("{base}/attachment/{blob}");
    let mut wrong_mac = mac.to_owned();
    wrong_mac.replace_range(0..1, if mac.starts_with('0') { "1" } else { "0" });
    let later: u64 = expires.parse::<u64>().unwrap() + 1;
    let links = store.attachment_links().unwrap();
    for bad in [
        format!("{prefix}/{expires}/{wrong_mac}/{name}"),
        format!("{prefix}/{later}/{mac}/{name}"),
        links.link(&blob, "x", 1_000),
        format!(
            "{base}/attachment/s{}/{expires}/{mac}/{name}",
            "0".repeat(64)
        ),
    ] {
        let status = http.get(&bad).send().await.unwrap().status();
        assert_eq!(status, 404, "{bad}");
    }
    // A wrong Host is refused before anything else.
    let status = http
        .get(&link)
        .header("host", "evil.example")
        .send()
        .await
        .unwrap()
        .status();
    assert_eq!(status, 421);
    // Only GET of a link goes without the token.
    let status = http.post(&link).send().await.unwrap().status();
    assert_eq!(status, 401);
    // A message deleted here takes its links with it.
    let answer = jmap
        .call("Message/set", json!({"destroy": [message]}))
        .await;
    assert!(
        answer["destroyed"]
            .as_array()
            .is_some_and(|d| !d.is_empty()),
        "{answer}"
    );
    assert_eq!(http.get(&link).send().await.unwrap().status(), 404);
    alice.stop().await;
}
