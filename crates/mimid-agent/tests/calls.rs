//! Calls to join (bead mimid-0p8s; docs/design/agent-frontends.md §7.24):
//! mimi-content-10 §5.10's conferencing example, an ExternalPart of
//! disposition `session`, sent and received through running daemons on
//! one provider and across two, and shown on IRC and JMAP Chat.
//!
//! Oracles: the §5.10 example itself (the WG's CBOR, committed under
//! crates/mimi-content/tests/fixtures/wg-10 with its PROVENANCE), whose
//! body a call sent from JMAP or IRC must equal; draft-atwood-jmap-chat-00
//! §Endpoint and §MessageAction (`type`
//! `urn:ietf:params:jmap:chat:cap:vtc`, `uri`, `label`); the IRC lines of
//! §7.24, written out here by hand.

#![forbid(unsafe_code)]

mod common;

use common::irc::{Irc, Msg};
use common::{ALICE, BOB, BOB_B, Client, Running, Server, config, server, two_providers};
use mimi_content::{Disposition, MimiContent, NestedPart, Part, PartSemantics};
use mimid_agent::Config;
use mimid_agent::config::IrcSetting;
use mimid_agent_store::Store;
use mimid_agent_store::record::{Call, Message};
use serde_json::{Value, json};

/// mimi-content-10 §5.10's example, as the WG published it.
const CONFERENCING: &[u8] =
    include_bytes!("../../mimi-content/tests/fixtures/wg-10/conferencing.cbor");

/// The example's URL and description.
const URL: &str = "https://example.com/join/12345";
const DESCRIPTION: &str = "Join the Foo 118 conference";

/// The ACTION text of the example's call on IRC (§7.24).
const CALL_LINE: &str =
    "\x01ACTION call: Join the Foo 118 conference <https://example.com/join/12345>\x01";

/// draft-atwood-jmap-chat-00 §Endpoint: a video or voice call.
const VTC: &str = "urn:ietf:params:jmap:chat:cap:vtc";

/// The client's `sentAt` for every Message it posts.
const SENT_AT: &str = "2026-11-21T12:00:00Z";

/// The channel both sides show the room under.
const CHANNEL: &str = "#lobby";

/// `config` with `[irc]` on a free loopback port.
fn with_irc(mut config: Config) -> Config {
    config.irc = Some(IrcSetting {
        listen: "127.0.0.1:0".parse().unwrap(),
        ..IrcSetting::default()
    });
    config
}

/// One side of the conversation: its daemon, IRC client, JMAP client,
/// user URI and hostmask.
struct Side {
    daemon: Running,
    irc: Irc,
    jmap: Client,
    user: &'static str,
    mask: &'static str,
}

impl Side {
    async fn start(
        server: &Server,
        user: &'static str,
        mask: &'static str,
        dir: &std::path::Path,
    ) -> Self {
        let daemon = Running::start(&with_irc(config(server, user, dir, "any"))).await;
        let (irc, _) = Irc::register(
            daemon.irc.unwrap(),
            daemon.token().trim(),
            "someone",
            &["message-tags", "server-time", "echo-message"],
        )
        .await;
        let jmap = daemon.client().await;
        Self {
            daemon,
            irc,
            jmap,
            user,
            mask,
        }
    }

    fn store(&self) -> &Store {
        &self.daemon.store
    }

    /// The URI of the one room.
    fn room(&self) -> String {
        let state = self.store().state();
        assert_eq!(state.rooms.len(), 1);
        state.rooms.values().next().unwrap().uri.clone()
    }

    /// The JMAP id of the one Chat.
    async fn chat(&self) -> String {
        let chats = self.jmap.get("Chat", None).await;
        assert_eq!(chats.len(), 1, "{chats:#?}");
        chats[0]["id"].as_str().unwrap().to_owned()
    }

    /// The Message whose `senderMsgId` is `id`.
    async fn message(&self, id: &str) -> Value {
        let messages = self.jmap.messages(&self.chat().await).await;
        messages
            .into_iter()
            .find(|m| m["senderMsgId"] == json!(id))
            .unwrap_or_else(|| panic!("no Message {id}"))
    }

    /// The record of the message whose `senderMsgId` is `id`.
    fn record(&self, id: &str) -> Message {
        self.store()
            .state()
            .messages
            .values()
            .find(|m| m.sender_msg_id == id)
            .cloned()
            .unwrap_or_else(|| panic!("no record {id}"))
    }

    /// Sends the §5.10 example's content as this user's, to the one room,
    /// with `body` in place of its body (the example's own if `None`) and
    /// `salt_tag` as the salt's first octet, so each send is a message of
    /// its own.
    async fn send_example(&self, body: Option<NestedPart>, salt_tag: u8) {
        let room = self.room();
        let mut content = MimiContent::decode(CONFERENCING).unwrap();
        content.salt[0] = salt_tag;
        content.mimi_extensions.sender_uri = Some(self.user.to_owned());
        content.mimi_extensions.room_uri = Some(room.clone());
        if let Some(body) = body {
            content.nested_part = body;
        }
        self.store()
            .agent()
            .lock()
            .await
            .send_content(&room, &content)
            .await
            .unwrap();
    }

    /// The next PRIVMSG from `mask` to the channel.
    async fn line_from(&mut self, mask: &str) -> Msg {
        self.irc
            .until("a PRIVMSG", |m| {
                m.command == "PRIVMSG" && m.source == mask && m.params[0] == CHANNEL
            })
            .await
    }
}

/// The §5.10 example's body.
fn example_body() -> NestedPart {
    MimiContent::decode(CONFERENCING).unwrap().nested_part
}

/// The MIMI content `record` keeps for reports: its `application_data`
/// as received, the first field of the kept (Unverified)AbusiveMessage,
/// an `opaque<V>` (RFC 9420 §2.1.2: a variable-length integer whose top
/// two bits give its length, then that many octets).
fn received_content(record: &Message) -> MimiContent {
    let hex = &record
        .kept_frank
        .as_ref()
        .expect("kept for reports")
        .message;
    let bytes: Vec<u8> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect();
    let width = 1usize << (bytes[0] >> 6);
    let mut len = u64::from(bytes[0] & 0x3f);
    for b in &bytes[1..width] {
        len = len << 8 | u64::from(*b);
    }
    let len = usize::try_from(len).unwrap();
    MimiContent::decode(&bytes[width..width + len]).unwrap()
}

/// Waits until both sides show the room under [`CHANNEL`]: `host` JOINs
/// it, which hosts a room, and invites `guest`, whose daemon joins at
/// once.
async fn in_one_room(host: &mut Side, guest: &mut Side) {
    host.irc.send(&format!("JOIN {CHANNEL}")).await;
    host.irc.until_command("366").await;
    host.irc
        .send(&format!("INVITE {} {CHANNEL}", guest.user))
        .await;
    host.irc.until_command("341").await;
    let mask = guest.mask;
    guest
        .irc
        .until("the JOIN", |m| {
            m.command == "JOIN" && m.source == mask && m.params[0] == CHANNEL
        })
        .await;
    guest.irc.until_command("366").await;
}

/// The scenario, between `alice` and `bob`, already in one room: calls
/// both ways, from raw MIMI content, JMAP and IRC; a URL that is no web
/// link; an inline session part; refusals.
async fn calls_both_ways(alice: &mut Side, bob: &mut Side) {
    let action = json!([{"type": VTC, "uri": URL, "label": DESCRIPTION}]);

    // alice's client sends §5.10's example as is. bob's daemon keeps the
    // call and fetches nothing: no attachment, none waiting for a retry.
    alice.send_example(None, 1).await;
    let line = bob.line_from(alice.mask).await;
    assert_eq!(line.params, [CHANNEL, CALL_LINE], "{}", line.raw);
    let id = line.tags["msgid"].clone();
    let record = bob.record(&id);
    assert_eq!(
        record.calls,
        [Call {
            url: URL.to_owned(),
            description: DESCRIPTION.to_owned(),
            expires: None,
        }]
    );
    assert_eq!(record.body, "");
    assert!(record.attachments.is_empty());
    assert!(bob.store().state().pending_attachments.is_empty());
    let message = bob.message(&id).await;
    assert_eq!(message["actions"], action, "{message:#}");
    assert_eq!(message["body"], json!(""));
    assert_eq!(message["attachments"], json!([]));
    assert_eq!(message["topicId"], json!("Foo 118"));

    // bob answers from JMAP with a MessageAction: alice receives the
    // example's body exactly, and sees the same line and action.
    let chat = bob.chat().await;
    let created = bob
        .jmap
        .create(
            "Message",
            json!({
                "chatId": chat,
                "body": "",
                "sentAt": SENT_AT,
                "actions": action,
            }),
        )
        .await;
    let id = created["senderMsgId"].as_str().unwrap().to_owned();
    let line = alice.line_from(bob.mask).await;
    assert_eq!(line.params, [CHANNEL, CALL_LINE], "{}", line.raw);
    assert_eq!(line.tags["msgid"], id);
    assert_eq!(
        received_content(&alice.record(&id)).nested_part,
        example_body()
    );
    assert_eq!(alice.message(&id).await["actions"], action);
    assert_eq!(bob.message(&id).await["actions"], action);

    // alice sends one from IRC: the same body; her echo and bob's line.
    alice
        .irc
        .send(&format!(
            "PRIVMSG mimid :call {CHANNEL} {URL} {DESCRIPTION}"
        ))
        .await;
    let mask = alice.mask;
    let echo = alice.line_from(mask).await;
    assert_eq!(echo.params, [CHANNEL, CALL_LINE], "{}", echo.raw);
    let line = bob.line_from(alice.mask).await;
    assert_eq!(line.params, [CHANNEL, CALL_LINE], "{}", line.raw);
    let id = line.tags["msgid"].clone();
    assert_eq!(echo.tags["msgid"], id);
    assert_eq!(
        received_content(&bob.record(&id)).nested_part,
        example_body()
    );

    // A URL that is no https or wss link is text, never an action.
    let mut sip = example_body();
    let Part::External(part) = &mut sip.part else {
        panic!("the example is an ExternalPart");
    };
    part.url = "sip:alice@example.com".to_owned();
    part.description = "Ring me".to_owned();
    alice.send_example(Some(sip), 2).await;
    let text = "call: Ring me (not a web link: sip:alice@example.com)";
    let line = bob.line_from(alice.mask).await;
    let action_text = format!("\x01ACTION {text}\x01");
    assert_eq!(line.params, [CHANNEL, action_text.as_str()], "{}", line.raw);
    let message = bob.message(&line.tags["msgid"]).await;
    assert_eq!(message["actions"], json!([]));
    assert_eq!(message["body"], json!(text));

    // An inline session part of text beside text: both shown, the text
    // first, with the message's tags.
    let part = |disposition, content_type: &str, content: &[u8]| NestedPart {
        disposition,
        language: String::new(),
        part: Part::Single {
            content_type: content_type.to_owned(),
            content: content.to_vec(),
        },
    };
    let inline = NestedPart {
        disposition: Disposition::RENDER,
        language: String::new(),
        part: Part::Multi {
            part_semantics: PartSemantics::ProcessAll,
            // The session part first: it is not the message's text.
            parts: vec![
                part(
                    Disposition::SESSION,
                    "text/uri-list",
                    format!("# the call\r\n{URL}\r\n").as_bytes(),
                ),
                part(
                    Disposition::RENDER,
                    "text/plain;charset=utf-8",
                    b"standup now",
                ),
            ],
        },
    };
    alice.send_example(Some(inline), 3).await;
    let first = bob.line_from(alice.mask).await;
    assert_eq!(first.params, [CHANNEL, "standup now"]);
    let second = bob.line_from(alice.mask).await;
    let action_text = format!("\x01ACTION call: <{URL}>\x01");
    assert_eq!(second.params, [CHANNEL, action_text.as_str()]);
    assert!(!second.tags.contains_key("msgid"), "{}", second.raw);
    let message = bob.message(&first.tags["msgid"]).await;
    assert_eq!(message["body"], json!("standup now"));
    assert_eq!(message["actions"], json!([{"type": VTC, "uri": URL}]));

    // Refusals: IRC and JMAP send only https and wss links, and JMAP no
    // other action.
    alice
        .irc
        .send(&format!(
            "PRIVMSG mimid :call {CHANNEL} http://example.com/x"
        ))
        .await;
    let notice = alice
        .irc
        .until("the service's answer", |m| {
            m.command == "NOTICE" && m.source.starts_with("mimid!")
        })
        .await;
    assert!(notice.text().contains("not sent"), "{}", notice.raw);
    for actions in [
        json!([{"type": VTC, "uri": "sip:bob@example.com"}]),
        json!([{"type": "urn:ietf:params:jmap:chat:cap:payment", "uri": URL}]),
        json!([{"type": VTC, "uri": URL, "metadata": {"protocol": "webrtc"}}]),
        json!([{"type": VTC, "uri": URL}, {"type": VTC, "uri": URL}]),
    ] {
        let answer = bob
            .jmap
            .call(
                "Message/set",
                json!({"create": {"k": {
                    "chatId": chat, "body": "", "sentAt": SENT_AT, "actions": actions,
                }}}),
            )
            .await;
        let refused = &answer["notCreated"]["k"];
        assert_eq!(refused["type"], json!("invalidProperties"), "{answer:#}");
        assert_eq!(refused["properties"], json!(["actions"]), "{answer:#}");
    }
}

/// alice and bob on a.example.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn calls_on_one_provider() {
    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path(), &[ALICE, BOB]).await;
    let mut alice = Side::start(&server, ALICE, "alice-a!alice@a.example", dir.path()).await;
    let mut bob = Side::start(&server, BOB, "bob-a!bob@a.example", dir.path()).await;
    in_one_room(&mut alice, &mut bob).await;
    calls_both_ways(&mut alice, &mut bob).await;
    for side in [alice, bob] {
        drop(side.irc);
        side.daemon.stop().await;
    }
}

/// alice on a.example, bob on b.example, the room on bob's provider.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn calls_across_two_providers() {
    let dir = tempfile::tempdir().unwrap();
    let (a, b) = two_providers(dir.path(), &[ALICE], &[BOB_B]).await;
    let mut alice = Side::start(&a, ALICE, "alice-a!alice@a.example", dir.path()).await;
    let mut bob = Side::start(&b, BOB_B, "bob-b!bob@b.example", dir.path()).await;
    in_one_room(&mut bob, &mut alice).await;
    calls_both_ways(&mut alice, &mut bob).await;
    for side in [alice, bob] {
        drop(side.irc);
        side.daemon.stop().await;
    }
}
