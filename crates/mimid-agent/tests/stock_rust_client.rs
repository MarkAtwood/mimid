//! Acceptance: an unmodified stock JMAP Chat client, crate-jmap's
//! `jmap-chat-client` at the revision the workspace pins, works against
//! two daemons (bead mimid-1wgh.13.11).
//!
//! alice's and bob's daemons run on one in-process mimid server
//! (a.example). Everything after the daemons start goes through the
//! client's public API only: `JmapClient::fetch_session`,
//! `SessionClient` methods for `ChatContact`, `Chat` and `Message`, and
//! `JmapClient::subscribe_events_session` for EventSource push. The test
//! harness supplies only what a client running as the user gets outside
//! JMAP: the daemon's URL and the local token from its state directory.
//!
//! bob's daemon joins every invite (`invites = "any"`): consent decisions
//! have no JMAP Chat method.
//!
//! Oracles: draft-atwood-jmap-chat-00 for the objects (a received
//! Message's `senderId` is a ChatContact whose `identity` is the sender's
//! user URI, an owner-composed one's is the accountId), draft-atwood-jmap-chat-mimi-00
//! §Chat.roomId for the room both Chats name, and RFC 8620 §7.3 for the
//! StateChange events. Each side must read exactly the text the other
//! posted.

#![forbid(unsafe_code)]

mod common;

use std::time::Duration;

use common::{ALICE, BOB, PATIENCE, Running, config, server};

/// One SSE frame named for a timeout message: a `StateChange` with the
/// types it carries, or an `Unknown` with its `event:` field.
///
/// A wait that times out has to say WHICH failure it is (bead
/// mimid-gn1w). No frame at all means the stream never delivered
/// anything. Frames that are all keepalives mean the stream is alive and
/// the state change it wanted was never sent -- for a stream opened just
/// before the write that causes it, that is a change published before
/// the subscribe completed, which the EventSource does not replay, so
/// waiting longer cannot help. A `StateChange` for other types means the
/// write landed but not for the type under test.
fn describe(event: &SseEvent) -> String {
    match event {
        SseEvent::StateChange(change) => {
            let types: Vec<&str> = change
                .changed
                .values()
                .flat_map(|types| types.keys().map(String::as_str))
                .collect();
            format!("StateChange({})", types.join("+"))
        }
        SseEvent::Unknown { event_type, .. } if event_type.is_empty() => {
            "Unknown(no event: field)".to_owned()
        }
        SseEvent::Unknown { event_type, .. } => format!("Unknown({event_type})"),
        // SseEvent is #[non_exhaustive]: a variant crate-jmap adds
        // later should still show up in a timeout message.
        other => format!("{other:?}"),
    }
}

/// What a wait saw, for its timeout message.
fn seen_report(seen: &[String]) -> String {
    if seen.is_empty() {
        "no frames arrived at all".to_owned()
    } else {
        format!("{} frame(s): {}", seen.len(), seen.join(", "))
    }
}
use futures::StreamExt;
use futures::stream::BoxStream;
use jmap_base_client::{
    BearerAuth, ClientConfig, ClientError, CloseAfter, JmapClient, QueryParams, Session, SseEvent,
    SseFrame, SubscribeEventsSessionParams,
};
use jmap_chat_client::{
    BodyType, ChatCreateInput, ChatSessionExt, JmapChatExt, MessageCreateInput, SessionClient,
};
use jmap_chat_types::{ChatKind, Message, MessageFilterCondition};
use jmap_types::{Filter, Id, UTCDate};

/// The client's `sentAt` for every Message it posts.
const SENT_AT: &str = "2026-11-16T12:00:00Z";

/// A stock client of one daemon.
struct Stock {
    client: JmapClient,
    session: Session,
    chat: SessionClient,
}

impl Stock {
    /// Builds the client from the daemon's URL and token and fetches the
    /// Session, as an application would.
    async fn connect(daemon: &Running) -> Self {
        let auth = BearerAuth::new(daemon.token().trim()).expect("a valid bearer token");
        let client = JmapClient::new_plain(auth, &daemon.base(), ClientConfig::default())
            .expect("the daemon URL is a valid base URL");
        let session = client.fetch_session().await.expect("fetch the Session");
        let chat = client.with_chat_session(session.clone());
        Self {
            client,
            session,
            chat,
        }
    }

    fn account(&self) -> Id {
        self.chat
            .chat_account_id()
            .expect("a primary account for urn:ietf:params:jmap:chat")
            .clone()
    }

    /// Opens the event source for every type, persisted, without pings.
    async fn events(&self) -> Events {
        let stream = self
            .client
            .subscribe_events_session(
                &self.session,
                SubscribeEventsSessionParams {
                    types: Some("*"),
                    close_after: Some(CloseAfter::No),
                    ping: Some(0),
                    last_event_id: None,
                },
            )
            .await
            .expect("open the event source");
        Events {
            stream,
            account: self.account(),
        }
    }

    /// Every Message of `chat`, in the server's default order.
    async fn messages(&self, chat: &Id) -> Vec<Message> {
        let mut condition = MessageFilterCondition::default();
        condition.chat_id = Some(chat.clone());
        let ids = self
            .chat
            .message_query(
                Some(&Filter::Condition(condition)),
                None,
                &QueryParams::default(),
            )
            .await
            .expect("Message/query")
            .ids;
        self.chat
            .message_get(Some(&ids), None)
            .await
            .expect("Message/get")
            .list
    }

    /// Posts `body` to `chat`; the new Message's id.
    async fn post(&self, chat: &Id, body: &str) -> Id {
        let sent_at = UTCDate::from(SENT_AT);
        let answer = self
            .chat
            .message_create(
                &MessageCreateInput {
                    client_id: Some("m"),
                    chat_id: chat,
                    body,
                    body_type: BodyType::Plain,
                    sent_at: &sent_at,
                    reply_to: None,
                    attachments: None,
                    mentions: None,
                    broadcast_mentions: None,
                    actions: None,
                    thread_root_id: None,
                    topic_id: None,
                    subject: None,
                    sender_expires_at: None,
                    burn_on_read: None,
                    expires_after_read_seconds: None,
                },
                None,
            )
            .await
            .expect("Message/set");
        assert!(answer.not_created.is_empty(), "{:?}", answer.not_created);
        answer.created["m"].id.clone().expect("a server-set id")
    }

    /// The `identity` of ChatContact `id`.
    async fn identity_of(&self, id: &Id) -> String {
        let got = self
            .chat
            .chat_contact_get(Some(std::slice::from_ref(id)), None)
            .await
            .expect("ChatContact/get");
        assert_eq!(got.list.len(), 1, "{:?}", got.not_found);
        got.list[0].identity.clone()
    }
}

/// An open event source.
struct Events {
    stream: BoxStream<'static, Result<SseFrame, ClientError>>,
    account: Id,
}

impl Events {
    /// Reads frames until a StateChange naming `type_name` for this
    /// account. Panics after [`PATIENCE`].
    async fn until_changed(&mut self, type_name: &str) {
        let account = self.account.clone();
        let stream = &mut self.stream;
        let mut seen: Vec<String> = Vec::new();
        let waited = tokio::time::timeout(*PATIENCE, async {
            loop {
                let frame = stream
                    .next()
                    .await
                    .expect("the stream stays open")
                    .expect("a well-formed frame");
                seen.push(describe(&frame.event));
                if let SseEvent::StateChange(change) = frame.event
                    && change
                        .changed
                        .get(&account)
                        .is_some_and(|types| types.contains_key(type_name))
                {
                    return;
                }
            }
        })
        .await;
        // As the reconnecting-stream wait does: say which failure this
        // is rather than only that it timed out (bead mimid-gn1w).
        assert!(
            waited.is_ok(),
            "no StateChange naming {type_name} in {PATIENCE:?}; {}",
            seen_report(&seen)
        );
    }

    /// Whether the stream ends within [`PATIENCE`].
    async fn ends(mut self) -> bool {
        tokio::time::timeout(*PATIENCE, async {
            while let Some(Ok(_)) = self.stream.next().await {}
        })
        .await
        .is_ok()
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stock_rust_client_chats_through_two_daemons() {
    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path(), &[ALICE, BOB]).await;
    let alice = Running::start(&config(&server, ALICE, dir.path(), "from-allowed")).await;
    let bob = Running::start(&config(&server, BOB, dir.path(), "any")).await;

    let a = Stock::connect(&alice).await;
    let b = Stock::connect(&bob).await;

    // The Session as the client parses it: one Chat account each.
    assert!(a.session.username == ALICE);
    assert!(b.session.username == BOB);
    assert_ne!(a.account(), b.account());
    assert!(a.session.api_url.as_str().starts_with(&alice.base()));
    let capability = a
        .session
        .chat_capability(a.account().as_ref())
        .expect("the chat account capability parses")
        .expect("a chat account capability");
    assert_eq!(
        capability.max_body_bytes,
        mimid_agent_core::MAX_TEXT_LEN as u64
    );

    // An empty account to start with.
    let none = a.chat.chat_get(None, None).await.expect("Chat/get");
    assert!(none.list.is_empty(), "{:?}", none.list);

    let mut b_events = b.events().await;

    // alice: a ChatContact for bob, then a group Chat with him.
    let created = a
        .chat
        .chat_contact_create(BOB, None)
        .await
        .expect("ChatContact/set");
    assert!(created.not_created.is_empty(), "{:?}", created.not_created);
    let bob_contact = created
        .created
        .into_values()
        .next()
        .and_then(|c| c.id)
        .expect("bob's ChatContact id");
    let created = a
        .chat
        .chat_create(
            &ChatCreateInput::Group {
                client_id: Some("c"),
                name: "planning",
                member_ids: std::slice::from_ref(&bob_contact),
                description: None,
                avatar_blob_id: None,
                message_expiry_seconds: None,
            },
            None,
        )
        .await
        .expect("Chat/set");
    assert!(created.not_created.is_empty(), "{:?}", created.not_created);
    let chat_a = created.created["c"].id.clone().expect("a server-set id");

    let chats = a
        .chat
        .chat_get(Some(std::slice::from_ref(&chat_a)), None)
        .await
        .expect("Chat/get")
        .list;
    assert_eq!(chats.len(), 1);
    assert_eq!(chats[0].kind, ChatKind::Group);
    assert_eq!(chats[0].name.as_deref(), Some("planning"));
    let room = chats[0].extra["roomId"]
        .as_str()
        .expect("a roomId")
        .to_owned();
    assert!(room.starts_with("mimi://a.example/r/"), "{room}");

    // bob's daemon joins at its next sync; his client hears of it.
    b_events.until_changed("Chat").await;
    let chats = b.chat.chat_get(None, None).await.expect("Chat/get").list;
    assert_eq!(chats.len(), 1, "{chats:?}");
    let chat_b = chats[0].id.clone();
    assert_eq!(chats[0].extra["roomId"].as_str(), Some(room.as_str()));
    assert_eq!(chats[0].name.as_deref(), Some("planning"));

    // alice posts; bob reads it with her as sender.
    let mut a_events = a.events().await;
    let sent = a.post(&chat_a, "hello bob").await;
    let mine = a.messages(&chat_a).await;
    assert_eq!(mine.len(), 1, "{mine:?}");
    assert_eq!(mine[0].id, sent);
    // draft-atwood-jmap-chat-00 §Message: an owner-composed Message's
    // senderId is the accountId.
    assert_eq!(mine[0].sender_id, a.account());

    b_events.until_changed("Message").await;
    let got = b.messages(&chat_b).await;
    assert_eq!(got.len(), 1, "{got:?}");
    assert_eq!(got[0].body, "hello bob");
    assert_eq!(got[0].chat_id, chat_b);
    assert_eq!(b.identity_of(&got[0].sender_id).await, ALICE);

    // bob answers; alice's client reads it after a StateChange.
    b.post(&chat_b, "hi alice").await;
    let got = tokio::time::timeout(*PATIENCE, async {
        loop {
            a_events.until_changed("Message").await;
            let got = a.messages(&chat_a).await;
            if got.len() == 2 {
                return got;
            }
        }
    })
    .await
    .expect("bob's answer reaches alice");
    let reply = got
        .iter()
        .find(|m| m.body == "hi alice")
        .unwrap_or_else(|| panic!("{got:?}"));
    assert_eq!(reply.sender_id, bob_contact);
    assert_eq!(a.identity_of(&reply.sender_id).await, BOB);

    // The client's reconnecting stream also reads the daemon's push.
    let mut again = a.client.subscribe_events_reconnecting(
        &a.session
            .event_source_url
            .as_str()
            .replace("{types}", "*")
            .replace("{closeafter}", "no")
            .replace("{ping}", "0"),
        None,
        Default::default(),
    );
    b.post(&chat_b, "one more").await;
    let mut seen: Vec<String> = Vec::new();
    let waited = tokio::time::timeout(*PATIENCE, async {
        loop {
            let frame = again.next().await.expect("open").expect("a frame");
            seen.push(describe(&frame.event));
            if matches!(frame.event, SseEvent::StateChange(_)) {
                return frame;
            }
        }
    })
    .await;
    let frame = waited.unwrap_or_else(|_| {
        panic!(
            "no StateChange on the reconnecting stream in {PATIENCE:?}; {}",
            seen_report(&seen)
        )
    });
    drop(frame);
    drop(again);

    // Stopping a daemon ends its event sources.
    bob.stop().await;
    assert!(b_events.ends().await);
    alice.stop().await;
    assert!(a_events.ends().await);

    // With the daemon gone the client reports a transport error, not a
    // panic or a parse error.
    let err = tokio::time::timeout(Duration::from_secs(10), a.chat.chat_get(None, None))
        .await
        .expect("the client gives up")
        .expect_err("no daemon");
    assert!(matches!(err, ClientError::Http(_)), "{err:?}");
}
