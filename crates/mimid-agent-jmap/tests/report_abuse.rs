//! Abuse reports end to end (bead mimid-oon0): alice@a.example hosts two
//! franked rooms on her provider, which is their hub; bob@b.example joins
//! both through his own provider and reports alice's messages from his
//! JMAP Chat account (`Message/reportAbuse`, decision mimid-1wgh.59). bob's
//! agent assembles the protocol-07 §5.9 AbuseReport and sends it to his
//! server (`Room/reportAbuse`, decision mimid-1wgh.58), which relays it to
//! a.example's `/reportAbuse` with provider-to-provider HTTP.
//!
//! Room "allowed" has mimid-agent-core's default roles, whose member role
//! holds room-policy-04 §8.3 `canReportAbuse` (bead mimid-14bu); room
//! "denied" has roles without it (decision mimid-1wgh.57).
//!
//! Oracles:
//!
//! - The hub's own frank verification: a.example answers the relayed POST
//!   with 200 only after recomputing `server_frank` with its secret
//!   `hub_key` and checking its signature (protocol-07 §5.9), and logs
//!   `abuse report accepted` with `verified=1` and bob as reporter.
//! - Independently of mimid's code, the report a.example received carries
//!   exactly the bytes alice's agent encrypted (her message's MIMI content
//!   decodes to her text, sender and room), and its frank's
//!   `franking_integrity_signature` verifies under the hub's public key
//!   for the context alice's content asserts.
//! - Unfranked messages (decision mimid-1wgh.60): alice's message reported
//!   once franked and once as unfranked reaches a.example in `messages`
//!   and in component 0xF020, and a.example logs `verified=1
//!   unverified=1`; a tampered frank beside an unfranked message is still
//!   refused 422. `unfranked_reports_reach_the_hub_unverified` covers a
//!   room without franking.
//! - Room policy: the report in "denied" is refused 403
//!   `report-not-allowed` by a.example, and bob sees `notAllowed`.
//! - Tampering: the accepted report's message with one bit of
//!   `server_frank` flipped, or one octet of its content changed, is
//!   refused 422 by a.example (`unverifiedMessage`).
//! - No frank: bob's own Message and an id that names no Message are
//!   refused by bob's agent before anything reaches a.example, as are
//!   reports past each limit or naming another room.
//! - Restart: after bob's agent and JMAP account are reopened from their
//!   files, the same Message is reported and accepted again.
//! - Identity: bob's server refuses a Room/reportAbuse whose
//!   `reportingUser` is not bob (the relay's identity check, decision
//!   mimid-1wgh.7.13) without contacting a.example.

#![forbid(unsafe_code)]

mod common;

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock};

use axum::extract::Request;
use axum::middleware::{self, Next};
use axum::response::Response;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jmap_server::{Dispatcher, Id, JmapRequest, State};
use mimi_content::MimiContent;
use mimi_mls::tls_codec::{Deserialize, Serialize};
use mimi_protocol::{
    AbuseReport, IdentifierUri, ServerFrankingContext, UnverifiedAbusiveMessage,
    UnverifiedAbusiveMessages,
};
use mimi_room_policy::{Capability, Role, RoleData, SingleSourceRoleChangeTargets};
use mimid_agent_core::{
    AbuseType, AbusiveMessage, Agent, AgentConfig, AgentError, HostOptions, MAX_NOTE_LEN,
    MAX_REPORTED_MESSAGES, MessageId, ReportOutcome, ReportedMessage,
};
use mimid_agent_jmap::{AgentChat, Options};
use mimid_server::config::{BaseUrl, Domain};
use mimid_server::directory::directory;
use mimid_server::follower::Follower;
use mimid_server::follower::key_packages::KeyPackages;
use mimid_server::follower::relay::Relay;
use mimid_server::http::router;
use mimid_server::hub::fanout::Fanout;
use mimid_server::hub::{Clock, Hub, HubRequirements, SystemClock};
use mimid_server::jmap::{self, JmapOptions};
use mimid_server::peer::PeerClient;
use mimid_server::store::Store;
use serde_json::{Value, json};

const ALICE: &str = "mimi://a.example/u/alice";
const BOB: &str = "mimi://b.example/u/bob";
const SENT_AT: &str = "2026-11-18T12:00:00Z";
const NOTE: &str = "report-note-canary-5b1e";

/// Every `/reportAbuse` request a.example received, as (body, status).
type Seen = Arc<Mutex<Vec<(Vec<u8>, u16)>>>;

/// Records each `/v1/reportAbuse/...` request and the status answered.
async fn record_reports(
    axum::extract::State(seen): axum::extract::State<Seen>,
    request: Request,
    next: Next,
) -> Response {
    if !request.uri().path().starts_with("/v1/reportAbuse/") {
        return next.run(request).await;
    }
    let (parts, body) = request.into_parts();
    let bytes = axum::body::to_bytes(body, usize::MAX).await.unwrap();
    let response = next
        .run(Request::from_parts(
            parts,
            axum::body::Body::from(bytes.clone()),
        ))
        .await;
    seen.lock()
        .unwrap()
        .push((bytes.to_vec(), response.status().as_u16()));
    response
}

/// A provider bound on loopback, before its stack runs.
struct Bound {
    domain: Domain,
    base: BaseUrl,
    text: String,
    listener: tokio::net::TcpListener,
}

async fn bind(domain: &str) -> Bound {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    Bound {
        domain: Domain::try_from(domain.to_owned()).unwrap(),
        base: BaseUrl::try_from(base.clone()).unwrap(),
        text: base,
        listener,
    }
}

/// A running provider: its base URL, its hub, a token per user and what
/// its `/reportAbuse` saw.
struct Server {
    base: String,
    hub: Arc<Hub>,
    tokens: BTreeMap<&'static str, String>,
    seen: Seen,
    /// What a wait is woken by.
    changes: common::Changes,
}

/// Starts `bound`'s stack as `main.rs` wires it, with `peers` as its peer
/// map, accounts for `users` and its hub's `requirements`.
async fn serve(
    bound: Bound,
    peers: &BTreeMap<Domain, BaseUrl>,
    dir: &Path,
    users: &[&'static str],
    requirements: HubRequirements,
) -> Server {
    let Bound {
        domain,
        base,
        text,
        listener,
    } = bound;
    let store = Store::open(&dir.join(format!("{domain}.sqlite")), &domain)
        .await
        .unwrap();
    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    let peer_client = || PeerClient::new(&domain, peers.clone()).unwrap();
    let key_packages = Arc::new(KeyPackages::new(
        store.clone(),
        domain.clone(),
        Arc::clone(&clock),
    ));
    let follower = Arc::new(
        Follower::new(domain.clone(), store.clone(), Arc::clone(&clock))
            .with_peers(peer_client())
            .with_key_packages(Arc::clone(&key_packages)),
    );
    let fanout = Fanout::new(
        store.clone(),
        domain.clone(),
        peer_client(),
        Arc::clone(&follower),
        Arc::clone(&clock),
    )
    .spawn();
    let hub = Arc::new(
        Hub::open(store.clone(), domain.clone(), Arc::clone(&clock))
            .await
            .unwrap()
            .with_requirements(requirements)
            .with_fanout(fanout)
            .with_peers(peer_client())
            .with_base_url(base.clone())
            .with_local_key_material(Arc::clone(&key_packages) as _),
    );
    follower
        .set_relay(Relay::new(Arc::clone(&hub), peer_client()))
        .unwrap();
    let mut tokens = BTreeMap::new();
    for user in users {
        let account = store.create_account(&domain, user, 1).await.unwrap();
        let token = store.issue_token(&account, 2).await.unwrap();
        tokens.insert(*user, token.expose_secret());
    }
    let jmap = jmap::router(
        &base,
        store,
        Arc::clone(&hub),
        Arc::clone(&follower),
        JmapOptions::default(),
    )
    .unwrap();
    let seen = Seen::default();
    let changes = common::Changes::of(&follower);
    let app = router(directory(&base), Arc::clone(&hub), follower)
        .merge(jmap)
        .layer(middleware::from_fn_with_state(
            Arc::clone(&seen),
            record_reports,
        ));
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    Server {
        base: text,
        hub,
        tokens,
        seen,
        changes,
    }
}

async fn agent(server: &Server, user: &'static str, dir: &Path) -> Agent {
    Agent::open(AgentConfig {
        server_url: server.base.clone(),
        binding: mimid_agent_core::Binding::Jmap,
        token: server.tokens[user].clone(),
        user_uri: user.to_owned(),
        state_dir: dir.join(user.rsplit('/').next().unwrap()),
        full_tree_hubs: Vec::new(),
        did_webvh: Default::default(),
    })
    .await
    .unwrap()
}

/// bob's JMAP Chat account over his agent, kept in his agent's database.
struct Client {
    chat: Arc<AgentChat>,
    dispatcher: Dispatcher<Id>,
    /// The server's change signal, which wakes the waits below.
    changes: common::Changes,
}

impl Client {
    async fn open(server: &Server, dir: &Path) -> Self {
        let chat = AgentChat::new(
            agent(server, BOB, dir).await,
            Id::from("bob"),
            Options::default(),
        )
        .persisted()
        .unwrap();
        let chat = Arc::new(chat);
        let mut dispatcher = Dispatcher::new();
        AgentChat::register(&chat, &mut dispatcher);
        Self {
            chat,
            dispatcher,
            changes: server.changes.clone(),
        }
    }

    /// One method call: the response's name and arguments.
    async fn call(&self, method: &str, mut args: Value) -> (String, Value) {
        args["accountId"] = json!("bob");
        let request: JmapRequest = serde_json::from_value(json!({
            "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:chat"],
            "methodCalls": [[method, args, "c0"]],
        }))
        .unwrap();
        let response = self
            .dispatcher
            .dispatch(request, self.chat.account_id().clone(), State::from("0"))
            .await;
        let response = serde_json::to_value(response).unwrap();
        let call = response["methodResponses"][0].as_array().unwrap();
        (call[0].as_str().unwrap().to_owned(), call[1].clone())
    }

    /// `Message/reportAbuse` of `ids`; its answer, which must not be a
    /// method error.
    async fn report(&self, ids: &[&str]) -> Value {
        let (name, answer) = self
            .call(
                "Message/reportAbuse",
                json!({"messageIds": ids, "reasonCode": 7, "note": NOTE}),
            )
            .await;
        assert_eq!(name, "Message/reportAbuse", "{answer}");
        answer
    }

    /// `Message/reportAbuse` of `ids`, which must be a method error of
    /// `kind`.
    async fn refused(&self, ids: &[&str], kind: &str) {
        let (name, answer) = self
            .call("Message/reportAbuse", json!({"messageIds": ids}))
            .await;
        assert_eq!(name, "error", "{answer}");
        assert_eq!(answer["type"], json!(kind), "{answer}");
    }

    /// The Chat of `room`, after syncing until it exists.
    ///
    /// Woken between syncs by the server or by what the last sync
    /// wrote.
    async fn chat_of(&self, room: &str) -> String {
        let mut watch = self.changes.watch(self.chat.store());
        let what = format!("bob to join {room}");
        loop {
            let report = self.chat.sync().await.unwrap();
            assert!(report.problems.is_empty(), "{report:?}");
            if let Some(chat) = self.chat.chat_of_room(room) {
                return chat.as_ref().to_owned();
            }
            watch.again(&what).await;
        }
    }

    /// The id of the Message in `chat` whose body is `body`, after syncing
    /// until it arrives.
    async fn message(&self, chat: &str, body: &str) -> String {
        let mut watch = self.changes.watch(self.chat.store());
        let what = format!("the message {body:?}");
        loop {
            let report = self.chat.sync().await.unwrap();
            assert!(report.problems.is_empty(), "{report:?}");
            let (_, query) = self
                .call("Message/query", json!({"filter": {"chatId": chat}}))
                .await;
            let (_, got) = self.call("Message/get", json!({"ids": query["ids"]})).await;
            if let Some(found) = got["list"]
                .as_array()
                .unwrap()
                .iter()
                .find(|m| m["body"] == json!(body))
            {
                return found["id"].as_str().unwrap().to_owned();
            }
            watch.again(&what).await;
        }
    }
}

/// The roles of room "denied": 1 "banned", 2 "member" and 3 "admin" (the
/// creator's role) as in mimid-agent-core's defaults, none of them with
/// `canReportAbuse`.
fn roles_without_reporting() -> RoleData {
    let capabilities = vec![
        Capability::CAN_ADD_PARTICIPANT,
        Capability::CAN_REMOVE_SELF,
        Capability::CAN_REMOVE_OWN_CLIENT,
        Capability::CAN_SEND_MESSAGE,
        Capability::CAN_RECEIVE_MESSAGE,
    ];
    let role = |role_index: u32, name: &str, role_capabilities, authorized_role_changes| Role {
        role_index,
        role_name: name.to_owned(),
        role_description: String::new(),
        role_capabilities,
        minimum_participants_constraint: 0,
        maximum_participants_constraint: None,
        minimum_active_participants_constraint: 0,
        maximum_active_participants_constraint: None,
        authorized_role_changes,
    };
    let changes = || {
        vec![
            SingleSourceRoleChangeTargets {
                from_role_index: 0,
                target_role_indexes: vec![2],
            },
            SingleSourceRoleChangeTargets {
                from_role_index: 2,
                target_role_indexes: vec![0],
            },
        ]
    };
    RoleData {
        roles: vec![
            role(1, "banned", vec![], vec![]),
            role(2, "member", capabilities.clone(), changes()),
            role(3, "admin", capabilities, changes()),
        ],
    }
}

/// Every `tracing` event of this test binary, as text.
fn logs() -> &'static Arc<Mutex<Vec<u8>>> {
    static LOGS: OnceLock<Arc<Mutex<Vec<u8>>>> = OnceLock::new();
    LOGS.get_or_init(|| {
        let logs = Arc::<Mutex<Vec<u8>>>::default();
        let sink = Arc::clone(&logs);
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .with_ansi(false)
            .with_writer(move || Sink(Arc::clone(&sink)))
            .finish();
        tracing::subscriber::set_global_default(subscriber).unwrap();
        logs
    })
}

struct Sink(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Sink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn log_text() -> String {
    String::from_utf8_lossy(&logs().lock().unwrap()).into_owned()
}

/// The last report a.example received, decoded, and its status.
fn last_seen(server: &Server) -> (AbuseReport, u16) {
    let seen = server.seen.lock().unwrap();
    let (body, status) = seen.last().expect("a.example received a report");
    (
        AbuseReport::tls_deserialize_exact(&body[..]).unwrap(),
        *status,
    )
}

fn uri(text: &str) -> IdentifierUri {
    IdentifierUri::new(text).unwrap()
}

/// The last `abuse report accepted` line logged for `room`.
fn last_accepted(room: &str) -> String {
    let field = format!("room_id=\"{room}\"");
    log_text()
        .lines()
        .rev()
        .find(|line| line.contains("abuse report accepted") && line.contains(&field))
        .unwrap_or_else(|| panic!("no accepted report logged for {room}"))
        .to_owned()
}

/// Asserts that `line` has each of `fields` as a whole `name=value` field.
fn assert_fields(line: &str, fields: &[&str]) {
    let have: Vec<&str> = line.split_whitespace().collect();
    for field in fields {
        assert!(have.contains(field), "{field}: {line}");
    }
}

#[tokio::test]
async fn reports_reach_the_hub_through_the_reporters_provider() {
    logs();
    let dir = tempfile::tempdir().unwrap();
    let (a, b) = (bind("a.example").await, bind("b.example").await);
    let peers_of_a = BTreeMap::from([(b.domain.clone(), b.base.clone())]);
    let peers_of_b = BTreeMap::from([(a.domain.clone(), a.base.clone())]);
    let a = serve(
        a,
        &peers_of_a,
        dir.path(),
        &[ALICE],
        HubRequirements::default(),
    )
    .await;
    let b = serve(
        b,
        &peers_of_b,
        dir.path(),
        &[BOB],
        HubRequirements::default(),
    )
    .await;

    // Both publish KeyPackages (a provider knows a user with a client,
    // decision mimid-1wgh.7.36); alice asks bob's consent across providers
    // (protocol-07 §5.7), and bob grants it.
    let mut alice = agent(&a, ALICE, dir.path()).await;
    alice.publish_key_packages(1).await.unwrap();
    let bob = Client::open(&b, dir.path()).await;
    bob.chat
        .agent()
        .lock()
        .await
        .publish_key_packages(4)
        .await
        .unwrap();
    alice.request_consent(BOB).await.unwrap();
    bob.chat.agent().lock().await.allow(ALICE).await.unwrap();

    // alice hosts the two rooms on a.example and invites bob into both.
    // "allowed" has the default roles, whose member role holds
    // canReportAbuse (bead mimid-14bu); "denied" has roles without it.
    let allowed = alice
        .host_room(&HostOptions::named("allowed"))
        .await
        .unwrap();
    let mut denied = HostOptions::named("denied");
    denied.roles = Some(roles_without_reporting());
    let denied = alice.host_room(&denied).await.unwrap();
    for room in [&allowed, &denied] {
        assert!(room.starts_with("mimi://a.example/r/"), "{room}");
        alice.invite(room, BOB).await.unwrap();
    }
    let chat_allowed = bob.chat_of(&allowed).await;
    let chat_denied = bob.chat_of(&denied).await;

    let text = "the abusive message";
    let sent = alice.send_text(&allowed, text).await.unwrap();
    alice.send_text(&denied, "another one").await.unwrap();
    let reported = bob.message(&chat_allowed, text).await;
    let in_denied = bob.message(&chat_denied, "another one").await;

    // 1. bob reports alice's message: a.example verifies its frank and
    // records the report.
    let answer = bob.report(&[&reported]).await;
    assert_eq!(answer["responseCode"], json!("accepted"), "{answer}");
    let (report, status) = last_seen(&a);
    assert_eq!(status, 200);
    assert_eq!(report.reporting_user, uri(BOB));
    assert_eq!(report.alleged_abuser_uri, uri(ALICE));
    assert_eq!(report.reason_code, AbuseType(7));
    assert_eq!(report.note, NOTE.as_bytes());
    let [message] = &report.messages[..] else {
        panic!("one reported message: {report:?}");
    };
    // What alice encrypted, checked without mimid's report code: her text,
    // her URI and the room in the content, the hub's acceptance time, and
    // a signature by the room's franking_agent key, which is the hub's.
    let content = MimiContent::decode(&message.message_content).unwrap();
    assert_eq!(content.mimi_extensions.sender_uri.as_deref(), Some(ALICE));
    assert_eq!(
        content.mimi_extensions.room_uri.as_deref(),
        Some(allowed.as_str())
    );
    assert!(
        String::from_utf8_lossy(&message.message_content).contains(text),
        "the content carries alice's text"
    );
    assert_eq!(message.accepted_timestamp, sent.accepted_at);
    // RFC 9420 §5.1.1: opaque SignaturePublicKey<V>, 32 octets.
    let hub_key = mimi_mls::wire::SignaturePublicKey::tls_deserialize_exact(
        &[&[0x20][..], &a.hub.signature_public_key()[..]].concat()[..],
    )
    .unwrap();
    message
        .frank
        .verify_integrity(
            &hub_key,
            &ServerFrankingContext {
                sender_uri: uri(ALICE),
                room_uri: uri(&allowed),
                accepted_timestamp: sent.accepted_at,
            },
        )
        .expect("the frank is the hub's signature over alice's context");
    let text_log = log_text();
    assert_fields(
        &last_accepted(&allowed),
        &[
            &format!("reporting_user=\"{BOB}\""),
            &format!("alleged_abuser=\"{ALICE}\""),
            &format!("room_id=\"{allowed}\""),
            "verified=1",
            "unverified=0",
        ],
    );
    assert!(!text_log.contains(NOTE), "the note is not logged");

    // 1b. The same message twice through bob's agent, once franked and
    // once as if unfranked (decision mimid-1wgh.60): a.example verifies the
    // first and records the second unverified.
    let unfranked = UnverifiedAbusiveMessage {
        message_content: message.message_content.clone(),
        accepted_timestamp: message.accepted_timestamp,
    };
    let outcome = bob
        .chat
        .agent()
        .lock()
        .await
        .report_abuse(
            &allowed,
            &[
                ReportedMessage::Franked(message.clone()),
                ReportedMessage::Unfranked(unfranked.clone()),
            ],
            AbuseType::RESERVED,
            "",
        )
        .await
        .unwrap();
    assert_eq!(outcome, ReportOutcome::Accepted);
    let (mixed, status) = last_seen(&a);
    assert_eq!(status, 200);
    assert_eq!(mixed.messages, std::slice::from_ref(message));
    assert_eq!(
        mixed.unverified_messages().unwrap(),
        Some(UnverifiedAbusiveMessages {
            messages: vec![unfranked.clone()]
        })
    );
    assert_fields(&last_accepted(&allowed), &["verified=1", "unverified=1"]);

    // 2. In "denied" bob's role lacks canReportAbuse: a.example refuses.
    let answer = bob.report(&[&in_denied]).await;
    assert_eq!(answer["responseCode"], json!("notAllowed"), "{answer}");
    let (_, status) = last_seen(&a);
    assert_eq!(status, 403);

    // 3. A tampered frank, and tampered content, sent through bob's agent:
    // a.example's verification refuses both.
    let flip_frank = |m: &mut AbusiveMessage| m.frank.server_frank[0] ^= 0x01;
    let change_content = |m: &mut AbusiveMessage| {
        let at = m
            .message_content
            .windows(text.len())
            .position(|w| w == text.as_bytes())
            .unwrap();
        m.message_content[at] = b'T';
    };
    for tamper in [&flip_frank as &dyn Fn(&mut AbusiveMessage), &change_content] {
        let mut tampered = message.clone();
        tamper(&mut tampered);
        // Alone, and beside an unfranked message: the report is refused
        // whole either way.
        for messages in [
            vec![ReportedMessage::Franked(tampered.clone())],
            vec![
                ReportedMessage::Franked(tampered.clone()),
                ReportedMessage::Unfranked(unfranked.clone()),
            ],
        ] {
            let outcome = bob
                .chat
                .agent()
                .lock()
                .await
                .report_abuse(&allowed, &messages, AbuseType::RESERVED, "")
                .await
                .unwrap();
            assert_eq!(outcome, ReportOutcome::UnverifiedMessage);
            let (_, status) = last_seen(&a);
            assert_eq!(status, 422);
        }
    }

    // 4. Messages bob never received: his own, and an id naming nothing.
    // Nothing reaches a.example.
    let seen_before = a.seen.lock().unwrap().len();
    let (_, created) = bob
        .call(
            "Message/set",
            json!({"create": {"k": {"chatId": chat_allowed, "body": "mine", "sentAt": SENT_AT}}}),
        )
        .await;
    let own = created["created"]["k"]["id"].as_str().unwrap().to_owned();
    bob.refused(&[&own], "invalidArguments").await;
    bob.refused(&["no-such-message"], "invalidArguments").await;
    bob.refused(&[&reported, &own], "invalidArguments").await;
    bob.refused(&[], "invalidArguments").await;
    // Limits, at and past each: the note, the number of messages, the
    // reason code; and a message reported under another room.
    for args in [
        json!({"messageIds": [reported], "note": "n".repeat(MAX_NOTE_LEN + 1)}),
        json!({"messageIds": (0..=MAX_REPORTED_MESSAGES).map(|i| format!("m{i}")).collect::<Vec<_>>()}),
        json!({"messageIds": [reported], "reasonCode": 256}),
        json!({"messageIds": [reported], "reasonCode": -1}),
        json!({"messageIds": [reported, reported]}),
        json!({"messageIds": [reported], "note": 5}),
    ] {
        let (name, answer) = bob.call("Message/reportAbuse", args.clone()).await;
        assert_eq!(name, "error", "{args}: {answer}");
        assert_eq!(
            answer["type"],
            json!("invalidArguments"),
            "{args}: {answer}"
        );
    }
    {
        let agent = bob.chat.agent().lock().await;
        let franked = ReportedMessage::Franked(message.clone());
        let at_limit = vec![franked.clone(); MAX_REPORTED_MESSAGES + 1];
        let unfranked_at_limit =
            vec![ReportedMessage::Unfranked(unfranked.clone()); MAX_REPORTED_MESSAGES + 1];
        for (room, messages, note) in [
            (&denied, std::slice::from_ref(&franked), ""),
            (&allowed, &at_limit[..], ""),
            (&allowed, &unfranked_at_limit[..], ""),
            (&allowed, &[][..], ""),
            (
                &allowed,
                std::slice::from_ref(&franked),
                &*"n".repeat(MAX_NOTE_LEN + 1),
            ),
        ] {
            let result = agent
                .report_abuse(room, messages, AbuseType::RESERVED, note)
                .await;
            assert!(matches!(result, Err(AgentError::Invalid(_))), "{result:?}");
        }
        let result = agent
            .report_abuse(
                "mimi://a.example/r/none",
                std::slice::from_ref(&franked),
                AbuseType::RESERVED,
                "",
            )
            .await;
        assert!(
            matches!(result, Err(AgentError::NoSuchRoom(_))),
            "{result:?}"
        );
    }
    assert_eq!(a.seen.lock().unwrap().len(), seen_before);

    // 5. Identity: bob's server relays only reports by bob.
    let mut forged = report.clone();
    forged.reporting_user = uri("mimi://b.example/u/mallory");
    let http = reqwest::Client::new();
    let api = format!("{}/jmap/api", b.base);
    let session = http
        .get(format!("{}/.well-known/jmap", b.base))
        .bearer_auth(&b.tokens[BOB])
        .send()
        .await
        .unwrap()
        .bytes()
        .await
        .unwrap();
    let session: Value = serde_json::from_slice(&session).unwrap();
    let account = session["primaryAccounts"]["urn:ietf:params:jmap:chat:mimi"].clone();
    let body = json!({
        "using": [
            "urn:ietf:params:jmap:core",
            "urn:ietf:params:jmap:chat",
            "urn:ietf:params:jmap:chat:mimi",
        ],
        "methodCalls": [["Room/reportAbuse", {
            "accountId": account,
            "roomId": allowed,
            "report": URL_SAFE_NO_PAD.encode(forged.tls_serialize_detached().unwrap()),
        }, "c0"]],
    });
    let answer = http
        .post(&api)
        .bearer_auth(&b.tokens[BOB])
        .header("content-type", "application/json")
        .body(body.to_string())
        .send()
        .await
        .unwrap()
        .bytes()
        .await
        .unwrap();
    let answer: Value = serde_json::from_slice(&answer).unwrap();
    let call = &answer["methodResponses"][0];
    assert_eq!(call[0], json!("error"), "{answer}");
    assert_eq!(call[1]["type"], json!("invalidArguments"), "{answer}");
    assert_eq!(a.seen.lock().unwrap().len(), seen_before);

    // 6. After a restart of bob's agent and account, the kept frank still
    // reports.
    drop(bob);
    let bob = Client::open(&b, dir.path()).await;
    let answer = bob.report(&[&reported]).await;
    assert_eq!(answer["responseCode"], json!("accepted"), "{answer}");
    let (again, status) = last_seen(&a);
    assert_eq!(status, 200);
    assert_eq!(again.messages, report.messages);
}

/// A room without franking (decision mimid-1wgh.52; a.example's operator
/// allows open rooms): bob reports alice's unfranked message from his
/// JMAP Chat account through b.example, and a.example records it as
/// unverified (decision mimid-1wgh.60).
///
/// Oracles: a.example's own log (`verified=0 unverified=1`); the relayed
/// report carries, in component 0xF020, bytes whose mimi-content-10 §3.3
/// MessageId is the one alice's agent computed when it sent them, so they
/// are exactly what alice encrypted; and the acceptance time is the one
/// a.example gave alice.
#[tokio::test]
async fn unfranked_reports_reach_the_hub_unverified() {
    logs();
    let dir = tempfile::tempdir().unwrap();
    let (a, b) = (bind("a.example").await, bind("b.example").await);
    let peers_of_a = BTreeMap::from([(b.domain.clone(), b.base.clone())]);
    let peers_of_b = BTreeMap::from([(a.domain.clone(), a.base.clone())]);
    let a = serve(
        a,
        &peers_of_a,
        dir.path(),
        &[ALICE],
        HubRequirements::new(false, false),
    )
    .await;
    let b = serve(
        b,
        &peers_of_b,
        dir.path(),
        &[BOB],
        HubRequirements::default(),
    )
    .await;

    let mut alice = agent(&a, ALICE, dir.path()).await;
    alice.publish_key_packages(1).await.unwrap();
    let bob = Client::open(&b, dir.path()).await;
    bob.chat
        .agent()
        .lock()
        .await
        .publish_key_packages(2)
        .await
        .unwrap();
    alice.request_consent(BOB).await.unwrap();
    bob.chat.agent().lock().await.allow(ALICE).await.unwrap();

    let mut open = HostOptions::named("open");
    open.open = true;
    let room = alice.host_room(&open).await.unwrap();
    alice.invite(&room, BOB).await.unwrap();
    let chat = bob.chat_of(&room).await;
    let text = "an unfranked abusive message";
    let sent = alice.send_text(&room, text).await.unwrap();
    let reported = bob.message(&chat, text).await;

    let check = |bob_report: Value| {
        assert_eq!(
            bob_report["responseCode"],
            json!("accepted"),
            "{bob_report}"
        );
        let (report, status) = last_seen(&a);
        assert_eq!(status, 200);
        assert_eq!(report.reporting_user, uri(BOB));
        assert_eq!(report.alleged_abuser_uri, uri(ALICE));
        assert!(report.messages.is_empty(), "no franked message");
        let unverified = report
            .unverified_messages()
            .unwrap()
            .expect("component 0xF020");
        let [message] = &unverified.messages[..] else {
            panic!("one unverified message: {unverified:?}");
        };
        let content = MimiContent::decode(&message.message_content).unwrap();
        assert_eq!(
            MessageId::compute(ALICE, &room, &message.message_content, &content.salt).unwrap(),
            sent.message_id,
            "the bytes alice sent"
        );
        assert!(String::from_utf8_lossy(&message.message_content).contains(text));
        assert_eq!(message.accepted_timestamp, sent.accepted_at);
        assert_fields(
            &last_accepted(&room),
            &[
                &format!("reporting_user=\"{BOB}\""),
                "verified=0",
                "unverified=1",
            ],
        );
        message.clone()
    };
    let first = check(bob.report(&[&reported]).await);

    // After a restart the kept content still reports, unverified.
    drop(bob);
    let bob = Client::open(&b, dir.path()).await;
    assert_eq!(check(bob.report(&[&reported]).await), first);
}
