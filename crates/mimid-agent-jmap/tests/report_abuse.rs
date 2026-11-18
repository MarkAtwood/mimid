//! Abuse reports end to end (bead mimid-oon0): alice@a.example hosts two
//! franked rooms on her provider, which is their hub; bob@b.example joins
//! both through his own provider and reports alice's messages from his
//! JMAP Chat account (`Message/reportAbuse`, decision mimid-1wgh.58). bob's
//! agent assembles the protocol-07 §5.9 AbuseReport and sends it to his
//! server (`Room/reportAbuse`, decision mimid-1wgh.57), which relays it to
//! a.example's `/reportAbuse` with provider-to-provider HTTP.
//!
//! Room "allowed" gives the member role room-policy-04 §8.3
//! `canReportAbuse`; room "denied" does not (decision mimid-1wgh.56).
//!
//! Oracles:
//!
//! - The hub's own frank verification: a.example answers the relayed POST
//!   with 200 only after recomputing `server_frank` with its secret
//!   `hub_key` and checking its signature (protocol-07 §5.9), and logs
//!   `abuse report accepted` with `verified=true` and bob as reporter.
//! - Independently of mimid's code, the report a.example received carries
//!   exactly the bytes alice's agent encrypted (her message's MIMI content
//!   decodes to her text, sender and room), and its frank's
//!   `franking_integrity_signature` verifies under the hub's public key
//!   for the context alice's content asserts.
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

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use axum::extract::Request;
use axum::middleware::{self, Next};
use axum::response::Response;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jmap_server::{Dispatcher, Id, JmapRequest, State};
use mimi_content::MimiContent;
use mimi_mls::tls_codec::{Deserialize, Serialize};
use mimi_protocol::{AbuseReport, IdentifierUri, ServerFrankingContext};
use mimi_room_policy::{Capability, Role, RoleData, SingleSourceRoleChangeTargets};
use mimid_agent_core::{
    AbuseType, AbusiveMessage, Agent, AgentConfig, AgentError, HostOptions, MAX_NOTE_LEN,
    MAX_REPORTED_MESSAGES, ReportOutcome,
};
use mimid_agent_jmap::{AgentChat, Options};
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
}

/// Starts `bound`'s stack as `main.rs` wires it, with `peers` as its peer
/// map and accounts for `users`.
async fn serve(
    bound: Bound,
    peers: &BTreeMap<Domain, BaseUrl>,
    dir: &Path,
    users: &[&'static str],
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
    }
}

async fn agent(server: &Server, user: &'static str, dir: &Path) -> Agent {
    Agent::open(AgentConfig {
        server_url: server.base.clone(),
        token: server.tokens[user].clone(),
        user_uri: user.to_owned(),
        state_dir: dir.join(user.rsplit('/').next().unwrap()),
        full_tree_hubs: Vec::new(),
        did_webvh: Default::default(),
    })
    .await
    .unwrap()
}

/// bob's JMAP Chat account over his agent, kept in `<dir>/bob-chat.json`.
struct Client {
    chat: Arc<AgentChat>,
    dispatcher: Dispatcher<()>,
}

impl Client {
    async fn open(server: &Server, dir: &Path) -> Self {
        let chat = AgentChat::new(
            agent(server, BOB, dir).await,
            Id::from("bob"),
            Options::default(),
        )
        .persisted_at(dir.join("bob-chat.json"))
        .unwrap();
        let chat = Arc::new(chat);
        let mut dispatcher = Dispatcher::new();
        AgentChat::register(&chat, &mut dispatcher);
        Self { chat, dispatcher }
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
            .dispatch(request, (), State::from("0"))
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
    async fn chat_of(&self, room: &str) -> String {
        for _ in 0..200 {
            let report = self.chat.sync().await.unwrap();
            assert!(report.problems.is_empty(), "{report:?}");
            if let Some(chat) = self.chat.chat_of_room(room) {
                return chat.as_ref().to_owned();
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("bob never joined {room}");
    }

    /// The id of the Message in `chat` whose body is `body`, after syncing
    /// until it arrives.
    async fn message(&self, chat: &str, body: &str) -> String {
        for _ in 0..200 {
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
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("{body:?} never arrived");
    }
}

/// The roles of a room alice hosts: 1 "banned" and 2 "member" as in
/// mimid-agent-core's defaults, with `canReportAbuse` when `may_report`.
fn roles(may_report: bool) -> RoleData {
    let mut capabilities = vec![
        Capability::CAN_ADD_PARTICIPANT,
        Capability::CAN_REMOVE_SELF,
        Capability::CAN_REMOVE_OWN_CLIENT,
        Capability::CAN_SEND_MESSAGE,
        Capability::CAN_RECEIVE_MESSAGE,
    ];
    if may_report {
        capabilities.push(Capability::CAN_REPORT_ABUSE);
    }
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
    RoleData {
        roles: vec![
            role(1, "banned", vec![], vec![]),
            role(
                2,
                "member",
                capabilities,
                vec![
                    SingleSourceRoleChangeTargets {
                        from_role_index: 0,
                        target_role_indexes: vec![2],
                    },
                    SingleSourceRoleChangeTargets {
                        from_role_index: 2,
                        target_role_indexes: vec![0],
                    },
                ],
            ),
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

#[tokio::test]
async fn reports_reach_the_hub_through_the_reporters_provider() {
    logs();
    let dir = tempfile::tempdir().unwrap();
    let (a, b) = (bind("a.example").await, bind("b.example").await);
    let peers_of_a = BTreeMap::from([(b.domain.clone(), b.base.clone())]);
    let peers_of_b = BTreeMap::from([(a.domain.clone(), a.base.clone())]);
    let a = serve(a, &peers_of_a, dir.path(), &[ALICE]).await;
    let b = serve(b, &peers_of_b, dir.path(), &[BOB]).await;

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
    let host = |name: &str, may_report: bool| {
        let mut options = HostOptions::named(name);
        options.roles = Some(roles(may_report));
        options
    };
    let allowed = alice.host_room(&host("allowed", true)).await.unwrap();
    let denied = alice.host_room(&host("denied", false)).await.unwrap();
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
    let accepted_line = text_log
        .lines()
        .find(|line| line.contains("abuse report accepted"))
        .expect("the hub records the report");
    for field in [
        format!("reporting_user=\"{BOB}\""),
        format!("alleged_abuser=\"{ALICE}\""),
        format!("room_id=\"{allowed}\""),
        "verified=true".to_owned(),
        "messages=1".to_owned(),
    ] {
        assert!(accepted_line.contains(&field), "{field}: {accepted_line}");
    }
    assert!(!text_log.contains(NOTE), "the note is not logged");

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
        let outcome = bob
            .chat
            .agent()
            .lock()
            .await
            .report_abuse(&allowed, &[tampered], AbuseType::RESERVED, "")
            .await
            .unwrap();
        assert_eq!(outcome, ReportOutcome::UnverifiedMessage);
        let (_, status) = last_seen(&a);
        assert_eq!(status, 422);
    }

    // 4. Messages bob never received with a frank: his own, and an id
    // naming nothing. Nothing reaches a.example.
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
        let at_limit = vec![message.clone(); MAX_REPORTED_MESSAGES + 1];
        for (room, messages, note) in [
            (&denied, std::slice::from_ref(message), ""),
            (&allowed, &at_limit[..], ""),
            (&allowed, &[][..], ""),
            (
                &allowed,
                std::slice::from_ref(message),
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
                std::slice::from_ref(message),
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
