//! Mutually authenticated TLS between real `mimid` binaries on loopback
//! (bead mimid-6x2f), each configured from TOML as an operator would
//! configure it, in enforce mode, with no other mechanism on: request
//! signatures are sent but no key is trusted, and DNS keys and DANE are off
//! unless a test turns DANE on.
//!
//! - **PKIX, both directions, mimid terminating TLS.** a.example and
//!   b.example each serve HTTPS (`[tls]`), present a client certificate
//!   (`[peer_tls.identity]`, with the other named in
//!   `[peer_tls.peers]`) and trust the test CA for the other's
//!   (a.example per peer, b.example for every peer). A JMAP-driven room
//!   exercises b → a `updateConsent`, `submitMessage`, `groupInfo` and
//!   `update`, and a → b `keyMaterial` and `notify`. Each side logs every
//!   request as authenticated by `pkix` with the other's certificate.
//! - **PKIX refusals.** a.example refuses `requestConsent` from b.example
//!   without a certificate, with a.example's certificate (wrong domain),
//!   with a b.example certificate from an unknown CA, and with an expired
//!   one; then accepts it with the right one.
//! - **A trusted proxy.** a.example serves plain HTTP behind a
//!   TLS-terminating proxy (this test's, standing in for Caddy) that
//!   forwards the client certificate in `X-Client-Cert` from 127.0.0.2,
//!   the configured `[trusted_proxy]` address. b.example's binary reaches
//!   it through the proxy. The header from any other address is ignored.
//! - **DANE, b → a only.** The binary's resolver is hickory's validating
//!   stub resolver, which validates from the IANA root trust anchor and
//!   asks port 53, so no local zone can be DNSSEC-secure for it without a
//!   code change. a.example is therefore the library's server, wired as
//!   `main.rs` wires it and served by [`tls::serve`], with a stub
//!   [`TlsaResolver`] that answers what each step says; b.example is the
//!   real binary presenting its certificate chain.
//!
//! Oracles: the statuses of protocol-07 §5 and draft-atwood-mimi-provider-auth-00
//! §11 (`403`); the stored consent rows and room epochs read back through
//! each server's local control listener; MLS agreement (each Member
//! decrypts exactly what the other sent; the KeyPackage a.example fetched
//! is the one bob published); and the certificate key ids and TLSA
//! association data computed with openssl outside mimid
//! (`fixtures/mtls/PROVENANCE`).

#![forbid(unsafe_code)]

#[allow(dead_code, reason = "each test binary uses part of the helpers")]
mod common;
#[allow(dead_code, reason = "each test binary uses part of the helpers")]
#[path = "common/group_info.rs"]
mod group_info;
#[allow(dead_code, reason = "each test binary uses part of the helpers")]
#[path = "common/key_packages.rs"]
mod key_packages;
#[allow(dead_code, reason = "each test binary uses part of the helpers")]
#[path = "common/update.rs"]
mod update;

use std::collections::{BTreeSet, VecDeque};
use std::io::BufRead;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::extract::{Extension, Request, State};
use axum::middleware::Next;
use axum::response::Response;
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use common::{
    ALICE, APP_COMPONENTS, BOB, FRANK_AAD_ONLY, HUB_IDENTITY, ROOM_APP_COMPONENTS, SAFE_AAD,
    base_room_policy, franking_agent, no_components,
};
use key_packages::{Ask, NO_REQUIREMENTS};
use mimi_mls::member::{AppDataUpdate, ComponentOp, ExternalSender, Incoming, Member};
use mimi_mls::tls_codec::Serialize;
use mimi_mls::wire::AppDataDictionary;
use mimi_mls::{ErrorSource, Identity, KeyPackageKind};
use mimi_protocol::component_id::{FRANK_AAD, FRANKING_AGENT, PARTICIPANT_LIST};
use mimi_protocol::{
    ConsentEntry, ConsentOperation, FanoutEvent, FanoutMessage, IdentifierUri, ParticipantListData,
    ParticipantListUpdate, UserRolePair, franking_tag,
};
use mimi_room_policy::component_id::{BASE_ROOM_POLICY, ROLES_LIST};
use mimi_room_policy::{Capability, Role, RoleData, SingleSourceRoleChangeTargets};
use mimid_server::config::{BaseUrl, Domain};
use mimid_server::directory::directory;
use mimid_server::follower::Follower;
use mimid_server::http::router;
use mimid_server::hub::{Clock, Hub, SystemClock};
use mimid_server::peer::PeerClient;
use mimid_server::provider_auth::{
    self, AuthenticatedProvider, BoxFuture, DnssecStatus, Mechanism, ProviderAuth,
    ProviderAuthConfig, TlsaRecord, TlsaResolver, TxtLookupError,
};
use mimid_server::store::{NewKeyPackage, Store};
use mimid_server::tls::{self, ClientCertificate, TlsConfig};
use serde_json::{Value, json};

const TLS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/tls");
const MTLS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/mtls");

/// `sha256:` and the SHA-256 of `tls/client.pem`'s DER, a.example's client
/// certificate (openssl; `fixtures/mtls/PROVENANCE`).
const A_KEY_ID: &str = "sha256:b25e4c0d7f17277edae982750eedb3a6c7a459b1a517b28adde03faf89888dad";
/// The same for `mtls/b-client.pem`, b.example's.
const B_KEY_ID: &str = "sha256:49fc05cb362c5a414a68e335d22d82ca5ab385fc6f52a45fb1908a02b5439c7b";
/// TLSA 3 1 1 data for `mtls/b-client.pem` (openssl).
const B_SPKI_SHA256: &str = "2d371a122bedf8c01e856e304588ed26f2606bbfb1fe775529415eee1a58f34a";
/// TLSA 3 1 1 data for `mtls/b-untrusted.pem` (openssl).
const UNTRUSTED_SPKI_SHA256: &str =
    "7f7b540ce0b61be168014237d6f5231fa27b7c2fe74665693fa92d3e02ec1f23";
/// TLSA 2 0 1 data for `tls/ca.pem` (openssl).
const CA_SHA256: &str = "bb95af8387a45662ae338174ef803406bbf75d29e7475143016ea3e3fbfba9c2";

/// The bound on the one wait in this file that has nothing to wait on
/// (`Jmap::next`, bead mimid-67e0.2). Generous: fanout retries use the
/// real backoff (1 s, then 2 s), and this test runs two binaries.
const WAIT: Duration = Duration::from_secs(60);

/// The log message of a successful provider authentication.
const AUTHENTICATED: &str = "provider authenticated";
/// The log message of an enforce-mode refusal.
const REFUSED: &str = "request refused: provider not authenticated";

const USING: [&str; 3] = [
    "urn:ietf:params:jmap:core",
    "urn:ietf:params:jmap:chat",
    "urn:ietf:params:jmap:chat:mimi",
];
/// Role 2: listed users may add participants and their own clients, and
/// send.
const ROLE_MEMBER: u32 = 2;

fn text(bytes: &[u8]) -> &str {
    std::str::from_utf8(bytes).unwrap()
}

fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn unb64(value: &Value) -> Vec<u8> {
    URL_SAFE_NO_PAD
        .decode(value.as_str().expect("a base64url string"))
        .unwrap()
}

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

/// Percent-encodes a user URI for a path segment.
fn encode(uri: &[u8]) -> String {
    text(uri).replace(':', "%3A").replace('/', "%2F")
}

fn domain(name: &str) -> Domain {
    Domain::try_from(name.to_owned()).unwrap()
}

fn read(path: &str) -> Vec<u8> {
    std::fs::read(path).unwrap()
}

/// The DER of the first certificate in a PEM file.
fn der(path: &str) -> Vec<u8> {
    let text = String::from_utf8(read(path)).unwrap();
    let body: String = text
        .lines()
        .skip_while(|l| !l.starts_with("-----BEGIN CERTIFICATE"))
        .skip(1)
        .take_while(|l| !l.starts_with("-----END"))
        .collect();
    STANDARD.decode(body).unwrap()
}

/// A free loopback port. Another process could take it before the server
/// binds it; that would fail the test, not pass it wrongly.
fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// An HTTP client trusting the test CA, presenting `identity` (a
/// certificate file and its key) if given.
fn client(identity: Option<(&str, &str)>) -> reqwest::Client {
    let ca = reqwest::Certificate::from_pem(&read(&format!("{TLS}/ca.pem"))).unwrap();
    let mut builder = reqwest::Client::builder().tls_certs_only([ca]);
    if let Some((cert, key)) = identity {
        let both = [read(cert), read(key)].concat();
        builder = builder.identity(reqwest::Identity::from_pem(&both).unwrap());
    }
    builder.build().unwrap()
}

/// GETs `url` over plain HTTP; the JSON body.
async fn get_json(url: &str) -> Value {
    let body = reqwest::Client::new()
        .get(url)
        .send()
        .await
        .unwrap()
        .bytes()
        .await
        .unwrap();
    serde_json::from_slice(&body).unwrap()
}

/// POSTs `body` as JSON to `url` over plain HTTP; the status and the JSON
/// body (`null` if empty).
async fn post_json(url: &str, body: &Value) -> (u16, Value) {
    let response = reqwest::Client::new()
        .post(url)
        .header("content-type", "application/json")
        .body(body.to_string())
        .send()
        .await
        .unwrap();
    let status = response.status().as_u16();
    let body = response.bytes().await.unwrap();
    (status, serde_json::from_slice(&body).unwrap_or(Value::Null))
}

/// A running `mimid` and the JSON lines it has logged.
struct Mimid {
    child: Child,
    logs: Arc<Mutex<Vec<Value>>>,
    /// Notified as each log line is read, so a test waits for one
    /// instead of looking at the sink again every so often.
    logged: Arc<tokio::sync::Notify>,
    /// The local control listener's base URL.
    local: String,
}

impl Drop for Mimid {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Mimid {
    /// Starts `mimid` for `domain` with `listen_port` and `base_url`, a
    /// database and a local listener in `dir`, and `tables` after the
    /// top-level keys; waits until its local listener answers.
    async fn start(
        dir: &Path,
        domain: &str,
        listen_port: u16,
        base_url: &str,
        tables: &str,
    ) -> Self {
        let local = format!("127.0.0.1:{}", free_port());
        let config = format!(
            "domain = \"{domain}\"\n\
             listen = \"127.0.0.1:{listen_port}\"\n\
             base_url = \"{base_url}\"\n\
             database = \"{database}\"\n\
             local_listen = \"{local}\"\n\
             \n{tables}",
            database = dir.join(format!("{domain}.sqlite")).display(),
        );
        let path = dir.join(format!("{domain}.toml"));
        std::fs::write(&path, config).unwrap();
        let mut child = Command::new(env!("CARGO_BIN_EXE_mimid"))
            .arg(&path)
            .env("RUST_LOG", "info,mimid_server::provider_auth=debug")
            .env("MIMID_LOG_FORMAT", "json")
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let stdout = child.stdout.take().unwrap();
        let logs = Arc::new(Mutex::new(Vec::new()));
        let logged = Arc::new(tokio::sync::Notify::new());
        let sink = Arc::clone(&logs);
        let arrived = Arc::clone(&logged);
        std::thread::spawn(move || {
            for line in std::io::BufReader::new(stdout).lines() {
                let Ok(line) = line else { break };
                let value = serde_json::from_str(&line)
                    .unwrap_or_else(|_| panic!("not a JSON log line: {line}"));
                sink.lock().unwrap().push(value);
                arrived.notify_waiters();
            }
        });
        let mimid = Self {
            child,
            logs,
            logged,
            local: format!("http://{local}/local/v1"),
        };
        // The binary logs its local listener's bind, so the first line
        // of that name says the socket is there to connect to. One
        // request then confirms it answers; a process that died says so
        // instead, because the reader stops and `wait` returns.
        eprintln!("waiting for {domain}'s local listener");
        mimid.await_events("local control listener on", 1).await;
        let http = reqwest::Client::new();
        http.get(format!("{}/users", mimid.local))
            .send()
            .await
            .unwrap_or_else(|e| panic!("{domain}'s local listener answers: {e}"));
        // The local listener is bound first, the protocol listener after
        // other startup work (`main.rs`), so the local one answering says
        // nothing of the other (bead mimid-fchx). Its log line comes
        // right after its bind.
        assert!(
            !mimid.await_events("mimid listening", 1).await.is_empty(),
            "{domain}: the protocol listener did not start"
        );
        mimid
    }

    /// The fields of every logged event with `message`.
    fn events(&self, message: &str) -> Vec<Value> {
        self.logs
            .lock()
            .unwrap()
            .iter()
            .filter(|line| line["message"] == message)
            .map(|line| line["fields"].clone())
            .collect()
    }

    /// Waits until `count` events with `message` are logged; their
    /// fields.
    ///
    /// Woken by the log reader, which notifies as each line arrives.
    /// The waiter is registered before the look, so a line that lands
    /// in between is waiting rather than missed. No deadline: an event
    /// that never comes hangs the test and names the message, where a
    /// guessed one returned too few events and failed at the caller's
    /// assertion instead.
    async fn await_events(&self, message: &str, count: usize) -> Vec<Value> {
        loop {
            let logged = self.logged.notified();
            let events = self.events(message);
            if events.len() >= count {
                return events;
            }
            eprintln!(
                "waiting for {count} {message:?} events, have {}",
                events.len()
            );
            logged.await;
        }
    }

    /// The consent rows this server received from `from`.
    async fn consent_from(&self, from: &str) -> Vec<Value> {
        let rows = get_json(&format!("{}/consent", self.local)).await;
        rows["consent"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|row| row["from"] == from)
            .map(|row| {
                json!({
                    "requester": row["requester"],
                    "target": row["target"],
                    "decision": row["decision"],
                })
            })
            .collect()
    }

    /// The hub's external sender key.
    async fn hub_key(&self) -> [u8; 32] {
        let sender = get_json(&format!("{}/hub-sender", self.local)).await;
        unb64(&sender["signatureKey"]).try_into().unwrap()
    }

    /// The epoch of a room hosted here.
    async fn epoch(&self, room_id: &str) -> u64 {
        let room = get_json(&format!(
            "{}/rooms/{}",
            self.local,
            encode(room_id.as_bytes())
        ))
        .await;
        room["epoch"].as_u64().unwrap()
    }
}

/// Gives alice@a.example an account and a KeyPackage, so a.example knows
/// her (decision mimid-1wgh.7.36).
async fn publish_alice(a: &Mimid, a_base: &str) {
    let alice = Identity::generate(ALICE, mimi_mls::Store::open_in_memory().unwrap()).unwrap();
    Jmap::open(a, a_base, ALICE).await.publish(&alice).await;
}

/// Unpadded lowercase RFC 4648 §6 base32.
fn base32(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
    let (mut out, mut buffer, mut bits) = (String::new(), 0u32, 0);
    for &byte in bytes {
        buffer = (buffer << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(char::from(ALPHABET[((buffer >> bits) & 31) as usize]));
        }
    }
    if bits > 0 {
        out.push(char::from(ALPHABET[((buffer << (5 - bits)) & 31) as usize]));
    }
    out
}

/// The (endpoint, mechanism, key id) of each authentication of `peer`
/// that `mimid` logged.
fn authentications(mimid: &Mimid, peer: &str) -> BTreeSet<(String, String, String)> {
    mimid
        .events(AUTHENTICATED)
        .iter()
        .filter(|fields| fields["peer"] == peer)
        .map(|fields| {
            (
                fields["endpoint"].as_str().unwrap().to_owned(),
                fields["mechanism"].as_str().unwrap().to_owned(),
                fields["key_id"].as_str().unwrap().to_owned(),
            )
        })
        .collect()
}

/// One JMAP account at one binary, and what it has read so far.
struct Jmap {
    http: reqwest::Client,
    api: String,
    token: String,
    account: String,
    state: Option<String>,
    queue: VecDeque<FanoutMessage>,
}

impl Jmap {
    /// A new account for `user` at `mimid`, whose JMAP API is under
    /// `base_url`, with a bearer token from the local listener.
    async fn open(mimid: &Mimid, base_url: &str, user: &[u8]) -> Self {
        let (status, created) = post_json(
            &format!("{}/users", mimid.local),
            &json!({"user": text(user)}),
        )
        .await;
        assert_eq!(status, 201, "{created}");
        let (status, token) = post_json(
            &format!("{}/users/{}/tokens", mimid.local, encode(user)),
            &Value::Null,
        )
        .await;
        assert_eq!(status, 201, "{token}");
        Self {
            http: client(None),
            api: format!("{base_url}/jmap/api"),
            token: token["token"].as_str().unwrap().to_owned(),
            account: created["accountId"].as_str().unwrap().to_owned(),
            state: None,
            queue: VecDeque::new(),
        }
    }

    async fn call(&self, method: &str, mut args: Value) -> (String, Value) {
        args["accountId"] = json!(self.account);
        let body = json!({"using": USING, "methodCalls": [[method, args, "c"]]});
        let response = self
            .http
            .post(&self.api)
            .bearer_auth(&self.token)
            .header("content-type", "application/json")
            .body(body.to_string())
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200, "{method}");
        let body: Value = serde_json::from_slice(&response.bytes().await.unwrap()).unwrap();
        let call = &body["methodResponses"][0];
        (call[0].as_str().unwrap().to_owned(), call[1].clone())
    }

    async fn ok(&self, method: &str, args: Value) -> Value {
        let (name, answer) = self.call(method, args).await;
        assert_eq!(name, method, "{method} failed: {answer}");
        answer
    }

    async fn publish(&self, identity: &Identity) -> Vec<u8> {
        let key_package = identity.key_package(KeyPackageKind::OneTime).unwrap();
        let answer = self
            .ok(
                "KeyPackage/set",
                json!({"create": {"k": {"keyPackage": b64(&key_package)}}}),
            )
            .await;
        assert!(answer["created"]["k"].is_object(), "{answer}");
        key_package
    }

    /// Consent/set granting `requester`; the answer for the one record.
    async fn grant(&self, requester: &[u8], target: &[u8]) -> Value {
        self.ok(
            "Consent/set",
            json!({"create": {"c": {
                "requesterUri": text(requester),
                "targetUri": text(target),
                "decision": "grant",
            }}}),
        )
        .await
    }

    async fn update(&self, room_id: &str, request: &[u8]) {
        let answer = self
            .ok(
                "Room/update",
                json!({"roomId": room_id, "request": b64(request)}),
            )
            .await;
        assert_eq!(answer["responseCode"], "success", "{answer}");
    }

    async fn send(&self, room_id: &str, message: &[u8]) {
        let answer = self
            .ok(
                "Room/send",
                json!({"roomId": room_id, "message": b64(message)}),
            )
            .await;
        assert_eq!(answer["responseCode"], "accepted", "{answer}");
    }

    async fn read(&mut self) {
        let ids = match &self.state {
            None => Value::Null,
            Some(since) => {
                let changes = self
                    .ok("Message/changes", json!({"sinceState": since}))
                    .await;
                self.state = Some(changes["newState"].as_str().unwrap().to_owned());
                let created = changes["created"].as_array().unwrap().clone();
                if created.is_empty() {
                    return;
                }
                Value::Array(created)
            }
        };
        let answer = self
            .ok("Message/get", json!({"ids": ids, "properties": ["body"]}))
            .await;
        if self.state.is_none() {
            self.state = Some(answer["state"].as_str().unwrap().to_owned());
        }
        let mut list = answer["list"].as_array().unwrap().clone();
        list.sort_by(|x, y| x["id"].as_str().cmp(&y["id"].as_str()));
        for message in list {
            let body = unb64(&message["body"]);
            self.queue
                .extend(FanoutMessage::decode_all(&body).expect("a FanoutMessage body"));
        }
    }

    /// The next FanoutMessage stored for this account.
    ///
    /// The one wait in this file with nothing to wait on: the providers
    /// are separate processes, and storing a fanout logs nothing at the
    /// `info` level they run at, so there is no line to follow and no
    /// in-process signal to subscribe to. Bead mimid-67e0.2 is to add
    /// that event; until then this reads on a bound ([`WAIT`]).
    async fn next(&mut self) -> FanoutMessage {
        let deadline = Instant::now() + WAIT;
        loop {
            if let Some(message) = self.queue.pop_front() {
                return message;
            }
            assert!(Instant::now() < deadline, "nothing arrived");
            self.read().await;
            if self.queue.is_empty() {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }
    }
}

/// `ParticipantListData` listing `users` with [`ROLE_MEMBER`].
fn participants(users: &[&[u8]]) -> Vec<u8> {
    ParticipantListData {
        participants: users
            .iter()
            .map(|user| UserRolePair {
                user: user.to_vec(),
                role_index: ROLE_MEMBER,
            })
            .collect(),
    }
    .tls_serialize_detached()
    .unwrap()
}

/// Role 1 banned; role 2 may add participants (0 -> 2) and its own
/// clients, and send.
fn roles_list() -> Vec<u8> {
    let role = |role_index, role_name: &str, role_capabilities, authorized_role_changes| Role {
        role_index,
        role_name: role_name.to_owned(),
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
                ROLE_MEMBER,
                "member",
                vec![
                    Capability::CAN_ADD_PARTICIPANT,
                    Capability::CAN_ADD_OWN_CLIENT,
                    Capability::CAN_SEND_MESSAGE,
                ],
                vec![SingleSourceRoleChangeTargets {
                    from_role_index: 0,
                    target_role_indexes: vec![ROLE_MEMBER],
                }],
            ),
        ],
    }
    .tls_serialize_detached()
    .unwrap()
}

fn components(hub_key: &[u8; 32]) -> Vec<(u16, Vec<u8>)> {
    let mut components = vec![
        (APP_COMPONENTS, ROOM_APP_COMPONENTS.to_vec()),
        (SAFE_AAD, FRANK_AAD_ONLY.to_vec()),
        (FRANKING_AGENT, franking_agent(hub_key, HUB_IDENTITY)),
        (PARTICIPANT_LIST, participants(&[ALICE])),
        (ROLES_LIST, roles_list()),
        (BASE_ROOM_POLICY, base_room_policy()),
    ];
    components.sort_by_key(|(component_id, _)| *component_id);
    components
}

type Applied = Result<Option<Vec<u8>>, ErrorSource>;

fn alice_and_bob(component_id: u16, _current: Option<&[u8]>, op: ComponentOp<'_>) -> Applied {
    match (component_id, op) {
        (PARTICIPANT_LIST, ComponentOp::Update(_)) => Ok(Some(participants(&[ALICE, BOB]))),
        _ => Err("unexpected AppDataUpdate".into()),
    }
}

fn add_bob() -> AppDataUpdate {
    AppDataUpdate::Update {
        component_id: PARTICIPANT_LIST,
        update: ParticipantListUpdate {
            changed_role_participants: vec![],
            removed_indices: vec![],
            added_participants: vec![UserRolePair {
                user: BOB.to_vec(),
                role_index: ROLE_MEMBER,
            }],
        }
        .tls_serialize_detached()
        .unwrap(),
    }
}

/// `identity` encrypts `data` with a `frank_aad` item over it.
fn franked(identity: &Identity, member: &mut Member, data: &[u8]) -> Vec<u8> {
    let salt = mimi_mls::label::random_array::<16>().unwrap();
    let tag = franking_tag(&salt, data);
    member
        .send(identity, data, &[(FRANK_AAD, tag.to_vec())])
        .unwrap()
}

fn mls_bytes(message: &FanoutMessage) -> &[u8] {
    match &message.event {
        FanoutEvent::Commit { message, .. }
        | FanoutEvent::Proposal { message, .. }
        | FanoutEvent::Application { message, .. } => message.as_bytes(),
        FanoutEvent::Welcome { .. } => panic!("a Welcome is not processed"),
    }
}

fn assert_decrypts(identity: &Identity, member: &mut Member, message: &FanoutMessage, data: &[u8]) {
    match member
        .process(identity, mls_bytes(message), no_components)
        .unwrap()
    {
        Incoming::Application { data: got, .. } => assert_eq!(got, data),
        other => panic!("not an application message: {other:?}"),
    }
}

/// The `[tls]`, `[peer_tls]` and `[provider_auth]` tables of a server that
/// terminates TLS with the test server certificate, presents
/// `identity` (certificate, key) to `to`, trusts the test CA for peers'
/// server certificates, and enforces with only PKIX on, anchored as
/// `anchors` says.
///
/// `to` is there because since bead mimid-75nk.14 a client certificate
/// goes only to the peers that ask for it: `[peer_tls.identity]` alone
/// is presented to nobody. These tests are the mTLS tests, so their one
/// peer asks.
fn mtls_tables(identity: (&str, &str), to: &str, anchors: &str) -> String {
    format!(
        "[tls]\n\
         cert = \"{TLS}/server.pem\"\n\
         key = \"{TLS}/server.key\"\n\
         \n\
         [peer_tls]\n\
         roots = [\"{TLS}/ca.pem\"]\n\
         \n\
         [peer_tls.identity]\n\
         cert = \"{}\"\n\
         key = \"{}\"\n\
         \n\
         [peer_tls.peers.\"{to}\"]\n\
         client_certificate = true\n\
         \n\
         [provider_auth]\n\
         mode = \"enforce\"\n\
         dns_keys = false\n\
         dane = false\n\
         {anchors}",
        identity.0, identity.1,
    )
}

/// Both halves, both directions, PKIX: each binary presents its client
/// certificate on every request it sends, and authenticates the other's
/// on every request it receives.
#[tokio::test]
async fn pkix_mtls_both_directions_between_two_binaries() {
    let dir = tempfile::tempdir().unwrap();
    let (a_port, b_port) = (free_port(), free_port());
    let a_base = format!("https://127.0.0.1:{a_port}");
    let b_base = format!("https://127.0.0.1:{b_port}");
    // a.example trusts the test CA for b.example only; b.example trusts it
    // for every peer.
    let a = Mimid::start(
        dir.path(),
        "a.example",
        a_port,
        &a_base,
        &format!(
            "[peers]\n\"b.example\" = \"{b_base}\"\n\n{}\n\
             [provider_auth.peers.\"b.example\"]\n\
             pkix_anchors = [\"{TLS}/ca.pem\"]\n",
            mtls_tables(
                (&format!("{TLS}/client.pem"), &format!("{TLS}/client.key")),
                "b.example",
                ""
            ),
        ),
    )
    .await;
    let b = Mimid::start(
        dir.path(),
        "b.example",
        b_port,
        &b_base,
        &format!(
            "[peers]\n\"a.example\" = \"{a_base}\"\n\n{}",
            mtls_tables(
                (
                    &format!("{MTLS}/b-client.pem"),
                    &format!("{MTLS}/b-client.key")
                ),
                "a.example",
                &format!("pkix_anchors = [\"{TLS}/ca.pem\"]\n"),
            ),
        ),
    )
    .await;

    // Accounts and KeyPackages; bob's consent for alice goes b -> a
    // (updateConsent).
    let mut alice_jmap = Jmap::open(&a, &a_base, ALICE).await;
    let mut bob_jmap = Jmap::open(&b, &b_base, BOB).await;
    let alice = Identity::generate(ALICE, mimi_mls::Store::open_in_memory().unwrap()).unwrap();
    let bob = Identity::generate(BOB, mimi_mls::Store::open_in_memory().unwrap()).unwrap();
    alice_jmap.publish(&alice).await;
    let bob_key_package = bob_jmap.publish(&bob).await;
    let consent = bob_jmap.grant(ALICE, BOB).await;
    assert!(consent["created"]["c"].is_object(), "{consent}");
    assert_eq!(
        a.consent_from("b.example").await,
        [json!({"requester": text(ALICE), "target": text(BOB), "decision": "grant"})]
    );

    // Epoch 1: alice's room, hosted at a.
    let hub_key = a.hub_key().await;
    let room_id = format!(
        "mimi://a.example/r/{}",
        base32(&mimi_mls::label::random_array::<16>().unwrap())
    );
    let senders = [ExternalSender {
        signature_key: hub_key.to_vec(),
        identity: HUB_IDENTITY.to_vec(),
    }];
    let group_id = mimi_mls::label::random_array::<16>().unwrap();
    let mut alice_group =
        Member::create(&alice, &group_id, &senders, &components(&hub_key)).unwrap();
    let bundle = alice_group
        .commit(&alice, &[], &[], &[], no_components)
        .unwrap();
    alice_group.merge_pending_commit(&alice).unwrap();
    let created = alice_jmap
        .ok(
            "Room/create",
            json!({
                "roomId": room_id,
                "groupInfo": b64(&bundle.group_info),
                "ratchetTree": b64(&alice_group.ratchet_tree().unwrap()),
            }),
        )
        .await;
    assert_eq!(created["roomId"], room_id.as_str(), "{created}");

    // a -> b keyMaterial: the KeyPackage served is the one bob published.
    let request = key_packages::request(&Ask {
        requesting_user: text(ALICE),
        credential_identity: text(ALICE),
        target_user: text(BOB),
        room_id: &room_id,
        required_capabilities: NO_REQUIREMENTS,
    });
    let material = alice_jmap
        .ok(
            "KeyMaterial/fetch",
            json!({"roomId": room_id, "request": b64(&request)}),
        )
        .await;
    assert_eq!(material["userStatus"], "success", "{material}");
    let clients = material["clients"].as_array().unwrap();
    assert_eq!(unb64(&clients[0]["keyPackage"]), bob_key_package);

    // Epoch 2: the Add; a -> b notify carries bob's Welcome.
    let bundle = alice_group
        .commit(
            &alice,
            &[&bob_key_package],
            &[],
            &[add_bob()],
            alice_and_bob,
        )
        .unwrap();
    alice_group.merge_pending_commit(&alice).unwrap();
    alice_jmap
        .update(
            &room_id,
            &update::commit_request(
                &bundle.commit,
                bundle.welcome.as_deref(),
                &bundle.group_info,
                &alice_group.ratchet_tree().unwrap(),
            ),
        )
        .await;
    alice_jmap.next().await;
    let message = bob_jmap.next().await;
    let FanoutEvent::Welcome {
        message: welcome,
        ratchet_tree_option,
    } = &message.event
    else {
        panic!("bob's first Message is not his Welcome: {message:?}");
    };
    let mut bob_group = Member::join_welcome(
        &bob,
        welcome.as_bytes(),
        Some(ratchet_tree_option.ratchet_tree().unwrap()),
    )
    .unwrap()
    .member;
    assert_eq!(a.epoch(&room_id).await, 2);
    assert_eq!(bob_group.epoch(), 2);

    // a -> b notify of alice's message; b -> a submitMessage of bob's.
    let hello = b"hello bob, over mTLS";
    let sent = franked(&alice, &mut alice_group, hello);
    alice_jmap.send(&room_id, &sent).await;
    alice_jmap.next().await;
    assert_decrypts(&bob, &mut bob_group, &bob_jmap.next().await, hello);
    let reply = b"hi alice, from b over mTLS";
    let sent = franked(&bob, &mut bob_group, reply);
    bob_jmap.send(&room_id, &sent).await;
    bob_jmap.next().await;
    assert_decrypts(&alice, &mut alice_group, &alice_jmap.next().await, reply);

    // b -> a groupInfo, relayed for bob.
    let requester = group_info::Requester::new(BOB);
    let fetched = bob_jmap
        .ok(
            "GroupInfo/fetch",
            json!({"roomId": room_id, "request": b64(&requester.request(None))}),
        )
        .await;
    assert_eq!(fetched["status"], "success", "{fetched}");

    // Epoch 3: b -> a update, bob's empty Commit.
    let bundle = bob_group
        .commit(&bob, &[], &[], &[], no_components)
        .unwrap();
    bob_group.merge_pending_commit(&bob).unwrap();
    bob_jmap
        .update(
            &room_id,
            &update::commit_request(
                &bundle.commit,
                None,
                &bundle.group_info,
                &bob_group.ratchet_tree().unwrap(),
            ),
        )
        .await;
    let commit = alice_jmap.next().await;
    match alice_group
        .process(&alice, mls_bytes(&commit), no_components)
        .unwrap()
    {
        Incoming::Commit(_) => {}
        other => panic!("not a Commit: {other:?}"),
    }
    assert_eq!(a.epoch(&room_id).await, 3);
    assert_eq!(
        alice_group.epoch_authenticator(),
        bob_group.epoch_authenticator()
    );

    // Every request was authenticated by PKIX with the other's
    // certificate, and none was refused.
    let pkix =
        |endpoint: &str, key_id: &str| (endpoint.to_owned(), "pkix".to_owned(), key_id.to_owned());
    a.await_events(AUTHENTICATED, 4).await;
    assert_eq!(
        authentications(&a, "b.example"),
        BTreeSet::from([
            pkix("updateConsent", B_KEY_ID),
            pkix("submitMessage", B_KEY_ID),
            pkix("groupInfo", B_KEY_ID),
            pkix("update", B_KEY_ID),
        ])
    );
    assert_eq!(
        authentications(&b, "a.example"),
        BTreeSet::from([pkix("keyMaterial", A_KEY_ID), pkix("notify", A_KEY_ID)])
    );
    assert!(a.events(REFUSED).is_empty(), "{:?}", a.events(REFUSED));
    assert!(b.events(REFUSED).is_empty(), "{:?}", b.events(REFUSED));
}

/// A requestConsent body: bob asks alice (protocol-07 §5.7).
fn bob_asks_alice() -> Vec<u8> {
    ConsentEntry {
        consent_operation: ConsentOperation::Request,
        requester_uri: IdentifierUri::new(text(BOB)).unwrap(),
        target_uri: IdentifierUri::new(text(ALICE)).unwrap(),
        room_id: None,
        client_key_packages: Vec::new(),
        consent_extensions: AppDataDictionary::new(&[]).unwrap(),
    }
    .tls_serialize_detached()
    .unwrap()
}

/// POSTs bob's requestConsent to `base` as `mimi@b.example` with
/// `client`; the status, the `Accept-Signature` field and the problem
/// type.
async fn ask(
    client: &reqwest::Client,
    base: &str,
    extra: Option<(&str, String)>,
) -> (u16, Option<String>, String) {
    let mut request = client
        .post(format!("{base}/v1/requestConsent/a.example"))
        .header("From", "mimi@b.example")
        .header("Content-Type", "application/mimi-protocol")
        .body(bob_asks_alice());
    if let Some((name, value)) = extra {
        request = request.header(name, value);
    }
    let response = request.send().await.unwrap();
    let status = response.status().as_u16();
    let accept = response
        .headers()
        .get("accept-signature")
        .map(|v| v.to_str().unwrap().to_owned());
    let body = response.bytes().await.unwrap();
    let kind = serde_json::from_slice::<Value>(&body)
        .ok()
        .and_then(|v| v["type"].as_str().map(str::to_owned))
        .unwrap_or_default();
    (status, accept, kind)
}

/// The reasons of a.example's refusals of `requestConsent` from b.example,
/// in order.
async fn refusal_reasons(a: &Mimid, count: usize) -> Vec<String> {
    a.await_events(REFUSED, count)
        .await
        .iter()
        .map(|fields| {
            assert_eq!(fields["peer"], "b.example");
            assert_eq!(fields["endpoint"], "requestConsent");
            assert_eq!(fields["status"], 403);
            fields["reason"].as_str().unwrap().to_owned()
        })
        .collect()
}

/// a.example, terminating TLS and enforcing PKIX for b.example, refuses
/// b.example's request without a certificate, with a.example's, with one
/// from an unknown CA and with an expired one, and accepts it with
/// b.example's.
#[tokio::test]
async fn pkix_refuses_missing_wrong_domain_untrusted_and_expired_certificates() {
    let dir = tempfile::tempdir().unwrap();
    let a_port = free_port();
    let a_base = format!("https://127.0.0.1:{a_port}");
    let a = Mimid::start(
        dir.path(),
        "a.example",
        a_port,
        &a_base,
        &format!(
            "[peers]\n\"b.example\" = \"https://127.0.0.1:9\"\n\n{}\n\
             [provider_auth.peers.\"b.example\"]\n\
             pkix_anchors = [\"{TLS}/ca.pem\"]\n",
            mtls_tables(
                (&format!("{TLS}/client.pem"), &format!("{TLS}/client.key")),
                "b.example",
                ""
            ),
        ),
    )
    .await;
    publish_alice(&a, &a_base).await;

    let a_cert = (format!("{TLS}/client.pem"), format!("{TLS}/client.key"));
    let refused = [
        client(None),
        client(Some((&a_cert.0, &a_cert.1))),
        client(Some((
            &format!("{MTLS}/b-untrusted.pem"),
            &format!("{MTLS}/b-untrusted.key"),
        ))),
        client(Some((
            &format!("{MTLS}/b-expired.pem"),
            &format!("{MTLS}/b-expired.key"),
        ))),
    ];
    for (i, http) in refused.iter().enumerate() {
        let (status, accept, kind) = ask(http, &a_base, None).await;
        assert_eq!(status, 403, "case {i}");
        assert_eq!(
            accept.as_deref(),
            Some(provider_auth::ACCEPT_SIGNATURE),
            "case {i}"
        );
        assert!(
            kind.ends_with("provider-authentication"),
            "case {i}: {kind}"
        );
    }
    let reasons = refusal_reasons(&a, 4).await;
    // The path errors are pkix-path's (RFC 5280 §6.1).
    assert_eq!(
        reasons,
        [
            "no credentials",
            "certificate refused: no dNSName for the domain",
            "certificate path refused: no path to a trusted anchor",
            "certificate path refused: validity period check failed at chain index 0",
        ]
    );
    assert!(a.consent_from("b.example").await.is_empty());

    let b_cert = client(Some((
        &format!("{MTLS}/b-client.pem"),
        &format!("{MTLS}/b-client.key"),
    )));
    assert_eq!(ask(&b_cert, &a_base, None).await.0, 202);
    assert_eq!(
        a.consent_from("b.example").await,
        [json!({"requester": text(BOB), "target": text(ALICE), "decision": null})]
    );
    a.await_events(AUTHENTICATED, 1).await;
    assert_eq!(
        authentications(&a, "b.example"),
        BTreeSet::from([(
            "requestConsent".to_owned(),
            "pkix".to_owned(),
            B_KEY_ID.to_owned()
        )])
    );
}

/// The proxy of the trusted-proxy test: terminates TLS with the test
/// server certificate, asking for a client certificate, and forwards each
/// request to `upstream` from 127.0.0.2 with the leaf in `X-Client-Cert`,
/// as Caddy's `header_up X-Client-Cert
/// {http.request.tls.client.certificate_der_base64}` does. A header of
/// that name from the client is dropped.
#[derive(Clone)]
struct Proxy {
    http: reqwest::Client,
    upstream: String,
}

async fn forward(
    State(proxy): State<Proxy>,
    certificate: Option<Extension<ClientCertificate>>,
    request: Request,
) -> Response {
    let (parts, body) = request.into_parts();
    let body = to_bytes(body, 1 << 24).await.unwrap();
    let path = parts.uri.path_and_query().map_or("/", |p| p.as_str());
    let mut outbound = proxy
        .http
        .request(parts.method, format!("{}{path}", proxy.upstream));
    for (name, value) in &parts.headers {
        if !matches!(
            name.as_str(),
            "x-client-cert" | "host" | "content-length" | "connection" | "transfer-encoding"
        ) {
            outbound = outbound.header(name, value);
        }
    }
    if let Some(Extension(certificate)) = certificate {
        outbound = outbound.header("x-client-cert", STANDARD.encode(&certificate.chain[0]));
    }
    let response = outbound.body(body).send().await.unwrap();
    let mut builder = Response::builder().status(response.status());
    for (name, value) in response.headers() {
        if !matches!(
            name.as_str(),
            "content-length" | "connection" | "transfer-encoding"
        ) {
            builder = builder.header(name, value);
        }
    }
    builder
        .body(Body::from(response.bytes().await.unwrap()))
        .unwrap()
}

/// Serves `app` over TLS with the test server certificate on a loopback
/// port; its base URL.
async fn serve_tls(app: Router) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!(
        "https://127.0.0.1:{}",
        listener.local_addr().unwrap().port()
    );
    let config = tls::server_config(&TlsConfig {
        cert: format!("{TLS}/server.pem").into(),
        key: format!("{TLS}/server.key").into(),
    })
    .unwrap();
    tokio::spawn(tls::serve(listener, config, app, std::future::pending()));
    base
}

/// a.example serves plain HTTP behind a TLS-terminating proxy at
/// 127.0.0.2 (`[trusted_proxy]`) and authenticates b.example's binary by
/// the certificate the proxy forwards. The header is honored from the
/// proxy's address only.
#[tokio::test]
async fn pkix_through_a_trusted_proxy() {
    let dir = tempfile::tempdir().unwrap();
    let a_port = free_port();
    let a_upstream = format!("http://127.0.0.1:{a_port}");
    let proxy = Proxy {
        http: reqwest::Client::builder()
            .local_address(std::net::IpAddr::from([127, 0, 0, 2]))
            .build()
            .unwrap(),
        upstream: a_upstream.clone(),
    };
    let a_base = serve_tls(Router::new().fallback(forward).with_state(proxy)).await;
    let a = Mimid::start(
        dir.path(),
        "a.example",
        a_port,
        &a_base,
        &format!(
            "[peers]\n\"b.example\" = \"https://127.0.0.1:9\"\n\n\
             [trusted_proxy]\n\
             addresses = [\"127.0.0.2\"]\n\
             header = \"X-Client-Cert\"\n\
             \n\
             [provider_auth]\n\
             mode = \"enforce\"\n\
             dns_keys = false\n\
             dane = false\n\
             \n\
             [provider_auth.peers.\"b.example\"]\n\
             pkix_anchors = [\"{TLS}/ca.pem\"]\n"
        ),
    )
    .await;
    publish_alice(&a, &a_base).await;
    let b_port = free_port();
    let b_base = format!("http://127.0.0.1:{b_port}");
    let b = Mimid::start(
        dir.path(),
        "b.example",
        b_port,
        &b_base,
        &format!(
            "[peers]\n\"a.example\" = \"{a_base}\"\n\n\
             [peer_tls]\n\
             roots = [\"{TLS}/ca.pem\"]\n\
             \n\
             [peer_tls.identity]\n\
             cert = \"{MTLS}/b-client.pem\"\n\
             key = \"{MTLS}/b-client.key\"\n\
             \n\
             [peer_tls.peers.\"a.example\"]\n\
             client_certificate = true\n\
             \n\
             [provider_auth]\n\
             dns_keys = false\n\
             dane = false\n"
        ),
    )
    .await;

    // Refused: the header straight from 127.0.0.1, which is not the
    // proxy; through the proxy without a certificate; through the proxy
    // with a certificate from an unknown CA.
    let b_der = STANDARD.encode(der(&format!("{MTLS}/b-client.pem")));
    let (status, ..) = ask(
        &reqwest::Client::new(),
        &a_upstream,
        Some(("X-Client-Cert", b_der)),
    )
    .await;
    assert_eq!(status, 403);
    assert_eq!(ask(&client(None), &a_base, None).await.0, 403);
    let untrusted = client(Some((
        &format!("{MTLS}/b-untrusted.pem"),
        &format!("{MTLS}/b-untrusted.key"),
    )));
    assert_eq!(ask(&untrusted, &a_base, None).await.0, 403);
    let reasons = refusal_reasons(&a, 3).await;
    assert_eq!(reasons[..2], ["no credentials", "no credentials"]);
    assert_eq!(
        reasons[2],
        "certificate path refused: no path to a trusted anchor"
    );

    // b.example's binary, through the proxy: bob's grant reaches a.
    let bob_jmap = Jmap::open(&b, &b_base, BOB).await;
    let consent = bob_jmap.grant(ALICE, BOB).await;
    assert!(consent["created"]["c"].is_object(), "{consent}");
    assert_eq!(
        a.consent_from("b.example").await,
        [json!({"requester": text(ALICE), "target": text(BOB), "decision": "grant"})]
    );
    a.await_events(AUTHENTICATED, 1).await;
    assert_eq!(
        authentications(&a, "b.example"),
        BTreeSet::from([(
            "updateConsent".to_owned(),
            "pkix".to_owned(),
            B_KEY_ID.to_owned()
        )])
    );
}

type TlsaAnswer = Result<Vec<(TlsaRecord, DnssecStatus)>, TxtLookupError>;

/// TLSA answers for `_mimi._client.b.example.` as the test sets them; as a
/// validating resolver would report them.
#[derive(Default)]
struct Zone(Mutex<Option<TlsaAnswer>>);

impl Zone {
    fn set(&self, answer: TlsaAnswer) {
        *self.0.lock().unwrap() = Some(answer);
    }
}

impl TlsaResolver for Zone {
    fn tlsa<'a>(&'a self, name: &'a str) -> BoxFuture<'a, TlsaAnswer> {
        let answer = if name == "_mimi._client.b.example." {
            self.0
                .lock()
                .unwrap()
                .clone()
                .unwrap_or(Err(TxtLookupError::NoRecords))
        } else {
            Err(TxtLookupError::NoRecords)
        };
        Box::pin(std::future::ready(answer))
    }
}

fn tlsa(usage: u8, selector: u8, matching: u8, data: &str, status: DnssecStatus) -> TlsaAnswer {
    Ok(vec![(
        TlsaRecord {
            usage,
            selector,
            matching,
            data: unhex(data),
        },
        status,
    )])
}

type Seen = Arc<Mutex<Vec<(String, Mechanism, String)>>>;

/// Records the provider each request was authenticated as.
async fn record(State(seen): State<Seen>, request: Request, next: Next) -> Response {
    if let Some(provider) = request.extensions().get::<AuthenticatedProvider>() {
        seen.lock().unwrap().push((
            provider.domain.as_str().to_owned(),
            provider.mechanism,
            provider.key_id.clone(),
        ));
    }
    next.run(request).await
}

/// DANE, b → a: a.example (the library's server over [`tls::serve`], with
/// a stub validating resolver) authenticates b.example's binary by its
/// TLSA records: DANE-EE matching its key, DANE-TA matching the CA in the
/// chain it presents. A record for another key, an insecure answer, or no
/// records at all leave it unauthenticated.
#[tokio::test]
async fn dane_authenticates_a_binary_by_its_tlsa_records() {
    let dir = tempfile::tempdir().unwrap();
    // a.example, as main.rs wires it, with DANE the only mechanism.
    let store = Store::open(&dir.path().join("a-lib.sqlite"), &domain("a.example"))
        .await
        .unwrap();
    let requesters: [&[u8]; 5] = [
        b"mimi://a.example/u/alice",
        b"mimi://a.example/u/carol",
        b"mimi://a.example/u/dave",
        b"mimi://a.example/u/erin",
        b"mimi://a.example/u/frank",
    ];
    // Known users have a client (decision mimid-1wgh.7.36).
    for (i, user) in requesters.into_iter().enumerate() {
        store
            .insert_key_package(&NewKeyPackage {
                client_id: &format!("{}/client", text(user)),
                user_uri: text(user),
                signature_key: b"signature key",
                reference: &[u8::try_from(i).unwrap(); 32],
                bytes: b"key package",
                last_resort: true,
                not_after: 4_000_000_000,
            })
            .await
            .unwrap();
    }
    let zone = Arc::new(Zone::default());
    let seen: Seen = Arc::default();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let a_base = format!(
        "https://127.0.0.1:{}",
        listener.local_addr().unwrap().port()
    );
    let base_url = BaseUrl::try_from(a_base.clone()).unwrap();
    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    let hub = Hub::open(store.clone(), domain("a.example"), Arc::clone(&clock))
        .await
        .unwrap();
    // Consent is taken from configured peers only (decision
    // mimid-1wgh.7.41); a.example sends nothing here.
    let peers = std::collections::BTreeMap::from([(
        domain("b.example"),
        BaseUrl::try_from("http://127.0.0.1:9".to_owned()).unwrap(),
    )]);
    let follower = Follower::new(domain("a.example"), store.clone(), Arc::clone(&clock))
        .with_peers(PeerClient::new(&domain("a.example"), peers).unwrap());
    let config: ProviderAuthConfig = toml::from_str("dns_keys = false\ndane = true\n").unwrap();
    let auth =
        Arc::new(ProviderAuth::new(&config, &base_url, clock).with_dane(Arc::clone(&zone) as _));
    let app = router(directory(&base_url), Arc::new(hub), Arc::new(follower))
        .layer(axum::middleware::from_fn_with_state(
            Arc::clone(&seen),
            record,
        ))
        .layer(axum::middleware::from_fn_with_state(
            auth,
            provider_auth::check,
        ));
    let tls_config = tls::server_config(&TlsConfig {
        cert: format!("{TLS}/server.pem").into(),
        key: format!("{TLS}/server.key").into(),
    })
    .unwrap();
    tokio::spawn(tls::serve(
        listener,
        tls_config,
        app,
        std::future::pending(),
    ));

    // b.example's binary presents its leaf and the CA above it.
    let chain = dir.path().join("b-chain.pem");
    std::fs::write(
        &chain,
        [
            read(&format!("{MTLS}/b-client.pem")),
            read(&format!("{TLS}/ca.pem")),
        ]
        .concat(),
    )
    .unwrap();
    let b_port = free_port();
    let b_base = format!("http://127.0.0.1:{b_port}");
    let b = Mimid::start(
        dir.path(),
        "b.example",
        b_port,
        &b_base,
        &format!(
            "[peers]\n\"a.example\" = \"{a_base}\"\n\n\
             [peer_tls]\n\
             roots = [\"{TLS}/ca.pem\"]\n\
             \n\
             [peer_tls.identity]\n\
             cert = \"{}\"\n\
             key = \"{MTLS}/b-client.key\"\n\
             \n\
             [peer_tls.peers.\"a.example\"]\n\
             client_certificate = true\n\
             \n\
             [provider_auth]\n\
             dns_keys = false\n\
             dane = false\n",
            chain.display()
        ),
    )
    .await;
    let bob_jmap = Jmap::open(&b, &b_base, BOB).await;

    let cases = [
        (tlsa(3, 1, 1, B_SPKI_SHA256, DnssecStatus::Secure), true),
        (
            tlsa(3, 1, 1, UNTRUSTED_SPKI_SHA256, DnssecStatus::Secure),
            false,
        ),
        (tlsa(3, 1, 1, B_SPKI_SHA256, DnssecStatus::Insecure), false),
        (Err(TxtLookupError::NoRecords), false),
        (tlsa(2, 0, 1, CA_SHA256, DnssecStatus::Secure), true),
    ];
    let mut granted = Vec::new();
    for (i, ((answer, accepted), requester)) in cases.into_iter().zip(requesters).enumerate() {
        zone.set(answer);
        let consent = bob_jmap.grant(requester, BOB).await;
        if accepted {
            assert!(consent["created"]["c"].is_object(), "case {i}: {consent}");
            granted.push((text(requester).to_owned(), "b.example".to_owned()));
        } else {
            assert_eq!(
                consent["notCreated"]["c"]["type"], "consentNotSent",
                "case {i}: {consent}"
            );
        }
    }
    let rows: Vec<(String, String)> = store
        .consent_rows()
        .await
        .unwrap()
        .into_iter()
        .map(|row| (row.requester_uri, row.from_domain))
        .collect();
    assert_eq!(rows, granted);
    let dane = ("b.example".to_owned(), Mechanism::Dane, B_KEY_ID.to_owned());
    assert_eq!(*seen.lock().unwrap(), [dane.clone(), dane]);
}
