//! What the daemon tests share: an in-process mimid server, daemons
//! started on it, and a JMAP client that speaks only HTTP to a daemon.

// Each test binary uses part of this module.
#![allow(dead_code)]

pub mod irc;

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use mimid_agent::{Config, Daemon};
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
use tokio::sync::{oneshot, watch};
use tokio::task::JoinHandle;

pub const ALICE: &str = "mimi://a.example/u/alice";
pub const BOB: &str = "mimi://a.example/u/bob";

/// How long a test waits for something that should happen.
pub const PATIENCE: Duration = Duration::from_secs(15);

/// A running mimid server: its base URL, a bearer token per user, and
/// the switch on its EventSource.
pub struct Server {
    pub base: String,
    pub tokens: BTreeMap<&'static str, String>,
    pub push: PushControl,
}

/// What a test does to the server's EventSource (`/jmap/eventsource`),
/// through a layer in front of mimid-server's router: refuse it, cut the
/// open streams, and count both.
#[derive(Clone)]
pub struct PushControl {
    refuse: Arc<AtomicBool>,
    opened: Arc<AtomicUsize>,
    refused: Arc<AtomicUsize>,
    cut: Arc<watch::Sender<u64>>,
}

impl Default for PushControl {
    fn default() -> Self {
        Self {
            refuse: Arc::default(),
            opened: Arc::default(),
            refused: Arc::default(),
            cut: Arc::new(watch::channel(0).0),
        }
    }
}

impl PushControl {
    /// From now on, answer `503` instead of opening a stream.
    pub fn refuse(&self, refuse: bool) {
        self.refuse.store(refuse, Ordering::SeqCst);
    }

    /// Ends every open stream, as a server going away does.
    pub fn cut(&self) {
        self.cut.send_modify(|n| *n += 1);
    }

    /// How many streams were opened.
    pub fn opened(&self) -> usize {
        self.opened.load(Ordering::SeqCst)
    }

    /// How many were refused.
    pub fn refused(&self) -> usize {
        self.refused.load(Ordering::SeqCst)
    }

    /// Waits until `count` returns at least `n`; panics after
    /// [`PATIENCE`].
    pub async fn until(&self, what: &str, n: usize, count: impl Fn(&Self) -> usize) {
        tokio::time::timeout(PATIENCE, async {
            while count(self) < n {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("{what}: {} is not {n}", count(self)));
    }

    async fn layer(
        axum::extract::State(control): axum::extract::State<Self>,
        request: axum::extract::Request,
        next: axum::middleware::Next,
    ) -> axum::response::Response {
        use axum::response::IntoResponse;
        use futures::StreamExt;
        if request.uri().path() != "/jmap/eventsource" {
            return next.run(request).await;
        }
        if control.refuse.load(Ordering::SeqCst) {
            control.refused.fetch_add(1, Ordering::SeqCst);
            return axum::http::StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
        let mut cut = control.cut.subscribe();
        cut.borrow_and_update();
        let response = next.run(request).await;
        if !response.status().is_success() {
            return response;
        }
        control.opened.fetch_add(1, Ordering::SeqCst);
        let (parts, body) = response.into_parts();
        let body = body.into_data_stream().take_until(async move {
            let _ = cut.changed().await;
        });
        axum::response::Response::from_parts(parts, axum::body::Body::from_stream(body))
    }
}

/// Starts a.example's stack as mimid-server's `main.rs` wires it (as
/// mimid-agent-jmap's two_accounts test does), with accounts for `users`.
pub async fn server(dir: &Path, users: &[&'static str]) -> Server {
    let domain = Domain::try_from("a.example".to_owned()).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base_text = format!("http://{}", listener.local_addr().unwrap());
    let base = BaseUrl::try_from(base_text.clone()).unwrap();
    let store = Store::open(&dir.join("mimid.sqlite"), &domain)
        .await
        .unwrap();
    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    let peers = || PeerClient::new(&domain, BTreeMap::new()).unwrap();
    let key_packages = Arc::new(KeyPackages::new(
        store.clone(),
        domain.clone(),
        Arc::clone(&clock),
    ));
    let follower = Arc::new(
        Follower::new(domain.clone(), store.clone(), Arc::clone(&clock))
            .with_peers(peers())
            .with_key_packages(Arc::clone(&key_packages)),
    );
    let fanout = Fanout::new(
        store.clone(),
        domain.clone(),
        peers(),
        Arc::clone(&follower),
        Arc::clone(&clock),
    )
    .spawn();
    let hub = Arc::new(
        Hub::open(store.clone(), domain.clone(), Arc::clone(&clock))
            .await
            .unwrap()
            .with_fanout(fanout)
            .with_peers(peers())
            .with_local_key_material(Arc::clone(&key_packages) as _),
    );
    follower
        .set_relay(Relay::new(Arc::clone(&hub), peers()))
        .unwrap();
    let mut tokens = BTreeMap::new();
    for user in users {
        let account = store.create_account(&domain, user, 1).await.unwrap();
        let token = store.issue_token(&account, 2).await.unwrap();
        tokens.insert(*user, token.expose_secret());
    }
    // The live stream on too, for daemons with binding = "stream".
    let mut options = JmapOptions::default();
    options.live_stream = true;
    let jmap = jmap::router(
        &base,
        store,
        Arc::clone(&hub),
        Arc::clone(&follower),
        options,
    )
    .unwrap();
    let push = PushControl::default();
    let app = router(directory(&base), hub, follower).merge(jmap).layer(
        axum::middleware::from_fn_with_state(push.clone(), PushControl::layer),
    );
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    Server {
        base: base_text,
        tokens,
        push,
    }
}

/// The configuration of `user`'s daemon on `server`, its files under
/// `dir`, listening on 127.0.0.1:0 and syncing every 100 ms.
pub fn config(server: &Server, user: &'static str, dir: &Path, invites: &str) -> Config {
    let name = user.rsplit('/').next().unwrap();
    let token_file = dir.join(format!("{name}-server-token"));
    std::fs::write(&token_file, format!("{}\n", server.tokens[user])).unwrap();
    let state_dir = dir.join(format!("{name}-state"));
    Config::parse(&format!(
        r#"
        server_url = "{}"
        user_uri = "{user}"
        token_file = "{}"
        state_dir = "{}"
        listen = "127.0.0.1:0"
        sync_interval_ms = 100
        key_packages = 3
        invites = "{invites}"
        "#,
        server.base,
        token_file.display(),
        state_dir.display(),
    ))
    .unwrap()
}

/// A daemon serving in a task.
pub struct Running {
    pub addr: SocketAddr,
    /// The IRC front end's address, with `[irc]`.
    pub irc: Option<SocketAddr>,
    pub state_dir: PathBuf,
    stop: oneshot::Sender<()>,
    task: JoinHandle<std::io::Result<()>>,
}

impl Running {
    /// Starts a daemon for `config` and serves it until [`Running::stop`].
    pub async fn start(config: &Config) -> Self {
        let daemon = Daemon::start(config).await.unwrap();
        let addr = daemon.local_addr().expect("the daemon listens for HTTP");
        let irc = daemon.irc_addr();
        let (stop, stopped) = oneshot::channel::<()>();
        let task = tokio::spawn(daemon.serve(async move {
            let _ = stopped.await;
        }));
        Self {
            addr,
            irc,
            state_dir: config.state_dir.clone(),
            stop,
            task,
        }
    }

    /// The local bearer token, read from the state directory as a client
    /// would.
    pub fn token(&self) -> String {
        std::fs::read_to_string(self.state_dir.join(mimid_agent::token::TOKEN_FILE)).unwrap()
    }

    pub fn base(&self) -> String {
        format!("http://{}", self.addr)
    }

    /// A client of this daemon.
    pub async fn client(&self) -> Client {
        Client::connect(&self.base(), &self.token()).await
    }

    /// Stops the daemon and waits for it, failing if that takes longer
    /// than [`PATIENCE`].
    pub async fn stop(self) {
        self.stop.send(()).unwrap();
        tokio::time::timeout(PATIENCE, self.task)
            .await
            .expect("the daemon stops")
            .unwrap()
            .unwrap();
    }
}

/// A JMAP client of one daemon, over HTTP only.
pub struct Client {
    pub http: reqwest::Client,
    pub token: String,
    pub session: Value,
    pub account: String,
    api_url: String,
    event_source_url: String,
}

impl Client {
    /// Fetches the Session at `<base>/.well-known/jmap`.
    pub async fn connect(base: &str, token: &str) -> Self {
        let http = reqwest::Client::new();
        let response = http
            .get(format!("{base}/.well-known/jmap"))
            .bearer_auth(token)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        let session: Value = serde_json::from_slice(&response.bytes().await.unwrap()).unwrap();
        let account = session["primaryAccounts"]["urn:ietf:params:jmap:chat"]
            .as_str()
            .unwrap()
            .to_owned();
        Self {
            api_url: session["apiUrl"].as_str().unwrap().to_owned(),
            event_source_url: session["eventSourceUrl"].as_str().unwrap().to_owned(),
            http,
            token: token.to_owned(),
            session,
            account,
        }
    }

    /// POSTs `body` to the API with this client's token; the status and
    /// the JSON answer.
    pub async fn post(&self, body: &Value) -> (u16, Value) {
        let response = self
            .http
            .post(&self.api_url)
            .bearer_auth(&self.token)
            .header("content-type", "application/json")
            .body(body.to_string())
            .send()
            .await
            .unwrap();
        let status = response.status().as_u16();
        let bytes = response.bytes().await.unwrap();
        (status, serde_json::from_slice(&bytes).unwrap())
    }

    /// One method call; its response arguments. Panics on a method-level
    /// error.
    pub async fn call(&self, method: &str, mut args: Value) -> Value {
        args["accountId"] = json!(self.account);
        let (status, response) = self
            .post(&json!({
                "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:chat"],
                "methodCalls": [[method, args, "c0"]],
            }))
            .await;
        assert_eq!(status, 200, "{response}");
        let [name, args, _] = &response["methodResponses"][0].as_array().unwrap()[..] else {
            panic!("{response}");
        };
        assert_eq!(name, method, "{args}");
        args.clone()
    }

    /// The single created object of a `/set` create.
    pub async fn create(&self, type_name: &str, object: Value) -> Value {
        let answer = self
            .call(
                &format!("{type_name}/set"),
                json!({"create": {"k": object}}),
            )
            .await;
        assert!(
            answer["notCreated"]
                .as_object()
                .is_none_or(|m| m.is_empty()),
            "{answer}"
        );
        answer["created"]["k"].clone()
    }

    pub async fn get(&self, type_name: &str, ids: Option<Vec<&str>>) -> Vec<Value> {
        let answer = self
            .call(&format!("{type_name}/get"), json!({"ids": ids}))
            .await;
        answer["list"].as_array().unwrap().clone()
    }

    pub async fn messages(&self, chat: &str) -> Vec<Value> {
        let ids = self
            .call("Message/query", json!({"filter": {"chatId": chat}}))
            .await["ids"]
            .clone();
        let ids: Vec<String> = serde_json::from_value(ids).unwrap();
        self.get("Message", Some(ids.iter().map(String::as_str).collect()))
            .await
    }

    /// Opens the EventSource for every type, with no pings.
    pub async fn events(&self) -> Events {
        let url = self
            .event_source_url
            .replace("{types}", "*")
            .replace("{closeafter}", "no")
            .replace("{ping}", "0");
        let response = self
            .http
            .get(url)
            .bearer_auth(&self.token)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        assert!(
            response.headers()["content-type"]
                .to_str()
                .unwrap()
                .starts_with("text/event-stream")
        );
        Events {
            response,
            buffer: String::new(),
            account: self.account.clone(),
        }
    }
}

/// An open EventSource stream.
pub struct Events {
    response: reqwest::Response,
    buffer: String,
    account: String,
}

impl Events {
    /// Reads events until a `state` event whose StateChange names
    /// `type_name` for this account; returns its data. Panics after
    /// [`PATIENCE`].
    pub async fn until_changed(&mut self, type_name: &str) -> Value {
        tokio::time::timeout(PATIENCE, async {
            loop {
                while let Some(end) = self.buffer.find("\n\n") {
                    let block: String = self.buffer.drain(..end + 2).collect();
                    let mut event = None;
                    let mut data = String::new();
                    for line in block.lines() {
                        if let Some(name) = line.strip_prefix("event:") {
                            event = Some(name.trim().to_owned());
                        } else if let Some(text) = line.strip_prefix("data:") {
                            data.push_str(text.trim_start());
                        }
                    }
                    if event.as_deref() != Some("state") {
                        continue;
                    }
                    let change: Value = serde_json::from_str(&data).unwrap();
                    assert_eq!(change["@type"], json!("StateChange"), "{change}");
                    if change["changed"][&self.account].get(type_name).is_some() {
                        return change;
                    }
                }
                let chunk = self
                    .response
                    .chunk()
                    .await
                    .unwrap()
                    .expect("the stream stays open");
                self.buffer.push_str(std::str::from_utf8(&chunk).unwrap());
            }
        })
        .await
        .unwrap_or_else(|_| panic!("no StateChange naming {type_name}"))
    }

    /// Whether the stream ends within [`PATIENCE`].
    pub async fn ends(mut self) -> bool {
        tokio::time::timeout(PATIENCE, async {
            while let Ok(Some(_)) = self.response.chunk().await {}
        })
        .await
        .is_ok()
    }
}
