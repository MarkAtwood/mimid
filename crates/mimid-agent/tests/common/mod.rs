//! What the daemon tests share: an in-process mimid server (or two,
//! peers of each other), daemons started on it, and a JMAP client that
//! speaks only HTTP to a daemon.

// Each test binary uses part of this module.
#![allow(dead_code)]

pub mod irc;
pub mod webpush;

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

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
/// bob on the second provider, for the two-provider tests.
pub const BOB_B: &str = "mimi://b.example/u/bob";

/// Installs a `tracing` subscriber for this test process, once, so the
/// in-process daemon's own events and spans can be read while a test
/// runs (bead mimid-604m.1). Without one they went nowhere, and the only
/// timeline a stalled test could offer came from the wait helpers, which
/// say what they are waiting for but not what the daemon is doing.
///
/// `RUST_LOG` is the switch, and nothing is installed without it. A
/// daemon's tasks run on the runtime's worker threads, and cargo's
/// capture of a test's output is per thread, so anything written from a
/// worker escapes it: a subscriber on by default would print on passing
/// runs too, in the middle of other tests' output. With `RUST_LOG` set
/// that is what was asked for.
///
/// `try_init` and not `init`: `no_token_in_logs` and `cert_expiry`
/// install a capturing subscriber of their own before they start a
/// daemon, and keep it.
pub fn logs() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        if let Ok(filter) = tracing_subscriber::EnvFilter::try_from_default_env() {
            let _ = tracing_subscriber::fmt()
                .with_env_filter(filter)
                .with_ansi(false)
                .with_test_writer()
                .try_init();
        }
    });
}

/// Waits until `ready` holds of the store, woken by the change feed.
///
/// `Store::subscribe` is a broadcast of the sequence number published at
/// each save, which is the same signal the front ends follow, so a test
/// learns of a write when a front end would. Nothing here sleeps and
/// there is no deadline: a condition that never holds hangs the test,
/// and no timeout could tell that apart from a slow machine.
///
/// `ready` is re-checked before the first wait, so a condition that
/// already holds returns at once, and re-checked after each wake. It is
/// called between awaits and never across one, so the store's lock is
/// not held while this waits.
///
/// `what` names the condition in the line this prints while waiting, so
/// a test that hangs says which wait it is in.
pub async fn until_store(
    what: &str,
    store: &mimid_agent_store::Store,
    ready: impl Fn(&mimid_agent_store::Store) -> bool,
) {
    let mut changes = store.subscribe();
    let mut woken = 0u64;
    while !ready(store) {
        // A hang here is the honest outcome, so say what is being
        // waited for and how often the feed has moved. Without this a
        // stuck test is silent, which is the one thing a deadline was
        // buying.
        if woken.is_multiple_of(32) {
            eprintln!("waiting for {what}: the change feed has moved {woken} times");
        }
        woken += 1;
        match changes.recv().await {
            Ok(_) => {}
            // The store dropped its sender, so no further change is
            // coming and the condition will not start holding.
            Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                assert!(ready(store), "the store closed before {what}");
                return;
            }
            // Fell behind the log. The condition is about the store as
            // it is now, so look again rather than replay.
            Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
        }
    }
}

/// Waits until `probe` gives something, woken by `store`'s change feed.
///
/// The asynchronous counterpart of [`until_store`], for a condition a
/// test can only read by asking the daemon -- over HTTP as a client
/// would. The wake signal is still the daemon's own: `Store::subscribe`
/// publishes a sequence number at each save, so the probe runs again
/// whenever the daemon has written something. It runs once before the
/// first wait, so a condition that already holds returns at once.
///
/// There is no deadline. A condition that never holds hangs the test
/// and prints which one it was, where a guessed deadline could not tell
/// that apart from a loaded machine (bead mimid-gn1w).
pub async fn until_probe<T, F, Fut>(what: &str, store: &mimid_agent_store::Store, probe: F) -> T
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = Option<T>>,
{
    let mut changes = store.subscribe();
    let mut woken = 0u64;
    loop {
        if let Some(found) = probe().await {
            return found;
        }
        if woken.is_multiple_of(32) {
            eprintln!("waiting for {what}: the change feed has moved {woken} times");
        }
        woken += 1;
        match changes.recv().await {
            Ok(_) | Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
            Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                panic!("the store closed before {what}")
            }
        }
    }
}

/// A running mimid server: its domain, its base URL, a bearer token per
/// user, and the switch on its EventSource.
pub struct Server {
    pub domain: String,
    pub base: String,
    pub tokens: BTreeMap<&'static str, String>,
    pub push: PushControl,
    /// The provider's database, to issue more tokens.
    pub store: Store,
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
    /// Woken whenever a count moves, so [`PushControl::until`] awaits
    /// instead of sleeping between looks.
    moved: Arc<tokio::sync::Notify>,
}

impl Default for PushControl {
    fn default() -> Self {
        Self {
            refuse: Arc::default(),
            opened: Arc::default(),
            refused: Arc::default(),
            cut: Arc::new(watch::channel(0).0),
            moved: Arc::default(),
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

    /// Waits until `count` returns at least `n`.
    ///
    /// Woken by the counter moving, not by a clock: the request layer
    /// signals after every change, so this neither sleeps nor needs a
    /// deadline to guess at. A count that never reaches `n` hangs the
    /// test, which says the same thing a timeout would and does not
    /// depend on how loaded the machine is.
    pub async fn until(&self, what: &str, n: usize, count: impl Fn(&Self) -> usize) {
        let mut woken = 0u64;
        while count(self) < n {
            if woken.is_multiple_of(32) {
                eprintln!("waiting for {what}: {} of {n} so far", count(self));
            }
            woken += 1;
            // Registered before the re-check, so a change between the
            // two still wakes this.
            let moved = self.moved.notified();
            if count(self) >= n {
                break;
            }
            moved.await;
        }
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
            control.moved.notify_waiters();
            return axum::http::StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
        let mut cut = control.cut.subscribe();
        cut.borrow_and_update();
        let response = next.run(request).await;
        if !response.status().is_success() {
            return response;
        }
        control.opened.fetch_add(1, Ordering::SeqCst);
        control.moved.notify_waiters();
        let (parts, body) = response.into_parts();
        let body = body.into_data_stream().take_until(async move {
            let _ = cut.changed().await;
        });
        axum::response::Response::from_parts(parts, axum::body::Body::from_stream(body))
    }
}

/// Starts a.example's stack as mimid-server's `main.rs` wires it (as
/// mimid-agent-jmap's two_accounts test does), with accounts for `users`
/// and no peers.
pub async fn server(dir: &Path, users: &[&'static str]) -> Server {
    logs();
    let listener = bind().await;
    provider(listener, "a.example", dir, users, BTreeMap::new()).await
}

/// Starts two providers, a.example with accounts for `a_users` and
/// b.example with accounts for `b_users`, each in the other's peer map,
/// as mimid-server's two-provider tests wire them
/// (crates/mimid-server/tests/common/providers.rs): plain HTTP on
/// loopback, and no provider authentication layer, as there.
pub async fn two_providers(
    dir: &Path,
    a_users: &[&'static str],
    b_users: &[&'static str],
) -> (Server, Server) {
    let (a_listener, b_listener) = (bind().await, bind().await);
    let peer = |domain: &str, listener: &tokio::net::TcpListener| {
        BTreeMap::from([(
            Domain::try_from(domain.to_owned()).unwrap(),
            BaseUrl::try_from(format!("http://{}", listener.local_addr().unwrap())).unwrap(),
        )])
    };
    let (a_peers, b_peers) = (
        peer("b.example", &b_listener),
        peer("a.example", &a_listener),
    );
    let a = provider(a_listener, "a.example", dir, a_users, a_peers).await;
    let b = provider(b_listener, "b.example", dir, b_users, b_peers).await;
    (a, b)
}

async fn bind() -> tokio::net::TcpListener {
    tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap()
}

/// Starts `domain`'s stack on `listener`, as mimid-server's `main.rs`
/// wires it, with `peer_map` as its peer map and accounts for `users`, each
/// of which must be on `domain`. Its database is `<domain>.sqlite` in
/// `dir`.
async fn provider(
    listener: tokio::net::TcpListener,
    domain: &str,
    dir: &Path,
    users: &[&'static str],
    peer_map: BTreeMap<Domain, BaseUrl>,
) -> Server {
    let domain = Domain::try_from(domain.to_owned()).unwrap();
    let base_text = format!("http://{}", listener.local_addr().unwrap());
    let base = BaseUrl::try_from(base_text.clone()).unwrap();
    let store = Store::open(&dir.join(format!("{domain}.sqlite")), &domain)
        .await
        .unwrap();
    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    let peers = || PeerClient::new(&domain, peer_map.clone()).unwrap();
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
            .with_base_url(base.clone())
            .with_local_key_material(Arc::clone(&key_packages) as _),
    );
    follower
        .set_relay(Relay::new(Arc::clone(&hub), peers()))
        .unwrap();
    let mut tokens = BTreeMap::new();
    for user in users {
        assert!(
            user.starts_with(&format!("mimi://{domain}/")),
            "{user} is on {domain}"
        );
        let account = store.create_account(&domain, user, 1).await.unwrap();
        let token = store.issue_token(&account, 2).await.unwrap();
        tokens.insert(*user, token.expose_secret());
    }
    // The live stream on too, for daemons with binding = "stream".
    let mut options = JmapOptions::default();
    options.live_stream = true;
    let jmap = jmap::router(
        &base,
        store.clone(),
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
        domain: domain.to_string(),
        base: base_text,
        tokens,
        push,
        store,
    }
}

/// The configuration of `user`'s daemon on `server`, its files under
/// `dir`, listening on 127.0.0.1:0 and syncing every 100 ms.
pub fn config(server: &Server, user: &'static str, dir: &Path, invites: &str) -> Config {
    Config::parse(&config_toml(server, user, dir, invites, "")).unwrap()
}

/// The TOML [`config`] parses, with `extra` after it: every setting
/// written out, so a test that needs the configuration on disk can have
/// the file say exactly what the daemon runs.
pub fn config_toml(
    server: &Server,
    user: &'static str,
    dir: &Path,
    invites: &str,
    extra: &str,
) -> String {
    let name = user.rsplit('/').next().unwrap();
    let token_file = dir.join(format!("{name}-server-token"));
    std::fs::write(&token_file, format!("{}\n", server.tokens[user])).unwrap();
    let state_dir = dir.join(format!("{name}-state"));
    format!(
        r#"
        server_url = "{}"
        user_uri = "{user}"
        token_file = "{}"
        state_dir = "{}"
        listen = "127.0.0.1:0"
        sync_interval_ms = 100
        key_packages = 3
        invites = "{invites}"
        {extra}
        "#,
        server.base,
        token_file.display(),
        state_dir.display(),
    )
}

/// [`config_toml`] written to a file under `dir` and read back from
/// there, with the path: the configuration a daemon started from this
/// file runs, and the file `REHASH` reads again.
///
/// Every table the daemon runs with belongs in `extra` rather than in a
/// field set after parsing, as the other tests here do: the reload
/// compares the file with the settings in use, so a configuration
/// changed in code after it was loaded would have the first `REHASH`
/// report that change as needing a restart -- correctly
/// (docs/design/agent-frontends.md §7.38).
pub fn config_at(
    server: &Server,
    user: &'static str,
    dir: &Path,
    invites: &str,
    extra: &str,
) -> (Config, PathBuf) {
    let name = user.rsplit('/').next().unwrap();
    let path = dir.join(format!("{name}.toml"));
    std::fs::write(&path, config_toml(server, user, dir, invites, extra)).unwrap();
    let config = Config::load(&path).unwrap();
    (config, path)
}

/// The test CA and server certificate (tests/fixtures/tls, made by its
/// make.sh): the server's names are localhost, 127.0.0.1 and
/// host.tailnet.ts.net.
pub fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/tls")
        .join(name)
}

/// A TLS connection to `addr` as `name`, trusting only the test CA.
pub async fn tls_connect(
    addr: SocketAddr,
    name: &str,
) -> std::io::Result<tokio_rustls::client::TlsStream<tokio::net::TcpStream>> {
    use rustls::pki_types::pem::PemObject;
    let mut roots = rustls::RootCertStore::empty();
    for cert in rustls::pki_types::CertificateDer::pem_file_iter(fixture("ca.pem")).unwrap() {
        roots.add(cert.unwrap()).unwrap();
    }
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let stream = tokio::net::TcpStream::connect(addr).await?;
    connector
        .connect(
            rustls::pki_types::ServerName::try_from(name.to_owned()).unwrap(),
            stream,
        )
        .await
}

/// A daemon serving in a task.
pub struct Running {
    pub addr: SocketAddr,
    /// The IRC front end's address, with `[irc]`.
    pub irc: Option<SocketAddr>,
    /// The IRC front end's TLS address, with `[irc] listen_tls`.
    pub irc_tls: Option<SocketAddr>,
    /// The HTTPS endpoint's address, with `[jmap] listen_tls`.
    pub https: Option<SocketAddr>,
    /// The CA bootstrap listener's address, with `[tls.local-ca]
    /// bootstrap`.
    pub ca_bootstrap: Option<SocketAddr>,
    pub state_dir: PathBuf,
    /// The daemon's store.
    pub store: Arc<mimid_agent_store::Store>,
    /// The daemon's push subscriptions, with a front end that pushes.
    pub pushes: Option<Arc<mimid_agent_store::push::PushSubscriptions>>,
    stop: oneshot::Sender<()>,
    task: JoinHandle<std::io::Result<()>>,
}

impl Running {
    /// Starts a daemon for `config` and serves it until [`Running::stop`].
    pub async fn start(config: &Config) -> Self {
        logs();
        let daemon = Daemon::start(config).await.unwrap();
        let addr = daemon.local_addr().expect("the daemon listens for HTTP");
        let irc = daemon.irc_addr();
        let irc_tls = daemon.irc_tls_addr();
        let https = daemon.https_addr();
        let ca_bootstrap = daemon.ca_bootstrap_addr();
        let store = Arc::clone(daemon.store());
        let pushes = daemon.push_subscriptions().map(Arc::clone);
        let (stop, stopped) = oneshot::channel::<()>();
        let task = tokio::spawn(daemon.serve(async move {
            let _ = stopped.await;
        }));
        Self {
            addr,
            irc,
            irc_tls,
            https,
            ca_bootstrap,
            state_dir: config.state_dir.clone(),
            store,
            pushes,
            stop,
            task,
        }
    }

    /// The daemon's credential table through a connection of its own, as
    /// the `app-password` CLI opens it.
    pub fn store_credentials(&self) -> mimid_agent_store::credentials::Credentials {
        mimid_agent_store::credentials::Credentials::open(
            &self.state_dir.join(mimid_agent::DATABASE_FILE),
        )
        .unwrap()
    }

    /// The local bearer token, read from the state directory as a client
    /// would.
    pub fn token(&self) -> String {
        std::fs::read_to_string(self.state_dir.join(mimid_agent::token::TOKEN_FILE)).unwrap()
    }

    pub fn base(&self) -> String {
        format!("http://{}", self.addr)
    }

    /// The HTTPS endpoint's base URL under the name the test certificate
    /// covers; panics without `[jmap] listen_tls`.
    pub fn https_base(&self) -> String {
        format!(
            "https://localhost:{}",
            self.https.expect("the daemon listens for HTTPS").port()
        )
    }

    /// A client of this daemon.
    pub async fn client(&self) -> Client {
        Client::connect(&self.base(), &self.token()).await
    }

    /// Stops the daemon and waits for it.
    ///
    /// The task finishing is the event; a daemon that will not stop
    /// hangs here, which is what it is.
    pub async fn stop(self) {
        self.stop.send(()).unwrap();
        eprintln!("waiting for the daemon to stop");
        self.task.await.unwrap().unwrap();
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
    pub async fn call(&self, method: &str, args: Value) -> Value {
        self.call_using(&[], method, args).await
    }

    /// [`Client::call`] with `capabilities` named in `using` as well, for
    /// a method outside core and chat.
    pub async fn call_using(&self, capabilities: &[&str], method: &str, mut args: Value) -> Value {
        let mut using = vec!["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:chat"];
        using.extend_from_slice(capabilities);
        args["accountId"] = json!(self.account);
        let (status, response) = self
            .post(&json!({
                "using": using,
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
        self.events_pinged(0).await
    }

    /// Opens the EventSource for every type, asking for a `ping` event
    /// every `ping` seconds (the agent clamps the interval, RFC 8620
    /// §7.3); `0` asks for none.
    pub async fn events_pinged(&self, ping: u64) -> Events {
        let url = self
            .event_source_url
            .replace("{types}", "*")
            .replace("{closeafter}", "no")
            .replace("{ping}", &ping.to_string());
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
    /// Waits for the next `StateChange` naming `type_name` for this
    /// account, and returns it.
    ///
    /// Woken by the stream: `chunk` is an await on the response body, so
    /// the reactor wakes this when bytes arrive. A stream that closes
    /// fails below with "the stream stays open"; a stream that stays
    /// open and never names `type_name` hangs the test, which a
    /// guessed deadline could not tell apart from a loaded machine --
    /// that guess is what bead mimid-gn1w kept failing on.
    pub async fn until_changed(&mut self, type_name: &str) -> Value {
        eprintln!("waiting for a StateChange naming {type_name}");
        loop {
            let (name, data) = self.next_event().await;
            if name != "state" {
                continue;
            }
            assert_eq!(data["@type"], json!("StateChange"), "{data}");
            if data["changed"][&self.account].get(type_name).is_some() {
                return data;
            }
        }
    }

    /// Waits for the next `ping` event and returns the interval it
    /// reports in seconds (RFC 8620 §7.3).
    pub async fn until_ping(&mut self) -> u64 {
        eprintln!("waiting for a ping event");
        loop {
            let (name, data) = self.next_event().await;
            if name == "ping" {
                return data["interval"].as_u64().unwrap();
            }
        }
    }

    /// The next event: its name, and its data parsed.
    async fn next_event(&mut self) -> (String, Value) {
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
                if let Some(name) = event {
                    return (name, serde_json::from_str(&data).unwrap());
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
    }

    /// Waits for the stream to end.
    ///
    /// The end of the stream is the event, so returning is the
    /// assertion.
    pub async fn ends(mut self) {
        eprintln!("waiting for the event stream to end");
        while let Ok(Some(_)) = self.response.chunk().await {}
    }
}

/// base64 of `bytes`.
pub fn b64(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// A SCRAM-SHA-256 client's proof and expected server signature, from RFC
/// 5802 §3's formulas.
pub fn scram_client(
    password: &str,
    client_first_bare: &str,
    server_first: &str,
    without_proof: &str,
) -> (String, String) {
    use base64::Engine;
    use hmac::{Hmac, KeyInit, Mac};
    use sha2::{Digest, Sha256};
    let mac = |key: &[u8], data: &[u8]| -> Vec<u8> {
        let mut m = <Hmac<Sha256> as KeyInit>::new_from_slice(key).unwrap();
        m.update(data);
        m.finalize().into_bytes().to_vec()
    };
    let mut fields = server_first.split(',');
    let _nonce = fields.next().unwrap();
    let salt = base64::engine::general_purpose::STANDARD
        .decode(fields.next().unwrap().strip_prefix("s=").unwrap())
        .unwrap();
    let iterations: u32 = fields
        .next()
        .unwrap()
        .strip_prefix("i=")
        .unwrap()
        .parse()
        .unwrap();
    // Hi() of RFC 5802 §2.2.
    let mut u = mac(
        password.as_bytes(),
        &[salt.as_slice(), &1u32.to_be_bytes()].concat(),
    );
    let mut salted = u.clone();
    for _ in 1..iterations {
        u = mac(password.as_bytes(), &u);
        for (s, x) in salted.iter_mut().zip(&u) {
            *s ^= x;
        }
    }
    let auth = format!("{client_first_bare},{server_first},{without_proof}");
    let client_key = mac(&salted, b"Client Key");
    let signature = mac(&Sha256::digest(&client_key), auth.as_bytes());
    let proof: Vec<u8> = client_key
        .iter()
        .zip(&signature)
        .map(|(a, b)| a ^ b)
        .collect();
    let server_key = mac(&salted, b"Server Key");
    (
        b64(&proof),
        format!("v={}", b64(&mac(&server_key, auth.as_bytes()))),
    )
}
