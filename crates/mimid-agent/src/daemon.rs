//! [`Daemon`]: the agent, its plaintext store, its front ends over the
//! store (JMAP Chat on the HTTP endpoint unless `[jmap] enabled = false`,
//! IRC with `[irc]`), the sync loop, and the expiry loop that deletes
//! messages at their time (docs/design/agent-frontends.md §7.20 to §7.23).
//! The loops are mimid-agent-store's [`Runner`], which embedders run too;
//! the daemon adds its did:webvh log watch before each sync.

use std::future::Future;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use mimid_agent_core::push::PushSource;
use mimid_agent_core::{Agent, AgentConfig, AgentError};
use mimid_agent_irc::{IrcFrontEnd, IrcOptions};
use mimid_agent_jmap::{AgentChat, BlobStore, Options};
use mimid_agent_store::Store;
use mimid_agent_store::credentials::Credentials;
use mimid_agent_store::push::PushSubscriptions;
use mimid_agent_store::runner::{
    BeforeSync, Runner, RunnerHooks, RunnerOptions, top_up_key_packages,
};
use tokio::net::TcpListener;
use tokio::sync::{Semaphore, broadcast, watch};

use crate::config::{Config, ConfigError};
use crate::didwebvh::LogWatch;
use crate::http::{
    self, CHANGE_BUFFER, Endpoint, Jmap, MAX_CONCURRENT_REQUESTS, MAX_CONCURRENT_UPLOAD, stopped,
};
use crate::token::{LocalToken, TokenError};
use mimid_agent_store::links::AttachmentLinks;

/// A started daemon: the agent is open, its KeyPackages published and the
/// listeners bound. [`Daemon::serve`] runs it.
pub struct Daemon {
    /// The HTTP endpoint, unless `listen` is left out.
    http: Option<Http>,
    /// The HTTPS endpoint, with `[jmap] listen_tls`: the same routes over
    /// TLS on any address, with its own Session (bead mimid-e13m.6).
    https: Option<Https>,
    /// The IRC front end, with `[irc]`.
    irc: Option<IrcFrontEnd>,
    /// The TLS certificate source, with `[tls]`.
    tls: Option<Arc<crate::tls::Tls>>,
    /// Whether tailnet identity is on (`[tailnet] identity`), for the
    /// start event; the rules themselves went to the front end.
    tailnet: bool,
    /// The plain-HTTP listener that serves the CA setup page and nothing
    /// else, with `[tls.local-ca] bootstrap` (decision mimid-1wgh.127).
    ca_bootstrap: Option<(TcpListener, SocketAddr, Arc<http::CaPage>)>,
    /// The plaintext store the front ends share; its sync is the loop's.
    store: Arc<Store>,
    /// The credentials every front end checks logins against.
    credentials: Arc<Credentials>,
    stop: watch::Sender<bool>,
    sync_interval: Duration,
    /// The server's EventSource, which wakes the sync loop; `None` if its
    /// Session has none.
    push: Option<PushSource>,
    /// The live stream's wake-up, with `binding = "stream"`: it wakes the
    /// sync loop as the EventSource does on JMAP.
    stream_wake: Option<Arc<tokio::sync::Notify>>,
    key_packages: u32,
    user_uri: String,
    server_url: String,
    /// The watch of `[did_webvh].log_file`, when set.
    log_watch: Option<LogWatch>,
    /// The Web Push subscriptions the pushing front ends share, with
    /// `[jmap] webpush` or `[irc] webpush`.
    pushes: Option<Arc<PushSubscriptions>>,
}

/// The HTTP endpoint: its listener and what its routes share.
struct Http {
    listener: TcpListener,
    local_addr: SocketAddr,
    endpoint: Arc<Endpoint>,
}

/// The HTTPS endpoint: the bound socket, the certificate every TLS
/// listener shares, and the routes' state. Its handshakes start in
/// [`Daemon::serve`], so a bind failure is still a start failure.
struct Https {
    listener: TcpListener,
    local_addr: SocketAddr,
    config: Arc<rustls::ServerConfig>,
    endpoint: Arc<Endpoint>,
}

impl std::fmt::Debug for Daemon {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Daemon")
            .field("local_addr", &self.local_addr())
            .field("irc_addr", &self.irc_addr())
            .field("user_uri", &self.user_uri)
            .finish_non_exhaustive()
    }
}

/// How often the daemon reads the credential table again, so that a
/// change the `app-password` CLI made is seen and the sessions of a
/// revoked credential close (docs/design/frontend-auth.md §3.6).
/// INVENTED VALUE, NOT FROM SPEC.
pub const CREDENTIAL_RECHECK: Duration = Duration::from_secs(2);

/// The blob store's directory in the state directory: attachments in
/// plaintext.
pub const BLOBS_DIR: &str = "blobs";

/// Why [`Daemon::start`] failed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum StartError {
    /// The configuration does not pass [`Config::parse`]'s checks (it was
    /// built or changed in code).
    #[error("invalid configuration")]
    Config(#[from] ConfigError),
    /// The server token file could not be read, or is empty.
    #[error("cannot read the server token from {}", path.display())]
    ServerToken {
        /// The configured `token_file`.
        path: PathBuf,
        /// The I/O error, if any (none: the file is empty).
        #[source]
        source: Option<std::io::Error>,
    },
    /// The local token could not be made or read.
    #[error("the local token")]
    LocalToken(#[from] TokenError),
    /// The credential table (`mimid.sqlite`) could not be opened.
    #[error("opening the credential table")]
    Credentials(#[from] mimid_agent_store::credentials::CredentialError),
    /// The agent could not be opened (state directory, server Session).
    #[error("opening the agent")]
    Agent(#[from] AgentError),
    /// The listen address could not be bound.
    #[error("binding {addr}")]
    Bind {
        /// The configured `listen` address.
        addr: SocketAddr,
        /// The I/O error.
        #[source]
        source: std::io::Error,
    },
    /// The TLS certificate could not be had (`[tls]`).
    #[error("TLS")]
    Tls(#[from] crate::tls::TlsError),
    /// The IRC front end could not start (`[irc].listen`).
    #[error("starting the IRC front end")]
    Irc(#[from] mimid_agent_irc::IrcError),
    /// The IRC front end's Web Push could not start (`[irc] webpush`).
    #[error("starting the IRC front end's Web Push")]
    WebPush(#[from] mimid_agent_irc::WebPushError),
    /// The push tables (`mimid.sqlite`) could not be opened.
    #[error("opening the push subscriptions")]
    Push(#[from] mimid_agent_store::push::PushError),
    /// The Session does not build (a crate-jmap type changed).
    #[error("building the Session")]
    Session(#[from] serde_json::Error),
    /// The plaintext store (its tables in `<state_dir>/mimid.sqlite`) could
    /// not be read.
    #[error("opening the plaintext store")]
    Records(#[from] mimid_agent_store::FileError),
    /// The plaintext store does not make this account's JMAP objects.
    #[error("opening the plaintext store")]
    Store(#[from] mimid_agent_jmap::PersistError),
    /// The blob store (`<state_dir>/blobs`) could not be opened.
    #[error("opening the blob store")]
    Blobs(#[from] mimid_agent_jmap::BlobError),
}

impl Daemon {
    /// Opens the agent for `config`'s user against its server, tops its
    /// KeyPackages up to `config.key_packages`, makes or reads the local
    /// token, binds the HTTP listener (if `listen` is set), builds the
    /// store and the front ends over it: JMAP unless `[jmap] enabled =
    /// false`, and IRC on `[irc].listen` with `[irc]`, its clients' `PASS`
    /// checked against the local token. Failing to publish KeyPackages is
    /// logged, not fatal: the sync loop tries again.
    ///
    /// # Errors
    ///
    /// See [`StartError`].
    pub async fn start(config: &Config) -> Result<Self, StartError> {
        config.check()?;
        let server_token = read_server_token(&config.token_file)?;
        let token = LocalToken::load_or_create(&config.state_dir)?;
        let mut agent = Agent::open(AgentConfig {
            server_url: config.server_url.clone(),
            binding: config.binding.into(),
            token: server_token,
            user_uri: config.user_uri.clone(),
            state_dir: config.state_dir.clone(),
            full_tree_hubs: config.full_tree_hubs.clone(),
            did_webvh: config
                .did_webvh
                .to_agent()
                .map_err(|e| AgentError::Invalid(format!("[did_webvh]: {e}")))?,
        })
        .await?;
        top_up_key_packages(&mut agent, config.key_packages).await;
        // docs/design/frontend-auth.md §3: the one credential check of
        // every front end; the agent token is one credential (§3.4).
        let credentials = Arc::new(Credentials::open(
            &config.state_dir.join(mimid_agent_core::DATABASE_FILE),
        )?);
        credentials.set_agent_token(token.as_bytes())?;
        // docs/design/frontend-auth.md §5; decision A6 is checked here
        // for the tailscale source.
        let tls = match &config.tls {
            Some(setting) => Some(Arc::new(
                crate::tls::Tls::start(setting, &config.state_dir).await?,
            )),
            None => None,
        };
        let push = agent.push_source()?;
        let stream_wake = agent.stream_wake();
        let listener = match config.listen {
            Some(addr) => {
                let bind = |source| StartError::Bind { addr, source };
                let listener = TcpListener::bind(addr).await.map_err(bind)?;
                let local_addr = listener.local_addr().map_err(bind)?;
                Some((listener, local_addr))
            }
            None => None,
        };
        // Config::check refuses [jmap] listen_tls without [tls] and with
        // JMAP off, so both are present here when it is.
        let tls_listener = match config.jmap.listen_tls {
            Some(addr) => {
                crate::tls::warn_if_public("jmap", addr);
                let bind = |source| StartError::Bind { addr, source };
                let listener = TcpListener::bind(addr).await.map_err(bind)?;
                let local_addr = listener.local_addr().map_err(bind)?;
                Some((listener, local_addr))
            }
            None => None,
        };
        // The store first, the front ends over it (docs/design/
        // agent-frontends.md §3 step 6): the decrypted records, kept across
        // restarts (bead mimid-1wgh.13.12), with the attachments (bead
        // mimid-1wgh.14).
        let blobs =
            BlobStore::open(config.state_dir.join(BLOBS_DIR))?.with_quota(config.blob_quota());
        let store = Store::new(agent, config.invites.into()).with_blobs(blobs);
        // The records in the agent's own database, so a sync's records and
        // its acknowledgement commit together (bead mimid-1vul.10).
        store.open_database()?;
        let store = Arc::new(store);
        // One subscription store for every front end that pushes: the
        // rows are keyed by front end and the VAPID key is the agent's,
        // so IRC's soju.im/webpush and JMAP's chatPush share it (bead
        // mimid-1wgh.99).
        let pushes = if config.jmap.webpush || config.irc.as_ref().is_some_and(|irc| irc.webpush) {
            Some(Arc::new(PushSubscriptions::open(
                &config.state_dir.join(mimid_agent_core::DATABASE_FILE),
            )?))
        } else {
            None
        };
        let (stop, stop_receiver) = watch::channel(false);
        // One AgentChat over the store for both endpoints: the plain one
        // and, with `[jmap] listen_tls`, the TLS one. Each gets its own
        // Session and dispatcher, because their URLs differ, but the
        // account, its states and its push store are one (bead
        // mimid-e13m.6).
        let account = http::account_id(&config.user_uri);
        let chat = if config.jmap.enabled && listener.is_some() {
            // `[jmap] vtc`: off by default, because this capability hands
            // out key material (decision mimid-1wgh.119). Off, the VTC
            // methods are not registered at all and the Session does not
            // name the capability.
            let mut options = Options::default();
            if config.jmap.vtc {
                options.vtc = mimid_agent_jmap::VtcOptions::enabled();
            }
            let mut chat = AgentChat::over(Arc::clone(&store), account.clone(), options)?;
            // One subscription store for every front end that pushes: the
            // rows are keyed by front end, and the VAPID key is the
            // agent's (bead mimid-1wgh.99).
            if let Some(pushes) = &pushes {
                chat = chat.enable_push(Arc::clone(pushes));
            }
            Some(Arc::new(chat))
        } else {
            None
        };
        // What the endpoints share: one change channel, so the states are
        // recomputed once for both, and the request and upload limits are
        // the agent's rather than each listener's.
        let (changes, _) = broadcast::channel(CHANGE_BUFFER);
        let in_flight = Arc::new(Semaphore::new(MAX_CONCURRENT_REQUESTS));
        let uploads = Arc::new(Semaphore::new(MAX_CONCURRENT_UPLOAD));
        // docs/design/frontend-auth.md §6.6: with `source = "local-ca"`
        // the endpoint serves the CA setup page, built once here.
        let ca_page = match tls.as_ref().and_then(|tls| tls.local_ca()) {
            Some(ca) => Some(Arc::new(http::CaPage::new(ca, &config.tls_names())?)),
            None => None,
        };
        let endpoint_for = |base: &str, port: u16, names: Vec<String>| {
            let jmap = match &chat {
                Some(chat) => {
                    let (session, session_state) =
                        http::session(base, &config.user_uri, &account, Some(chat.vtc_options()))?;
                    Some(Jmap {
                        dispatcher: http::dispatcher(chat, &credentials, &account),
                        chat: Arc::clone(chat),
                        session,
                        session_state,
                        capabilities: http::allowed_capabilities(chat.vtc_options().enabled),
                    })
                }
                None => None,
            };
            Ok::<_, StartError>(Arc::new(Endpoint {
                credentials: Arc::clone(&credentials),
                store: Arc::clone(&store),
                jmap,
                in_flight: Arc::clone(&in_flight),
                uploads: Arc::clone(&uploads),
                changes: changes.clone(),
                // The store's own: its write methods wake the loop too.
                sync_now: Arc::clone(store.sync_wanted()),
                stop: stop_receiver.clone(),
                allowed_origins: config.allowed_origins.clone(),
                local_ca: ca_page.clone(),
                port,
                names,
            }))
        };
        let http = match &listener {
            Some((_, local_addr)) => {
                // docs/design/agent-frontends.md §7.30: links any front
                // end can hand its client. A client off this machine
                // reaches only the TLS listener, so with one the links are
                // its https URLs; a loopback link would be useless to the
                // remote clients that TLS is there for.
                let link_base = match &tls_listener {
                    Some((_, tls_addr)) => https_endpoint(config.tls.as_ref(), *tls_addr).0,
                    None => format!("http://{local_addr}"),
                };
                store.set_attachment_links(AttachmentLinks::new(token.link_key(), link_base));
                let endpoint = endpoint_for(
                    &format!("http://{local_addr}"),
                    local_addr.port(),
                    Vec::new(),
                )?;
                Some(endpoint)
            }
            // Config::check refuses JMAP on without listen.
            None => None,
        };
        let https = match &tls_listener {
            Some((_, local_addr)) => {
                let (base, names) = https_endpoint(config.tls.as_ref(), *local_addr);
                Some(endpoint_for(&base, local_addr.port(), names)?)
            }
            None => None,
        };
        let http = match (listener, http) {
            (Some((listener, local_addr)), Some(endpoint)) => Some(Http {
                listener,
                local_addr,
                endpoint,
            }),
            _ => None,
        };
        // Config::check refuses [jmap] listen_tls without [tls], so the
        // certificate is here whenever the listener is.
        let https = match (tls_listener, https, &tls) {
            (Some((listener, local_addr)), Some(endpoint), Some(tls)) => Some(Https {
                listener,
                local_addr,
                config: tls.server_config(),
                endpoint,
            }),
            _ => None,
        };
        // docs/design/frontend-auth.md §4.6, decision A7: off unless
        // `[tailnet] identity = true`. Reading `status` now means a
        // tailscaled that cannot be reached is a start failure, rather
        // than the agent quietly serving the password rules while the
        // operator believes a node needs none.
        let tailnet = if config.tailnet.identity {
            Some(Arc::new(
                crate::tailnet::Tailnet::start(&config.tailnet, &config.state_dir).await?,
            ))
        } else {
            None
        };
        // docs/design/frontend-auth.md §6.6, decision mimid-1wgh.127: a
        // device that does not trust the CA yet cannot fetch it over
        // TLS, so this one listener serves it in the clear — and serves
        // nothing else. Off unless `[tls.local-ca] bootstrap` names an
        // address.
        let ca_bootstrap = match (
            &ca_page,
            config
                .tls
                .as_ref()
                .and_then(|tls| tls.local_ca.as_ref())
                .and_then(|local| local.bootstrap),
        ) {
            (Some(page), Some(addr)) => {
                crate::tls::warn_if_public("ca-bootstrap", addr);
                let bind = |source| StartError::Bind { addr, source };
                let listener = TcpListener::bind(addr).await.map_err(bind)?;
                let local_addr = listener.local_addr().map_err(bind)?;
                Some((listener, local_addr, Arc::clone(page)))
            }
            _ => None,
        };
        let irc = match &config.irc {
            Some(setting) => {
                // docs/design/frontend-auth.md §4.1: the IRC client's PASS
                // is any credential; the one check at the IRC boundary
                // (AGENTS.md).
                let mut options = IrcOptions::new(setting.listen, setting.server_name.clone());
                options.listen_tls = setting.listen_tls;
                if let Some(addr) = setting.listen_tls {
                    crate::tls::warn_if_public("irc", addr);
                }
                let irc = IrcFrontEnd::bind(
                    Arc::clone(&store),
                    options,
                    Arc::clone(&credentials),
                    tls.as_ref().map(|t| t.server_config()),
                )
                .await?;
                // §4.6: the rules are the daemon's (the `tailnet`
                // module); the front end only asks who a peer is.
                if let Some(tailnet) = &tailnet {
                    irc.enable_peer_identity(
                        Arc::clone(tailnet) as Arc<dyn mimid_agent_irc::PeerIdentity>
                    );
                }
                // §7.38: REHASH reads the file this configuration came
                // from. A configuration built in code has no file, so an
                // embedder and every test that builds one get the
                // REHASH that says there is nothing to read; which
                // settings can be taken and which cannot is the
                // `reload` module's, not the front end's.
                if let Some(path) = config.loaded_from() {
                    irc.enable_rehash(Arc::new(crate::reload::Reloader::new(
                        path.to_owned(),
                        config,
                        Arc::clone(&store),
                    )) as Arc<dyn mimid_agent_irc::Reload>);
                }
                // client-survey.md §10 S4: push on by default, with its own
                // switch; the subscriptions in the agent's database.
                if setting.webpush
                    && let Some(subscriptions) = &pushes
                {
                    irc.enable_web_push(Arc::clone(subscriptions))?;
                }
                Some(irc)
            }
            None => None,
        };
        Ok(Self {
            http,
            https,
            irc,
            tailnet: tailnet.is_some(),
            ca_bootstrap,
            tls,
            store,
            credentials,
            stop,
            sync_interval: config.sync_interval(),
            push,
            stream_wake,
            key_packages: config.key_packages,
            user_uri: config.user_uri.clone(),
            server_url: config.server_url.clone(),
            // Bead mimid-1wgh.4.81.28: Agent::open has read the file; a
            // change from now on is taken while running.
            log_watch: config
                .did_webvh
                .log_file
                .clone()
                .map(|log| LogWatch::new(log, config.did_webvh.witness_file.clone())),
            pushes,
        })
    }

    /// The address the HTTP endpoint listens on (the configured one, with
    /// the port filled in if it was 0); `None` without `listen`.
    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.http.as_ref().map(|http| http.local_addr)
    }

    /// The address the HTTPS endpoint listens on; `None` without
    /// `[jmap] listen_tls`.
    pub fn https_addr(&self) -> Option<SocketAddr> {
        self.https.as_ref().map(|https| https.local_addr)
    }

    /// The address the CA bootstrap listener answers on; `None` without
    /// `[tls.local-ca] bootstrap`.
    pub fn ca_bootstrap_addr(&self) -> Option<SocketAddr> {
        self.ca_bootstrap.as_ref().map(|(_, addr, _)| *addr)
    }

    /// The address the IRC front end listens on; `None` without `[irc]`.
    pub fn irc_addr(&self) -> Option<SocketAddr> {
        self.irc.as_ref().map(IrcFrontEnd::local_addr)
    }

    /// The address of the IRC front end's TLS listener; `None` without
    /// `[irc] listen_tls`.
    pub fn irc_tls_addr(&self) -> Option<SocketAddr> {
        self.irc.as_ref().and_then(IrcFrontEnd::tls_addr)
    }

    /// The plaintext store the front ends share. Its sync is the daemon's
    /// sync loop's: nothing else may call [`Store::sync`] while the daemon
    /// serves.
    pub fn store(&self) -> &Arc<Store> {
        &self.store
    }

    /// The Web Push subscriptions its pushing front ends share; `None`
    /// with neither `[jmap] webpush` nor `[irc] webpush`.
    ///
    /// The handle, so a caller can follow
    /// [`PushSubscriptions::changed`]: a subscription a push service
    /// says is gone is dropped through this one.
    #[must_use]
    pub fn push_subscriptions(&self) -> Option<&Arc<PushSubscriptions>> {
        self.pushes.as_ref()
    }

    /// Serves the front ends and runs the sync loop until `shutdown`
    /// resolves, then stops accepting connections, ends the open
    /// EventSource streams and IRC connections (each IRC client gets
    /// `ERROR`), lets requests in flight and a running sync finish, and
    /// returns. With JMAP on, each save the store publishes tells the
    /// EventSource streams to look. The sync loop runs at once, whenever
    /// the server's EventSource names a type it reads (see the `push`
    /// module), whenever a front end writes, and every `sync_interval_ms`
    /// as a fallback.
    ///
    /// When this returns, the state directory is free: the lock is
    /// released here rather than when the last clone of it drops, so a
    /// caller can open the same directory again at once (bead
    /// mimid-036n, [`mimid_agent_core::StateLock::release`]).
    ///
    /// # Errors
    ///
    /// The HTTP listener's I/O error.
    pub async fn serve(
        self,
        shutdown: impl Future<Output = ()> + Send + 'static,
    ) -> std::io::Result<()> {
        let jmap = self
            .http
            .as_ref()
            .is_some_and(|http| http.endpoint.jmap.is_some());
        tracing::info!(
            name: "agent_listening",
            listen = %self.local_addr().map_or_else(|| "none".to_owned(), |a| a.to_string()),
            listen_tls = %self.https_addr().map_or_else(|| "none".to_owned(), |a| a.to_string()),
            jmap,
            irc = self.irc.is_some(),
            irc_listen = %self.irc_addr().map_or_else(|| "none".to_owned(), |a| a.to_string()),
            irc_listen_tls = %self.irc_tls_addr().map_or_else(|| "none".to_owned(), |a| a.to_string()),
            // docs/design/frontend-auth.md §4.6: an operator reading the
            // log should see that a node can log in with no credential.
            tailnet = self.tailnet,
            ca_bootstrap = %self.ca_bootstrap_addr().map_or_else(|| "none".to_owned(), |a| a.to_string()),
            user = %self.user_uri,
            server_url = %self.server_url,
            "mimid-agent listening"
        );
        let stop = self.stop;
        // The one place the stop signal is raised: it ends the sync loop,
        // the HTTP server, every EventSource stream and every IRC
        // connection.
        let signal = tokio::spawn({
            let stop = stop.clone();
            async move {
                shutdown.await;
                stop.send_replace(true);
            }
        });
        // The sync and expiry loops, and the live stream's wake-ups
        // (each Deliver, Position, Changed or lost connection wakes the
        // sync loop, which alone receives: Store::sync).
        let runner = Runner::start(
            &self.store,
            RunnerOptions::new(self.sync_interval, self.key_packages)
                .with_stream_wake(self.stream_wake.clone().filter(|_| self.push.is_none())),
            &stop.subscribe(),
            self.log_watch.map_or_else(RunnerHooks::new, |watch| {
                RunnerHooks::new().before(Box::new(watch) as Box<dyn BeforeSync>)
            }),
        );
        let reload = self
            .tls
            .as_ref()
            .map(|tls| tokio::spawn(Arc::clone(tls).reload_loop(stop.subscribe())));
        let recheck = tokio::spawn(recheck_credentials(
            Arc::clone(&self.credentials),
            stop.subscribe(),
        ));
        // The server's EventSource wakes the sync loop; the interval is
        // the fallback.
        let push = match (self.push, self.stream_wake.is_some()) {
            (Some(source), _) => Some(tokio::spawn(crate::push::follow(
                Arc::clone(&self.store),
                source,
                stop.subscribe(),
            ))),
            // The live stream: the runner follows it.
            (None, true) => None,
            (None, false) => {
                tracing::warn!(
                    name: "agent_push_unavailable",
                    "the server's Session has no eventSourceUrl; polling only"
                );
                None
            }
        };
        // Only the EventSource streams, which are JMAP's, read the ticks.
        let feed = self
            .http
            .as_ref()
            .filter(|http| http.endpoint.jmap.is_some())
            .map(|http| {
                tokio::spawn(forward_feed(
                    Arc::clone(&self.store),
                    Arc::clone(&http.endpoint),
                ))
            });
        // chatPush delivery, when the endpoint has a subscription store
        // (bead mimid-1wgh.99). It follows the same change feed the
        // EventSource does, and ends with `stop`.
        let pushing = self
            .http
            .as_ref()
            .and_then(|http| http.endpoint.jmap.as_ref())
            .filter(|jmap| jmap.chat.push_store().is_some())
            .map(|jmap| {
                tokio::spawn(mimid_agent_jmap::push::deliver(
                    Arc::clone(&jmap.chat),
                    stop.subscribe(),
                ))
            });
        let irc = self
            .irc
            .map(|irc| tokio::spawn(irc.serve(stop.subscribe())));
        // The HTTPS endpoint, with `[jmap] listen_tls`: the same routes
        // over TLS, its handshakes in their own tasks (the `https`
        // module). `ConnectInfo` carries the peer to the guard, for the
        // per-source slowdown and the logs of §7.
        let serving_tls = self.https.map(|https| {
            let mut stopping = stop.subscribe();
            let listener = crate::https::TlsListener::spawn(
                https.listener,
                https.local_addr,
                https.config,
                stop.subscribe(),
            );
            tokio::spawn(async move {
                axum::serve(
                    axum::serve::ListenerExt::tap_io(listener, |_| {}),
                    http::router(https.endpoint)
                        .into_make_service_with_connect_info::<SocketAddr>(),
                )
                .with_graceful_shutdown(async move { stopped(&mut stopping).await })
                .await
            })
        });
        // The CA bootstrap listener: plain HTTP, the three CA paths and a
        // 404 on everything else (decision mimid-1wgh.127).
        let serving_ca = self.ca_bootstrap.map(|(listener, _, page)| {
            let mut stopping = stop.subscribe();
            tokio::spawn(async move {
                axum::serve(listener, http::ca_router(page))
                    .with_graceful_shutdown(async move { stopped(&mut stopping).await })
                    .await
            })
        });
        let served = match self.http {
            Some(http) => {
                let mut stopping = stop.subscribe();
                axum::serve(
                    http.listener,
                    http::router(http.endpoint).into_make_service_with_connect_info::<SocketAddr>(),
                )
                .with_graceful_shutdown(async move { stopped(&mut stopping).await })
                .await
            }
            None => {
                stopped(&mut stop.subscribe()).await;
                Ok(())
            }
        };
        // The HTTP server ends only once stopped, or on an error.
        stop.send_replace(true);
        signal.abort();
        runner.join().await;
        let served_ca = match serving_ca {
            Some(task) => match task.await {
                Ok(result) => result,
                Err(error) => {
                    tracing::error!(
                        name: "agent_task_panicked",
                        task = "CA bootstrap listener",
                        error = &error as &dyn std::error::Error,
                        "a task of the daemon ended abnormally"
                    );
                    Ok(())
                }
            },
            None => Ok(()),
        };
        let served_tls = match serving_tls {
            Some(task) => match task.await {
                Ok(result) => result,
                Err(error) => {
                    tracing::error!(
                        name: "agent_task_panicked",
                        task = "HTTPS endpoint",
                        error = &error as &dyn std::error::Error,
                        "a task of the daemon ended abnormally"
                    );
                    Ok(())
                }
            },
            None => Ok(()),
        };
        for (name, task) in [
            ("credential recheck", Some(recheck)),
            ("certificate reload", reload),
            ("push", push),
            ("chatPush delivery", pushing),
            ("feed", feed),
            ("IRC front end", irc),
        ] {
            if let Some(task) = task
                && let Err(error) = task.await
            {
                tracing::error!(
                    name: "agent_task_panicked",
                    task = name,
                    error = &error as &dyn std::error::Error,
                    "a task of the daemon ended abnormally"
                );
            }
        }
        // The daemon has stopped: every loop of its own is joined and
        // both servers have returned. A clone of the store can still sit
        // in a connection task that is being torn down, though, and with
        // it a clone of the state lock, so the lock is released here
        // rather than left to the last clone's drop. `Daemon::serve`
        // returning then means the state directory is free, which is
        // what an embedder stopping one agent and starting another on the
        // same directory needs (bead mimid-036n).
        self.store.state_lock().release();
        tracing::info!(name: "agent_stopped", "mimid-agent stopped");
        // Either listener's failure is the daemon's; the plain one first,
        // since it is the one that always exists.
        served.and(served_tls).and(served_ca)
    }
}

/// Reads the credential table again every [`CREDENTIAL_RECHECK`] until
/// stopped: a change another process made (the `app-password` CLI) then
/// reaches the front ends ([`Credentials::changes`]). A failure is logged.
async fn recheck_credentials(credentials: Arc<Credentials>, mut stop: watch::Receiver<bool>) {
    loop {
        tokio::select! {
            () = stopped(&mut stop) => return,
            () = tokio::time::sleep(CREDENTIAL_RECHECK) => {}
        }
        if let Err(error) = credentials.refresh() {
            tracing::warn!(
                name: "agent_credentials_unreadable",
                error = &error as &dyn std::error::Error,
                "the credential table could not be read again"
            );
        }
    }
}

/// The HTTPS endpoint's base URL and the names its Host check accepts
/// besides the loopback ones (docs/design/frontend-auth.md §5.3).
///
/// The base URL names the first `[tls] names` entry, which is the name
/// the certificate is for and the one setup output prints, so the Session
/// hands a client URLs it can reach and whose certificate matches. With
/// no configured name, which `source = "files"` allows, it is the address
/// itself. The address is accepted as a Host either way, because a client
/// that connects by address sends it; that is no rebinding hole, since a
/// page served from another name cannot make a browser send an address as
/// its Host.
fn https_endpoint(tls: Option<&crate::tls::TlsSetting>, addr: SocketAddr) -> (String, Vec<String>) {
    let mut names: Vec<String> = tls.map(|tls| tls.names.clone()).unwrap_or_default();
    let base = match names.first() {
        // RFC 3986 §3.2.3: the port is left out when it is the scheme's.
        Some(name) if addr.port() == 443 => format!("https://{name}"),
        Some(name) => format!("https://{name}:{}", addr.port()),
        None => format!("https://{addr}"),
    };
    let literal = match addr.ip() {
        std::net::IpAddr::V4(ip) => ip.to_string(),
        std::net::IpAddr::V6(ip) => format!("[{ip}]"),
    };
    if !names.contains(&literal) {
        names.push(literal);
    }
    (base, names)
}

/// The trimmed contents of the server token file.
fn read_server_token(path: &std::path::Path) -> Result<String, StartError> {
    let text = std::fs::read_to_string(path).map_err(|source| StartError::ServerToken {
        path: path.to_owned(),
        source: Some(source),
    })?;
    let token = text.trim();
    if token.is_empty() {
        return Err(StartError::ServerToken {
            path: path.to_owned(),
            source: None,
        });
    }
    Ok(token.to_owned())
}

/// Tells the EventSource streams to look whenever the store publishes
/// changes (each save that has some), until the daemon stops: the JMAP
/// front end has shown them by then ([`mimid_agent_store::Frontend`]).
async fn forward_feed(store: Arc<Store>, endpoint: Arc<Endpoint>) {
    let mut stop = endpoint.stop.clone();
    let mut published = store.subscribe();
    loop {
        tokio::select! {
            () = stopped(&mut stop) => return,
            received = published.recv() => match received {
                Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => {
                    // No receiver only means no stream is open.
                    let _ = endpoint.changes.send(());
                }
                Err(broadcast::error::RecvError::Closed) => return,
            },
        }
    }
}
