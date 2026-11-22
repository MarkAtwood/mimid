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
    /// The IRC front end, with `[irc]`.
    irc: Option<IrcFrontEnd>,
    /// The TLS certificate source, with `[tls]`.
    tls: Option<Arc<crate::tls::Tls>>,
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
}

/// The HTTP endpoint: its listener and what its routes share.
struct Http {
    listener: TcpListener,
    local_addr: SocketAddr,
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
        let (stop, stop_receiver) = watch::channel(false);
        let http = match listener {
            Some((listener, local_addr)) => {
                let jmap = if config.jmap.enabled {
                    let account = http::account_id(&config.user_uri);
                    let (session, session_state) =
                        http::session(&format!("http://{local_addr}"), &config.user_uri, &account)?;
                    let chat = Arc::new(AgentChat::over(
                        Arc::clone(&store),
                        account,
                        Options::default(),
                    )?);
                    Some(Jmap {
                        dispatcher: http::dispatcher(&chat),
                        chat,
                        session,
                        session_state,
                    })
                } else {
                    None
                };
                // docs/design/agent-frontends.md §7.30: links any front
                // end can hand its client, served on this listener.
                store.set_attachment_links(AttachmentLinks::new(
                    token.link_key(),
                    format!("http://{local_addr}"),
                ));
                let (changes, _) = broadcast::channel(CHANGE_BUFFER);
                let endpoint = Arc::new(Endpoint {
                    credentials: Arc::clone(&credentials),
                    store: Arc::clone(&store),
                    jmap,
                    in_flight: Arc::new(Semaphore::new(MAX_CONCURRENT_REQUESTS)),
                    uploads: Arc::new(Semaphore::new(MAX_CONCURRENT_UPLOAD)),
                    changes,
                    // The store's own: its write methods wake the loop too.
                    sync_now: Arc::clone(store.sync_wanted()),
                    stop: stop_receiver,
                    allowed_origins: config.allowed_origins.clone(),
                    port: local_addr.port(),
                });
                Some(Http {
                    listener,
                    local_addr,
                    endpoint,
                })
            }
            // Config::check refuses JMAP on without listen.
            None => None,
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
                // client-survey.md §10 S4: push on by default, with its own
                // switch; the subscriptions in the agent's database.
                if setting.webpush {
                    let subscriptions = PushSubscriptions::open(
                        &config.state_dir.join(mimid_agent_core::DATABASE_FILE),
                    )?;
                    irc.enable_web_push(Arc::new(subscriptions))?;
                }
                Some(irc)
            }
            None => None,
        };
        Ok(Self {
            http,
            irc,
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
        })
    }

    /// The address the HTTP endpoint listens on (the configured one, with
    /// the port filled in if it was 0); `None` without `listen`.
    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.http.as_ref().map(|http| http.local_addr)
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
            jmap,
            irc = self.irc.is_some(),
            irc_listen = %self.irc_addr().map_or_else(|| "none".to_owned(), |a| a.to_string()),
            irc_listen_tls = %self.irc_tls_addr().map_or_else(|| "none".to_owned(), |a| a.to_string()),
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
        let irc = self
            .irc
            .map(|irc| tokio::spawn(irc.serve(stop.subscribe())));
        let served = match self.http {
            Some(http) => {
                let mut stopping = stop.subscribe();
                axum::serve(http.listener, http::router(http.endpoint))
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
        for (name, task) in [
            ("credential recheck", Some(recheck)),
            ("certificate reload", reload),
            ("push", push),
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
        tracing::info!(name: "agent_stopped", "mimid-agent stopped");
        served
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
