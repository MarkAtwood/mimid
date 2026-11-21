//! [`Daemon`]: the agent, its plaintext store, its front ends over the
//! store (JMAP Chat on the HTTP endpoint unless `[jmap] enabled = false`,
//! IRC with `[irc]`), the sync loop, and the expiry loop that deletes
//! messages at their time (docs/design/agent-frontends.md §7.20 to §7.23).

use std::future::Future;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use mimid_agent_core::push::PushSource;
use mimid_agent_core::{Agent, AgentConfig, AgentError};
use mimid_agent_irc::{IrcFrontEnd, IrcOptions};
use mimid_agent_jmap::{AgentChat, BlobStore, Options};
use mimid_agent_store::credentials::Credentials;
use mimid_agent_store::{Store, SyncReport};
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
    /// The IRC front end could not start (`[irc].listen`).
    #[error("starting the IRC front end")]
    Irc(#[from] mimid_agent_irc::IrcError),
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
                Some(
                    IrcFrontEnd::bind(
                        Arc::clone(&store),
                        IrcOptions::new(setting.listen, setting.server_name.clone()),
                        Arc::clone(&credentials),
                    )
                    .await?,
                )
            }
            None => None,
        };
        Ok(Self {
            http,
            irc,
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
        let sync = tokio::spawn(sync_loop(
            Arc::clone(&self.store),
            stop.subscribe(),
            self.sync_interval,
            self.key_packages,
            self.log_watch,
        ));
        let expiry = tokio::spawn(expiry_loop(Arc::clone(&self.store), stop.subscribe()));
        let recheck = tokio::spawn(recheck_credentials(
            Arc::clone(&self.credentials),
            stop.subscribe(),
        ));
        // The server's EventSource wakes the sync loop; the interval is
        // the fallback.
        let push = match (self.push, self.stream_wake) {
            (Some(source), _) => Some(tokio::spawn(crate::push::follow(
                Arc::clone(&self.store),
                source,
                stop.subscribe(),
            ))),
            // The live stream: each Deliver, Position, Changed or lost
            // connection wakes the sync loop, which alone receives
            // (Store::sync).
            (None, Some(wake)) => Some(tokio::spawn(follow_stream(
                Arc::clone(&self.store),
                wake,
                stop.subscribe(),
            ))),
            (None, None) => {
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
        for (name, task) in [
            ("sync loop", Some(sync)),
            ("expiry loop", Some(expiry)),
            ("credential recheck", Some(recheck)),
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

/// Wakes the sync loop each time the live stream has something, until
/// stopped.
async fn follow_stream(
    store: Arc<Store>,
    wake: Arc<tokio::sync::Notify>,
    mut stop: watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            () = wake.notified() => store.sync_wanted().notify_one(),
            () = stopped(&mut stop) => return,
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

/// Learns which of the agent's KeyPackages were handed out
/// ([`Agent::refresh_key_packages`]: `KeyPackage/changes`, findings log
/// F9) and publishes KeyPackages until `target` are outstanding. A failure
/// is logged; publishing then goes by what the agent knew before.
async fn top_up_key_packages(agent: &mut Agent, target: u32) {
    if let Err(error) = agent.refresh_key_packages().await {
        tracing::warn!(
            name: "agent_key_packages_unknown",
            error = &error as &dyn std::error::Error,
            "which KeyPackages were handed out could not be read"
        );
    }
    let have = agent.key_packages_outstanding();
    if have >= target {
        return;
    }
    let wanted = target - have;
    match agent.publish_key_packages(wanted).await {
        Ok(()) => tracing::info!(
            name: "agent_key_packages_published",
            count = wanted,
            "KeyPackages published"
        ),
        Err(error) => tracing::warn!(
            name: "agent_key_packages_failed",
            error = &error as &dyn std::error::Error,
            "publishing KeyPackages failed"
        ),
    }
}

/// Syncs the store at once ([`Store::sync`], the agent's only journal
/// consumer), then when woken ([`Store::sync_wanted`]: a write of a front
/// end, or a StateChange on the server's EventSource) or after `interval`
/// without one, until `stop` is true; before each sync,
/// takes a changed did:webvh log file (`log_watch`); after it, tops the
/// KeyPackages up.
async fn sync_loop(
    store: Arc<Store>,
    mut stop: watch::Receiver<bool>,
    interval: Duration,
    key_packages: u32,
    mut log_watch: Option<LogWatch>,
) {
    let sync_now = Arc::clone(store.sync_wanted());
    loop {
        if let Some(watch) = log_watch.as_mut() {
            watch.check(&store).await;
        }
        match store.sync().await {
            Ok(report) => log_report(&report),
            Err(error) => tracing::warn!(
                name: "agent_sync_failed",
                error = &error as &dyn std::error::Error,
                "sync with the server failed"
            ),
        }
        top_up_key_packages(&mut *store.agent().lock().await, key_packages).await;
        tokio::select! {
            () = stopped(&mut stop) => return,
            () = tokio::time::sleep(interval) => {}
            () = sync_now.notified() => {}
        }
    }
}

/// The longest the expiry loop sleeps without looking again, so a clock
/// set forward is noticed. INVENTED VALUE, NOT FROM SPEC.
const EXPIRY_RECHECK: Duration = Duration::from_secs(60);

/// Deletes messages at their expiry (docs/design/agent-frontends.md §7.20
/// to §7.23; [`Store::expire_now`]) until `stop` is true: at once, so what
/// fell due while the agent was stopped goes at start, then at each next
/// deadline ([`Store::next_expiry`]), when a new one may be nearer
/// ([`Store::expiry_wanted`]), and at least every [`EXPIRY_RECHECK`].
async fn expiry_loop(store: Arc<Store>, mut stop: watch::Receiver<bool>) {
    let wanted = Arc::clone(store.expiry_wanted());
    loop {
        match store.expire_now().await {
            Ok(0) => {}
            Ok(count) => tracing::info!(
                name: "agent_messages_expired",
                count,
                "messages deleted at their expiry"
            ),
            Err(error) => tracing::warn!(
                name: "agent_expiry_save_failed",
                error = &error as &dyn std::error::Error,
                "messages deleted at their expiry were not saved; the next save writes them"
            ),
        }
        let wait = store.next_expiry().map_or(EXPIRY_RECHECK, |at| {
            let now = mimid_agent_store::sync::now_ms();
            Duration::from_millis(at.saturating_sub(now)).min(EXPIRY_RECHECK)
        });
        tokio::select! {
            () = stopped(&mut stop) => return,
            () = tokio::time::sleep(wait) => {}
            () = wanted.notified() => {}
        }
    }
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

fn log_report(report: &SyncReport) {
    for room in &report.joined {
        tracing::info!(name: "agent_room_joined", room = %room, "joined a room");
    }
    for problem in &report.problems {
        tracing::warn!(name: "agent_sync_problem", problem = %problem, "the agent reported a problem");
    }
    tracing::debug!(
        messages = report.messages,
        pending_invites = report.pending_invites.len(),
        skipped = ?report.skipped,
        "sync done"
    );
}
