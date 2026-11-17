//! [`Daemon`]: the agent, its JMAP endpoint and its sync loop.

use std::future::Future;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use mimid_agent_core::{Agent, AgentConfig, AgentError};
use mimid_agent_jmap::{AgentChat, Options, SyncReport};
use tokio::net::TcpListener;
use tokio::sync::{Notify, Semaphore, broadcast, watch};

use crate::config::Config;
use crate::http::{
    self, CHANGE_BUFFER, Endpoint, MAX_CONCURRENT_REQUESTS, MAX_CONCURRENT_UPLOAD, stopped,
};
use crate::token::{LocalToken, TokenError};

/// A started daemon: the agent is open, its KeyPackages published and the
/// listener bound. [`Daemon::serve`] runs it.
pub struct Daemon {
    listener: TcpListener,
    local_addr: SocketAddr,
    endpoint: Arc<Endpoint>,
    stop: watch::Sender<bool>,
    sync_interval: Duration,
    key_packages: u32,
    user_uri: String,
    server_url: String,
}

impl std::fmt::Debug for Daemon {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Daemon")
            .field("local_addr", &self.local_addr)
            .field("user_uri", &self.user_uri)
            .finish_non_exhaustive()
    }
}

/// The plaintext store's file name in the state directory.
pub const CHAT_STORE_FILE: &str = "chat.json";

/// The blob store's directory in the state directory: attachments in
/// plaintext.
pub const BLOBS_DIR: &str = "blobs";

/// Why [`Daemon::start`] failed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum StartError {
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
    /// The Session does not build (a crate-jmap type changed).
    #[error("building the Session")]
    Session(#[from] serde_json::Error),
    /// The plaintext store (`<state_dir>/chat.json`) could not be read.
    #[error("opening the plaintext store")]
    Store(#[from] mimid_agent_jmap::PersistError),
    /// The blob store (`<state_dir>/blobs`) could not be opened.
    #[error("opening the blob store")]
    Blobs(#[from] mimid_agent_jmap::BlobError),
}

impl Daemon {
    /// Opens the agent for `config`'s user against its server, tops its
    /// KeyPackages up to `config.key_packages`, makes or reads the local
    /// token and binds the listener. Failing to publish KeyPackages is
    /// logged, not fatal: the sync loop tries again.
    ///
    /// # Errors
    ///
    /// See [`StartError`].
    pub async fn start(config: &Config) -> Result<Self, StartError> {
        let server_token = read_server_token(&config.token_file)?;
        let token = LocalToken::load_or_create(&config.state_dir)?;
        let mut agent = Agent::open(AgentConfig {
            server_url: config.server_url.clone(),
            token: server_token,
            user_uri: config.user_uri.clone(),
            state_dir: config.state_dir.clone(),
        })
        .await?;
        top_up_key_packages(&mut agent, config.key_packages).await;
        let listener =
            TcpListener::bind(config.listen)
                .await
                .map_err(|source| StartError::Bind {
                    addr: config.listen,
                    source,
                })?;
        let local_addr = listener.local_addr().map_err(|source| StartError::Bind {
            addr: config.listen,
            source,
        })?;
        let account = http::account_id(&config.user_uri);
        let (session, session_state) =
            http::session(&format!("http://{local_addr}"), &config.user_uri, &account)?;
        // The decrypted Chats and Messages, kept across restarts (bead
        // mimid-1wgh.13.12).
        let chat = Arc::new(
            AgentChat::new(
                agent,
                account,
                Options::default().with_invites(config.invites.into()),
            )
            .persisted_at(config.state_dir.join(CHAT_STORE_FILE))?
            // Attachments (bead mimid-1wgh.14).
            .with_blobs(config.state_dir.join(BLOBS_DIR))?,
        );
        let (stop, stop_receiver) = watch::channel(false);
        let (changes, _) = broadcast::channel(CHANGE_BUFFER);
        let endpoint = Arc::new(Endpoint {
            token,
            dispatcher: http::dispatcher(&chat),
            chat,
            session,
            session_state,
            in_flight: Arc::new(Semaphore::new(MAX_CONCURRENT_REQUESTS)),
            uploads: Arc::new(Semaphore::new(MAX_CONCURRENT_UPLOAD)),
            changes,
            sync_now: Arc::new(Notify::new()),
            stop: stop_receiver,
            allowed_origins: config.allowed_origins.clone(),
            port: local_addr.port(),
        });
        Ok(Self {
            listener,
            local_addr,
            endpoint,
            stop,
            sync_interval: config.sync_interval(),
            key_packages: config.key_packages,
            user_uri: config.user_uri.clone(),
            server_url: config.server_url.clone(),
        })
    }

    /// The address the endpoint listens on (the configured one, with the
    /// port filled in if it was 0).
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Serves the endpoint and runs the sync loop until `shutdown`
    /// resolves, then stops accepting connections, ends the open
    /// EventSource streams, lets requests in flight and a running sync
    /// finish, and returns.
    ///
    /// # Errors
    ///
    /// The listener's I/O error.
    pub async fn serve(
        self,
        shutdown: impl Future<Output = ()> + Send + 'static,
    ) -> std::io::Result<()> {
        tracing::info!(
            name: "agent_listening",
            listen = %self.local_addr,
            user = %self.user_uri,
            server_url = %self.server_url,
            "mimid-agent listening"
        );
        let sync = tokio::spawn(sync_loop(
            Arc::clone(&self.endpoint),
            self.sync_interval,
            self.key_packages,
        ));
        let stop = self.stop;
        let served = axum::serve(self.listener, http::router(self.endpoint))
            .with_graceful_shutdown(async move {
                shutdown.await;
                // Ends the sync loop and every EventSource stream, which
                // graceful shutdown would otherwise wait for forever.
                stop.send_replace(true);
            })
            .await;
        if let Err(error) = sync.await {
            tracing::error!(
                name: "agent_sync_loop_panicked",
                error = &error as &dyn std::error::Error,
                "the sync loop ended abnormally"
            );
        }
        tracing::info!(name: "agent_stopped", "mimid-agent stopped");
        served
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

/// Publishes KeyPackages until the agent thinks `target` are outstanding.
/// A failure is logged.
async fn top_up_key_packages(agent: &mut Agent, target: u32) {
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

/// Syncs at once, then every `interval` or when woken, until the daemon
/// stops; after each sync, tells the EventSource streams to look and tops
/// the KeyPackages up.
async fn sync_loop(endpoint: Arc<Endpoint>, interval: Duration, key_packages: u32) {
    let mut stop = endpoint.stop.clone();
    loop {
        match endpoint.chat.sync().await {
            Ok(report) => log_report(&report),
            Err(error) => tracing::warn!(
                name: "agent_sync_failed",
                error = &error as &dyn std::error::Error,
                "sync with the server failed"
            ),
        }
        // No receiver only means no stream is open.
        let _ = endpoint.changes.send(());
        top_up_key_packages(&mut *endpoint.chat.agent().lock().await, key_packages).await;
        tokio::select! {
            () = stopped(&mut stop) => return,
            () = tokio::time::sleep(interval) => {}
            () = endpoint.sync_now.notified() => {}
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
