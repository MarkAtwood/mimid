//! What runs around a [`Store`] while it serves: the sync loop, the
//! expiry loop, and the live stream's wake-ups (docs/design/purple-mimi.md
//! §5.1 and §5.7). mimid-agent's daemon and any embedder run the same
//! loops through [`Runner`], so their behaviour cannot drift apart.
//!
//! - The sync loop runs [`Store::sync`] (the agent's only journal
//!   consumer) at once, then whenever woken ([`Store::sync_wanted`]: a
//!   write of a front end, the server's push) or after
//!   [`RunnerOptions::sync_interval`] without a wake-up. Before each sync
//!   it runs the caller's [`BeforeSync`] hook, if any; after it, it hands
//!   the outcome to the caller's [`AfterSync`] hook, if any, and tops the
//!   KeyPackages up ([`top_up_key_packages`]).
//! - The expiry loop deletes messages at their expiry
//!   ([`Store::expire_now`]): at once, then at each next deadline, when a
//!   nearer one may have come ([`Store::expiry_wanted`]), and at least
//!   every [`EXPIRY_RECHECK`].
//! - With the live stream ([`RunnerOptions::stream_wake`]), each
//!   `Deliver`, `Position`, `Changed` or lost connection wakes the sync
//!   loop. A JMAP EventSource is the caller's to follow.
//!
//! Every loop ends when the stop signal turns `true`, at the end of the
//! step it is in: a sync or an expiry pass is not cut. [`Runner::join`]
//! waits for that however long it takes; [`Runner::join_within`] waits a
//! grace period and then aborts what is left, which an embedder releasing
//! an account needs (docs/design/purple-mimi.md §6.3 items 8 to 10).
//!
//! # Limitations
//!
//! - Failures are logged and retried at the next turn, never returned.
//!   An embedder that must act on one (tell its user the server cannot be
//!   reached) installs an [`AfterSync`] hook.
//! - A hook runs inside the sync loop, which waits for it: one that
//!   blocks holds the next sync up.
//! - Nothing here watches the state lock or takes an account over; that
//!   is the embedder's.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use mimid_agent_core::Agent;
use tokio::sync::{Notify, watch};
use tokio::task::JoinHandle;

use crate::{Store, SyncError, SyncReport};

/// The longest the expiry loop sleeps without looking again, so a clock
/// set forward is noticed. INVENTED VALUE, NOT FROM SPEC.
pub const EXPIRY_RECHECK: Duration = Duration::from_secs(60);

/// What a [`Runner`] runs with.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct RunnerOptions {
    /// The longest the sync loop waits without a wake-up.
    pub sync_interval: Duration,
    /// How many KeyPackages to keep outstanding.
    pub key_packages: u32,
    /// The live stream's wake-up ([`Agent::stream_wake`]), or `None` on
    /// JMAP.
    pub stream_wake: Option<Arc<Notify>>,
}

impl RunnerOptions {
    /// Syncing at least every `sync_interval`, keeping `key_packages`
    /// KeyPackages outstanding, with no stream wake-up.
    #[must_use]
    pub fn new(sync_interval: Duration, key_packages: u32) -> Self {
        Self {
            sync_interval,
            key_packages,
            stream_wake: None,
        }
    }

    /// These options, woken by the live stream's `wake`.
    #[must_use]
    pub fn with_stream_wake(mut self, wake: Option<Arc<Notify>>) -> Self {
        self.stream_wake = wake;
        self
    }
}

/// A step the sync loop runs before each [`Store::sync`], such as taking a
/// changed did:webvh log file.
pub trait BeforeSync: Send {
    /// Runs before a sync. Failures are the hook's to log.
    fn before_sync<'a>(
        &'a mut self,
        store: &'a Store,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>>;
}

/// A step the sync loop runs after each [`Store::sync`], with what the
/// pass did or why it failed.
///
/// The runner itself only logs a failed sync. An embedder that must tell
/// its user when the agent cannot reach its server learns of it here:
/// purple-mimi reports `MIMI_EV_DISCONNECTED` with `MIMI_ERR_NETWORK`
/// and closes the account (docs/design/purple-mimi.md §7.4; bead
/// mimid-2vxv).
///
/// A failure is not by itself a lost connection: the sync retries at the
/// next turn and nothing is lost either way ([`SyncError`]). Whether to
/// act on one failure or on a run of them is the hook's.
pub trait AfterSync: Send {
    /// Runs after a sync, with its outcome. Failures are the hook's to
    /// log. Like [`crate::Frontend::before_save`] it must not call
    /// [`Store::sync`] or [`Store::save`], or take the agent
    /// ([`Store::agent`]): the sync loop is between passes, not holding
    /// the agent, and a hook that takes it deadlocks against the next
    /// pass.
    fn after_sync<'a>(
        &'a mut self,
        store: &'a Store,
        outcome: Result<&'a SyncReport, &'a SyncError>,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>>;
}

/// The hooks a [`Runner`]'s sync loop runs around each pass, none by
/// default.
#[derive(Default)]
#[non_exhaustive]
pub struct RunnerHooks {
    /// Runs before each sync.
    pub before_sync: Option<Box<dyn BeforeSync>>,
    /// Runs after each sync, with its outcome.
    pub after_sync: Option<Box<dyn AfterSync>>,
}

impl RunnerHooks {
    /// No hooks.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// These hooks, with `hook` run before each sync.
    #[must_use]
    pub fn before(mut self, hook: Box<dyn BeforeSync>) -> Self {
        self.before_sync = Some(hook);
        self
    }

    /// These hooks, with `hook` run after each sync.
    #[must_use]
    pub fn after(mut self, hook: Box<dyn AfterSync>) -> Self {
        self.after_sync = Some(hook);
        self
    }
}

impl std::fmt::Debug for RunnerHooks {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RunnerHooks")
            .field("before_sync", &self.before_sync.is_some())
            .field("after_sync", &self.after_sync.is_some())
            .finish()
    }
}

/// The running loops of one store.
#[derive(Debug)]
pub struct Runner {
    tasks: Vec<(&'static str, JoinHandle<()>)>,
}

impl Runner {
    /// Starts the sync loop, the expiry loop and, with
    /// [`RunnerOptions::stream_wake`], the stream follower, on the current
    /// Tokio runtime, each until `stop` turns `true`.
    ///
    /// # Panics
    ///
    /// Outside a Tokio runtime.
    #[must_use]
    pub fn start(
        store: &Arc<Store>,
        options: RunnerOptions,
        stop: &watch::Receiver<bool>,
        hooks: RunnerHooks,
    ) -> Self {
        let mut tasks = vec![
            (
                "sync loop",
                tokio::spawn(sync_loop(
                    Arc::clone(store),
                    stop.clone(),
                    options.sync_interval,
                    options.key_packages,
                    hooks,
                )),
            ),
            (
                "expiry loop",
                tokio::spawn(expiry_loop(Arc::clone(store), stop.clone())),
            ),
        ];
        if let Some(wake) = options.stream_wake {
            tasks.push((
                "stream follower",
                tokio::spawn(follow_stream(Arc::clone(store), wake, stop.clone())),
            ));
        }
        Self { tasks }
    }

    /// Waits for every loop to end (after the stop signal), logging one
    /// that panicked. Waits as long as it takes: a loop stuck in a hook
    /// or a request never ends. [`Runner::join_within`] gives up.
    pub async fn join(self) {
        self.stop_within(None).await;
    }

    /// Waits up to `grace` for every loop to end (after the stop
    /// signal), then aborts the ones still running and names them.
    ///
    /// An embedder releasing an account needs this: it waits for the work
    /// in flight, then drops what is left, so that it holds the last
    /// reference to the store and can close the database and release the
    /// state lock (docs/design/purple-mimi.md §6.3 items 8 to 10; bead
    /// mimid-2vxv). Every loop ends at a transaction boundary, and the
    /// journal and the outbox are built so that any cut point is
    /// consistent (§6.4), so an aborted loop loses no state.
    ///
    /// An aborted task is awaited, so when this returns every loop has
    /// dropped its reference to the store. A loop blocked in a
    /// synchronous call cannot be cut at all and is waited for even so.
    pub async fn join_within(self, grace: Duration) -> RunnerStop {
        self.stop_within(Some(grace)).await
    }

    /// [`Runner::join`] with no deadline, [`Runner::join_within`] with
    /// one.
    async fn stop_within(self, grace: Option<Duration>) -> RunnerStop {
        let deadline = grace.map(|grace| tokio::time::Instant::now() + grace);
        let mut stopped = RunnerStop::default();
        for (name, mut task) in self.tasks {
            let ended = match deadline {
                Some(at) => tokio::time::timeout_at(at, &mut task).await.map_err(|_| ()),
                None => Ok((&mut task).await),
            };
            match ended {
                Ok(Ok(())) => {}
                Ok(Err(error)) => log_panic(name, &error),
                Err(()) => {
                    task.abort();
                    // The task is awaited so that it has dropped its
                    // reference to the store before this returns.
                    if let Err(error) = task.await
                        && !error.is_cancelled()
                    {
                        log_panic(name, &error);
                    }
                    tracing::warn!(
                        name: "agent_task_aborted",
                        task = name,
                        "a loop of the agent did not end within the grace period and was aborted"
                    );
                    stopped.aborted.push(name);
                }
            }
        }
        stopped
    }
}

/// What [`Runner::join_within`] did: which loops had to be aborted
/// because they were still running when the grace period ran out.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct RunnerStop {
    /// The loops aborted, by the names [`Runner`] gives them: `"sync
    /// loop"`, `"expiry loop"`, `"stream follower"`.
    pub aborted: Vec<&'static str>,
}

impl RunnerStop {
    /// Whether every loop ended on its own, nothing aborted.
    #[must_use]
    pub fn clean(&self) -> bool {
        self.aborted.is_empty()
    }
}

fn log_panic(name: &'static str, error: &tokio::task::JoinError) {
    tracing::error!(
        name: "agent_task_panicked",
        task = name,
        error = error as &dyn std::error::Error,
        "a task of the agent ended abnormally"
    );
}

/// Resolves once `stop` is `true`, or its sender is gone.
async fn stopped(stop: &mut watch::Receiver<bool>) {
    let _ = stop.wait_for(|stopping| *stopping).await;
}

/// Learns which of the agent's KeyPackages were handed out
/// ([`Agent::refresh_key_packages`]: `KeyPackage/changes`, findings log
/// F9) and publishes KeyPackages until `target` are outstanding. A failure
/// is logged; publishing then goes by what the agent knew before.
pub async fn top_up_key_packages(agent: &mut Agent, target: u32) {
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

/// The sync loop (module documentation).
async fn sync_loop(
    store: Arc<Store>,
    mut stop: watch::Receiver<bool>,
    interval: Duration,
    key_packages: u32,
    mut hooks: RunnerHooks,
) {
    let sync_now = Arc::clone(store.sync_wanted());
    loop {
        if *stop.borrow() {
            return;
        }
        if let Some(hook) = hooks.before_sync.as_mut() {
            hook.before_sync(&store).await;
        }
        let outcome = store.sync().await;
        match &outcome {
            Ok(report) => log_report(report),
            Err(error) => tracing::warn!(
                name: "agent_sync_failed",
                error = error as &dyn std::error::Error,
                "sync with the server failed"
            ),
        }
        if let Some(hook) = hooks.after_sync.as_mut() {
            hook.after_sync(&store, outcome.as_ref()).await;
        }
        top_up_key_packages(&mut *store.agent().lock().await, key_packages).await;
        tokio::select! {
            () = stopped(&mut stop) => return,
            () = tokio::time::sleep(interval) => {}
            () = sync_now.notified() => {}
        }
    }
}

/// The expiry loop (module documentation).
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
            let now = crate::sync::now_ms();
            Duration::from_millis(at.saturating_sub(now)).min(EXPIRY_RECHECK)
        });
        tokio::select! {
            () = stopped(&mut stop) => return,
            () = tokio::time::sleep(wait) => {}
            () = wanted.notified() => {}
        }
    }
}

/// Wakes the sync loop each time the live stream has something, until
/// stopped.
async fn follow_stream(store: Arc<Store>, wake: Arc<Notify>, mut stop: watch::Receiver<bool>) {
    loop {
        tokio::select! {
            () = wake.notified() => store.sync_wanted().notify_one(),
            () = stopped(&mut stop) => return,
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
