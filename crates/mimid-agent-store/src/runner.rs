//! What runs around a [`Store`] while it serves: the sync loop, the
//! expiry loop, and the live stream's wake-ups (docs/design/purple-mimi.md
//! §5.1 and §5.7). mimid-agent's daemon and any embedder run the same
//! loops through [`Runner`], so their behaviour cannot drift apart.
//!
//! - The sync loop runs [`Store::sync`] (the agent's only journal
//!   consumer) at once, then whenever woken ([`Store::sync_wanted`]: a
//!   write of a front end, the server's push) or after
//!   [`RunnerOptions::sync_interval`] without a wake-up. Before each sync
//!   it runs the caller's [`BeforeSync`] hook, if any; after it, it tops
//!   the KeyPackages up ([`top_up_key_packages`]).
//! - The expiry loop deletes messages at their expiry
//!   ([`Store::expire_now`]): at once, then at each next deadline, when a
//!   nearer one may have come ([`Store::expiry_wanted`]), and at least
//!   every [`EXPIRY_RECHECK`].
//! - With the live stream ([`RunnerOptions::stream_wake`]), each
//!   `Deliver`, `Position`, `Changed` or lost connection wakes the sync
//!   loop. A JMAP EventSource is the caller's to follow.
//!
//! Every loop ends when the stop signal turns `true`, at the end of the
//! step it is in: a sync or an expiry pass is not cut.
//!
//! # Limitations
//!
//! - Failures are logged and retried at the next turn, never returned.
//! - Nothing here watches the state lock or takes an account over; that
//!   is the embedder's.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use mimid_agent_core::Agent;
use tokio::sync::{Notify, watch};
use tokio::task::JoinHandle;

use crate::{Store, SyncReport};

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
        before_sync: Option<Box<dyn BeforeSync>>,
    ) -> Self {
        let mut tasks = vec![
            (
                "sync loop",
                tokio::spawn(sync_loop(
                    Arc::clone(store),
                    stop.clone(),
                    options.sync_interval,
                    options.key_packages,
                    before_sync,
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
    /// that panicked.
    pub async fn join(self) {
        for (name, task) in self.tasks {
            if let Err(error) = task.await {
                tracing::error!(
                    name: "agent_task_panicked",
                    task = name,
                    error = &error as &dyn std::error::Error,
                    "a task of the agent ended abnormally"
                );
            }
        }
    }
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
    mut before_sync: Option<Box<dyn BeforeSync>>,
) {
    let sync_now = Arc::clone(store.sync_wanted());
    loop {
        if *stop.borrow() {
            return;
        }
        if let Some(hook) = before_sync.as_mut() {
            hook.before_sync(&store).await;
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
