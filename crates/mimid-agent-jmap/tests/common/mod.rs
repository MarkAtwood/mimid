//! What the tests here share: the server's change signal, so a test
//! waits on the server rather than on the clock.
//!
//! Each test file wires its own copy of a.example's stack, because each
//! wants the hub, the routes or the accounts a little differently. What
//! they all want is the same: a way to know when the server has
//! something a client's next sync would fetch, so the sync happens then
//! rather than every hundred milliseconds until a count runs out.
//!
//! mimid-agent-store's tests have the same module: a test module cannot be
//! shared between crates without making it a crate of its own. Neither
//! copy is the original, so a change to one belongs in both.

#![allow(dead_code)]

use mimid_server::follower::Follower;
use tokio::sync::broadcast;

/// How many wake-ups are kept for a receiver that has not read them.
///
/// Generous: a receiver that falls behind is told, and told to look
/// again rather than replay, so the only cost of a large buffer is
/// memory.
const CAPACITY: usize = 1024;

/// One wake-up for each thing the server stores that a client could
/// then fetch: an event in any room, a membership added or ended, a
/// local user's Consent.
///
/// The in-process stand-in for the EventSource that wakes the daemon's
/// sync loop in production. The follower's three announcements are
/// merged because what a test waits for is "the server has something
/// for me", and which of the three carried it is the implementation's
/// business.
#[derive(Clone)]
pub struct Changes(broadcast::Sender<()>);

impl Changes {
    /// Forwards `follower`'s announcements, each on its own task, which
    /// ends when the follower drops that sender.
    #[must_use]
    pub fn of(follower: &Follower) -> Self {
        let (sender, _) = broadcast::channel(CAPACITY);
        Self::forward(follower.subscribe(), sender.clone());
        Self::forward(follower.subscribe_membership(), sender.clone());
        Self::forward(follower.subscribe_consent(), sender.clone());
        Self(sender)
    }

    fn forward<T: Clone + Send + 'static>(
        mut source: broadcast::Receiver<T>,
        sender: broadcast::Sender<()>,
    ) {
        tokio::spawn(async move {
            loop {
                match source.recv().await {
                    // A lag is still a change, and the receiver only
                    // needs to know that there was one.
                    Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => {
                        let _ = sender.send(());
                    }
                    Err(broadcast::error::RecvError::Closed) => return,
                }
            }
        });
    }

    /// A watch on the changes from now on, and on what `store` writes.
    ///
    /// Take it before the look that might miss something: a
    /// `broadcast` receiver keeps what is published from its
    /// subscription on, so a change made while a sync is in flight is
    /// waiting rather than lost.
    #[must_use]
    pub fn watch(&self, store: &mimid_agent_store::Store) -> Watch {
        Watch {
            server: self.0.subscribe(),
            local: Some(store.subscribe()),
            woken: 0,
        }
    }

    /// A watch on the server's changes alone, for a waiter that has no
    /// store of its own to watch: an `Agent` without an `AgentChat`
    /// over it, or an HTTP client of the server's.
    ///
    /// Such a waiter judges its own progress -- an `Agent::poll` that
    /// returned events has more to read -- so [`Watch::next`] waits for
    /// the server without asking about a store.
    #[must_use]
    pub fn watch_server(&self) -> Watch {
        Watch {
            server: self.0.subscribe(),
            local: None,
            woken: 0,
        }
    }
}

/// A watch on a [`Changes`] and on one store, from where it was taken.
pub struct Watch {
    server: broadcast::Receiver<()>,
    local: Option<broadcast::Receiver<u64>>,
    woken: u64,
}

impl Watch {
    /// Returns when there is reason to look again.
    ///
    /// Two reasons, in order. The store wrote something since the last
    /// look, so the sync that just ran made progress and the next one
    /// may make more: one change at the server can take an agent
    /// several syncs to work through, and waiting for a second change
    /// that will never come would hang. Otherwise the server has
    /// changed, which is when a sync is worth making at all.
    ///
    /// There is no deadline. A change that never comes hangs the test
    /// and names itself, where a count of tries would have failed on a
    /// loaded machine instead (beads mimid-gn1w, mimid-zr08).
    pub async fn again(&mut self, what: &str) {
        let mut wrote = false;
        if let Some(local) = &mut self.local {
            // Drain, so the next call does not see these again.
            while local.try_recv().is_ok() {
                wrote = true;
            }
        }
        if wrote {
            return;
        }
        self.next(what).await;
    }

    /// Waits for the next change at the server, whatever the caller's
    /// own state.
    ///
    /// For a waiter that judges its own progress: it calls this only
    /// when its last look found nothing at all, so there is nothing to
    /// do until the server has something.
    pub async fn next(&mut self, what: &str) {
        if self.woken.is_multiple_of(32) {
            eprintln!(
                "waiting for {what}: the server has changed {} times",
                self.woken
            );
        }
        self.woken += 1;
        match self.server.recv().await {
            Ok(()) | Err(broadcast::error::RecvError::Lagged(_)) => {}
            Err(broadcast::error::RecvError::Closed) => {
                panic!("the server stopped before {what}")
            }
        }
    }
}
