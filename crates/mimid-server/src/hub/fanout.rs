//! Fanout delivery (protocol-07 §5.5): sends the outbox's `/notify` bodies
//! to each destination provider, in order.
//!
//! Each (room, domain) pair is a FIFO queue. Only its head row is ever
//! attempted. It is retried until accepted, unless the peer refuses it
//! for good: a `4xx` other than `408` and `429` drops the row, so one
//! message a peer will not take does not hold up every later Commit and
//! Welcome of the room (decision mimid-1wgh.6.19, amended 2026-11-15 after
//! Haven said it would refuse messages it cannot deliver). Network
//! failures, `5xx`, `408` and `429` are retried. The delay before the next attempt is
//! a capped exponential backoff, lengthened to honour a `Retry-After`
//! header (§5.5 SHOULD). Rows for the hub's own domain go to a
//! [`LocalDelivery`] hook instead of over HTTP (decision mimid-1wgh.6.17).
//! A row whose domain is neither the hub's own nor a configured peer is
//! parked: left in the outbox untried, and logged once per process.
//!
//! The outbox lives in SQLite, so delivery resumes after a restart.
//!
//! # Limitations
//!
//! - Delivery is at least once. A crash or store failure between a
//!   follower's `201` and the row's removal sends the row again, so
//!   followers must deduplicate, as §5.5 requires of them.
//! - ponytail: one request per FanoutMessage body and one request at a
//!   time across all queues; the ceiling is throughput, and a slow peer
//!   delays the others by up to [`crate::peer::REQUEST_TIMEOUT`] per
//!   attempt. Upgrade path: concatenate queued FanoutMessages of a room
//!   into one request (§5.5 allows it) and deliver queues concurrently.
//! - ponytail: rows are kept until delivered, with no expiry (decision
//!   mimid-1wgh.6.19); the ceiling is unbounded growth while a peer is
//!   down or parked. Upgrade path: a retention limit with admin
//!   visibility.

use std::collections::BTreeSet;
use std::error::Error;
use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, UNIX_EPOCH};

use mimid_telemetry::refusals::Refusal;
use tokio::sync::Notify;
use tokio::task::JoinHandle;

use super::Clock;
use crate::config::Domain;
use crate::peer::{PeerClient, PeerError, RejectionFields, RetryAfter};
use crate::store::{OutboxRow, Store, StoreError};

/// The delay after a first failed attempt, in milliseconds; each further
/// failure doubles it. INVENTED, NOT FROM SPEC (decision mimid-1wgh.6.19).
pub const BASE_BACKOFF_MS: u64 = 1_000;

/// The longest backoff delay, in milliseconds. INVENTED, NOT FROM SPEC
/// (decision mimid-1wgh.6.19).
pub const MAX_BACKOFF_MS: u64 = 5 * 60 * 1_000;

/// The longest `Retry-After` delay honoured, in milliseconds; longer
/// guidance is cut to this. INVENTED, NOT FROM SPEC (decision
/// mimid-1wgh.6.49).
pub const MAX_RETRY_AFTER_MS: u64 = 24 * 60 * 60 * 1_000;

/// How long the worker waits after a store failure before trying again,
/// in milliseconds. INVENTED, NOT FROM SPEC.
pub const STORE_RETRY_MS: u64 = 5_000;

/// Delivers fanout to the hub's own provider: the follower side of the same
/// server (decision mimid-1wgh.6.17).
pub trait LocalDelivery: Send + Sync + 'static {
    /// Why a delivery failed. A failed delivery is retried.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Accepts `body`, the concatenated FanoutMessages of a `/notify`
    /// request (protocol-07 §5.5), for the room `room_id`, at the room's
    /// `fanout_seq` (docs/design/mimi-catchup.md §4; 0 when the fanout
    /// has none). Returning `Ok` has the meaning of a `201` response.
    /// The same body may be delivered more than once.
    fn deliver(
        &self,
        room_id: &str,
        body: &[u8],
        fanout_seq: u64,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;
}

/// The fanout delivery worker's state.
pub struct Fanout<L> {
    store: Store,
    own_domain: Domain,
    peers: PeerClient,
    local: L,
    clock: Arc<dyn Clock>,
    /// Parked (room, domain) queues already logged.
    parked: BTreeSet<(String, Domain)>,
}

impl<L> std::fmt::Debug for Fanout<L> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Fanout")
            .field("own_domain", &self.own_domain)
            .field("peers", &self.peers)
            .finish_non_exhaustive()
    }
}

impl<L: LocalDelivery> Fanout<L> {
    /// A worker delivering `store`'s outbox: rows for `own_domain` to
    /// `local`, and the rest through `peers`.
    pub fn new(
        store: Store,
        own_domain: Domain,
        peers: PeerClient,
        local: L,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            store,
            own_domain,
            peers,
            local,
            clock,
            parked: BTreeSet::new(),
        }
    }

    /// Attempts every queue head that is due, repeating until no head is
    /// due, and returns the earliest time a waiting head becomes due, or
    /// `None` if no deliverable row is left. Parked rows are not attempted
    /// and do not count.
    ///
    /// # Errors
    ///
    /// Returns [`FanoutError::Store`] if the store fails. Rows are left as
    /// they were, apart from attempts already recorded.
    pub async fn deliver_due(&mut self) -> Result<Option<u64>, FanoutError> {
        loop {
            let now = self.clock.now_ms();
            let mut attempted = false;
            let mut next_due: Option<u64> = None;
            for row in self.store.outbox_heads().await? {
                if row.domain != self.own_domain && !self.peers.knows(&row.domain) {
                    self.park(&row);
                } else if row.next_attempt_at > now {
                    next_due = Some(
                        next_due.map_or(row.next_attempt_at, |next| next.min(row.next_attempt_at)),
                    );
                } else {
                    attempted = true;
                    self.attempt(row).await?;
                }
            }
            if !attempted {
                return Ok(next_due);
            }
        }
    }

    /// Runs the worker as a tokio task until the handle stops it.
    pub fn spawn(mut self) -> FanoutHandle {
        let wake = Arc::new(Notify::new());
        let notified = Arc::clone(&wake);
        let passed = Arc::new(Notify::new());
        let each_pass = Arc::clone(&passed);
        let task = tokio::spawn(async move {
            loop {
                let wait_ms = match self.deliver_due().await {
                    Ok(Some(next)) => Some(next.saturating_sub(self.clock.now_ms())),
                    Ok(None) => None,
                    Err(error) => {
                        tracing::error!(
                            name: "fanout_pass_failed",
                            error = &error as &dyn Error,
                            retry_in_ms = STORE_RETRY_MS,
                            "fanout pass failed"
                        );
                        Some(STORE_RETRY_MS)
                    }
                };
                // The pass is over, whatever it did: a caller following
                // delivery can look at the outbox now.
                each_pass.notify_waiters();
                match wait_ms {
                    // Never sleep longer than MAX_BACKOFF_MS, so a clock
                    // change is noticed.
                    Some(ms) => {
                        let sleep = Duration::from_millis(ms.min(MAX_BACKOFF_MS));
                        tokio::select! {
                            () = notified.notified() => {}
                            () = tokio::time::sleep(sleep) => {}
                        }
                    }
                    None => notified.notified().await,
                }
            }
        });
        FanoutHandle { wake, task, passed }
    }

    fn park(&mut self, row: &OutboxRow) {
        if self
            .parked
            .insert((row.room_id.clone(), row.domain.clone()))
        {
            tracing::warn!(
                name: "fanout_queue_parked",
                room_id = %row.room_id,
                domain = %row.domain,
                "fanout destination is not a configured peer; its queue is parked"
            );
        }
    }

    /// Attempts one head row: removes it on success, or records the attempt
    /// and the time of the next one.
    async fn attempt(&mut self, row: OutboxRow) -> Result<(), FanoutError> {
        let OutboxRow {
            id,
            room_id,
            domain,
            body,
            attempts,
            fanout_seq,
            ..
        } = row;
        let result: Result<(), Failure> = if domain == self.own_domain {
            self.local
                .deliver(&room_id, &body, fanout_seq)
                .await
                .map_err(|error| (Box::new(error) as _, None, false))
        } else {
            self.peers
                .notify(&domain, &room_id, body, fanout_seq)
                .await
                .map_err(|error| {
                    let (retry_after, refused) = match &error {
                        PeerError::Rejected {
                            status,
                            retry_after,
                            ..
                        } => (*retry_after, refused_for_good(*status)),
                        _ => (None, false),
                    };
                    (Box::new(error) as _, retry_after, refused)
                })
        };
        match result {
            Ok(()) => {
                self.store.mark_delivered(id).await?;
                tracing::debug!(%room_id, %domain, id, "fanout delivered");
            }
            Err((error, _, true)) => {
                self.store.drop_refused(id).await?;
                let error: &(dyn Error + 'static) = &*error;
                let rejection = RejectionFields::of(error);
                crate::metrics::instruments().fanout_dropped.add(
                    1,
                    &[
                        opentelemetry::KeyValue::new("peer", domain.as_str().to_owned()),
                        opentelemetry::KeyValue::new(
                            "status",
                            i64::from(rejection.status.unwrap_or_default()),
                        ),
                    ],
                );
                // The peer decided; this layer disposes of the row, and the
                // room's later rows go on. One line per window, since a
                // peer that refuses everything would otherwise write one
                // per row (bead mimid-sami); `mimid.fanout.dropped` above
                // counts them by peer and status either way.
                if let Some(suppressed) = Refusal::FanoutDeliveryRefused.count() {
                    tracing::warn!(
                        name: "fanout_delivery_refused",
                        %room_id,
                        %domain,
                        id,
                        attempts = attempts.saturating_add(1),
                        error,
                        status = rejection.status,
                        response_len = rejection.response_len,
                        response_code = rejection.response_code,
                        error_description = rejection.error_description,
                        suppressed,
                        "fanout delivery refused by the peer; dropped"
                    );
                }
            }
            Err((error, retry_after, false)) => {
                let now = self.clock.now_ms();
                let attempts = attempts.saturating_add(1);
                let delay = retry_delay_ms(
                    attempts,
                    retry_after.map(|guidance| retry_after_ms(guidance, now)),
                );
                self.store
                    .record_attempt(id, now.saturating_add(delay))
                    .await?;
                let error: &(dyn Error + 'static) = &*error;
                let rejection = RejectionFields::of(error);
                // The attempt failed but the row stays queued, so the
                // delivery itself has not failed yet: warn, not error.
                tracing::warn!(
                    name: "fanout_delivery_failed",
                    %room_id,
                    %domain,
                    id,
                    attempts,
                    retry_in_ms = delay,
                    error,
                    status = rejection.status,
                    response_len = rejection.response_len,
                    "fanout delivery failed; will retry"
                );
            }
        }
        Ok(())
    }
}

/// A running fanout worker. Dropping the handle leaves the worker running.
#[derive(Debug)]
pub struct FanoutHandle {
    wake: Arc<Notify>,
    task: JoinHandle<()>,
    passed: Arc<Notify>,
}

impl FanoutHandle {
    /// Makes the worker look at the outbox now, e.g. after rows were
    /// enqueued. A wake while the worker is busy is kept, not lost.
    pub fn wake(&self) {
        self.wake.notify_one();
    }

    /// Notified after each pass over the outbox, whatever that pass did.
    ///
    /// For a caller following delivery rather than asking about it: the
    /// outbox is worth looking at once a pass has ended, and not before.
    /// `Notify::notified` only hears a notification made after it is
    /// registered, so register the waiter, then look, then await it; a
    /// pass that ends in between is then waiting rather than missed.
    #[must_use]
    pub fn passed(&self) -> &Arc<Notify> {
        &self.passed
    }

    /// Stops the worker. A request in flight is abandoned, and its row is
    /// sent again when a worker next runs.
    pub async fn stop(self) {
        self.task.abort();
        if let Err(error) = self.task.await
            && error.is_panic()
        {
            tracing::error!(
                name: "fanout_worker_panicked",
                error = &error as &dyn Error,
                "fanout worker panicked"
            );
        }
    }
}

/// The delay before the next attempt after `attempts` failures: the capped
/// exponential backoff, or the `Retry-After` delay if that is longer.
/// A failed attempt: the error, the peer's `Retry-After`, and whether the
/// peer refused the row for good.
type Failure = (Box<dyn Error + Send + Sync>, Option<RetryAfter>, bool);

/// Whether a peer's `status` refuses a delivery for good: any `4xx` but
/// `408 Request Timeout` and `429 Too Many Requests`, which ask for a retry.
fn refused_for_good(status: u16) -> bool {
    (400..500).contains(&status) && status != 408 && status != 429
}

fn retry_delay_ms(attempts: u64, retry_after_ms: Option<u64>) -> u64 {
    let doublings = u32::try_from(attempts.saturating_sub(1)).unwrap_or(u32::MAX);
    let backoff = BASE_BACKOFF_MS
        .saturating_mul(2_u64.saturating_pow(doublings))
        .min(MAX_BACKOFF_MS);
    backoff.max(retry_after_ms.unwrap_or(0).min(MAX_RETRY_AFTER_MS))
}

/// A `Retry-After` delay in milliseconds from `now_ms`. A date in the past
/// gives 0.
fn retry_after_ms(guidance: RetryAfter, now_ms: u64) -> u64 {
    let millis = |duration: Duration| u64::try_from(duration.as_millis()).unwrap_or(u64::MAX);
    match guidance {
        RetryAfter::Delay(delay) => millis(delay),
        RetryAfter::At(at) => at
            .duration_since(UNIX_EPOCH)
            .map_or(0, millis)
            .saturating_sub(now_ms),
    }
}

/// An error from the fanout worker.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum FanoutError {
    /// The database failed.
    #[error("database error")]
    Store(#[from] StoreError),
}

#[cfg(test)]
mod tests {
    use std::time::SystemTime;

    use super::*;

    #[test]
    fn backoff_doubles_from_one_second_up_to_five_minutes() {
        // 1 s, 2 s, 4 s, ... 256 s, then capped at 300 s.
        let expected = [
            1_000, 2_000, 4_000, 8_000, 16_000, 32_000, 64_000, 128_000, 256_000, 300_000, 300_000,
        ];
        for (attempts, want) in (1..).zip(expected) {
            assert_eq!(retry_delay_ms(attempts, None), want, "attempts {attempts}");
        }
        assert_eq!(retry_delay_ms(u64::MAX, None), 300_000);
    }

    #[test]
    fn retry_after_lengthens_but_never_shortens_backoff() {
        assert_eq!(retry_delay_ms(1, Some(120_000)), 120_000);
        assert_eq!(retry_delay_ms(1, Some(0)), 1_000);
        assert_eq!(retry_delay_ms(5, Some(1_000)), 16_000);
        assert_eq!(retry_delay_ms(1, Some(u64::MAX)), 86_400_000);
    }

    #[test]
    fn retry_after_date_is_relative_to_now() {
        let now = 1_700_000_000_000;
        let at = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_090);
        assert_eq!(retry_after_ms(RetryAfter::At(at), now), 90_000);
        let past = SystemTime::UNIX_EPOCH + Duration::from_secs(1_600_000_000);
        assert_eq!(retry_after_ms(RetryAfter::At(past), now), 0);
        assert_eq!(
            retry_after_ms(RetryAfter::Delay(Duration::from_secs(u64::MAX)), now),
            u64::MAX
        );
    }
}
