//! Following the server's EventSource (RFC 8620 §7.3) to wake the sync
//! loop: each StateChange that names a type the sync reads
//! ([`SYNC_TYPES`]) notifies [`Store::sync_wanted`], and so does each
//! (re)connection, since changes made while the stream was down are not
//! replayed (mimid-server sets no event IDs). The stream only says when;
//! [`Store::sync`] alone reads what, so it stays the agent's only journal
//! consumer.
//!
//! A stream that cannot be opened, or ends, is tried again after a delay
//! that doubles from [`RETRY_MIN`] to [`RETRY_MAX`], with equal jitter,
//! back to [`RETRY_MIN`] once a stream has delivered an event. Meanwhile
//! the sync loop's interval (`sync_interval_ms`) keeps polling.

use std::sync::Arc;
use std::time::Duration;

use mimid_agent_core::AgentError;
use mimid_agent_core::push::{PushEvent, PushSource, PushStream, SYNC_TYPES};
use mimid_agent_store::Store;
use tokio::sync::watch;

use crate::http::stopped;

/// The first delay before opening the stream again. INVENTED, NOT FROM
/// SPEC.
pub const RETRY_MIN: Duration = Duration::from_secs(1);

/// The longest delay before opening the stream again. INVENTED, NOT FROM
/// SPEC.
pub const RETRY_MAX: Duration = Duration::from_secs(60);

/// How a stream ended.
enum Ended {
    /// The daemon is stopping.
    Stopped,
    /// The server closed it or it failed; whether it delivered an event
    /// first.
    Lost { delivered: bool },
}

/// Follows `source` until `stop` is true, waking `store`'s sync.
pub(crate) async fn follow(store: Arc<Store>, source: PushSource, mut stop: watch::Receiver<bool>) {
    let sync_now = Arc::clone(store.sync_wanted());
    let mut delay = RETRY_MIN;
    let mut last_event_id: Option<String> = None;
    // Whether a failure to open is news (the first one, at start), so that
    // only a change between up and down is logged above DEBUG; a lost
    // stream is logged when it is lost.
    let mut up = true;
    loop {
        let opened = tokio::select! {
            () = stopped(&mut stop) => return,
            opened = source.open(&SYNC_TYPES, last_event_id.as_deref()) => opened,
        };
        match opened {
            Ok(mut stream) => {
                tracing::info!(name: "agent_push_connected", "following the server's EventSource");
                // What changed while no stream was open.
                sync_now.notify_one();
                let ended = read(&mut stream, &sync_now, &mut stop).await;
                last_event_id = stream.last_event_id().map(str::to_owned);
                // The loss is logged; failures to reopen are not, until
                // a stream opens again.
                up = false;
                match ended {
                    Ended::Stopped => return,
                    Ended::Lost { delivered } => {
                        if delivered {
                            delay = RETRY_MIN;
                        }
                    }
                }
            }
            Err(error) => {
                if up {
                    log_down(&error);
                } else {
                    tracing::debug!(
                        error = &error as &dyn std::error::Error,
                        "the server's EventSource is still unavailable"
                    );
                }
                up = false;
            }
        }
        tokio::select! {
            () = stopped(&mut stop) => return,
            () = tokio::time::sleep(jitter(delay)) => {}
        }
        delay = (delay * 2).min(RETRY_MAX);
    }
}

/// Reads `stream` until it ends or the daemon stops, waking the sync for
/// each StateChange naming a [`SYNC_TYPES`] type.
async fn read(
    stream: &mut PushStream,
    sync_now: &tokio::sync::Notify,
    stop: &mut watch::Receiver<bool>,
) -> Ended {
    let mut delivered = false;
    loop {
        let next = tokio::select! {
            () = stopped(stop) => return Ended::Stopped,
            next = stream.next() => next,
        };
        match next {
            Ok(Some(PushEvent::State(types))) => {
                delivered = true;
                if SYNC_TYPES.iter().any(|t| types.contains(*t)) {
                    sync_now.notify_one();
                }
            }
            Ok(Some(_)) => delivered = true,
            Ok(None) => {
                tracing::info!(
                    name: "agent_push_closed",
                    "the server closed its EventSource; polling until it reopens"
                );
                return Ended::Lost { delivered };
            }
            Err(error) => {
                log_down(&error);
                return Ended::Lost { delivered };
            }
        }
    }
}

fn log_down(error: &AgentError) {
    tracing::warn!(
        name: "agent_push_failed",
        error = error as &dyn std::error::Error,
        "the server's EventSource is unavailable; polling until it reopens"
    );
}

/// A delay drawn uniformly from `[delay / 2, delay]` (equal jitter), so
/// that the agents of a restarted server do not all come back at once.
fn jitter(delay: Duration) -> Duration {
    let mut bytes = [0; 4];
    // Without randomness, the full delay.
    if getrandom::fill(&mut bytes).is_err() {
        return delay;
    }
    let half = delay / 2;
    half + half.mul_f64(f64::from(u32::from_le_bytes(bytes)) / f64::from(u32::MAX))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jitter_stays_between_half_and_whole() {
        for _ in 0..1000 {
            let got = jitter(RETRY_MAX);
            assert!(got >= RETRY_MAX / 2 && got <= RETRY_MAX, "{got:?}");
        }
    }
}
