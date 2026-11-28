//! Refusals a sender could otherwise write the log with (bead
//! mimid-sami): a counter for every one, and a line for the first of
//! each kind in a window.
//!
//! Eight events fire once per item on a path whose volume someone else
//! decides. A peer that refuses every delivery, a sender that submits
//! ten thousand messages whose expiry has passed, or a client that sends
//! REHASH in a loop against a configuration file that does not parse,
//! would write a line each, at the level an operator watches.
//!
//! Each kept its name and its level, since they are what an operator
//! alerts on (`welcome_too_large` is docs/operating.md's own example),
//! and gained:
//!
//! - **a window.** [`Refusal::count`] says whether to log. The first
//!   refusal of a kind is logged in full; the next line of that kind
//!   comes no sooner than [`WINDOW`] later and carries `suppressed`,
//!   how many went uncounted in the log in between. A refusal of
//!   another kind is logged at once: the window is per kind.
//! - **a count.** `mimid.refusals`, by `event`, which every refusal
//!   bumps whether or not it is logged. [`install`] registers it, and
//!   [`crate::Telemetry::new`] calls that when metrics are configured.
//!   Without a collector the counts are kept and read by nobody.
//!
//! The count is by event and not by reason: at some of these sites the
//! reason is free text, and a metric label chosen by an unauthenticated
//! sender is what this crate's Limitations forbid. The reason stays a
//! field of the line, so the line that is logged still says which it
//! was.
//!
//! # Limitations
//!
//! - `suppressed` reaches the log on the next line of that kind. When
//!   the refusals stop, the count of the last window is in the metric
//!   only, so an operator who reads the log alone sees that it was
//!   happening but not the total.
//! - The window is per event, not per room, per sender or per reason: a
//!   peer refusing everything hides, for [`WINDOW`], another peer's
//!   refusal of the same kind. The metric still counts both.
//! - A process that lives less than [`WINDOW`] logs the first of each
//!   kind and nothing more.
//! - The counts and the windows are process-global, so a test that
//!   asserts on one of these lines must be the first thing in its test
//!   binary to provoke that kind.

use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use opentelemetry::KeyValue;
use opentelemetry::metrics::ObservableCounter;

/// How long after a refusal is logged the next line of that kind waits.
/// INVENTED, NOT FROM SPEC: short enough that an operator sees a problem
/// start, long enough that ten thousand refusals are not ten thousand
/// lines.
pub const WINDOW: Duration = Duration::from_secs(60);

/// A refusal that fires once per item on a path whose volume a sender,
/// a peer or a server decides.
///
/// The set is the registry: a new such event becomes a variant here, and
/// its `event` name is what the call site passes to `name:`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// mimid-agent-store: a received message the agent will not show the
    /// user, once per message (`sync`). The sender chooses how many.
    AgentMessageDiscarded,
    /// mimid-agent-jmap: a push entry that does not fit a push body,
    /// once per entry (`push_deliver`).
    AgentJmapPushTooLarge,
    /// mimid-agent-core: a live-stream frame that does not decode, once
    /// per frame (`stream`). An unknown type does not end the
    /// connection, so a server can send any number.
    LiveStreamFrameRefused,
    /// mimid-server: a fanout row a peer refused for good, once per row
    /// (`hub::fanout`).
    FanoutDeliveryRefused,
    /// mimid-server: a hub's refusal of a catch-up request, once per
    /// attempt per room (`follower::notify`).
    CatchUpRefused,
    /// mimid-server: a GroupInfo answer too large for one body, once per
    /// request (`hub::group_info`).
    GroupInfoTooLarge,
    /// mimid-server: a Commit whose Welcome cannot reach the new
    /// members, once per Commit (`hub::update`).
    WelcomeTooLarge,
    /// mimid-agent: a configuration file that could not be read or
    /// parsed again, once per attempt (`reload`). A registered IRC
    /// client decides how many by sending REHASH.
    AgentConfigReloadRefused,
}

impl Refusal {
    /// Every refusal, in the order their counts are observed.
    pub const ALL: [Self; 8] = [
        Self::AgentMessageDiscarded,
        Self::AgentJmapPushTooLarge,
        Self::LiveStreamFrameRefused,
        Self::FanoutDeliveryRefused,
        Self::CatchUpRefused,
        Self::GroupInfoTooLarge,
        Self::WelcomeTooLarge,
        Self::AgentConfigReloadRefused,
    ];

    /// The stable event name of the line this refusal logs, and the
    /// value of the counter's `event` label.
    #[must_use]
    pub const fn event(self) -> &'static str {
        match self {
            Self::AgentMessageDiscarded => "agent_message_discarded",
            Self::AgentJmapPushTooLarge => "agent_jmap_push_too_large",
            Self::LiveStreamFrameRefused => "live_stream_frame_refused",
            Self::FanoutDeliveryRefused => "fanout_delivery_refused",
            Self::CatchUpRefused => "catch_up_refused",
            Self::GroupInfoTooLarge => "group_info_too_large",
            Self::WelcomeTooLarge => "welcome_too_large",
            Self::AgentConfigReloadRefused => "agent_config_reload_refused",
        }
    }

    /// Counts this refusal and says whether to log it: `Some(n)` to log
    /// it, with `n` the number suppressed since the last line of this
    /// kind, and `None` when one was logged less than [`WINDOW`] ago.
    ///
    /// The count is kept either way, so `None` loses the item from the
    /// log and not from `mimid.refusals`.
    #[must_use]
    pub fn count(self) -> Option<u64> {
        self.counted().count_at(now_ms())
    }

    /// How many of this refusal the process has counted, for a test.
    #[doc(hidden)]
    #[must_use]
    pub fn total(self) -> u64 {
        self.counted().total.load(Ordering::Relaxed)
    }

    fn counted(self) -> &'static Counted {
        static TABLE: [Counted; Refusal::ALL.len()] =
            [const { Counted::new() }; Refusal::ALL.len()];
        // `as usize` is the discriminant, and the table has one entry
        // per variant.
        &TABLE[self as usize]
    }
}

/// One refusal's count and window.
struct Counted {
    /// Every refusal counted, which is what the metric reports.
    total: AtomicU64,
    /// Counted but not logged since the last line, which the next line
    /// carries.
    suppressed: AtomicU64,
    /// When the last line was written, in milliseconds since the first
    /// call to [`now_ms`], or [`Counted::NEVER`].
    last_ms: AtomicU64,
}

impl Counted {
    /// `last_ms` before any line of this kind. Not zero: at zero the
    /// first refusal of a process's first minute would be suppressed.
    const NEVER: u64 = u64::MAX;

    const fn new() -> Self {
        Self {
            total: AtomicU64::new(0),
            suppressed: AtomicU64::new(0),
            last_ms: AtomicU64::new(Self::NEVER),
        }
    }

    /// [`Refusal::count`] at `now`, in the same milliseconds.
    fn count_at(&self, now: u64) -> Option<u64> {
        self.total.fetch_add(1, Ordering::Relaxed);
        let last = self.last_ms.load(Ordering::Relaxed);
        let due = last == Self::NEVER || now.saturating_sub(last) >= window_ms();
        // The exchange, not the load, decides: of two threads that both
        // find the window open, one takes the line and the other is
        // suppressed, rather than both logging.
        if due
            && self
                .last_ms
                .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
        {
            return Some(self.suppressed.swap(0, Ordering::Relaxed));
        }
        self.suppressed.fetch_add(1, Ordering::Relaxed);
        None
    }
}

fn window_ms() -> u64 {
    u64::try_from(WINDOW.as_millis()).unwrap_or(u64::MAX)
}

/// Milliseconds since this function was first called. Monotonic, so a
/// clock the operator moves cannot close or reopen a window.
fn now_ms() -> u64 {
    static START: OnceLock<Instant> = OnceLock::new();
    u64::try_from(START.get_or_init(Instant::now).elapsed().as_millis()).unwrap_or(u64::MAX)
}

/// Registers `mimid.refusals`, a counter of every refusal by `event`,
/// read from the counts at each collection. Nothing is returned: the
/// callback lives in the meter provider, and the instrument handle is a
/// marker with no state of its own.
///
/// It is not `mimid.hub.update.refusals`, which counts the hub's refused
/// update requests by reason. This counts the events of [`Refusal`],
/// whose lines are rate limited, so that a refusal left out of the log
/// is still in a number.
pub fn install() {
    let _counter: ObservableCounter<u64> = opentelemetry::global::meter("mimid")
        .u64_observable_counter("mimid.refusals")
        .with_description("Refusals, by the event that logs them")
        .with_callback(|observer| {
            for refusal in Refusal::ALL {
                observer.observe(refusal.total(), &[KeyValue::new("event", refusal.event())]);
            }
        })
        .build();
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    /// The window on its own clock: the first is logged, the rest are
    /// counted, and the line after the window carries how many.
    #[test]
    fn one_line_per_window_carries_what_it_left_out() {
        let counted = Counted::new();
        assert_eq!(counted.count_at(0), Some(0), "the first is always logged");
        for at in [1, 2, 500, 59_999] {
            assert_eq!(counted.count_at(at), None, "within the window at {at}");
        }
        assert_eq!(
            counted.count_at(60_000),
            Some(4),
            "the window is over, and the four suppressed are reported"
        );
        assert_eq!(counted.count_at(60_001), None);
        assert_eq!(
            counted.count_at(240_000),
            Some(1),
            "a later window reports only what it suppressed"
        );
        assert_eq!(
            counted.total.load(Ordering::Relaxed),
            8,
            "every one counted"
        );
    }

    /// A refusal of one kind does not close another kind's window, and
    /// each counts for itself.
    #[test]
    fn each_kind_has_its_own_window_and_count() {
        let first = Refusal::GroupInfoTooLarge;
        let second = Refusal::WelcomeTooLarge;
        let before = (first.total(), second.total());
        assert!(first.count().is_some(), "the first of this kind");
        assert_eq!(
            second.count(),
            Some(0),
            "another kind is logged at once, not suppressed"
        );
        assert_eq!(first.count(), None, "the kind's own window is now closed");
        assert_eq!(first.total(), before.0 + 2);
        assert_eq!(second.total(), before.1 + 1);
    }

    /// The names are the registry: all distinct, and spelled as the
    /// `name:` of an event (lower snake case).
    #[test]
    fn every_event_name_is_distinct_and_snake_case() {
        let names: BTreeSet<&str> = Refusal::ALL.iter().map(|r| r.event()).collect();
        assert_eq!(names.len(), Refusal::ALL.len());
        for name in names {
            assert!(
                name.chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'),
                "{name}"
            );
        }
    }
}
