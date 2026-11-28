//! The keepalive's two intervals: what a responder states in its hello,
//! and how a prober paces itself inside them
//! (draft-atwood-mimi-keepalive-00 §4.1, §4.3 and §4.4, the draft held in
//! bead mimid-f9x4's design field; decision mimid-1wgh.137).
//!
//! - [`Keepalive`] is the pair. Only [`Keepalive::new`] builds one, so a
//!   pair that leaves a prober no base period it may legally pace itself
//!   by cannot be held at all: the decoder refuses the hello that
//!   carried it.
//! - [`Prober`] is the pacing: how long to stay quiet, when to probe and
//!   when the carrier is dead. A prober that holds no pair never probes
//!   (§4.3).
//!
//! The probe itself is elsewhere: on the live stream it is a WebSocket
//! Ping (RFC 6455 §5.5.2; decision mimid-1wgh.133), which the caller
//! sends, and anything at all arriving from the far end answers it.

use std::time::Duration;

/// How many base periods one idle period must hold: a prober chooses P
/// with `PROBES_PER_IDLE * P` less than `maxIdleSeconds` (§4.3). Two
/// probes paced at up to 1.2 of the period account for 2.4 of it; the
/// remaining 0.6 is the budget for the second answer to arrive, so the
/// arithmetic cannot call a carrier alive while it is being reaped.
pub const PROBES_PER_IDLE: u64 = 3;

/// The pacing floor of §4.1 as a fraction, of which this is the
/// numerator: one idle period must hold more than
/// `PACING_FLOOR_NUMERATOR / PACING_FLOOR_DENOMINATOR` minimum
/// intervals, so a pair leaves a prober room to pace itself legally when
/// `PACING_FLOOR_NUMERATOR * minIntervalSeconds` is less than
/// `PACING_FLOOR_DENOMINATOR * maxIdleSeconds`.
///
/// The ratio is 15/4, which is 3.75, in integers because both values are
/// whole seconds, and it is derived rather than chosen:
/// [`PROBES_PER_IDLE`] base periods to an idle period, and a base period
/// of 1000/[`JITTER_LOW_PERMILLE`] minimum intervals, because §4.3 puts
/// the floor on the jittered interval and not on the period. A narrower
/// pair leaves no period a prober may legally choose (bead
/// mimid-f9x4.1).
pub const PACING_FLOOR_NUMERATOR: u64 = 15;

/// The denominator of [`PACING_FLOOR_NUMERATOR`]'s ratio (§4.1).
pub const PACING_FLOOR_DENOMINATOR: u64 = 4;

/// How many probes go unanswered before a carrier is dead (§4.4): one
/// lost probe, or one lost answer, is an ordinary event.
pub const UNANSWERED_PROBES: u32 = 2;

/// The largest either value may be, in seconds: a day. INVENTED, NOT FROM
/// SPEC, since the draft states no bound. A parse-time cap keeps the
/// arithmetic on a hostile hello in range (AGENTS.md "Every size, depth
/// and count limit is a named constant").
pub const MAX_KEEPALIVE_SECONDS: u64 = 24 * 60 * 60;

/// The low end of the jitter, in thousandths of the period: each interval
/// is the period randomized between 0.8 and 1.2 of its value, so that
/// probers do not synchronize (§4.3, the pacing rule of RFC 7675 §5.1).
pub const JITTER_LOW_PERMILLE: u64 = 800;

/// The high end of the jitter, in thousandths of the period (§4.3).
pub const JITTER_HIGH_PERMILLE: u64 = 1200;

/// Why a pair of intervals is not usable
/// (draft-atwood-mimi-keepalive-00 §4.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum KeepaliveError {
    /// §4.1: a responder states both as non-zero.
    #[error("{name} is zero")]
    Zero {
        /// Which member.
        name: &'static str,
    },
    /// Past [`MAX_KEEPALIVE_SECONDS`].
    #[error("{name} is {seconds} seconds, past the {MAX_KEEPALIVE_SECONDS} accepted")]
    TooLong {
        /// Which member.
        name: &'static str,
        /// What it said.
        seconds: u64,
    },
    /// §4.1: the idle tolerance leaves no base period a prober may
    /// legally pace itself by.
    #[error(
        "{PACING_FLOOR_NUMERATOR} x minIntervalSeconds ({min}) is not less than \
         {PACING_FLOOR_DENOMINATOR} x maxIdleSeconds ({max})"
    )]
    NoRoom {
        /// `minIntervalSeconds`.
        min: u64,
        /// `maxIdleSeconds`.
        max: u64,
    },
    /// One of the pair without the other, which states nothing usable.
    #[error("{present} without {missing}")]
    Half {
        /// The member present.
        present: &'static str,
        /// The member absent.
        missing: &'static str,
    },
}

/// What a responder states: the shortest interval between probes it
/// undertakes to answer (`minIntervalSeconds`) and the longest it will
/// leave an idle carrier open (`maxIdleSeconds`), both in seconds
/// (draft-atwood-mimi-keepalive-00 §4.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Keepalive {
    min_interval_seconds: u64,
    max_idle_seconds: u64,
}

/// The offered pair satisfies the pacing floor, checked when this crate is
/// compiled rather than when a test runs, because [`Default`] builds the pair
/// without [`Keepalive::new`] and so is not checked by it.
const _: () = assert!(
    crate::PING_AFTER.as_secs() * PACING_FLOOR_NUMERATOR
        < crate::MAX_IDLE.as_secs() * PACING_FLOOR_DENOMINATOR,
    "the offered keepalive pair leaves a prober no base period it may legally choose"
);

impl Default for Keepalive {
    /// What mimid offers: [`crate::PING_AFTER`] and [`crate::MAX_IDLE`].
    ///
    /// Infallible, and the `const` assertion above is why: the pair cannot
    /// reach a build that breaks the rule [`Keepalive::new`] enforces.
    fn default() -> Self {
        Self {
            min_interval_seconds: crate::PING_AFTER.as_secs(),
            max_idle_seconds: crate::MAX_IDLE.as_secs(),
        }
    }
}

impl Keepalive {
    /// The pair a responder states.
    ///
    /// # Errors
    ///
    /// [`KeepaliveError`]: either value zero or past
    /// [`MAX_KEEPALIVE_SECONDS`], or an idle tolerance under the pacing
    /// floor of [`PACING_FLOOR_NUMERATOR`] (§4.1).
    pub fn new(min_interval_seconds: u64, max_idle_seconds: u64) -> Result<Self, KeepaliveError> {
        for (name, seconds) in [
            ("minIntervalSeconds", min_interval_seconds),
            ("maxIdleSeconds", max_idle_seconds),
        ] {
            if seconds == 0 {
                return Err(KeepaliveError::Zero { name });
            }
            if seconds > MAX_KEEPALIVE_SECONDS {
                return Err(KeepaliveError::TooLong { name, seconds });
            }
        }
        // In u128 because the wire carries any u64 and
        // PACING_FLOOR_NUMERATOR x minIntervalSeconds overflows u64 for a
        // large one. The cap above returns first for such a value; this
        // comparison is exact for every pair of u64s rather than
        // depending on that.
        if u128::from(min_interval_seconds) * u128::from(PACING_FLOOR_NUMERATOR)
            >= u128::from(max_idle_seconds) * u128::from(PACING_FLOOR_DENOMINATOR)
        {
            return Err(KeepaliveError::NoRoom {
                min: min_interval_seconds,
                max: max_idle_seconds,
            });
        }
        Ok(Self {
            min_interval_seconds,
            max_idle_seconds,
        })
    }

    /// `minIntervalSeconds`.
    pub fn min_interval_seconds(&self) -> u64 {
        self.min_interval_seconds
    }

    /// `maxIdleSeconds`.
    pub fn max_idle_seconds(&self) -> u64 {
        self.max_idle_seconds
    }

    /// `minIntervalSeconds` as a duration.
    pub fn min_interval(&self) -> Duration {
        Duration::from_secs(self.min_interval_seconds)
    }

    /// `maxIdleSeconds` as a duration.
    pub fn max_idle(&self) -> Duration {
        Duration::from_secs(self.max_idle_seconds)
    }

    /// The base period P a prober paces itself by: the largest whole
    /// millisecond satisfying both conditions §4.3 puts on P, that
    /// `PROBES_PER_IDLE * P` is under `maxIdleSeconds` and that every
    /// jittered interval is at least `minIntervalSeconds`.
    ///
    /// The largest rather than the smallest, because the floor is on the
    /// jittered interval and not on P: at P = `minIntervalSeconds` the
    /// 0.8 end of the jitter puts one interval in five sooner than the
    /// responder undertook to answer, which §4.3 lets a responder refuse
    /// as `tooFrequent` (bead mimid-f9x4.1; decision mimid-1wgh.137).
    ///
    /// Whole milliseconds, because a legal pair need not admit a legal
    /// whole second: 1 and 6 leaves P between 1.25 and 2 seconds.
    pub fn period(&self) -> Duration {
        Duration::from_millis(self.period_millis())
    }

    /// [`Keepalive::period`] in whole milliseconds.
    fn period_millis(&self) -> u64 {
        // The largest P with PROBES_PER_IDLE x P under maxIdleSeconds.
        // In range: maxIdleSeconds is at most MAX_KEEPALIVE_SECONDS, so
        // this is at most 86_400_000.
        //
        // That P is also at or above the jitter's floor, 1000 /
        // JITTER_LOW_PERMILLE of minIntervalSeconds, for every pair
        // Keepalive::new accepts: the floor in milliseconds is
        // 1_250 x minIntervalSeconds, and it is itself a legal P exactly
        // when 3 x 1_250 x minIntervalSeconds is under
        // 1_000 x maxIdleSeconds, which is the rule of
        // PACING_FLOOR_NUMERATOR with both sides divided by 250.
        let millis = self.max_idle_seconds.saturating_mul(1_000);
        millis.saturating_sub(1) / PROBES_PER_IDLE
    }

    /// One interval: [`Keepalive::period`] randomized between
    /// [`JITTER_LOW_PERMILLE`] and [`JITTER_HIGH_PERMILLE`] thousandths
    /// of its value, from any `random` (§4.3).
    pub fn interval(&self, random: u64) -> Duration {
        let span = JITTER_HIGH_PERMILLE - JITTER_LOW_PERMILLE + 1;
        let permille = JITTER_LOW_PERMILLE + random % span;
        // In range: the period is under 86_400_000 ms, so this is under
        // 86_400_000 x 1_200.
        let millis = self.period_millis();
        Duration::from_millis(millis.saturating_mul(permille) / 1_000)
    }
}

/// What a prober does when its quiet period has elapsed with nothing
/// heard from the far end.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Outcome {
    /// Send one probe, then wait [`Prober::wait`] again.
    Probe,
    /// The carrier is dead (§4.4): [`UNANSWERED_PROBES`] probes went
    /// unanswered and the responder's idle tolerance is spent. Stop
    /// sending on it.
    Dead,
    /// Nothing: this prober holds no pair, so it must not probe (§4.3).
    /// [`Prober::wait`] is `None` for it, so a caller that waits on that
    /// never reaches this.
    Nothing,
}

/// The pacing of one carrier's probes: the intervals of §4.3 and the
/// failure rule of §4.4.
///
/// A prober built with no pair never probes and never declares the
/// carrier dead, since it has no pacing the far end undertook to answer
/// (§4.3).
#[derive(Debug, Clone)]
pub struct Prober {
    pair: Option<Keepalive>,
    /// The jitter's state, seeded once per carrier.
    state: u64,
    /// The current quiet period, meaningless without a pair.
    wait: Duration,
    /// Probes sent since anything was last heard.
    unanswered: u32,
    /// Quiet periods elapsed since anything was last heard.
    idle: Duration,
}

impl Prober {
    /// A prober of `pair`, jittering from `seed`.
    ///
    /// `seed` need not be unpredictable: the jitter's only job is that
    /// many probers do not synchronize, so a seed per carrier from the
    /// system's randomness is enough (decision mimid-1wgh.137).
    pub fn new(pair: Option<Keepalive>, seed: u64) -> Self {
        let mut prober = Self {
            pair,
            state: seed,
            wait: Duration::ZERO,
            unanswered: 0,
            idle: Duration::ZERO,
        };
        prober.arm();
        prober
    }

    /// The pair this prober holds, if any.
    pub fn pair(&self) -> Option<&Keepalive> {
        self.pair.as_ref()
    }

    /// How long to stay quiet before the next [`Prober::quiet`], or
    /// `None` for a prober that must not probe at all (§4.3).
    pub fn wait(&self) -> Option<Duration> {
        self.pair.is_some().then_some(self.wait)
    }

    /// Probes sent since anything was last heard.
    pub fn unanswered(&self) -> u32 {
        self.unanswered
    }

    /// Anything at all arrived from the far end: the outstanding probes
    /// are answered and the idle period starts again.
    pub fn heard(&mut self) {
        self.unanswered = 0;
        self.idle = Duration::ZERO;
        self.arm();
    }

    /// The quiet period elapsed with nothing heard.
    pub fn quiet(&mut self) -> Outcome {
        let Some(pair) = self.pair else {
            return Outcome::Nothing;
        };
        self.idle = self.idle.saturating_add(self.wait);
        if self.unanswered >= UNANSWERED_PROBES && self.idle >= pair.max_idle() {
            return Outcome::Dead;
        }
        self.unanswered = self.unanswered.saturating_add(1);
        self.arm();
        Outcome::Probe
    }

    /// Draws the next quiet period.
    fn arm(&mut self) {
        if let Some(pair) = self.pair {
            self.wait = pair.interval(self.next_random());
        }
    }

    /// SplitMix64, by Steele, Lea and Flood (2014). Not cryptographic:
    /// see [`Prober::new`].
    fn next_random(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
}
