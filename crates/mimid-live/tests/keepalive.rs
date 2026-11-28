//! The keepalive's pacing and failure rules
//! (draft-atwood-mimi-keepalive-00 §4.1, §4.3, §4.4; bead mimid-mm42).
//! Each test counts steps and compares durations the prober was given; no
//! test reads a clock or sleeps.

use std::time::Duration;

use mimid_live::keepalive::{
    JITTER_HIGH_PERMILLE, JITTER_LOW_PERMILLE, MAX_KEEPALIVE_SECONDS, Outcome,
    PACING_FLOOR_DENOMINATOR, PACING_FLOOR_NUMERATOR, PROBES_PER_IDLE, Prober, UNANSWERED_PROBES,
};
use mimid_live::{Keepalive, MAX_IDLE, PING_AFTER};

fn pair(min: u64, max: u64) -> Keepalive {
    Keepalive::new(min, max).expect("a usable pair")
}

/// The smallest `maxIdleSeconds` the rule of §4.1 accepts beside `min`:
/// one more than the largest it refuses, the comparison being strict.
fn smallest_idle(min: u64) -> u64 {
    PACING_FLOOR_NUMERATOR * min / PACING_FLOOR_DENOMINATOR + 1
}

/// The pacing floor of §4.1 is what §4.3 asks of a base period, not a
/// number chosen beside it: PROBES_PER_IDLE periods to an idle period,
/// each period at 1000/JITTER_LOW_PERMILLE minimum intervals, which is
/// 3 x 1.25 = 15/4 (bead mimid-f9x4.1).
#[test]
fn the_pacing_floor_follows_from_the_jitter() {
    assert_eq!(
        PACING_FLOOR_NUMERATOR * JITTER_LOW_PERMILLE,
        PACING_FLOOR_DENOMINATOR * PROBES_PER_IDLE * 1_000
    );
}

/// What mimid offers satisfies the rule it enforces (§4.1).
#[test]
fn the_offered_pair_is_usable() {
    let offered = pair(PING_AFTER.as_secs(), MAX_IDLE.as_secs());
    assert_eq!(Keepalive::default(), offered);
    assert!(
        PACING_FLOOR_NUMERATOR * offered.min_interval_seconds()
            < PACING_FLOOR_DENOMINATOR * offered.max_idle_seconds(),
        "{offered:?}"
    );
    // The cadence stays under the 60 seconds where a NAT reaps an idle
    // carrier, jitter included.
    let longest = offered.period().as_millis() * u128::from(JITTER_HIGH_PERMILLE) / 1_000;
    assert!(longest < 60_000, "{longest} ms");
}

/// §4.3 puts two conditions on the base period P: every interval
/// jittered out of P is at least `minIntervalSeconds`, and
/// `PROBES_PER_IDLE * P` is under `maxIdleSeconds`. Both hold for every
/// pair the rule of §4.1 accepts, and a pair under that rule's floor is
/// no pair at all.
#[test]
fn the_period_is_inside_the_pair() {
    for min in [1, 2, 7, 30, 3_600] {
        // One second under the floor. For min 2 that is 7, which is
        // PROBES_PER_IDLE x 2 + 1: the pair bead mimid-f9x4.1 found,
        // inside which no legal P exists.
        let refused = smallest_idle(min) - 1;
        assert!(
            Keepalive::new(min, refused).is_err(),
            "{min} and {refused} is under the floor"
        );
        for max in [
            smallest_idle(min),
            smallest_idle(min) + 1,
            4 * min,
            100 * min,
            MAX_KEEPALIVE_SECONDS,
        ] {
            if max > MAX_KEEPALIVE_SECONDS {
                continue;
            }
            let keepalive = pair(min, max);
            let period = keepalive.period().as_millis();
            let lowest = period * u128::from(JITTER_LOW_PERMILLE) / 1_000;
            assert!(
                lowest >= u128::from(min) * 1_000,
                "{min} and {max}: P is {period} ms, jittered down to {lowest} ms"
            );
            assert!(
                u128::from(PROBES_PER_IDLE) * period < u128::from(max) * 1_000,
                "{min} and {max}: P is {period} ms"
            );
            // The largest such millisecond, so one more breaks the rule.
            assert!(
                u128::from(PROBES_PER_IDLE) * (period + 1) >= u128::from(max) * 1_000,
                "{min} and {max}: P is {period} ms, not the largest"
            );
        }
    }
}

/// The rule of §4.1 and the two conditions of §4.3 agree over every
/// small pair: each pair the rule accepts has a legal P, and the P
/// chosen is legal. A pair that satisfied the floor while admitting no
/// legal P is what bead mimid-f9x4.1 found, so the agreement is asserted
/// over a range rather than over the pairs named above.
#[test]
fn every_accepted_small_pair_has_a_legal_period() {
    let mut accepted = 0;
    for min in 1..=64 {
        for max in 1..=1_024 {
            let Ok(keepalive) = Keepalive::new(min, max) else {
                continue;
            };
            accepted += 1;
            let period = keepalive.period().as_millis();
            let lowest = period * u128::from(JITTER_LOW_PERMILLE) / 1_000;
            assert!(
                lowest >= u128::from(min) * 1_000,
                "{min} and {max}: P is {period} ms, jittered down to {lowest} ms"
            );
            assert!(
                u128::from(PROBES_PER_IDLE) * period < u128::from(max) * 1_000,
                "{min} and {max}: P is {period} ms"
            );
        }
    }
    assert!(accepted > 10_000, "{accepted} pairs accepted");
}

/// §4.3: each interval is P randomized between 0.8 and 1.2 of its value.
/// The bounds hold for every draw, and the range is used: with one seed,
/// 2000 intervals come within a hundredth of each end.
#[test]
fn every_interval_is_inside_the_jitter() {
    let keepalive = pair(30, 120);
    let period = keepalive.period().as_millis();
    let low = period * u128::from(JITTER_LOW_PERMILLE) / 1_000;
    let high = period * u128::from(JITTER_HIGH_PERMILLE) / 1_000;
    let mut prober = Prober::new(Some(keepalive), 0x5eed);
    let mut seen_low = high;
    let mut seen_high = low;
    for step in 0..2_000 {
        let wait = prober.wait().expect("a pair probes").as_millis();
        assert!(wait >= low, "step {step}: {wait} ms under {low}");
        assert!(wait <= high, "step {step}: {wait} ms over {high}");
        seen_low = seen_low.min(wait);
        seen_high = seen_high.max(wait);
        prober.heard();
    }
    assert!(seen_low <= low + (high - low) / 100, "{seen_low} ms");
    assert!(seen_high >= high - (high - low) / 100, "{seen_high} ms");
}

/// Two probers of the same pair with different seeds do not probe
/// together, which is what the jitter is for (§4.3).
#[test]
fn two_probers_do_not_share_their_intervals() {
    let keepalive = pair(30, 120);
    let mut one = Prober::new(Some(keepalive), 1);
    let mut two = Prober::new(Some(keepalive), 2);
    let mut same = 0;
    for _ in 0..100 {
        if one.wait() == two.wait() {
            same += 1;
        }
        one.heard();
        two.heard();
    }
    assert!(same < 50, "{same} of 100 intervals were equal");
}

/// §4.3: a prober that holds no pair must not probe. It also never
/// declares the carrier dead: it has nothing to measure.
#[test]
fn a_prober_with_no_pair_does_not_probe() {
    let mut prober = Prober::new(None, 7);
    assert_eq!(prober.wait(), None);
    assert!(prober.pair().is_none());
    for _ in 0..10 {
        assert_eq!(prober.quiet(), Outcome::Nothing);
        assert_eq!(prober.wait(), None);
        assert_eq!(prober.unanswered(), 0);
    }
}

/// §4.4: one unanswered probe does not kill a carrier, and the second
/// does not either until the idle tolerance is spent; nothing heard for
/// `maxIdleSeconds` does.
#[test]
fn a_carrier_dies_on_the_second_unanswered_probe_and_the_idle_tolerance() {
    let keepalive = pair(1, 10);
    let mut prober = Prober::new(Some(keepalive), 3);
    let mut idle = Duration::ZERO;
    let mut probes = 0;
    loop {
        let wait = prober.wait().expect("a pair probes");
        match prober.quiet() {
            Outcome::Probe => {
                idle += wait;
                probes += 1;
                assert_eq!(prober.unanswered(), probes);
                assert!(
                    idle < keepalive.max_idle() || probes < UNANSWERED_PROBES,
                    "dead after {probes} probes and {idle:?}"
                );
            }
            Outcome::Dead => {
                idle += wait;
                // The derivation of PROBES_PER_IDLE (§4.1): by the time
                // the idle tolerance is spent, two probes have gone
                // unanswered.
                assert!(probes >= UNANSWERED_PROBES, "{probes} probes");
                assert!(idle >= keepalive.max_idle(), "{idle:?}");
                return;
            }
            other => panic!("{other:?}"),
        }
        assert!(probes < 100, "the carrier never died");
    }
}

/// Anything heard answers the probes outstanding, so a carrier that
/// answers one probe in every two is never declared dead (§4.4).
#[test]
fn a_carrier_that_answers_lives() {
    let mut prober = Prober::new(Some(pair(1, 10)), 11);
    for step in 0..100 {
        assert!(prober.wait().is_some());
        assert_eq!(prober.quiet(), Outcome::Probe, "step {step}");
        assert_eq!(prober.unanswered(), 1);
        prober.heard();
        assert_eq!(prober.unanswered(), 0);
    }
}

/// The first probe of a carrier is one probe, not a death: §4.4's "MUST
/// NOT declare a carrier dead on a single unanswered probe" holds however
/// short the pair is.
#[test]
fn the_first_quiet_period_only_probes() {
    for (min, max) in [(1, 4), (30, 113), (1, MAX_KEEPALIVE_SECONDS)] {
        let mut prober = Prober::new(Some(pair(min, max)), 13);
        assert_eq!(prober.quiet(), Outcome::Probe, "{min} and {max}");
        assert_eq!(prober.unanswered(), 1);
        assert_eq!(prober.quiet(), Outcome::Probe, "{min} and {max}");
        assert_eq!(prober.unanswered(), UNANSWERED_PROBES);
    }
}
