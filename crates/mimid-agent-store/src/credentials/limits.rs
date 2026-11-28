//! Failed logins and unauthenticated connections, per source address
//! (docs/design/frontend-auth.md §7.1). Every value here is INVENTED, NOT
//! FROM SPEC.
//!
//! - **No lockout.** A credential is never disabled for failed logins.
//! - **A slowdown per source.** After [`FAILURES_BEFORE_SLOWING`] failed
//!   logins from one source in [`FAILURE_WINDOW`] ([`LOOPBACK_FAILURES`]
//!   from loopback), each further failure is answered after a delay,
//!   [`FIRST_DELAY`] doubling up to [`MAX_DELAY`]; a success from the
//!   source forgets its failures. IPv6 sources are counted per /64.
//! - **Unauthenticated connections are capped**: [`MAX_UNAUTHENTICATED`] in
//!   all and [`MAX_UNAUTHENTICATED_PER_SOURCE`] per source, each to log in
//!   within [`LOGIN_WITHIN`].
//!
//! # Limitations
//!
//! - Counts are in memory: a restart forgets them.
//! - At most [`MAX_SOURCES`] sources are tracked; past that the oldest
//!   window is dropped first.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

/// The window failures are counted in.
pub const FAILURE_WINDOW: Duration = Duration::from_secs(10 * 60);

/// Failures from one source in [`FAILURE_WINDOW`] before it is slowed.
pub const FAILURES_BEFORE_SLOWING: u32 = 5;

/// The same, from a loopback address, so a local script in a loop does
/// not slow the user's own clients for long.
pub const LOOPBACK_FAILURES: u32 = 20;

/// The delay of the first failure answered slowly.
pub const FIRST_DELAY: Duration = Duration::from_secs(1);

/// The longest delay.
pub const MAX_DELAY: Duration = Duration::from_secs(30);

/// Connections not yet logged in, in all.
pub const MAX_UNAUTHENTICATED: usize = 32;

/// Connections not yet logged in, per source.
pub const MAX_UNAUTHENTICATED_PER_SOURCE: usize = 8;

/// How long a connection has to log in.
pub const LOGIN_WITHIN: Duration = Duration::from_secs(30);

/// The most sources whose failures are tracked.
pub const MAX_SOURCES: usize = 4096;

/// A source: an IPv4 address, or an IPv6 /64.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct Source(u128);

impl Source {
    fn of(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(v4) => Self(u128::from(u32::from(v4))),
            IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
                Some(v4) => Self(u128::from(u32::from(v4))),
                // The /64, tagged with bit 63, which no IPv4 key has.
                None => Self((u128::from(v6) & !((1u128 << 64) - 1)) | 1u128 << 63),
            },
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct Failures {
    since: Instant,
    count: u32,
}

#[derive(Debug, Default)]
struct Inner {
    failures: HashMap<Source, Failures>,
    unauthenticated: HashMap<Source, usize>,
    total: usize,
}

/// What a failed login is to be answered with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Failure {
    /// How long to wait before the answer.
    pub delay: Duration,
    /// Whether this is the source's first failure in the window: log it
    /// at INFO, later ones at DEBUG.
    pub first: bool,
    /// Whether the source starts being slowed with this failure: log a
    /// WARN.
    pub slowing_starts: bool,
}

/// The counts of one agent, shared by its front ends.
#[derive(Debug, Default)]
pub struct Limiter {
    inner: Mutex<Inner>,
}

impl Limiter {
    /// A limiter with nothing counted.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn inner(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Counts a failed login from `ip` and says how to answer it.
    #[must_use]
    pub fn failed(&self, ip: IpAddr) -> Failure {
        let now = Instant::now();
        let source = Source::of(ip);
        let mut inner = self.inner();
        if inner.failures.len() >= MAX_SOURCES
            && !inner.failures.contains_key(&source)
            && let Some(oldest) = inner
                .failures
                .iter()
                .min_by_key(|(_, f)| f.since)
                .map(|(s, _)| *s)
        {
            inner.failures.remove(&oldest);
        }
        let entry = inner.failures.entry(source).or_insert(Failures {
            since: now,
            count: 0,
        });
        if now.duration_since(entry.since) > FAILURE_WINDOW {
            *entry = Failures {
                since: now,
                count: 0,
            };
        }
        entry.count = entry.count.saturating_add(1);
        let threshold = if ip.is_loopback() {
            LOOPBACK_FAILURES
        } else {
            FAILURES_BEFORE_SLOWING
        };
        let over = entry.count.saturating_sub(threshold);
        let delay = if over == 0 {
            Duration::ZERO
        } else {
            FIRST_DELAY
                .saturating_mul(1u32 << (over - 1).min(16))
                .min(MAX_DELAY)
        };
        Failure {
            delay,
            first: entry.count == 1,
            slowing_starts: over == 1,
        }
    }

    /// Forgets the failures from `ip` after a successful login.
    pub fn succeeded(&self, ip: IpAddr) {
        self.inner().failures.remove(&Source::of(ip));
    }

    /// Admits a new connection from `ip` that has not logged in, if the
    /// caps allow; the guard counts it until dropped (at login or close).
    #[must_use]
    pub fn admit(self: &Arc<Self>, ip: IpAddr) -> Option<Unauthenticated> {
        let source = Source::of(ip);
        let mut inner = self.inner();
        let count = inner.unauthenticated.get(&source).copied().unwrap_or(0);
        if inner.total >= MAX_UNAUTHENTICATED || count >= MAX_UNAUTHENTICATED_PER_SOURCE {
            return None;
        }
        inner.unauthenticated.insert(source, count + 1);
        inner.total += 1;
        Some(Unauthenticated {
            limiter: Arc::clone(self),
            source,
        })
    }

    /// How many connections [`Limiter::admit`] let in that have not
    /// logged in or closed: the count [`MAX_UNAUTHENTICATED`] bounds,
    /// over every boundary that admits a connection, since one limiter
    /// serves the whole agent.
    #[must_use]
    pub fn unauthenticated(&self) -> usize {
        self.inner().total
    }
}

/// A connection counted against the caps until it logs in or closes.
#[derive(Debug)]
pub struct Unauthenticated {
    limiter: Arc<Limiter>,
    source: Source,
}

impl Drop for Unauthenticated {
    fn drop(&mut self) {
        let mut inner = self.limiter.inner();
        inner.total = inner.total.saturating_sub(1);
        if let Some(count) = inner.unauthenticated.get_mut(&self.source) {
            *count -= 1;
            if *count == 0 {
                inner.unauthenticated.remove(&self.source);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_source_is_slowed_after_five_failures_and_forgiven_on_success() {
        let limiter = Limiter::new();
        let ip: IpAddr = "192.0.2.1".parse().unwrap();
        let first = limiter.failed(ip);
        assert!(first.first && first.delay.is_zero());
        for _ in 2..=5 {
            let f = limiter.failed(ip);
            assert!(!f.first && f.delay.is_zero() && !f.slowing_starts);
        }
        let sixth = limiter.failed(ip);
        assert!(sixth.slowing_starts);
        assert_eq!(sixth.delay, FIRST_DELAY);
        assert_eq!(limiter.failed(ip).delay, FIRST_DELAY * 2);
        for _ in 0..10 {
            let _ = limiter.failed(ip);
        }
        assert_eq!(limiter.failed(ip).delay, MAX_DELAY);
        // Another source is not slowed.
        assert!(limiter.failed("192.0.2.2".parse().unwrap()).delay.is_zero());
        limiter.succeeded(ip);
        assert!(limiter.failed(ip).first);
    }

    #[test]
    fn loopback_gets_twenty_and_ipv6_counts_per_slash_64() {
        let limiter = Limiter::new();
        let loopback: IpAddr = "127.0.0.1".parse().unwrap();
        for _ in 0..LOOPBACK_FAILURES {
            assert!(limiter.failed(loopback).delay.is_zero());
        }
        assert_eq!(limiter.failed(loopback).delay, FIRST_DELAY);
        for i in 0..FAILURES_BEFORE_SLOWING {
            let ip: IpAddr = format!("2001:db8:1:2::{i}").parse().unwrap();
            assert!(limiter.failed(ip).delay.is_zero());
        }
        assert_eq!(
            limiter
                .failed("2001:db8:1:2:ffff::1".parse().unwrap())
                .delay,
            FIRST_DELAY
        );
        assert!(
            limiter
                .failed("2001:db8:1:3::1".parse().unwrap())
                .delay
                .is_zero()
        );
    }

    #[test]
    fn unauthenticated_connections_are_capped() {
        let limiter = Arc::new(Limiter::new());
        let ip: IpAddr = "192.0.2.1".parse().unwrap();
        let held: Vec<_> = (0..MAX_UNAUTHENTICATED_PER_SOURCE)
            .map(|_| limiter.admit(ip).unwrap())
            .collect();
        assert!(limiter.admit(ip).is_none());
        drop(held);
        let mut held = Vec::new();
        for i in 0..MAX_UNAUTHENTICATED {
            let ip: IpAddr = format!("192.0.2.{}", i / 4 + 10).parse().unwrap();
            held.push(limiter.admit(ip).unwrap());
        }
        assert!(limiter.admit("198.51.100.1".parse().unwrap()).is_none());
        held.pop();
        assert!(limiter.admit("198.51.100.1".parse().unwrap()).is_some());
    }

    /// The count of connections not logged in falls as each one logs in
    /// or closes: a count that only climbed would report half-open
    /// connections that are gone for the life of the daemon.
    #[test]
    fn the_unauthenticated_count_falls_when_a_connection_goes() {
        let limiter = Arc::new(Limiter::new());
        assert_eq!(limiter.unauthenticated(), 0);
        let one = limiter.admit("192.0.2.1".parse().unwrap()).unwrap();
        let two = limiter.admit("192.0.2.1".parse().unwrap()).unwrap();
        let three = limiter.admit("198.51.100.1".parse().unwrap()).unwrap();
        assert_eq!(limiter.unauthenticated(), 3);
        drop(two);
        assert_eq!(limiter.unauthenticated(), 2);
        drop((one, three));
        assert_eq!(limiter.unauthenticated(), 0);
    }
}
