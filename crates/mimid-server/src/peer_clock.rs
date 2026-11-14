//! Peer clock checks: a WARN when a configured peer's clock is more than
//! the configured tolerance (`peer_clock_tolerance_secs`, default 5 s) away
//! from this server's.
//!
//! The peer's time is the HTTP `Date` header (RFC 9110 §6.6.1), which has
//! one-second resolution:
//!
//! - on a response to a peer call ([`crate::peer::PeerClient`]), the peer
//!   stamped it between the moment the request was sent and the moment the
//!   response arrived, so it is out of range only if it falls outside that
//!   window widened by the tolerance, plus one second below for the
//!   truncation to whole seconds;
//! - on a request from a peer (the [`check_request`] middleware), the
//!   window is the arrival time alone. Most peers send no `Date` on
//!   requests; nothing is checked then.
//!
//! Only configured peers are tracked, so a `From` header naming anyone else
//! (it is not authenticated, decision mimid-1wgh.17) adds no state and no
//! log line. A peer out of range is reported at WARN at most once per
//! [`WARN_INTERVAL`]; when its clock is back in range after a warning, one
//! INFO line says so. Skew is a deployment problem, not a request failure:
//! no request is refused for it.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant, SystemTime};

use axum::extract::{Request, State};
use axum::http::HeaderMap;
use axum::http::header::{DATE, FROM};
use axum::middleware::Next;
use axum::response::Response;

use crate::config::Domain;

/// The default tolerance, in seconds.
pub const DEFAULT_TOLERANCE_SECS: u64 = 5;

/// The least time between two warnings about the same peer.
pub const WARN_INTERVAL: Duration = Duration::from_secs(600);

/// `Date` has one-second resolution: a time stamped at x.999 reads as x.
const DATE_RESOLUTION: Duration = Duration::from_secs(1);

/// How far a peer's `Date` is outside the window it should fall in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Skew {
    /// The peer's clock is ahead by at least this much beyond the
    /// tolerance's window.
    Ahead(Duration),
    /// The peer's clock is behind by at least this much.
    Behind(Duration),
}

/// Where `date` falls against the window `[earliest, latest]` in which the
/// peer should have stamped it, widened by `tolerance`: `None` if inside,
/// else the skew measured from the nearer window edge, tolerance included.
pub fn skew(
    date: SystemTime,
    earliest: SystemTime,
    latest: SystemTime,
    tolerance: Duration,
) -> Option<Skew> {
    // `date` is truncated to a whole second: the true stamp is in
    // [date, date + 1 s).
    let date_latest = date + DATE_RESOLUTION;
    if let Ok(ahead) = date.duration_since(latest) {
        return (ahead > tolerance).then_some(Skew::Ahead(ahead));
    }
    if let Ok(behind) = earliest.duration_since(date_latest) {
        return (behind > tolerance).then_some(Skew::Behind(behind));
    }
    None
}

/// The skew tracker, shared by every peer client and the request
/// middleware.
#[derive(Debug)]
pub struct PeerClocks {
    tolerance: Duration,
    peers: BTreeSet<Domain>,
    state: Mutex<BTreeMap<Domain, Instant>>,
}

impl PeerClocks {
    /// A tracker for `peers` with `tolerance`.
    pub fn new(peers: impl IntoIterator<Item = Domain>, tolerance: Duration) -> Arc<Self> {
        Arc::new(Self {
            tolerance,
            peers: peers.into_iter().collect(),
            state: Mutex::new(BTreeMap::new()),
        })
    }

    /// Whether `peer` was last seen out of range, warned about, and not
    /// seen back in range since.
    pub fn is_skewed(&self, peer: &Domain) -> bool {
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .contains_key(peer)
    }

    /// Checks a `Date` header value from `peer`, which should have been
    /// stamped between `earliest` and `latest`. A missing or unparsable
    /// value, or a peer that is not configured, is ignored.
    pub fn observe(
        &self,
        peer: &Domain,
        date: Option<&str>,
        earliest: SystemTime,
        latest: SystemTime,
    ) {
        if !self.peers.contains(peer) {
            return;
        }
        let Some(date) = date.and_then(|text| httpdate::parse_http_date(text).ok()) else {
            return;
        };
        let skew = skew(date, earliest, latest, self.tolerance);
        let mut warned = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        match skew {
            Some(skew) => {
                let now = Instant::now();
                if warned
                    .get(peer)
                    .is_some_and(|last| now.duration_since(*last) < WARN_INTERVAL)
                {
                    return;
                }
                warned.insert(peer.clone(), now);
                let (direction, by) = match skew {
                    Skew::Ahead(by) => ("ahead", by),
                    Skew::Behind(by) => ("behind", by),
                };
                tracing::warn!(
                    name: "peer_clock_skew",
                    peer = peer.as_str(),
                    direction,
                    skew_ms = u64::try_from(by.as_millis()).unwrap_or(u64::MAX),
                    tolerance_ms = u64::try_from(self.tolerance.as_millis()).unwrap_or(u64::MAX),
                    "peer clock is {direction} of this server's by more than the tolerance"
                );
            }
            None => {
                if warned.remove(peer).is_some() {
                    tracing::info!(
                        name: "peer_clock_in_range",
                        peer = peer.as_str(),
                        "peer clock is back within the tolerance"
                    );
                }
            }
        }
    }
}

/// Middleware: checks the `Date` of a request whose `From` names a
/// configured peer (`mimi@<domain>`), against its arrival time.
pub async fn check_request(
    State(clocks): State<Arc<PeerClocks>>,
    request: Request,
    next: Next,
) -> Response {
    let arrived = SystemTime::now();
    if let Some(peer) = from_peer(request.headers()) {
        let date = request.headers().get(DATE).and_then(|v| v.to_str().ok());
        clocks.observe(&peer, date, arrived, arrived);
    }
    next.run(request).await
}

/// The domain in a single `From: mimi@<domain>` header.
fn from_peer(headers: &HeaderMap) -> Option<Domain> {
    let mut values = headers.get_all(FROM).iter();
    let (Some(value), None) = (values.next(), values.next()) else {
        return None;
    };
    let domain = value.to_str().ok()?.strip_prefix("mimi@")?;
    Domain::try_from(domain.to_owned()).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    const T: Duration = Duration::from_secs(5);

    fn at(secs: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(1_800_000_000 + secs)
    }

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    #[test]
    fn inside_the_widened_window_is_no_skew() {
        // Sent at 100 s, answered at 101 s.
        for date in [95, 96, 100, 101, 106] {
            assert_eq!(skew(at(date), at(100), at(101), T), None, "{date}");
        }
    }

    #[test]
    fn ahead_beyond_the_tolerance() {
        assert_eq!(
            skew(at(107), at(100), at(101), T),
            Some(Skew::Ahead(ms(6_000)))
        );
    }

    #[test]
    fn behind_beyond_the_tolerance_allows_for_whole_seconds() {
        // A Date of 94 may be 94.999: 5.001 s behind 100.
        assert_eq!(skew(at(94), at(100), at(101), T), None);
        assert_eq!(
            skew(at(93), at(100), at(101), T),
            Some(Skew::Behind(ms(6_000)))
        );
    }

    #[test]
    fn a_slow_round_trip_widens_the_window() {
        // Sent at 100, answered at 130: anything stamped in between is fine.
        assert_eq!(skew(at(120), at(100), at(130), T), None);
    }

    #[test]
    fn from_names_a_peer_only_in_the_mimi_form() {
        let mut headers = HeaderMap::new();
        headers.insert(FROM, "mimi@b.example".parse().unwrap());
        assert_eq!(
            from_peer(&headers).map(|d| d.as_str().to_owned()),
            Some("b.example".to_owned())
        );
        headers.insert(FROM, "alice@b.example".parse().unwrap());
        assert_eq!(from_peer(&headers), None);
    }

    #[test]
    fn unconfigured_peers_and_bad_dates_are_ignored() {
        let b = Domain::try_from("b.example".to_owned()).unwrap();
        let c = Domain::try_from("c.example".to_owned()).unwrap();
        let clocks = PeerClocks::new([b.clone()], T);
        clocks.observe(&c, Some("Thu, 01 Jan 1970 00:00:00 GMT"), at(0), at(0));
        clocks.observe(&b, Some("not a date"), at(0), at(0));
        clocks.observe(&b, None, at(0), at(0));
        assert!(clocks.state.lock().unwrap().is_empty());
    }

    #[test]
    fn a_skewed_peer_is_remembered_until_it_is_back_in_range() {
        let b = Domain::try_from("b.example".to_owned()).unwrap();
        let clocks = PeerClocks::new([b.clone()], T);
        let date = httpdate::fmt_http_date(at(0));
        clocks.observe(&b, Some(&date), at(60), at(60));
        assert!(clocks.state.lock().unwrap().contains_key(&b));
        clocks.observe(&b, Some(&date), at(0), at(0));
        assert!(clocks.state.lock().unwrap().is_empty());
    }
}
