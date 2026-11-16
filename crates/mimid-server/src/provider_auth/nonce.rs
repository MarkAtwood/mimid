//! Replay protection by RFC 9421 `nonce` (bead mimid-75nk.9).
//!
//! draft-atwood-mimi-provider-auth -01 §13.2: some MIMI requests are not
//! harmless to replay. A keyMaterial answer hands out a KeyPackage, so a
//! replayed signed request within the `created` window consumes another.
//! Signers SHOULD put a `nonce` on such requests and verifiers SHOULD
//! refuse a nonce the same key has already used within the window.
//!
//! [`NonceCache`] remembers each `(provider, keyid, nonce)` seen on a
//! signature that verified, until its `created` time leaves the window, and
//! refuses a second use. A signature without a nonce is not refused here
//! (the draft's SHOULD is on the signer). Only signatures that verified are
//! recorded, so the entries come from keys this server trusts; the cache is
//! still bounded ([`MAX_NONCES`]): when full, the entry whose window ends
//! first is dropped, which can only let an old replay through, never
//! refuse a fresh request.

use std::collections::{BTreeSet, HashMap};
use std::sync::{Mutex, PoisonError};

use crate::config::Domain;

/// The most nonces remembered at once. INVENTED, NOT FROM SPEC: a few
/// minutes of traffic from all peers.
pub const MAX_NONCES: usize = 65_536;

/// The longest nonce kept. INVENTED, NOT FROM SPEC: mimid's own are 22
/// characters; a longer one is refused rather than stored.
pub const MAX_NONCE_LEN: usize = 128;

/// Why a nonce is refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum NonceRefusal {
    /// The same key already used this nonce within the window.
    #[error("the signature's nonce was already used")]
    Replayed,
    /// The nonce is longer than [`MAX_NONCE_LEN`].
    #[error("the signature's nonce is too long")]
    TooLong,
}

type Entry = (Domain, String, String);

/// The nonces seen, each until the `created` window around it closes.
#[derive(Debug)]
pub struct NonceCache {
    /// Seconds after `created` that a signature stays acceptable: the
    /// verifier's maximum age plus its allowed clock skew.
    window: i64,
    inner: Mutex<Inner>,
}

#[derive(Debug, Default)]
struct Inner {
    /// Entry to the time its window closes (seconds since the epoch).
    seen: HashMap<Entry, i64>,
    /// The same entries by closing time, for expiry and eviction.
    by_close: BTreeSet<(i64, Entry)>,
}

impl NonceCache {
    /// A cache for signatures acceptable until `window` seconds after
    /// their `created` time.
    pub fn new(window: i64) -> Self {
        Self {
            window,
            inner: Mutex::default(),
        }
    }

    /// Records `nonce` from `keyid` of `provider`, on a signature `created`
    /// at that time, at `now`.
    ///
    /// # Errors
    ///
    /// [`NonceRefusal::Replayed`] if it is already recorded and its window
    /// is open; [`NonceRefusal::TooLong`] if it exceeds [`MAX_NONCE_LEN`].
    pub fn check_and_record(
        &self,
        provider: &Domain,
        keyid: &str,
        nonce: &str,
        created: i64,
        now: i64,
    ) -> Result<(), NonceRefusal> {
        if nonce.len() > MAX_NONCE_LEN {
            return Err(NonceRefusal::TooLong);
        }
        // A replay is acceptable to the signature check until the window
        // closes, so the nonce is kept until then.
        let closes = created.saturating_add(self.window);
        // The map is valid after any panic: each update leaves both
        // collections consistent before it can panic.
        let mut inner = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        inner.expire(now);
        let entry = (provider.clone(), keyid.to_owned(), nonce.to_owned());
        if inner.seen.contains_key(&entry) {
            return Err(NonceRefusal::Replayed);
        }
        while inner.seen.len() >= MAX_NONCES {
            let Some(first) = inner.by_close.pop_first() else {
                break;
            };
            inner.seen.remove(&first.1);
        }
        inner.seen.insert(entry.clone(), closes);
        inner.by_close.insert((closes, entry));
        Ok(())
    }

    /// How many nonces are remembered.
    pub fn len(&self) -> usize {
        self.inner
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .seen
            .len()
    }

    /// Whether none are.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Inner {
    /// Forgets every entry whose window closed before `now`.
    fn expire(&mut self, now: i64) {
        while let Some((closes, _)) = self.by_close.first() {
            if *closes >= now {
                break;
            }
            if let Some((_, entry)) = self.by_close.pop_first() {
                self.seen.remove(&entry);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn domain(name: &str) -> Domain {
        Domain::try_from(name.to_owned()).unwrap()
    }

    const T: i64 = 1_700_000_000;

    #[test]
    fn a_nonce_is_refused_the_second_time_within_the_window() {
        let cache = NonceCache::new(360);
        let b = domain("b.example");
        assert_eq!(cache.check_and_record(&b, "k1", "n1", T, T), Ok(()));
        assert_eq!(
            cache.check_and_record(&b, "k1", "n1", T, T + 299),
            Err(NonceRefusal::Replayed)
        );
        // Another key, provider or nonce is a different entry.
        assert_eq!(cache.check_and_record(&b, "k2", "n1", T, T), Ok(()));
        assert_eq!(
            cache.check_and_record(&domain("c.example"), "k1", "n1", T, T),
            Ok(())
        );
        assert_eq!(cache.check_and_record(&b, "k1", "n2", T, T), Ok(()));
    }

    #[test]
    fn a_nonce_is_forgotten_when_its_window_closes() {
        let cache = NonceCache::new(360);
        let b = domain("b.example");
        cache.check_and_record(&b, "k1", "n1", T, T).unwrap();
        // Window closes at T + 360; at T + 361 the entry is gone (the
        // signature itself would now fail the created check).
        assert_eq!(
            cache.check_and_record(&b, "k1", "n1", T, T + 360),
            Err(NonceRefusal::Replayed)
        );
        cache
            .check_and_record(&b, "k1", "other", T + 361, T + 361)
            .unwrap();
        assert_eq!(cache.len(), 1, "n1 expired");
    }

    #[test]
    fn long_nonces_are_refused_and_not_stored() {
        let cache = NonceCache::new(360);
        let long = "x".repeat(MAX_NONCE_LEN + 1);
        assert_eq!(
            cache.check_and_record(&domain("b.example"), "k1", &long, T, T),
            Err(NonceRefusal::TooLong)
        );
        assert!(cache.is_empty());
    }
}
