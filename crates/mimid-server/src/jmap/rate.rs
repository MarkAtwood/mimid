//! Per-account rate limits on the methods of draft-atwood-jmap-chat-mimi-00
//! (jmap-chat-spec 43ee02c, §capability: "A server that limits how often
//! an account calls the methods of this document answers a call over its
//! limit with the method-level error `rateLimited` ... MAY include
//! `retryAfter`"; bead mimid-e64f.21).
//!
//! mimid limits `KeyMaterial/fetch`, which the draft's Security
//! Considerations ask for ("Servers SHOULD rate-limit key material
//! requests per requester"): every request hands out one of each target
//! client's KeyPackages, and so brings them closer to their last-resort
//! ones. Each account has a token bucket of [`RateLimit::burst`] tokens,
//! refilled one per [`RateLimit::refill_ms`]; a call that finds it empty
//! is `rateLimited`, with `retryAfter` the whole seconds until a token is
//! back (at least 1). Both bindings call the limit through the method's
//! core function, so they share one bucket per account.
//!
//! # Limitations
//!
//! - The buckets live in memory: a restart fills them again.
//! - An account's bucket is kept once made; there is one per account that
//!   ever fetched key material, a few dozen octets each.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};

use jmap_server::JmapError;
use serde_json::json;

use crate::hub::Clock;

/// The method-level error (jmap-chat-spec bde5330).
pub const RATE_LIMITED: &str = "rateLimited";

/// The default `KeyMaterial/fetch` limit: a burst of 30, then one a
/// second. INVENTED, NOT FROM SPEC: the draft leaves the limit to the
/// server; room for adding thirty users at once, and for a client that
/// retries.
pub const DEFAULT_KEY_MATERIAL_LIMIT: RateLimit = RateLimit {
    burst: 30,
    refill_ms: 1000,
};

/// A token bucket's size and refill.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimit {
    /// Calls an account may make at once.
    pub burst: u32,
    /// Milliseconds after which one more call is allowed.
    pub refill_ms: u64,
}

#[derive(Debug, Clone, Copy)]
struct Bucket {
    tokens: u32,
    /// When the bucket was last filled to `tokens`.
    at_ms: u64,
}

/// Token buckets, one per account.
#[derive(Clone)]
pub struct RateLimiter {
    limit: RateLimit,
    clock: Arc<dyn Clock>,
    buckets: Arc<Mutex<HashMap<String, Bucket>>>,
}

impl std::fmt::Debug for RateLimiter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RateLimiter")
            .field("limit", &self.limit)
            .finish_non_exhaustive()
    }
}

impl RateLimiter {
    pub(crate) fn new(limit: RateLimit, clock: Arc<dyn Clock>) -> Self {
        Self {
            limit,
            clock,
            buckets: Arc::default(),
        }
    }

    /// Takes a token from `account_id`'s bucket, or answers how many
    /// seconds until one is back.
    pub(crate) fn take(&self, account_id: &str) -> Result<(), u64> {
        let now = self.clock.now_ms();
        let refill = self.limit.refill_ms.max(1);
        let mut buckets = self.buckets.lock().unwrap_or_else(PoisonError::into_inner);
        let bucket = buckets.entry(account_id.to_owned()).or_insert(Bucket {
            tokens: self.limit.burst,
            at_ms: now,
        });
        let elapsed = now.saturating_sub(bucket.at_ms);
        let earned = elapsed / refill;
        if earned > 0 {
            let tokens = u64::from(bucket.tokens).saturating_add(earned);
            bucket.tokens =
                u32::try_from(tokens.min(u64::from(self.limit.burst))).unwrap_or(self.limit.burst);
            bucket.at_ms = bucket.at_ms.saturating_add(earned.saturating_mul(refill));
            if bucket.tokens == self.limit.burst {
                bucket.at_ms = now;
            }
        }
        if bucket.tokens > 0 {
            bucket.tokens -= 1;
            return Ok(());
        }
        let wait_ms = refill.saturating_sub(now.saturating_sub(bucket.at_ms));
        Err(wait_ms.div_ceil(1000).max(1))
    }

    /// [`RateLimiter::take`] as the method-level error.
    pub(crate) fn check(&self, method: &'static str, account_id: &str) -> Result<(), JmapError> {
        self.take(account_id).map_err(|retry_after| {
            tracing::info!(
                name: "rate_limited",
                method,
                retry_after,
                "a call over the account's rate limit"
            );
            rate_limited(retry_after)
        })
    }
}

/// `rateLimited` with `retryAfter` seconds.
pub(crate) fn rate_limited(retry_after: u64) -> JmapError {
    let mut error = JmapError::custom(RATE_LIMITED);
    error
        .extra
        .insert("retryAfter".to_owned(), json!(retry_after));
    error
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Manual(Mutex<u64>);

    impl Clock for Manual {
        fn now_ms(&self) -> u64 {
            *self.0.lock().unwrap()
        }
    }

    /// A burst, then one per refill; another account has its own bucket;
    /// `retryAfter` rounds up to whole seconds.
    #[test]
    fn buckets_refill_per_account() {
        let clock = Arc::new(Manual(Mutex::new(10_000)));
        let limiter = RateLimiter::new(
            RateLimit {
                burst: 2,
                refill_ms: 1500,
            },
            Arc::clone(&clock) as Arc<dyn Clock>,
        );
        assert_eq!(limiter.take("A"), Ok(()));
        assert_eq!(limiter.take("A"), Ok(()));
        assert_eq!(limiter.take("A"), Err(2));
        assert_eq!(limiter.take("B"), Ok(()));
        *clock.0.lock().unwrap() = 11_000;
        assert_eq!(limiter.take("A"), Err(1));
        *clock.0.lock().unwrap() = 11_500;
        assert_eq!(limiter.take("A"), Ok(()));
        assert_eq!(limiter.take("A"), Err(2));
        // A long pause fills the bucket only to its burst.
        *clock.0.lock().unwrap() = 1_000_000;
        assert_eq!(limiter.take("A"), Ok(()));
        assert_eq!(limiter.take("A"), Ok(()));
        assert_eq!(limiter.take("A"), Err(2));
        let error = limiter.check("KeyMaterial/fetch", "A").unwrap_err();
        assert_eq!(
            serde_json::to_value(&error).unwrap(),
            json!({"type": "rateLimited", "retryAfter": 2})
        );
    }
}
