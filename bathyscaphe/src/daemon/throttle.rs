// SPDX-License-Identifier: GPL-3.0-or-later
//! A shared token-bucket throttle for the loud `security` records
//! (refinement R1): the Falco pattern (a small burst allowance plus a slow
//! steady refill, roughly "1 every 30s" once the burst is spent) so a
//! drop/violation storm never floods stdout. ONE bucket is shared across
//! every reason code (`policy.unenforceable_name`, `tamper.event_drops`,
//! `policy.violation`, `enforce.blocked`) per `bathy_build_spec.md`'s R1
//! section ("Token-bucket throttle all of these"), not one bucket per
//! reason -- a host under simultaneous drop-storm-plus-block-storm
//! pressure gets one bounded stream of loud records, not N independently
//! bounded streams that sum past the intended cap.

use std::time::{Duration, Instant};

/// Burst capacity: this many records can be emitted back-to-back before
/// the steady-state rate takes over.
pub const DEFAULT_BURST: f64 = 5.0;
/// Steady-state refill rate: one token roughly every 30 seconds, matching
/// Falco's own default cadence for its throttled alert classes.
pub const DEFAULT_REFILL_PER_SEC: f64 = 1.0 / 30.0;

/// A single token bucket. Not `Send`/`Sync` on its own -- callers sharing
/// one instance across threads wrap it in a `Mutex` (see
/// `super::security`).
pub struct TokenBucket {
    capacity: f64,
    refill_per_sec: f64,
    tokens: f64,
    last_refill: Instant,
}

impl TokenBucket {
    pub fn new(capacity: f64, refill_per_sec: f64) -> Self {
        Self { capacity, refill_per_sec, tokens: capacity, last_refill: Instant::now() }
    }

    /// The Falco-pattern default: a small burst, then roughly one every 30s.
    pub fn falco_default() -> Self {
        Self::new(DEFAULT_BURST, DEFAULT_REFILL_PER_SEC)
    }

    /// Attempts to take one token at `now`. Returns `true` (and consumes a
    /// token) if one was available, `false` if the bucket is empty --
    /// callers drop the record they were about to emit on `false`, rather
    /// than queuing it, since a queued backlog of security records is
    /// exactly the flood this throttle exists to prevent.
    pub fn try_take(&mut self, now: Instant) -> bool {
        let elapsed = now.saturating_duration_since(self.last_refill).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.refill_per_sec).min(self.capacity);
        self.last_refill = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn burst_capacity_is_available_up_front() {
        let mut bucket = TokenBucket::new(3.0, 0.0);
        let now = Instant::now();
        assert!(bucket.try_take(now));
        assert!(bucket.try_take(now));
        assert!(bucket.try_take(now));
        assert!(!bucket.try_take(now), "the fourth take in the same instant must be refused: burst capacity is 3");
    }

    #[test]
    fn refill_grants_a_token_after_enough_elapsed_time() {
        let mut bucket = TokenBucket::new(1.0, 1.0); // 1 token/sec, capacity 1
        let t0 = Instant::now();
        assert!(bucket.try_take(t0), "the initial burst token is available immediately");
        assert!(!bucket.try_take(t0), "no refill has happened yet at the same instant");

        let t1 = t0 + Duration::from_millis(1100);
        assert!(bucket.try_take(t1), "just over 1 second at 1 token/sec should have refilled one token");
    }

    #[test]
    fn refill_never_exceeds_capacity() {
        let mut bucket = TokenBucket::new(2.0, 100.0);
        let t0 = Instant::now();
        let t1 = t0 + Duration::from_secs(10); // would refill far past capacity without the cap
        assert!(bucket.try_take(t1));
        assert!(bucket.try_take(t1));
        assert!(!bucket.try_take(t1), "capacity caps accumulated tokens at 2, not the raw refill amount");
    }

    #[test]
    fn a_storm_of_calls_is_bounded_not_all_admitted() {
        let mut bucket = TokenBucket::falco_default();
        let now = Instant::now();
        let admitted = (0..1000).filter(|_| bucket.try_take(now)).count();
        assert_eq!(admitted as f64, DEFAULT_BURST, "only the burst allowance is admitted in a single instant, not all 1000 attempts");
    }
}
