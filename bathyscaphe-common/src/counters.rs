// SPDX-License-Identifier: GPL-3.0-or-later
//! The per-cgroup tamper counter: the map value the kernel bumps on
//! `RingBuf` reserve failure (the connect/sendmsg hook could not get
//! space to write an [`crate::event::Event`] and had to drop it silently
//! from the kernel's point of view — this counter is what keeps it from
//! being silent to the operator). The map declaration itself
//! (`HashMap<u64, TamperCounter>`, keyed by `cgroup_id`, pinned to bpffs
//! alongside the policy and enforcement maps) lives in `bathyscaphe-ebpf`
//! and the loader, not here.
//!
//! Userspace reads this map on the `stats` cadence and reports it as
//! `stats.containers[].dropped_total` (per-container) and folds the sum
//! across all containers into `stats.events_dropped_total` (cumulative,
//! process-wide). Per `docs/PROTOCOL.md` section 5, a nonzero delta here
//! between consecutive `stats` lines is airlock's cue for a high-severity
//! alert, and refinement R2 (opt-in fail-closed-on-sustained-drops, off
//! by default) watches this same counter's rate over a configured window
//! — both are daemon-side logic built on top of this one `u64`.

/// A single `u64` counter, wrapped in its own named type (rather than
/// using a bare `HashMap<u64, u64>` map value) so the map's purpose is
/// self-documenting at the type level and so a future per-cgroup stat
/// (e.g. a separate "policy map lookup failed" counter, distinct from
/// "ring buffer full") is an additive field here rather than a second,
/// easy-to-forget-to-read map.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(C)]
pub struct TamperCounter {
    /// Cumulative count of `RingBuf::reserve()` failures for this
    /// cgroup's events since the counter was last zeroed (container
    /// start, or an explicit reset the daemon may choose to perform on
    /// `release`/re-adopt — a daemon-side policy choice, not this
    /// struct's concern).
    pub events_dropped: u64,
}

impl TamperCounter {
    /// Trivial constructor.
    pub const fn new(events_dropped: u64) -> Self {
        Self { events_dropped }
    }

    /// Trivial constructor for the zeroed initial state.
    pub const fn zero() -> Self {
        Self::new(0)
    }
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for TamperCounter {}

#[cfg(test)]
mod tests {
    use super::*;

    const _TAMPER_COUNTER_SIZE: () = assert!(core::mem::size_of::<TamperCounter>() == 8);
    const _TAMPER_COUNTER_ALIGN: () = assert!(core::mem::align_of::<TamperCounter>() == 8);

    #[test]
    fn tamper_counter_is_pinned() {
        assert_eq!(core::mem::size_of::<TamperCounter>(), 8);
        assert_eq!(core::mem::align_of::<TamperCounter>(), 8);
    }

    #[test]
    fn zero_is_the_default() {
        assert_eq!(TamperCounter::zero(), TamperCounter::default());
    }
}
