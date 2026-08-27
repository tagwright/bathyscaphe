// SPDX-License-Identifier: GPL-3.0-or-later
//! Refinement R2: OPT-IN fail-closed-on-sustained-drops
//! (`bathy_build_spec.md`'s R2 section), modeled on Falco's
//! `syscall_event_drops` `exit`/`log`/`alert` actions gated by a
//! threshold. Layered on the same per-container `TAMPER` counter R1's
//! `tamper.event_drops` record already reads: if a container's drop RATE
//! stays above a configured threshold for a configured WINDOW, escalate
//! that container to full enforcement lockdown, or exit the whole process
//! -- the operator's choice, via [`DropEscalationConfig::action`].
//!
//! **OFF BY DEFAULT** ([`DropEscalationConfig::default`] sets
//! `enabled: false`), matching Falco's own default of log+alert rather
//! than exit -- see `docs/README` (chunk #12) for why this must stay
//! evident to an operator reading the docs, not just discoverable by
//! reading this source file.
//!
//! This module is pure decision logic: [`DropTracker::observe`] takes a
//! drop delta and returns a decision, nothing more. [`super::stats`] is
//! what actually calls [`super::probe_api::ProbeApi::set_enforcement`] (for
//! [`EscalationAction::Lockdown`]) or exits the process (for
//! [`EscalationAction::Exit`], via `std::process::exit` specifically
//! because it skips destructors -- see that module's doc on why that is
//! the SAFEST way to preserve pins on this particular exit path, not an
//! oversight).

use std::collections::{HashMap, HashSet};

/// What to do once a container's drop rate has been over threshold for
/// the whole configured window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EscalationAction {
    /// Set that container's enforcement to `mode: block`, `default: deny`
    /// -- full lockdown, scoped to the one misbehaving container.
    Lockdown,
    /// Exit the whole process (pins preserved: enforcement freezes at
    /// last-known-good, a supervised restart resumes it, per the
    /// fail-closed pinning model every other exit path in this daemon
    /// already relies on).
    Exit,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct DropEscalationConfig {
    pub enabled: bool,
    /// Drops per second sustained over `window_s` before escalating.
    pub threshold_per_sec: f64,
    /// How long the rate must stay over threshold, in seconds, before
    /// escalating.
    pub window_s: u64,
    pub action: EscalationAction,
}

impl Default for DropEscalationConfig {
    fn default() -> Self {
        Self { enabled: false, threshold_per_sec: 10.0, window_s: 60, action: EscalationAction::Lockdown }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EscalationDecision {
    None,
    Escalate(EscalationAction),
}

/// Per-container consecutive-over-threshold tick counters, plus which
/// containers have already been escalated (escalation fires exactly once
/// per container per process lifetime -- re-escalating a container that
/// is already in lockdown, or re-exiting a process that is already about
/// to exit, would add nothing).
#[derive(Default)]
pub struct DropTracker {
    consecutive_over_threshold_ticks: HashMap<u64, u32>,
    escalated: HashSet<u64>,
}

impl DropTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Call once per `stats` tick, per container, with the drop delta
    /// observed THIS tick (not the cumulative total) and the tick interval
    /// in seconds. Returns whether this observation crosses the
    /// escalation threshold.
    pub fn observe(&mut self, cgroup_id: u64, dropped_delta: u64, stats_interval_s: u64, config: &DropEscalationConfig) -> EscalationDecision {
        if !config.enabled || self.escalated.contains(&cgroup_id) {
            return EscalationDecision::None;
        }

        let interval = stats_interval_s.max(1) as f64;
        let rate = dropped_delta as f64 / interval;
        let counter = self.consecutive_over_threshold_ticks.entry(cgroup_id).or_insert(0);
        if rate > config.threshold_per_sec {
            *counter += 1;
        } else {
            *counter = 0;
            return EscalationDecision::None;
        }

        let ticks_needed = ((config.window_s as f64 / interval).ceil() as u32).max(1);
        if *counter >= ticks_needed {
            self.escalated.insert(cgroup_id);
            EscalationDecision::Escalate(config.action)
        } else {
            EscalationDecision::None
        }
    }

    /// Forgets a container entirely -- called on `release`, so a
    /// container that was mid-way through accumulating over-threshold
    /// ticks does not carry that history into a differently-policied
    /// future life of the same cgroup id.
    pub fn forget(&mut self, cgroup_id: u64) {
        self.consecutive_over_threshold_ticks.remove(&cgroup_id);
        self.escalated.remove(&cgroup_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabled_by_default_never_escalates() {
        let config = DropEscalationConfig::default();
        assert!(!config.enabled, "R2 must be off by default");
        let mut tracker = DropTracker::new();
        for _ in 0..100 {
            assert_eq!(tracker.observe(1, 1_000_000, 10, &config), EscalationDecision::None);
        }
    }

    #[test]
    fn sustained_over_threshold_drops_escalate_after_the_configured_window() {
        let config = DropEscalationConfig { enabled: true, threshold_per_sec: 10.0, window_s: 30, action: EscalationAction::Lockdown };
        let mut tracker = DropTracker::new();
        // stats_interval_s = 10, window_s = 30 -> 3 consecutive over-threshold ticks needed.
        assert_eq!(tracker.observe(1, 200, 10, &config), EscalationDecision::None); // rate 20/s, tick 1
        assert_eq!(tracker.observe(1, 200, 10, &config), EscalationDecision::None); // tick 2
        assert_eq!(tracker.observe(1, 200, 10, &config), EscalationDecision::Escalate(EscalationAction::Lockdown)); // tick 3
    }

    #[test]
    fn a_rate_that_dips_below_threshold_resets_the_counter() {
        let config = DropEscalationConfig { enabled: true, threshold_per_sec: 10.0, window_s: 30, action: EscalationAction::Lockdown };
        let mut tracker = DropTracker::new();
        assert_eq!(tracker.observe(1, 200, 10, &config), EscalationDecision::None);
        assert_eq!(tracker.observe(1, 200, 10, &config), EscalationDecision::None);
        assert_eq!(tracker.observe(1, 5, 10, &config), EscalationDecision::None, "a below-threshold tick resets the streak");
        assert_eq!(tracker.observe(1, 200, 10, &config), EscalationDecision::None, "back to tick 1 of a fresh streak");
        assert_eq!(tracker.observe(1, 200, 10, &config), EscalationDecision::None);
        assert_eq!(tracker.observe(1, 200, 10, &config), EscalationDecision::Escalate(EscalationAction::Lockdown));
    }

    #[test]
    fn escalation_fires_exactly_once_per_container() {
        let config = DropEscalationConfig { enabled: true, threshold_per_sec: 1.0, window_s: 1, action: EscalationAction::Exit };
        let mut tracker = DropTracker::new();
        assert_eq!(tracker.observe(1, 100, 1, &config), EscalationDecision::Escalate(EscalationAction::Exit));
        assert_eq!(tracker.observe(1, 100, 1, &config), EscalationDecision::None, "already escalated -- do not re-fire");
    }

    #[test]
    fn different_containers_are_tracked_independently() {
        let config = DropEscalationConfig { enabled: true, threshold_per_sec: 1.0, window_s: 1, action: EscalationAction::Lockdown };
        let mut tracker = DropTracker::new();
        assert_eq!(tracker.observe(1, 100, 1, &config), EscalationDecision::Escalate(EscalationAction::Lockdown));
        assert_eq!(tracker.observe(2, 0, 1, &config), EscalationDecision::None, "a quiet container must not inherit another container's streak");
    }

    #[test]
    fn forget_clears_a_containers_history() {
        let config = DropEscalationConfig { enabled: true, threshold_per_sec: 1.0, window_s: 1, action: EscalationAction::Lockdown };
        let mut tracker = DropTracker::new();
        assert_eq!(tracker.observe(1, 100, 1, &config), EscalationDecision::Escalate(EscalationAction::Lockdown));
        tracker.forget(1);
        assert_eq!(tracker.observe(1, 100, 1, &config), EscalationDecision::Escalate(EscalationAction::Lockdown), "forgetting clears the escalated flag too, so a re-attached container can be evaluated fresh");
    }
}
