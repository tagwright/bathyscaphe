// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 techgaud
//! The daemon's own bookkeeping: what it currently believes about each
//! container it holds policy state for. This is deliberately separate from
//! kernel ground truth (`EnforcementState`, read fresh from
//! [`super::probe_api::ProbeApi::get_enforcement`] whenever `stats` needs
//! it) -- `orphaned` in particular is a fact ONLY the daemon knows
//! (`bathy_build_spec.md`'s RECONCILIATION section: the kernel has no
//! concept of "airlock never covered this container during the last
//! resync").

use std::collections::{HashMap, HashSet};

use bathyscaphe_common::{DefaultVerdict, Mode};

/// What the daemon knows about one container that has (or had) policy
/// applied. Absence from [`DaemonState::containers`] means "never had
/// policy applied and not orphaned" -- a container that is merely attached
/// for observation (no `policy` ever received) does not get an entry here,
/// matching `EnforcementState`'s own "no entry means no enforcement"
/// convention at the daemon layer.
#[derive(Debug, Clone, PartialEq)]
pub struct ContainerState {
    pub container_id: String,
    pub cgroup_id: u64,
    pub mode: Mode,
    pub generation: u64,
    pub default: DefaultVerdict,
    /// Cached from the last successful `policy_ack` compilation --
    /// `PolicyStore`/`EnforcementStore` don't track "how many of these
    /// entries came from an inert rule", only the daemon's own compile
    /// step does.
    pub rules_active: u32,
    pub rules_inert: u32,
    /// True for pinned enforcement airlock did not cover during the most
    /// recent reconciliation round (`sync_complete` fired without a
    /// `policy` or `release` for this container in between). Kept
    /// enforcing regardless (fail-closed); cleared the moment a `policy`
    /// or `release` for this container arrives.
    pub orphaned: bool,
}

/// The daemon's shared, mutable view of every container it has policy
/// state for, plus the in-progress reconciliation bookkeeping. Held behind
/// one `Mutex` alongside the [`super::probe_api::ProbeApi`] (see
/// `daemon::mod`'s doc on the threading model) so a directive application
/// and a stats/orphan pass never observe a torn intermediate state.
#[derive(Default)]
pub struct DaemonState {
    pub containers: HashMap<String, ContainerState>,
    /// `cgroup_id -> container_id`, kept in lockstep with `containers` so
    /// the stats/reconciliation pass (which iterates
    /// `ProbeApi::attached_containers()`, a list of cgroup ids) can find
    /// the matching `ContainerState` without a linear scan.
    pub by_cgroup_id: HashMap<u64, String>,
    /// Container ids that received a `policy` or `release` since the last
    /// `sync_complete` (or since process start, if no `sync_complete` has
    /// fired yet this session). Reset to empty every time `sync_complete`
    /// runs its orphan-marking pass, so a later resync round (airlock
    /// reconnecting a second time in the same process lifetime) is judged
    /// against its own coverage, not a stale one.
    pub covered_since_last_sync: HashSet<String>,
}

impl DaemonState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn upsert(&mut self, state: ContainerState) {
        self.by_cgroup_id.insert(state.cgroup_id, state.container_id.clone());
        self.covered_since_last_sync.insert(state.container_id.clone());
        self.containers.insert(state.container_id.clone(), state);
    }

    /// Removes a container's tracked state entirely -- the `release`/
    /// `release_all` path, matching `EnforcementState`'s own "no entry
    /// means no enforcement" convention: a released container simply has
    /// no daemon-side record either, not a record with a "released" flag.
    pub fn remove(&mut self, container_id: &str) {
        self.covered_since_last_sync.insert(container_id.to_string());
        if let Some(state) = self.containers.remove(container_id) {
            self.by_cgroup_id.remove(&state.cgroup_id);
        }
    }

    pub fn get_by_cgroup(&self, cgroup_id: u64) -> Option<&ContainerState> {
        self.by_cgroup_id.get(&cgroup_id).and_then(|id| self.containers.get(id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(container_id: &str, cgroup_id: u64) -> ContainerState {
        ContainerState { container_id: container_id.to_string(), cgroup_id, mode: Mode::Block, generation: 1, default: DefaultVerdict::Deny, rules_active: 1, rules_inert: 0, orphaned: false }
    }

    #[test]
    fn upsert_marks_covered_and_indexes_by_cgroup_id() {
        let mut state = DaemonState::new();
        state.upsert(sample("c1", 100));
        assert!(state.covered_since_last_sync.contains("c1"));
        assert_eq!(state.get_by_cgroup(100).unwrap().container_id, "c1");
    }

    #[test]
    fn remove_drops_both_indexes() {
        let mut state = DaemonState::new();
        state.upsert(sample("c1", 100));
        state.remove("c1");
        assert!(state.containers.get("c1").is_none());
        assert!(state.get_by_cgroup(100).is_none());
    }
}
