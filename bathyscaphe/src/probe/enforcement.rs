// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 techgaud
//! The `ENFORCEMENT` map API: per-container posture (mode + default verdict
//! + generation). See `bathyscaphe_common::enforcement`'s module doc --
//! absence of an entry, not a field on it, is what "no enforcement
//! configured" means, so [`EnforcementStore::clear_enforcement`] removes
//! the key entirely rather than writing a disabled-looking value.

use anyhow::{Context, Result};
use aya::maps::{HashMap, MapData, MapError};
use bathyscaphe_common::{DefaultVerdict, EnforcementState, Mode};

pub struct EnforcementStore {
    map: HashMap<MapData, u64, EnforcementState>,
}

impl EnforcementStore {
    pub(crate) fn new(map: HashMap<MapData, u64, EnforcementState>) -> Self {
        Self { map }
    }

    /// Writes (or overwrites) `cgroup_id`'s enforcement posture. `generation`
    /// is airlock's own monotonic counter, threaded through unmodified so
    /// `stats`/`hello.pinned` can report exactly what's enforced (see
    /// `EnforcementState::generation`'s doc).
    pub fn set_enforcement(&mut self, cgroup_id: u64, mode: Mode, default_verdict: DefaultVerdict, generation: u64) -> Result<()> {
        let state = EnforcementState::new(generation, mode as u8, default_verdict as u8);
        self.map.insert(cgroup_id, state, 0).context("ENFORCEMENT map insert failed")
    }

    /// Removes `cgroup_id`'s entry entirely, reverting it to "no enforcement
    /// configured" (full observe-only-with-no-policy-lookup, per
    /// `EnforcementState`'s module doc) rather than some zeroed-but-present
    /// value. Not finding an entry to remove is not an error -- the
    /// post-condition ("no entry for this cgroup") already holds.
    pub fn clear_enforcement(&mut self, cgroup_id: u64) -> Result<()> {
        match self.map.remove(&cgroup_id) {
            Ok(()) | Err(MapError::KeyNotFound) => Ok(()),
            Err(error) => Err(error).context("ENFORCEMENT map remove failed"),
        }
    }

    /// Reads back `cgroup_id`'s current posture, or `None` if it has none
    /// configured.
    pub fn get(&self, cgroup_id: u64) -> Result<Option<EnforcementState>> {
        match self.map.get(&cgroup_id, 0) {
            Ok(state) => Ok(Some(state)),
            Err(MapError::KeyNotFound) => Ok(None),
            Err(error) => Err(error).context("ENFORCEMENT map read failed"),
        }
    }
}
