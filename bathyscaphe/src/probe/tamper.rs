// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 techgaud
//! The `TAMPER` map API: read-only from userspace (only the kernel programs
//! ever write it, on a `RingBuf` reserve failure -- see
//! `bathyscaphe_common::counters`'s module doc).

use anyhow::{Context, Result};
use aya::maps::{HashMap, MapData, MapError};
use bathyscaphe_common::TamperCounter;

pub struct TamperStore {
    map: HashMap<MapData, u64, TamperCounter>,
}

impl TamperStore {
    pub(crate) fn new(map: HashMap<MapData, u64, TamperCounter>) -> Self {
        Self { map }
    }

    /// Reads `cgroup_id`'s cumulative dropped-event count. A cgroup that has
    /// never dropped an event has no map entry at all (the kernel side only
    /// inserts one lazily, on the first drop) -- that decodes as zero here,
    /// not an error.
    pub fn read_tamper(&self, cgroup_id: u64) -> Result<TamperCounter> {
        match self.map.get(&cgroup_id, 0) {
            Ok(counter) => Ok(counter),
            Err(MapError::KeyNotFound) => Ok(TamperCounter::zero()),
            Err(error) => Err(error).with_context(|| format!("TAMPER map read failed for cgroup {cgroup_id:016x}")),
        }
    }
}
