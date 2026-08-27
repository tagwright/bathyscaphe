// SPDX-License-Identifier: GPL-3.0-or-later
//! `meta.dropped_since_last`: a per-cgroup delta of the kernel's cumulative
//! `TAMPER` counter (`probe::tamper::TamperStore::read_tamper`) against the
//! value seen at this container's last EMITTED event, per
//! `docs/PROTOCOL.md` section 3 ("events lost since the previous emitted
//! event") and the build brief's explicit instruction.

use std::collections::HashMap;
use std::sync::Mutex;

/// One entry per cgroup this process has emitted at least one event for.
/// A cgroup with no entry yet is exactly a cgroup with no prior emitted
/// event, so its first delta is computed against an implicit baseline of
/// `0` -- see [`Self::delta`]'s doc for why that is the correct behavior,
/// not a bug.
#[derive(Default)]
pub struct DroppedTracker {
    last_seen: Mutex<HashMap<u64, u64>>,
}

impl DroppedTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Records `current_total` as the new baseline for `cgroup_id` and
    /// returns the delta against whatever was there before (`0` if this is
    /// the first event ever seen for this cgroup). `TamperCounter` is
    /// monotonically increasing and never reset by anything but a fresh
    /// map entry (`bathyscaphe_common::counters`'s module doc), so
    /// `saturating_sub` is a defensive floor, not a case expected to bite
    /// in practice.
    ///
    /// Returning the FULL current total on the very first call (rather
    /// than suppressing it to `0`, "we have no prior baseline so report
    /// nothing") is deliberate: if this process starts observing a
    /// container whose tamper counter is already nonzero (a resumed boot
    /// re-adopting a container that was already dropping events before
    /// this process existed), that loss is real and happened "since the
    /// previous emitted event" in the only sense that makes sense for an
    /// event that has never been emitted before -- silently zeroing it
    /// would hide a real, already-happened drop.
    pub fn delta(&self, cgroup_id: u64, current_total: u64) -> u64 {
        let mut last_seen = self.last_seen.lock().unwrap_or_else(|poison| poison.into_inner());
        let previous = last_seen.insert(cgroup_id, current_total).unwrap_or(0);
        current_total.saturating_sub(previous)
    }
}
