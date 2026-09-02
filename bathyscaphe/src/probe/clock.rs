// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 techgaud
//! `CLOCK_BOOTTIME` in userspace, matching the clock the kernel programs use
//! for `PolicyValue::expires_at_ns` and `Event::ktime_ns`
//! (`bpf_ktime_get_boot_ns()`). `std::time::Instant` is deliberately not
//! used here: it's tied to `CLOCK_MONOTONIC` on Linux, which -- unlike
//! `CLOCK_BOOTTIME` -- does not advance across system suspend, so the two
//! clocks can drift apart on any host that suspends.

use anyhow::{Context, Result};

pub fn now_boottime_ns() -> Result<u64> {
    let mut ts: libc::timespec = unsafe { std::mem::zeroed() };
    // SAFETY: `ts` is a valid, fully zeroed `libc::timespec` for the
    // duration of the call.
    let rc = unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut ts) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error()).context("clock_gettime(CLOCK_BOOTTIME) failed");
    }
    // Boottime is never negative in practice (it's time-since-boot); a
    // negative tv_sec would indicate a broken clock, not a value worth
    // trying to represent, so this saturates to 0 rather than panicking or
    // silently wrapping.
    let secs = u64::try_from(ts.tv_sec).unwrap_or(0);
    let nanos = u64::try_from(ts.tv_nsec).unwrap_or(0);
    Ok(secs.saturating_mul(1_000_000_000).saturating_add(nanos))
}
