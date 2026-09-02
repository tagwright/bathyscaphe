// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 techgaud
//! The kernel-floor check: cgroup v2 unified hierarchy + Linux 5.8+
//! (`RingBuf`, `CAP_BPF`). Per `bathy_ebpf_design.md` section 5 and
//! `bathy_build_spec.md`'s ratified architecture: fail LOUD on an
//! unsupported host, never silently degrade (e.g. by falling back to a
//! `PerfEventArray` or skipping enforcement). This runs once, at the very
//! top of [`crate::probe::Probe::load_or_reopen`], before anything touches
//! bpffs or the kernel's BPF syscalls.

use std::ffi::CString;

use anyhow::{Context, Result, bail};
use aya::util::KernelVersion;

const KERNEL_FLOOR_MAJOR: u8 = 5;
const KERNEL_FLOOR_MINOR: u8 = 8;
const KERNEL_FLOOR_PATCH: u16 = 0;

const CGROUP_MOUNT: &str = "/sys/fs/cgroup";
/// `CGROUP2_SUPER_MAGIC` from `include/uapi/linux/magic.h`. Not re-exported
/// by the pinned `libc` version as a named constant, so declared locally
/// (same convention `bathyscaphe-ebpf` uses for kernel constants it needs
/// but its pinned crate doesn't name -- see that crate's `SOCK_RAW` /
/// `IPPROTO_UDP`).
const CGROUP2_SUPER_MAGIC: i64 = 0x6367_7270;

/// Runs both checks. Returns an error with a human-readable explanation on
/// the first failure; callers should propagate it and refuse to start
/// rather than attempt any fallback.
pub fn check() -> Result<()> {
    check_kernel_version()?;
    check_cgroup_v2_unified()?;
    Ok(())
}

fn check_kernel_version() -> Result<()> {
    let current = KernelVersion::current().map_err(|error| anyhow::anyhow!("{error}")).context("failed to determine the running kernel version")?;
    let floor = KernelVersion::new(KERNEL_FLOOR_MAJOR, KERNEL_FLOOR_MINOR, KERNEL_FLOOR_PATCH);
    if current < floor {
        bail!(
            "bathyscaphe requires Linux {KERNEL_FLOOR_MAJOR}.{KERNEL_FLOOR_MINOR}+ (RingBuf \
             support and the post-5.8 CAP_BPF split); this host's running kernel is older. \
             Refusing to start rather than silently falling back to a weaker event channel or \
             running without enforcement -- see bathy_ebpf_design.md section 5."
        );
    }
    Ok(())
}

fn check_cgroup_v2_unified() -> Result<()> {
    let path = CString::new(CGROUP_MOUNT).expect("static path contains no NUL bytes");
    let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
    // SAFETY: `stat` is a valid, fully zeroed `libc::statfs` for the
    // duration of the call, and `path` is a valid NUL-terminated C string
    // for at least that long.
    let rc = unsafe { libc::statfs(path.as_ptr(), &mut stat) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error()).with_context(|| format!("statfs({CGROUP_MOUNT}) failed; cannot verify a cgroup v2 unified hierarchy is mounted"));
    }
    // `f_type`'s concrete integer type varies by libc/arch (i32/i64/u32/u64
    // across platforms); `as i64` is deliberately used instead of `From`, so
    // this compiles regardless of which one the pinned libc exposes here.
    if stat.f_type as i64 != CGROUP2_SUPER_MAGIC {
        bail!(
            "{CGROUP_MOUNT} is not mounted as a cgroup2 (unified hierarchy) filesystem (found fs \
             type {:#x}, expected {CGROUP2_SUPER_MAGIC:#x}). bathyscaphe's enforcement hooks \
             (BPF_PROG_TYPE_CGROUP_SOCK_ADDR / BPF_PROG_TYPE_CGROUP_SOCK) only attach to cgroup \
             v2 paths -- a v1 or hybrid hierarchy is out of scope, per bathy_ebpf_design.md \
             section 5.",
            stat.f_type as i64,
        );
    }
    Ok(())
}
