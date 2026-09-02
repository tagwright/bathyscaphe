// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 techgaud
//! Deriving a cgroup id from a cgroup v2 directory path.

use std::os::unix::fs::MetadataExt;
use std::path::Path;

use anyhow::{Context, Result, bail};

/// The value `bpf_get_current_cgroup_id()` returns for processes inside
/// `path` is the cgroup's kernfs node id, which is exactly the inode number
/// of the cgroup v2 directory as seen from userspace (`bathy_build_spec.md`'s
/// ATTRIBUTION section: "cgroup id == the cgroup dir inode"). No BPF call is
/// needed here -- a plain `stat()` gives the same value the kernel hook sees.
pub fn cgroup_id_of(path: &Path) -> Result<u64> {
    let meta = std::fs::metadata(path).with_context(|| format!("failed to stat cgroup path {}", path.display()))?;
    if !meta.is_dir() {
        bail!("{} is not a directory (expected a cgroup v2 path)", path.display());
    }
    Ok(meta.ino())
}
