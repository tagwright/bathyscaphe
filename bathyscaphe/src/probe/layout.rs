// SPDX-License-Identifier: GPL-3.0-or-later
//! The bpffs pin subtree layout. See `probe`'s module doc for the full
//! picture (fresh-load vs resumed-boot lifecycle); this module owns only
//! the path arithmetic and the "what's actually on disk right now" check.

use std::path::PathBuf;

/// Default bpffs root a `Probe` pins under when the caller doesn't override
/// it. A later CLI chunk exposes this as a flag; nothing in this crate
/// hardcodes it beyond this one default.
pub const DEFAULT_BPFFS_ROOT: &str = "/sys/fs/bpf/bathyscaphe";

/// `(ELF map name as declared in bathyscaphe-ebpf's `maps.rs`, pin file
/// basename)`. The two differ in case only (ELF names are conventionally
/// SCREAMING_CASE, pin paths are lowercase) -- kept as an explicit pairing
/// rather than a `.to_lowercase()` call so a future rename on either side is
/// a compile-visible edit here, not a silent runtime mismatch.
pub(crate) const MAP_PIN_NAMES: [(&str, &str); 4] =
    [("POLICY", "policy"), ("ENFORCEMENT", "enforcement"), ("TAMPER", "tamper"), ("EVENTS", "events")];

/// Program names, identical in the ELF and on bpffs (both are just the
/// `bathyscaphe-ebpf` function names -- see that crate's `main.rs`).
pub(crate) const PROG_NAMES: [&str; 5] = ["connect4", "connect6", "sendmsg4", "sendmsg6", "sock_create"];

/// Path arithmetic for the pin subtree. Never touches the filesystem itself
/// (see [`crate::probe::Probe`] for the calls that do); this is pure enough
/// to unit test without bpffs or privilege.
#[derive(Debug, Clone)]
pub struct PinPaths {
    pub root: PathBuf,
}

impl PinPaths {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn maps_dir(&self) -> PathBuf {
        self.root.join("maps")
    }

    pub fn progs_dir(&self) -> PathBuf {
        self.root.join("progs")
    }

    pub fn links_dir(&self) -> PathBuf {
        self.root.join("links")
    }

    pub fn map_path(&self, pin_basename: &str) -> PathBuf {
        self.maps_dir().join(pin_basename)
    }

    pub fn prog_path(&self, name: &str) -> PathBuf {
        self.progs_dir().join(name)
    }

    /// One container's link directory, named by its cgroup id as 16 lowercase
    /// hex digits (fixed width, so the directory listing sorts consistently
    /// and every entry is unambiguously a `u64`, not a truncated one).
    pub fn container_links_dir(&self, cgroup_id: u64) -> PathBuf {
        self.links_dir().join(format!("{cgroup_id:016x}"))
    }

    pub fn container_link_path(&self, cgroup_id: u64, prog_name: &str) -> PathBuf {
        self.container_links_dir(cgroup_id).join(prog_name)
    }
}

/// What's actually pinned on disk right now, relative to what a fully
/// loaded `Probe` expects (the 4 maps + 5 programs; per-container links
/// under `links/` are not part of this check -- their presence or absence
/// doesn't change whether the global maps/programs need a fresh load).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PinState {
    /// Nothing pinned yet: a true cold start.
    Fresh,
    /// Every expected map and program pin is present: safe to reopen.
    Complete,
    /// Some but not all expected pins are present -- most plausibly a crash
    /// partway through a fresh load. Refuse to guess; see
    /// [`crate::probe::Probe::load_or_reopen`].
    Partial(Vec<String>),
}

pub(crate) fn pin_state(paths: &PinPaths) -> PinState {
    let mut missing = Vec::new();
    let mut present = 0usize;
    for (_, pin_basename) in MAP_PIN_NAMES {
        if paths.map_path(pin_basename).exists() {
            present += 1;
        } else {
            missing.push(format!("maps/{pin_basename}"));
        }
    }
    for name in PROG_NAMES {
        if paths.prog_path(name).exists() {
            present += 1;
        } else {
            missing.push(format!("progs/{name}"));
        }
    }
    if missing.is_empty() {
        PinState::Complete
    } else if present == 0 {
        PinState::Fresh
    } else {
        PinState::Partial(missing)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn map_and_prog_paths_are_namespaced_under_root() {
        let paths = PinPaths::new("/sys/fs/bpf/bathyscaphe");
        assert_eq!(paths.map_path("policy"), PathBuf::from("/sys/fs/bpf/bathyscaphe/maps/policy"));
        assert_eq!(paths.prog_path("connect4"), PathBuf::from("/sys/fs/bpf/bathyscaphe/progs/connect4"));
    }

    #[test]
    fn container_link_paths_use_fixed_width_hex_cgroup_id() {
        let paths = PinPaths::new("/sys/fs/bpf/bathyscaphe");
        let path = paths.container_link_path(0x2a, "connect4");
        assert_eq!(path, PathBuf::from("/sys/fs/bpf/bathyscaphe/links/000000000000002a/connect4"));
    }

    #[test]
    fn container_links_dir_disambiguates_by_full_64_bits_not_a_truncated_prefix() {
        // Two cgroup ids that share every byte except the last one must not
        // collide on disk -- this is the filesystem-layer analogue of the
        // in-kernel isolation invariant tested in `policy`'s tests.
        let paths = PinPaths::new("/sys/fs/bpf/bathyscaphe");
        let a = paths.container_links_dir(0x0000_0000_0000_0001);
        let b = paths.container_links_dir(0x0000_0000_0000_0002);
        assert_ne!(a, b);
    }

    #[test]
    fn pin_state_is_fresh_when_nothing_exists() {
        let paths = PinPaths::new("/no/such/path/bathyscaphe-test-fixture");
        assert_eq!(pin_state(&paths), PinState::Fresh);
    }
}
