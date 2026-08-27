// SPDX-License-Identifier: GPL-3.0-or-later
//! `bathyscaphe-common`: no_std POD types shared between the kernel-side
//! eBPF programs (`bathyscaphe-ebpf`) and the userspace loader
//! (`bathyscaphe`).
//!
//! This crate is a placeholder for build chunk #1 (scaffold + toolchain
//! proof). The real map key/value/event structs described in
//! `bathy_ebpf_design.md` (policy rule entries, the kernel-written event
//! struct, per-cgroup counters) land in a later build chunk. What's here
//! now exists only to prove that a `#[repr(C)]`, `aya::Pod`-derivable type
//! can be shared between the `no_std` eBPF crate and the `std` userspace
//! crate across the `user` feature boundary.
#![no_std]

/// Placeholder POD type. Stands in for the real map value types until the
/// COMMON crate build chunk lands.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct PlaceholderRecord {
    pub cgroup_id: u64,
    pub verdict: u8,
    pub _pad: [u8; 7],
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for PlaceholderRecord {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placeholder_record_is_repr_c_sized() {
        // u64 + u8 + 7 bytes of padding, no surprise alignment.
        assert_eq!(core::mem::size_of::<PlaceholderRecord>(), 16);
    }
}
