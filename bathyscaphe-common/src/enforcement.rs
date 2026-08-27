// SPDX-License-Identifier: GPL-3.0-or-later
//! The outer per-cgroup **enforcement state**: the map value that tells
//! the kernel connect/sendmsg hooks a container's current posture, keyed
//! directly by `cgroup_id: u64` (the map declaration itself — a plain
//! `HashMap<u64, EnforcementState>`, pinned to bpffs — lives in
//! `bathyscaphe-ebpf` and the loader, not here).
//!
//! This is a **separate** map from the policy map-in-map described in
//! `policy.rs`: the outer policy map answers "what does this container's
//! rule set say about this destination", this map answers "does this
//! container have enforcement configured at all, and if so, what mode and
//! default". The two are consulted together by the connect/sendmsg hook:
//! **no entry here means no enforcement** (see [`EnforcementState`]'s
//! cold-start note below) regardless of what the policy map-in-map holds.

/// A container's enforcement posture as the kernel knows it.
///
/// Field order puts the `u64 generation` first for the same reason as
/// [`crate::policy::PolicyValue`]: it reaches 8-byte alignment without a
/// compiler-inserted gap ahead of it, and the explicit trailing `_pad`
/// keeps every byte of the struct deterministically initialized (this
/// type crosses the kernel/user boundary as `aya::Pod`, so uninitialized
/// padding would be observable, un-zeroed garbage in a userspace read).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(C)]
pub struct EnforcementState {
    /// airlock-owned monotonic counter, echoed straight from the wire
    /// protocol's `policy.generation` into this map so `hello.pinned` and
    /// `stats.containers[].generation` can report exactly what's
    /// enforced, not just what was last requested.
    pub generation: u64,
    /// [`crate::enums::Mode`] as a raw `u8`. On the kernel side, `Audit`
    /// and `Alert` are indistinguishable — both always allow and always
    /// report `would_deny` honestly; the value is threaded through
    /// unmodified because `stats.containers[].mode` reports the intent,
    /// not just the kernel's binary armed/not-armed state (`enforcing` in
    /// the wire protocol is a userspace-computed cross-check, not stored
    /// here).
    pub mode: u8,
    /// [`crate::enums::DefaultVerdict`] as a raw `u8`: what the kernel
    /// hook returns for a destination that matches no entry in this
    /// container's policy map-in-map trie (and no [`crate::policy::ExactPortKey`]
    /// entry, if that map is wired). This is the "empty/never-configured
    /// policy" question the eBPF design brief's fork #1 raises, and it is
    /// answered per-container, explicitly, on the wire (`policy.default`)
    /// — never a single hardcoded kernel constant.
    pub default_verdict: u8,
    /// Reserved for future per-container bits (none assigned). Always
    /// `0` in this build.
    pub flags: u8,
    _pad: [u8; 5],
}

impl EnforcementState {
    /// Trivial constructor. `flags` is always `0` until a bit is defined.
    pub const fn new(generation: u64, mode: u8, default_verdict: u8) -> Self {
        Self { generation, mode, default_verdict, flags: 0, _pad: [0; 5] }
    }
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for EnforcementState {}

#[cfg(test)]
mod tests {
    use super::*;

    const _ENFORCEMENT_STATE_SIZE: () = assert!(core::mem::size_of::<EnforcementState>() == 16);
    const _ENFORCEMENT_STATE_ALIGN: () = assert!(core::mem::align_of::<EnforcementState>() == 8);

    #[test]
    fn enforcement_state_is_pinned() {
        assert_eq!(core::mem::size_of::<EnforcementState>(), 16);
        assert_eq!(core::mem::align_of::<EnforcementState>(), 8);
    }

    #[test]
    fn no_entry_means_no_enforcement_is_a_map_semantics_fact_not_a_field() {
        // There is deliberately no "enabled" bit on this struct: a
        // cold-start container simply has no key in the outer map at
        // all, and the kernel hook's map-miss branch is what returns
        // allow-with-no-policy-lookup. A zeroed EnforcementState would
        // decode as Mode::Audit / DefaultVerdict::Allow, which is a valid
        // *configured* state, not the same thing as "absent" -- so
        // constructing one here is only ever meaningful once a real
        // `policy` directive has actually written an entry.
        let never_configured_would_look_like = EnforcementState::default();
        assert_eq!(never_configured_would_look_like.mode, 0);
        assert_eq!(never_configured_would_look_like.default_verdict, 0);
    }
}
