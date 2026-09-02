// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 techgaud
//! The kernel-written event struct: what the connect4/connect6 and
//! udp4/6-sendmsg hooks (`bathyscaphe-ebpf`, chunk #4) write into the
//! shared `RingBuf` on every invocation, regardless of the allow/deny
//! outcome (`bathy_ebpf_design.md` section 2, "one hook, two output
//! paths"). Userspace (chunk #5's ring-buf consumer) reads these,
//! enriches `cgroup_id` into full container attribution (see the
//! kernel-vs-userspace split note below), and maps the result onto
//! `bathyscaphe_proto::up::Event`, the wire type.
//!
//! ## `verdict` + `would_deny`: two fields, not one
//!
//! The wire protocol's `Verdict` is three-valued (`allow` / `deny` /
//! `would_deny`, see `bathyscaphe-proto::common::Verdict`), but this
//! struct's `verdict` field is only ever [`crate::enums::Verdict::Allow`]
//! or [`crate::enums::Verdict::Deny`] as a raw `u8` — the action the
//! kernel hook actually returned to the caller (`1` allow / `0` deny,
//! surfaced as `EPERM` on deny). `would_deny` is a separate `0`/`1` byte:
//! whether the policy lookup's own verdict was deny, independent of what
//! was actually returned. This is what makes observe-only and
//! enforce-mode a single code path with no drift (`bathy_ebpf_design.md`
//! section 2): in observe-only / audit / alert, `verdict` is always
//! `Allow` and `would_deny` carries the honest lookup result; in `block`
//! mode with a matching deny rule, `verdict` is `Deny` and `would_deny`
//! is also `1` (redundant in that case, but never inconsistent). The
//! daemon reconstructs the wire `Verdict` as: `Deny` if `verdict ==
//! Deny`, else `WouldDeny` if `would_deny != 0`, else `Allow`.
//!
//! ## Kernel-side vs userspace-side attribution
//!
//! **Kernel-side (this struct, and the only identity the kernel hook
//! itself ever needs): `cgroup_id: u64`.** The connect/sendmsg hook reads
//! its own cgroup id via `bpf_get_current_cgroup_id()` — that single u64
//! is sufficient to do the policy map-in-map lookup (`policy.rs`) and the
//! enforcement-state lookup (`enforcement.rs`), and it is the only
//! container-identifying value written into this event. The kernel never
//! knows, and never needs to know, a container's id string, name, image,
//! or runtime.
//!
//! **Userspace-side (NOT in this crate, deliberately no POD type
//! defined for it here):** the `cgroup_id -> container metadata` mapping
//! (container id/name/image/runtime, per `bathy_attribution.md`'s
//! inotify-walk + bollard design) lives entirely in the userspace daemon
//! as an ordinary Rust `HashMap<u64, ContainerInfo>` with heap-allocated
//! `String` fields. It is not `repr(C)`, not `Pod`, and never crosses
//! into a BPF map — the kernel side of that lookup direction does not
//! exist. The daemon's ring-buf consumer is the one place `cgroup_id`
//! (kernel truth) and container metadata (userspace truth) meet, joining
//! this struct with that map to build `bathyscaphe_proto::common::Container`.
//! process/pid/tid/uid/gid/comm are the exception: those ARE resolved
//! kernel-side (cheap, already available in the hook's context via
//! `bpf_get_current_pid_tgid()` / `bpf_get_current_uid_gid()` /
//! `bpf_get_current_comm()`) and written directly into this struct, so
//! `bathyscaphe_proto::common::Process` needs no further kernel lookup,
//! only the `Option`-wrapping the wire type does (a `0` sentinel here
//! means "not resolved", the daemon's problem to decide when that applies).

/// One kernel-observed connect/sendmsg decision.
///
/// Field order is chosen so the struct has zero implicit padding: every
/// multi-byte field either has 8-byte natural alignment and sits in the
/// leading 32-byte run of `u64`/`u32` fields, or is a byte array /
/// single `u8` with alignment 1. Ports are `[u8; 2]` rather than `u16`
/// for the same reason as [`crate::policy::PolicyKeyData::port`]: network
/// byte order as raw bytes, no host-endianness conversion ambiguity, and
/// (incidentally, since alignment isn't the reason here) it keeps the
/// struct's only alignment-driving fields in the leading 32 bytes where
/// they already are naturally.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(C)]
pub struct Event {
    /// `bpf_ktime_get_boot_ns()` at the moment of the hook invocation —
    /// the same clock `PolicyValue::expires_at_ns` is measured on, so an
    /// event's timestamp and a rule's expiry are always directly
    /// comparable without a wall-clock offset. The daemon converts to the
    /// wire protocol's RFC3339 `ts` using a boot-time/wall-clock offset
    /// it samples once at process start.
    pub ktime_ns: u64,
    /// `bpf_get_current_cgroup_id()`. The sole kernel-side container
    /// identity; see the module-level attribution split note.
    pub cgroup_id: u64,
    pub pid: u32,
    pub tid: u32,
    pub uid: u32,
    pub gid: u32,
    /// `bpf_get_current_comm()`. Linux `TASK_COMM_LEN` is 16 including a
    /// NUL terminator; a name at the full 15-character limit will not be
    /// NUL-terminated within this array, matching the kernel's own
    /// on-the-wire convention for `comm` — the daemon must not assume a
    /// trailing NUL is always present.
    pub comm: [u8; 16],
    /// IPv4-mapped-into-IPv6 for a v4 source, same RFC 4291 embedding as
    /// [`crate::policy::PolicyKeyData::addr`].
    pub src_addr: [u8; 16],
    /// Source port, network byte order.
    pub src_port: [u8; 2],
    /// Destination address, same embedding as `src_addr`. This is the
    /// policy lookup input.
    pub dst_addr: [u8; 16],
    /// Destination port, network byte order. This is the policy lookup
    /// input.
    pub dst_port: [u8; 2],
    /// [`crate::enums::TransportProto`] as a raw `u8`.
    pub proto: u8,
    /// [`crate::enums::Verdict`] as a raw `u8`, restricted in practice to
    /// `Allow` or `Deny` — see the module-level note on why `WouldDeny`
    /// is a separate field rather than a third value written here.
    pub verdict: u8,
    /// `0` or `1`: whether the policy lookup's own verdict was deny,
    /// independent of `verdict` (which reflects what the hook actually
    /// returned to the caller).
    pub would_deny: u8,
    /// [`crate::enums::EventType`] as a raw `u8`. v1 kernel programs
    /// write `Connect` only.
    pub event_type: u8,
}

impl Event {
    /// The struct's pinned wire size in bytes, exposed as a named
    /// constant so a size-changing edit anywhere in this struct is caught
    /// at the single call site that matters (the `RingBuf` reserve size
    /// in `bathyscaphe-ebpf`) rather than only in this crate's own tests.
    pub const WIRE_SIZE: usize = core::mem::size_of::<Self>();
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for Event {}

#[cfg(test)]
mod tests {
    use super::*;

    const _EVENT_SIZE: () = assert!(core::mem::size_of::<Event>() == 88);
    const _EVENT_ALIGN: () = assert!(core::mem::align_of::<Event>() == 8);
    const _EVENT_WIRE_SIZE_CONST: () = assert!(Event::WIRE_SIZE == 88);

    #[test]
    fn event_is_pinned() {
        assert_eq!(core::mem::size_of::<Event>(), 88);
        assert_eq!(core::mem::align_of::<Event>(), 8);
        assert_eq!(Event::WIRE_SIZE, 88);
    }

    #[test]
    fn default_event_decodes_as_connect_tcp_allow() {
        // Every field zeroed is a valid, meaningful decode (Connect / Tcp
        // / Allow / not-would-deny), not a sentinel "invalid" state --
        // consistent with every repr(u8) enum in this crate assigning its
        // "first" / most common variant to discriminant 0.
        let ev = Event::default();
        assert_eq!(ev.proto, crate::enums::TransportProto::Tcp as u8);
        assert_eq!(ev.verdict, crate::enums::Verdict::Allow as u8);
        assert_eq!(ev.would_deny, 0);
        assert_eq!(ev.event_type, crate::enums::EventType::Connect as u8);
    }
}
