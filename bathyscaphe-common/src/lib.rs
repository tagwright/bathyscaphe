// SPDX-License-Identifier: GPL-3.0-or-later
//! `bathyscaphe-common`: `no_std`, `repr(C)`, `aya::Pod`-derivable types
//! shared between the kernel-side eBPF programs (`bathyscaphe-ebpf`,
//! chunk #4) and the userspace loader/daemon (`bathyscaphe`, chunks
//! #5-#8). This crate IS the ABI between kernel and user: every public
//! type here is fixed-size, contains no pointers, and carries no logic
//! beyond trivial constructors and named constants (rule application,
//! make-before-break policy swaps, and `Match::is_inert`-style evaluation
//! belong to the daemon and live in `bathyscaphe` / `bathyscaphe-proto`,
//! not here).
//!
//! `bathyscaphe-common` deliberately does not depend on
//! `bathyscaphe-proto` (a `std` + serde crate) — see `enums.rs` for how
//! numeric equivalence with the wire protocol's enums is documented
//! instead of enforced by a shared dependency.
//!
//! See `bathy_ebpf_design.md` (the eBPF design brief) for the map/hook
//! architecture this crate's types implement, and `policy.rs` in
//! particular for the in-kernel policy map schema — ratified 2026-08-27
//! as a nested per-prefix-port-rules scheme, with a documented,
//! toolchain-forced deviation from true per-container map-in-map (aya's
//! map-in-map support is unmerged upstream as of this writing).
//!
//! ## Module map
//!
//! - [`enums`]: shared `repr(u8)` enums (`TransportProto`, `Verdict`,
//!   `RuleAction`, `RuleSource`, `Mode`, `DefaultVerdict`, `EventType`),
//!   documented numeric equivalence to `bathyscaphe-proto::common`. Never
//!   used directly as a map key/value type — see that module's doc for
//!   why.
//! - [`policy`]: the in-kernel policy map schema — [`policy::PolicyKeyData`]
//!   (the `LpmTrie` key's `data` portion, `cgroup_id` folded in as a
//!   toolchain-forced substitute for true map-in-map, see that module's
//!   doc), [`policy::PolicyValue`] (the `LpmTrie` value: a per-prefix
//!   default action plus up to [`policy::MAX_PORT_RULES`] bounded
//!   [`policy::PortRule`]s).
//! - [`enforcement`]: [`enforcement::EnforcementState`], the outer
//!   per-cgroup map value (mode, default verdict, generation) that gates
//!   whether a container is enforced at all.
//! - [`event`]: [`event::Event`], the kernel-written `RingBuf` record.
//! - [`counters`]: [`counters::TamperCounter`], the per-cgroup
//!   ring-buffer-drop counter.
//! - [`dns`]: [`dns::DnsCapture`], the kernel-written DNS-snoop `RingBuf`
//!   record (build chunk #9's DNS observation layer).
#![no_std]

pub mod counters;
pub mod dns;
pub mod enforcement;
pub mod enums;
pub mod event;
pub mod policy;

pub use counters::TamperCounter;
pub use dns::{DNS_CAPTURE_MAX, DnsCapture};
pub use enforcement::EnforcementState;
pub use enums::{DefaultVerdict, EventType, InvalidDiscriminant, Mode, RuleAction, RuleSource, TransportProto, Verdict};
pub use event::Event;
pub use policy::{MAX_PORT_RULES, PolicyKeyData, PolicyValue, PortRule};
