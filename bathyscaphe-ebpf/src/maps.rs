// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 techgaud
//! The four maps the connect/sendmsg/sock_create hooks share. See
//! `bathyscaphe-common::policy` for why [`POLICY`] is one flat `LpmTrie`
//! (with `cgroup_id` folded into the key) rather than a map-in-map, and
//! `bathy_ebpf_design.md` section 6 for the map-level design this
//! implements.
//!
//! Sizing (`*_MAX_ENTRIES`, `EVENTS_BYTE_SIZE`) is a chunk-#4 placeholder,
//! not a tuned or configurable value — the loader (build chunk #5) does
//! not currently expose a way to override a map's `max_entries` after
//! this object is built, so revisiting these constants is that chunk's
//! problem if the defaults prove too small in practice.

use aya_ebpf::{
    macros::map,
    maps::{HashMap, LpmTrie, RingBuf},
};
use bathyscaphe_common::{EnforcementState, PolicyKeyData, PolicyValue, TamperCounter};

/// Distinct policy prefixes across *all* containers sharing this one flat
/// trie (see `bathyscaphe_common::policy`'s module doc for why it's
/// shared rather than per-container).
const POLICY_MAX_ENTRIES: u32 = 8192;
/// One entry per actively-enforced-or-observed cgroup.
const ENFORCEMENT_MAX_ENTRIES: u32 = 4096;
/// One entry per cgroup that has ever hit a `RingBuf` reserve failure.
const TAMPER_MAX_ENTRIES: u32 = 4096;
/// 256 KiB, a power-of-two multiple of a 4 KiB page as `RingBuf` requires.
const EVENTS_BYTE_SIZE: u32 = 256 * 1024;
/// 128 KiB, same page-alignment requirement as [`EVENTS_BYTE_SIZE`].
/// Smaller than `EVENTS` despite each record being larger
/// (`DnsCapture::WIRE_SIZE` is 552 bytes versus `Event::WIRE_SIZE`'s 88):
/// DNS response traffic is far lower-frequency than connect/sendmsg
/// traffic for any real container, and a placeholder chosen independently
/// of the `EVENTS` sizing on purpose -- see `bathyscaphe_common::dns`'s
/// module doc for why this is a *separate* ring rather than a shared one.
const DNS_EVENTS_BYTE_SIZE: u32 = 128 * 1024;
/// 32 KiB. `DnsQueryCapture` records (24 bytes each, build chunk #10) are
/// smaller than `DnsCapture`'s and there is at most one outbound query per
/// inbound answer this workload will ever generate, so this ring can be
/// smaller than [`DNS_EVENTS_BYTE_SIZE`] while still comfortably holding a
/// burst of concurrent lookups.
const DNS_QUERIES_BYTE_SIZE: u32 = 32 * 1024;

/// The shared policy trie. Key: `cgroup_id (8 bytes) || addr (16 bytes)`,
/// `prefix_len` always `>= PolicyKeyData::MIN_PREFIX_LEN` for any stored
/// entry (see that constant's doc for the isolation invariant this map
/// depends on). Value: a per-prefix default action plus bounded port
/// rules.
#[map]
pub static POLICY: LpmTrie<PolicyKeyData, PolicyValue> = LpmTrie::with_max_entries(POLICY_MAX_ENTRIES, 0);

/// Per-cgroup enforcement posture. Absence of an entry means "no
/// enforcement configured" — see
/// `bathyscaphe_common::enforcement::EnforcementState`'s module doc.
#[map]
pub static ENFORCEMENT: HashMap<u64, EnforcementState> = HashMap::with_max_entries(ENFORCEMENT_MAX_ENTRIES, 0);

/// Per-cgroup count of `RingBuf` reserve failures (dropped events). Bumped
/// by the connect/sendmsg hooks; read by userspace on the `stats` cadence.
#[map]
pub static TAMPER: HashMap<u64, TamperCounter> = HashMap::with_max_entries(TAMPER_MAX_ENTRIES, 0);

/// The shared event output ring, written by every connect/sendmsg
/// invocation regardless of verdict (`bathy_ebpf_design.md` section 2,
/// "one hook, two output paths").
#[map]
pub static EVENTS: RingBuf = RingBuf::with_byte_size(EVENTS_BYTE_SIZE, 0);

/// The DNS-observation output ring, written by `dns_snoop`
/// (`bathyscaphe-ebpf::dns`) for every recognized DNS-response UDP
/// datagram. Separate from [`EVENTS`] -- see [`DNS_EVENTS_BYTE_SIZE`]'s
/// doc.
#[map]
pub static DNS_EVENTS: RingBuf = RingBuf::with_byte_size(DNS_EVENTS_BYTE_SIZE, 0);

/// The DNS QUERY-observation output ring (build chunk #10), written by
/// `dns_query_snoop` (`bathyscaphe-ebpf::dns_query`) for every recognized
/// DNS-query UDP datagram LEAVING a container. Separate from both
/// [`EVENTS`] and [`DNS_EVENTS`] for the identical independent-failure-mode
/// reasoning [`DNS_EVENTS_BYTE_SIZE`]'s doc gives -- a burst of queries
/// dropped here degrades correlation confidence only, never the answer
/// capture stream or connect-event observation.
#[map]
pub static DNS_QUERIES: RingBuf = RingBuf::with_byte_size(DNS_QUERIES_BYTE_SIZE, 0);
