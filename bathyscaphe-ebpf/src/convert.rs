// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 techgaud
//! Byte-level extraction from the `bpf_sock_addr` context the kernel hands
//! `cgroup/connect4`, `cgroup/connect6`, `cgroup/sendmsg4`, and
//! `cgroup/sendmsg6` programs (`bathy_ebpf_design.md` section 1a).
//!
//! ## The `to_ne_bytes`, not `to_be_bytes`, gotcha
//!
//! `bpf_sock_addr::user_ip4`, `user_ip6[i]`, and `user_port` are all
//! documented by the kernel as holding their value "in network byte
//! order" — but they are typed as plain `__u32` fields, not byte arrays.
//! The kernel writes the address/port's network-order bytes directly into
//! that field's memory; this module reads the field back as a normal
//! machine integer. `u32::to_ne_bytes()` returns a value's bytes in
//! whatever order they already sit in memory (no reordering), so calling
//! it on one of these fields recovers exactly the network-order byte
//! sequence the kernel wrote, on any host endianness. Calling
//! `to_be_bytes()` here instead would silently byte-swap an
//! already-correct value on a little-endian host — a classic eBPF
//! off-by-endianness bug this module avoids by construction.
//!
//! ## Source address: not collected in v1
//!
//! `bpf_sock_addr` exposes the *destination* the syscall is dialing
//! (`user_ip4`/`user_ip6`/`user_port`) directly as safe-to-read fields,
//! but no equivalent safe field for the *local/source* address — only a
//! raw `sk: *mut bpf_sock` pointer behind a union, which needs additional
//! verifier-sensitive helpers (`bpf_sk_fullsock` and friends) to read
//! from safely. This chunk's mandate is compile+link+section-presence,
//! not a verifier-proven runtime path (see the eBPF build chunk's brief),
//! so `Event::src_addr`/`src_port` are left zeroed for now rather than
//! risk an unverified pointer-chasing pattern. Source address is also the
//! least valuable half of this event's addressing anyway — it's always
//! "this container", already known via `cgroup_id`/attribution — so this
//! is a reasonable v1 gap, not a load-bearing omission. A future chunk
//! (daemon or runtime-testing) can fill this in once it's proven safe
//! against a real verifier.

use aya_ebpf::bindings::bpf_sock_addr;
use bathyscaphe_common::TransportProto;

/// `IPPROTO_UDP`. Not re-exported by `aya-ebpf-bindings` as a named
/// constant at the pinned version, so declared locally.
const IPPROTO_UDP: u32 = 17;

/// Destination address for a `connect4`/`sendmsg4` invocation, embedded as
/// IPv4-mapped-into-IPv6 per RFC 4291 (matching
/// `bathyscaphe_common::PolicyKeyData`'s convention).
pub fn dst_addr_v4(sa: &bpf_sock_addr) -> [u8; 16] {
    let mut addr = [0u8; 16];
    addr[10] = 0xff;
    addr[11] = 0xff;
    addr[12..16].copy_from_slice(&sa.user_ip4.to_ne_bytes());
    addr
}

/// Destination address for a `connect6`/`sendmsg6` invocation. `user_ip6`
/// is four `__u32` words, each carrying four network-order bytes in
/// memory order (word 0 = the address's first four bytes) — the same
/// `to_ne_bytes` convention as `dst_addr_v4`, applied per word.
pub fn dst_addr_v6(sa: &bpf_sock_addr) -> [u8; 16] {
    let mut addr = [0u8; 16];
    let mut i = 0;
    while i < 4 {
        let word = sa.user_ip6[i].to_ne_bytes();
        addr[i * 4] = word[0];
        addr[i * 4 + 1] = word[1];
        addr[i * 4 + 2] = word[2];
        addr[i * 4 + 3] = word[3];
        i += 1;
    }
    addr
}

/// Destination port, network byte order, for any of the four hooks.
pub fn dst_port(sa: &bpf_sock_addr) -> [u8; 2] {
    let bytes = sa.user_port.to_ne_bytes();
    [bytes[0], bytes[1]]
}

/// Transport derived from the context's `protocol` field (`IPPROTO_TCP` /
/// `IPPROTO_UDP`), rather than assumed from the hook name. `connect()` can
/// be called on a `SOCK_DGRAM` socket (connected UDP — see
/// `bathy_ebpf_design.md` section 1a), so `connect4`/`connect6` are not
/// TCP-only in practice; this is a deliberate refinement of "connect
/// hooks are TCP" for that reason. `sendmsg4`/`sendmsg6` are UDP-only by
/// construction of the attach type itself, so their call sites hardcode
/// `TransportProto::Udp` instead of calling this (same answer, no need to
/// re-derive it).
pub fn proto_from_context(sa: &bpf_sock_addr) -> u8 {
    if sa.protocol == IPPROTO_UDP { TransportProto::Udp as u8 } else { TransportProto::Tcp as u8 }
}
