// SPDX-License-Identifier: GPL-3.0-or-later
//! `bathyscaphe-ebpf`: the kernel-side programs, built with `bpf-linker`
//! against a `bpfel`/`bpfeb`-unknown-none target (see docs/BUILDING.md).
//!
//! Seven attach points, all sharing the maps in [`maps`] and the single
//! decision routine in [`decide`] (`bathy_ebpf_design.md` sections 1a and
//! 6):
//!
//! - `cgroup/connect4`, `cgroup/connect6` — primary enforcement +
//!   observation hook (`BPF_CGROUP_INET4_CONNECT` / `_INET6_CONNECT`).
//! - `cgroup/sendmsg4`, `cgroup/sendmsg6` — the unconnected-UDP companion
//!   (`BPF_CGROUP_UDP4_SENDMSG` / `_UDP6_SENDMSG`), same decision logic,
//!   proto hardcoded to UDP since these attach types are UDP-only by
//!   construction.
//! - `cgroup/sock_create` — denies `SOCK_RAW` socket creation outright
//!   for any cgroup whose [`bathyscaphe_common::EnforcementState::mode`]
//!   is `Block`, closing the raw-socket gap connect/sendmsg can't see
//!   (`bathy_ebpf_design.md` section 1d). This program type IS available
//!   in the pinned `aya-ebpf-macros` (`#[cgroup_sock(sock_create)]`,
//!   attach type `BPF_CGROUP_INET_SOCK_CREATE`) — implemented, not
//!   deferred.
//! - `cgroup_skb` (attached ingress, function name `dns_snoop`) — DNS
//!   response observation (build chunk #9): recognizes a UDP:53-sourced
//!   datagram and captures a bounded prefix of its payload for userspace
//!   to parse. Pure observation, always returns `1` (pass) regardless of
//!   what it finds — see [`dns::try_dns_snoop`]'s module doc for the full
//!   design.
//! - `cgroup_skb` (attached egress, function name `dns_query_snoop`) — DNS
//!   QUERY observation (build chunk #10): recognizes a UDP:53-destined
//!   datagram LEAVING the container and captures its transaction id, its
//!   source port, and the CORRECT cgroup id (the querying container's own
//!   — egress never suffers the resolver-injection attribution problem
//!   `dns_snoop` documents), so userspace can correlate a later response
//!   back to the right container. Also pure observation — see
//!   [`dns_query::try_dns_query_snoop`]'s module doc.
#![no_std]
#![no_main]

mod convert;
mod decide;
mod dns;
mod dns_query;
mod maps;

use aya_ebpf::{
    helpers::bpf_get_current_cgroup_id,
    macros::{cgroup_skb, cgroup_sock, cgroup_sock_addr},
    programs::{SkBuffContext, SockAddrContext, SockContext},
};
use bathyscaphe_common::{EventType, Mode, TransportProto};

use crate::{
    convert::{dst_addr_v4, dst_addr_v6, dst_port, proto_from_context},
    decide::{DestTuple, decide_and_emit},
    maps::ENFORCEMENT,
};

#[cgroup_sock_addr(connect4)]
pub fn connect4(ctx: SockAddrContext) -> i32 {
    match try_connect4(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_connect4(ctx: SockAddrContext) -> Result<i32, i32> {
    let sa = unsafe { &*ctx.sock_addr };
    let dest = DestTuple { dst_addr: dst_addr_v4(sa), dst_port: dst_port(sa), proto: proto_from_context(sa) };
    Ok(decide_and_emit(dest, EventType::Connect))
}

#[cgroup_sock_addr(connect6)]
pub fn connect6(ctx: SockAddrContext) -> i32 {
    match try_connect6(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_connect6(ctx: SockAddrContext) -> Result<i32, i32> {
    let sa = unsafe { &*ctx.sock_addr };
    let dest = DestTuple { dst_addr: dst_addr_v6(sa), dst_port: dst_port(sa), proto: proto_from_context(sa) };
    Ok(decide_and_emit(dest, EventType::Connect))
}

#[cgroup_sock_addr(sendmsg4)]
pub fn sendmsg4(ctx: SockAddrContext) -> i32 {
    match try_sendmsg4(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_sendmsg4(ctx: SockAddrContext) -> Result<i32, i32> {
    let sa = unsafe { &*ctx.sock_addr };
    let dest = DestTuple { dst_addr: dst_addr_v4(sa), dst_port: dst_port(sa), proto: TransportProto::Udp as u8 };
    Ok(decide_and_emit(dest, EventType::Connect))
}

#[cgroup_sock_addr(sendmsg6)]
pub fn sendmsg6(ctx: SockAddrContext) -> i32 {
    match try_sendmsg6(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_sendmsg6(ctx: SockAddrContext) -> Result<i32, i32> {
    let sa = unsafe { &*ctx.sock_addr };
    let dest = DestTuple { dst_addr: dst_addr_v6(sa), dst_port: dst_port(sa), proto: TransportProto::Udp as u8 };
    Ok(decide_and_emit(dest, EventType::Connect))
}

/// `SOCK_RAW` (`include/linux/net.h`). Not re-exported by
/// `aya-ebpf-bindings` as a named constant at the pinned version, so
/// declared locally.
const SOCK_RAW: u32 = 3;

#[cgroup_sock(sock_create)]
pub fn sock_create(ctx: SockContext) -> i32 {
    match try_sock_create(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_sock_create(ctx: SockContext) -> Result<i32, i32> {
    let sock = unsafe { &*ctx.sock };
    if sock.type_ != SOCK_RAW {
        return Ok(1);
    }
    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };
    let blocked = matches!(unsafe { ENFORCEMENT.get(cgroup_id) }, Some(es) if es.mode == Mode::Block as u8);
    Ok(if blocked { 0 } else { 1 })
}

/// DNS observation (build chunk #9). Attached **ingress** (the direction is
/// chosen at attach time in userspace, not by this macro — see
/// `dns::try_dns_snoop`'s module doc). Always returns `1` (pass): this
/// program never gates traffic, only observes it, so a verifier-safe
/// parsing miss, a malformed packet, or a full `DNS_EVENTS` ring never has
/// any effect on the container's actual connectivity.
#[cgroup_skb]
pub fn dns_snoop(ctx: SkBuffContext) -> i32 {
    let _ = dns::try_dns_snoop(&ctx);
    1
}

/// DNS query observation (build chunk #10). Attached **egress** (chosen at
/// attach time in userspace — see `dns_query::try_dns_query_snoop`'s module
/// doc). Always returns `1` (pass): pure observation, exactly like
/// `dns_snoop`.
#[cgroup_skb]
pub fn dns_query_snoop(ctx: SkBuffContext) -> i32 {
    let _ = dns_query::try_dns_query_snoop(&ctx);
    1
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

// The kernel's GPL-helper gate checks this ELF section for one of a fixed
// set of recognized strings; "GPL" is the one that applies to a
// GPL-3.0-or-later-licensed program (this crate's own license, see
// SPDX header above and ../LICENSE).
#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 4] = *b"GPL\0";
