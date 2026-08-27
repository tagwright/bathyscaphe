// SPDX-License-Identifier: GPL-3.0-or-later
//! `bathyscaphe-ebpf`: the kernel-side programs, built with `bpf-linker`
//! against a `bpfel`/`bpfeb`-unknown-none target (see docs/BUILDING.md).
//!
//! This chunk is the toolchain proof: one real, trivial cgroup/connect4
//! program (`aya::programs::CgroupSockAddr`, attach type
//! `BPF_CGROUP_INET4_CONNECT`) that always allows the connection. It
//! exercises the full compile path (no_std, aya-ebpf macros, bpf-linker)
//! without yet doing any policy work. The real connect4/connect6 +
//! udp4/6-sendmsg + sock_create programs, the LpmTrie policy lookup, the
//! RingBuf event emission, and the per-cgroup tamper counter described in
//! `bathy_ebpf_design.md` land in the EBPF PROGRAMS build chunk.
#![no_std]
#![no_main]

use aya_ebpf::{macros::cgroup_sock_addr, programs::SockAddrContext};
use bathyscaphe_common::Event;

/// Primary enforcement + observation hook (bathy_ebpf_design.md, section
/// 1a / 6.1). Returning `1` allows the connection; `0` would deny it
/// (surfaces as `EPERM` to the caller). For now this always allows: the
/// policy-map lookup and the observe/enforce split are not built yet.
#[cgroup_sock_addr(connect4)]
pub fn connect4(ctx: SockAddrContext) -> i32 {
    match try_connect4(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_connect4(_ctx: SockAddrContext) -> Result<i32, i32> {
    // Touch bathyscaphe-common's shared repr(C) event type from the kernel
    // side, proving it compiles for both the BPF target here and the host
    // target in userspace. No RingBuf, no policy lookup yet -- both land
    // in the EBPF PROGRAMS build chunk, which consumes the map/event
    // schema this crate's COMMON build chunk defines.
    let _event = Event::default();

    // Always allow. See EBPF PROGRAMS build chunk for the real verdict.
    Ok(1)
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
