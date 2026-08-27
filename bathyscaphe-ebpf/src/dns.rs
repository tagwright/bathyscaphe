// SPDX-License-Identifier: GPL-3.0-or-later
//! DNS observation: `cgroup/dns_snoop`, a `cgroup_skb` program attached
//! **ingress** to a container's cgroup, that recognizes a UDP datagram
//! whose source port is 53 (a DNS response arriving at the container from
//! its resolver) and copies a bounded prefix of its payload into the
//! `DNS_EVENTS` `RingBuf` for userspace to parse (`bathy_ebpf_design.md`'s
//! DNS-observation section; `bathyscaphe_common::dns`'s module doc for why
//! parsing itself never happens here).
//!
//! ## Program type choice: `cgroup_skb`, not `cgroup_sock_addr`
//!
//! The five programs in `main.rs` all attach via `CgroupSockAddr`
//! (`connect4`/`connect6`/`sendmsg4`/`sendmsg6`) or `CgroupSock`
//! (`sock_create`) -- both fire at a specific *syscall* boundary
//! (`connect()`, `sendmsg()`, socket creation) and only ever see the
//! calling process's own outbound intent, never inbound packet bytes.
//! Observing an *inbound* UDP datagram's payload needs a packet-level
//! hook: `cgroup_skb` (`BPF_PROG_TYPE_CGROUP_SKB`) is the one in this
//! workspace's toolchain that attaches per-cgroup (so attribution is free,
//! exactly like the other five programs) and gets read access to the
//! actual `sk_buff`. `aya::programs::CgroupSkb` / the `#[cgroup_skb]`
//! macro are documented, mature aya APIs (`bathy_ebpf_design.md` section
//! 1b / section 4) -- this is not a new, unproven program type for this
//! codebase's toolchain, just a new attach point of an already-designed-in
//! one (the design brief lists `cgroup_skb/egress` as an *optional v2
//! catch-all enforcement layer*; this chunk uses the sibling `ingress`
//! direction for pure observation instead, a different purpose entirely).
//!
//! ## Why ingress, not egress
//!
//! A DNS *answer* arrives at the container FROM its resolver -- that is
//! ingress traffic from the container's own point of view, regardless of
//! whether the resolver is an external server or Docker's embedded
//! resolver at `127.0.0.11:53` reached over loopback (loopback traffic
//! still passes through the per-cgroup ingress hook like any other
//! interface). The corresponding *query* is egress and is not captured at
//! all -- userspace only ever needs the answer (name + resolved
//! IPs + TTL), never the question packet's own bytes.
//!
//! ## Verifier safety: `bpf_skb_load_bytes` with literal-constant lengths,
//! never raw pointer arithmetic
//!
//! Every fixed-size read in this module (IP version nibble, IHL, protocol,
//! ports, the UDP length field) goes through `SkBuffContext::load::<T>()`,
//! a safe wrapper around the `bpf_skb_load_bytes()` helper -- there is no
//! `data`/`data_end` pointer arithmetic anywhere in this file.
//!
//! The variable-length PAYLOAD copy is the one place this module does NOT
//! use `SkBuffContext::load_bytes()` (the obvious, aya-provided
//! convenience wrapper for exactly this): that wrapper computes its copy
//! length as `(skb_len - offset).min(dst.len())`, and the verifier rejects
//! `bpf_skb_load_bytes`'s length ARGUMENT ("invalid zero-sized read")
//! whenever its tracked range does not provably exclude zero -- which,
//! empirically, against this workspace's pinned toolchain and kernel, it
//! never could be made to, no matter how the surrounding scalar arithmetic
//! was restructured (an explicit `>=`-branch early-return immediately
//! before the call still lost its narrowing to `u32` wraparound-truncation
//! codegen or to imprecise signed/unsigned bound tracking across the
//! subtraction, depending on which integer width was used). The tiered
//! loop inside `capture_if_dns_response` (via the local `try_tier!` macro)
//! sidesteps the entire class of problem by calling `bpf_skb_load_bytes`
//! several times with LITERAL, compile-time `u32` lengths (512, 384,
//! 256, ...), largest first, keeping the first that succeeds -- a
//! literal's range is exactly that one value, trivially nonzero, with no
//! arithmetic for the verifier to reason about. The kernel itself still
//! bounds-checks each attempt against the real `sk_buff` length and
//! returns an error rather than ever reading out of bounds, so nothing
//! about this is less safe than the convenience wrapper -- it is only
//! coarser-grained (see "Tier-granular length" below).
//!
//! ## Tier-granular length, not exact
//!
//! Because the copy length is one of a handful of literal tiers rather
//! than the payload's exact size, a captured record's `payload` can
//! include a few bytes past the true UDP payload boundary (whatever
//! happens to sit there in the `sk_buff`'s linear data). `DnsCapture::len`
//! is set from the UDP header's OWN length field (trusted, read
//! separately) clamped to whichever tier actually succeeded -- never the
//! tier size itself -- so `DnsCapture::captured()` never exposes that
//! trailing tier padding to the parser. See `docs/DNS.md`.
//!
//! ## What is and is not parsed here
//!
//! Only enough of the IPv4/IPv6 + UDP headers to answer "is this a UDP
//! datagram whose source port is 53" and "where does the UDP payload
//! start" -- fixed-offset, fixed-size reads only. The DNS message itself
//! (variable-length names, compression pointers) is never touched in
//! kernel code; see `bathyscaphe_common::dns`'s module doc for why.
//!
//! ## Documented v1 gaps (see `docs/DNS.md` for the full, honest account)
//!
//! - **IPv6 extension headers**: [`try_dns_snoop_v6`] assumes UDP is the
//!   IPv6 fixed header's *immediate* next header (offset 6). A response
//!   arriving behind a Hop-by-Hop/Routing/Fragment extension header is
//!   silently not recognized as DNS (the protocol-byte check at a fixed
//!   offset simply won't match `IPPROTO_UDP`) and is not captured. DNS
//!   traffic essentially never uses IPv6 extension headers in practice, so
//!   this is a low-cost simplification, not a silent correctness gap for
//!   the traffic this program is meant to catch.
//! - **TCP DNS** (large/truncated responses that fall back to TCP:53) is
//!   entirely out of scope for this program -- it only ever matches
//!   `IPPROTO_UDP`. `docs/DNS.md` states this plainly: UDP DNS covers the
//!   overwhelming majority of real-world container DNS traffic (a single
//!   A/AAAA lookup against a typical resolver), TCP fallback is a
//!   documented gap, not a silent one.
//! - **DoH/DoT/ECH**: never touch UDP/TCP port 53 at all and are
//!   structurally invisible to this program by construction -- see
//!   `docs/DNS.md`.
//! - **Spoofing**: this program trusts *any* UDP:53-sourced datagram
//!   reaching the container's ingress path, with no allow-listing of
//!   trusted resolver addresses (unlike Calico/NSX's "trusted DNS
//!   servers" restriction, `prior_art_fqdn.md`). A process inside the same
//!   network namespace capable of spoofing a UDP source port could poison
//!   the userspace cache this feeds. Chunk #10 (FQDN enforcement) is where
//!   this stops being purely a display-enrichment concern and starts
//!   mattering for policy, and is the right point to revisit tightening
//!   this if warranted -- see `docs/DNS.md`.

use aya_ebpf::EbpfContext;
use aya_ebpf::helpers::{bpf_get_current_cgroup_id, bpf_ktime_get_boot_ns, bpf_skb_load_bytes};
use aya_ebpf::programs::SkBuffContext;
use bathyscaphe_common::{DNS_CAPTURE_MAX, DnsCapture};

use crate::maps::DNS_EVENTS;

/// `IPPROTO_UDP` (see `convert.rs`'s identically-named local constant --
/// not re-exported by name at the pinned `aya-ebpf-bindings` version).
const IPPROTO_UDP: u8 = 17;
/// The DNS response signature this program looks for: a UDP datagram
/// whose *source* port is exactly 53.
const DNS_SRC_PORT: u16 = 53;
/// Minimum IPv4 IHL, in 32-bit words (a plain 20-byte header, no options).
/// An IHL below this is malformed and skipped rather than trusted.
const IPV4_MIN_IHL_WORDS: u8 = 5;
/// Fixed IPv6 base header length in bytes (RFC 8200): version/traffic
/// class/flow label (4) + payload length (2) + next header (1) + hop
/// limit (1) + source (16) + destination (16).
const IPV6_FIXED_HEADER_LEN: usize = 40;
/// UDP header length in bytes: source port, dest port, length, checksum.
const UDP_HEADER_LEN: usize = 8;

/// Entry point called from `main.rs`'s `#[cgroup_skb]` function. Always
/// returns successfully to the caller regardless of what it finds --
/// see that call site for why the *return value* of the attached program
/// itself is unconditionally `1` (pass): this hook never gates traffic,
/// only observes it.
pub fn try_dns_snoop(ctx: &SkBuffContext) -> Result<(), i64> {
    // The cgroup_skb context starts at the network (IP) header -- no
    // Ethernet header is present for a cgroup-scoped hook -- so the first
    // nibble of the first byte is the IP version field in both IPv4 and
    // IPv6, independent of which one it turns out to be.
    let version_byte: u8 = ctx.load(0)?;
    match version_byte >> 4 {
        4 => try_dns_snoop_v4(ctx),
        6 => try_dns_snoop_v6(ctx),
        // Not IP at all: should not occur on an AF_INET/AF_INET6 cgroup
        // ingress hook, but there is nothing to capture either way.
        _ => Ok(()),
    }
}

fn try_dns_snoop_v4(ctx: &SkBuffContext) -> Result<(), i64> {
    let ver_ihl: u8 = ctx.load(0)?;
    let ihl_words = ver_ihl & 0x0F;
    if ihl_words < IPV4_MIN_IHL_WORDS {
        // A malformed (impossibly short) IPv4 header. Bail quietly --
        // this program never has an opinion on whether to pass the
        // packet, only on whether it can find a DNS answer inside it.
        return Ok(());
    }
    let ip_header_len = (ihl_words as usize) * 4;

    // IPv4 header byte 9 is the protocol field, at a fixed offset
    // regardless of IHL.
    let protocol: u8 = ctx.load(9)?;
    if protocol != IPPROTO_UDP {
        return Ok(());
    }

    capture_if_dns_response(ctx, ip_header_len)
}

fn try_dns_snoop_v6(ctx: &SkBuffContext) -> Result<(), i64> {
    // IPv6 fixed header byte 6 is Next Header. See this module's doc for
    // the documented extension-header gap this fixed-offset read implies.
    let next_header: u8 = ctx.load(6)?;
    if next_header != IPPROTO_UDP {
        return Ok(());
    }
    capture_if_dns_response(ctx, IPV6_FIXED_HEADER_LEN)
}

/// Shared v4/v6 tail: `l4_offset` is where the UDP header starts. Checks
/// the source port, then copies the bounded payload and submits it.
///
/// ## Never a full `DnsCapture` on the stack
///
/// `DnsCapture` is 536 bytes -- over the eBPF program stack's 512-byte
/// limit on its own, before counting anything else this function (or its
/// callers) needs. Reserving first and initializing/filling the record
/// **in place through a raw pointer into the `RingBuf` slot itself**
/// (`DnsCapture::init_at`, then direct writes to its public `payload`/
/// `len` fields) means no local of `DnsCapture`'s size, or anywhere near
/// it, ever exists -- every write here touches a small, fixed-size field
/// (or is a direct memset through the pointer), which is exactly the
/// "move large on-stack variables into ... map [memory]" fix the verifier
/// itself suggests, applied to `RingBuf` reserved memory rather than a
/// per-CPU array (reserved ring buffer memory is exactly as valid a
/// write destination and needs no extra map).
fn capture_if_dns_response(ctx: &SkBuffContext, l4_offset: usize) -> Result<(), i64> {
    let src_port_bytes: [u8; 2] = ctx.load(l4_offset)?;
    if u16::from_be_bytes(src_port_bytes) != DNS_SRC_PORT {
        return Ok(());
    }

    // The UDP header's own `length` field (bytes 4-5, header+payload,
    // network byte order): trusted here purely to learn how many of the
    // captured bytes are real payload versus tier-padding "garbage" past
    // the true payload boundary (see the tiered-load comment below) --
    // never used to size the `bpf_skb_load_bytes` call itself.
    let udp_len_bytes: [u8; 2] = ctx.load(l4_offset + 4)?;
    let payload_len_hint = u16::from_be_bytes(udp_len_bytes).saturating_sub(UDP_HEADER_LEN as u16);

    let payload_offset = l4_offset + UDP_HEADER_LEN;
    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };
    let ktime_ns = unsafe { bpf_ktime_get_boot_ns() };

    let Some(mut entry) = DNS_EVENTS.reserve::<DnsCapture>(0) else {
        // Deliberately no dedicated tamper counter for a dropped DNS
        // capture: it degrades enrichment freshness only, never
        // enforcement or the connect/sendmsg observation stream that
        // `bathyscaphe_common::counters::TamperCounter` exists to make
        // loud. See this module's doc.
        return Ok(());
    };

    let ptr = entry.as_mut_ptr();
    // SAFETY: `ptr` points at the just-reserved `RingBuf` slot, valid for
    // reads/writes of `DnsCapture::WIRE_SIZE` bytes and correctly aligned
    // -- exactly `init_at`'s precondition.
    unsafe {
        DnsCapture::init_at(ptr, cgroup_id, ktime_ns);
    }

    // Tiered fixed-size loads, largest first: each `bpf_skb_load_bytes`
    // call below requests a LITERAL, compile-time-constant length (512,
    // 384, ...), never a computed scalar.
    //
    // This is a deliberate departure from the "clamp the length to
    // whatever's available" shape `SkBuffContext::load_bytes` (and this
    // module's own earlier draft, calling `bpf_skb_load_bytes` with a
    // manually range-narrowed scalar) uses: `bpf_skb_load_bytes`'s length
    // argument has verifier type `ARG_CONST_SIZE`, which is rejected
    // ("invalid zero-sized read") whenever the argument's tracked range
    // does not provably exclude zero. Every attempt to derive that
    // guarantee from a runtime subtraction (`skb_len - offset`), even
    // behind an explicit `>=` early-return branch immediately before the
    // call, was observed (against this workspace's pinned toolchain and
    // kernel) to still leave the verifier unable to conclude the result
    // is nonzero by the time it reaches the call -- LLVM's BPF backend
    // codegen for the intervening arithmetic loses the narrowing in ways
    // that differ depending on whether the subtraction is done in `u32`
    // (a `<<32`/`>>32` truncate-back-to-32-bits pair for wraparound
    // semantics resets the tracked lower bound to 0) or `u64` (the
    // subtraction's SIGNED bound tracking comes out unrelated to the
    // UNSIGNED bound the preceding `>=` branch established). A literal
    // integer argument sidesteps the entire class of problem: its range
    // is exactly that one value, trivially nonzero, with no arithmetic
    // for the verifier to reason about at all.
    //
    // The tradeoff: a captured record's USEFUL length is tier-granular,
    // not exact -- a 90-byte real DNS message captured via the 128-byte
    // tier includes 38 bytes of whatever happens to sit past the true
    // UDP payload in the skb's linear data (padding, or nothing in
    // particular). `payload_len_hint` (the UDP header's own honest
    // length field, read above) is what keeps this from leaking into
    // anything: `Self::len` is set to `payload_len_hint` clamped to
    // whichever tier actually succeeded, never the tier size itself, so
    // `DnsCapture::captured()` never exposes that padding to the parser.
    // See `docs/DNS.md` for this documented as a v1 characteristic, not
    // a silent gap.
    //
    // SAFETY: `ptr` was initialized by `init_at` above and remains valid
    // for `DnsCapture::WIRE_SIZE` bytes; `payload_ptr` points at exactly
    // `DNS_CAPTURE_MAX` writable bytes within it, at least as large as
    // every literal tier requested below.
    let skb_ptr = ctx.as_ptr();
    let payload_offset_u32 = payload_offset as u32;
    let payload_ptr = unsafe { core::ptr::addr_of_mut!((*ptr).payload).cast::<core::ffi::c_void>() };

    macro_rules! try_tier {
        ($len:literal) => {
            if unsafe { bpf_skb_load_bytes(skb_ptr, payload_offset_u32, payload_ptr, $len) } == 0 {
                Some($len)
            } else {
                None
            }
        };
    }

    const _TOP_TIER_MATCHES_CAPACITY: () = assert!(512 == DNS_CAPTURE_MAX);
    let tier_used = try_tier!(512)
        .or_else(|| try_tier!(384))
        .or_else(|| try_tier!(256))
        .or_else(|| try_tier!(128))
        .or_else(|| try_tier!(64))
        .or_else(|| try_tier!(32));

    let Some(tier_used) = tier_used else {
        // Not even the smallest tier fit -- no payload at all, or a UDP
        // header claiming a length the skb doesn't actually have.
        entry.discard(0);
        return Ok(());
    };

    let useful_len = if payload_len_hint < tier_used { payload_len_hint } else { tier_used };
    // SAFETY: same pointer, still valid; `len` is a plain `u16` field.
    unsafe {
        (*ptr).len = useful_len;
    }

    entry.submit(0);
    Ok(())
}
