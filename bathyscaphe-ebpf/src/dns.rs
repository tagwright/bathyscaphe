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
//! ## Verifier safety: `bpf_skb_load_bytes` with a clamp-then-mask
//! computed length, never raw pointer arithmetic
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
//! whenever its tracked range does not provably exclude zero. Build chunk
//! #9's first fix for this abandoned a computed length entirely in favor
//! of a handful of literal, compile-time-constant tiers (512, 384, 256,
//! 128, 64, 32 bytes), tried largest-first -- which sidestepped the
//! verifier problem completely (a literal's range is exactly that one
//! value, trivially nonzero) at the cost of a real correctness bug: a
//! response whose true length fell strictly BETWEEN two adjacent tiers
//! (observed live: a genuine ~100-byte answer, between the 64- and
//! 128-byte tiers) was captured at the next SMALLER tier, silently
//! TRUNCATING it -- a truncated DNS message fails to parse in userspace,
//! so that answer never reached the domain cache or the FQDN allow-map at
//! all. Build chunk #12 fixes this by computing the EXACT clamped length
//! instead of picking from a coarse ladder, using an idiom that proves
//! the verifier-required nonzero bound WITHOUT depending on any branch's
//! narrowing surviving codegen (the specific failure chunk #9's own
//! investigation hit: an explicit `>=`-branch early-return immediately
//! before the call still lost its narrowing to `u32`
//! wraparound-truncation codegen or to imprecise signed/unsigned bound
//! tracking across a runtime subtraction, depending on which integer
//! width was used for `skb_len - offset`):
//!
//! 1. **Clamp** the UDP header's own honest length (`payload_len_hint`,
//!    read separately, below) to [`bathyscaphe_common::DNS_CAPTURE_MAX`]
//!    with a plain `if`/`else` -- an ordinary runtime `min`, no
//!    subtraction against any skb-context-derived value at all (the
//!    earlier attempts that failed were all subtracting `skb_len`, a
//!    value with its own uncertain verifier-tracked range; clamping a
//!    small `u16` header field already loaded via `ctx.load` against a
//!    compile-time constant is a much simpler computation for the
//!    verifier, though this step's own narrowing is still not what the
//!    nonzero proof below depends on -- see the next point).
//! 2. **Mask, then add one.** Whatever the clamp step's own tracked range
//!    ends up being (even in the worst case where the compiler loses it
//!    entirely, as chunk #9 found happens for some arithmetic shapes), a
//!    bitwise AND against `DNS_CAPTURE_MAX - 1` (a power-of-two mask)
//!    gives the verifier a FRESH, precise upper bound derived from the AND
//!    instruction itself -- the eBPF verifier computes an AND's output
//!    range directly from the mask operand, independent of the input
//!    register's own prior range. Adding the literal `1` back gives an
//!    equally fresh, precise LOWER bound of exactly 1 -- an unsigned add
//!    of a compile-time positive constant has a provable minimum of
//!    `(prior minimum) + 1`, and the AND's own minimum is triviably `>= 0`
//!    regardless of its input. The combination proves the final value is
//!    in `[1, DNS_CAPTURE_MAX]` by construction, satisfying
//!    `bpf_skb_load_bytes`'s `ARG_CONST_SIZE` requirement -- and, because
//!    the clamped length is already in `[1, DNS_CAPTURE_MAX]` at runtime
//!    (payload_len_hint of exactly 0 is special-cased away before this
//!    code even runs -- see below), subtracting 1, masking, and adding 1
//!    back is a value-preserving IDENTITY: `safe_len` always equals
//!    `capped` exactly, so nothing is lost to the trick itself.
//!
//! The kernel still bounds-checks the resulting single `bpf_skb_load_bytes`
//! call against the real `sk_buff` length and returns an error rather than
//! ever reading out of bounds; a length the skb genuinely cannot satisfy
//! (a corrupt/lying UDP length field, or a fragmented/non-linear skb) now
//! has no smaller-literal-tier fallback to retry -- see
//! `capture_if_dns_response`'s doc for why this is an acceptable,
//! genuinely rare edge case rather than the routine question the tiered
//! design had to answer for every single capture.
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
//! - **Spoofing (mitigated as of build chunk #11)**: this program still
//!   captures *any* UDP:53-sourced datagram reaching the container's
//!   ingress path -- it has no opinion of its own on trust, matching every
//!   other kernel-side program in this crate (`bathy_ebpf_design.md`'s
//!   "policy lives in maps, not in program logic" convention). What
//!   changed in chunk #11: this program now ALSO captures the packet's own
//!   SOURCE address ([`bathyscaphe_common::DnsCapture::src_addr`]) so
//!   userspace can check it against an operator-configured
//!   trusted-resolver allowlist (`bathyscaphe::dns::trust`) before using
//!   the answer to seed enforcement -- see `docs/DNS.md`'s trusted-resolver
//!   section. A source address is not spoofable the way a source PORT
//!   is by a process sharing the same network namespace as the querying
//!   container: it is set by whichever real host actually sent the reply,
//!   the same property IP/CIDR policy itself already relies on everywhere
//!   else in this codebase.

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

/// Embeds a raw IPv4 source address as IPv4-mapped-into-IPv6 per RFC 4291
/// -- the same embedding `bathyscaphe-ebpf::convert::dst_addr_v4` uses for
/// a `bpf_sock_addr` destination, applied here to a byte array read
/// straight off the packet instead.
fn embed_v4(addr: [u8; 4]) -> [u8; 16] {
    let mut out = [0u8; 16];
    out[10] = 0xff;
    out[11] = 0xff;
    out[12..16].copy_from_slice(&addr);
    out
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

    // IPv4 header bytes 12-15 are the SOURCE address, at a fixed offset
    // regardless of IHL (options, if any, come after byte 20) -- build
    // chunk #11's trusted-resolver signal (see this module's doc).
    let src_addr: [u8; 4] = ctx.load(12)?;

    capture_if_dns_response(ctx, ip_header_len, embed_v4(src_addr))
}

fn try_dns_snoop_v6(ctx: &SkBuffContext) -> Result<(), i64> {
    // IPv6 fixed header byte 6 is Next Header. See this module's doc for
    // the documented extension-header gap this fixed-offset read implies.
    let next_header: u8 = ctx.load(6)?;
    if next_header != IPPROTO_UDP {
        return Ok(());
    }
    // IPv6 fixed header bytes 8-23 are the SOURCE address -- no RFC 4291
    // embedding needed, a native IPv6 address is already 16 bytes.
    let src_addr: [u8; 16] = ctx.load(8)?;
    capture_if_dns_response(ctx, IPV6_FIXED_HEADER_LEN, src_addr)
}

/// Shared v4/v6 tail: `l4_offset` is where the UDP header starts. Checks
/// the source port, then copies the EXACT (clamped, not tiered) payload
/// length and submits it -- see this module's doc for the verifier-safe
/// clamp-then-mask idiom this function uses instead of build chunk #9's
/// literal-tier ladder.
///
/// ## Never a full `DnsCapture` on the stack
///
/// `DnsCapture` is 552 bytes -- over the eBPF program stack's 512-byte
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
fn capture_if_dns_response(ctx: &SkBuffContext, l4_offset: usize, src_addr: [u8; 16]) -> Result<(), i64> {
    let src_port_bytes: [u8; 2] = ctx.load(l4_offset)?;
    if u16::from_be_bytes(src_port_bytes) != DNS_SRC_PORT {
        return Ok(());
    }

    // The response's own UDP destination port (bytes 2-3 of the UDP
    // header): the querying process's ephemeral source port, which the
    // resolver addresses its reply back to. Build chunk #10's userspace
    // query/response correlation (`bathyscaphe::dns::pending`) matches
    // this against a captured query's `src_port` to recover the correct
    // querying container's cgroup id when `cgroup_id` below is wrong (see
    // `bathyscaphe_common::dns::DnsCapture::dst_port`'s doc).
    let dst_port_bytes: [u8; 2] = ctx.load(l4_offset + 2)?;
    let dst_port = u16::from_be_bytes(dst_port_bytes);

    // The UDP header's own `length` field (bytes 4-5, header+payload,
    // network byte order): the authoritative basis for the EXACT copy
    // length below (clamped to the capture cap), not merely a hint used
    // to trim tier padding after the fact as it was pre-chunk-#12.
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
        (*ptr).dst_port = dst_port;
        (*ptr).src_addr = src_addr;
    }

    if payload_len_hint == 0 {
        // A zero-length UDP body, or a UDP header claiming less than its
        // own 8-byte size -- nothing to copy. `len` is already 0 from
        // `init_at` above. Still submitted (rather than discarded) so the
        // metadata fields (`dst_port`, `src_addr`, `cgroup_id`) reach
        // userspace like any other capture; `captured()` on a zero-`len`
        // record already yields an empty slice.
        entry.submit(0);
        return Ok(());
    }

    // The EXACT (clamped, not tiered) variable-length copy -- see this
    // module's doc for the full derivation of why the verifier accepts
    // this single call's length argument.
    //
    // SAFETY: `ptr` was initialized by `init_at` above and remains valid
    // for `DnsCapture::WIRE_SIZE` bytes; `payload_ptr` points at exactly
    // `DNS_CAPTURE_MAX` writable bytes within it, at least as large as
    // `safe_len` below can ever be.
    let skb_ptr = ctx.as_ptr();
    let payload_offset_u32 = payload_offset as u32;
    let payload_ptr = unsafe { core::ptr::addr_of_mut!((*ptr).payload).cast::<core::ffi::c_void>() };

    // Step 1: clamp. `payload_len_hint` is nonzero here (the `== 0` case
    // returned above), so `capped` is in `[1, DNS_CAPTURE_MAX]` at
    // runtime -- a plain compile-time-constant `min`, no subtraction
    // against any skb-context-derived value.
    let capped: u32 = if payload_len_hint as u32 > DNS_CAPTURE_MAX as u32 { DNS_CAPTURE_MAX as u32 } else { payload_len_hint as u32 };

    // Step 2: mask, then add one back. This is a value-preserving
    // IDENTITY given `capped`'s actual runtime range above (`capped - 1`
    // is in `[0, DNS_CAPTURE_MAX - 1]`, exactly the mask's own range, so
    // the AND changes nothing) -- its entire purpose is handing the
    // verifier a length argument it can prove is in `[1, DNS_CAPTURE_MAX]`
    // from the AND/ADD instructions THEMSELVES, without depending on
    // whichever range (if any) it managed to track through step 1's own
    // branch. See this module's doc for the full reasoning.
    const DNS_CAPTURE_MASK: u32 = DNS_CAPTURE_MAX as u32 - 1;
    let safe_len: u32 = ((capped - 1) & DNS_CAPTURE_MASK) + 1;

    let ret = unsafe { bpf_skb_load_bytes(skb_ptr, payload_offset_u32, payload_ptr, safe_len) };
    if ret != 0 {
        // The skb didn't actually have `safe_len` bytes available past
        // `payload_offset` -- a corrupt/lying UDP length field, or a
        // fragmented/non-linear skb the kernel could not satisfy. Unlike
        // build chunk #9's tiered design, there is no smaller-literal
        // fallback to retry: this is now a genuinely rare edge case (a
        // real, intact packet's own UDP length field is, by construction,
        // never larger than the packet actually carries), not the
        // routine "which tier fits" question every single capture used
        // to have to answer.
        entry.discard(0);
        return Ok(());
    }

    // `safe_len` is a lossless identity transform of `capped` (see step 2
    // above), and the call just succeeded, so the exact number of bytes
    // actually copied is `capped` itself: the UDP header's own honest
    // length, clamped to the cap, with NO tier-granularity truncation.
    // SAFETY: same pointer, still valid; `len` is a plain `u16` field.
    unsafe {
        (*ptr).len = capped as u16;
    }

    entry.submit(0);
    Ok(())
}
