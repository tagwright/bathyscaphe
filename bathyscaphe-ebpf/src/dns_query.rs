// SPDX-License-Identifier: GPL-3.0-or-later
//! DNS query observation: `cgroup/dns_query_snoop`, a `cgroup_skb` program
//! attached **egress** to a container's cgroup, that recognizes a UDP
//! datagram whose destination port is 53 (a DNS query LEAVING the
//! container toward its resolver) and captures just enough of its
//! identity -- the DNS transaction id, the query's own source port, and
//! the CORRECT cgroup id -- into the `DNS_QUERIES` `RingBuf` for userspace
//! query/response correlation (build chunk #10, `bathyscaphe::dns::pending`).
//!
//! ## Why this is the FIX for chunk #9's attribution problem
//!
//! `bathyscaphe-ebpf::dns` (`dns_snoop`, ingress) documents that
//! `bpf_get_current_cgroup_id()` at the moment a DNS RESPONSE arrives can
//! report the RESOLVER's cgroup (`docker.service`, `tailscaled.service`)
//! rather than the querying container's, for a reply synthesized/injected
//! directly into the container's netns rather than delivered over a real
//! NIC/veth boundary -- the common case for Docker's embedded resolver at
//! `127.0.0.11` on a user-defined network. The outbound QUERY has no such
//! problem: it is the container's OWN process making an ordinary
//! `sendto()`/`send()` call on its OWN socket, so `bpf_get_current_cgroup_id()`
//! at THIS egress hook is, by construction, always the querying
//! container's real cgroup -- there is no injection, synthesis, or
//! cross-process delivery on the way OUT. Capturing that correct
//! attribution here, keyed by the query's own transaction id and source
//! port, is what lets userspace correlate a later (possibly
//! wrongly-attributed) response back to the right container.
//!
//! ## Program type and direction: `cgroup_skb`, egress
//!
//! Same program type as `dns_snoop` (`bathy_ebpf_design.md` section 1b /
//! section 4's already-designed-in `cgroup_skb` attach point), the sibling
//! `egress` direction instead of `ingress` -- see `dns_snoop`'s module doc
//! for why `cgroup_skb` is the right hook family for per-cgroup packet
//! inspection in this toolchain. One loaded `CgroupSkb` program can be
//! attached at either direction independently (`probe::mod`'s
//! `attach_and_pin_cgroup_skb` already threads an explicit
//! `CgroupSkbAttachType` through for exactly this reason); `dns_snoop` and
//! `dns_query_snoop` are two SEPARATE loaded program instances (distinct
//! ELF sections, distinct function names), not the same program attached
//! twice, since they need different matching logic and write to different
//! ring buffers.
//!
//! ## Verifier safety: fixed-offset, fixed-size loads only
//!
//! Every read here is `SkBuffContext::load::<T>()` at a literal,
//! compile-time-known offset for a compile-time-known-size `T` -- the IP
//! version nibble, IHL, protocol byte, both UDP ports, and the two-byte
//! DNS transaction id immediately following the UDP header. None of this
//! needs `dns_snoop`'s tiered-literal-length `bpf_skb_load_bytes` trick:
//! that trick exists specifically for the ONE call that copies a
//! variable-length, potentially-large payload (`dns_snoop`'s full DNS
//! message body). This program never copies a payload at all -- it reads
//! exactly six small, fixed-size fields and discards the rest of the
//! packet, so every load already has the "literal, trivially nonzero
//! length" shape that sidesteps the "invalid zero-sized read" verifier
//! rejection `dns_snoop`'s doc describes in detail.
//!
//! [`DnsQueryCapture`] is 24 bytes, far under the eBPF program stack's
//! 512-byte limit even alongside this function's other locals, so unlike
//! `dns_snoop`'s [`bathyscaphe_common::DnsCapture`] (552 bytes), it is
//! built by value on the stack and written into the reserved `RingBuf`
//! slot with a plain `entry.write(...)` -- the same shape
//! `bathyscaphe-ebpf::decide::emit_event` already uses for the similarly
//! small `Event` struct. No `init_at`-style raw-pointer constructor is
//! needed here.
//!
//! ## Docker's embedded-DNS DNAT rewrite (found empirically, build chunk #10)
//!
//! A naive `dst_port == 53` match, run against a real container on a
//! user-defined Docker network, captured NOTHING for the query side even
//! though the corresponding response was captured correctly by `dns_snoop`
//! (proving the query really was sent and really did get an answer).
//! Investigated directly (a temporary diagnostic build that captured EVERY
//! egress UDP datagram's cgroup id, ports, and destination regardless of
//! port, run three times against fresh containers): every run showed the
//! query's OBSERVED destination port at THIS hook was a random high port
//! (55561, 55508, and 48204 across three separate container lifetimes) --
//! never 53 -- while the query's source port exactly matched the later
//! response's destination port each time (proving these captured
//! datagrams really were the DNS query/response pair, correctly
//! correlatable, just not recognizable by port alone). The destination
//! ADDRESS, however, stayed `127.0.0.11` (Docker's embedded resolver)
//! throughout.
//!
//! The explanation: Docker's embedded DNS resolver is not actually bound
//! to `127.0.0.11:53` directly. Per-container-network-namespace iptables
//! `DNAT` rules rewrite a query addressed to `127.0.0.11:53` to an
//! internal, randomly-allocated high port where the real resolver listens
//! -- and `cgroup_skb`'s `BPF_CGROUP_INET_EGRESS` attach point fires AFTER
//! `LOCAL_OUT` netfilter NAT processing, so this program only ever
//! observes the ALREADY-REWRITTEN destination port, never the port `55508`
//! the container's own userspace code actually dialed (`53`, per the
//! Docker documentation and its `resolv.conf`). This is the inverse of
//! `dns_snoop`'s (ingress) situation: conntrack un-NATs the RETURN leg
//! symmetrically, so the response's SOURCE port correctly reads back as
//! `53` by the time `dns_snoop` sees it -- ingress and egress are affected
//! asymmetrically by the exact same NAT rule.
//!
//! **The fix**: match EITHER the genuine port-53 case (a query sent
//! directly to an external resolver reached over a real path, never
//! NAT-rewritten) OR a destination address of `127.0.0.11`
//! ([`DOCKER_EMBEDDED_DNS_V4`]) regardless of port -- the DNAT rule
//! rewrites the port but not the address (a `REDIRECT`-style same-host
//! DNAT), so the address stays a reliable, NAT-invariant signal
//! specifically for this one well-known resolver. This is a targeted,
//! Docker-specific special case, not a general "any locally-DNAT'd UDP
//! traffic" heuristic -- documented as such in `docs/DNS.md`, alongside
//! the residual gap this does NOT close: a resolver reached through some
//! OTHER local DNAT scheme (a different container runtime's own embedded
//! resolver at a different well-known address, for instance) would need
//! its own address added here to be recognized the same way.
//!
//! ## What is NOT captured, and why (see `docs/DNS.md` for the full account)
//!
//! - **The query NAME** is never parsed here -- see
//!   [`bathyscaphe_common::DnsQueryCapture`]'s module doc: the response
//!   (already fully captured by `dns_snoop`) carries the queried name back
//!   in its own question section, which userspace already parses.
//! - **TCP DNS queries** are out of scope, matching `dns_snoop`'s own
//!   documented TCP gap: this program matches `IPPROTO_UDP` only.
//! - **DoH/DoT/ECH** queries never touch UDP/TCP port 53 at all and are
//!   structurally invisible here, for the identical reason `dns_snoop`
//!   documents for responses.
//! - **IPv6 extension headers**: the IPv6 path assumes UDP is the fixed
//!   40-byte header's immediate next header, the same simplification
//!   `dns_snoop` makes.
//! - **This program is pure observation**: it always returns `1` (pass)
//!   regardless of what it finds, and a full `DNS_QUERIES` ring or a
//!   parsing miss has no effect on the container's actual connectivity --
//!   identical posture to `dns_snoop`.

use aya_ebpf::helpers::{bpf_get_current_cgroup_id, bpf_ktime_get_boot_ns};
use aya_ebpf::programs::SkBuffContext;
use bathyscaphe_common::DnsQueryCapture;

use crate::maps::DNS_QUERIES;

/// `IPPROTO_UDP` (mirrors `dns.rs`'s identically-named local constant).
const IPPROTO_UDP: u8 = 17;
/// The DNS query signature this program looks for: a UDP datagram whose
/// *destination* port is exactly 53.
const DNS_DST_PORT: u16 = 53;
const IPV4_MIN_IHL_WORDS: u8 = 5;
const IPV6_FIXED_HEADER_LEN: usize = 40;
const UDP_HEADER_LEN: usize = 8;
/// Docker's fixed embedded-DNS resolver address (127.0.0.11). See this
/// module's doc, "Docker's embedded-DNS DNAT rewrite", for why a query's
/// DESTINATION ADDRESS is checked against this constant as an ADDITIONAL
/// match condition alongside the port-53 check, not merely for
/// documentation/enrichment purposes.
const DOCKER_EMBEDDED_DNS_V4: [u8; 4] = [127, 0, 0, 11];

/// Entry point called from `main.rs`'s `#[cgroup_skb]` function. Always
/// returns successfully to the caller regardless of what it finds -- see
/// that call site for why the attached program's own return value is
/// unconditionally `1` (pass): this hook never gates traffic, only
/// observes it.
pub fn try_dns_query_snoop(ctx: &SkBuffContext) -> Result<(), i64> {
    // Identical "no Ethernet header on a cgroup_skb hook" reasoning as
    // `dns::try_dns_snoop` -- the context starts at the IP header.
    let version_byte: u8 = ctx.load(0)?;
    match version_byte >> 4 {
        4 => try_dns_query_snoop_v4(ctx),
        6 => try_dns_query_snoop_v6(ctx),
        _ => Ok(()),
    }
}

fn try_dns_query_snoop_v4(ctx: &SkBuffContext) -> Result<(), i64> {
    let ver_ihl: u8 = ctx.load(0)?;
    let ihl_words = ver_ihl & 0x0F;
    if ihl_words < IPV4_MIN_IHL_WORDS {
        return Ok(());
    }
    let ip_header_len = (ihl_words as usize) * 4;

    let protocol: u8 = ctx.load(9)?;
    if protocol != IPPROTO_UDP {
        return Ok(());
    }

    // IPv4 header bytes 16-19 are the destination address, at a fixed
    // offset regardless of IHL (options, if any, come after byte 20). See
    // this module's doc ("Docker's embedded-DNS DNAT rewrite") for why
    // this address check exists alongside the port check below.
    let dst_addr: [u8; 4] = ctx.load(16)?;
    let is_docker_embedded_resolver = dst_addr == DOCKER_EMBEDDED_DNS_V4;

    capture_if_dns_query(ctx, ip_header_len, is_docker_embedded_resolver)
}

fn try_dns_query_snoop_v6(ctx: &SkBuffContext) -> Result<(), i64> {
    let next_header: u8 = ctx.load(6)?;
    if next_header != IPPROTO_UDP {
        return Ok(());
    }
    // Docker's embedded resolver is documented (`docs/DNS.md`) as an
    // IPv4-only fixed address (`127.0.0.11`); no analogous well-known IPv6
    // address exists to special-case here, so the port-only match applies.
    capture_if_dns_query(ctx, IPV6_FIXED_HEADER_LEN, false)
}

/// Shared v4/v6 tail: `l4_offset` is where the UDP header starts. Matches
/// EITHER a genuine port-53 destination (a query sent directly to an
/// external resolver, or to a resolver not sitting behind Docker's
/// embedded-DNS DNAT) OR `is_docker_embedded_resolver` (see this module's
/// doc for why port alone misses Docker's own embedded resolver), then
/// reads the transaction id and submits.
fn capture_if_dns_query(ctx: &SkBuffContext, l4_offset: usize, is_docker_embedded_resolver: bool) -> Result<(), i64> {
    let dst_port_bytes: [u8; 2] = ctx.load(l4_offset + 2)?;
    let dst_port = u16::from_be_bytes(dst_port_bytes);
    if dst_port != DNS_DST_PORT && !is_docker_embedded_resolver {
        return Ok(());
    }

    let src_port_bytes: [u8; 2] = ctx.load(l4_offset)?;
    let src_port = u16::from_be_bytes(src_port_bytes);

    // The DNS message's transaction id: the first two bytes of the UDP
    // payload, immediately after the 8-byte UDP header. A fixed, literal
    // 2-byte load -- no tiered trick needed, see this module's doc.
    let Ok(txid_bytes) = ctx.load::<[u8; 2]>(l4_offset + UDP_HEADER_LEN) else {
        // A datagram too short to carry even a DNS header (e.g. a
        // zero-length payload) has no transaction id to correlate on --
        // nothing to capture, not an error to propagate.
        return Ok(());
    };
    let txid = u16::from_be_bytes(txid_bytes);

    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };
    let ktime_ns = unsafe { bpf_ktime_get_boot_ns() };

    if let Some(mut entry) = DNS_QUERIES.reserve::<DnsQueryCapture>(0) {
        entry.write(DnsQueryCapture::new(ktime_ns, cgroup_id, txid, src_port));
        entry.submit(0);
    }
    // A `RingBuf` reserve failure here is deliberately not tracked by the
    // security-relevant `TamperCounter` -- identical reasoning to
    // `dns_snoop`'s own dropped-capture handling: a lost query capture
    // degrades correlation confidence only (the later response falls back
    // to its own, possibly-wrong, cgroup attribution), never enforcement.

    Ok(())
}
