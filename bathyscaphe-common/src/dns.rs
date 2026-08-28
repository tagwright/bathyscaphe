// SPDX-License-Identifier: GPL-3.0-or-later
//! The kernel-written DNS capture record: what the DNS-snoop `cgroup_skb`
//! program (`bathyscaphe-ebpf::dns`, build chunk #9) writes into the
//! `DNS_EVENTS` `RingBuf` for every UDP datagram it judges to be a DNS
//! response (source port 53) reaching a monitored container.
//!
//! ## Why a separate ring buffer from `EVENTS`
//!
//! [`crate::event::Event`] is a small, fixed 88-byte record sized for
//! connect/sendmsg throughput. A DNS response payload is far larger and
//! genuinely variable in size (up to [`DNS_CAPTURE_MAX`] bytes captured
//! here). Sharing one ring buffer between a high-frequency small record and
//! a lower-frequency large one would mean a burst of DNS traffic could
//! starve the connect-event stream's capacity (or vice versa) purely on
//! byte accounting, not on anything policy-relevant. A dedicated
//! `DNS_EVENTS` ring (`bathyscaphe-ebpf::maps`) keeps the two failure modes
//! independent: a dropped DNS capture degrades enrichment freshness only,
//! never enforcement or connect-event observation.
//!
//! ## Why the kernel does not parse DNS
//!
//! DNS names use variable-length labels and compression pointers (RFC
//! 1035 section 4.1.4) that require following backward offsets into
//! earlier parts of the message -- a pattern the eBPF verifier's bounded,
//! loop-limited execution model handles poorly and unsafely if attempted
//! by hand. This struct carries the **raw captured bytes only**; a real,
//! maintained DNS parser crate does the parsing in userspace (see
//! `bathyscaphe`'s `attribution::dns` module).

/// Maximum DNS message payload bytes captured per record. Chosen well
/// above the historical 512-byte "traditional" UDP DNS response ceiling
/// yet still small: most A/AAAA answers for the handful of names a
/// container resolves are far smaller than this, and a response that
/// doesn't fit is truncated (documented in `docs/DNS.md`) rather than
/// causing the capture to fail -- see [`crate::event::Event::WIRE_SIZE`]
/// for the same "pin a wire size as a named constant" convention this
/// crate follows throughout.
pub const DNS_CAPTURE_MAX: usize = 512;

/// One captured (and possibly truncated) UDP payload from a source-port-53
/// datagram, plus the identity/timing fields userspace needs to attribute
/// and age it.
///
/// Field order and the explicit `_pad` follow the same deterministic,
/// zero-implicit-padding convention as every other kernel/user boundary
/// type in this crate (see [`crate::policy::PolicyValue`]'s doc): the two
/// `u64`s reach 8-byte alignment with no compiler-inserted gap, `len`/
/// `dst_port` (two `u16`s) need no gap after them, [`Self::src_addr`]
/// (alignment 1, 16 bytes) follows with no gap of its own, `_pad` rounds
/// the running total up to a multiple of 8 before `payload` (whose own
/// alignment is 1, so it needs no padding of its own) so every byte that
/// crosses the kernel/user boundary as `aya::Pod` is deterministically
/// initialized.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct DnsCapture {
    /// `bpf_ktime_get_boot_ns()` at capture time -- the same clock
    /// [`crate::event::Event::ktime_ns`] and [`crate::policy::PolicyValue::expires_at_ns`]
    /// use, so userspace can compute "how fresh is this answer" without a
    /// wall-clock offset.
    pub ktime_ns: u64,
    /// `bpf_get_current_cgroup_id()`: which container observed this DNS
    /// traffic. Userspace's per-container IP->domain cache is keyed on
    /// this, exactly like [`crate::event::Event::cgroup_id`] -- but see
    /// `docs/DNS.md`'s attribution caveat: for a reply synthesized/injected
    /// by a resolver such as Docker's embedded `127.0.0.11`, THIS value is
    /// the RESOLVER's cgroup, not necessarily the querying container's.
    /// [`Self::dst_port`] (build chunk #10) is what lets userspace recover
    /// the correct cgroup via query/response correlation.
    pub cgroup_id: u64,
    /// How many leading bytes of [`Self::payload`] the kernel actually
    /// wrote (bounded by both the real UDP payload length and
    /// [`DNS_CAPTURE_MAX`]). Never trust bytes at index `>= len` --
    /// they are zero-initialized, not truncated message content.
    pub len: u16,
    /// The UDP destination port this response arrived on, network byte
    /// order stored host-endian here (a plain `u16`, unlike the raw
    /// `[u8; 2]` convention `bathyscaphe_common::event::Event` uses for
    /// wire ports -- this value never crosses back onto the wire itself,
    /// it only ever feeds a userspace hash-map key, so there is no
    /// byte-order ambiguity to preserve). This is the querying process's
    /// own ephemeral source port from the original DNS query -- build
    /// chunk #10's query/response correlation
    /// (`bathyscaphe::dns::pending::PendingQueryTable`) matches this
    /// against a captured query's `src_port` (same value) plus both
    /// messages' shared DNS transaction id to recover the CORRECT
    /// querying container's cgroup id when [`Self::cgroup_id`] above is
    /// wrong (the Docker-embedded-DNS / Tailscale-intercepted-DNS case
    /// `docs/DNS.md` documents).
    pub dst_port: u16,
    /// Build chunk #11: the IP packet's own SOURCE address that carried
    /// this response, IPv4-mapped-into-IPv6 per RFC 4291 -- the same
    /// embedding [`crate::event::Event::src_addr`] and
    /// [`crate::policy::PolicyKeyData::addr`] use. This is the field the
    /// trusted-resolver allowlist (`bathyscaphe::dns::trust`) checks: only
    /// a response whose `src_addr` is in the operator-configured
    /// trusted-resolver set is used to seed enforcement (`docs/DNS.md`'s
    /// spoofing section). Unlike [`Self::cgroup_id`], this value is never
    /// wrong for an injected/synthesized reply -- the packet's own source
    /// address is set by whatever process actually sent it (the resolver),
    /// regardless of which cgroup's task context happened to be running
    /// when the kernel hook fired.
    pub src_addr: [u8; 16],
    _pad: [u8; 4],
    /// The raw, unparsed UDP payload bytes (a DNS message, if the source
    /// port really was 53 and the sender is honest -- see `docs/DNS.md`
    /// for the spoofing caveat). Only `payload[..len]` is meaningful. The
    /// message's own transaction id (the first two bytes) is what
    /// query/response correlation matches against a captured query's own
    /// transaction id.
    pub payload: [u8; DNS_CAPTURE_MAX],
}

impl DnsCapture {
    /// The struct's pinned wire size, named for the same reason
    /// [`crate::event::Event::WIRE_SIZE`] is: a size-changing edit is
    /// caught at the one call site that matters (the `RingBuf` reserve in
    /// `bathyscaphe-ebpf::dns`) rather than only in this crate's tests.
    pub const WIRE_SIZE: usize = core::mem::size_of::<Self>();

    /// Builds a zeroed record for `cgroup_id` at `ktime_ns` **by value**.
    /// Safe to use anywhere in ordinary (stack-unconstrained) userspace
    /// code -- tests, and `probe::dns`'s ring-buffer decode, which already
    /// has the full record as a byte slice off the ring and reads it back
    /// as one owned value. **Never call this from `bathyscaphe-ebpf`**:
    /// constructing a whole `Self` (552 bytes) as a local blows the eBPF
    /// program stack's 512-byte limit. The kernel-side constructor is
    /// [`Self::init_at`], which writes directly through a pointer into
    /// already-allocated destination memory (a `RingBuf` reserved slot)
    /// instead of ever materializing a full `Self` on the stack.
    pub const fn zeroed_for(cgroup_id: u64, ktime_ns: u64) -> Self {
        Self { ktime_ns, cgroup_id, len: 0, dst_port: 0, src_addr: [0u8; 16], _pad: [0; 4], payload: [0u8; DNS_CAPTURE_MAX] }
    }

    /// Initializes a `DnsCapture` **in place** at `ptr`: every field is
    /// written directly through the pointer (including a memset-zeroed
    /// `payload`), never by constructing a `Self` value first. This is
    /// the constructor `bathyscaphe-ebpf::dns` must use -- see
    /// [`Self::zeroed_for`]'s doc for why a by-value construction is
    /// unusable there. After this call, the caller fills in `payload`
    /// (e.g. via `SkBuffContext::load_bytes(offset, &mut (*ptr).payload)`
    /// -- `payload` is a public field, reachable without a further helper
    /// here) and, once it knows how many bytes were actually written,
    /// sets `(*ptr).len` directly (also public).
    ///
    /// # Safety
    /// `ptr` must be valid for reads and writes of `Self`'s full size
    /// ([`Self::WIRE_SIZE`] bytes) and correctly aligned for `Self` (8
    /// bytes) for the duration of the call -- the precondition any
    /// `RingBuf` reserved-slot pointer or per-CPU map value pointer
    /// already satisfies.
    pub unsafe fn init_at(ptr: *mut Self, cgroup_id: u64, ktime_ns: u64) {
        // SAFETY: forwarded from this function's own safety contract.
        // Each write below touches only a small, fixed-size field (or, for
        // `payload`, a direct memset through the pointer) -- none of it
        // requires materializing a `Self`-sized value anywhere, which is
        // the entire reason this constructor exists.
        unsafe {
            core::ptr::addr_of_mut!((*ptr).ktime_ns).write(ktime_ns);
            core::ptr::addr_of_mut!((*ptr).cgroup_id).write(cgroup_id);
            core::ptr::addr_of_mut!((*ptr).len).write(0);
            core::ptr::addr_of_mut!((*ptr).dst_port).write(0);
            core::ptr::addr_of_mut!((*ptr).src_addr).write([0u8; 16]);
            core::ptr::addr_of_mut!((*ptr)._pad).write([0u8; 4]);
            core::ptr::write_bytes(core::ptr::addr_of_mut!((*ptr).payload).cast::<u8>(), 0, DNS_CAPTURE_MAX);
        }
    }

    /// The captured bytes, bounded to [`Self::len`] -- the only view of
    /// [`Self::payload`] any caller should ever parse. Bytes at index
    /// `>= len` are zero-fill, not message content, even though the array
    /// itself is always [`DNS_CAPTURE_MAX`] bytes long.
    pub fn captured(&self) -> &[u8] {
        let len = (self.len as usize).min(DNS_CAPTURE_MAX);
        &self.payload[..len]
    }
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for DnsCapture {}

/// The kernel-written DNS QUERY capture record: what the egress DNS-query
/// snoop program (`bathyscaphe-ebpf::dns_query`, build chunk #10) writes
/// into the `DNS_QUERIES` `RingBuf` for every UDP datagram it recognizes as
/// a DNS query (destination port 53) LEAVING a monitored container.
///
/// ## Why this exists: correct attribution at the SOURCE
///
/// `docs/DNS.md` documents that [`DnsCapture::cgroup_id`] can be wrong for
/// a response synthesized/injected by a resolver (Docker's embedded
/// `127.0.0.11`, a Tailscale-intercepted resolver) rather than delivered
/// over a real NIC/veth path: `bpf_get_current_cgroup_id()` at that INGRESS
/// hook reports the RESOLVER's cgroup, not the querying container's. The
/// outbound QUERY, by contrast, always fires in the container's OWN
/// cgroup -- it is that container's own process making an ordinary
/// `sendto()`/`send()` call on its own socket, with no resolver-side
/// injection involved on the egress path. Capturing the query's identity
/// (transaction id + source port) alongside its CORRECT cgroup id gives
/// userspace (`bathyscaphe::dns::pending::PendingQueryTable`) what it needs
/// to correlate a later response back to the right container, overriding
/// the response hook's own (possibly wrong) attribution.
///
/// ## Deliberately minimal: no query NAME captured
///
/// Parsing the query's QNAME in-kernel would need the same
/// variable-length-label handling [`DnsCapture`]'s own doc explains the
/// eBPF verifier handles poorly -- and it is unnecessary here: the
/// RESPONSE (already captured in full by `dns_snoop`, ingress) carries the
/// queried name back in its own question section, which userspace already
/// parses via `simple-dns`. This record's whole job is correlation
/// identity (txid + port + the correct cgroup id), nothing more.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct DnsQueryCapture {
    /// `bpf_ktime_get_boot_ns()` at capture time -- the instant the query
    /// left the container, used as the correlation table's insertion time
    /// for its own short TTL.
    pub ktime_ns: u64,
    /// `bpf_get_current_cgroup_id()` at the EGRESS hook: the querying
    /// container's own cgroup, correctly attributed by construction (see
    /// this struct's module-level doc) -- this is the value query/response
    /// correlation recovers for a response whose own [`DnsCapture::cgroup_id`]
    /// is wrong.
    pub cgroup_id: u64,
    /// The DNS message's transaction id (the first two bytes of the UDP
    /// payload), host-endian. Matched against a captured response's own
    /// transaction id (the first two bytes of [`DnsCapture::payload`],
    /// decoded the same way by the correlation table).
    pub txid: u16,
    /// The query's UDP source port -- the ephemeral port the querying
    /// process's socket used, and the SAME port the resolver's reply is
    /// addressed back to (that reply's [`DnsCapture::dst_port`]). This is
    /// the other half of the `(txid, port)` correlation key.
    pub src_port: u16,
    _pad: [u8; 4],
}

impl DnsQueryCapture {
    /// The struct's pinned wire size, named for the same reason
    /// [`DnsCapture::WIRE_SIZE`] is.
    pub const WIRE_SIZE: usize = core::mem::size_of::<Self>();

    /// Trivial constructor. Unlike [`DnsCapture`], this struct is small
    /// enough (24 bytes, comfortably under the eBPF stack limit even
    /// alongside everything else a program frame needs) to build by value
    /// on the stack and hand to `RingBuf::reserve::<Self>(0)`'s
    /// `entry.write(...)` -- the same convention
    /// `bathyscaphe-ebpf::decide::emit_event` already uses for the
    /// similarly small `Event` struct. No `init_at`-style raw-pointer
    /// constructor is needed here.
    pub const fn new(ktime_ns: u64, cgroup_id: u64, txid: u16, src_port: u16) -> Self {
        Self { ktime_ns, cgroup_id, txid, src_port, _pad: [0; 4] }
    }
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for DnsQueryCapture {}

#[cfg(test)]
mod tests {
    use super::*;

    const _DNS_CAPTURE_SIZE: () = assert!(core::mem::size_of::<DnsCapture>() == 40 + DNS_CAPTURE_MAX);
    const _DNS_CAPTURE_ALIGN: () = assert!(core::mem::align_of::<DnsCapture>() == 8);
    const _DNS_QUERY_CAPTURE_SIZE: () = assert!(core::mem::size_of::<DnsQueryCapture>() == 24);
    const _DNS_QUERY_CAPTURE_ALIGN: () = assert!(core::mem::align_of::<DnsQueryCapture>() == 8);

    #[test]
    fn dns_capture_is_pinned() {
        assert_eq!(core::mem::size_of::<DnsCapture>(), 40 + DNS_CAPTURE_MAX);
        assert_eq!(core::mem::align_of::<DnsCapture>(), 8);
        assert_eq!(DnsCapture::WIRE_SIZE, 40 + DNS_CAPTURE_MAX);
    }

    #[test]
    fn dns_capture_carries_dst_port() {
        let mut capture = DnsCapture::zeroed_for(1, 1);
        capture.dst_port = 54321;
        assert_eq!(capture.dst_port, 54321);
    }

    #[test]
    fn dns_capture_carries_src_addr() {
        let mut capture = DnsCapture::zeroed_for(1, 1);
        capture.src_addr = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 127, 0, 0, 11];
        assert_eq!(capture.src_addr[12..16], [127, 0, 0, 11]);
    }

    #[test]
    fn zeroed_for_starts_with_a_zeroed_src_addr() {
        let capture = DnsCapture::zeroed_for(1, 1);
        assert_eq!(capture.src_addr, [0u8; 16]);
    }

    #[test]
    fn dns_query_capture_is_pinned() {
        assert_eq!(core::mem::size_of::<DnsQueryCapture>(), 24);
        assert_eq!(core::mem::align_of::<DnsQueryCapture>(), 8);
        assert_eq!(DnsQueryCapture::WIRE_SIZE, 24);
    }

    #[test]
    fn dns_query_capture_round_trips_its_fields() {
        let capture = DnsQueryCapture::new(42, 0xABCD, 0x1234, 5353);
        assert_eq!(capture.ktime_ns, 42);
        assert_eq!(capture.cgroup_id, 0xABCD);
        assert_eq!(capture.txid, 0x1234);
        assert_eq!(capture.src_port, 5353);
    }

    #[test]
    fn zeroed_for_starts_with_len_zero_and_a_zeroed_payload() {
        let capture = DnsCapture::zeroed_for(0x1234, 42);
        assert_eq!(capture.cgroup_id, 0x1234);
        assert_eq!(capture.ktime_ns, 42);
        assert_eq!(capture.len, 0);
        assert!(capture.payload.iter().all(|&b| b == 0));
        assert_eq!(capture.captured(), &[] as &[u8]);
    }

    #[test]
    fn captured_bounds_to_len_even_if_payload_has_trailing_garbage() {
        let mut capture = DnsCapture::zeroed_for(1, 1);
        capture.payload[0] = 0xAA;
        capture.payload[1] = 0xBB;
        capture.payload[2] = 0xCC; // beyond len, must never be exposed
        capture.len = 2;
        assert_eq!(capture.captured(), &[0xAA, 0xBB]);
    }

    #[test]
    fn captured_clamps_a_corrupt_oversized_len_to_the_capture_cap() {
        let mut capture = DnsCapture::zeroed_for(1, 1);
        capture.len = u16::MAX;
        assert_eq!(capture.captured().len(), DNS_CAPTURE_MAX);
    }
}
