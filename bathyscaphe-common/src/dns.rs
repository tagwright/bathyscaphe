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
/// `u64`s reach 8-byte alignment with no compiler-inserted gap, `len` (a
/// `u16`) needs no gap after them, and `_pad` rounds up to a multiple of 8
/// before `payload` (whose own alignment is 1, so it needs no padding of
/// its own) so every byte that crosses the kernel/user boundary as
/// `aya::Pod` is deterministically initialized.
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
    /// this, exactly like [`crate::event::Event::cgroup_id`].
    pub cgroup_id: u64,
    /// How many leading bytes of [`Self::payload`] the kernel actually
    /// wrote (bounded by both the real UDP payload length and
    /// [`DNS_CAPTURE_MAX`]). Never trust bytes at index `>= len` --
    /// they are zero-initialized, not truncated message content.
    pub len: u16,
    _pad: [u8; 6],
    /// The raw, unparsed UDP payload bytes (a DNS message, if the source
    /// port really was 53 and the sender is honest -- see `docs/DNS.md`
    /// for the spoofing caveat). Only `payload[..len]` is meaningful.
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
    /// constructing a whole `Self` (536 bytes) as a local blows the eBPF
    /// program stack's 512-byte limit. The kernel-side constructor is
    /// [`Self::init_at`], which writes directly through a pointer into
    /// already-allocated destination memory (a `RingBuf` reserved slot)
    /// instead of ever materializing a full `Self` on the stack.
    pub const fn zeroed_for(cgroup_id: u64, ktime_ns: u64) -> Self {
        Self { ktime_ns, cgroup_id, len: 0, _pad: [0; 6], payload: [0u8; DNS_CAPTURE_MAX] }
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
            core::ptr::addr_of_mut!((*ptr)._pad).write([0u8; 6]);
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

#[cfg(test)]
mod tests {
    use super::*;

    const _DNS_CAPTURE_SIZE: () = assert!(core::mem::size_of::<DnsCapture>() == 24 + DNS_CAPTURE_MAX);
    const _DNS_CAPTURE_ALIGN: () = assert!(core::mem::align_of::<DnsCapture>() == 8);

    #[test]
    fn dns_capture_is_pinned() {
        assert_eq!(core::mem::size_of::<DnsCapture>(), 24 + DNS_CAPTURE_MAX);
        assert_eq!(core::mem::align_of::<DnsCapture>(), 8);
        assert_eq!(DnsCapture::WIRE_SIZE, 24 + DNS_CAPTURE_MAX);
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
