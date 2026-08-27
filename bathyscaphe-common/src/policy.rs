// SPDX-License-Identifier: GPL-3.0-or-later
//! The in-kernel policy map schema. THIS IS THE LOAD-BEARING DESIGN
//! DECISION for chunk #3, flagged for Nate's arbitration per the build
//! brief. See `bathy_ebpf_design.md` section 6 for the map-level context
//! this refines.
//!
//! ## Chosen scheme
//!
//! Two maps per container, both keyed indirectly by `cgroup_id`:
//!
//! - **Outer map (map-in-map, built in chunk #4/#5, not this crate):** a
//!   `HASH_OF_MAPS` keyed by `cgroup_id: u64`, whose value is the file
//!   descriptor of a per-container **inner `LpmTrie`**. One inner trie per
//!   container keeps a violating/large container's rule count from ever
//!   affecting another container's lookup cost, and lets a container's
//!   entire policy be replaced or dropped by swapping/deleting one outer
//!   entry (`release` in the wire protocol) rather than walking and
//!   deleting N inner entries one at a time.
//! - **Inner map: `LpmTrie<Key<PolicyKeyData>, PolicyValue>`.** [`PolicyKeyData`]
//!   is this crate's contribution: the fixed 19-byte `data` portion of
//!   the trie key (the `prefix_len: u32` wrapper itself is
//!   `aya::maps::lpm_trie::Key<T>` / `aya_ebpf::maps::lpm_trie::Key<T>`,
//!   supplied by aya on each side, not redefined here).
//!
//! `PolicyKeyData` byte layout, most-significant-bit-first (the order
//! `prefix_len` counts across for longest-prefix-match):
//!
//! ```text
//! byte offset:  0                                   16      18
//!               +-----------------------------------+-------+----+
//! field:        | addr (16 bytes, IPv4-mapped-into-  | port  |proto|
//!               | IPv6 for v4 destinations, RFC 4291)| (BE)  |    |
//!               +-----------------------------------+-------+----+
//! bit offset:   0                                   128     144  152
//! ```
//!
//! `prefix_len` (bits, counted from bit 0) determines how much of that
//! 152-bit key is significant for a given trie entry:
//!
//! | `prefix_len` | Rule shape |
//! |---|---|
//! | 0..=128 | CIDR on the address only ("allow `10.0.0.0/8`, any port, any proto"); `port`/`proto` bytes are present in the key (padding, conventionally zero) but not matched |
//! | 128 + 16 = 144 | full exact address (a `/32` or `/128`, i.e. `prefix_len` for the address portion must be exactly 128) plus an exact port, any proto |
//! | 128 + 16 + 8 = 152 | full exact address, exact port, exact proto — the fully specific rule |
//!
//! `PolicyValue` (the trie's value type): `action` (allow/deny),
//! `source` (static/dns), `expires_at_ns` (absolute, `0` = never expires,
//! measured on `CLOCK_BOOTTIME` — the same clock `bpf_ktime_get_boot_ns()`
//! reads in-kernel — so kernel-side expiry comparisons never need wall-clock
//! sync; the daemon is responsible for translating the wire protocol's
//! RFC3339 `expires_at` into a boot-relative `expires_at_ns` at the point
//! it writes the map, using a wall-clock/boot-clock offset it samples
//! once at startup), and a reserved `flags` byte for future per-rule bits
//! (none defined yet; always `0` in this build).
//!
//! ## The known limitation, flagged for arbitration
//!
//! Because a longest-prefix match can only ever match a **contiguous
//! prefix starting at bit 0**, this key layout can express:
//!
//! - "CIDR X, any port, any proto" (any prefix length up to 128), and
//! - "exact single address, exact port[, exact proto]" (prefix length
//!   144 or 152, which requires the address portion to be the full 128
//!   bits — i.e. a `/32`/`/128` host route, not a broader CIDR),
//!
//! but it **cannot** express either of these, which are both real,
//! plausible operator intents:
//!
//! 1. **"any address, specific port"** (e.g. "block outbound port 25 to
//!    stop a spam relay, regardless of destination") — there is no way to
//!    wildcard the *front* of an LPM key and pin down only the *tail*;
//!    LPM match length always starts at bit 0.
//! 2. **"a CIDR narrower than a full host route, plus a specific port"**
//!    (e.g. "allow `10.0.0.0/24` but only to port 443") — this is not
//!    just the brief's stated gap, it is a strictly larger limitation:
//!    *any* combination of "non-host-route CIDR" with "port constraint"
//!    is unrepresentable in one entry, not only the fully-wildcarded
//!    address case, because the port bits are not reachable by a prefix
//!    match unless every address bit ahead of them is also pinned.
//!
//! **Recommended mitigation, for arbitration:** add a small, separate
//! **exact-port map** — [`ExactPortKey`] below — a plain `HashMap<ExactPortKey,
//! PolicyValue>` (no LPM needed; `(port, proto)` is looked up by exact
//! equality) consulted as a second, independent gate alongside the
//! per-container `LpmTrie`. This covers case 1 outright ("any address,
//! this exact port") without touching the LPM key layout, and is the
//! same amount of code as the trie lookup (`bpf_map_lookup_elem`, one
//! more time). It does **not** fully solve case 2 (CIDR + port together
//! still is not one entry), but case 2 has no clean single-map fix under
//! any left-to-right byte ordering short of a second full trie keyed
//! `(port, proto, addr-prefix)` in parallel with this one, which doubles
//! the map count and the lookup cost for a combination that in practice
//! is well served by *either* narrowing the CIDR to host routes (verbose
//! but correct) *or* accepting that "CIDR + port" rules are enforced as
//! "CIDR, any port" with the port narrowing handled by a userspace-side
//! warning that the rule was widened, which is a policy-correctness
//! regression I am NOT recommending silently. The two combination
//! semantics for the exact-port map and the LPM trie's outcomes both
//! having a hit (e.g. LPM says allow, exact-port says deny) also needs an
//! explicit rule, proposed: **deny wins** (matches the wire protocol's
//! own "deny wins at equal specificity" rule in `docs/PROTOCOL.md`
//! section 4), applied in the kernel lookup chunk #4 will implement.
//!
//! This module defines [`ExactPortKey`] so the type exists and is
//! ABI-pinned regardless of which way the arbitration goes; whether
//! chunk #4/#5 actually wires a second map using it in v1, or defers it
//! and documents "CIDR+port rules require a host-route CIDR" as a known
//! v1 restriction, is Nate's call, not this crate's.
//!
//! ## What is explicitly NOT in this crate
//!
//! The outer `HASH_OF_MAPS` declaration itself (the map-in-map wiring,
//! the inner-map template creation, `BPF_MAP_TYPE_HASH_OF_MAPS`) is a
//! loader/map-management concern, not a POD type — it lives in
//! `bathyscaphe-ebpf` (the `#[map]` declaration) and the userspace loader
//! (creating the inner map's template FD before creating the outer map).
//! Likewise `aya::maps::lpm_trie::Key<PolicyKeyData>` /
//! `aya_ebpf::maps::lpm_trie::Key<PolicyKeyData>` (the `prefix_len` +
//! `data` wrapper) is aya's own type, parameterized over
//! `PolicyKeyData` from here; this crate does not redeclare it and does
//! not depend on `aya-ebpf` (only optionally on `aya`, for the userspace
//! `Pod` impls, per the `user` feature).

/// The `LpmTrie` key's `data` portion (the wrapping `prefix_len: u32` is
/// supplied by aya's own `Key<T>` type on each side, not redefined here).
///
/// All three fields are byte arrays / a single `u8`, deliberately never a
/// multi-byte integer: this keeps the struct's alignment at 1 with zero
/// implicit padding (any padding byte would sit inside the range the LPM
/// trie treats as key data, and would silently participate in — or
/// silently fail to participate in, depending on its uninitialized value
/// — prefix matching). `port` is two bytes in network (big-endian) byte
/// order, matching how a destination port already exists in a socket
/// address; storing it as `u16` would require an explicit host/network
/// conversion at every call site to avoid an endianness bug, for zero
/// benefit since the value is never arithmetic here, only compared/matched
/// as bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(C)]
pub struct PolicyKeyData {
    /// IPv4-mapped-into-IPv6 (RFC 4291: 10 zero bytes, `0xff`, `0xff`,
    /// then the 4-byte v4 address) for IPv4 destinations; a native v6
    /// address otherwise.
    pub addr: [u8; 16],
    /// Destination port, network byte order. Only significant when
    /// `prefix_len >= ADDR_BITS + PORT_BITS`.
    pub port: [u8; 2],
    /// [`crate::enums::TransportProto`] as a raw `u8`. Only significant
    /// when `prefix_len == PREFIX_LEN_FULL`.
    pub proto: u8,
}

impl PolicyKeyData {
    /// Bit width of the address portion of the key.
    pub const ADDR_BITS: u32 = 128;
    /// Bit width of the port portion of the key.
    pub const PORT_BITS: u32 = 16;
    /// Bit width of the proto portion of the key.
    pub const PROTO_BITS: u32 = 8;
    /// `prefix_len` for a rule that pins the full address plus an exact
    /// port (any proto). Only meaningful when the address itself is a
    /// full `/32`/`/128` host route — see the module-level limitation
    /// note.
    pub const PREFIX_LEN_ADDR_AND_PORT: u32 = Self::ADDR_BITS + Self::PORT_BITS;
    /// `prefix_len` for the fully specific rule: exact address, exact
    /// port, exact proto.
    pub const PREFIX_LEN_FULL: u32 = Self::PREFIX_LEN_ADDR_AND_PORT + Self::PROTO_BITS;
    /// The RFC 4291 IPv4-mapped-into-IPv6 prefix: ten zero bytes then
    /// `0xff, 0xff`.
    pub const IPV4_MAPPED_PREFIX: [u8; 12] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff];

    /// Trivial constructor: assemble a key from already-formed fields.
    pub const fn new(addr: [u8; 16], port: [u8; 2], proto: u8) -> Self {
        Self { addr, port, proto }
    }

    /// Trivial constructor: build the IPv4-mapped-into-IPv6 form of a v4
    /// destination address. No policy logic, just RFC 4291 embedding.
    pub const fn from_ipv4(octets: [u8; 4], port: [u8; 2], proto: u8) -> Self {
        let mut addr = [0u8; 16];
        addr[10] = 0xff;
        addr[11] = 0xff;
        addr[12] = octets[0];
        addr[13] = octets[1];
        addr[14] = octets[2];
        addr[15] = octets[3];
        Self { addr, port, proto }
    }
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for PolicyKeyData {}

/// The `LpmTrie` value: what a matched policy entry says to do.
///
/// Field order puts the `u64` first so the struct needs no manually
/// inserted padding to reach 8-byte alignment for `expires_at_ns` — the
/// three trailing `u8` fields plus the explicit `_pad` fill out the rest
/// of the last 8-byte word. `_pad` is explicit (rather than left to the
/// compiler) so its bytes are always deterministically zeroed by
/// [`PolicyValue::new`] and by `Default`, since an `aya::Pod` type's
/// padding bytes are read back out of the map by userspace and must never
/// be uninitialized data leaking across the kernel/user boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(C)]
pub struct PolicyValue {
    /// Absolute expiry on `CLOCK_BOOTTIME` (same clock as
    /// `bpf_ktime_get_boot_ns()`). `0` means "never expires" — the
    /// overwhelming majority of static rules — chosen over a sentinel
    /// `u64::MAX` so the common case is the natural zero-initialized
    /// value.
    pub expires_at_ns: u64,
    /// [`crate::enums::RuleAction`] as a raw `u8`.
    pub action: u8,
    /// [`crate::enums::RuleSource`] as a raw `u8`.
    pub source: u8,
    /// Reserved for future per-rule bits (e.g. "log on match" separate
    /// from `action`). Always `0` in this build; no bits are assigned
    /// yet.
    pub flags: u8,
    _pad: [u8; 5],
}

impl PolicyValue {
    /// Sentinel `expires_at_ns` meaning "never expires".
    pub const NEVER_EXPIRES: u64 = 0;

    /// Trivial constructor. `flags` is always `0` until a bit is defined.
    pub const fn new(action: u8, source: u8, expires_at_ns: u64) -> Self {
        Self { expires_at_ns, action, source, flags: 0, _pad: [0; 5] }
    }
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for PolicyValue {}

/// Key for the recommended (flagged, not yet wired by this crate)
/// **exact-port map**: the mitigation for the "any address, specific
/// port" case the [`PolicyKeyData`] LPM layout cannot express (see the
/// module-level doc). A plain equality `HashMap<ExactPortKey,
/// PolicyValue>` keyed by this type, checked alongside the per-container
/// `LpmTrie`, needs no prefix semantics at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(C)]
pub struct ExactPortKey {
    /// Destination port, network byte order (same convention as
    /// [`PolicyKeyData::port`]).
    pub port: [u8; 2],
    /// [`crate::enums::TransportProto`] as a raw `u8`.
    pub proto: u8,
}

impl ExactPortKey {
    /// Trivial constructor.
    pub const fn new(port: [u8; 2], proto: u8) -> Self {
        Self { port, proto }
    }
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for ExactPortKey {}

#[cfg(test)]
mod tests {
    use super::*;

    const _POLICY_KEY_DATA_SIZE: () = assert!(core::mem::size_of::<PolicyKeyData>() == 19);
    const _POLICY_KEY_DATA_ALIGN: () = assert!(core::mem::align_of::<PolicyKeyData>() == 1);
    const _POLICY_VALUE_SIZE: () = assert!(core::mem::size_of::<PolicyValue>() == 16);
    const _POLICY_VALUE_ALIGN: () = assert!(core::mem::align_of::<PolicyValue>() == 8);
    const _EXACT_PORT_KEY_SIZE: () = assert!(core::mem::size_of::<ExactPortKey>() == 3);

    #[test]
    fn policy_key_data_is_pinned_and_padding_free() {
        assert_eq!(core::mem::size_of::<PolicyKeyData>(), 19);
        assert_eq!(core::mem::align_of::<PolicyKeyData>(), 1);
    }

    #[test]
    fn policy_value_is_pinned() {
        assert_eq!(core::mem::size_of::<PolicyValue>(), 16);
        assert_eq!(core::mem::align_of::<PolicyValue>(), 8);
    }

    #[test]
    fn exact_port_key_is_pinned() {
        assert_eq!(core::mem::size_of::<ExactPortKey>(), 3);
    }

    #[test]
    fn from_ipv4_embeds_rfc4291_prefix() {
        let key = PolicyKeyData::from_ipv4([10, 0, 0, 1], [0x01, 0xbb], 0);
        assert_eq!(&key.addr[0..12], &PolicyKeyData::IPV4_MAPPED_PREFIX[..]);
        assert_eq!(&key.addr[12..16], &[10, 0, 0, 1]);
        assert_eq!(key.port, [0x01, 0xbb]);
    }

    #[test]
    fn prefix_len_constants_match_the_documented_layout() {
        assert_eq!(PolicyKeyData::ADDR_BITS, 128);
        assert_eq!(PolicyKeyData::PREFIX_LEN_ADDR_AND_PORT, 144);
        assert_eq!(PolicyKeyData::PREFIX_LEN_FULL, 152);
    }

    #[test]
    fn policy_value_never_expires_is_zero() {
        let v = PolicyValue::new(0, 0, PolicyValue::NEVER_EXPIRES);
        assert_eq!(v.expires_at_ns, 0);
        assert_eq!(v.flags, 0);
    }
}
