// SPDX-License-Identifier: GPL-3.0-or-later
//! The in-kernel policy map schema (ratified 2026-08-27, superseding the
//! flagged-for-arbitration flat combined-key scheme this crate shipped
//! with in the COMMON build chunk).
//!
//! ## Chosen scheme: nested per-prefix port rules
//!
//! A policy entry is keyed on the **destination address prefix alone**
//! (CIDR or host route), and its value carries a small, bounded set of
//! **port rules** evaluated within that prefix. This directly expresses
//! both gaps the previous scheme could not ("any address, specific port"
//! and "CIDR narrower than a host route, plus a port") without a second
//! map: "allow `443` anywhere" is one `/0` entry with one port rule;
//! "allow `10.0.0.0/24` but only to port `443`" is one `/24` entry with
//! one port rule. [`ExactPortKey`] and the exact-port side-map it implied
//! are gone — there is no longer a second map to consult or a cross-map
//! deny-wins rule to apply.
//!
//! - [`PolicyKeyData`] — the `LpmTrie` key's `data` portion (the wrapping
//!   `prefix_len: u32` is aya's own `Key<T>`, not redefined here).
//! - [`PolicyValue`] — the `LpmTrie` value: a per-prefix default action
//!   plus up to [`MAX_PORT_RULES`] [`PortRule`]s.
//!
//! ## The map-in-map deviation, and why
//!
//! The ratified design calls for **per-container isolation**: an outer
//! map keyed by `cgroup_id: u64` (a `HASH_OF_MAPS`) whose value is the
//! file descriptor of a per-container inner `LpmTrie<Key<addr>,
//! PolicyValue>`, so [`PolicyKeyData`] would hold only the 16-byte
//! address and the trie itself would never need to know which container
//! it belongs to.
//!
//! **That is not implementable against the toolchain this workspace is
//! pinned to.** Checked directly against upstream source as of
//! 2026-08-27: `aya-ebpf` `v0.2.1` (the version in this workspace's
//! `Cargo.toml`) has no `hash_of_maps` / `array_of_maps` module under
//! `ebpf/aya-ebpf/src/maps/` — only `array`, `hash_map`, `lpm_trie`,
//! `ring_buf`, and the other non-nesting map types are present. The
//! matching userspace support (`aya-obj`/`aya` inner-map-definition and
//! initial-slot-fd plumbing) is likewise unmerged: upstream PR
//! [aya-rs/aya#1564](https://github.com/aya-rs/aya/pull/1564), "feat(aya):
//! add support for map-of-maps (HashOfMaps, ArrayOfMaps)", is still
//! **open**, not merged, as of the same date. There is no version of
//! `aya`/`aya-ebpf` on crates.io today that ships a typed map-in-map API
//! on either side of the kernel/user boundary. This is a toolchain gap,
//! not a design mistake to route around cleverly — routing around it
//! with hand-rolled raw ELF map definitions would mean the userspace
//! loader (built on the same pinned `aya` crate) still has no way to
//! create the outer map or populate an inner map's fd, so it would not
//! actually unblock anything.
//!
//! **The fallback, until that lands:** one flat, shared `LpmTrie` for
//! every container, with `cgroup_id` folded into the leading, always-
//! fully-matched bits of the key instead of living in an outer map.
//! [`PolicyKeyData`] is `{ cgroup_id: [u8; 8], addr: [u8; 16] }` (24
//! bytes), and every stored entry's `prefix_len` **must** be at least
//! [`PolicyKeyData::MIN_PREFIX_LEN`] (64 — the full `cgroup_id`) before
//! it may extend into the address bits. A lookup always supplies
//! `prefix_len = `[`PolicyKeyData::PREFIX_LEN_FULL`]` (192), so the
//! kernel's own longest-prefix-match finds the most specific stored entry
//! whose `cgroup_id` matches *exactly* and whose address prefix is the
//! longest one that also matches — the same "any address" (prefix 64) to
//! "full address" (prefix 192) range the nested design's inner trie would
//! have covered on its own, just addressed 64 bits further to the right.
//!
//! This preserves every *value*-level property of the ratified design
//! (bounded port rules, per-prefix default, expiry, source tag) exactly.
//! What is genuinely different from true map-in-map:
//!
//! 1. **Bulk container release is no longer O(1).** Deleting all of one
//!    container's policy in the nested design is "delete the outer map's
//!    one entry for that `cgroup_id`". Here it is "delete every trie
//!    entry whose leading 8 bytes are that `cgroup_id`" — the loader
//!    (build chunk #5) must track, per container, the exact set of keys
//!    it inserted (it already needs this to diff one directive snapshot
//!    against the previous one) and issue one `LpmTrie::remove()` per
//!    key on `release`. There is no bulk/prefix delete operation on an
//!    `LpmTrie` to lean on instead.
//! 2. **Lookup cost is a function of the whole trie, not one container's
//!    slice of it.** An `LpmTrie` lookup is still logarithmic in the
//!    number of distinct stored prefixes, so this is a mild shared-cost
//!    regression, not a correctness one — no container's rules can ever
//!    match another's lookup (see the invariant below), only the trie's
//!    depth is shared.
//! 3. **The isolation invariant is now a userspace obligation, not a
//!    structural guarantee.** In the nested design, one container simply
//!    cannot see another's inner trie. Here, isolation depends entirely
//!    on every inserted key's `prefix_len` being `>= MIN_PREFIX_LEN`: a
//!    shorter prefix would let a lookup match on a partial `cgroup_id`,
//!    silently leaking one container's rule onto another's traffic
//!    whenever their `cgroup_id`s happen to share a leading byte run.
//!    **Build chunk #5 must never write a `Key` with `prefix_len <
//!    PolicyKeyData::MIN_PREFIX_LEN`.** The eBPF programs (build chunk
//!    #4) do not and cannot check this at lookup time — it is purely an
//!    insert-time discipline.
//!
//! **Migration path**, once `aya`/`aya-ebpf` ship map-in-map: move
//! `cgroup_id` back out of [`PolicyKeyData`] into an outer
//! `HashOfMaps<u64, LpmTrie<Key<[u8; 16]>, PolicyValue>>`; shrink
//! [`PolicyKeyData`] to just the 16-byte address. [`PolicyValue`] and
//! [`PortRule`] need no change at all — the nested-port-rule schema was
//! designed independently of how containers are indexed.
//!
//! ## Expiry lookup limitation
//!
//! A kernel lookup is a single `LpmTrie::get()` call at the maximal
//! prefix length. If the entry that call returns has already expired
//! (`expires_at_ns != 0 && expires_at_ns < now`), the kernel does **not**
//! retry at a shorter prefix to find a still-valid, less-specific entry
//! underneath it — `LpmTrie::get()` does not expose how many bits of the
//! match it found, so there is nothing to shrink the retry to. An expired
//! match falls straight through to the container's
//! [`crate::enforcement::EnforcementState::default_verdict`]. This is a
//! deliberate v1 simplification (a bounded shrink-and-retry loop is
//! possible later if this proves to matter in practice), not an oversight.

/// Bounded number of [`PortRule`]s a single [`PolicyValue`] can carry.
/// Chosen as a small power of two: generous for the "allow a handful of
/// ports on this prefix" case this schema targets, cheap for the kernel's
/// bounded scan loop, and small enough that a `PolicyValue` stays a single
/// cache line and a half. A directive that needs more than
/// `MAX_PORT_RULES` port rules for one destination prefix **cannot be
/// represented** — the array is fixed-size, so there is no silent-drop
/// path, only a compile-time-enforced ceiling. Build chunk #5 (the
/// userspace loader) MUST validate `n_port_rules <= MAX_PORT_RULES`
/// before writing a [`PolicyValue`] and, on overflow, either reject the
/// directive with a loud accounting record (R1) or split the excess rules
/// onto an additional, narrower (up to host-route) prefix entry — never
/// truncate silently.
pub const MAX_PORT_RULES: usize = 8;

/// The `LpmTrie` key's `data` portion (the wrapping `prefix_len: u32` is
/// supplied by aya's own `Key<T>` type on each side, not redefined here).
///
/// All fields are byte arrays, deliberately never a multi-byte integer:
/// this keeps the struct's alignment at 1 with zero implicit padding (any
/// padding byte would sit inside the range the LPM trie treats as key
/// data, and would silently participate in — or silently fail to
/// participate in, depending on its uninitialized value — prefix
/// matching). `cgroup_id` is stored big-endian purely by convention (it
/// is always either fully present or entirely absent from a match, never
/// partially matched — see [`Self::MIN_PREFIX_LEN`] — so no particular
/// byte order is load-bearing here, unlike `addr`/port fields elsewhere in
/// this crate where partial-prefix matching makes byte order meaningful).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(C)]
pub struct PolicyKeyData {
    /// The owning container's cgroup id (`bpf_get_current_cgroup_id()`),
    /// big-endian. See the module doc: this crate's substitute for true
    /// map-in-map, folded into the leading, always-fully-matched bits of
    /// the key instead of living in an outer map.
    pub cgroup_id: [u8; 8],
    /// IPv4-mapped-into-IPv6 (RFC 4291: 10 zero bytes, `0xff`, `0xff`,
    /// then the 4-byte v4 address) for IPv4 destinations; a native v6
    /// address otherwise.
    pub addr: [u8; 16],
}

impl PolicyKeyData {
    /// Bit width of the `cgroup_id` portion of the key.
    pub const CGROUP_ID_BITS: u32 = 64;
    /// Bit width of the address portion of the key.
    pub const ADDR_BITS: u32 = 128;
    /// The minimum `prefix_len` any *stored* entry may use: the full
    /// `cgroup_id`, matched exactly, with zero address bits pinned (the
    /// "any address, this container only" rule — the flat-key equivalent
    /// of the nested design's inner `/0`). Inserting an entry with a
    /// shorter prefix would break cross-container isolation — see the
    /// module doc's point 3.
    pub const MIN_PREFIX_LEN: u32 = Self::CGROUP_ID_BITS;
    /// `prefix_len` for a lookup key: the full `cgroup_id` plus the full
    /// address. Every kernel-side lookup uses exactly this value so the
    /// trie's own longest-prefix-match picks the most specific stored
    /// entry at or below it — see the module doc.
    pub const PREFIX_LEN_FULL: u32 = Self::CGROUP_ID_BITS + Self::ADDR_BITS;
    /// The RFC 4291 IPv4-mapped-into-IPv6 prefix: ten zero bytes then
    /// `0xff, 0xff`.
    pub const IPV4_MAPPED_PREFIX: [u8; 12] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff];

    /// Trivial constructor: assemble a key from a cgroup id and an
    /// already-formed address.
    pub const fn new(cgroup_id: u64, addr: [u8; 16]) -> Self {
        Self { cgroup_id: cgroup_id.to_be_bytes(), addr }
    }

    /// Trivial constructor: build the IPv4-mapped-into-IPv6 form of a v4
    /// destination address for a given cgroup id. No policy logic, just
    /// RFC 4291 embedding.
    pub const fn from_ipv4(cgroup_id: u64, octets: [u8; 4]) -> Self {
        let mut addr = [0u8; 16];
        addr[10] = 0xff;
        addr[11] = 0xff;
        addr[12] = octets[0];
        addr[13] = octets[1];
        addr[14] = octets[2];
        addr[15] = octets[3];
        Self { cgroup_id: cgroup_id.to_be_bytes(), addr }
    }
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for PolicyKeyData {}

/// One bounded port/proto/action rule inside a [`PolicyValue`].
///
/// `port_lo`/`port_hi` are ordinary host-order `u16` port numbers
/// (deliberately *not* the raw-network-order-bytes convention used by
/// [`PolicyKeyData::addr`]'s companion port fields elsewhere in this
/// crate's sibling types) because a rule needs numeric range comparison
/// (`port_lo..=port_hi`), not byte-equality prefix matching. A
/// single-port rule sets `port_lo == port_hi`.
///
/// Field order (`u16, u16, u8, u8`) needs no explicit padding: total size
/// is 6 bytes, already a multiple of the struct's 2-byte alignment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(C)]
pub struct PortRule {
    /// Inclusive lower bound of the matched port range, host byte order.
    pub port_lo: u16,
    /// Inclusive upper bound of the matched port range, host byte order.
    pub port_hi: u16,
    /// Encoded transport constraint. `0` ([`Self::PROTO_ANY`]) means "any
    /// protocol" — see [`Self::encode_proto`] for why nonzero values are
    /// `1 + `[`crate::enums::TransportProto`]`, not the raw discriminant.
    pub proto: u8,
    /// [`crate::enums::RuleAction`] as a raw `u8`.
    pub action: u8,
}

impl PortRule {
    /// Sentinel meaning "any transport protocol". Not the same numbering
    /// as [`crate::enums::TransportProto`] itself (whose `Tcp` variant is
    /// discriminant `0`) — seeing `0` mean "any" here as well would make
    /// it impossible to write a TCP-only rule, since there would be no
    /// distinct encoding left for "TCP specifically". See
    /// [`Self::encode_proto`].
    pub const PROTO_ANY: u8 = 0;

    /// Trivial constructor.
    pub const fn new(port_lo: u16, port_hi: u16, proto: u8, action: u8) -> Self {
        Self { port_lo, port_hi, proto, action }
    }

    /// Trivial constructor for a single-port rule (`port_lo == port_hi`).
    pub const fn single_port(port: u16, proto: u8, action: u8) -> Self {
        Self::new(port, port, proto, action)
    }

    /// Encode a [`crate::enums::TransportProto`] discriminant (`Tcp = 0`,
    /// `Udp = 1`) for storage in [`Self::proto`], shifted up by one so `0`
    /// stays free for [`Self::PROTO_ANY`].
    pub const fn encode_proto(transport_proto: u8) -> u8 {
        transport_proto + 1
    }

    /// Whether this rule's proto constraint matches a connection whose
    /// transport is `transport_proto` (a raw
    /// [`crate::enums::TransportProto`] discriminant, e.g.
    /// [`crate::event::Event::proto`]).
    pub const fn matches_proto(&self, transport_proto: u8) -> bool {
        self.proto == Self::PROTO_ANY || self.proto == Self::encode_proto(transport_proto)
    }

    /// Whether `port` (host byte order) falls within this rule's
    /// inclusive range.
    pub const fn matches_port(&self, port: u16) -> bool {
        port >= self.port_lo && port <= self.port_hi
    }
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for PortRule {}

/// The `LpmTrie` value: what a matched policy prefix says to do.
///
/// Field order puts the `u64` first for the same reason as every other
/// multi-field struct in this crate: it reaches 8-byte alignment without
/// a compiler-inserted gap ahead of it. The explicit `_pad` keeps every
/// byte deterministically initialized (this type crosses the kernel/user
/// boundary as `aya::Pod`, so uninitialized padding would be observable,
/// un-zeroed garbage in a userspace read). Total size is 64 bytes (8 +
/// 1+1+1 + 5 pad + 8 × 6-byte [`PortRule`]s), already a multiple of the
/// struct's 8-byte alignment, so no trailing padding is needed either.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct PolicyValue {
    /// Absolute expiry on `CLOCK_BOOTTIME` (same clock as
    /// `bpf_ktime_get_boot_ns()`). `0` means "never expires" — the
    /// overwhelming majority of static rules — chosen over a sentinel
    /// `u64::MAX` so the common case is the natural zero-initialized
    /// value. See the module doc's "expiry lookup limitation" note for
    /// what happens when this prefix's own entry has expired.
    pub expires_at_ns: u64,
    /// [`crate::enums::RuleAction`] as a raw `u8`: what to do when the
    /// destination matches this prefix but no [`PortRule`] in
    /// [`Self::port_rules`] matches the connection's port/proto.
    pub cidr_default_action: u8,
    /// [`crate::enums::RuleSource`] as a raw `u8`.
    pub source: u8,
    /// Number of entries in [`Self::port_rules`] that are actually
    /// populated, `<= `[`MAX_PORT_RULES`]. Entries at index
    /// `>= n_port_rules` are ignored by the kernel scan regardless of
    /// their contents.
    pub n_port_rules: u8,
    _pad: [u8; 5],
    /// Bounded set of port/proto/action rules evaluated within this
    /// prefix, deny-wins across all matches. See the module doc for why
    /// this replaces the old two-map (`LpmTrie` + exact-port `HashMap`)
    /// scheme with one nested value.
    pub port_rules: [PortRule; MAX_PORT_RULES],
}

impl PolicyValue {
    /// Sentinel `expires_at_ns` meaning "never expires".
    pub const NEVER_EXPIRES: u64 = 0;
    /// Re-exported here as an associated const for call-site convenience;
    /// identical to the free [`MAX_PORT_RULES`] constant.
    pub const MAX_PORT_RULES: usize = MAX_PORT_RULES;

    /// Trivial constructor for a prefix entry with no port rules yet
    /// (only `cidr_default_action` applies). Use
    /// [`Self::with_port_rule`] to populate [`Self::port_rules`].
    pub const fn new(cidr_default_action: u8, source: u8, expires_at_ns: u64) -> Self {
        Self {
            expires_at_ns,
            cidr_default_action,
            source,
            n_port_rules: 0,
            _pad: [0; 5],
            port_rules: [PortRule::new(0, 0, 0, 0); MAX_PORT_RULES],
        }
    }

    /// Append one port rule, returning `false` (and leaving `self`
    /// unchanged) if [`MAX_PORT_RULES`] is already reached — the caller
    /// (build chunk #5) must treat that as the overflow case documented
    /// on [`MAX_PORT_RULES`], not silently drop the rule.
    pub fn with_port_rule(mut self, rule: PortRule) -> Result<Self, Self> {
        let idx = self.n_port_rules as usize;
        if idx >= MAX_PORT_RULES {
            return Err(self);
        }
        self.port_rules[idx] = rule;
        self.n_port_rules += 1;
        Ok(self)
    }
}

impl Default for PolicyValue {
    fn default() -> Self {
        Self::new(0, 0, Self::NEVER_EXPIRES)
    }
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for PolicyValue {}

#[cfg(test)]
mod tests {
    use super::*;

    const _POLICY_KEY_DATA_SIZE: () = assert!(core::mem::size_of::<PolicyKeyData>() == 24);
    const _POLICY_KEY_DATA_ALIGN: () = assert!(core::mem::align_of::<PolicyKeyData>() == 1);
    const _PORT_RULE_SIZE: () = assert!(core::mem::size_of::<PortRule>() == 6);
    const _PORT_RULE_ALIGN: () = assert!(core::mem::align_of::<PortRule>() == 2);
    const _POLICY_VALUE_SIZE: () = assert!(core::mem::size_of::<PolicyValue>() == 64);
    const _POLICY_VALUE_ALIGN: () = assert!(core::mem::align_of::<PolicyValue>() == 8);

    #[test]
    fn policy_key_data_is_pinned_and_padding_free() {
        assert_eq!(core::mem::size_of::<PolicyKeyData>(), 24);
        assert_eq!(core::mem::align_of::<PolicyKeyData>(), 1);
    }

    #[test]
    fn port_rule_is_pinned() {
        assert_eq!(core::mem::size_of::<PortRule>(), 6);
        assert_eq!(core::mem::align_of::<PortRule>(), 2);
    }

    #[test]
    fn policy_value_is_pinned() {
        assert_eq!(core::mem::size_of::<PolicyValue>(), 64);
        assert_eq!(core::mem::align_of::<PolicyValue>(), 8);
    }

    #[test]
    fn from_ipv4_embeds_rfc4291_prefix_and_cgroup_id() {
        let key = PolicyKeyData::from_ipv4(0x0102_0304_0506_0708, [10, 0, 0, 1]);
        assert_eq!(key.cgroup_id, 0x0102_0304_0506_0708u64.to_be_bytes());
        assert_eq!(&key.addr[0..12], &PolicyKeyData::IPV4_MAPPED_PREFIX[..]);
        assert_eq!(&key.addr[12..16], &[10, 0, 0, 1]);
    }

    #[test]
    fn prefix_len_constants_match_the_documented_layout() {
        assert_eq!(PolicyKeyData::CGROUP_ID_BITS, 64);
        assert_eq!(PolicyKeyData::MIN_PREFIX_LEN, 64);
        assert_eq!(PolicyKeyData::PREFIX_LEN_FULL, 192);
    }

    #[test]
    fn policy_value_never_expires_is_zero() {
        let v = PolicyValue::new(0, 0, PolicyValue::NEVER_EXPIRES);
        assert_eq!(v.expires_at_ns, 0);
        assert_eq!(v.n_port_rules, 0);
    }

    #[test]
    fn port_rule_proto_any_does_not_collide_with_tcp_discriminant() {
        // TransportProto::Tcp is discriminant 0; PortRule::PROTO_ANY is
        // also 0 but means something different (see the module doc) --
        // encode_proto's +1 shift is what keeps a TCP-only rule
        // distinguishable from an any-proto rule.
        const TCP: u8 = 0;
        const UDP: u8 = 1;
        let tcp_only = PortRule::single_port(443, PortRule::encode_proto(TCP), 0);
        let any_proto = PortRule::single_port(443, PortRule::PROTO_ANY, 0);
        assert!(tcp_only.matches_proto(TCP));
        assert!(!tcp_only.matches_proto(UDP));
        assert!(any_proto.matches_proto(TCP));
        assert!(any_proto.matches_proto(UDP));
    }

    #[test]
    fn with_port_rule_fills_up_to_the_cap_then_rejects() {
        let mut value = PolicyValue::new(1, 0, PolicyValue::NEVER_EXPIRES);
        for i in 0..MAX_PORT_RULES {
            value = value.with_port_rule(PortRule::single_port(i as u16, PortRule::PROTO_ANY, 0)).expect("under cap");
        }
        assert_eq!(value.n_port_rules as usize, MAX_PORT_RULES);
        let rejected = value.with_port_rule(PortRule::single_port(9999, PortRule::PROTO_ANY, 0));
        assert!(rejected.is_err());
    }

    #[test]
    fn port_rule_range_matching() {
        let rule = PortRule::new(8000, 8080, PortRule::PROTO_ANY, 0);
        assert!(rule.matches_port(8000));
        assert!(rule.matches_port(8080));
        assert!(rule.matches_port(8040));
        assert!(!rule.matches_port(7999));
        assert!(!rule.matches_port(8081));
    }
}
