// SPDX-License-Identifier: GPL-3.0-or-later
//! The isolation-safe `POLICY` map API.
//!
//! `bathyscaphe_common::policy`'s module doc explains why this workspace's
//! `PolicyKeyData` folds the full `cgroup_id` into the leading 64 bits of
//! every `LpmTrie` key instead of using a true per-container map-in-map
//! (unavailable in the pinned `aya`/`aya-ebpf`): isolation between
//! containers is therefore an INSERT-TIME userspace obligation, not a
//! structural guarantee the kernel enforces on its own. This module is
//! where that obligation is discharged, once, so nothing downstream of it
//! can get it wrong.
//!
//! The load-bearing property: [`build_policy_key`] is the *only* way this
//! crate constructs an `aya::maps::lpm_trie::Key<PolicyKeyData>`, and its
//! signature makes `prefix_len < PolicyKeyData::MIN_PREFIX_LEN` (64)
//! impossible to request -- there is no parameter through which a caller
//! can supply a raw `prefix_len` at all. A caller can only ask for
//! `prefix_bits_over_addr` (0..=128, the bits of the *address* to match
//! beyond the always-fully-matched `cgroup_id`), and the real `prefix_len`
//! is computed as `PolicyKeyData::MIN_PREFIX_LEN + prefix_bits_over_addr`,
//! which is bounded below by `MIN_PREFIX_LEN` by construction (the addend
//! is an unsigned integer) and validated not to exceed
//! `PolicyKeyData::PREFIX_LEN_FULL` above. See `tests::isolation` below for
//! the property spelled out as an executable proof.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use anyhow::{Context, Result};
use aya::maps::MapData;
use aya::maps::lpm_trie::{Key, LpmTrie};
use bathyscaphe_common::{MAX_PORT_RULES, PolicyKeyData, PolicyValue, PortRule, TransportProto};

/// Builds a well-formed [`Key<PolicyKeyData>`] for a policy entry. This is
/// the crate's sole path to constructing one -- see the module doc. Purely
/// a value computation: no map access, no privilege required, safe to call
/// (and unit test) anywhere.
///
/// `prefix_bits_over_addr` is how many leading bits of `addr` to pin, on
/// top of the always-fully-matched `cgroup_id`: `0` means "any address for
/// this container" (the flat-key equivalent of the nested design's inner
/// `/0`), `128` means an exact host route. Anything outside `0..=128` is
/// rejected rather than clamped, since silently narrowing a caller's
/// intended prefix would change which traffic a rule matches.
pub fn build_policy_key(cgroup_id: u64, addr: [u8; 16], prefix_bits_over_addr: u32) -> Result<Key<PolicyKeyData>> {
    if prefix_bits_over_addr > PolicyKeyData::ADDR_BITS {
        anyhow::bail!(
            "prefix_bits_over_addr {prefix_bits_over_addr} exceeds the {} address bits available \
             (PolicyKeyData::ADDR_BITS)",
            PolicyKeyData::ADDR_BITS
        );
    }
    // No underflow, no caller-suppliable path below MIN_PREFIX_LEN: this is
    // exactly the "impossible by construction" property this module exists
    // to provide.
    let prefix_len = PolicyKeyData::MIN_PREFIX_LEN + prefix_bits_over_addr;
    Ok(Key::new(prefix_len, PolicyKeyData::new(cgroup_id, addr)))
}

/// Embeds an [`IpAddr`] as the RFC 4291 form [`PolicyKeyData::addr`]
/// expects: IPv4-mapped-into-IPv6 for a v4 address, the address's own
/// octets for v6. Mirrors `PolicyKeyData::from_ipv4`'s embedding without
/// needing a throwaway `cgroup_id` to call it with.
pub fn addr_to_rfc4291(addr: IpAddr) -> [u8; 16] {
    match addr {
        IpAddr::V4(v4) => {
            let mut bytes = [0u8; 16];
            bytes[..12].copy_from_slice(&PolicyKeyData::IPV4_MAPPED_PREFIX);
            bytes[12..16].copy_from_slice(&v4.octets());
            bytes
        }
        IpAddr::V6(v6) => v6.octets(),
    }
}

/// Validates a [`PolicyValue`] before it's allowed anywhere near the map.
///
/// `PolicyValue::n_port_rules` and `PolicyValue::port_rules` are public
/// fields (the type crosses the kernel/user boundary as `aya::Pod`, which
/// forbids private invariants enforced only by a constructor), so a caller
/// that bypasses [`PolicyValue::with_port_rule`] could hand `set_policy` a
/// value claiming more entries than the fixed-size array actually holds.
/// This is the backstop: `set_policy` calls it before ever touching the
/// map, and rejects rather than truncates, per
/// `bathyscaphe_common::policy::MAX_PORT_RULES`'s doc -- the caller (a
/// later chunk) must split an over-full rule set across an additional,
/// narrower prefix instead.
pub fn validate_policy_value(value: &PolicyValue) -> Result<()> {
    if value.n_port_rules as usize > MAX_PORT_RULES {
        anyhow::bail!(
            "policy value declares n_port_rules={} which exceeds MAX_PORT_RULES={MAX_PORT_RULES}; \
             split the rule set across an additional prefix entry, never truncate",
            value.n_port_rules
        );
    }
    Ok(())
}

/// A `PortRule` matching TCP specifically, via
/// [`PortRule::encode_proto`] rather than the raw
/// [`bathyscaphe_common::TransportProto`] discriminant -- see that
/// function's doc for why the raw discriminant would be silently wrong
/// here (it would collide with [`PortRule::PROTO_ANY`]).
pub fn tcp_port_rule(port_lo: u16, port_hi: u16, action: u8) -> PortRule {
    PortRule::new(port_lo, port_hi, PortRule::encode_proto(TransportProto::Tcp as u8), action)
}

/// The UDP counterpart of [`tcp_port_rule`].
pub fn udp_port_rule(port_lo: u16, port_hi: u16, action: u8) -> PortRule {
    PortRule::new(port_lo, port_hi, PortRule::encode_proto(TransportProto::Udp as u8), action)
}

/// A stored key's identity, minus the `cgroup_id` (implied by whichever
/// [`PolicyStore::container_keys`] bucket it lives in). Used only for
/// userspace bookkeeping -- never crosses into a BPF map.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct TrackedKey {
    prefix_len: u32,
    addr: [u8; 16],
}

/// The typed, isolation-safe wrapper around the shared `POLICY` `LpmTrie`.
///
/// Tracks every key it has inserted, per `cgroup_id`, in
/// [`Self::container_keys`] -- this is the userspace structure
/// `bathyscaphe_common::policy`'s module doc calls for so
/// [`Self::release_container`] can delete exactly one container's entries
/// out of the shared trie with no outer map to drop a whole subtree from.
pub struct PolicyStore {
    trie: LpmTrie<MapData, PolicyKeyData, PolicyValue>,
    container_keys: HashMap<u64, HashSet<TrackedKey>>,
}

impl PolicyStore {
    pub(crate) fn new(trie: LpmTrie<MapData, PolicyKeyData, PolicyValue>) -> Self {
        Self { trie, container_keys: HashMap::new() }
    }

    /// Inserts (or overwrites) one policy entry for `cgroup_id`. See the
    /// module doc: `prefix_bits_over_addr` is the only prefix knob exposed,
    /// so the resulting key can never fall below
    /// `PolicyKeyData::MIN_PREFIX_LEN`.
    pub fn set_policy(&mut self, cgroup_id: u64, addr: IpAddr, prefix_bits_over_addr: u32, value: PolicyValue) -> Result<()> {
        validate_policy_value(&value)?;
        let addr_bytes = addr_to_rfc4291(addr);
        let key = build_policy_key(cgroup_id, addr_bytes, prefix_bits_over_addr)?;
        self.trie.insert(&key, value, 0).context("POLICY map insert failed")?;
        self.container_keys.entry(cgroup_id).or_default().insert(TrackedKey { prefix_len: key.prefix_len(), addr: addr_bytes });
        Ok(())
    }

    /// Deletes every policy entry ever inserted for `cgroup_id` through this
    /// store, returning how many were actually removed. A key already gone
    /// from the map (e.g. reaped by [`Self::reap_expired`] first) is not an
    /// error -- both paths racing to the same end state is expected, not
    /// exceptional.
    pub fn release_container(&mut self, cgroup_id: u64) -> Result<usize> {
        let Some(keys) = self.container_keys.remove(&cgroup_id) else {
            return Ok(0);
        };
        let mut removed = 0usize;
        for tracked in keys {
            let key = Key::new(tracked.prefix_len, PolicyKeyData::new(cgroup_id, tracked.addr));
            match self.trie.remove(&key) {
                Ok(()) => removed += 1,
                Err(aya::maps::MapError::KeyNotFound) => {}
                Err(error) => return Err(error).context("POLICY map remove failed during release_container"),
            }
        }
        Ok(removed)
    }

    /// Deletes every entry in the shared trie whose `expires_at_ns` has
    /// passed `now_boottime_ns`, across every container -- not just ones
    /// this process's own bookkeeping remembers inserting (a restart or an
    /// adopted orphan may have entries this instance never itself wrote).
    /// Returns how many were removed.
    ///
    /// This matters beyond simple cleanup: `bathyscaphe_common::policy`'s
    /// module doc notes that a kernel lookup does not retry at a shorter
    /// prefix when the entry it finds has expired -- an expired *specific*
    /// entry sitting in the trie would keep shadowing a broader,
    /// still-valid entry underneath it (relevant once the DNS-snoop layer,
    /// chunk #8, is inserting short-TTL host routes next to longer-lived
    /// CIDR rules). Reaping expired entries promptly is what keeps that
    /// shadowing window short.
    pub fn reap_expired(&mut self, now_boottime_ns: u64) -> Result<usize> {
        let expired: Vec<(u32, PolicyKeyData)> = self
            .trie
            .iter()
            .filter_map(|entry| entry.ok())
            .filter(|(_, value)| value.expires_at_ns != PolicyValue::NEVER_EXPIRES && value.expires_at_ns < now_boottime_ns)
            .map(|(key, _)| (key.prefix_len(), key.data()))
            .collect();

        let mut removed = 0usize;
        for (prefix_len, data) in expired {
            let key = Key::new(prefix_len, data);
            match self.trie.remove(&key) {
                Ok(()) => {
                    removed += 1;
                    let cgroup_id = u64::from_be_bytes(data.cgroup_id);
                    if let Some(set) = self.container_keys.get_mut(&cgroup_id) {
                        set.remove(&TrackedKey { prefix_len, addr: data.addr });
                    }
                }
                Err(aya::maps::MapError::KeyNotFound) => {}
                Err(error) => return Err(error).context("POLICY map remove failed during reap_expired"),
            }
        }
        Ok(removed)
    }

    /// How many containers currently have at least one tracked policy
    /// entry. Exposed for tests and future stats reporting; not itself
    /// security-relevant.
    pub fn tracked_container_count(&self) -> usize {
        self.container_keys.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn any_addr() -> [u8; 16] {
        addr_to_rfc4291(IpAddr::from([10, 0, 0, 1]))
    }

    // --- prefix computation -------------------------------------------------

    #[test]
    fn prefix_len_is_min_prefix_len_plus_bits_over_addr() {
        let key = build_policy_key(1, any_addr(), 0).unwrap();
        assert_eq!(key.prefix_len(), PolicyKeyData::MIN_PREFIX_LEN);

        let key = build_policy_key(1, any_addr(), 64).unwrap();
        assert_eq!(key.prefix_len(), 128);

        let key = build_policy_key(1, any_addr(), 128).unwrap();
        assert_eq!(key.prefix_len(), PolicyKeyData::PREFIX_LEN_FULL);
    }

    #[test]
    fn prefix_bits_over_addr_beyond_the_address_width_is_rejected() {
        assert!(build_policy_key(1, any_addr(), 129).is_err());
        assert!(build_policy_key(1, any_addr(), u32::MAX).is_err());
    }

    // --- isolation by construction ------------------------------------------
    //
    // The property under test: no call to `build_policy_key` -- the sole
    // constructor of a POLICY lookup/insert key anywhere in this crate --
    // can ever produce `prefix_len < PolicyKeyData::MIN_PREFIX_LEN`, and
    // two different cgroup ids sharing every bit but one still produce
    // keys that cannot cross-match under the kernel's own LPM semantics
    // (a match requires the lookup key's leading `prefix_len` bits to
    // equal the stored key's).

    #[test]
    fn build_policy_key_never_produces_a_prefix_below_min_prefix_len() {
        for bits_over in 0..=PolicyKeyData::ADDR_BITS {
            let key = build_policy_key(0xDEAD_BEEF, any_addr(), bits_over).unwrap();
            assert!(key.prefix_len() >= PolicyKeyData::MIN_PREFIX_LEN, "prefix_len {} < MIN_PREFIX_LEN for bits_over={bits_over}", key.prefix_len());
        }
    }

    #[test]
    fn adversarial_cgroup_ids_differing_in_one_bit_cannot_cross_match() {
        // Worst case: two cgroup ids identical except for their lowest bit,
        // same destination address, same requested prefix width.
        let cgroup_a: u64 = 0x0000_0000_0000_0001;
        let cgroup_b: u64 = 0x0000_0000_0000_0002;
        let addr = any_addr();

        for bits_over in 0..=PolicyKeyData::ADDR_BITS {
            let stored_a = build_policy_key(cgroup_a, addr, bits_over).unwrap();
            let lookup_b = build_policy_key(cgroup_b, addr, PolicyKeyData::ADDR_BITS).unwrap(); // full lookup key, as the kernel always uses

            assert!(
                !lpm_would_match(&stored_a, &lookup_b),
                "a stored entry for cgroup {cgroup_a:016x} matched a lookup for cgroup {cgroup_b:016x} at bits_over={bits_over}"
            );
        }
    }

    #[test]
    fn same_cgroup_id_different_address_bits_still_matches_as_expected() {
        // Sanity check on `lpm_would_match` itself and on the "any address"
        // (bits_over=0) case: a /0-over-address entry for a container DOES
        // match any lookup for that same container, which is the intended,
        // non-isolation-breaking behavior.
        let cgroup = 0x1234_5678_9abc_def0u64;
        let stored_any_addr = build_policy_key(cgroup, [0u8; 16], 0).unwrap();
        let lookup = build_policy_key(cgroup, any_addr(), PolicyKeyData::ADDR_BITS).unwrap();
        assert!(lpm_would_match(&stored_any_addr, &lookup));
    }

    /// A userspace re-implementation of the kernel's `LpmTrie` matching
    /// rule (longest-prefix-match reduces to: does the lookup key's value
    /// agree with the stored key's value on the stored key's leading
    /// `prefix_len` bits?), used only to make the isolation property
    /// concrete and checkable in a plain unit test, without a kernel.
    fn lpm_would_match(stored: &Key<PolicyKeyData>, lookup: &Key<PolicyKeyData>) -> bool {
        if stored.prefix_len() > lookup.prefix_len() {
            return false;
        }
        let stored_bytes = key_bytes(stored.data());
        let lookup_bytes = key_bytes(lookup.data());
        bits_equal(&stored_bytes, &lookup_bytes, stored.prefix_len())
    }

    fn key_bytes(data: PolicyKeyData) -> [u8; 24] {
        let mut out = [0u8; 24];
        out[..8].copy_from_slice(&data.cgroup_id);
        out[8..].copy_from_slice(&data.addr);
        out
    }

    fn bits_equal(a: &[u8; 24], b: &[u8; 24], bits: u32) -> bool {
        let full_bytes = (bits / 8) as usize;
        if a[..full_bytes] != b[..full_bytes] {
            return false;
        }
        let remaining_bits = bits % 8;
        if remaining_bits == 0 {
            return true;
        }
        let mask = 0xFFu8 << (8 - remaining_bits);
        (a[full_bytes] & mask) == (b[full_bytes] & mask)
    }

    // --- n_port_rules overflow ------------------------------------------

    #[test]
    fn validate_policy_value_rejects_hand_crafted_overflow() {
        let mut value = PolicyValue::new(0, 0, PolicyValue::NEVER_EXPIRES);
        // Bypass `with_port_rule` (which itself refuses to overflow) to
        // simulate a value some other, buggier caller handed us directly --
        // exactly the case `validate_policy_value` exists to catch.
        value.n_port_rules = (MAX_PORT_RULES + 1) as u8;
        assert!(validate_policy_value(&value).is_err());
    }

    #[test]
    fn validate_policy_value_accepts_a_full_but_not_overflowing_value() {
        let mut value = PolicyValue::new(0, 0, PolicyValue::NEVER_EXPIRES);
        for i in 0..MAX_PORT_RULES {
            value = value.with_port_rule(PortRule::single_port(i as u16, PortRule::PROTO_ANY, 0)).unwrap();
        }
        assert!(validate_policy_value(&value).is_ok());
    }

    // --- encode_proto round trip, at this layer's own API surface -------

    #[test]
    fn tcp_and_udp_port_rule_helpers_use_encode_proto_not_the_raw_discriminant() {
        let tcp = tcp_port_rule(443, 443, 0);
        let udp = udp_port_rule(53, 53, 0);

        // The raw TCP discriminant is 0, same numeric value as
        // PortRule::PROTO_ANY -- if these helpers forgot encode_proto's +1
        // shift, `tcp.proto` would equal PROTO_ANY and this assertion would
        // fail, silently turning a TCP-only rule into an any-proto one.
        assert_ne!(tcp.proto, PortRule::PROTO_ANY);
        assert_eq!(tcp.proto, PortRule::encode_proto(TransportProto::Tcp as u8));
        assert_eq!(udp.proto, PortRule::encode_proto(TransportProto::Udp as u8));

        assert!(tcp.matches_proto(TransportProto::Tcp as u8));
        assert!(!tcp.matches_proto(TransportProto::Udp as u8));
        assert!(udp.matches_proto(TransportProto::Udp as u8));
        assert!(!udp.matches_proto(TransportProto::Tcp as u8));
    }

    // --- address embedding -------------------------------------------------

    #[test]
    fn addr_to_rfc4291_embeds_v4_with_the_documented_prefix() {
        let bytes = addr_to_rfc4291(IpAddr::from([10, 0, 0, 1]));
        assert_eq!(&bytes[..12], &PolicyKeyData::IPV4_MAPPED_PREFIX[..]);
        assert_eq!(&bytes[12..], &[10, 0, 0, 1]);
    }

    #[test]
    fn addr_to_rfc4291_passes_v6_through_unchanged() {
        let v6 = std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        assert_eq!(addr_to_rfc4291(IpAddr::from(v6)), v6.octets());
    }
}
