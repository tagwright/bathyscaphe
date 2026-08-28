// SPDX-License-Identifier: GPL-3.0-or-later
//! Query/response correlation (build chunk #10): [`PendingQueryTable`]
//! is the userspace PENDING-QUERY table `docs/DNS.md`'s attribution
//! problem calls for.
//!
//! ## The problem this solves
//!
//! `bathyscaphe-ebpf::dns`'s ingress `dns_snoop` program attributes a DNS
//! RESPONSE to whatever cgroup `bpf_get_current_cgroup_id()` reports at the
//! moment the hook runs -- which, for a reply synthesized/injected by a
//! resolver such as Docker's embedded `127.0.0.11` (the default for
//! compose/user-defined networks) or a Tailscale-intercepted resolver, is
//! the RESOLVER's own cgroup (`docker.service`, `tailscaled.service`), not
//! the querying container's. The corresponding outbound QUERY has no such
//! problem: `bathyscaphe-ebpf::dns_query`'s egress `dns_query_snoop`
//! program fires in the container's OWN cgroup, always, because it is the
//! container's own process making an ordinary `sendto()`/`send()` call on
//! its own socket -- there is no resolver-side injection on the way out.
//!
//! [`PendingQueryTable`] is the bridge: every captured query records
//! `(txid, src_port) -> {cgroup_id, inserted_at}` here; every captured
//! response looks up `(txid, dst_port)` (the response's destination port
//! IS the query's original source port -- the resolver addresses its reply
//! back to it) and, on a hit, recovers the CORRECT cgroup id to attribute
//! the answer to, overriding the response hook's own (possibly wrong)
//! attribution.
//!
//! ## Correlation key: `(txid, port)`, not `(txid, port, resolver addr)`
//!
//! The build brief that specified this table allows an optional resolver
//! address component in the key. This implementation omits it: a
//! container's own ephemeral source port is, in practice, unique among its
//! OWN concurrently in-flight queries (the OS kernel's own port allocator
//! guarantees this for a single querying process/socket), and the DNS
//! transaction id adds a second, independent 16-bit disambiguator on top.
//! A COLLISION -- two different containers happening to pick the exact
//! same ephemeral port for a query with the exact same transaction id,
//! within the same [`PENDING_QUERY_TTL_NS`] window -- is possible in
//! principle but exceedingly unlikely, and its consequence if it ever
//! occurred would be a single answer attributed to the wrong (but still
//! REAL, actually-querying) container, not a fabricated one -- a narrower
//! failure mode than the STRUCTURAL misattribution this table exists to
//! fix. Adding the resolver's source address to the key would need it
//! plumbed through from `dns_snoop`'s capture (not currently captured, to
//! keep `DnsCapture` unchanged), a real cost for a narrowing this
//! implementation judges not worth it at v1 -- documented here, not
//! silently omitted, as a residual limitation (`docs/DNS.md`).
//!
//! ## TTL and eviction
//!
//! [`PENDING_QUERY_TTL_NS`] (5 seconds) bounds how long a recorded query
//! waits for its response before becoming uncorrelatable: comfortably
//! longer than any local or lightly-loaded upstream resolver's real
//! round-trip time, short enough that a table entry for a query whose
//! response never arrived (a dropped packet, a resolver timeout) does not
//! linger. Sweeping is opportunistic (mirrors
//! `bathyscaphe::dns::cache::DomainCache`'s own "sweep on every write"
//! convention) rather than a dedicated background thread: every
//! [`PendingQueryTable::record_query`] and
//! [`PendingQueryTable::correlate`] call sweeps every entry across every
//! container past its TTL, bounding the table's size to "queries actually
//! in flight right now," never an unbounded host-wide accumulation.
//!
//! ## Multiple responses to one query are still correlatable
//!
//! Unlike a table that removes an entry the instant it correlates one
//! response, [`PendingQueryTable::correlate`] leaves the entry in place
//! until it naturally ages out of [`PENDING_QUERY_TTL_NS`] -- a resolver
//! that answers with more than one UDP datagram for the same query (a
//! duplicate/retransmitted packet, or separate A and AAAA responses that
//! happen to reuse the same transaction id and port, which some resolver
//! implementations do) still correlates correctly on every one of them,
//! not just the first.
//!
//! ## The uncorrelatable fallback
//!
//! [`PendingQueryTable::correlate`] returns `None` when no matching query
//! was ever recorded (the query's own capture was dropped by a full
//! `DNS_QUERIES` ring, the query used TCP or a resolver this build cannot
//! see for any of `docs/DNS.md`'s documented reasons, or the response
//! arrived more than [`PENDING_QUERY_TTL_NS`] after the query). Every
//! caller (`crate::dns::capture_callback`) falls back to the response
//! hook's OWN `cgroup_id` in that case, exactly as chunk #9 shipped, and
//! marks the resulting cache/enforcement action low-confidence --
//! documented plainly, never silently treated as equally trustworthy as a
//! correlated hit.

use std::collections::HashMap;

/// How long a recorded query waits for a correlating response before it
/// ages out. See this module's doc for the rationale.
pub const PENDING_QUERY_TTL_NS: u64 = 5 * 1_000_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PendingQuery {
    cgroup_id: u64,
    inserted_at_ns: u64,
}

/// The correlation table itself: `(txid, src_port) -> PendingQuery`. See
/// this module's doc for the full design.
#[derive(Default)]
pub struct PendingQueryTable {
    by_key: HashMap<(u16, u16), PendingQuery>,
}

impl PendingQueryTable {
    pub fn new() -> Self {
        Self::default()
    }

    /// Records that a query with `txid`/`src_port` left `cgroup_id` at
    /// `now_ns` (a captured [`bathyscaphe_common::DnsQueryCapture`]'s own
    /// `ktime_ns`). Overwrites any prior entry at the same key -- the most
    /// recently observed query for a given `(txid, src_port)` pair wins,
    /// matching [`super::cache::DomainCache::record`]'s own
    /// overwrite-on-re-record convention.
    pub fn record_query(&mut self, txid: u16, src_port: u16, cgroup_id: u64, now_ns: u64) {
        self.by_key.insert((txid, src_port), PendingQuery { cgroup_id, inserted_at_ns: now_ns });
        self.sweep(now_ns);
    }

    /// Looks up a captured response's `(txid, dst_port)` (its destination
    /// port IS the original query's source port) at `now_ns` (the
    /// response's own `ktime_ns`). Returns the CORRECT querying
    /// container's `cgroup_id` on a hit still within
    /// [`PENDING_QUERY_TTL_NS`], `None` on a miss or an aged-out entry --
    /// see this module's doc for the fallback callers must apply on `None`.
    pub fn correlate(&mut self, txid: u16, dst_port: u16, now_ns: u64) -> Option<u64> {
        self.sweep(now_ns);
        self.by_key.get(&(txid, dst_port)).map(|pending| pending.cgroup_id)
    }

    /// Removes every entry (across every container) whose own `now_ns -
    /// inserted_at_ns` exceeds [`PENDING_QUERY_TTL_NS`].
    fn sweep(&mut self, now_ns: u64) {
        self.by_key.retain(|_, pending| now_ns.saturating_sub(pending.inserted_at_ns) <= PENDING_QUERY_TTL_NS);
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.by_key.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fresh_query_correlates_its_response() {
        let mut table = PendingQueryTable::new();
        table.record_query(0x1234, 54321, 42, 1_000_000_000);
        assert_eq!(table.correlate(0x1234, 54321, 1_000_000_500), Some(42));
    }

    #[test]
    fn an_uncorrelatable_response_with_no_matching_query_is_none() {
        let mut table = PendingQueryTable::new();
        assert_eq!(table.correlate(0xFFFF, 12345, 0), None);
    }

    #[test]
    fn a_different_txid_at_the_same_port_does_not_correlate() {
        let mut table = PendingQueryTable::new();
        table.record_query(0x1234, 54321, 42, 0);
        assert_eq!(table.correlate(0x5678, 54321, 0), None);
    }

    #[test]
    fn a_different_port_at_the_same_txid_does_not_correlate() {
        let mut table = PendingQueryTable::new();
        table.record_query(0x1234, 54321, 42, 0);
        assert_eq!(table.correlate(0x1234, 9999, 0), None);
    }

    #[test]
    fn a_response_past_the_ttl_window_does_not_correlate() {
        let mut table = PendingQueryTable::new();
        table.record_query(0x1234, 54321, 42, 0);
        let past_ttl = PENDING_QUERY_TTL_NS + 1;
        assert_eq!(table.correlate(0x1234, 54321, past_ttl), None);
    }

    #[test]
    fn a_response_exactly_at_the_ttl_boundary_still_correlates() {
        let mut table = PendingQueryTable::new();
        table.record_query(0x1234, 54321, 42, 0);
        assert_eq!(table.correlate(0x1234, 54321, PENDING_QUERY_TTL_NS), Some(42));
    }

    #[test]
    fn multiple_responses_to_the_same_query_all_correlate() {
        let mut table = PendingQueryTable::new();
        table.record_query(0x1234, 54321, 42, 0);
        assert_eq!(table.correlate(0x1234, 54321, 100), Some(42));
        assert_eq!(table.correlate(0x1234, 54321, 200), Some(42), "a second response (duplicate/retransmit) still correlates");
    }

    #[test]
    fn sweep_bounds_the_table_to_queries_still_in_flight() {
        let mut table = PendingQueryTable::new();
        table.record_query(0x1111, 1, 1, 0);
        table.record_query(0x2222, 2, 2, PENDING_QUERY_TTL_NS + 1);
        // The second insert's own sweep should have evicted the first,
        // now-aged-out entry.
        assert_eq!(table.len(), 1);
    }

    /// The key scenario the build brief calls out: simulate Docker's
    /// embedded-DNS case where the RESPONSE hook's own `cgroup_id`
    /// (`docker.service`'s, e.g. a large well-known value distinct from
    /// any container's) differs from the QUERYING container's real cgroup
    /// id, and prove correlation recovers the correct one anyway.
    #[test]
    fn correlation_recovers_the_querying_containers_cgroup_even_when_the_responses_own_cgroup_differs() {
        let querying_container_cgroup_id: u64 = 0x0000_0000_0000_2A2A;
        let dockerd_cgroup_id: u64 = 0x0000_0000_DEC0_DE00; // stands in for docker.service's own cgroup

        let mut table = PendingQueryTable::new();
        // The query fires in the CONTAINER's own cgroup (dns_query_snoop,
        // egress -- never suffers the injection-attribution problem).
        table.record_query(0xBEEF, 44321, querying_container_cgroup_id, 1_000_000_000);

        // The response's OWN response-hook cgroup_id (what dns_snoop
        // captured, ingress) is dockerd's, not the container's -- exactly
        // the misattribution `docs/DNS.md` documents. A caller that
        // ignored correlation entirely would wrongly use this value.
        let responses_own_cgroup_id = dockerd_cgroup_id;
        assert_ne!(responses_own_cgroup_id, querying_container_cgroup_id, "sanity: the simulated response cgroup really is different from the container's");

        // Correlating on the response's (txid, dst_port) -- dst_port here
        // equals the query's own src_port, per this module's doc -- must
        // recover the CONTAINER's cgroup id, not the resolver's.
        let corrected = table.correlate(0xBEEF, 44321, 1_000_000_500);
        assert_eq!(corrected, Some(querying_container_cgroup_id), "correlation must override the response's own (wrong) cgroup attribution with the querying container's");
        assert_ne!(corrected, Some(responses_own_cgroup_id));
    }
}
