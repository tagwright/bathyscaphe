// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 techgaud
//! Query/response correlation (build chunk #10, hardened build chunk #14):
//! [`PendingQueryTable`] is the userspace PENDING-QUERY table `docs/DNS.md`'s
//! attribution problem calls for.
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
//! ## Build chunk #14: the cross-container isolation fix
//!
//! Build chunk #13's live integration testing PROVED the chunk #10 design
//! note below (a `(txid, port)` collision between two DIFFERENT containers
//! was "possible in principle but exceedingly unlikely") wrong in practice:
//! it reproduced a real collision deterministically, 5/5 runs, between two
//! SEPARATE containers' DNS traffic observed by the same daemon process
//! (`docs/TESTING.md`'s chunk #13 account, and `scenario_6_untrusted_resolver`'s
//! own module doc in `test/integration/scenarios.py`, which had to be
//! ISOLATED onto its own daemon/bpffs root specifically to dodge this bug
//! rather than fix it). The old table's `HashMap<(u16, u16), PendingQuery>`
//! held exactly ONE entry per key: a second container's query at the same
//! `(txid, src_port)` silently OVERWROTE the first container's still-live
//! entry, and a later response correlating against that key received
//! whichever container happened to have recorded LAST -- a real
//! cross-container policy misattribution (in `mode: block`, a DNS answer
//! for one container's resolved name could seed a DIFFERENT container's
//! kernel allow-map).
//!
//! ### Empirical investigation: is a container's own IP address a usable
//! discriminator? No -- documented here precisely why.
//!
//! The obvious fix would add a container-identifying address component to
//! the correlation key (the query's own source address, or the response's
//! own destination address) so two containers can never collide even if
//! their `(txid, port)` pair does. This was investigated directly (a real
//! `alpine` container on a real user-defined Docker network, kernel
//! 6.8.0-136, `tcpdump` inside the container's own network namespace) before
//! choosing a fix, per this build's brief: **for Docker's embedded-DNS
//! path -- the exact case chunk #9/#10 already established has the
//! wrong-cgroup problem in the first place, and therefore the only case
//! that actually needs this fix -- both addresses are useless.**
//!
//! Captured directly on the container's own `lo` interface (the embedded
//! resolver's reply never crosses `eth0` at all -- it is injected straight
//! into the container's loopback, which is why chunk #9's own `tcpdump -i
//! eth0` capture attempt for this same path saw nothing):
//!
//! ```text
//! 127.0.0.1.35026 > 127.0.0.11.50427: ...  (the QUERY, post-DNAT)
//! 127.0.0.11.53 > 127.0.0.1.35026: ...      (the RESPONSE)
//! ```
//!
//! The query's own SOURCE address and the response's own DESTINATION
//! address are BOTH `127.0.0.1` -- not the container's real bridge-network
//! IP (`192.168.16.2` in this run, confirmed via `ip addr show eth0` inside
//! the same container). This is not a capture artifact: `127.0.0.1` is a
//! PER-NETWORK-NAMESPACE address -- every container has its own private
//! loopback interface, so this exact byte pattern (`7f 00 00 01`) is
//! IDENTICAL across every container using Docker's embedded resolver,
//! regardless of which container it is. Plumbing this address into
//! [`bathyscaphe_common::DnsQueryCapture`]/[`bathyscaphe_common::DnsCapture`]
//! and keying on it would add real complexity (new eBPF loads, a wire-size
//! change) for a value that provides **zero** cross-container
//! discrimination in precisely the scenario this fix exists for. (A
//! response delivered over a REAL NIC/veth path -- an external resolver --
//! would carry the container's genuine IP on both ends, but that path's
//! `cgroup_id` attribution is already correct per `docs/DNS.md`'s own
//! "Why ingress" section, so it was never the vulnerable case to begin
//! with.) This is why build chunk #14 does NOT add an address component to
//! the correlation key -- documented here as a deliberate, evidence-based
//! choice, not an oversight.
//!
//! ### The fix actually applied: detect ambiguity, never guess
//!
//! Since no address discriminator is available for the case that matters,
//! [`PendingQueryTable`] now tracks **every distinct cgroup** that has a
//! live, unexpired query recorded under a given `(txid, port)` key, not
//! just the most recent one. [`PendingQueryTable::correlate`] returns a
//! [`Correlation`]:
//!
//! - Exactly one distinct cgroup has a live entry at that key:
//!   [`Correlation::Resolved`] -- correlation succeeds exactly as chunk #10
//!   designed it.
//! - No entry at all: [`Correlation::Miss`] -- unchanged from chunk #10's
//!   "uncorrelatable" case.
//! - **More than one DIFFERENT container's query is live at that exact
//!   key right now**: [`Correlation::Ambiguous`]. The table refuses to
//!   guess which container the response actually belongs to -- this is the
//!   fail-safe the build brief calls for: [`super::capture_callback`]
//!   treats `Ambiguous` exactly like `Miss` (falls back to the response
//!   capture's own, possibly-wrong-but-never-CROSS-CONTAINER, `cgroup_id`,
//!   and marks `correlated: false`), which can never insert a `POLICY`
//!   entry under a REAL container's cgroup that container's own traffic
//!   didn't actually earn (the fallback cgroup_id is either the true
//!   resolver-service cgroup, which no container's name patterns are ever
//!   registered against, or -- for a non-injected path -- the response's
//!   own already-correct cgroup). A DNS answer is now either attributed
//!   with confidence or not attributed to any specific container's policy
//!   at all -- **never attributed to the WRONG one.**
//!
//! ## Bounding the collision window (Part B of the fix)
//!
//! Two further changes shrink how often two containers' queries can ever
//! be concurrently live at the same key in the first place:
//!
//! - [`PENDING_QUERY_TTL_NS`] is cut from chunk #10's 5 seconds to 2
//!   seconds -- still comfortably longer than any real resolver round trip
//!   (`docs/DNS.md`'s own reasoning), but less than half the prior window
//!   during which two unrelated containers' queries could overlap.
//! - [`MAX_SERVED_RESPONSES`]: an entry that has already correlated this
//!   many responses (4 -- enough for a legitimate A answer, an AAAA
//!   answer, and a couple of retransmits, per chunk #10's own
//!   "multiple responses to one query" reasoning) is evicted immediately
//!   on the correlation that reaches the cap, rather than lingering for
//!   the rest of its TTL doing nothing further but occupying a slot a
//!   colliding second container could land in.
//!
//! ## Cleanup on release (Part C of the fix)
//!
//! [`PendingQueryTable::remove_container`] purges every entry belonging to
//! one cgroup id, called from `daemon::apply::apply_release`/
//! `apply_release_all` the moment a container is released -- this is the
//! other half of chunk #13's live repro (`docs/TESTING.md`): a STALE entry
//! left behind by an already-released container was what a later,
//! unrelated container's query collided with. A released container can no
//! longer collide with anything once this runs.
//!
//! ## Multiple responses to one query are still correlatable (unchanged)
//!
//! A resolver that answers with more than one UDP datagram for the same
//! query (a duplicate/retransmitted packet, or separate A and AAAA
//! responses that happen to reuse the same transaction id and port, which
//! some resolver implementations do) still correlates correctly up to
//! [`MAX_SERVED_RESPONSES`] times, not just once.
//!
//! ## The uncorrelatable fallback (unchanged)
//!
//! [`PendingQueryTable::correlate`] returns [`Correlation::Miss`] when no
//! matching query was ever recorded (the query's own capture was dropped
//! by a full `DNS_QUERIES` ring, the query used TCP or a resolver this
//! build cannot see for any of `docs/DNS.md`'s documented reasons, or the
//! response arrived more than [`PENDING_QUERY_TTL_NS`] after the query).
//! Every caller (`crate::dns::capture_callback`) falls back to the response
//! hook's OWN `cgroup_id` in that case, exactly as chunk #9 shipped, and
//! marks the resulting cache/enforcement action low-confidence --
//! documented plainly, never silently treated as equally trustworthy as a
//! correlated hit. `Correlation::Ambiguous` uses the identical fallback --
//! see this module's doc above.

use std::collections::HashMap;

/// How long a recorded query waits for a correlating response before it
/// ages out. Cut from chunk #10's 5 seconds to 2 seconds by build chunk
/// #14 to shrink the window during which two different containers' queries
/// can ever be concurrently live at the same key -- see this module's doc.
pub const PENDING_QUERY_TTL_NS: u64 = 2 * 1_000_000_000;

/// How many responses a single recorded query will correlate before being
/// evicted early (rather than lingering for the rest of [`PENDING_QUERY_TTL_NS`]
/// doing nothing further but occupying a slot). See this module's doc,
/// "Bounding the collision window".
pub const MAX_SERVED_RESPONSES: u8 = 4;

/// The outcome of [`PendingQueryTable::correlate`]. See this module's doc
/// for the full design `Ambiguous` exists to make possible.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Correlation {
    /// Exactly one container has a live query recorded at this key --
    /// correlation succeeds with confidence.
    Resolved(u64),
    /// MORE THAN ONE different container has a live query recorded at this
    /// exact `(txid, port)` key right now. The table refuses to pick
    /// either -- see this module's doc for why this is the fail-safe
    /// build chunk #14 requires, not a defect.
    Ambiguous,
    /// No live query recorded at this key at all.
    Miss,
}

impl Correlation {
    #[cfg(test)]
    fn resolved(self) -> Option<u64> {
        match self {
            Correlation::Resolved(cgroup_id) => Some(cgroup_id),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PendingQuery {
    cgroup_id: u64,
    inserted_at_ns: u64,
    served: u8,
}

/// The correlation table itself: `(txid, src_port) -> one entry PER
/// DISTINCT querying cgroup currently live at that key`. See this module's
/// doc for the full design, including why a key can legitimately hold more
/// than one entry (two different containers' queries colliding) and how
/// that case is handled without ever cross-attributing.
#[derive(Default)]
pub struct PendingQueryTable {
    by_key: HashMap<(u16, u16), Vec<PendingQuery>>,
}

impl PendingQueryTable {
    pub fn new() -> Self {
        Self::default()
    }

    /// Records that a query with `txid`/`src_port` left `cgroup_id` at
    /// `now_ns` (a captured [`bathyscaphe_common::DnsQueryCapture`]'s own
    /// `ktime_ns`). Re-recording from the SAME cgroup at the same key
    /// refreshes its recency and resets its serve count (the most recently
    /// observed query for a given container/key wins, matching chunk #10's
    /// own overwrite-on-re-record convention) -- but a DIFFERENT cgroup
    /// recording at the same key gets its OWN entry alongside the first,
    /// never overwriting it. This is the structural half of the chunk #14
    /// fix: the old table's silent same-key overwrite is what let a second
    /// container's query erase the first's still-live entry.
    pub fn record_query(&mut self, txid: u16, src_port: u16, cgroup_id: u64, now_ns: u64) {
        let entries = self.by_key.entry((txid, src_port)).or_default();
        match entries.iter_mut().find(|entry| entry.cgroup_id == cgroup_id) {
            Some(entry) => {
                entry.inserted_at_ns = now_ns;
                entry.served = 0;
            }
            None => entries.push(PendingQuery { cgroup_id, inserted_at_ns: now_ns, served: 0 }),
        }
        self.sweep(now_ns);
    }

    /// Looks up a captured response's `(txid, dst_port)` (its destination
    /// port IS the original query's source port) at `now_ns` (the
    /// response's own `ktime_ns`). See [`Correlation`]'s doc for the three
    /// possible outcomes and this module's doc for why `Ambiguous` exists.
    pub fn correlate(&mut self, txid: u16, dst_port: u16, now_ns: u64) -> Correlation {
        self.sweep(now_ns);
        let key = (txid, dst_port);
        let Some(entries) = self.by_key.get_mut(&key) else {
            return Correlation::Miss;
        };

        match entries.len() {
            0 => Correlation::Miss,
            1 => {
                let cgroup_id = entries[0].cgroup_id;
                entries[0].served = entries[0].served.saturating_add(1);
                if entries[0].served >= MAX_SERVED_RESPONSES {
                    entries.clear();
                }
                if entries.is_empty() {
                    self.by_key.remove(&key);
                }
                Correlation::Resolved(cgroup_id)
            }
            _ => Correlation::Ambiguous,
        }
    }

    /// Removes every entry belonging to `cgroup_id`, across every key.
    /// Called on container release (`daemon::apply::apply_release`/
    /// `apply_release_all`) so a released container's queries can never
    /// become the STALE entry a later, unrelated container's query
    /// collides with -- see this module's doc, "Cleanup on release".
    pub fn remove_container(&mut self, cgroup_id: u64) {
        self.by_key.retain(|_, entries| {
            entries.retain(|entry| entry.cgroup_id != cgroup_id);
            !entries.is_empty()
        });
    }

    /// Removes every entry (across every container/key) whose own `now_ns -
    /// inserted_at_ns` exceeds [`PENDING_QUERY_TTL_NS`], and drops any key
    /// left with no entries at all.
    fn sweep(&mut self, now_ns: u64) {
        self.by_key.retain(|_, entries| {
            entries.retain(|pending| now_ns.saturating_sub(pending.inserted_at_ns) <= PENDING_QUERY_TTL_NS);
            !entries.is_empty()
        });
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.by_key.values().map(Vec::len).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fresh_query_correlates_its_response() {
        let mut table = PendingQueryTable::new();
        table.record_query(0x1234, 54321, 42, 1_000_000_000);
        assert_eq!(table.correlate(0x1234, 54321, 1_000_000_500).resolved(), Some(42));
    }

    #[test]
    fn an_uncorrelatable_response_with_no_matching_query_is_a_miss() {
        let mut table = PendingQueryTable::new();
        assert_eq!(table.correlate(0xFFFF, 12345, 0), Correlation::Miss);
    }

    #[test]
    fn a_different_txid_at_the_same_port_does_not_correlate() {
        let mut table = PendingQueryTable::new();
        table.record_query(0x1234, 54321, 42, 0);
        assert_eq!(table.correlate(0x5678, 54321, 0), Correlation::Miss);
    }

    #[test]
    fn a_different_port_at_the_same_txid_does_not_correlate() {
        let mut table = PendingQueryTable::new();
        table.record_query(0x1234, 54321, 42, 0);
        assert_eq!(table.correlate(0x1234, 9999, 0), Correlation::Miss);
    }

    #[test]
    fn a_response_past_the_ttl_window_does_not_correlate() {
        let mut table = PendingQueryTable::new();
        table.record_query(0x1234, 54321, 42, 0);
        let past_ttl = PENDING_QUERY_TTL_NS + 1;
        assert_eq!(table.correlate(0x1234, 54321, past_ttl), Correlation::Miss);
    }

    #[test]
    fn a_response_exactly_at_the_ttl_boundary_still_correlates() {
        let mut table = PendingQueryTable::new();
        table.record_query(0x1234, 54321, 42, 0);
        assert_eq!(table.correlate(0x1234, 54321, PENDING_QUERY_TTL_NS).resolved(), Some(42));
    }

    #[test]
    fn multiple_responses_to_the_same_query_all_correlate() {
        let mut table = PendingQueryTable::new();
        table.record_query(0x1234, 54321, 42, 0);
        assert_eq!(table.correlate(0x1234, 54321, 100).resolved(), Some(42));
        assert_eq!(table.correlate(0x1234, 54321, 200).resolved(), Some(42), "a second response (duplicate/retransmit) still correlates");
    }

    #[test]
    fn an_entry_is_evicted_after_serving_max_responses_rather_than_lingering_the_full_ttl() {
        let mut table = PendingQueryTable::new();
        table.record_query(0x1234, 54321, 42, 0);
        for _ in 0..MAX_SERVED_RESPONSES {
            assert_eq!(table.correlate(0x1234, 54321, 1).resolved(), Some(42));
        }
        // The entry has now served its cap and must be gone, well within
        // the TTL window still.
        assert_eq!(table.correlate(0x1234, 54321, 2), Correlation::Miss, "an entry that already served MAX_SERVED_RESPONSES must not linger for the rest of its TTL");
        assert_eq!(table.len(), 0);
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
        let corrected = table.correlate(0xBEEF, 44321, 1_000_000_500).resolved();
        assert_eq!(corrected, Some(querying_container_cgroup_id), "correlation must override the response's own (wrong) cgroup attribution with the querying container's");
        assert_ne!(corrected, Some(responses_own_cgroup_id));
    }

    /// Build chunk #14's core security property: two DIFFERENT containers
    /// whose queries happen to collide on the exact same `(txid, port)`
    /// key must NEVER have a response attributed to either one with
    /// confidence -- see this module's doc for why an address-based
    /// discriminator is not viable and `Ambiguous` is the fix instead.
    #[test]
    fn two_different_containers_colliding_on_the_same_key_never_cross_attribute() {
        let container_a: u64 = 0x1111_1111_1111_1111;
        let container_b: u64 = 0x2222_2222_2222_2222;

        let mut table = PendingQueryTable::new();
        table.record_query(0x4242, 55555, container_a, 1_000_000_000);
        table.record_query(0x4242, 55555, container_b, 1_000_000_050);

        let outcome = table.correlate(0x4242, 55555, 1_000_000_100);
        assert_eq!(outcome, Correlation::Ambiguous, "a genuine (txid, port) collision between two different containers must never resolve to either one");
        assert_ne!(outcome.resolved(), Some(container_a));
        assert_ne!(outcome.resolved(), Some(container_b));
    }

    /// The OLD table (a plain `HashMap<(u16,u16), PendingQuery>`) would
    /// have let container B's later `record_query` silently overwrite
    /// container A's still-live entry, so a response actually meant for A
    /// would have correlated to B. Prove that no longer happens: A's own
    /// entry survives B's insert at the same key.
    #[test]
    fn a_second_containers_query_at_the_same_key_does_not_evict_the_firsts_entry() {
        let container_a: u64 = 10;
        let container_b: u64 = 20;

        let mut table = PendingQueryTable::new();
        table.record_query(0xAAAA, 1234, container_a, 0);
        table.record_query(0xAAAA, 1234, container_b, 1);

        assert_eq!(table.len(), 2, "both containers' entries must coexist rather than one silently overwriting the other");
    }

    /// The release-cleanup half of the chunk #14 fix: once a container is
    /// released, its entries can no longer contribute to an ambiguity --
    /// a prior collision resolves cleanly to whichever container remains.
    #[test]
    fn removing_a_released_container_resolves_a_prior_ambiguity_to_the_remaining_container() {
        let container_a: u64 = 111;
        let container_b: u64 = 222;

        let mut table = PendingQueryTable::new();
        table.record_query(0x9999, 7777, container_a, 0);
        table.record_query(0x9999, 7777, container_b, 1);
        assert_eq!(table.correlate(0x9999, 7777, 2), Correlation::Ambiguous);

        // Container A is released (its cgroup is torn down / no longer
        // observed) -- `daemon::apply::apply_release` calls exactly this.
        table.remove_container(container_a);

        assert_eq!(table.correlate(0x9999, 7777, 3).resolved(), Some(container_b), "with the stale/departed container's entry gone, correlation must recover cleanly");
    }

    /// `remove_container` must not disturb an unrelated key/container.
    #[test]
    fn remove_container_only_removes_that_containers_own_entries() {
        let mut table = PendingQueryTable::new();
        table.record_query(0x1, 1, 100, 0);
        table.record_query(0x2, 2, 200, 0);

        table.remove_container(100);

        assert_eq!(table.correlate(0x1, 1, 1), Correlation::Miss);
        assert_eq!(table.correlate(0x2, 2, 1).resolved(), Some(200), "an unrelated container's entry must survive");
    }
}
