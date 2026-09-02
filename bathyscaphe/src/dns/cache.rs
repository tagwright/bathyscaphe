// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 techgaud
//! The per-container `dst IP -> {domain, confidence}` cache built from
//! snooped DNS answers ([`super::parse::parse_dns_response`]), read by
//! [`crate::pipeline::map`] to enrich `connect` events with `domain.*`
//! (`docs/PROTOCOL.md` section 3).
//!
//! ## The seam chunk #10 (FQDN enforcement) plugs into
//!
//! This cache is deliberately not `enforce_fqdn`-aware: it exists purely
//! for enrichment in this chunk, but its shape is exactly what name-rule
//! enforcement needs too, and is meant to be read (not rebuilt) by that
//! later layer:
//!
//! - **The insertion path** ([`DomainCache::record`]) is where chunk #10
//!   registers interest: once a container has a `type: "name"` rule
//!   compiled (`docs/PROTOCOL.md` section 4), that chunk's directive
//!   compilation should keep the container's set of enforceable name
//!   patterns (exact names and `*.wildcard`s) alongside the existing
//!   `DaemonState::ContainerState`, and on every `record()` call check
//!   whether `domain` matches one of that container's patterns.
//! - **On a match**, chunk #10 inserts `addr` into the `POLICY` `LpmTrie`
//!   (`bathyscaphe_common::policy`, via `probe::policy::PolicyStore::set_policy`)
//!   as a host-route entry (`prefix_bits_over_addr = 128`) carrying
//!   `source: RuleSource::Dns` and `expires_at_ns` derived from the SAME
//!   `ttl_secs`/`now_boottime_ns` this cache already computes
//!   `expires_at_ns` from (see [`CacheEntry::expires_at_ns`]) -- the two
//!   expiries should be the identical absolute instant, not independently
//!   recomputed, so the enrichment cache and the enforcement allow-map
//!   never disagree about when an answer goes stale.
//! - **This module never touches `POLICY` itself** (no `ProbeApi`
//!   dependency, no ties to `probe::policy`) -- it is pure, kernel-free
//!   userspace state, precisely so chunk #10 can read from it (or fold its
//!   `record()` call site into its own directly, whichever proves
//!   cleaner) without this chunk needing to anticipate enforcement's exact
//!   shape. [`DomainCache::lookup`] and [`DomainCache::record`] are the
//!   whole public surface a consumer needs.
//!
//! ## Confidence rule
//!
//! A hit within its answer's own TTL window is [`bathyscaphe_proto::DomainConfidence::Asserted`]
//! (a fresh, direct DNS answer). A hit PAST its TTL but still within
//! [`STALE_GRACE_NS`] is [`bathyscaphe_proto::DomainConfidence::Inferred`]
//! (stale: the container may still be using a connection opened before the
//! answer expired, or may be relying on a longer-lived resolver-side
//! cache this process never directly observed re-querying). Past the
//! grace window, a lookup returns `None` -- identical, from the caller's
//! perspective, to a cache miss (`docs/DNS.md`'s "why `domain` is null"
//! list does not distinguish the two).
//!
//! ## Trust flooring (build chunk #11)
//!
//! [`DomainCache::record`] takes a `trusted` bit (from
//! `crate::dns::AttributedAnswer::trusted`, ultimately
//! `crate::dns::trust::TrustedResolvers::is_trusted` on the answer's own
//! captured source address). An answer from an UNTRUSTED source is still
//! recorded here -- this cache exists purely for display/enrichment, a
//! materially lower-stakes consumer than `POLICY` enforcement
//! (`daemon::fqdn::on_dns_answer` gates enforcement on trust directly and
//! never even calls into this module for an untrusted answer's
//! insertion) -- but its confidence is FLOORED at
//! [`bathyscaphe_proto::DomainConfidence::Inferred`] regardless of how
//! fresh the answer's own TTL says it is, so an untrusted-sourced
//! `domain.name` on a wire event never silently reads as
//! [`bathyscaphe_proto::DomainConfidence::Asserted`] -- the wire's
//! strongest confidence value is reserved for answers this build actually
//! trusts. See `docs/DNS.md`'s "enforcement versus enrichment trust"
//! section for why this cache still records an untrusted answer at all
//! rather than discarding it outright: a possibly-spoofed `domain.name` on
//! an event, clearly marked `Inferred`, is still more useful to an
//! operator reading `bilgeline` logs than a null one, and enrichment never
//! gates a verdict the way `POLICY` does.

use std::collections::HashMap;
use std::net::IpAddr;

use bathyscaphe_proto::DomainConfidence;

/// How long, past a record's own TTL, a stale entry is still returned (as
/// [`bathyscaphe_proto::DomainConfidence::Inferred`]) before being reaped
/// outright. Mirrors Cilium's `--tofqdns-idle-connection-grace-period`
/// reasoning (`prior_art_fqdn.md`): a container's OS-level connection can
/// keep using an address after its DNS answer's TTL has technically
/// elapsed without necessarily re-resolving, so treating "just past TTL"
/// as "wrong" rather than "less certain" discards real information. A
/// fixed constant (not yet operator-configurable) is a deliberate v1
/// scope choice -- see `docs/DNS.md`.
pub const STALE_GRACE_NS: u64 = 15 * 60 * 1_000_000_000;

/// Computes the absolute `CLOCK_BOOTTIME` instant a DNS answer's TTL
/// elapses, from the same `(ttl_secs, now_boottime_ns)` pair every caller
/// that needs an answer's expiry receives. Factored out of
/// [`DomainCache::record`] so build chunk #10's FQDN enforcement layer
/// (`daemon::fqdn::on_dns_answer`) computes the EXACT SAME absolute instant
/// for a `POLICY` host-route's `expires_at_ns` as this cache computes for
/// its own enrichment entry -- per `docs/DNS.md`'s plugging-in note, the
/// enrichment cache and the enforcement allow-map must agree on one
/// expiry, never derive it twice and risk drift.
pub fn expiry_ns(now_boottime_ns: u64, ttl_secs: u32) -> u64 {
    now_boottime_ns.saturating_add(u64::from(ttl_secs).saturating_mul(1_000_000_000))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CacheEntry {
    domain: String,
    /// Absolute `CLOCK_BOOTTIME` instant the DNS answer's own TTL elapses.
    expires_at_ns: u64,
    /// `expires_at_ns + STALE_GRACE_NS`: past this, [`DomainCache::lookup`]
    /// treats the entry as gone and [`DomainCache::record`]'s
    /// opportunistic sweep (see that method's doc) removes it.
    purge_at_ns: u64,
    /// Build chunk #11: whether this answer arrived from a trusted
    /// resolver. `false` floors [`DomainCache::lookup`]'s confidence at
    /// [`DomainConfidence::Inferred`] regardless of TTL freshness -- see
    /// this module's "Trust flooring" doc section.
    trusted: bool,
}

/// One successful [`DomainCache::lookup`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainHit {
    pub name: String,
    pub confidence: DomainConfidence,
}

/// Per-container `dst IP -> CacheEntry`. No internal locking -- shared
/// across threads the same way `probe::tamper::TamperStore` is (an
/// external `Arc<Mutex<DomainCache>>`, via the
/// `pipeline::sink::DomainLookupSource` blanket impl for that wrapper),
/// keeping this type itself trivially unit-testable with no lock in
/// sight.
#[derive(Default)]
pub struct DomainCache {
    by_container: HashMap<u64, HashMap<IpAddr, CacheEntry>>,
}

impl DomainCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Records that `addr` resolved to `domain` for `cgroup_id`, valid for
    /// `ttl_secs` seconds from `now_boottime_ns`. Overwrites any prior
    /// mapping for the same `(cgroup_id, addr)` -- the most recently
    /// observed answer wins, matching every DNS-snooping prior-art tool
    /// surveyed in `prior_art_fqdn.md`. `trusted` (build chunk #11, see
    /// this module's "Trust flooring" doc section) is carried onto the
    /// stored entry and consulted only at lookup time.
    ///
    /// Also opportunistically sweeps this SAME container's entries that
    /// are past their grace window (see [`STALE_GRACE_NS`]) on every call
    /// -- a container that keeps resolving names bounds its own cache
    /// size for free, at the cost of a container that stops resolving
    /// (and also stops connecting, so nothing else ever reads its cache
    /// either) leaking a bounded, per-container amount of state until
    /// process restart or an explicit `release`. There is no separate
    /// background reap thread in this chunk; `docs/DNS.md` documents this
    /// as an accepted v1 gap, not a silent unbounded leak (the leak is
    /// bounded by "however many distinct addresses this one container
    /// ever resolved," not host-wide).
    pub fn record(&mut self, cgroup_id: u64, domain: String, addr: IpAddr, ttl_secs: u32, now_boottime_ns: u64, trusted: bool) {
        let expires_at_ns = expiry_ns(now_boottime_ns, ttl_secs);
        let purge_at_ns = expires_at_ns.saturating_add(STALE_GRACE_NS);
        let container = self.by_container.entry(cgroup_id).or_default();
        container.insert(addr, CacheEntry { domain, expires_at_ns, purge_at_ns, trusted });
        container.retain(|_, entry| entry.purge_at_ns > now_boottime_ns);
    }

    /// Looks up `addr` for `cgroup_id` at `now_boottime_ns` -- the
    /// CALLER's choice of "now". [`crate::pipeline::map::map_event`]
    /// deliberately passes the connect event's own `ktime_ns` rather than
    /// a freshly sampled clock reading, so enrichment reflects whether the
    /// DNS answer was still fresh AT THE MOMENT of that specific
    /// connection, not at whatever moment this function happens to run.
    ///
    /// `None` on a miss, or on an entry past [`STALE_GRACE_NS`] -- see
    /// this module's doc on why the two are indistinguishable to callers.
    /// An entry recorded as untrusted (build chunk #11) never returns
    /// [`DomainConfidence::Asserted`], regardless of TTL freshness -- see
    /// this module's "Trust flooring" doc section.
    pub fn lookup(&self, cgroup_id: u64, addr: IpAddr, now_boottime_ns: u64) -> Option<DomainHit> {
        let entry = self.by_container.get(&cgroup_id)?.get(&addr)?;
        if now_boottime_ns >= entry.purge_at_ns {
            return None;
        }
        let confidence = if entry.trusted && now_boottime_ns < entry.expires_at_ns { DomainConfidence::Asserted } else { DomainConfidence::Inferred };
        Some(DomainHit { name: entry.domain.clone(), confidence })
    }

    #[cfg(test)]
    fn container_entry_count(&self, cgroup_id: u64) -> usize {
        self.by_container.get(&cgroup_id).map(HashMap::len).unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr() -> IpAddr {
        IpAddr::from([93, 184, 216, 34])
    }

    #[test]
    fn a_miss_on_an_unknown_container_or_address_is_none() {
        let cache = DomainCache::new();
        assert_eq!(cache.lookup(1, addr(), 0), None);
    }

    #[test]
    fn a_fresh_record_is_asserted() {
        let mut cache = DomainCache::new();
        cache.record(1, "example.com".to_string(), addr(), 300, 1_000_000_000, true);
        let hit = cache.lookup(1, addr(), 1_000_000_000).expect("just-recorded entry should hit");
        assert_eq!(hit.name, "example.com");
        assert_eq!(hit.confidence, DomainConfidence::Asserted);
    }

    #[test]
    fn a_lookup_still_within_ttl_stays_asserted() {
        let mut cache = DomainCache::new();
        let now = 1_000_000_000u64;
        cache.record(1, "example.com".to_string(), addr(), 300, now, true);
        let almost_expired = now + 299 * 1_000_000_000;
        let hit = cache.lookup(1, addr(), almost_expired).unwrap();
        assert_eq!(hit.confidence, DomainConfidence::Asserted);
    }

    #[test]
    fn a_lookup_past_ttl_but_within_grace_is_inferred() {
        let mut cache = DomainCache::new();
        let now = 1_000_000_000u64;
        cache.record(1, "example.com".to_string(), addr(), 300, now, true);
        let just_past_ttl = now + 300 * 1_000_000_000 + 1;
        let hit = cache.lookup(1, addr(), just_past_ttl).expect("just past TTL should still hit, as Inferred");
        assert_eq!(hit.confidence, DomainConfidence::Inferred);
    }

    #[test]
    fn a_lookup_past_the_grace_window_is_none() {
        let mut cache = DomainCache::new();
        let now = 1_000_000_000u64;
        cache.record(1, "example.com".to_string(), addr(), 300, now, true);
        let expires_at = now + 300 * 1_000_000_000;
        let past_grace = expires_at + STALE_GRACE_NS + 1;
        assert_eq!(cache.lookup(1, addr(), past_grace), None);
    }

    #[test]
    fn a_different_container_never_sees_another_containers_entry() {
        let mut cache = DomainCache::new();
        cache.record(1, "example.com".to_string(), addr(), 300, 0, true);
        assert_eq!(cache.lookup(2, addr(), 0), None);
    }

    #[test]
    fn recording_again_for_the_same_key_overwrites_the_prior_answer() {
        let mut cache = DomainCache::new();
        cache.record(1, "old.example.com".to_string(), addr(), 300, 0, true);
        cache.record(1, "new.example.com".to_string(), addr(), 300, 0, true);
        let hit = cache.lookup(1, addr(), 0).unwrap();
        assert_eq!(hit.name, "new.example.com");
    }

    #[test]
    fn record_opportunistically_sweeps_this_containers_own_entries_past_grace() {
        let mut cache = DomainCache::new();
        let short_lived = IpAddr::from([10, 0, 0, 1]);
        cache.record(1, "short.example.com".to_string(), short_lived, 1, 0, true);
        assert_eq!(cache.container_entry_count(1), 1);

        // Far past that first entry's grace window; recording a second,
        // unrelated address for the SAME container should sweep it.
        let long_after = 1 * 1_000_000_000 + STALE_GRACE_NS + 1;
        cache.record(1, "other.example.com".to_string(), addr(), 300, long_after, true);

        assert_eq!(cache.container_entry_count(1), 1, "the expired-past-grace entry should have been swept");
        assert_eq!(cache.lookup(1, short_lived, long_after), None);
        assert!(cache.lookup(1, addr(), long_after).is_some());
    }

    #[test]
    fn an_untrusted_fresh_record_is_inferred_not_asserted() {
        // Build chunk #11: even a perfectly fresh, well-within-TTL answer
        // must never read as Asserted when it came from an untrusted
        // source -- see this module's "Trust flooring" doc section.
        let mut cache = DomainCache::new();
        cache.record(1, "example.com".to_string(), addr(), 300, 1_000_000_000, false);
        let hit = cache.lookup(1, addr(), 1_000_000_000).expect("an untrusted answer is still recorded for enrichment");
        assert_eq!(hit.confidence, DomainConfidence::Inferred);
    }

    #[test]
    fn an_untrusted_record_past_ttl_is_still_just_inferred() {
        let mut cache = DomainCache::new();
        let now = 1_000_000_000u64;
        cache.record(1, "example.com".to_string(), addr(), 300, now, false);
        let just_past_ttl = now + 300 * 1_000_000_000 + 1;
        let hit = cache.lookup(1, addr(), just_past_ttl).expect("still within the grace window");
        assert_eq!(hit.confidence, DomainConfidence::Inferred);
    }

    #[test]
    fn an_untrusted_record_still_expires_past_the_grace_window() {
        // Trust flooring only ever LOWERS confidence -- it must not exempt
        // an untrusted entry from the same purge/grace lifecycle every
        // other entry follows.
        let mut cache = DomainCache::new();
        let now = 1_000_000_000u64;
        cache.record(1, "example.com".to_string(), addr(), 300, now, false);
        let expires_at = now + 300 * 1_000_000_000;
        let past_grace = expires_at + STALE_GRACE_NS + 1;
        assert_eq!(cache.lookup(1, addr(), past_grace), None);
    }

    #[test]
    fn overwriting_a_trusted_record_with_an_untrusted_one_drops_the_confidence() {
        let mut cache = DomainCache::new();
        cache.record(1, "example.com".to_string(), addr(), 300, 0, true);
        assert_eq!(cache.lookup(1, addr(), 0).unwrap().confidence, DomainConfidence::Asserted);

        cache.record(1, "example.com".to_string(), addr(), 300, 0, false);
        assert_eq!(cache.lookup(1, addr(), 0).unwrap().confidence, DomainConfidence::Inferred, "the most recently observed answer's own trust must win, exactly like its name/TTL already do");
    }
}
