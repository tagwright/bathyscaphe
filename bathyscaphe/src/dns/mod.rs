// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 techgaud
//! The DNS observation domain layer (build chunk #9): parsing captured raw
//! DNS response payloads and the per-container IP->domain cache that
//! feeds today's event enrichment ([`crate::pipeline::map`]) and will feed
//! chunk #10's FQDN-rule enforcement tomorrow. See `docs/DNS.md` for the
//! full, honest account of what this observes and what it structurally
//! cannot (DoH/DoT/ECH, TCP-DNS, spoofing).
//!
//! - [`parse`]: pure, no-map, no-clock DNS message parsing
//!   ([`parse::parse_dns_response`]) using the `simple-dns` crate. See that
//!   module's doc for why this crate was chosen over `hickory-proto` and
//!   `dns-parser`.
//! - [`cache`]: [`cache::DomainCache`], the per-container `dst IP -> {name,
//!   confidence}` store the parser feeds and [`crate::pipeline::map`]
//!   reads.
//! - [`pending`]: [`pending::PendingQueryTable`], build chunk #10's
//!   query/response correlation table -- see that module's doc for the
//!   full attribution-fix design.
//! - [`patterns`]: [`patterns::NamePatternStore`], build chunk #10's
//!   per-container FQDN name-rule pattern registry and wildcard matching.
//! - [`trust`]: [`trust::TrustedResolvers`], build chunk #11's
//!   operator-configured trusted-resolver allowlist -- see that module's
//!   doc for the spoofing gap it closes and the default set it builds.

pub mod cache;
pub mod parse;
pub mod patterns;
pub mod pending;
pub mod trust;

use std::net::{IpAddr, Ipv6Addr};
use std::sync::{Arc, Mutex};

use bathyscaphe_common::{DnsCapture, DnsQueryCapture};

pub use cache::{DomainCache, DomainHit, STALE_GRACE_NS};
pub use parse::{ParsedDnsResponse, parse_dns_response};
pub use patterns::{NamePattern, NamePatternStore};
pub use pending::{Correlation, PendingQueryTable};
pub use trust::{TrustedResolvers, parse_resolv_conf_nameservers};

/// The minimum boottime-nanosecond gap between two `Correlation::Ambiguous`
/// stderr diagnostics -- a low-rate, always-on log line (not gated by the
/// R1 security-record token bucket, since this is an operational
/// diagnostic about the DNS layer's own confidence, not a security-relevant
/// event about a container's traffic; see `dns::pending`'s module doc,
/// "The fix actually applied"). Keyed off `ktime_ns` (the same
/// `CLOCK_BOOTTIME` every capture already carries) rather than a wall-clock
/// read, so this needs no extra syscall on the hot path.
const AMBIGUOUS_LOG_MIN_INTERVAL_NS: u64 = 5 * 1_000_000_000;

/// Emits a throttled stderr line the first time (and no more than once per
/// [`AMBIGUOUS_LOG_MIN_INTERVAL_NS`] thereafter) a genuine cross-container
/// `(txid, port)` collision is detected. Never parsed (per
/// `bathy_build_spec.md`'s FROZEN PROTOCOL: "human logs on stderr, never
/// parsed"), so this stays a plain line rather than the OTel-aligned
/// `security` record shape `daemon::security` builds -- there is no single
/// container to attribute an ambiguous answer TO, which is the entire
/// point of the condition being reported.
fn log_ambiguous_correlation(last_logged_ns: &std::sync::atomic::AtomicU64, now_ns: u64, txid: u16, port: u16) {
    use std::sync::atomic::Ordering;
    let last = last_logged_ns.load(Ordering::Relaxed);
    if now_ns.saturating_sub(last) < AMBIGUOUS_LOG_MIN_INTERVAL_NS {
        return;
    }
    if last_logged_ns.compare_exchange(last, now_ns, Ordering::Relaxed, Ordering::Relaxed).is_ok() {
        eprintln!(
            "bathyscaphe: DNS query/response correlation ambiguous for txid={txid:#06x} port={port} \
             (two different containers' queries collided at the same key) -- this answer was not \
             attributed to any specific container's policy; see docs/DNS.md's build chunk #14 account"
        );
    }
}

/// Unmaps a captured RFC 4291 address back to an [`IpAddr`]: an
/// IPv4-mapped-into-IPv6 address recovers its original [`IpAddr::V4`]
/// form, anything else stays [`IpAddr::V6`]. Duplicated (rather than
/// depended on) from `probe::policy`'s equivalent -- this module
/// deliberately carries no dependency on `probe`, the same boundary
/// `daemon::compile`'s own private `unmap_addr` keeps for the same reason
/// (its own doc comment explains: kernel-touching-adjacent code stays out
/// of a module meant to stay kernel-free and independently testable).
fn unmap_addr(bytes: [u8; 16]) -> IpAddr {
    let v6 = Ipv6Addr::from(bytes);
    v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(IpAddr::V6(v6))
}

/// One correctly-attributed (or, on `correlated: false`, best-effort)
/// resolved DNS answer, handed from [`capture_callback`]'s cache-recording
/// path to a daemon-supplied hook so build chunk #10's FQDN enforcement
/// (`daemon::fqdn::on_dns_answer`) can act on it without this module
/// needing to depend on `probe`/`daemon` at all -- see `capture_callback`'s
/// doc for the layering this exists to preserve.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttributedAnswer {
    /// The CORRECT querying container's cgroup id: either recovered by
    /// query/response correlation, or (on `correlated: false`) the
    /// response hook's own possibly-wrong attribution, used as the
    /// documented fallback.
    pub cgroup_id: u64,
    /// The originally queried name (see
    /// [`parse::parse_dns_response`]'s doc on CNAME chains).
    pub name: String,
    pub addr: IpAddr,
    pub ttl_secs: u32,
    /// `bpf_ktime_get_boot_ns()` at the moment the response was captured --
    /// the same instant [`cache::expiry_ns`] and
    /// `daemon::fqdn::on_dns_answer`'s `POLICY` insertion must agree on.
    pub ktime_ns: u64,
    /// Whether [`pending::PendingQueryTable::correlate`] found a matching
    /// query (`true`), or this is the uncorrelated fallback using the
    /// response hook's own `cgroup_id` (`false`) -- see this module's doc
    /// and `docs/DNS.md`'s residual-limitations list for what a caller
    /// should do differently in the `false` case (nothing is REQUIRED to
    /// differ -- the whole cache/enforcement pipeline still functions --
    /// but a caller wanting to log/report confidence has the signal here).
    pub correlated: bool,
    /// Build chunk #11: the response's own captured SOURCE address
    /// (`bathyscaphe_common::DnsCapture::src_addr`, unmapped back to an
    /// [`IpAddr`]). Unlike [`Self::correlated`], this is never wrong for
    /// an injected/synthesized reply -- see that field's doc on
    /// `DnsCapture`.
    pub src_addr: IpAddr,
    /// Build chunk #11: whether [`Self::src_addr`] is in the
    /// operator-configured [`trust::TrustedResolvers`] set passed to
    /// [`capture_callback`]. `daemon::fqdn::on_dns_answer` (Part A's
    /// enforcement gate) only seeds `POLICY` from an answer where this is
    /// `true` -- see `trust`'s module doc for the full trust model and
    /// `docs/DNS.md` for how enrichment (`DomainCache`) is allowed to
    /// treat an untrusted answer differently (recorded, but never as
    /// `Asserted` confidence).
    pub trusted: bool,
}

/// Extracts a DNS message's transaction id: the first two bytes, per RFC
/// 1035 section 4.1.1. `None` if `bytes` is too short to carry one at all
/// (an even-more-truncated capture than `parse_dns_response` itself would
/// tolerate) -- treated as "nothing to correlate on," not an error.
fn extract_txid(bytes: &[u8]) -> Option<u16> {
    let txid_bytes: [u8; 2] = bytes.get(0..2)?.try_into().ok()?;
    Some(u16::from_be_bytes(txid_bytes))
}

/// Builds the `DNS_EVENTS` ring-buffer callback shared by both
/// `daemon::Daemon::run` and the standalone `observe` CLI: parse the
/// captured payload, correlate its attribution via `pending` (build chunk
/// #10 -- see [`pending::PendingQueryTable`]'s module doc), record every
/// resolved answer into `cache` under the CORRECTED `cgroup_id`, and invoke
/// `on_answer` once per resolved answer so a daemon-supplied hook can act
/// on it (FQDN enforcement's `POLICY` insertion) without this module
/// depending on `probe`/`daemon`. A capture that fails to parse as DNS, or
/// parses but carries no A/AAAA answers, is silently not recorded or
/// forwarded -- see [`parse::parse_dns_response`]'s doc and `docs/DNS.md`'s
/// "why domain is null" list for why that is the expected, correct
/// behavior for a meaningful fraction of captured datagrams.
///
/// Returns the exact `Box<dyn FnMut(DnsCapture) + Send + 'static>` shape
/// `probe::dns::DnsCaptureConsumer::spawn` (aliased there as
/// `probe::DnsCallback`) expects.
///
/// `trusted_resolvers` (build chunk #11) gates nothing in THIS function --
/// every parsed answer is still recorded into `cache` (enrichment) and
/// still forwarded to `on_answer` (enforcement) regardless of trust. What
/// changes is the `trusted` bit each of those two paths receives:
/// [`cache::DomainCache::record`] uses it to floor a matching answer's
/// confidence at [`bathyscaphe_proto::DomainConfidence::Inferred`]
/// (`docs/DNS.md`'s enrichment-vs-enforcement trust section), and
/// [`AttributedAnswer::trusted`] is what `daemon::fqdn::on_dns_answer`
/// (Part A's actual enforcement gate) checks before ever calling
/// `ProbeApi::set_policy`. Keeping the gate itself out of this function
/// means every consumer sees the SAME trust signal and decides for itself
/// how much to weight it, rather than this shared plumbing baking in one
/// consumer's policy.
pub fn capture_callback(
    cache: Arc<Mutex<DomainCache>>,
    pending: Arc<Mutex<PendingQueryTable>>,
    trusted_resolvers: Arc<TrustedResolvers>,
    mut on_answer: impl FnMut(AttributedAnswer) + Send + 'static,
) -> Box<dyn FnMut(DnsCapture) + Send + 'static> {
    let last_ambiguous_log_ns = std::sync::atomic::AtomicU64::new(0);
    Box::new(move |capture: DnsCapture| {
        let Some(parsed) = parse::parse_dns_response(capture.captured()) else {
            return;
        };

        let (cgroup_id, correlated) = match extract_txid(capture.captured()) {
            Some(txid) => {
                let mut pending = pending.lock().unwrap_or_else(|poison| poison.into_inner());
                match pending.correlate(txid, capture.dst_port, capture.ktime_ns) {
                    Correlation::Resolved(correct_cgroup_id) => (correct_cgroup_id, true),
                    Correlation::Ambiguous => {
                        log_ambiguous_correlation(&last_ambiguous_log_ns, capture.ktime_ns, txid, capture.dst_port);
                        (capture.cgroup_id, false)
                    }
                    Correlation::Miss => (capture.cgroup_id, false),
                }
            }
            None => (capture.cgroup_id, false),
        };

        let src_addr = unmap_addr(capture.src_addr);
        let trusted = trusted_resolvers.is_trusted(src_addr);

        {
            let mut cache = cache.lock().unwrap_or_else(|poison| poison.into_inner());
            for (addr, ttl_secs) in &parsed.answers {
                cache.record(cgroup_id, parsed.name.clone(), *addr, *ttl_secs, capture.ktime_ns, trusted);
            }
        }

        for (addr, ttl_secs) in parsed.answers {
            on_answer(AttributedAnswer { cgroup_id, name: parsed.name.clone(), addr, ttl_secs, ktime_ns: capture.ktime_ns, correlated, src_addr, trusted });
        }
    })
}

/// Builds the `DNS_QUERIES` ring-buffer callback: every captured query
/// simply feeds [`pending::PendingQueryTable::record_query`], so a later
/// response can correlate against it. Returns the exact
/// `Box<dyn FnMut(DnsQueryCapture) + Send + 'static>` shape
/// `probe::dns_query::DnsQueryCaptureConsumer::spawn` (aliased there as
/// `probe::DnsQueryCallback`) expects.
pub fn query_capture_callback(pending: Arc<Mutex<PendingQueryTable>>) -> Box<dyn FnMut(DnsQueryCapture) + Send + 'static> {
    Box::new(move |capture: DnsQueryCapture| {
        let mut pending = pending.lock().unwrap_or_else(|poison| poison.into_inner());
        pending.record_query(capture.txid, capture.src_port, capture.cgroup_id, capture.ktime_ns);
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_txid_reads_the_first_two_bytes_big_endian() {
        assert_eq!(extract_txid(&[0x12, 0x34, 0x00, 0x00]), Some(0x1234));
    }

    #[test]
    fn extract_txid_on_too_short_input_is_none() {
        assert_eq!(extract_txid(&[0x12]), None);
        assert_eq!(extract_txid(&[]), None);
    }

    /// Embeds an [`IpAddr`] into the RFC 4291 form `DnsCapture::src_addr`
    /// expects. Test-only counterpart to production's `unmap_addr` --
    /// duplicated rather than shared for the same "no probe dependency"
    /// boundary reason `unmap_addr`'s own doc gives.
    fn embed_addr(addr: IpAddr) -> [u8; 16] {
        match addr {
            IpAddr::V4(v4) => {
                let mut bytes = [0u8; 16];
                bytes[10] = 0xff;
                bytes[11] = 0xff;
                bytes[12..16].copy_from_slice(&v4.octets());
                bytes
            }
            IpAddr::V6(v6) => v6.octets(),
        }
    }

    fn trusted_set(addr: IpAddr) -> Arc<TrustedResolvers> {
        Arc::new(TrustedResolvers::new([addr]))
    }

    #[test]
    fn capture_callback_uses_the_correlated_cgroup_id_over_the_captures_own() {
        let cache = Arc::new(Mutex::new(DomainCache::new()));
        let pending = Arc::new(Mutex::new(PendingQueryTable::new()));
        // The container's own query fires first (as it always does in
        // reality), recording the CORRECT cgroup id under (txid, src_port).
        pending.lock().unwrap().record_query(0xBEEF, 44321, /*correct*/ 100, 1_000_000_000);

        let resolver_addr = IpAddr::from([127, 0, 0, 11]);
        let answers = Arc::new(Mutex::new(Vec::new()));
        let answers_clone = Arc::clone(&answers);
        let mut callback = capture_callback(Arc::clone(&cache), Arc::clone(&pending), trusted_set(resolver_addr), move |answer| {
            answers_clone.lock().unwrap().push(answer);
        });

        // Build a real DNS response payload (txid 0xBEEF) whose OWN
        // capture cgroup_id is deliberately the WRONG one (simulating
        // docker.service's), arriving on dst_port 44321 (the query's own
        // src_port), from the trusted resolver address.
        let payload = build_a_response(0xBEEF, "example.com.", 300, [93, 184, 216, 34]);
        let mut capture = DnsCapture::zeroed_for(/*wrong*/ 999, 1_000_000_500);
        capture.dst_port = 44321;
        capture.src_addr = embed_addr(resolver_addr);
        capture.payload[..payload.len()].copy_from_slice(&payload);
        capture.len = payload.len() as u16;

        callback(capture);

        let recorded = answers.lock().unwrap();
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0].cgroup_id, 100, "the correlated (correct) cgroup id must win over the capture's own (wrong) one");
        assert!(recorded[0].correlated);
        assert_eq!(recorded[0].name, "example.com");
        assert_eq!(recorded[0].src_addr, resolver_addr);
        assert!(recorded[0].trusted, "the resolver address is in the trusted set");

        // The cache itself must also be keyed under the CORRECTED cgroup
        // id, not the response's own.
        let cache = cache.lock().unwrap();
        assert!(cache.lookup(100, std::net::IpAddr::from([93, 184, 216, 34]), 1_000_000_500).is_some());
        assert!(cache.lookup(999, std::net::IpAddr::from([93, 184, 216, 34]), 1_000_000_500).is_none());
    }

    #[test]
    fn capture_callback_falls_back_to_the_captures_own_cgroup_id_when_uncorrelatable() {
        let cache = Arc::new(Mutex::new(DomainCache::new()));
        let pending = Arc::new(Mutex::new(PendingQueryTable::new()));
        let answers = Arc::new(Mutex::new(Vec::new()));
        let answers_clone = Arc::clone(&answers);
        let mut callback = capture_callback(cache, pending, trusted_set(IpAddr::from([8, 8, 8, 8])), move |answer| answers_clone.lock().unwrap().push(answer));

        let payload = build_a_response(0x0001, "example.com.", 60, [1, 2, 3, 4]);
        let mut capture = DnsCapture::zeroed_for(777, 0);
        capture.dst_port = 12345; // no query was ever recorded for this key
        capture.payload[..payload.len()].copy_from_slice(&payload);
        capture.len = payload.len() as u16;

        callback(capture);

        let recorded = answers.lock().unwrap();
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0].cgroup_id, 777, "an uncorrelatable response falls back to its own capture's cgroup_id");
        assert!(!recorded[0].correlated);
    }

    #[test]
    fn capture_callback_marks_an_answer_from_an_untrusted_source_as_untrusted() {
        let cache = Arc::new(Mutex::new(DomainCache::new()));
        let pending = Arc::new(Mutex::new(PendingQueryTable::new()));
        let answers = Arc::new(Mutex::new(Vec::new()));
        let answers_clone = Arc::clone(&answers);
        // Trusted set contains a DIFFERENT address than the one the
        // response will actually arrive from.
        let mut callback = capture_callback(Arc::clone(&cache), pending, trusted_set(IpAddr::from([127, 0, 0, 11])), move |answer| answers_clone.lock().unwrap().push(answer));

        let untrusted_source = IpAddr::from([203, 0, 113, 53]);
        let payload = build_a_response(0x0002, "example.com.", 60, [1, 2, 3, 4]);
        let mut capture = DnsCapture::zeroed_for(1, 0);
        capture.dst_port = 22222;
        capture.src_addr = embed_addr(untrusted_source);
        capture.payload[..payload.len()].copy_from_slice(&payload);
        capture.len = payload.len() as u16;

        callback(capture);

        let recorded = answers.lock().unwrap();
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0].src_addr, untrusted_source);
        assert!(!recorded[0].trusted, "an answer from an address outside the trusted set must be marked untrusted");

        // Enrichment still records it (per docs/DNS.md), but never as
        // Asserted -- see cache.rs's own dedicated tests for the full
        // confidence-flooring behavior; this just proves the bit reaches
        // the cache call at all.
        let cache = cache.lock().unwrap();
        let hit = cache.lookup(1, IpAddr::from([1, 2, 3, 4]), 0).expect("untrusted answers are still recorded for enrichment");
        assert_eq!(hit.confidence, bathyscaphe_proto::DomainConfidence::Inferred, "an untrusted answer is never Asserted, even when perfectly fresh");
    }

    /// Build chunk #14's end-to-end proof at the `capture_callback` layer
    /// (complementing `dns::pending`'s own table-level test): two DIFFERENT
    /// containers' queries collide on the exact same `(txid, dst_port)`
    /// key, both responses arrive carrying the SAME (wrong, injected-relay)
    /// `cgroup_id` of their own -- and neither one is EVER attributed to
    /// the OTHER container's cgroup. Each answer falls back to its own
    /// capture's cgroup_id with `correlated: false`, never cross-attributed.
    #[test]
    fn capture_callback_never_cross_attributes_a_genuine_two_container_collision() {
        let cache = Arc::new(Mutex::new(DomainCache::new()));
        let pending = Arc::new(Mutex::new(PendingQueryTable::new()));
        let resolver_addr = IpAddr::from([127, 0, 0, 11]);

        let container_a: u64 = 0xAAAA_AAAA_AAAA_AAAA;
        let container_b: u64 = 0xBBBB_BBBB_BBBB_BBBB;
        let injected_relay_cgroup_id: u64 = 0xDEC0_DE00_DEC0_DE00; // stands in for docker.service's own cgroup

        // Both containers' queries land at the identical (txid, src_port)
        // key -- a genuine collision, not a test artifact.
        pending.lock().unwrap().record_query(0x4242, 55555, container_a, 1_000_000_000);
        pending.lock().unwrap().record_query(0x4242, 55555, container_b, 1_000_000_010);

        let answers = Arc::new(Mutex::new(Vec::new()));
        let answers_clone = Arc::clone(&answers);
        let mut callback = capture_callback(cache, Arc::clone(&pending), trusted_set(resolver_addr), move |answer| {
            answers_clone.lock().unwrap().push(answer);
        });

        // Container A's OWN real answer -- domain "a.example.com" -- and
        // container B's OWN real answer -- domain "b.example.com" -- both
        // arrive with the SAME wrong (injected-relay) cgroup_id of their
        // own and the SAME colliding (txid, dst_port).
        let payload_a = build_a_response(0x4242, "a.example.com.", 300, [10, 0, 0, 1]);
        let mut capture_a = DnsCapture::zeroed_for(injected_relay_cgroup_id, 1_000_000_100);
        capture_a.dst_port = 55555;
        capture_a.src_addr = embed_addr(resolver_addr);
        capture_a.payload[..payload_a.len()].copy_from_slice(&payload_a);
        capture_a.len = payload_a.len() as u16;
        callback(capture_a);

        let payload_b = build_a_response(0x4242, "b.example.com.", 300, [10, 0, 0, 2]);
        let mut capture_b = DnsCapture::zeroed_for(injected_relay_cgroup_id, 1_000_000_200);
        capture_b.dst_port = 55555;
        capture_b.src_addr = embed_addr(resolver_addr);
        capture_b.payload[..payload_b.len()].copy_from_slice(&payload_b);
        capture_b.len = payload_b.len() as u16;
        callback(capture_b);

        let recorded = answers.lock().unwrap();
        assert_eq!(recorded.len(), 2);
        for answer in recorded.iter() {
            assert_ne!(answer.cgroup_id, container_a, "an ambiguous collision must never attribute either answer to container A");
            assert_ne!(answer.cgroup_id, container_b, "an ambiguous collision must never attribute either answer to container B");
            assert_eq!(answer.cgroup_id, injected_relay_cgroup_id, "the fail-safe fallback is the capture's own (non-container) cgroup_id");
            assert!(!answer.correlated, "an ambiguous collision must never report as a confident correlation");
        }
    }

    #[test]
    fn query_capture_callback_feeds_the_pending_table() {
        let pending = Arc::new(Mutex::new(PendingQueryTable::new()));
        let mut callback = query_capture_callback(Arc::clone(&pending));
        callback(DnsQueryCapture::new(1_000_000_000, 42, 0xABCD, 5555));

        let mut guard = pending.lock().unwrap();
        assert_eq!(guard.correlate(0xABCD, 5555, 1_000_000_100), Correlation::Resolved(42));
    }

    /// Builds a minimal, real, hand-assembled DNS A-response wire message
    /// with the given transaction id -- deliberately not going through
    /// `simple_dns`'s own `Packet` builder (that's exercised in
    /// `parse::tests`), so this fixture proves `extract_txid` reads the
    /// SAME bytes a real captured payload would carry, independent of
    /// whatever internal representation the parser crate uses.
    fn build_a_response(txid: u16, name: &str, ttl: u32, addr: [u8; 4]) -> Vec<u8> {
        let mut packet = simple_dns::Packet::new_reply(txid);
        packet.set_flags(simple_dns::PacketFlag::RESPONSE);
        packet.questions.push(simple_dns::Question::new(simple_dns::Name::new_unchecked(name).into_owned(), simple_dns::TYPE::A.into(), simple_dns::CLASS::IN.into(), false));
        packet.answers.push(simple_dns::ResourceRecord::new(
            simple_dns::Name::new_unchecked(name),
            simple_dns::CLASS::IN,
            ttl,
            simple_dns::rdata::RData::A(simple_dns::rdata::A { address: std::net::Ipv4Addr::from(addr).into() }),
        ));
        packet.build_bytes_vec().expect("test packet should always serialize")
    }
}
