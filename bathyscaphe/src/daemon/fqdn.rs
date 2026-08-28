// SPDX-License-Identifier: GPL-3.0-or-later
//! FQDN enforcement (build chunks #10-#11): the pieces that turn a
//! correctly-attributed DNS answer (`crate::dns::AttributedAnswer`) and a
//! container's registered name-rule patterns (`crate::dns::NamePatternStore`,
//! populated by `daemon::apply`) into actual kernel-enforced policy.
//!
//! - [`on_dns_answer`]: the enforcement gate. Chunk #11 added the
//!   trusted-resolver check (Part A: an untrusted-sourced answer never
//!   seeds `POLICY`, and a would-have-matched `Allow` pattern from an
//!   untrusted source fires the loud `dns.untrusted_answer` record instead)
//!   and name-based DENY enforcement (Part B: a trusted answer matching an
//!   active `Deny` pattern inserts a DENY host route, winning over any
//!   `Allow` pattern match on the same answer).
//! - [`NameUnresolvedBlockWatcher`]: an [`EventSink`] wrapper (composes
//!   with `daemon::stats::CountingSink` the same way that sink already
//!   composes with the raw stdout channel) that watches every mapped
//!   `Event` for the "denied, no domain, but this container has an active
//!   name rule" signal and fires the evolved R1 loud record
//!   (`policy.name_unresolved_block`).

use std::sync::{Arc, Mutex};

use bathyscaphe_common::{PolicyValue, PortRule, RuleAction, RuleSource};
use bathyscaphe_proto::security::SecurityContainer;
use bathyscaphe_proto::{UpMessage, Verdict};

use crate::attribution::Attributor;
use crate::dns::{AttributedAnswer, NamePattern, NamePatternStore};
use crate::pipeline::EventSink;

use super::probe_api::ProbeApi;
use super::security::{SecurityEmitter, dns_untrusted_answer_record, name_unresolved_block_record};
use super::stats::now_rfc3339;
use super::state::DaemonState;

/// The `POLICY` host route this build inserts is always a full `/128`
/// (`prefix_bits_over_addr = 128` per `probe::policy::build_policy_key`'s
/// convention) -- a single resolved address, never a wider prefix. See
/// `docs/DNS.md` for why a name rule resolves to individual answer IPs,
/// not a synthesized CIDR.
const HOST_ROUTE_PREFIX_BITS: u32 = 128;

/// Builds and inserts the `POLICY` host route for `pattern` matching
/// `answer` -- shared by both the `Allow` (chunk #10) and `Deny` (chunk
/// #11 Part B) insertion paths, since the two only differ in which
/// `RuleAction` ends up where.
///
/// `expires_at_ns` is computed from the EXACT SAME `(ttl_secs,
/// now_boottime_ns)` pair `crate::dns::cache::DomainCache::record` already
/// used for this same answer (via [`crate::dns::cache::expiry_ns`]) -- the
/// enrichment cache and the enforcement allow-map agree on one absolute
/// expiry instant, per `docs/DNS.md`'s plugging-in note. Same TTL/reaper
/// handling either way: `probe::policy::PolicyStore::reap_expired` (driven
/// by `daemon::stats::tick`) sweeps an expired DENY host route exactly like
/// an expired ALLOW one.
///
/// A pattern carrying a port/proto constraint applies that constraint to
/// the inserted host route's `PortRule`s, with the host route's own
/// `cidr_default_action` set to the INVERSE of `pattern.action`: an
/// `Allow` pattern scoped to `github.com:443/tcp` defaults every OTHER
/// port on that address to `Deny` (never opens up more than the rule
/// asked for) and grants `Allow` only for the constrained port/proto; a
/// `Deny` pattern scoped the same way defaults every other port to
/// `Allow` and denies only the constrained port/proto -- a name-based deny
/// means "block this address on this port", never "block this address
/// entirely" once a port/proto constraint is present. A pattern with no
/// port/proto constraint instead sets `cidr_default_action` directly to
/// `pattern.action` with no port rules -- the address is fully open
/// (`Allow`) or fully blocked (`Deny`), matching the rule's own
/// unconstrained intent.
fn insert_host_route(probe: &mut dyn ProbeApi, answer: &AttributedAnswer, pattern: &NamePattern) {
    let expires_at_ns = crate::dns::cache::expiry_ns(answer.ktime_ns, answer.ttl_secs);
    let action_raw = pattern.action as u8;

    let value = match (pattern.port, pattern.proto) {
        (None, None) => PolicyValue::new(action_raw, RuleSource::Dns as u8, expires_at_ns),
        (port, proto) => {
            let port_lo = port.unwrap_or(0);
            let port_hi = port.unwrap_or(u16::MAX);
            let proto_raw = proto.map(|p| PortRule::encode_proto(p as u8)).unwrap_or(PortRule::PROTO_ANY);
            let default_raw = if pattern.action == RuleAction::Allow { RuleAction::Deny as u8 } else { RuleAction::Allow as u8 };
            PolicyValue::new(default_raw, RuleSource::Dns as u8, expires_at_ns)
                .with_port_rule(PortRule::new(port_lo, port_hi, proto_raw, action_raw))
                .unwrap_or_else(|value| value) // MAX_PORT_RULES is 8; one rule never overflows a fresh value.
        }
    };

    if let Err(error) = probe.set_policy(answer.cgroup_id, answer.addr, HOST_ROUTE_PREFIX_BITS, value) {
        eprintln!(
            "bathyscaphe: FQDN POLICY insert failed for cgroup {:016x} at {}/128 (name rule {:?} action {:?} matched {:?}): {error}",
            answer.cgroup_id, answer.addr, pattern.rule_id, pattern.action, answer.name
        );
    }
}

/// The enforcement gate for a DNS answer, build chunk #11:
///
/// 1. **Trust check (Part A)**: `answer.trusted` is false when the
///    response's own captured source address
///    (`bathyscaphe_common::DnsCapture::src_addr`) is not in the
///    operator-configured `bathyscaphe::dns::trust::TrustedResolvers` set.
///    An untrusted answer NEVER seeds `POLICY` -- fail closed, not fail
///    open, per `bathy_build_spec.md`'s ratified stance. If it would have
///    matched an active `Allow` pattern anyway, that is exactly the
///    spoofing scenario worth surfacing loudly: a throttled
///    `dns.untrusted_answer` security record fires instead of any
///    insertion. A would-have-matched `Deny` pattern from an untrusted
///    source is not separately reported -- failing to enforce a deny an
///    attacker was trying to defeat by spoofing is a strictly safer
///    outcome than the allow-spoofing case, and reporting it too would
///    double the loud-record volume for a materially less urgent signal.
/// 2. **Deny wins (Part B)**: on a trusted answer, a match against an
///    active `Deny` pattern (`crate::dns::NamePatternStore::first_matching_deny`)
///    is checked BEFORE any `Allow` match and, if present, is the only
///    thing inserted -- an `Allow` pattern also matching the same answer
///    is ignored entirely, matching `docs/PROTOCOL.md`'s wire-level "deny
///    wins at equal specificity" rule extended to name rules.
/// 3. **Allow (chunk #10, unchanged)**: absent a deny match, a trusted
///    answer matching an active `Allow` pattern
///    (`crate::dns::NamePatternStore::first_matching_allow` -- only the
///    FIRST matching pattern is used, a documented v1 simplification, see
///    that method's doc) is inserted.
///
/// No-op (nothing inserted, nothing reported) when neither pattern
/// matches. `answer.correlated` is irrelevant to this decision (an
/// uncorrelated answer still gets whatever `cgroup_id`
/// `crate::dns::capture_callback` decided to use -- see that function's
/// fallback doc; this function has no additional opinion about
/// correlation confidence, only about resolver trust).
pub fn on_dns_answer(probe: &mut dyn ProbeApi, name_rules: &Mutex<NamePatternStore>, attributor: &dyn Attributor, security: &SecurityEmitter, sink: &mut dyn EventSink, answer: &AttributedAnswer) {
    let (deny_pattern, allow_pattern) = {
        let name_rules = name_rules.lock().unwrap_or_else(|poison| poison.into_inner());
        (name_rules.first_matching_deny(answer.cgroup_id, &answer.name).cloned(), name_rules.first_matching_allow(answer.cgroup_id, &answer.name).cloned())
    };

    if !answer.trusted {
        if allow_pattern.is_some() {
            let attribution = attributor.resolve(answer.cgroup_id);
            let container_id = attribution.as_ref().map(|a| a.container_id.as_str()).unwrap_or("");
            let (name, image) = attribution.as_ref().map(|a| (a.name.as_deref(), a.image.as_deref())).unwrap_or((None, None));
            let container = SecurityContainer { id: container_id, name, image };
            let record = dns_untrusted_answer_record(now_rfc3339(), container, answer.src_addr, &answer.name);
            security.try_emit(sink, record);
        }
        return;
    }

    if let Some(pattern) = deny_pattern {
        insert_host_route(probe, answer, &pattern);
        return;
    }

    if let Some(pattern) = allow_pattern {
        insert_host_route(probe, answer, &pattern);
    }
}

/// An [`EventSink`] wrapper: on every mapped `Event` that was actually
/// DENIED (`verdict: deny`) with NO domain enrichment (`domain.name` null
/// -- this build never observed a DNS answer for this destination, for
/// ANY of `docs/DNS.md`'s documented reasons) AND whose container has at
/// least one active `Allow` name pattern registered, fires the throttled
/// `policy.name_unresolved_block` loud record before forwarding the event
/// on unchanged. See `docs/DNS.md`'s residual-limitations list for the
/// honest caveat: this heuristic can also fire on an ordinary CIDR-policy
/// deny that has nothing to do with the container's name rules -- there is
/// no kernel-side signal distinguishing "denied because no name rule ever
/// resolved this IP" from "denied by an unrelated explicit deny rule",
/// short of a materially larger kernel-side change this chunk does not
/// make.
pub struct NameUnresolvedBlockWatcher<S> {
    inner: S,
    state: Arc<Mutex<DaemonState>>,
    name_rules: Arc<Mutex<NamePatternStore>>,
    security: Arc<SecurityEmitter>,
}

impl<S: EventSink> NameUnresolvedBlockWatcher<S> {
    pub fn new(inner: S, state: Arc<Mutex<DaemonState>>, name_rules: Arc<Mutex<NamePatternStore>>, security: Arc<SecurityEmitter>) -> Self {
        Self { inner, state, name_rules, security }
    }

    fn cgroup_id_for(&self, container_id: &str) -> Option<u64> {
        let state = self.state.lock().unwrap_or_else(|poison| poison.into_inner());
        state.containers.get(container_id).map(|c| c.cgroup_id)
    }

    fn has_active_allow_pattern(&self, cgroup_id: u64) -> bool {
        let name_rules = self.name_rules.lock().unwrap_or_else(|poison| poison.into_inner());
        name_rules.has_active_allow_pattern(cgroup_id)
    }
}

impl<S: EventSink> EventSink for NameUnresolvedBlockWatcher<S> {
    fn emit(&mut self, message: UpMessage) {
        if let UpMessage::Event(ref event) = message {
            if event.verdict == Verdict::Deny && event.domain.name.is_none() {
                if let Some(cgroup_id) = self.cgroup_id_for(&event.container.id) {
                    if self.has_active_allow_pattern(cgroup_id) {
                        let container = SecurityContainer { id: &event.container.id, name: event.container.name.as_deref(), image: event.container.image.as_deref() };
                        let record = name_unresolved_block_record(event.ts.clone(), container, event.dst.addr, event.dst.port);
                        self.security.try_emit(&mut self.inner, record);
                    }
                }
            }
        }
        self.inner.emit(message);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attribution::Attribution;
    use crate::daemon::probe_api::MockProbe;
    use crate::daemon::state::ContainerState;
    use crate::dns::NamePattern;
    use bathyscaphe_common::{DefaultVerdict, Mode, PolicyKeyData, TransportProto};
    use bathyscaphe_proto::{Container, Domain, Endpoint, Event as WireEvent, EventKind, EventMeta, Process, Runtime};
    use std::net::IpAddr;

    fn allow_pattern(rule_id: &str, pattern: &str, port: Option<u16>, proto: Option<TransportProto>) -> NamePattern {
        NamePattern { rule_id: rule_id.to_string(), pattern: pattern.to_string(), action: RuleAction::Allow, port, proto }
    }

    fn deny_pattern(rule_id: &str, pattern: &str, port: Option<u16>, proto: Option<TransportProto>) -> NamePattern {
        NamePattern { rule_id: rule_id.to_string(), pattern: pattern.to_string(), action: RuleAction::Deny, port, proto }
    }

    fn answer(cgroup_id: u64, name: &str, addr: IpAddr, ttl_secs: u32) -> AttributedAnswer {
        AttributedAnswer { cgroup_id, name: name.to_string(), addr, ttl_secs, ktime_ns: 1_000_000_000, correlated: true, src_addr: IpAddr::from([127, 0, 0, 11]), trusted: true }
    }

    fn untrusted_answer(cgroup_id: u64, name: &str, addr: IpAddr, ttl_secs: u32) -> AttributedAnswer {
        AttributedAnswer { trusted: false, src_addr: IpAddr::from([203, 0, 113, 53]), ..answer(cgroup_id, name, addr, ttl_secs) }
    }

    struct StubAttributor(Option<Attribution>);
    impl Attributor for StubAttributor {
        fn resolve(&self, _cgroup_id: u64) -> Option<Attribution> {
            self.0.clone()
        }
    }

    fn stub_attributor() -> StubAttributor {
        StubAttributor(Some(Attribution { container_id: "c".repeat(64), name: Some("web".to_string()), image: Some("app:1".to_string()), runtime: Runtime::Docker }))
    }

    struct CapturingSink(Vec<UpMessage>);
    impl EventSink for CapturingSink {
        fn emit(&mut self, message: UpMessage) {
            self.0.push(message);
        }
    }

    #[test]
    fn on_dns_answer_inserts_an_unconstrained_host_route_on_a_match() {
        let mut probe = MockProbe::new();
        let name_rules = Mutex::new(NamePatternStore::new());
        name_rules.lock().unwrap().set_patterns(1, vec![allow_pattern("r1", "*.github.com", None, None)]);
        let attributor = stub_attributor();
        let security = SecurityEmitter::new();
        let mut sink = CapturingSink(Vec::new());

        let addr = IpAddr::from([140, 82, 121, 4]);
        on_dns_answer(&mut probe, &name_rules, &attributor, &security, &mut sink, &answer(1, "api.github.com", addr, 300));

        let addr_bytes = crate::probe::policy::addr_to_rfc4291(addr);
        let keys = probe.tracked_policy_keys(1);
        assert!(keys.contains(&(PolicyKeyData::MIN_PREFIX_LEN + 128, addr_bytes)), "a /128 host route must be inserted");
        assert!(sink.0.is_empty(), "a trusted, successfully-enforced match reports nothing extra");
    }

    #[test]
    fn on_dns_answer_does_nothing_when_no_pattern_matches() {
        let mut probe = MockProbe::new();
        let name_rules = Mutex::new(NamePatternStore::new());
        name_rules.lock().unwrap().set_patterns(1, vec![allow_pattern("r1", "*.github.com", None, None)]);
        let attributor = stub_attributor();
        let security = SecurityEmitter::new();
        let mut sink = CapturingSink(Vec::new());

        on_dns_answer(&mut probe, &name_rules, &attributor, &security, &mut sink, &answer(1, "example.com", IpAddr::from([1, 2, 3, 4]), 300));
        assert!(probe.tracked_policy_keys(1).is_empty());
        assert!(sink.0.is_empty());
    }

    #[test]
    fn on_dns_answer_applies_the_patterns_port_and_proto_constraint() {
        let mut probe = MockProbe::new();
        let name_rules = Mutex::new(NamePatternStore::new());
        name_rules.lock().unwrap().set_patterns(1, vec![allow_pattern("r1", "github.com", Some(443), Some(TransportProto::Tcp))]);
        let attributor = stub_attributor();
        let security = SecurityEmitter::new();
        let mut sink = CapturingSink(Vec::new());

        let addr = IpAddr::from([140, 82, 121, 4]);
        on_dns_answer(&mut probe, &name_rules, &attributor, &security, &mut sink, &answer(1, "github.com", addr, 300));

        let addr_bytes = crate::probe::policy::addr_to_rfc4291(addr);
        let value = probe.policy_keys.get(&1).unwrap().get(&(PolicyKeyData::MIN_PREFIX_LEN + 128, addr_bytes)).expect("host route inserted");
        assert_eq!(value.cidr_default_action, RuleAction::Deny as u8, "everything but the constrained port/proto must fall to deny on this specific host route");
        assert_eq!(value.n_port_rules, 1);
        assert_eq!(value.port_rules[0].port_lo, 443);
        assert_eq!(value.port_rules[0].port_hi, 443);
        assert!(value.port_rules[0].matches_proto(TransportProto::Tcp as u8));
        assert!(!value.port_rules[0].matches_proto(TransportProto::Udp as u8));
    }

    #[test]
    fn on_dns_answer_expiry_matches_the_domain_caches_own_formula() {
        let mut probe = MockProbe::new();
        let name_rules = Mutex::new(NamePatternStore::new());
        name_rules.lock().unwrap().set_patterns(1, vec![allow_pattern("r1", "github.com", None, None)]);
        let attributor = stub_attributor();
        let security = SecurityEmitter::new();
        let mut sink = CapturingSink(Vec::new());

        let addr = IpAddr::from([140, 82, 121, 4]);
        let a = answer(1, "github.com", addr, 300);
        on_dns_answer(&mut probe, &name_rules, &attributor, &security, &mut sink, &a);

        let addr_bytes = crate::probe::policy::addr_to_rfc4291(addr);
        let value = probe.policy_keys.get(&1).unwrap().get(&(PolicyKeyData::MIN_PREFIX_LEN + 128, addr_bytes)).unwrap();
        assert_eq!(value.expires_at_ns, crate::dns::cache::expiry_ns(a.ktime_ns, a.ttl_secs));
    }

    #[test]
    fn on_dns_answer_inserts_a_deny_host_route_for_a_matching_deny_pattern() {
        let mut probe = MockProbe::new();
        let name_rules = Mutex::new(NamePatternStore::new());
        name_rules.lock().unwrap().set_patterns(1, vec![deny_pattern("r1", "evil.example.com", None, None)]);
        let attributor = stub_attributor();
        let security = SecurityEmitter::new();
        let mut sink = CapturingSink(Vec::new());

        let addr = IpAddr::from([198, 51, 100, 7]);
        on_dns_answer(&mut probe, &name_rules, &attributor, &security, &mut sink, &answer(1, "evil.example.com", addr, 300));

        let addr_bytes = crate::probe::policy::addr_to_rfc4291(addr);
        let value = probe.policy_keys.get(&1).unwrap().get(&(PolicyKeyData::MIN_PREFIX_LEN + 128, addr_bytes)).expect("a deny host route must be inserted");
        assert_eq!(value.cidr_default_action, RuleAction::Deny as u8);
        assert_eq!(value.n_port_rules, 0);
        assert_eq!(value.source, RuleSource::Dns as u8);
    }

    #[test]
    fn on_dns_answer_deny_pattern_with_a_port_constraint_only_denies_that_port() {
        let mut probe = MockProbe::new();
        let name_rules = Mutex::new(NamePatternStore::new());
        name_rules.lock().unwrap().set_patterns(1, vec![deny_pattern("r1", "evil.example.com", Some(443), Some(TransportProto::Tcp))]);
        let attributor = stub_attributor();
        let security = SecurityEmitter::new();
        let mut sink = CapturingSink(Vec::new());

        let addr = IpAddr::from([198, 51, 100, 7]);
        on_dns_answer(&mut probe, &name_rules, &attributor, &security, &mut sink, &answer(1, "evil.example.com", addr, 300));

        let addr_bytes = crate::probe::policy::addr_to_rfc4291(addr);
        let value = probe.policy_keys.get(&1).unwrap().get(&(PolicyKeyData::MIN_PREFIX_LEN + 128, addr_bytes)).unwrap();
        assert_eq!(value.cidr_default_action, RuleAction::Allow as u8, "a port-scoped deny must not block the whole address, only the named port");
        assert_eq!(value.n_port_rules, 1);
        assert_eq!(value.port_rules[0].port_lo, 443);
        assert!(!value.port_rules[0].matches_proto(TransportProto::Udp as u8));
    }

    #[test]
    fn on_dns_answer_deny_wins_when_the_same_answer_matches_both_an_allow_and_a_deny_pattern() {
        let mut probe = MockProbe::new();
        let name_rules = Mutex::new(NamePatternStore::new());
        name_rules.lock().unwrap().set_patterns(1, vec![allow_pattern("r-allow", "*.example.com", None, None), deny_pattern("r-deny", "evil.example.com", None, None)]);
        let attributor = stub_attributor();
        let security = SecurityEmitter::new();
        let mut sink = CapturingSink(Vec::new());

        let addr = IpAddr::from([198, 51, 100, 7]);
        on_dns_answer(&mut probe, &name_rules, &attributor, &security, &mut sink, &answer(1, "evil.example.com", addr, 300));

        let addr_bytes = crate::probe::policy::addr_to_rfc4291(addr);
        let value = probe.policy_keys.get(&1).unwrap().get(&(PolicyKeyData::MIN_PREFIX_LEN + 128, addr_bytes)).expect("exactly one host route, the deny");
        assert_eq!(value.cidr_default_action, RuleAction::Deny as u8, "deny must win over an allow pattern matching the same answer");
        assert_eq!(probe.tracked_policy_keys(1).len(), 1, "only the deny route is inserted, never a second entry for the allow");
    }

    #[test]
    fn on_dns_answer_never_seeds_policy_from_an_untrusted_answer() {
        let mut probe = MockProbe::new();
        let name_rules = Mutex::new(NamePatternStore::new());
        name_rules.lock().unwrap().set_patterns(1, vec![allow_pattern("r1", "github.com", None, None)]);
        let attributor = stub_attributor();
        let security = SecurityEmitter::new();
        let mut sink = CapturingSink(Vec::new());

        on_dns_answer(&mut probe, &name_rules, &attributor, &security, &mut sink, &untrusted_answer(1, "github.com", IpAddr::from([140, 82, 121, 4]), 300));

        assert!(probe.tracked_policy_keys(1).is_empty(), "an untrusted answer must never insert a POLICY entry, even on a matching allow pattern");
    }

    #[test]
    fn on_dns_answer_emits_a_loud_record_when_an_untrusted_answer_matches_an_active_allow_pattern() {
        let mut probe = MockProbe::new();
        let name_rules = Mutex::new(NamePatternStore::new());
        name_rules.lock().unwrap().set_patterns(1, vec![allow_pattern("r1", "github.com", None, None)]);
        let attributor = stub_attributor();
        let security = SecurityEmitter::new();
        let mut sink = CapturingSink(Vec::new());

        on_dns_answer(&mut probe, &name_rules, &attributor, &security, &mut sink, &untrusted_answer(1, "github.com", IpAddr::from([140, 82, 121, 4]), 300));

        assert_eq!(sink.0.len(), 1, "exactly one loud record, no event to forward here (this is not an EventSink pipeline stage)");
        let UpMessage::Security(record) = &sink.0[0] else { panic!("expected a security record") };
        assert_eq!(record.attributes.get("reason").unwrap(), bathyscaphe_proto::security::reason::DNS_UNTRUSTED_ANSWER);
        assert_eq!(record.attributes.get("resolver.addr").unwrap(), "203.0.113.53");
        assert_eq!(record.attributes.get("container.id").unwrap(), &"c".repeat(64));
    }

    #[test]
    fn on_dns_answer_stays_quiet_on_an_untrusted_answer_matching_no_pattern_at_all() {
        let mut probe = MockProbe::new();
        let name_rules = Mutex::new(NamePatternStore::new());
        name_rules.lock().unwrap().set_patterns(1, vec![allow_pattern("r1", "github.com", None, None)]);
        let attributor = stub_attributor();
        let security = SecurityEmitter::new();
        let mut sink = CapturingSink(Vec::new());

        on_dns_answer(&mut probe, &name_rules, &attributor, &security, &mut sink, &untrusted_answer(1, "example.com", IpAddr::from([1, 2, 3, 4]), 300));

        assert!(sink.0.is_empty(), "an untrusted answer matching no active allow pattern is not the spoofing signal -- nothing to report");
    }

    #[test]
    fn on_dns_answer_stays_quiet_on_an_untrusted_answer_matching_only_a_deny_pattern() {
        // Per this module's doc: a would-have-matched DENY from an
        // untrusted source is not separately reported -- failing to
        // enforce a deny is the safer direction, not a spoofing win.
        let mut probe = MockProbe::new();
        let name_rules = Mutex::new(NamePatternStore::new());
        name_rules.lock().unwrap().set_patterns(1, vec![deny_pattern("r1", "evil.example.com", None, None)]);
        let attributor = stub_attributor();
        let security = SecurityEmitter::new();
        let mut sink = CapturingSink(Vec::new());

        on_dns_answer(&mut probe, &name_rules, &attributor, &security, &mut sink, &untrusted_answer(1, "evil.example.com", IpAddr::from([198, 51, 100, 7]), 300));

        assert!(probe.tracked_policy_keys(1).is_empty());
        assert!(sink.0.is_empty());
    }

    fn sample_event(container_id: &str, verdict: Verdict, domain_name: Option<&str>) -> WireEvent {
        WireEvent {
            ts: "2026-08-27T00:00:00Z".to_string(),
            event: EventKind::Connect,
            proto: bathyscaphe_proto::TransportProto::Tcp,
            container: Container { id: container_id.to_string(), name: Some("web".to_string()), image: Some("app:1".to_string()), runtime: Runtime::Docker },
            process: Process { pid: None, tid: None, uid: None, gid: None, comm: None },
            src: Endpoint { addr: IpAddr::from([10, 0, 0, 1]), port: 44444 },
            dst: Endpoint { addr: IpAddr::from([203, 0, 113, 9]), port: 443 },
            verdict,
            rule_id: None,
            domain: domain_name.map(|name| Domain { name: Some(name.to_string()), source: Some(bathyscaphe_proto::DomainSource::Dns), confidence: Some(bathyscaphe_proto::DomainConfidence::Asserted) }).unwrap_or_default(),
            meta: EventMeta { dropped_since_last: 0 },
        }
    }

    fn state_with_container(container_id: &str, cgroup_id: u64) -> Arc<Mutex<DaemonState>> {
        let mut state = DaemonState::new();
        state.upsert(ContainerState { container_id: container_id.to_string(), cgroup_id, mode: Mode::Block, generation: 1, default: DefaultVerdict::Deny, rules_active: 1, rules_inert: 0, orphaned: false });
        Arc::new(Mutex::new(state))
    }

    #[test]
    fn watcher_fires_on_a_deny_with_no_domain_and_an_active_name_rule() {
        let container_id = "c".repeat(64);
        let state = state_with_container(&container_id, 5);
        let name_rules = Arc::new(Mutex::new(NamePatternStore::new()));
        name_rules.lock().unwrap().set_patterns(5, vec![allow_pattern("r1", "github.com", None, None)]);
        let security = Arc::new(SecurityEmitter::new());

        let mut watcher = NameUnresolvedBlockWatcher::new(CapturingSink(Vec::new()), state, name_rules, security);
        watcher.emit(UpMessage::Event(sample_event(&container_id, Verdict::Deny, None)));

        assert_eq!(watcher.inner.0.len(), 2, "the original event plus one security record");
        assert!(matches!(watcher.inner.0[0], UpMessage::Security(_)), "the security record is emitted before the original event is forwarded");
        let UpMessage::Security(record) = &watcher.inner.0[0] else { unreachable!() };
        assert_eq!(record.attributes.get("reason").unwrap(), bathyscaphe_proto::security::reason::POLICY_NAME_UNRESOLVED_BLOCK);
        assert!(matches!(watcher.inner.0[1], UpMessage::Event(_)));
    }

    #[test]
    fn watcher_stays_quiet_on_a_deny_with_domain_enrichment() {
        let container_id = "c".repeat(64);
        let state = state_with_container(&container_id, 5);
        let name_rules = Arc::new(Mutex::new(NamePatternStore::new()));
        name_rules.lock().unwrap().set_patterns(5, vec![allow_pattern("r1", "github.com", None, None)]);
        let security = Arc::new(SecurityEmitter::new());

        let mut watcher = NameUnresolvedBlockWatcher::new(CapturingSink(Vec::new()), state, name_rules, security);
        watcher.emit(UpMessage::Event(sample_event(&container_id, Verdict::Deny, Some("github.com"))));

        assert_eq!(watcher.inner.0.len(), 1, "a resolved-and-still-denied connection is not the unresolved-name signal");
        assert!(matches!(watcher.inner.0[0], UpMessage::Event(_)));
    }

    #[test]
    fn watcher_stays_quiet_when_the_container_has_no_active_name_rule() {
        let container_id = "c".repeat(64);
        let state = state_with_container(&container_id, 5);
        let name_rules = Arc::new(Mutex::new(NamePatternStore::new())); // nothing registered
        let security = Arc::new(SecurityEmitter::new());

        let mut watcher = NameUnresolvedBlockWatcher::new(CapturingSink(Vec::new()), state, name_rules, security);
        watcher.emit(UpMessage::Event(sample_event(&container_id, Verdict::Deny, None)));

        assert_eq!(watcher.inner.0.len(), 1, "no name rule at all means this deny has nothing to do with unresolved-name traffic");
    }

    #[test]
    fn watcher_stays_quiet_on_an_allow_verdict() {
        let container_id = "c".repeat(64);
        let state = state_with_container(&container_id, 5);
        let name_rules = Arc::new(Mutex::new(NamePatternStore::new()));
        name_rules.lock().unwrap().set_patterns(5, vec![allow_pattern("r1", "github.com", None, None)]);
        let security = Arc::new(SecurityEmitter::new());

        let mut watcher = NameUnresolvedBlockWatcher::new(CapturingSink(Vec::new()), state, name_rules, security);
        watcher.emit(UpMessage::Event(sample_event(&container_id, Verdict::Allow, None)));

        assert_eq!(watcher.inner.0.len(), 1, "only an actual deny is the fail-closed signal this record reports");
    }
}
