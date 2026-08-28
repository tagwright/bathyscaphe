// SPDX-License-Identifier: GPL-3.0-or-later
//! FQDN enforcement (build chunk #10): the two pieces that turn a
//! correctly-attributed DNS answer (`crate::dns::AttributedAnswer`) and a
//! container's registered name-rule patterns (`crate::dns::NamePatternStore`,
//! populated by `daemon::apply`) into actual kernel-enforced policy.
//!
//! - [`on_dns_answer`]: on a DNS answer matching a container's active
//!   `Allow` name pattern, inserts the resolved address into `POLICY` as a
//!   host route, applying the pattern's port/proto constraint if any.
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

use crate::dns::{AttributedAnswer, NamePatternStore};
use crate::pipeline::EventSink;

use super::probe_api::ProbeApi;
use super::security::{SecurityEmitter, name_unresolved_block_record};
use super::state::DaemonState;

/// The `POLICY` host route this build inserts is always a full `/128`
/// (`prefix_bits_over_addr = 128` per `probe::policy::build_policy_key`'s
/// convention) -- a single resolved address, never a wider prefix. See
/// `docs/DNS.md` for why a name rule resolves to individual answer IPs,
/// not a synthesized CIDR.
const HOST_ROUTE_PREFIX_BITS: u32 = 128;

/// On a DNS answer, checks whether `answer.name` matches one of
/// `answer.cgroup_id`'s registered `Allow` name patterns
/// (`crate::dns::NamePatternStore::first_matching_allow` -- only the FIRST
/// matching pattern is used, a documented v1 simplification, see that
/// method's doc) and, on a match, inserts `answer.addr` into `POLICY` as a
/// host route with `source: RuleSource::Dns` and `expires_at_ns` computed
/// from the EXACT SAME `(ttl_secs, now_boottime_ns)` pair
/// `crate::dns::cache::DomainCache::record` already used for this same
/// answer (via [`crate::dns::cache::expiry_ns`]) -- the enrichment cache
/// and the enforcement allow-map agree on one absolute expiry instant, per
/// `docs/DNS.md`'s plugging-in note.
///
/// A pattern carrying a port/proto constraint applies that constraint to
/// the inserted host route's `PortRule`s: the host route's own
/// `cidr_default_action` becomes `Deny` and exactly one `PortRule` grants
/// `Allow` for the pattern's port range/proto -- so a name rule scoped to
/// `github.com:443/tcp` never opens up other ports/protocols to whatever
/// address `github.com` happens to resolve to, even though the host route
/// itself is the single most-specific entry an `LpmTrie` lookup will ever
/// find for that exact address. A pattern with no port/proto constraint
/// instead sets `cidr_default_action: Allow` with no port rules -- the
/// address is fully open, matching the rule's own unconstrained intent.
///
/// No-op (nothing inserted) when no pattern matches, `answer.correlated`
/// is irrelevant to this decision (an uncorrelated answer still gets
/// whatever `cgroup_id` `crate::dns::capture_callback` decided to use --
/// see that function's fallback doc; this function has no additional
/// opinion about confidence).
pub fn on_dns_answer(probe: &mut dyn ProbeApi, name_rules: &Mutex<NamePatternStore>, answer: &AttributedAnswer) {
    let pattern = {
        let name_rules = name_rules.lock().unwrap_or_else(|poison| poison.into_inner());
        name_rules.first_matching_allow(answer.cgroup_id, &answer.name).cloned()
    };
    let Some(pattern) = pattern else {
        return;
    };

    let expires_at_ns = crate::dns::cache::expiry_ns(answer.ktime_ns, answer.ttl_secs);

    let value = match (pattern.port, pattern.proto) {
        (None, None) => PolicyValue::new(RuleAction::Allow as u8, RuleSource::Dns as u8, expires_at_ns),
        (port, proto) => {
            let port_lo = port.unwrap_or(0);
            let port_hi = port.unwrap_or(u16::MAX);
            let proto_raw = proto.map(|p| PortRule::encode_proto(p as u8)).unwrap_or(PortRule::PROTO_ANY);
            PolicyValue::new(RuleAction::Deny as u8, RuleSource::Dns as u8, expires_at_ns)
                .with_port_rule(PortRule::new(port_lo, port_hi, proto_raw, RuleAction::Allow as u8))
                .unwrap_or_else(|value| value) // MAX_PORT_RULES is 8; one rule never overflows a fresh value.
        }
    };

    if let Err(error) = probe.set_policy(answer.cgroup_id, answer.addr, HOST_ROUTE_PREFIX_BITS, value) {
        eprintln!("bathyscaphe: FQDN POLICY insert failed for cgroup {:016x} at {}/128 (name rule {:?} matched {:?}): {error}", answer.cgroup_id, answer.addr, pattern.rule_id, answer.name);
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
    use crate::daemon::probe_api::MockProbe;
    use crate::daemon::state::ContainerState;
    use crate::dns::NamePattern;
    use bathyscaphe_common::{DefaultVerdict, Mode, PolicyKeyData, TransportProto};
    use bathyscaphe_proto::{Container, Domain, Endpoint, Event as WireEvent, EventKind, EventMeta, Process, Runtime};
    use std::net::IpAddr;

    fn allow_pattern(rule_id: &str, pattern: &str, port: Option<u16>, proto: Option<TransportProto>) -> NamePattern {
        NamePattern { rule_id: rule_id.to_string(), pattern: pattern.to_string(), action: RuleAction::Allow, port, proto }
    }

    fn answer(cgroup_id: u64, name: &str, addr: IpAddr, ttl_secs: u32) -> AttributedAnswer {
        AttributedAnswer { cgroup_id, name: name.to_string(), addr, ttl_secs, ktime_ns: 1_000_000_000, correlated: true }
    }

    #[test]
    fn on_dns_answer_inserts_an_unconstrained_host_route_on_a_match() {
        let mut probe = MockProbe::new();
        let name_rules = Mutex::new(NamePatternStore::new());
        name_rules.lock().unwrap().set_patterns(1, vec![allow_pattern("r1", "*.github.com", None, None)]);

        let addr = IpAddr::from([140, 82, 121, 4]);
        on_dns_answer(&mut probe, &name_rules, &answer(1, "api.github.com", addr, 300));

        let addr_bytes = crate::probe::policy::addr_to_rfc4291(addr);
        let keys = probe.tracked_policy_keys(1);
        assert!(keys.contains(&(PolicyKeyData::MIN_PREFIX_LEN + 128, addr_bytes)), "a /128 host route must be inserted");
    }

    #[test]
    fn on_dns_answer_does_nothing_when_no_pattern_matches() {
        let mut probe = MockProbe::new();
        let name_rules = Mutex::new(NamePatternStore::new());
        name_rules.lock().unwrap().set_patterns(1, vec![allow_pattern("r1", "*.github.com", None, None)]);

        on_dns_answer(&mut probe, &name_rules, &answer(1, "example.com", IpAddr::from([1, 2, 3, 4]), 300));
        assert!(probe.tracked_policy_keys(1).is_empty());
    }

    #[test]
    fn on_dns_answer_applies_the_patterns_port_and_proto_constraint() {
        let mut probe = MockProbe::new();
        let name_rules = Mutex::new(NamePatternStore::new());
        name_rules.lock().unwrap().set_patterns(1, vec![allow_pattern("r1", "github.com", Some(443), Some(TransportProto::Tcp))]);

        let addr = IpAddr::from([140, 82, 121, 4]);
        on_dns_answer(&mut probe, &name_rules, &answer(1, "github.com", addr, 300));

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

        let addr = IpAddr::from([140, 82, 121, 4]);
        let a = answer(1, "github.com", addr, 300);
        on_dns_answer(&mut probe, &name_rules, &a);

        let addr_bytes = crate::probe::policy::addr_to_rfc4291(addr);
        let value = probe.policy_keys.get(&1).unwrap().get(&(PolicyKeyData::MIN_PREFIX_LEN + 128, addr_bytes)).unwrap();
        assert_eq!(value.expires_at_ns, crate::dns::cache::expiry_ns(a.ktime_ns, a.ttl_secs));
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

    struct CapturingSink(Vec<UpMessage>);
    impl EventSink for CapturingSink {
        fn emit(&mut self, message: UpMessage) {
            self.0.push(message);
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
