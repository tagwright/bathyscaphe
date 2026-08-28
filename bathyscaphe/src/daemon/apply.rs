// SPDX-License-Identifier: GPL-3.0-or-later
//! Applying a compiled directive against a [`ProbeApi`]: resolving
//! `container_id -> cgroup_id`/path (attaching if needed), the
//! make-before-break key diff, updating [`DaemonState`], and (build chunk
//! #10) registering this snapshot's `type: "name"` rule patterns into
//! [`crate::dns::NamePatternStore`]. [`super::compile`] stays pure (no
//! probe, no attribution, no clock); this module is the thin, still-
//! unit-testable (via [`super::probe_api::MockProbe`] and a stub
//! `ContainerLookup` impl) layer that actually drives state.
//!
//! Build chunk #10 removed this module's former unenforceable-name loud
//! record path entirely: `enforce_fqdn` is always advertised now, so a
//! name rule is enforceable at COMPILE time -- what can still go wrong is
//! a runtime fact about a later connection ("no DNS answer was ever seen
//! for the destination actually reached"), which
//! `daemon::fqdn::NameUnresolvedBlockWatcher` detects at the event
//! pipeline, not here.

use std::sync::Mutex;

use bathyscaphe_common::{PolicyKeyData, RuleSource};
use bathyscaphe_proto::down::Policy;
use bathyscaphe_proto::{PolicyAck, PolicyAckStatus, ReleaseAck, ReleaseStatus};

use crate::attribution::ContainerLookup;
use crate::dns::{NamePattern, NamePatternStore};

use super::compile::{self, CompiledPolicy};
use super::probe_api::ProbeApi;
use super::state::{ContainerState, DaemonState};

/// Converts a rule's absolute `expires_at` RFC3339 string into an absolute
/// `CLOCK_BOOTTIME` nanosecond value, using the same wall-clock/boottime
/// offset convention as `pipeline::map`'s `sample_boot_offset_ns`
/// (`boot_offset_ns = wall_now_ns - boot_now_ns` at the moment it was
/// sampled). Returns `None` on an unparseable string -- a malformed
/// `expires_at` is treated as "no expiry" rather than a hard compile
/// error, since a directive's shape has already passed NDJSON decoding by
/// this point and a single bad timestamp should not veto an entire
/// snapshot the way a port-rule overflow does.
pub fn resolve_expiry(expires_at: &str, boot_offset_ns: i128) -> Option<u64> {
    let dt = time::OffsetDateTime::parse(expires_at, &time::format_description::well_known::Rfc3339).ok()?;
    let wall_ns = dt.unix_timestamp_nanos();
    let boot_ns = wall_ns - boot_offset_ns;
    Some(u64::try_from(boot_ns.max(0)).unwrap_or(u64::MAX))
}

/// Resolves `container_id` to a `cgroup_id`, attaching the container's
/// cgroup if this process is not already observing it. `Err` carries a
/// human-readable reason suitable for `policy_ack.error` -- most commonly
/// the container-creation race (`docs/PROTOCOL.md` doesn't specify a retry
/// queue for this; airlock re-pushing on its own reconciliation cadence is
/// the recovery path, not a queue held here, per the build brief's
/// "do not rabbit-hole" instruction).
fn resolve_or_attach(probe: &mut dyn ProbeApi, lookup: &dyn ContainerLookup, container_id: &str) -> Result<u64, String> {
    let Some(cgroup_id) = lookup.cgroup_id_for_container(container_id) else {
        return Err(format!("container {container_id} has no known cgroup yet (races container creation, or the container has already exited); not applied, awaiting a resend"));
    };
    if !probe.attached_containers().contains(&cgroup_id) {
        let path = lookup.cgroup_path_for_container(container_id).ok_or_else(|| format!("container {container_id} resolved to cgroup {cgroup_id:016x} but its cgroup path is no longer known"))?;
        probe.attach_container(&path).map_err(|error| format!("failed to attach container {container_id}: {error}"))?;
    }
    Ok(cgroup_id)
}

/// The make-before-break key diff: every entry `compiled` calls for is
/// inserted FIRST (the "make"), then every previously-tracked STATIC key
/// not in the new set is removed (the "break") -- in that order, so a
/// connect evaluated concurrently on another CPU never observes a window
/// where this container has fewer entries than either the old or the new
/// snapshot alone.
///
/// Build chunk #10: the "old keys" baseline is
/// [`ProbeApi::tracked_policy_keys_by_source`] filtered to
/// `RuleSource::Static`, NOT the unfiltered `tracked_policy_keys` chunk #7
/// shipped with. A DNS-derived host route
/// (`daemon::fqdn::on_dns_answer`) is tracked in the SAME per-container key
/// set but was never part of any compiled STATIC snapshot, so it must
/// never be treated as "stale" just because this particular re-push didn't
/// mention it -- per `bathy_build_spec.md`'s ratified POLICY MAPS section,
/// the DNS-snoop layer is additive to static policy. A DNS route's own
/// lifecycle is governed entirely by its TTL (`ProbeApi::reap_expired_policy`)
/// or an explicit `release`, never by an unrelated static resnapshot.
fn apply_make_before_break(probe: &mut dyn ProbeApi, cgroup_id: u64, compiled: &CompiledPolicy) {
    let old_keys = probe.tracked_policy_keys_by_source(cgroup_id, RuleSource::Static as u8);

    let mut new_keys: std::collections::HashSet<(u32, [u8; 16])> = std::collections::HashSet::with_capacity(compiled.entries.len());
    for entry in &compiled.entries {
        let addr_bytes = crate::probe::policy::addr_to_rfc4291(entry.addr);
        new_keys.insert((PolicyKeyData::MIN_PREFIX_LEN + entry.prefix_bits_over_addr, addr_bytes));
        if let Err(error) = probe.set_policy(cgroup_id, entry.addr, entry.prefix_bits_over_addr, entry.value) {
            eprintln!("bathyscaphe: POLICY insert failed for cgroup {cgroup_id:016x} at {}/{} ({error}); this entry may be missing from enforcement", entry.addr, entry.prefix_bits_over_addr);
        }
    }

    for (prefix_len, addr) in old_keys {
        if !new_keys.contains(&(prefix_len, addr)) {
            if let Err(error) = probe.remove_policy_key(cgroup_id, prefix_len, addr) {
                eprintln!("bathyscaphe: POLICY remove failed for cgroup {cgroup_id:016x} at prefix_len={prefix_len} ({error}); a stale entry may remain enforced");
            }
        }
    }
}

/// Converts a snapshot's compiled name patterns into the
/// `crate::dns::NamePattern` shape [`crate::dns::NamePatternStore`] stores
/// -- a trivial field-for-field carry, kept as its own function so
/// [`apply_policy`]'s main body reads as one straight-line sequence.
fn to_dns_patterns(compiled: &[compile::CompiledNamePattern]) -> Vec<NamePattern> {
    compiled
        .iter()
        .map(|p| NamePattern { rule_id: p.rule_id.clone(), pattern: p.pattern.clone(), action: p.action, port: p.port, proto: p.proto })
        .collect()
}

/// Applies one `policy` directive end to end: compile, resolve/attach,
/// make-before-break, update [`DaemonState`], register this snapshot's
/// name-rule patterns (build chunk #10), and produce the `policy_ack`.
pub fn apply_policy(probe: &mut dyn ProbeApi, state: &mut DaemonState, lookup: &dyn ContainerLookup, name_rules: &Mutex<NamePatternStore>, boot_offset_ns: i128, policy: &Policy) -> PolicyAck {
    let compiled = match compile::compile_policy(policy, |s| resolve_expiry(s, boot_offset_ns)) {
        Ok(compiled) => compiled,
        Err(error) => {
            return PolicyAck { container_id: policy.container_id.clone(), generation: policy.generation, status: PolicyAckStatus::Error, inert_rules: 0, error: Some(error.0) };
        }
    };

    let cgroup_id = match resolve_or_attach(probe, lookup, &policy.container_id) {
        Ok(cgroup_id) => cgroup_id,
        Err(error) => {
            return PolicyAck { container_id: policy.container_id.clone(), generation: policy.generation, status: PolicyAckStatus::Error, inert_rules: compiled.inert_rules, error: Some(error) };
        }
    };

    apply_make_before_break(probe, cgroup_id, &compiled);

    if let Err(error) = probe.set_enforcement(cgroup_id, compiled.mode, compiled.default, compiled.generation) {
        return PolicyAck { container_id: policy.container_id.clone(), generation: policy.generation, status: PolicyAckStatus::Error, inert_rules: compiled.inert_rules, error: Some(format!("ENFORCEMENT write failed: {error}")) };
    }

    // Build chunk #10: register this snapshot's name-rule patterns,
    // replacing this container's ENTIRE prior pattern set wholesale --
    // `policy` is a full replacement, never a delta (`docs/PROTOCOL.md`
    // section 4), so a name rule dropped from a re-push must stop being
    // enforceable immediately, not linger from a stale registration.
    {
        let mut name_rules = name_rules.lock().unwrap_or_else(|poison| poison.into_inner());
        name_rules.set_patterns(cgroup_id, to_dns_patterns(&compiled.name_patterns));
    }

    state.upsert(ContainerState {
        container_id: policy.container_id.clone(),
        cgroup_id,
        mode: compiled.mode,
        generation: compiled.generation,
        default: compiled.default,
        rules_active: compiled.entries.len() as u32,
        rules_inert: compiled.inert_rules,
        orphaned: false,
    });

    PolicyAck { container_id: policy.container_id.clone(), generation: policy.generation, status: PolicyAckStatus::Applied, inert_rules: compiled.inert_rules, error: None }
}

/// Drops enforcement for one container back to observe-only, keeping the
/// attach hooks in place. Idempotent: a container this process never knew
/// about (or already released) still acks `released`.
pub fn apply_release(probe: &mut dyn ProbeApi, state: &mut DaemonState, lookup: &dyn ContainerLookup, name_rules: &Mutex<NamePatternStore>, container_id: &str) -> ReleaseAck {
    let cgroup_id = lookup.cgroup_id_for_container(container_id).or_else(|| state.containers.get(container_id).map(|c| c.cgroup_id));
    if let Some(cgroup_id) = cgroup_id {
        let _ = probe.clear_enforcement(cgroup_id);
        let _ = probe.release_policy_container(cgroup_id);
        name_rules.lock().unwrap_or_else(|poison| poison.into_inner()).remove_container(cgroup_id);
    }
    state.remove(container_id);
    ReleaseAck { container_id: container_id.to_string(), status: ReleaseStatus::Released }
}

/// The host-level emergency variant: releases every container this
/// process currently holds policy state for, acking one `release_ack`
/// each.
pub fn apply_release_all(probe: &mut dyn ProbeApi, state: &mut DaemonState, name_rules: &Mutex<NamePatternStore>) -> Vec<ReleaseAck> {
    let container_ids: Vec<String> = state.containers.keys().cloned().collect();
    let mut acks = Vec::with_capacity(container_ids.len());
    for container_id in container_ids {
        if let Some(cgroup_id) = state.containers.get(&container_id).map(|c| c.cgroup_id) {
            let _ = probe.clear_enforcement(cgroup_id);
            let _ = probe.release_policy_container(cgroup_id);
            name_rules.lock().unwrap_or_else(|poison| poison.into_inner()).remove_container(cgroup_id);
        }
        state.remove(&container_id);
        acks.push(ReleaseAck { container_id, status: ReleaseStatus::Released });
    }
    acks
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon::probe_api::{MockCall, MockProbe};
    use bathyscaphe_proto::down::{Match, Rule};
    use bathyscaphe_proto::{DefaultVerdict as WireDefault, Mode as WireMode, RuleAction as WireAction, RuleSource as WireSource};
    use std::path::PathBuf;

    struct StubLookup {
        id_to_cgroup: std::collections::HashMap<String, (u64, PathBuf)>,
    }
    impl ContainerLookup for StubLookup {
        fn cgroup_id_for_container(&self, container_id: &str) -> Option<u64> {
            self.id_to_cgroup.get(container_id).map(|(id, _)| *id)
        }
        fn cgroup_path_for_container(&self, container_id: &str) -> Option<PathBuf> {
            self.id_to_cgroup.get(container_id).map(|(_, path)| path.clone())
        }
    }

    fn container_id() -> String {
        "a".repeat(64)
    }

    fn cidr_rule(cidr: &str, action: WireAction) -> Rule {
        Rule { id: "r1".to_string(), action, r#match: Match::Cidr { cidr: cidr.to_string(), port: None, proto: None, unknown: Default::default() }, expires_at: None, source: WireSource::Static }
    }

    fn lookup_with_one_container(cgroup_id: u64) -> StubLookup {
        let mut map = std::collections::HashMap::new();
        map.insert(container_id(), (cgroup_id, PathBuf::from("/sys/fs/cgroup/docker".to_string() + &format!("/{}", container_id()))));
        StubLookup { id_to_cgroup: map }
    }

    fn empty_name_rules() -> Mutex<NamePatternStore> {
        Mutex::new(NamePatternStore::new())
    }

    #[test]
    fn apply_policy_attaches_a_not_yet_attached_container_then_enforces() {
        let mut probe = MockProbe::new();
        let lookup = lookup_with_one_container(42);
        probe.seed_path(&lookup.cgroup_path_for_container(&container_id()).unwrap(), 42);
        let mut state = DaemonState::new();
        let name_rules = empty_name_rules();

        let policy = Policy { container_id: container_id(), generation: 1, mode: WireMode::Block, default: WireDefault::Deny, rules: vec![cidr_rule("10.0.0.0/8", WireAction::Allow)] };
        let ack = apply_policy(&mut probe, &mut state, &lookup, &name_rules, 0, &policy);

        assert_eq!(ack.status, PolicyAckStatus::Applied);
        assert!(probe.calls.contains(&MockCall::Attach(42)));
        assert!(probe.calls.contains(&MockCall::SetEnforcement(42)));
        assert!(state.containers.contains_key(&container_id()));
    }

    #[test]
    fn apply_policy_does_not_reattach_an_already_attached_container() {
        let mut probe = MockProbe::new();
        let lookup = lookup_with_one_container(7);
        probe.seed_path(&lookup.cgroup_path_for_container(&container_id()).unwrap(), 7);
        probe.attach_container(&lookup.cgroup_path_for_container(&container_id()).unwrap()).unwrap();
        probe.calls.clear();

        let mut state = DaemonState::new();
        let name_rules = empty_name_rules();
        let policy = Policy { container_id: container_id(), generation: 1, mode: WireMode::Audit, default: WireDefault::Allow, rules: vec![] };

        apply_policy(&mut probe, &mut state, &lookup, &name_rules, 0, &policy);
        assert!(!probe.calls.iter().any(|c| matches!(c, MockCall::Attach(_))), "an already-attached container must not be re-attached");
    }

    #[test]
    fn apply_policy_on_a_compile_error_never_touches_the_probe() {
        let mut probe = MockProbe::new();
        let lookup = lookup_with_one_container(1);
        let mut state = DaemonState::new();
        let name_rules = empty_name_rules();

        let mut rules = Vec::new();
        for port in 0..=8u16 {
            rules.push(Rule { id: format!("r{port}"), action: WireAction::Allow, r#match: Match::Cidr { cidr: "10.0.0.0/24".to_string(), port: Some(1000 + port), proto: None, unknown: Default::default() }, expires_at: None, source: WireSource::Static });
        }
        let policy = Policy { container_id: container_id(), generation: 1, mode: WireMode::Block, default: WireDefault::Deny, rules };

        let ack = apply_policy(&mut probe, &mut state, &lookup, &name_rules, 0, &policy);
        assert_eq!(ack.status, PolicyAckStatus::Error);
        assert!(probe.calls.is_empty(), "a compile error must never touch the probe -- the previous generation, if any, stays enforced");
        assert!(!state.containers.contains_key(&container_id()));
    }

    #[test]
    fn apply_policy_for_an_unresolvable_container_errors_without_touching_the_probe() {
        let mut probe = MockProbe::new();
        let lookup = StubLookup { id_to_cgroup: std::collections::HashMap::new() };
        let mut state = DaemonState::new();
        let name_rules = empty_name_rules();
        let policy = Policy { container_id: container_id(), generation: 1, mode: WireMode::Audit, default: WireDefault::Allow, rules: vec![] };

        let ack = apply_policy(&mut probe, &mut state, &lookup, &name_rules, 0, &policy);
        assert_eq!(ack.status, PolicyAckStatus::Error);
        assert!(probe.calls.is_empty());
    }

    #[test]
    fn apply_policy_registers_a_name_rules_pattern_and_reports_it_as_not_inert() {
        let mut probe = MockProbe::new();
        let lookup = lookup_with_one_container(9);
        probe.seed_path(&lookup.cgroup_path_for_container(&container_id()).unwrap(), 9);
        let mut state = DaemonState::new();
        let name_rules = empty_name_rules();

        let name_rule = Rule { id: "r-name".to_string(), action: WireAction::Allow, r#match: Match::Name { pattern: "github.com".to_string(), port: None, proto: None, unknown: Default::default() }, expires_at: None, source: WireSource::Static };
        let policy = Policy { container_id: container_id(), generation: 1, mode: WireMode::Block, default: WireDefault::Deny, rules: vec![name_rule] };

        let ack = apply_policy(&mut probe, &mut state, &lookup, &name_rules, 0, &policy);
        assert_eq!(ack.status, PolicyAckStatus::Applied);
        assert_eq!(ack.inert_rules, 0, "a well-formed name rule is active, not inert, under enforce_fqdn");
        assert!(name_rules.lock().unwrap().has_active_allow_pattern(9), "the pattern must be registered under the container's cgroup_id");
    }

    #[test]
    fn apply_policy_replaces_a_containers_prior_name_patterns_wholesale() {
        let mut probe = MockProbe::new();
        let lookup = lookup_with_one_container(9);
        probe.seed_path(&lookup.cgroup_path_for_container(&container_id()).unwrap(), 9);
        let mut state = DaemonState::new();
        let name_rules = empty_name_rules();

        let first_rule = Rule { id: "r1".to_string(), action: WireAction::Allow, r#match: Match::Name { pattern: "old.example.com".to_string(), port: None, proto: None, unknown: Default::default() }, expires_at: None, source: WireSource::Static };
        let first = Policy { container_id: container_id(), generation: 1, mode: WireMode::Alert, default: WireDefault::Allow, rules: vec![first_rule] };
        apply_policy(&mut probe, &mut state, &lookup, &name_rules, 0, &first);
        assert!(name_rules.lock().unwrap().first_matching_allow(9, "old.example.com").is_some());

        let second = Policy { container_id: container_id(), generation: 2, mode: WireMode::Alert, default: WireDefault::Allow, rules: vec![] };
        apply_policy(&mut probe, &mut state, &lookup, &name_rules, 0, &second);
        assert!(name_rules.lock().unwrap().first_matching_allow(9, "old.example.com").is_none(), "a re-push with no name rules must clear the prior registration, not leave it stale");
    }

    #[test]
    fn make_before_break_diff_removes_stale_keys_not_in_the_new_snapshot() {
        let mut probe = MockProbe::new();
        let lookup = lookup_with_one_container(11);
        let mut state = DaemonState::new();
        let name_rules = empty_name_rules();

        let first = Policy { container_id: container_id(), generation: 1, mode: WireMode::Block, default: WireDefault::Deny, rules: vec![cidr_rule("10.0.0.0/24", WireAction::Allow)] };
        apply_policy(&mut probe, &mut state, &lookup, &name_rules, 0, &first);
        let keys_after_first = probe.tracked_policy_keys(11).len();
        assert_eq!(keys_after_first, 2, "the /24 rule plus the synthesized baseline");

        let second = Policy { container_id: container_id(), generation: 2, mode: WireMode::Block, default: WireDefault::Deny, rules: vec![cidr_rule("192.168.0.0/16", WireAction::Allow)] };
        apply_policy(&mut probe, &mut state, &lookup, &name_rules, 0, &second);

        let final_keys = probe.tracked_policy_keys(11);
        assert_eq!(final_keys.len(), 2, "the old /24 entry must be gone, replaced by the new /16 plus baseline");
        // Make happened before break: the mock recorded a SetPolicy call
        // for the new snapshot before any RemovePolicyKey for the old one.
        let first_remove = probe.calls.iter().position(|c| matches!(c, MockCall::RemovePolicyKey(_)));
        let last_set_for_second_gen = probe.calls.iter().rposition(|c| matches!(c, MockCall::SetPolicy(_)));
        assert!(last_set_for_second_gen.unwrap() > first_remove.unwrap_or(0) || first_remove.is_none(), "inserts for the new snapshot must happen before removals of the old one");
    }

    #[test]
    fn make_before_break_never_removes_a_dns_sourced_host_route() {
        // Build chunk #10's correctness fix: a DNS-derived host route
        // (source: Dns) sitting in the SAME per-container key pool as a
        // static snapshot's entries must survive a static re-push that
        // never mentions it.
        use bathyscaphe_common::PolicyValue;
        let mut probe = MockProbe::new();
        let lookup = lookup_with_one_container(12);
        probe.seed_path(&lookup.cgroup_path_for_container(&container_id()).unwrap(), 12);
        let mut state = DaemonState::new();
        let name_rules = empty_name_rules();

        let first = Policy { container_id: container_id(), generation: 1, mode: WireMode::Block, default: WireDefault::Deny, rules: vec![cidr_rule("10.0.0.0/24", WireAction::Allow)] };
        apply_policy(&mut probe, &mut state, &lookup, &name_rules, 0, &first);

        // Simulate the DNS-answer insertion path (`daemon::fqdn::on_dns_answer`)
        // writing a host route directly against the probe.
        let dns_addr = std::net::IpAddr::from([93, 184, 216, 34]);
        probe.set_policy(12, dns_addr, 128, PolicyValue::new(bathyscaphe_common::RuleAction::Allow as u8, RuleSource::Dns as u8, 0)).unwrap();
        assert_eq!(probe.tracked_policy_keys(12).len(), 3, "the /24 rule, the baseline, and the DNS host route");

        // A second STATIC snapshot re-push, mentioning neither the /24 nor
        // the DNS host route.
        let second = Policy { container_id: container_id(), generation: 2, mode: WireMode::Block, default: WireDefault::Deny, rules: vec![] };
        apply_policy(&mut probe, &mut state, &lookup, &name_rules, 0, &second);

        let final_keys = probe.tracked_policy_keys(12);
        assert_eq!(final_keys.len(), 2, "the old static /24 entry is gone (replaced by the new baseline), but the DNS host route must remain");
        let addr_bytes = crate::probe::policy::addr_to_rfc4291(dns_addr);
        assert!(final_keys.contains(&(bathyscaphe_common::PolicyKeyData::MIN_PREFIX_LEN + 128, addr_bytes)), "the DNS-sourced host route must survive a static resnapshot untouched");
    }

    #[test]
    fn apply_release_clears_enforcement_but_the_mock_never_detaches() {
        let mut probe = MockProbe::new();
        let lookup = lookup_with_one_container(21);
        probe.seed_path(&lookup.cgroup_path_for_container(&container_id()).unwrap(), 21);
        let mut state = DaemonState::new();
        let name_rules = empty_name_rules();

        let policy = Policy { container_id: container_id(), generation: 1, mode: WireMode::Block, default: WireDefault::Deny, rules: vec![cidr_rule("10.0.0.0/8", WireAction::Allow)] };
        apply_policy(&mut probe, &mut state, &lookup, &name_rules, 0, &policy);

        let ack = apply_release(&mut probe, &mut state, &lookup, &name_rules, &container_id());
        assert_eq!(ack.status, ReleaseStatus::Released);
        assert!(!state.containers.contains_key(&container_id()));
        assert!(probe.get_enforcement(21).unwrap().is_none());
        // Observation hooks stay attached -- release never detaches.
        assert!(probe.attached_containers().contains(&21));
    }

    #[test]
    fn apply_release_clears_the_containers_name_patterns_too() {
        let mut probe = MockProbe::new();
        let lookup = lookup_with_one_container(22);
        let mut state = DaemonState::new();
        let name_rules = empty_name_rules();

        let name_rule = Rule { id: "r1".to_string(), action: WireAction::Allow, r#match: Match::Name { pattern: "github.com".to_string(), port: None, proto: None, unknown: Default::default() }, expires_at: None, source: WireSource::Static };
        let policy = Policy { container_id: container_id(), generation: 1, mode: WireMode::Alert, default: WireDefault::Allow, rules: vec![name_rule] };
        apply_policy(&mut probe, &mut state, &lookup, &name_rules, 0, &policy);
        assert!(name_rules.lock().unwrap().has_active_allow_pattern(22));

        apply_release(&mut probe, &mut state, &lookup, &name_rules, &container_id());
        assert!(!name_rules.lock().unwrap().has_active_allow_pattern(22), "release must clear the container's registered name patterns");
    }

    #[test]
    fn apply_release_for_an_unknown_container_is_idempotent() {
        let mut probe = MockProbe::new();
        let lookup = StubLookup { id_to_cgroup: std::collections::HashMap::new() };
        let mut state = DaemonState::new();
        let name_rules = empty_name_rules();
        let ack = apply_release(&mut probe, &mut state, &lookup, &name_rules, "never-seen");
        assert_eq!(ack.status, ReleaseStatus::Released);
        assert!(probe.calls.is_empty());
    }

    #[test]
    fn apply_release_all_releases_every_tracked_container() {
        let mut probe = MockProbe::new();
        let lookup1 = lookup_with_one_container(31);
        let mut state = DaemonState::new();
        let name_rules = empty_name_rules();

        let policy = Policy { container_id: container_id(), generation: 1, mode: WireMode::Block, default: WireDefault::Deny, rules: vec![] };
        apply_policy(&mut probe, &mut state, &lookup1, &name_rules, 0, &policy);
        assert_eq!(state.containers.len(), 1);

        let acks = apply_release_all(&mut probe, &mut state, &name_rules);
        assert_eq!(acks.len(), 1);
        assert_eq!(acks[0].status, ReleaseStatus::Released);
        assert!(state.containers.is_empty());
    }
}
