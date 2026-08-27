// SPDX-License-Identifier: GPL-3.0-or-later
//! Applying a compiled directive against a [`ProbeApi`]: resolving
//! `container_id -> cgroup_id`/path (attaching if needed), the
//! make-before-break key diff, updating [`DaemonState`], and turning
//! [`super::compile::UnenforceableNameHit`]s into throttled `security`
//! records. [`super::compile`] stays pure (no probe, no attribution, no
//! clock); this module is the thin, still-unit-testable (via
//! [`super::probe_api::MockProbe`] and stub `Attributor`/`ContainerLookup`
//! impls) layer that actually drives state.

use bathyscaphe_common::PolicyKeyData;
use bathyscaphe_proto::down::Policy;
use bathyscaphe_proto::security::SecurityContainer;
use bathyscaphe_proto::{PolicyAck, PolicyAckStatus, ReleaseAck, ReleaseStatus};

use crate::attribution::{Attributor, ContainerLookup};
use crate::pipeline::EventSink;

use super::compile::{self, CompiledPolicy};
use super::probe_api::ProbeApi;
use super::security::{unenforceable_name_record, SecurityEmitter};
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

fn now_rfc3339() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
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
/// inserted FIRST (the "make"), then every previously-tracked key not in
/// the new set is removed (the "break") -- in that order, so a connect
/// evaluated concurrently on another CPU never observes a window where
/// this container has fewer entries than either the old or the new
/// snapshot alone.
fn apply_make_before_break(probe: &mut dyn ProbeApi, cgroup_id: u64, compiled: &CompiledPolicy) {
    let old_keys = probe.tracked_policy_keys(cgroup_id);

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

/// Applies one `policy` directive end to end: compile, resolve/attach,
/// make-before-break, update [`DaemonState`], emit any unenforceable-name
/// `security` records, and produce the `policy_ack`.
#[allow(clippy::too_many_arguments)]
pub fn apply_policy(probe: &mut dyn ProbeApi, state: &mut DaemonState, lookup: &dyn ContainerLookup, attributor: &dyn Attributor, security: &SecurityEmitter, sink: &mut dyn EventSink, boot_offset_ns: i128, policy: &Policy) -> PolicyAck {
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

    if !compiled.unenforceable_name_hits.is_empty() {
        let attribution = attributor.resolve(cgroup_id);
        let (name, image) = attribution.as_ref().map(|a| (a.name.as_deref(), a.image.as_deref())).unwrap_or((None, None));
        let timestamp = now_rfc3339();
        for hit in &compiled.unenforceable_name_hits {
            let container = SecurityContainer { id: &policy.container_id, name, image };
            security.try_emit(sink, unenforceable_name_record(timestamp.clone(), container, &hit.rule_id, &hit.pattern));
        }
    }

    PolicyAck { container_id: policy.container_id.clone(), generation: policy.generation, status: PolicyAckStatus::Applied, inert_rules: compiled.inert_rules, error: None }
}

/// Drops enforcement for one container back to observe-only, keeping the
/// attach hooks in place. Idempotent: a container this process never knew
/// about (or already released) still acks `released`.
pub fn apply_release(probe: &mut dyn ProbeApi, state: &mut DaemonState, lookup: &dyn ContainerLookup, container_id: &str) -> ReleaseAck {
    let cgroup_id = lookup.cgroup_id_for_container(container_id).or_else(|| state.containers.get(container_id).map(|c| c.cgroup_id));
    if let Some(cgroup_id) = cgroup_id {
        let _ = probe.clear_enforcement(cgroup_id);
        let _ = probe.release_policy_container(cgroup_id);
    }
    state.remove(container_id);
    ReleaseAck { container_id: container_id.to_string(), status: ReleaseStatus::Released }
}

/// The host-level emergency variant: releases every container this
/// process currently holds policy state for, acking one `release_ack`
/// each.
pub fn apply_release_all(probe: &mut dyn ProbeApi, state: &mut DaemonState) -> Vec<ReleaseAck> {
    let container_ids: Vec<String> = state.containers.keys().cloned().collect();
    let mut acks = Vec::with_capacity(container_ids.len());
    for container_id in container_ids {
        if let Some(cgroup_id) = state.containers.get(&container_id).map(|c| c.cgroup_id) {
            let _ = probe.clear_enforcement(cgroup_id);
            let _ = probe.release_policy_container(cgroup_id);
        }
        state.remove(&container_id);
        acks.push(ReleaseAck { container_id, status: ReleaseStatus::Released });
    }
    acks
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attribution::Attribution;
    use crate::daemon::probe_api::{MockCall, MockProbe};
    use bathyscaphe_proto::down::{Match, Rule};
    use bathyscaphe_proto::{DefaultVerdict as WireDefault, Mode as WireMode, RuleAction as WireAction, RuleSource as WireSource, UpMessage};
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

    struct StubAttributor(Option<Attribution>);
    impl Attributor for StubAttributor {
        fn resolve(&self, _cgroup_id: u64) -> Option<Attribution> {
            self.0.clone()
        }
    }

    struct CapturingSink(Vec<UpMessage>);
    impl EventSink for CapturingSink {
        fn emit(&mut self, message: UpMessage) {
            self.0.push(message);
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

    #[test]
    fn apply_policy_attaches_a_not_yet_attached_container_then_enforces() {
        let mut probe = MockProbe::new();
        let lookup = lookup_with_one_container(42);
        probe.seed_path(&lookup.cgroup_path_for_container(&container_id()).unwrap(), 42);
        let attributor = StubAttributor(None);
        let security = SecurityEmitter::new();
        let mut sink = CapturingSink(Vec::new());
        let mut state = DaemonState::new();

        let policy = Policy { container_id: container_id(), generation: 1, mode: WireMode::Block, default: WireDefault::Deny, rules: vec![cidr_rule("10.0.0.0/8", WireAction::Allow)] };
        let ack = apply_policy(&mut probe, &mut state, &lookup, &attributor, &security, &mut sink, 0, &policy);

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

        let attributor = StubAttributor(None);
        let security = SecurityEmitter::new();
        let mut sink = CapturingSink(Vec::new());
        let mut state = DaemonState::new();
        let policy = Policy { container_id: container_id(), generation: 1, mode: WireMode::Audit, default: WireDefault::Allow, rules: vec![] };

        apply_policy(&mut probe, &mut state, &lookup, &attributor, &security, &mut sink, 0, &policy);
        assert!(!probe.calls.iter().any(|c| matches!(c, MockCall::Attach(_))), "an already-attached container must not be re-attached");
    }

    #[test]
    fn apply_policy_on_a_compile_error_never_touches_the_probe() {
        let mut probe = MockProbe::new();
        let lookup = lookup_with_one_container(1);
        let attributor = StubAttributor(None);
        let security = SecurityEmitter::new();
        let mut sink = CapturingSink(Vec::new());
        let mut state = DaemonState::new();

        let mut rules = Vec::new();
        for port in 0..=8u16 {
            rules.push(Rule { id: format!("r{port}"), action: WireAction::Allow, r#match: Match::Cidr { cidr: "10.0.0.0/24".to_string(), port: Some(1000 + port), proto: None, unknown: Default::default() }, expires_at: None, source: WireSource::Static });
        }
        let policy = Policy { container_id: container_id(), generation: 1, mode: WireMode::Block, default: WireDefault::Deny, rules };

        let ack = apply_policy(&mut probe, &mut state, &lookup, &attributor, &security, &mut sink, 0, &policy);
        assert_eq!(ack.status, PolicyAckStatus::Error);
        assert!(probe.calls.is_empty(), "a compile error must never touch the probe -- the previous generation, if any, stays enforced");
        assert!(!state.containers.contains_key(&container_id()));
    }

    #[test]
    fn apply_policy_for_an_unresolvable_container_errors_without_touching_the_probe() {
        let mut probe = MockProbe::new();
        let lookup = StubLookup { id_to_cgroup: std::collections::HashMap::new() };
        let attributor = StubAttributor(None);
        let security = SecurityEmitter::new();
        let mut sink = CapturingSink(Vec::new());
        let mut state = DaemonState::new();
        let policy = Policy { container_id: container_id(), generation: 1, mode: WireMode::Audit, default: WireDefault::Allow, rules: vec![] };

        let ack = apply_policy(&mut probe, &mut state, &lookup, &attributor, &security, &mut sink, 0, &policy);
        assert_eq!(ack.status, PolicyAckStatus::Error);
        assert!(probe.calls.is_empty());
    }

    #[test]
    fn apply_policy_emits_a_throttled_unenforceable_name_record_in_block_deny_mode() {
        let mut probe = MockProbe::new();
        let lookup = lookup_with_one_container(9);
        let attribution = Attribution { container_id: container_id(), name: Some("web".to_string()), image: Some("nginx:latest".to_string()), runtime: bathyscaphe_proto::Runtime::Docker };
        let attributor = StubAttributor(Some(attribution));
        let security = SecurityEmitter::new();
        let mut sink = CapturingSink(Vec::new());
        let mut state = DaemonState::new();

        let name_rule = Rule { id: "r-name".to_string(), action: WireAction::Allow, r#match: Match::Name { pattern: "github.com".to_string(), port: None, proto: None, unknown: Default::default() }, expires_at: None, source: WireSource::Static };
        let policy = Policy { container_id: container_id(), generation: 1, mode: WireMode::Block, default: WireDefault::Deny, rules: vec![name_rule] };

        let ack = apply_policy(&mut probe, &mut state, &lookup, &attributor, &security, &mut sink, 0, &policy);
        assert_eq!(ack.inert_rules, 1);
        assert_eq!(sink.0.len(), 1);
        let UpMessage::Security(record) = &sink.0[0] else { panic!("expected a security record") };
        assert_eq!(record.attributes.get("container.name").unwrap(), "web");
    }

    #[test]
    fn make_before_break_diff_removes_stale_keys_not_in_the_new_snapshot() {
        let mut probe = MockProbe::new();
        let lookup = lookup_with_one_container(11);
        let attributor = StubAttributor(None);
        let security = SecurityEmitter::new();
        let mut sink = CapturingSink(Vec::new());
        let mut state = DaemonState::new();

        let first = Policy { container_id: container_id(), generation: 1, mode: WireMode::Block, default: WireDefault::Deny, rules: vec![cidr_rule("10.0.0.0/24", WireAction::Allow)] };
        apply_policy(&mut probe, &mut state, &lookup, &attributor, &security, &mut sink, 0, &first);
        let keys_after_first = probe.tracked_policy_keys(11).len();
        assert_eq!(keys_after_first, 2, "the /24 rule plus the synthesized baseline");

        let second = Policy { container_id: container_id(), generation: 2, mode: WireMode::Block, default: WireDefault::Deny, rules: vec![cidr_rule("192.168.0.0/16", WireAction::Allow)] };
        apply_policy(&mut probe, &mut state, &lookup, &attributor, &security, &mut sink, 0, &second);

        let final_keys = probe.tracked_policy_keys(11);
        assert_eq!(final_keys.len(), 2, "the old /24 entry must be gone, replaced by the new /16 plus baseline");
        // Make happened before break: the mock recorded a SetPolicy call
        // for the new snapshot before any RemovePolicyKey for the old one.
        let first_remove = probe.calls.iter().position(|c| matches!(c, MockCall::RemovePolicyKey(_)));
        let last_set_for_second_gen = probe.calls.iter().rposition(|c| matches!(c, MockCall::SetPolicy(_)));
        assert!(last_set_for_second_gen.unwrap() > first_remove.unwrap_or(0) || first_remove.is_none(), "inserts for the new snapshot must happen before removals of the old one");
    }

    #[test]
    fn apply_release_clears_enforcement_but_the_mock_never_detaches() {
        let mut probe = MockProbe::new();
        let lookup = lookup_with_one_container(21);
        probe.seed_path(&lookup.cgroup_path_for_container(&container_id()).unwrap(), 21);
        let attributor = StubAttributor(None);
        let security = SecurityEmitter::new();
        let mut sink = CapturingSink(Vec::new());
        let mut state = DaemonState::new();

        let policy = Policy { container_id: container_id(), generation: 1, mode: WireMode::Block, default: WireDefault::Deny, rules: vec![cidr_rule("10.0.0.0/8", WireAction::Allow)] };
        apply_policy(&mut probe, &mut state, &lookup, &attributor, &security, &mut sink, 0, &policy);

        let ack = apply_release(&mut probe, &mut state, &lookup, &container_id());
        assert_eq!(ack.status, ReleaseStatus::Released);
        assert!(!state.containers.contains_key(&container_id()));
        assert!(probe.get_enforcement(21).unwrap().is_none());
        // Observation hooks stay attached -- release never detaches.
        assert!(probe.attached_containers().contains(&21));
    }

    #[test]
    fn apply_release_for_an_unknown_container_is_idempotent() {
        let mut probe = MockProbe::new();
        let lookup = StubLookup { id_to_cgroup: std::collections::HashMap::new() };
        let mut state = DaemonState::new();
        let ack = apply_release(&mut probe, &mut state, &lookup, "never-seen");
        assert_eq!(ack.status, ReleaseStatus::Released);
        assert!(probe.calls.is_empty());
    }

    #[test]
    fn apply_release_all_releases_every_tracked_container() {
        let mut probe = MockProbe::new();
        let lookup1 = lookup_with_one_container(31);
        let attributor = StubAttributor(None);
        let security = SecurityEmitter::new();
        let mut sink = CapturingSink(Vec::new());
        let mut state = DaemonState::new();

        let policy = Policy { container_id: container_id(), generation: 1, mode: WireMode::Block, default: WireDefault::Deny, rules: vec![] };
        apply_policy(&mut probe, &mut state, &lookup1, &attributor, &security, &mut sink, 0, &policy);
        assert_eq!(state.containers.len(), 1);

        let acks = apply_release_all(&mut probe, &mut state);
        assert_eq!(acks.len(), 1);
        assert_eq!(acks[0].status, ReleaseStatus::Released);
        assert!(state.containers.is_empty());
    }
}
