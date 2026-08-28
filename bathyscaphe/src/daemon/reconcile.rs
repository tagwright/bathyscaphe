// SPDX-License-Identifier: GPL-3.0-or-later
//! The `sync_complete` orphan-marking pass (`docs/PROTOCOL.md` section 6):
//! after airlock has re-pushed every snapshot it manages on `start` ->
//! resync, anything this process found ENFORCING in the kernel that
//! received neither a `policy` nor a `release` in between is orphaned --
//! kept enforcing exactly as pinned (fail-closed), never auto-dropped, and
//! surfaced in `stats.containers[].orphaned` until airlock or an operator
//! explicitly adopts or releases it.

use bathyscaphe_common::{DefaultVerdict, Mode};

use super::probe_api::ProbeApi;
use super::state::{ContainerState, DaemonState};

/// Runs the orphan-marking pass and resets the coverage set for the next
/// reconciliation round. `resolve_container_id` is the attribution
/// fallback for a cgroup this process has enforcement pinned for but no
/// [`ContainerState`] entry yet (a pinned-from-a-previous-process
/// container rediscovered at startup, never before seen this session) --
/// typically `Resolver::resolve(..).map(|a| a.container_id)`, injected as
/// a closure so this stays testable with no attribution machinery.
pub fn mark_orphans(state: &mut DaemonState, probe: &dyn ProbeApi, resolve_container_id: impl Fn(u64) -> Option<String>) {
    for cgroup_id in probe.attached_containers() {
        let Ok(Some(enforcement)) = probe.get_enforcement(cgroup_id) else {
            // No enforcement configured for this cgroup at all -- an
            // observe-only attachment, not a reconciliation concern.
            continue;
        };

        let container_id = state.by_cgroup_id.get(&cgroup_id).cloned().or_else(|| resolve_container_id(cgroup_id));
        let Some(container_id) = container_id else {
            eprintln!("bathyscaphe: cgroup {cgroup_id:016x} has enforcement pinned but no attributable container id; cannot report it in reconciliation");
            continue;
        };

        if state.covered_since_last_sync.contains(&container_id) {
            continue;
        }

        // Not covered this round: orphaned. Build (or refresh) its
        // ContainerState from kernel ground truth, preserving whatever
        // rules_active/rules_inert the daemon last knew (kernel truth
        // alone cannot recover "how many of these were inert").
        let (rules_active, rules_inert) = state.containers.get(&container_id).map(|c| (c.rules_active, c.rules_inert)).unwrap_or_else(|| (probe.tracked_policy_keys(cgroup_id).len() as u32, 0));

        let mode = Mode::try_from(enforcement.mode).unwrap_or(Mode::Audit);
        let default = DefaultVerdict::try_from(enforcement.default_verdict).unwrap_or(DefaultVerdict::Deny);

        state.by_cgroup_id.insert(cgroup_id, container_id.clone());
        state.containers.insert(container_id.clone(), ContainerState { container_id, cgroup_id, mode, generation: enforcement.generation, default, rules_active, rules_inert, orphaned: true });
    }

    state.covered_since_last_sync.clear();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon::probe_api::MockProbe;
    use bathyscaphe_common::PolicyValue;

    fn attach_with_enforcement(probe: &mut MockProbe, cgroup_id: u64, mode: Mode, generation: u64) {
        probe.attached.insert(cgroup_id);
        probe.set_enforcement(cgroup_id, mode, DefaultVerdict::Deny, generation).unwrap();
        probe.set_policy(cgroup_id, std::net::IpAddr::from([0, 0, 0, 0]), 0, PolicyValue::new(1, 0, 0)).unwrap();
    }

    #[test]
    fn a_cgroup_covered_by_a_policy_this_round_is_not_orphaned() {
        let mut probe = MockProbe::new();
        attach_with_enforcement(&mut probe, 100, Mode::Block, 1);

        let mut state = DaemonState::new();
        state.upsert(ContainerState {
            container_id: "c1".to_string(),
            cgroup_id: 100,
            mode: Mode::Block,
            generation: 1,
            default: DefaultVerdict::Deny,
            rules_active: 1,
            rules_inert: 0,
            orphaned: false,
        });

        mark_orphans(&mut state, &probe, |_| None);
        assert!(!state.containers["c1"].orphaned);
    }

    #[test]
    fn a_pinned_cgroup_not_covered_this_round_is_marked_orphaned() {
        let mut probe = MockProbe::new();
        attach_with_enforcement(&mut probe, 200, Mode::Block, 5);

        let mut state = DaemonState::new();
        // Simulate a previous session's tracked state that was NOT
        // re-covered by a `policy`/`release` before `sync_complete` fired.
        state.containers.insert(
            "c2".to_string(),
            ContainerState { container_id: "c2".to_string(), cgroup_id: 200, mode: Mode::Block, generation: 5, default: DefaultVerdict::Deny, rules_active: 1, rules_inert: 0, orphaned: false },
        );
        state.by_cgroup_id.insert(200, "c2".to_string());
        // covered_since_last_sync deliberately left empty for "c2".

        mark_orphans(&mut state, &probe, |_| None);
        assert!(state.containers["c2"].orphaned, "uncovered pinned enforcement must be marked orphaned, never silently dropped");
        // And it is still enforcing in the mock -- reconciliation never
        // clears enforcement itself.
        assert!(probe.get_enforcement(200).unwrap().is_some());
    }

    #[test]
    fn a_rediscovered_container_with_no_prior_container_state_is_attributed_via_the_fallback() {
        let mut probe = MockProbe::new();
        attach_with_enforcement(&mut probe, 300, Mode::Block, 9);

        let mut state = DaemonState::new();
        mark_orphans(&mut state, &probe, |cgroup_id| if cgroup_id == 300 { Some("c3".to_string()) } else { None });

        let entry = state.containers.get("c3").expect("the fallback resolver's attribution should have created an entry");
        assert!(entry.orphaned);
        assert_eq!(entry.generation, 9);
    }

    #[test]
    fn an_observe_only_attachment_with_no_enforcement_is_never_orphaned() {
        let mut probe = MockProbe::new();
        probe.attached.insert(400); // attached, but no set_enforcement call at all

        let mut state = DaemonState::new();
        mark_orphans(&mut state, &probe, |_| None);
        assert!(state.containers.is_empty(), "observe-only attachment is not a reconciliation concern");
    }

    #[test]
    fn the_coverage_set_is_reset_for_the_next_reconciliation_round() {
        let mut probe = MockProbe::new();
        attach_with_enforcement(&mut probe, 500, Mode::Block, 1);

        let mut state = DaemonState::new();
        state.covered_since_last_sync.insert("c5".to_string());
        mark_orphans(&mut state, &probe, |_| None);
        assert!(state.covered_since_last_sync.is_empty());
    }
}
