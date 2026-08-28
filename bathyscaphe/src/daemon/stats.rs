// SPDX-License-Identifier: GPL-3.0-or-later
//! The periodic `stats` heartbeat (`docs/PROTOCOL.md` section 5): emitted
//! every `stats_interval_s`, ALWAYS, even fully idle, so airlock can tell
//! "no traffic" from "probe wedged" (three missed intervals = probe
//! considered dead). Each tick also drives:
//!
//! - R1's `tamper.event_drops` record, whenever a container's `TAMPER`
//!   counter moved since the previous tick.
//! - R1's `enforce.blocked` THROTTLED SUMMARY, drained from a per-tick
//!   tally of deny-verdict events (fed by [`CountingSink`], which every
//!   `Event` the pipeline emits passes through on its way to stdout) --
//!   never one record per deny.
//! - R2's opt-in escalation (`super::r2`), layered on the same tamper
//!   delta.
//!
//! [`CountingSink`] is also where `stats.events_emitted` (cumulative)
//! comes from: it wraps whatever sink the pipeline was already handed
//! (chunk #6's `Sender<UpMessage>` impl of `EventSink`) and counts without
//! changing behavior otherwise.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use bathyscaphe_common::{DefaultVerdict, Mode};
use bathyscaphe_proto::security::{SecurityContainer, Severity};
use bathyscaphe_proto::{ContainerStats, Stats, Verdict};

use crate::attribution::Attributor;
use crate::pipeline::EventSink;

use super::probe_api::ProbeApi;
use super::r2::{DropEscalationConfig, DropTracker, EscalationAction, EscalationDecision};
use super::security::{enforce_blocked_summary_record, tamper_event_drops_record, SecurityEmitter};
use super::state::DaemonState;

/// Wraps an inner [`EventSink`] to count every `Event` message that passes
/// through (for `stats.events_emitted`) and tally deny-verdict events per
/// container id (for the throttled `enforce.blocked` summary), without
/// otherwise changing what reaches the inner sink.
pub struct CountingSink<S> {
    inner: S,
    events_emitted: Arc<AtomicU64>,
    denies_since_last: Arc<Mutex<HashMap<String, u64>>>,
}

impl<S: EventSink> CountingSink<S> {
    pub fn new(inner: S) -> (Self, Arc<AtomicU64>, Arc<Mutex<HashMap<String, u64>>>) {
        let events_emitted = Arc::new(AtomicU64::new(0));
        let denies_since_last = Arc::new(Mutex::new(HashMap::new()));
        (Self { inner, events_emitted: events_emitted.clone(), denies_since_last: denies_since_last.clone() }, events_emitted, denies_since_last)
    }
}

impl<S: EventSink> EventSink for CountingSink<S> {
    fn emit(&mut self, message: bathyscaphe_proto::UpMessage) {
        if let bathyscaphe_proto::UpMessage::Event(ref event) = message {
            self.events_emitted.fetch_add(1, Ordering::Relaxed);
            if event.verdict == Verdict::Deny {
                let mut denies = self.denies_since_last.lock().unwrap_or_else(|poison| poison.into_inner());
                *denies.entry(event.container.id.clone()).or_insert(0) += 1;
            }
        }
        self.inner.emit(message);
    }
}

pub(super) fn now_rfc3339() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
}

fn mode_to_wire(mode: Mode) -> bathyscaphe_proto::Mode {
    match mode {
        Mode::Audit => bathyscaphe_proto::Mode::Audit,
        Mode::Alert => bathyscaphe_proto::Mode::Alert,
        Mode::Block => bathyscaphe_proto::Mode::Block,
    }
}

/// The per-tick bookkeeping the stats thread owns: sequence number,
/// process start time, per-cgroup last-seen tamper totals (for the delta
/// R1/R2 need), and the R2 escalation tracker. Separate from
/// [`DaemonState`] because none of this is directive-driven state -- it is
/// purely this thread's own view of "what changed since last tick".
pub struct StatsRuntime {
    pub seq: u64,
    started_at: Instant,
    last_tamper_total: HashMap<u64, u64>,
    pub drop_tracker: DropTracker,
    events_emitted: Arc<AtomicU64>,
    denies_since_last: Arc<Mutex<HashMap<String, u64>>>,
}

impl StatsRuntime {
    pub fn new(events_emitted: Arc<AtomicU64>, denies_since_last: Arc<Mutex<HashMap<String, u64>>>) -> Self {
        Self { seq: 0, started_at: Instant::now(), last_tamper_total: HashMap::new(), drop_tracker: DropTracker::new(), events_emitted, denies_since_last }
    }
}

fn container_stats(probe: &dyn ProbeApi, state: &DaemonState) -> Vec<ContainerStats> {
    let mut out = Vec::with_capacity(state.containers.len());
    for container in state.containers.values() {
        let enforcing = probe.get_enforcement(container.cgroup_id).ok().flatten().map(|e| Mode::try_from(e.mode) == Ok(Mode::Block)).unwrap_or(false);
        let dropped_total = probe.read_tamper(container.cgroup_id).map(|t| t.events_dropped).unwrap_or(0);
        out.push(ContainerStats {
            id: container.container_id.clone(),
            mode: mode_to_wire(container.mode),
            generation: container.generation,
            enforcing,
            rules_active: container.rules_active,
            rules_inert: container.rules_inert,
            dropped_total,
            orphaned: container.orphaned,
        });
    }
    out
}

/// One heartbeat tick: builds and returns the `Stats` message, and as a
/// side effect runs the R1 tamper-drop / enforce-blocked-summary
/// accounting, the R2 escalation check, and (build chunk #10) the `POLICY`
/// TTL reaper. `stats_interval_s` is the negotiated cadence from
/// `start.stats_interval_s`, needed by R2's rate/window arithmetic.
/// `now_boottime_ns` is the real `CLOCK_BOOTTIME` reading this tick reaps
/// against -- injected rather than sampled internally so this function
/// stays testable with a synthetic clock, the same convention
/// `daemon::compile::compile_policy`'s `resolve_expiry` parameter uses.
#[allow(clippy::too_many_arguments)]
pub fn tick(runtime: &mut StatsRuntime, probe: &mut dyn ProbeApi, state: &mut DaemonState, attributor: &dyn Attributor, security: &SecurityEmitter, sink: &mut dyn EventSink, r2_config: &DropEscalationConfig, stats_interval_s: u64, now_boottime_ns: u64) -> Stats {
    runtime.seq += 1;
    let timestamp = now_rfc3339();
    let mut events_dropped_total = 0u64;

    if let Err(error) = probe.reap_expired_policy(now_boottime_ns) {
        eprintln!("bathyscaphe: POLICY TTL reap failed this tick ({error:#}); expired entries (if any) will be retried next tick");
    }

    for cgroup_id in probe.attached_containers() {
        let total = probe.read_tamper(cgroup_id).map(|t| t.events_dropped).unwrap_or(0);
        events_dropped_total += total;
        let previous = runtime.last_tamper_total.insert(cgroup_id, total).unwrap_or(0);
        let delta = total.saturating_sub(previous);

        let decision = runtime.drop_tracker.observe(cgroup_id, delta, stats_interval_s, r2_config);
        let severity = if matches!(decision, EscalationDecision::Escalate(_)) { Severity::Error } else { Severity::Warning };

        if delta > 0 {
            if let Some(container_id) = state.by_cgroup_id.get(&cgroup_id).cloned() {
                let attribution = attributor.resolve(cgroup_id);
                let (name, image) = attribution.as_ref().map(|a| (a.name.as_deref(), a.image.as_deref())).unwrap_or((None, None));
                let container = SecurityContainer { id: &container_id, name, image };
                security.try_emit(sink, tamper_event_drops_record(timestamp.clone(), container, delta, total, severity));
            }
        }

        if let EscalationDecision::Escalate(action) = decision {
            apply_escalation(action, cgroup_id, probe, state);
        }
    }

    let denies = {
        let mut map = runtime.denies_since_last.lock().unwrap_or_else(|poison| poison.into_inner());
        std::mem::take(&mut *map)
    };
    for (container_id, count) in denies {
        if count == 0 {
            continue;
        }
        let cgroup_id = state.containers.get(&container_id).map(|c| c.cgroup_id);
        let attribution = cgroup_id.and_then(|id| attributor.resolve(id));
        let (name, image) = attribution.as_ref().map(|a| (a.name.as_deref(), a.image.as_deref())).unwrap_or((None, None));
        let container = SecurityContainer { id: &container_id, name, image };
        security.try_emit(sink, enforce_blocked_summary_record(timestamp.clone(), container, count));
    }

    Stats { ts: timestamp, seq: runtime.seq, uptime_s: runtime.started_at.elapsed().as_secs(), events_emitted: runtime.events_emitted.load(Ordering::Relaxed), events_dropped_total, containers: container_stats(probe, state) }
}

/// Applies an R2 escalation decision. [`EscalationAction::Exit`] calls
/// `std::process::exit` DIRECTLY, deliberately, rather than returning a
/// value the caller might route through ordinary cleanup: `process::exit`
/// skips destructors, which is exactly what "preserve pins on this exit
/// path" requires here -- there is no unpin/detach call anywhere between
/// this decision and the process actually stopping to accidentally run.
fn apply_escalation(action: EscalationAction, cgroup_id: u64, probe: &mut dyn ProbeApi, state: &mut DaemonState) {
    match action {
        EscalationAction::Lockdown => {
            let Some(container_id) = state.by_cgroup_id.get(&cgroup_id).cloned() else { return };
            let generation = state.containers.get(&container_id).map(|c| c.generation).unwrap_or(0);
            if let Err(error) = probe.set_enforcement(cgroup_id, Mode::Block, DefaultVerdict::Deny, generation) {
                eprintln!("bathyscaphe: R2 lockdown escalation failed to write ENFORCEMENT for cgroup {cgroup_id:016x} ({error})");
                return;
            }
            if let Some(c) = state.containers.get_mut(&container_id) {
                c.mode = Mode::Block;
                c.default = DefaultVerdict::Deny;
            }
            eprintln!("bathyscaphe: R2 escalation: container {container_id} (cgroup {cgroup_id:016x}) exceeded its sustained drop threshold; placed into full lockdown (mode=block, default=deny)");
        }
        EscalationAction::Exit => {
            eprintln!("bathyscaphe: R2 escalation: cgroup {cgroup_id:016x} exceeded its sustained drop threshold; exiting per the configured action (pins preserved, enforcement continues)");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attribution::Attribution;
    use crate::daemon::probe_api::MockProbe;
    use crate::daemon::state::ContainerState;
    use bathyscaphe_common::PolicyValue;
    use bathyscaphe_proto::UpMessage;
    use std::net::IpAddr;

    struct StubAttributor;
    impl Attributor for StubAttributor {
        fn resolve(&self, _cgroup_id: u64) -> Option<Attribution> {
            Some(Attribution { container_id: "c1".repeat(1), name: Some("web".to_string()), image: Some("nginx:latest".to_string()), runtime: bathyscaphe_proto::Runtime::Docker })
        }
    }

    struct CapturingSink(Vec<UpMessage>);
    impl EventSink for CapturingSink {
        fn emit(&mut self, message: UpMessage) {
            self.0.push(message);
        }
    }

    struct NoopSink;
    impl EventSink for NoopSink {
        fn emit(&mut self, _: UpMessage) {}
    }

    fn seeded_probe_and_state() -> (MockProbe, DaemonState) {
        let mut probe = MockProbe::new();
        probe.attached.insert(1);
        probe.set_enforcement(1, Mode::Block, DefaultVerdict::Deny, 3).unwrap();
        probe.set_policy(1, IpAddr::from([10, 0, 0, 0]), 0, PolicyValue::new(1, 0, 0)).unwrap();
        let mut state = DaemonState::new();
        state.upsert(ContainerState { container_id: "c1".to_string(), cgroup_id: 1, mode: Mode::Block, generation: 3, default: DefaultVerdict::Deny, rules_active: 1, rules_inert: 0, orphaned: false });
        (probe, state)
    }

    #[test]
    fn a_heartbeat_is_produced_even_with_no_drops_or_events() {
        let (mut probe, mut state) = seeded_probe_and_state();
        let attributor = StubAttributor;
        let security = SecurityEmitter::new();
        let mut sink = CapturingSink(Vec::new());
        let (_counting, events_emitted, denies) = CountingSink::new(NoopSink);
        let mut runtime = StatsRuntime::new(events_emitted, denies);

        let stats = tick(&mut runtime, &mut probe, &mut state, &attributor, &security, &mut sink, &DropEscalationConfig::default(), 10, 0);
        assert_eq!(stats.seq, 1);
        assert_eq!(stats.containers.len(), 1);
        assert_eq!(stats.containers[0].id, "c1");
        assert!(stats.containers[0].enforcing);
        assert!(!stats.containers[0].orphaned);
    }

    #[test]
    fn a_tamper_delta_emits_a_throttled_security_record() {
        let (mut probe, mut state) = seeded_probe_and_state();
        probe.tamper.insert(1, bathyscaphe_common::TamperCounter::new(5));
        let attributor = StubAttributor;
        let security = SecurityEmitter::new();
        let mut sink = CapturingSink(Vec::new());
        let (_counting, events_emitted, denies) = CountingSink::new(NoopSink);
        let mut runtime = StatsRuntime::new(events_emitted, denies);

        let stats = tick(&mut runtime, &mut probe, &mut state, &attributor, &security, &mut sink, &DropEscalationConfig::default(), 10, 0);
        assert_eq!(stats.events_dropped_total, 5);
        assert_eq!(stats.containers[0].dropped_total, 5);
        assert_eq!(sink.0.len(), 1);
        assert!(matches!(sink.0[0], UpMessage::Security(_)));
    }

    #[test]
    fn r2_lockdown_escalation_sets_full_block_enforcement() {
        let (mut probe, mut state) = seeded_probe_and_state();
        // Start the container out of lockdown (audit/allow) so the test can
        // observe R2 actually change it.
        probe.set_enforcement(1, Mode::Audit, DefaultVerdict::Allow, 3).unwrap();
        state.containers.get_mut("c1").unwrap().mode = Mode::Audit;
        state.containers.get_mut("c1").unwrap().default = DefaultVerdict::Allow;
        probe.tamper.insert(1, bathyscaphe_common::TamperCounter::new(1000));

        let attributor = StubAttributor;
        let security = SecurityEmitter::new();
        let mut sink = CapturingSink(Vec::new());
        let (_counting, events_emitted, denies) = CountingSink::new(NoopSink);
        let mut runtime = StatsRuntime::new(events_emitted, denies);
        let config = DropEscalationConfig { enabled: true, threshold_per_sec: 1.0, window_s: 1, action: EscalationAction::Lockdown };

        tick(&mut runtime, &mut probe, &mut state, &attributor, &security, &mut sink, &config, 1, 0);

        let enforcement = probe.get_enforcement(1).unwrap().unwrap();
        assert_eq!(Mode::try_from(enforcement.mode).unwrap(), Mode::Block);
        assert_eq!(DefaultVerdict::try_from(enforcement.default_verdict).unwrap(), DefaultVerdict::Deny);
        assert_eq!(state.containers["c1"].mode, Mode::Block);
    }

    #[test]
    fn enforce_blocked_summary_counts_denies_since_last_tick_as_one_record() {
        let (mut probe, mut state) = seeded_probe_and_state();
        let attributor = StubAttributor;
        let security = SecurityEmitter::new();
        let mut sink = CapturingSink(Vec::new());
        let (mut counting, events_emitted, denies) = CountingSink::new(NoopSink);
        let mut runtime = StatsRuntime::new(events_emitted, denies);

        // Simulate 3 denied connect events for container c1 passing
        // through the counting sink before this tick runs.
        for _ in 0..3 {
            counting.emit(UpMessage::Event(bathyscaphe_proto::Event {
                ts: "2026-08-27T00:00:00Z".to_string(),
                event: bathyscaphe_proto::EventKind::Connect,
                proto: bathyscaphe_proto::TransportProto::Tcp,
                container: bathyscaphe_proto::Container { id: "c1".to_string(), name: None, image: None, runtime: bathyscaphe_proto::Runtime::Docker },
                process: bathyscaphe_proto::Process { pid: None, tid: None, uid: None, gid: None, comm: None },
                src: bathyscaphe_proto::Endpoint { addr: IpAddr::from([0, 0, 0, 0]), port: 0 },
                dst: bathyscaphe_proto::Endpoint { addr: IpAddr::from([0, 0, 0, 0]), port: 0 },
                verdict: Verdict::Deny,
                rule_id: None,
                domain: bathyscaphe_proto::Domain::unresolved(),
                meta: bathyscaphe_proto::EventMeta { dropped_since_last: 0 },
            }));
        }

        let stats = tick(&mut runtime, &mut probe, &mut state, &attributor, &security, &mut sink, &DropEscalationConfig::default(), 10, 0);
        assert_eq!(stats.events_emitted, 3);
        assert_eq!(sink.0.len(), 1, "3 denies collapse into exactly one throttled summary record");
        let UpMessage::Security(record) = &sink.0[0] else { panic!("expected a security record") };
        assert_eq!(record.attributes.get("denied_count").unwrap(), 3);
    }

    #[test]
    fn a_tick_reaps_an_expired_policy_entry() {
        // Build chunk #10: the periodic tick this test drives directly is
        // exactly the wiring `daemon::mod::spawn_stats_thread` runs on a
        // real cadence -- this proves the reaper actually fires from that
        // call site's shape, using a synthetic `now_boottime_ns` rather
        // than a real clock/thread/sleep.
        let (mut probe, mut state) = seeded_probe_and_state();
        probe.set_policy(1, IpAddr::from([93, 184, 216, 34]), 128, bathyscaphe_common::PolicyValue::new(0, bathyscaphe_common::RuleSource::Dns as u8, 500)).unwrap();
        assert_eq!(probe.tracked_policy_keys(1).len(), 2, "the baseline entry plus the short-lived DNS host route");

        let attributor = StubAttributor;
        let security = SecurityEmitter::new();
        let mut sink = CapturingSink(Vec::new());
        let (_counting, events_emitted, denies) = CountingSink::new(NoopSink);
        let mut runtime = StatsRuntime::new(events_emitted, denies);

        // now_boottime_ns (1000) is past the DNS entry's expires_at_ns
        // (500) but this test's OTHER seeded policy entry never expires
        // (NEVER_EXPIRES == 0), so only the one entry should be reaped.
        tick(&mut runtime, &mut probe, &mut state, &attributor, &security, &mut sink, &DropEscalationConfig::default(), 10, 1000);

        assert_eq!(probe.tracked_policy_keys(1).len(), 1, "the expired DNS host route must be gone; the never-expiring baseline entry must remain");
    }
}
