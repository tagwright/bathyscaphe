// SPDX-License-Identifier: GPL-3.0-or-later
//! The one policy decision + event-emission routine shared by all four
//! `cgroup/{connect,sendmsg}{4,6}` hooks (`bathy_ebpf_design.md` section
//! 2, "one hook, two output paths"). Written once here so enforcement and
//! observation can never drift between the four attach points, per the
//! same rationale `bathyscaphe_common::event`'s module doc gives for
//! `Event::verdict` vs `Event::would_deny` being two separate fields.

use aya_ebpf::{
    helpers::{bpf_get_current_cgroup_id, bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_ktime_get_boot_ns},
    maps::lpm_trie::Key,
};
use bathyscaphe_common::{DefaultVerdict, Event, EventType, Mode, PolicyKeyData, PolicyValue, RuleAction, TamperCounter, Verdict};

use crate::maps::{ENFORCEMENT, EVENTS, POLICY, TAMPER};

/// The destination-tuple inputs common to connect4/connect6/sendmsg4/sendmsg6.
pub struct DestTuple {
    pub dst_addr: [u8; 16],
    pub dst_port: [u8; 2],
    pub proto: u8,
}

/// Runs the full observe+enforce decision for one connect/sendmsg
/// invocation and returns the kernel verdict to hand back to the caller:
/// `1` (allow) or `0` (deny, surfaces as `EPERM`).
pub fn decide_and_emit(dest: DestTuple, event_type: EventType) -> i32 {
    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };

    // Absence of an EnforcementState entry means "no posture configured
    // for this cgroup at all" -- per that struct's own module doc, this
    // is cold-start/never-adopted, full observe-only-with-no-lookup: the
    // policy trie is not even consulted, matching the fail-closed design
    // brief's "cold start attaches no enforcement" invariant (nothing to
    // enforce against until a real directive lands).
    let (verdict, would_deny) = match unsafe { ENFORCEMENT.get(cgroup_id) } {
        None => (Verdict::Allow, false),
        Some(es) => {
            let deny = evaluate_policy(cgroup_id, dest.dst_addr, dest.dst_port, dest.proto, es.default_verdict);
            let verdict = if es.mode == Mode::Block as u8 && deny { Verdict::Deny } else { Verdict::Allow };
            (verdict, deny)
        }
    };

    emit_event(cgroup_id, &dest, verdict, would_deny, event_type);

    if verdict == Verdict::Deny { 0 } else { 1 }
}

/// The honest policy lookup, independent of what gets returned to the
/// caller. See `bathyscaphe_common::policy`'s module doc for the flat
/// `LpmTrie` layout and the expiry-lookup limitation this implements.
fn evaluate_policy(cgroup_id: u64, dst_addr: [u8; 16], dst_port: [u8; 2], proto: u8, default_verdict: u8) -> bool {
    let lookup_key = Key::new(PolicyKeyData::PREFIX_LEN_FULL, PolicyKeyData::new(cgroup_id, dst_addr));

    let Some(pv) = POLICY.get(&lookup_key) else {
        return default_verdict == DefaultVerdict::Deny as u8;
    };

    let now = unsafe { bpf_ktime_get_boot_ns() };
    if pv.expires_at_ns != 0 && pv.expires_at_ns < now {
        // Known simplification: an expired entry falls straight through
        // to the container default, not to the next less-specific
        // still-valid prefix underneath it -- see the module doc on
        // bathyscaphe_common::policy.
        return default_verdict == DefaultVerdict::Deny as u8;
    }

    let port = u16::from_be_bytes(dst_port);
    let mut any_deny = false;
    let mut any_allow = false;
    let n = pv.n_port_rules as usize;
    // Bounded loop over the fixed-size array -- verifier-friendly by
    // construction, no runtime-dependent trip count.
    for i in 0..PolicyValue::MAX_PORT_RULES {
        if i >= n {
            break;
        }
        let rule = pv.port_rules[i];
        if rule.matches_proto(proto) && rule.matches_port(port) {
            if rule.action == RuleAction::Deny as u8 {
                any_deny = true;
            } else {
                any_allow = true;
            }
        }
    }

    if any_deny {
        true
    } else if any_allow {
        false
    } else {
        pv.cidr_default_action == RuleAction::Deny as u8
    }
}

fn emit_event(cgroup_id: u64, dest: &DestTuple, verdict: Verdict, would_deny: bool, event_type: EventType) {
    let pid_tgid = bpf_get_current_pid_tgid();
    let uid_gid = bpf_get_current_uid_gid();
    let comm = bpf_get_current_comm().unwrap_or([0u8; 16]);
    let ktime_ns = unsafe { bpf_ktime_get_boot_ns() };

    let event = Event {
        ktime_ns,
        cgroup_id,
        pid: (pid_tgid >> 32) as u32,
        tid: pid_tgid as u32,
        uid: uid_gid as u32,
        gid: (uid_gid >> 32) as u32,
        comm,
        // Not collected in v1 -- see convert.rs's module doc.
        src_addr: [0u8; 16],
        src_port: [0u8; 2],
        dst_addr: dest.dst_addr,
        dst_port: dest.dst_port,
        proto: dest.proto,
        verdict: verdict as u8,
        would_deny: would_deny as u8,
        event_type: event_type as u8,
    };

    match EVENTS.reserve::<Event>(0) {
        Some(mut entry) => {
            entry.write(event);
            entry.submit(0);
        }
        None => bump_tamper_counter(cgroup_id),
    }
}

/// Bump (or initialize) the per-cgroup dropped-event counter on a
/// `RingBuf` reserve failure. Non-atomic read-modify-write: an
/// occasional undercount under heavy concurrent contention on the same
/// cgroup is an accepted imprecision for a "something is dropping
/// events, go look" signal, not a value anything security-critical is
/// computed from bit-exactly.
fn bump_tamper_counter(cgroup_id: u64) {
    match TAMPER.get_ptr_mut(cgroup_id) {
        Some(ptr) => unsafe { (*ptr).events_dropped += 1 },
        None => {
            let _ = TAMPER.insert(cgroup_id, TamperCounter::new(1), 0);
        }
    }
}
