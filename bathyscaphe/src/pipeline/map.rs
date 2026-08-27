// SPDX-License-Identifier: GPL-3.0-or-later
//! Pure kernel-`Event` -> wire-`Event` mapping, unit-testable with no ring
//! buffer, no cgroup tree, and no Docker socket in sight.

use std::net::{IpAddr, Ipv6Addr};

use bathyscaphe_common::enums::Verdict as KernelVerdict;
use bathyscaphe_proto::{Container, Domain, DomainSource, Endpoint, Event as WireEvent, EventMeta, Process, Verdict as WireVerdict};

use crate::attribution::Attributor;

use super::dropped::DroppedTracker;
use super::sink::{DomainLookupSource, TamperSource};

/// Maps one kernel-observed `Event` onto the wire protocol's `Event`, or
/// `None` if attribution came back completely empty -- the one case where
/// this pipeline does not emit, since `Container.id` is a required,
/// non-nullable wire field and there is nothing honest to put in it. This
/// is NOT the same thing as a ring-buffer drop: it does not touch
/// `dropped_since_last`/`events_dropped_total`, and per
/// `bathy_attribution.md` it should not happen in practice for an event
/// that reached bathyscaphe's own ring buffer at all (every hook is
/// attached to a cgroup this process already resolved once, to attach to
/// it) -- see [`Attributor::resolve`]'s doc for exactly when it can still
/// occur.
pub fn map_event(kernel_event: &bathyscaphe_common::Event, attributor: &impl Attributor, tamper: &impl TamperSource, domain_lookup: &impl DomainLookupSource, dropped: &DroppedTracker, boot_offset_ns: i128) -> Option<WireEvent> {
    let attribution = attributor.resolve(kernel_event.cgroup_id)?;

    let container = Container { id: attribution.container_id, name: attribution.name, image: attribution.image, runtime: attribution.runtime };
    let process = decode_process(kernel_event);
    let proto = decode_proto(kernel_event.proto);
    let event = decode_event_kind(kernel_event.event_type);
    let verdict = decode_verdict(kernel_event.verdict, kernel_event.would_deny);
    let src = Endpoint { addr: unmap_addr(kernel_event.src_addr), port: u16::from_be_bytes(kernel_event.src_port) };
    let dst = Endpoint { addr: unmap_addr(kernel_event.dst_addr), port: u16::from_be_bytes(kernel_event.dst_port) };
    let ts = format_ts(kernel_event.ktime_ns, boot_offset_ns);
    // The DNS cache lookup uses the connect event's OWN kernel timestamp as
    // "now", not a freshly sampled clock -- see `DomainCache::lookup`'s
    // doc for why this is the semantically correct choice (was the DNS
    // answer still fresh AT THE MOMENT of this specific connection).
    let domain = decode_domain(domain_lookup, kernel_event.cgroup_id, dst.addr, kernel_event.ktime_ns);

    let current_total = match tamper.read_tamper(kernel_event.cgroup_id) {
        Ok(counter) => counter.events_dropped,
        Err(error) => {
            eprintln!("bathyscaphe: TAMPER read failed for cgroup {:016x} ({error}); treating this event's drop delta as 0", kernel_event.cgroup_id);
            0
        }
    };
    let dropped_since_last = dropped.delta(kernel_event.cgroup_id, current_total);

    Some(WireEvent {
        ts,
        event,
        proto,
        container,
        process,
        src,
        dst,
        verdict,
        // bathyscaphe-ebpf's `Event` struct (chunk #4) carries no rule-id
        // field at all yet -- this build genuinely does not track it, the
        // documented `rule_id: None` case in docs/PROTOCOL.md section 3.
        rule_id: None,
        domain,
        meta: EventMeta { dropped_since_last },
    })
}

/// `pid`/`tid` of `0` is not a value `bpf_get_current_pid_tgid()` can
/// legitimately produce for a task making a syscall (pid/tid 0 is reserved
/// for the kernel's own idle/swapper task, which never calls `connect()`),
/// so `0` there means "not resolved" and maps to `None`, per
/// `bathyscaphe_common::event`'s module doc. `uid`/`gid` do NOT get the same
/// treatment: `0` is root, a completely ordinary and common value for a
/// container process to run as, not a sentinel -- `bpf_get_current_uid_gid()`
/// always returns something for a live task, so these are always `Some`.
fn decode_process(kernel_event: &bathyscaphe_common::Event) -> Process {
    Process {
        pid: (kernel_event.pid != 0).then_some(kernel_event.pid),
        tid: (kernel_event.tid != 0).then_some(kernel_event.tid),
        uid: Some(kernel_event.uid),
        gid: Some(kernel_event.gid),
        comm: decode_comm(&kernel_event.comm),
    }
}

/// `bpf_get_current_comm()`'s `TASK_COMM_LEN`-16 buffer, NUL-terminated
/// when the name is short enough to leave room, not necessarily otherwise
/// (`bathyscaphe_common::event`'s module doc). Take bytes up to the first
/// NUL (or all 16, if none), lossily decode (`comm` is not guaranteed valid
/// UTF-8 in general), and treat an empty result as unresolved.
fn decode_comm(raw: &[u8; 16]) -> Option<String> {
    let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
    if end == 0 {
        return None;
    }
    Some(String::from_utf8_lossy(&raw[..end]).into_owned())
}

fn decode_proto(raw: u8) -> bathyscaphe_proto::TransportProto {
    match bathyscaphe_common::enums::TransportProto::try_from(raw) {
        Ok(bathyscaphe_common::enums::TransportProto::Tcp) => bathyscaphe_proto::TransportProto::Tcp,
        Ok(bathyscaphe_common::enums::TransportProto::Udp) => bathyscaphe_proto::TransportProto::Udp,
        Err(bathyscaphe_common::InvalidDiscriminant(byte)) => {
            eprintln!("bathyscaphe: kernel event carried an invalid proto discriminant {byte}; defaulting to tcp");
            bathyscaphe_proto::TransportProto::Tcp
        }
    }
}

fn decode_event_kind(raw: u8) -> bathyscaphe_proto::EventKind {
    match bathyscaphe_common::EventType::try_from(raw) {
        Ok(bathyscaphe_common::EventType::Connect) => bathyscaphe_proto::EventKind::Connect,
        Ok(bathyscaphe_common::EventType::Accept) => bathyscaphe_proto::EventKind::Accept,
        Ok(bathyscaphe_common::EventType::Close) => bathyscaphe_proto::EventKind::Close,
        Err(bathyscaphe_common::InvalidDiscriminant(byte)) => {
            eprintln!("bathyscaphe: kernel event carried an invalid event_type discriminant {byte}; defaulting to connect");
            bathyscaphe_proto::EventKind::Connect
        }
    }
}

/// The three-valued wire `Verdict` reconstruction rule, exactly as
/// documented in `bathyscaphe_common::event`'s and `enums::Verdict`'s
/// module docs: `Deny` if the kernel's own `verdict` byte is `Deny`,
/// else `WouldDeny` if the honest policy-lookup result (`would_deny`) says
/// so, else `Allow`. Compared against the raw `Deny` discriminant directly
/// rather than routing through `TryFrom` first, since this rule is defined
/// in terms of "was the byte exactly `Deny`", not "decode the byte as a
/// `Verdict` and match" -- a corrupted byte that happens to equal neither
/// `Allow` nor `Deny` still falls through correctly to the `would_deny`
/// check instead of needing a third error arm here.
fn decode_verdict(raw_verdict: u8, would_deny: u8) -> WireVerdict {
    if raw_verdict == KernelVerdict::Deny as u8 {
        WireVerdict::Deny
    } else if would_deny != 0 {
        WireVerdict::WouldDeny
    } else {
        WireVerdict::Allow
    }
}

/// `domain.*` enrichment (build chunk #9): a cache hit on `dst_addr` for
/// this event's container populates `name`/`source: dns`/`confidence`;
/// a miss (never resolved, resolved via DoH/DoT and therefore invisible to
/// the snoop, raw-IP egress with no DNS lookup at all, or an entry past
/// its grace window) emits the all-null [`Domain::unresolved`] shape --
/// see `docs/DNS.md`'s "why `domain` is null" list for the full account of
/// the causes this single `None` branch collapses.
fn decode_domain(domain_lookup: &impl DomainLookupSource, cgroup_id: u64, dst_addr: std::net::IpAddr, now_boottime_ns: u64) -> Domain {
    match domain_lookup.lookup_domain(cgroup_id, dst_addr, now_boottime_ns) {
        Some(hit) => Domain { name: Some(hit.name), source: Some(DomainSource::Dns), confidence: Some(hit.confidence) },
        None => Domain::unresolved(),
    }
}

/// `bathyscaphe_common::event::Event::src_addr`/`dst_addr` carry an
/// IPv4-mapped-into-IPv6 embedding (RFC 4291) for a v4 address, matching
/// `bathyscaphe_common::policy::PolicyKeyData::addr`'s convention.
/// `Ipv6Addr::to_ipv4_mapped` is the standard library's own implementation
/// of exactly that unmapping.
fn unmap_addr(raw: [u8; 16]) -> IpAddr {
    let v6 = Ipv6Addr::from(raw);
    v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(IpAddr::V6(v6))
}

/// `bpf_ktime_get_boot_ns()` (kernel, `CLOCK_BOOTTIME`) plus a wall-clock
/// offset sampled once at process start (see
/// [`super::sample_boot_offset_ns`]) gives the event's wall-clock instant;
/// formatted as RFC3339 with (at minimum) microsecond precision, per
/// `docs/PROTOCOL.md` section 3. `time`'s nanosecond-precision `Rfc3339`
/// formatter already exceeds that floor.
fn format_ts(ktime_ns: u64, boot_offset_ns: i128) -> String {
    let unix_ns = boot_offset_ns.saturating_add(i128::from(ktime_ns));
    time::OffsetDateTime::from_unix_timestamp_nanos(unix_ns)
        .ok()
        .and_then(|dt| dt.format(&time::format_description::well_known::Rfc3339).ok())
        .unwrap_or_else(|| {
            eprintln!("bathyscaphe: could not format event timestamp (ktime_ns={ktime_ns}, boot_offset_ns={boot_offset_ns}); this should not happen on a sane clock");
            "1970-01-01T00:00:00Z".to_string()
        })
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use bathyscaphe_common::TamperCounter;

    use crate::attribution::Attribution;

    use super::*;

    struct StubAttributor(Option<Attribution>);
    impl Attributor for StubAttributor {
        fn resolve(&self, _cgroup_id: u64) -> Option<Attribution> {
            self.0.clone()
        }
    }

    struct StubTamper(u64);
    impl TamperSource for StubTamper {
        fn read_tamper(&self, _cgroup_id: u64) -> anyhow::Result<TamperCounter> {
            Ok(TamperCounter::new(self.0))
        }
    }

    struct StubDomainLookup(Option<crate::dns::DomainHit>);
    impl DomainLookupSource for StubDomainLookup {
        fn lookup_domain(&self, _cgroup_id: u64, _addr: IpAddr, _now_boottime_ns: u64) -> Option<crate::dns::DomainHit> {
            self.0.clone()
        }
    }

    fn no_domain() -> StubDomainLookup {
        StubDomainLookup(None)
    }

    fn docker_attribution() -> Attribution {
        Attribution { container_id: "a".repeat(64), name: Some("web".to_string()), image: Some("nginx:latest".to_string()), runtime: bathyscaphe_proto::Runtime::Docker }
    }

    #[test]
    fn verdict_allow_when_not_denied_and_would_not_deny() {
        assert_eq!(decode_verdict(0, 0), WireVerdict::Allow);
    }

    #[test]
    fn verdict_would_deny_in_observe_mode_when_policy_lookup_says_deny() {
        // verdict == Allow (the hook always returns allow to the kernel in
        // observe/audit/alert), would_deny == 1 (the honest lookup result).
        assert_eq!(decode_verdict(bathyscaphe_common::enums::Verdict::Allow as u8, 1), WireVerdict::WouldDeny);
    }

    #[test]
    fn verdict_deny_in_block_mode() {
        assert_eq!(decode_verdict(bathyscaphe_common::enums::Verdict::Deny as u8, 1), WireVerdict::Deny);
        // Deny wins even if would_deny were somehow 0 -- the actual kernel
        // action taken is definitionally the wire verdict here.
        assert_eq!(decode_verdict(bathyscaphe_common::enums::Verdict::Deny as u8, 0), WireVerdict::Deny);
    }

    #[test]
    fn v4_in_v6_address_unmaps_to_ipv4() {
        let mut raw = [0u8; 16];
        raw[10] = 0xff;
        raw[11] = 0xff;
        raw[12..16].copy_from_slice(&[93, 184, 216, 34]);
        assert_eq!(unmap_addr(raw), IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)));
    }

    #[test]
    fn native_v6_address_stays_v6() {
        let raw = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let IpAddr::V6(got) = unmap_addr(raw) else { panic!("expected a native v6 address to stay v6") };
        assert_eq!(got, Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1));
    }

    #[test]
    fn comm_decodes_a_nul_terminated_name() {
        let mut raw = [0u8; 16];
        raw[..4].copy_from_slice(b"curl");
        assert_eq!(decode_comm(&raw), Some("curl".to_string()));
    }

    #[test]
    fn comm_decodes_a_name_filling_the_whole_buffer_with_no_nul() {
        let raw: [u8; 16] = *b"exactly-16-chars";
        assert_eq!(decode_comm(&raw), Some("exactly-16-chars".to_string()));
    }

    #[test]
    fn comm_all_zero_is_none() {
        assert_eq!(decode_comm(&[0u8; 16]), None);
    }

    #[test]
    fn pid_zero_is_unresolved_but_uid_zero_is_root_not_unresolved() {
        let mut kernel_event = bathyscaphe_common::Event::default();
        kernel_event.pid = 0;
        kernel_event.tid = 0;
        kernel_event.uid = 0;
        kernel_event.gid = 0;
        let process = decode_process(&kernel_event);
        assert_eq!(process.pid, None);
        assert_eq!(process.tid, None);
        assert_eq!(process.uid, Some(0), "uid 0 is root, a real value, not a sentinel");
        assert_eq!(process.gid, Some(0));
    }

    #[test]
    fn map_event_with_full_attribution() {
        let mut kernel_event = bathyscaphe_common::Event::default();
        kernel_event.cgroup_id = 42;
        kernel_event.dst_port = 443u16.to_be_bytes();

        let attributor = StubAttributor(Some(docker_attribution()));
        let tamper = StubTamper(0);
        let dropped = DroppedTracker::new();

        let wire = map_event(&kernel_event, &attributor, &tamper, &no_domain(), &dropped, 0).expect("full attribution should always map to Some");
        assert_eq!(wire.container.id, "a".repeat(64));
        assert_eq!(wire.container.name.as_deref(), Some("web"));
        assert_eq!(wire.container.image.as_deref(), Some("nginx:latest"));
        assert_eq!(wire.container.runtime, bathyscaphe_proto::Runtime::Docker);
        assert_eq!(wire.dst.port, 443);
        assert_eq!(wire.rule_id, None);
        assert_eq!(wire.domain, Domain::unresolved());
    }

    #[test]
    fn map_event_with_partial_attribution_emits_null_name_and_image_not_a_dropped_event() {
        let kernel_event = bathyscaphe_common::Event::default();
        let partial = Attribution { container_id: "b".repeat(64), name: None, image: None, runtime: bathyscaphe_proto::Runtime::Podman };
        let attributor = StubAttributor(Some(partial));
        let tamper = StubTamper(0);
        let dropped = DroppedTracker::new();

        let wire = map_event(&kernel_event, &attributor, &tamper, &no_domain(), &dropped, 0).expect("partial attribution (name/image races lost) must still emit");
        assert_eq!(wire.container.id, "b".repeat(64));
        assert_eq!(wire.container.name, None);
        assert_eq!(wire.container.image, None);
        assert_eq!(wire.container.runtime, bathyscaphe_proto::Runtime::Podman);
    }

    #[test]
    fn map_event_with_no_attribution_at_all_returns_none() {
        let kernel_event = bathyscaphe_common::Event::default();
        let attributor = StubAttributor(None);
        let tamper = StubTamper(0);
        let dropped = DroppedTracker::new();

        assert_eq!(map_event(&kernel_event, &attributor, &tamper, &no_domain(), &dropped, 0), None);
    }

    #[test]
    fn map_event_populates_domain_on_a_cache_hit() {
        let kernel_event = bathyscaphe_common::Event::default();
        let attributor = StubAttributor(Some(docker_attribution()));
        let tamper = StubTamper(0);
        let dropped = DroppedTracker::new();
        let hit = crate::dns::DomainHit { name: "example.com".to_string(), confidence: bathyscaphe_proto::DomainConfidence::Asserted };
        let domain_lookup = StubDomainLookup(Some(hit));

        let wire = map_event(&kernel_event, &attributor, &tamper, &domain_lookup, &dropped, 0).unwrap();
        assert_eq!(wire.domain.name.as_deref(), Some("example.com"));
        assert_eq!(wire.domain.source, Some(DomainSource::Dns));
        assert_eq!(wire.domain.confidence, Some(bathyscaphe_proto::DomainConfidence::Asserted));
    }

    #[test]
    fn map_event_leaves_domain_null_on_a_cache_miss() {
        let kernel_event = bathyscaphe_common::Event::default();
        let attributor = StubAttributor(Some(docker_attribution()));
        let tamper = StubTamper(0);
        let dropped = DroppedTracker::new();

        let wire = map_event(&kernel_event, &attributor, &tamper, &no_domain(), &dropped, 0).unwrap();
        assert_eq!(wire.domain, Domain::unresolved());
    }

    #[test]
    fn dropped_since_last_is_the_baseline_total_on_the_first_event_for_a_cgroup() {
        // No prior emitted event to delta against; the honest report of
        // "lost since we started observing this container" is the whole
        // current total, not a suppressed 0.
        let dropped = DroppedTracker::new();
        assert_eq!(dropped.delta(7, 5), 5);
    }

    #[test]
    fn dropped_since_last_is_a_delta_thereafter() {
        let dropped = DroppedTracker::new();
        assert_eq!(dropped.delta(7, 5), 5);
        assert_eq!(dropped.delta(7, 5), 0, "no new drops since the last emitted event");
        assert_eq!(dropped.delta(7, 8), 3);
    }

    #[test]
    fn dropped_since_last_tracks_each_cgroup_independently() {
        let dropped = DroppedTracker::new();
        assert_eq!(dropped.delta(1, 10), 10);
        assert_eq!(dropped.delta(2, 3), 3, "a different cgroup's baseline must not see cgroup 1's history");
        assert_eq!(dropped.delta(1, 12), 2);
    }
}
