// SPDX-License-Identifier: GPL-3.0-or-later
//! Building the `hello` handshake message: the fixed capability set this
//! build advertises, plus the `pinned` reconciliation inventory discovered
//! from whatever [`super::probe_api::ProbeApi::attached_containers`]
//! reports enforcement configured for (an empty vec on a true cold start,
//! per `docs/PROTOCOL.md` section 2).

use bathyscaphe_common::{DefaultVerdict, Mode};
use bathyscaphe_proto::{Capability, Hello, PinnedContainer, PROTO_VERSION};

use super::probe_api::ProbeApi;

/// This build's capability set. `dns_enrich` (build chunk #9) populates
/// `domain.*` on events from snooped DNS answers. `enforce_fqdn` (build
/// chunk #10) is now also live: `type: "name"` rules are actively
/// resolved and enforced (`daemon::compile`/`daemon::fqdn`), not merely
/// counted inert. Deliberately still does NOT include `sni_enrich`
/// (unbuilt) -- advertising a capability this build cannot actually honor
/// would make a `policy` sender's request for it a silent downgrade rather
/// than the sticky validation error `docs/PROTOCOL.md` section 2 calls
/// for.
pub fn capabilities() -> Vec<Capability> {
    vec![Capability::Observe, Capability::Enforce, Capability::EnforceUdp, Capability::DnsEnrich, Capability::EnforceFqdn]
}

fn mode_to_wire(mode: Mode) -> bathyscaphe_proto::Mode {
    match mode {
        Mode::Audit => bathyscaphe_proto::Mode::Audit,
        Mode::Alert => bathyscaphe_proto::Mode::Alert,
        Mode::Block => bathyscaphe_proto::Mode::Block,
    }
}

/// Builds the `pinned` inventory: one [`PinnedContainer`] per cgroup this
/// process attached with enforcement configured (an attached-for-
/// observation-only cgroup, with no `ENFORCEMENT` map entry, is not
/// enforcement state to reconcile and is left out, matching
/// `EnforcementState`'s own "no entry means no enforcement" convention).
/// `resolve_container_id` is the attribution lookup, injected so this
/// function has no dependency on a live `Resolver`/Docker socket for
/// tests.
pub fn pinned_inventory(probe: &dyn ProbeApi, resolve_container_id: impl Fn(u64) -> Option<String>) -> Vec<PinnedContainer> {
    let mut pinned = Vec::new();
    for cgroup_id in probe.attached_containers() {
        let Ok(Some(enforcement)) = probe.get_enforcement(cgroup_id) else { continue };
        let container_id = resolve_container_id(cgroup_id).unwrap_or_else(|| format!("unknown-{cgroup_id:016x}"));
        let mode = Mode::try_from(enforcement.mode).unwrap_or(Mode::Audit);
        let _ = DefaultVerdict::try_from(enforcement.default_verdict); // validated, not itself part of PinnedContainer's wire shape
        let rules = probe.tracked_policy_keys(cgroup_id).len() as u32;
        pinned.push(PinnedContainer { container_id, cgroup_id, generation: enforcement.generation, mode: mode_to_wire(mode), rules });
    }
    pinned
}

pub fn build_hello(probe: &dyn ProbeApi, resolve_container_id: impl Fn(u64) -> Option<String>, backend_version: &str) -> Hello {
    Hello { backend: "bathyscaphe".to_string(), backend_version: backend_version.to_string(), proto_versions: vec![PROTO_VERSION], capabilities: capabilities(), pinned: pinned_inventory(probe, resolve_container_id) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon::probe_api::MockProbe;
    use bathyscaphe_common::PolicyValue;
    use std::net::IpAddr;

    #[test]
    fn capabilities_include_dns_enrich_and_enforce_fqdn_but_not_sni_enrich() {
        let caps = capabilities();
        assert!(caps.contains(&Capability::Observe));
        assert!(caps.contains(&Capability::Enforce));
        assert!(caps.contains(&Capability::EnforceUdp));
        assert!(caps.contains(&Capability::DnsEnrich));
        assert!(caps.contains(&Capability::EnforceFqdn));
        assert!(!caps.contains(&Capability::SniEnrich));
    }

    #[test]
    fn cold_start_has_an_empty_pinned_inventory() {
        let probe = MockProbe::new();
        let hello = build_hello(&probe, |_| None, "0.1.0");
        assert!(hello.pinned.is_empty());
        assert_eq!(hello.backend, "bathyscaphe");
        assert_eq!(hello.proto_versions, vec![PROTO_VERSION]);
    }

    #[test]
    fn a_pinned_enforced_container_is_reported_with_its_kernel_truth() {
        let mut probe = MockProbe::new();
        probe.attached.insert(9);
        probe.set_enforcement(9, Mode::Block, DefaultVerdict::Deny, 7).unwrap();
        probe.set_policy(9, IpAddr::from([10, 0, 0, 0]), 0, PolicyValue::new(1, 0, 0)).unwrap();

        let hello = build_hello(&probe, |id| if id == 9 { Some("c1".to_string()) } else { None }, "0.1.0");
        assert_eq!(hello.pinned.len(), 1);
        assert_eq!(hello.pinned[0].container_id, "c1");
        assert_eq!(hello.pinned[0].cgroup_id, 9);
        assert_eq!(hello.pinned[0].generation, 7);
        assert_eq!(hello.pinned[0].mode, bathyscaphe_proto::Mode::Block);
        assert_eq!(hello.pinned[0].rules, 1);
    }

    #[test]
    fn an_attached_observe_only_container_with_no_enforcement_is_not_pinned_inventory() {
        let mut probe = MockProbe::new();
        probe.attached.insert(3); // attached, but set_enforcement never called
        let hello = build_hello(&probe, |_| Some("c1".to_string()), "0.1.0");
        assert!(hello.pinned.is_empty());
    }
}
