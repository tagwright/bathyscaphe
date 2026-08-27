// SPDX-License-Identifier: GPL-3.0-or-later
//! Messages bathyscaphe writes to stdout, one NDJSON line each. See
//! `docs/PROTOCOL.md` and `bathy_protocol_draft.md` for the framing and
//! reconciliation model these messages participate in.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::common::{Capability, Container, Domain, Endpoint, EventKind, Mode, Process, TransportProto, Verdict};
use crate::security::SecurityRecord;

/// The envelope for every line bathyscaphe writes to stdout. Tagged on
/// `kind`, so a single decoder loop on the airlock side dispatches on one
/// field uniformly, including for `event` lines.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum UpMessage {
    Hello(Hello),
    Event(Event),
    Stats(Stats),
    PolicyAck(PolicyAck),
    ReleaseAck(ReleaseAck),
    Security(SecurityRecord),
    Error(ErrorMsg),
}

/// First line on stdout, exactly once per process lifetime.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hello {
    /// `"bathyscaphe"`. airlock's IG adapter synthesizes an equivalent
    /// hello internally with `"inspektor-gadget"`.
    pub backend: String,
    /// This build's own semver, informational.
    pub backend_version: String,
    /// Protocol versions this build speaks. v1 builds send `[1]`.
    pub proto_versions: Vec<u32>,
    pub capabilities: Vec<Capability>,
    /// Inventory of enforcement state found already pinned in bpffs at
    /// startup, one entry per container whose policy survived a previous
    /// process. Empty on true cold start. This is the reconciliation
    /// input.
    pub pinned: Vec<PinnedContainer>,
}

/// One entry of `hello.pinned`: enforcement state bathyscaphe found
/// already pinned in bpffs before airlock said anything.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PinnedContainer {
    pub container_id: String,
    pub cgroup_id: u64,
    pub generation: u64,
    pub mode: Mode,
    /// Rule count in the pinned snapshot, for a quick sanity glance
    /// without decoding the whole map.
    pub rules: u32,
}

/// One observed egress decision. The nouns are IG's, so airlock's join
/// logic against `container.*` is backend-neutral.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Event {
    /// RFC3339 with at least microseconds, UTC. Kernel event time.
    pub ts: String,
    pub event: EventKind,
    pub proto: TransportProto,
    pub container: Container,
    pub process: Process,
    pub src: Endpoint,
    /// The policy input, resolved at connect time.
    pub dst: Endpoint,
    pub verdict: Verdict,
    /// Id of the matching rule from the active snapshot. Null when no
    /// rule matched (the default verdict applied) or the build does not
    /// track it.
    pub rule_id: Option<String>,
    /// Always present; all three inner fields null until the DNS/SNI
    /// layer lands.
    pub domain: Domain,
    pub meta: EventMeta,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventMeta {
    /// Events lost (ring buffer overflow or userspace shed) since the
    /// previous emitted event. Ground truth, defaults to 0, never
    /// omitted. Deliberately NOT carrying `backend`: that identity is
    /// established once in `hello` and airlock stamps it downstream.
    pub dropped_since_last: u64,
}

/// Periodic heartbeat, emitted every `stats_interval_s` seconds, ALWAYS,
/// including when fully idle, so airlock can distinguish "no traffic"
/// from "probe wedged".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Stats {
    pub ts: String,
    /// Monotonic per process. Gaps are visible if airlock's reader lags.
    pub seq: u64,
    pub uptime_s: u64,
    /// Cumulative since process start.
    pub events_emitted: u64,
    /// Cumulative since process start. The tamper counter: ring-buffer
    /// reservation failures in the kernel program plus any userspace
    /// shedding. A hostile container's cheapest blinding move is
    /// flooding connects until the ring overflows, so this is never
    /// silent.
    pub events_dropped_total: u64,
    /// One entry per container bathyscaphe currently holds state for.
    pub containers: Vec<ContainerStats>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContainerStats {
    pub id: String,
    /// The directive's intent.
    pub mode: Mode,
    pub generation: u64,
    /// The kernel truth: whether the deny path is armed. Distinct from
    /// `mode`, so "asked for block, not actually armed" is visible.
    pub enforcing: bool,
    pub rules_active: u32,
    pub rules_inert: u32,
    /// Per-container attribution of the tamper counter.
    pub dropped_total: u64,
    /// True for pinned enforcement airlock did not cover during
    /// reconciliation. Kept enforcing (fail-closed) until adopted or
    /// released.
    pub orphaned: bool,
}

/// One per `policy`, in order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyAck {
    pub container_id: String,
    pub generation: u64,
    pub status: PolicyAckStatus,
    /// Count of rules accepted but not enforceable by this build (name
    /// rules pre-`enforce_fqdn`, udp rules pre-`enforce_udp`, unknown
    /// matcher types or unknown fields inside a matcher). Cross-checks
    /// what capabilities promised.
    pub inert_rules: u32,
    /// Human string on `Error`. On error the previously applied
    /// generation remains enforced (fail-closed, never partially
    /// applied).
    pub error: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyAckStatus {
    Applied,
    Error,
}

/// Ack for `release`. Idempotent: a late release for an already-gone or
/// never-known container still acks `Released`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseAck {
    pub container_id: String,
    pub status: ReleaseStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseStatus {
    Released,
}

/// A backend-level protocol/operational error not scoped to one
/// container's policy (which has its own `PolicyAck.error` instead): for
/// example a kernel-floor check failing after `start`, or a fatal load
/// error discovered after `hello`. Distinct from the loud, throttled
/// `Security` records, which are about policy-relevant events on
/// monitored traffic, not backend self-diagnosis.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorMsg {
    pub message: String,
}

/// Map type used by the security module's attribute maps, re-exported
/// here so downstream crates don't need a direct `serde_json` /
/// `std::collections` dependency just to build one.
pub type AttributeMap = BTreeMap<String, serde_json::Value>;
