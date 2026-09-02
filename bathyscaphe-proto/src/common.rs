// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 techgaud
//! Leaf types shared by the up and down messages: container/process
//! attribution, endpoints, and the enums used across more than one
//! message kind.
//!
//! Enum wire spellings follow `#[serde(rename_all = "snake_case")]`
//! uniformly, including `enforce_udp` / `dns_enrich` / `sni_enrich` /
//! `enforce_fqdn` / `would_deny`. `bathy_protocol_draft.md`'s prose spells
//! these with hyphens (`enforce-udp`, `would-deny`); no wire example in
//! the draft actually shows the hyphenated form. This crate uses one
//! uniform casing rule everywhere rather than special-casing five enum
//! values, and picks underscores to match the build brief's explicit
//! spelling. See `docs/PROTOCOL.md` for the note to Nate on this point.

use serde::{Deserialize, Serialize};

/// The protocol version this crate implements. Advertised in `hello` as
/// one entry of `proto_versions`, selected by airlock in `start`.
pub const PROTO_VERSION: u32 = 1;

/// Container runtime, inferred from the cgroup path shape. Ground truth,
/// never null.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Runtime {
    Docker,
    Podman,
}

/// Transport used for a connection or matcher. `Udp` events and matchers
/// are only meaningful on a backend advertising `enforce_udp`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportProto {
    Tcp,
    Udp,
}

/// Backend capability, advertised in `hello.capabilities`. Unknown
/// strings on a hypothetical Rust-side reader deserialize to `Unknown`
/// rather than erroring (airlock's Go reader independently ignores
/// unrecognized capability strings; this is this crate's mirror of that
/// forward-compat rule).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    /// Emits normalized egress events.
    Observe,
    /// Accepts `policy` directives and can return deny at connect time
    /// for cidr matchers.
    Enforce,
    /// The UDP4/6 sendmsg companion hooks are attached: `proto: udp`
    /// events and udp matchers are live.
    EnforceUdp,
    /// Populates `domain.*` on events from DNS snooping.
    DnsEnrich,
    /// Populates `domain.*` on events from TLS ClientHello SNI.
    SniEnrich,
    /// Name-based matchers are actually enforced, not alert-only.
    EnforceFqdn,
    /// Forward-compat catch-all for a capability string this build does
    /// not recognize.
    #[serde(other)]
    Unknown,
}

/// Per-container enforcement posture, the label grammar's escalation
/// ladder. On the probe, `Audit` and `Alert` behave identically (always
/// allow, honest verdicts); the distinction exists for airlock-side
/// alerting and is carried through so `stats` and `hello.pinned` can
/// report the operator-visible truth.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    Audit,
    Alert,
    Block,
}

/// Verdict when no policy rule matches a connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DefaultVerdict {
    Allow,
    Deny,
}

/// A rule's action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleAction {
    Allow,
    Deny,
}

/// Provenance of a policy rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleSource {
    /// Compiled from operator labels/config.
    Static,
    /// Derived from a DNS answer under a name rule.
    Dns,
}

/// Which signal produced `domain.name` on an event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DomainSource {
    /// Same-connection TLS ClientHello SNI evidence.
    Sni,
    /// DNS-cache join evidence.
    Dns,
}

/// How trustworthy `domain.name` is, given its source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DomainConfidence {
    /// SNI: same-connection evidence.
    Asserted,
    /// DNS-cache join: inferred, not necessarily the connection's own
    /// resolution.
    Inferred,
}

/// The verdict actually applied (or that would have been applied) to a
/// connection. `Deny` only ever appears in `mode: block`. `WouldDeny`
/// appears in `audit`/`alert` when the policy lookup says the connection
/// would have been blocked; observe-only builds always return allow to
/// the kernel, this field reports the lookup result honestly regardless.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Allow,
    Deny,
    WouldDeny,
}

/// The observed lifecycle point of a connection. v1 builds emit `Connect`
/// only; `Accept` and `Close` are reserved in the enum now so later
/// builds are additive with no wire bump.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    Connect,
    Accept,
    Close,
}

/// Container attribution on an event, IG-parity nouns so airlock's join
/// logic is backend-neutral.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Container {
    /// Full 64-hex container id. Wire always carries the full id; display
    /// truncation is a consumer concern.
    pub id: String,
    /// Null only when the runtime-API race is lost (short-lived
    /// container), never omitted.
    pub name: Option<String>,
    /// Same runtime-API race caveat as `name`.
    pub image: Option<String>,
    pub runtime: Runtime,
}

/// Process attribution on an event. Every field is best-effort and
/// nullable; none of it gates a verdict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Process {
    pub pid: Option<u32>,
    pub tid: Option<u32>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub comm: Option<String>,
}

/// Network endpoint (source or destination) of a connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Endpoint {
    pub addr: std::net::IpAddr,
    pub port: u16,
}

/// The domain-name enrichment object. ALWAYS present on an event, with
/// all three inner fields null until the DNS/SNI layer lands, so
/// airlock's "unresolved IP" classification never special-cases a
/// missing field and the DNS layer's arrival changes values, not shape.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Domain {
    pub name: Option<String>,
    pub source: Option<DomainSource>,
    pub confidence: Option<DomainConfidence>,
}

impl Domain {
    /// The all-null shape emitted by every pre-DNS-layer build.
    pub fn unresolved() -> Self {
        Self::default()
    }
}
