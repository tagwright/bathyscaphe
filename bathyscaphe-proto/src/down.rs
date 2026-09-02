// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 techgaud
//! Messages airlock writes to bathyscaphe's stdin, one NDJSON line each.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::common::{DefaultVerdict, Mode, RuleAction, RuleSource, TransportProto};

/// The envelope for every line airlock writes to bathyscaphe's stdin.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DownMessage {
    Start(Start),
    Policy(Policy),
    Release(Release),
    ReleaseAll(ReleaseAll),
    Shutdown(Shutdown),
    SyncComplete(SyncComplete),
}

/// airlock's reply to `hello`, exactly once. bathyscaphe emits nothing
/// after `hello` until `start` arrives, except stderr.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Start {
    /// The version airlock selects from `hello.proto_versions`. If no
    /// overlap exists airlock does not send `start` at all: it kills the
    /// subprocess and surfaces a fatal backend-incompatible error to the
    /// operator instead.
    pub proto: u32,
    /// Cadence for `stats` lines. Defaults to 10 when the sender omits
    /// it.
    #[serde(default = "default_stats_interval_s")]
    pub stats_interval_s: u32,
}

fn default_stats_interval_s() -> u32 {
    10
}

/// A full compiled policy snapshot for one container, replacing that
/// container's entire prior policy atomically. Not a delta: idempotent,
/// re-sendable at any time, applying it twice is a no-op. bathyscaphe
/// applies it make-before-break, no connect ever observes a
/// half-applied policy.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Policy {
    /// Full 64-hex id, the join key both sides already agree on.
    pub container_id: String,
    /// airlock-owned monotonic counter per container. Echoed in
    /// `policy_ack` and `stats` so airlock can verify what is actually
    /// enforced. bathyscaphe persists it in the pinned metadata so it
    /// survives probe restarts and shows up in `hello.pinned`.
    pub generation: u64,
    pub mode: Mode,
    /// Verdict when no rule matches. Explicit, never implied by `mode`.
    pub default: DefaultVerdict,
    /// Ordered. Evaluation is most-specific-match on cidr (LPM), with
    /// `deny` winning over `allow` at equal specificity. Name rules are
    /// evaluated only by builds with the relevant capability.
    pub rules: Vec<Rule>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Rule {
    /// airlock-assigned, opaque to bathyscaphe, echoed on events as
    /// `rule_id` for alert attribution.
    pub id: String,
    pub action: RuleAction,
    #[serde(rename = "match")]
    pub r#match: Match,
    /// Absolute expiry, RFC3339, null = no expiry. Absolute rather than
    /// relative so a re-pushed snapshot is idempotent: replaying the same
    /// snapshot after a restart must not extend any rule's life.
    /// bathyscaphe expunges expired entries from the kernel map itself,
    /// no round trip.
    pub expires_at: Option<String>,
    pub source: RuleSource,
}

/// A rule's matcher, discriminated by `type`. This is the ONE place in
/// the wire protocol where ignore-unknown does NOT apply: an unrecognized
/// `type`, or an unrecognized field inside a known matcher, must never be
/// silently dropped, because dropping a matcher constraint can silently
/// widen an allow or narrow a deny. Both cases are captured rather than
/// rejected, and reported as inert via [`Match::is_inert`] /
/// `policy_ack.inert_rules`, never guessed at and never a hard parse
/// error that would take down the whole snapshot.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Match {
    Cidr {
        /// IPv4 or IPv6 prefix.
        cidr: String,
        /// Null = any port.
        port: Option<u16>,
        /// Null = both tcp and udp.
        #[serde(default)]
        proto: Option<TransportProto>,
        /// Any field inside this matcher this build does not recognize.
        /// Captured, never dropped: see [`Match::is_inert`].
        #[serde(flatten, default, skip_serializing_if = "Map::is_empty")]
        unknown: Map<String, Value>,
    },
    Name {
        /// Exact FQDN or a single leading wildcard (`*.example.com`),
        /// grammar Axis 3 syntax exactly. Enforced only under
        /// `enforce_fqdn`; evaluated for `would_deny` annotation only
        /// under `dns_enrich` without `enforce_fqdn`; otherwise inert.
        pattern: String,
        port: Option<u16>,
        #[serde(default)]
        proto: Option<TransportProto>,
        #[serde(flatten, default, skip_serializing_if = "Map::is_empty")]
        unknown: Map<String, Value>,
    },
    /// Catch-all for a `type` this build does not recognize at all. Any
    /// fields the matcher carried are not preserved individually (an
    /// internally tagged enum's `#[serde(other)]` fallback cannot also
    /// capture content), but the rule is still accepted onto the
    /// snapshot rather than failing the whole `policy` message, and is
    /// unconditionally inert.
    #[serde(other)]
    Unknown,
}

impl Match {
    /// True when this matcher carries a constraint this build cannot
    /// evaluate: an unrecognized `type`, or an unrecognized field inside
    /// a known matcher type. A rule whose `match` is inert is accepted
    /// onto the snapshot, contributes to `policy_ack.inert_rules`, and
    /// never participates in verdict lookups.
    pub fn is_inert(&self) -> bool {
        match self {
            Match::Cidr { unknown, .. } | Match::Name { unknown, .. } => !unknown.is_empty(),
            Match::Unknown => true,
        }
    }
}

/// Drops enforcement for one container: detach the enforcement programs'
/// deny path, delete and unpin that container's policy maps and
/// metadata. Egress is fully open afterward, observation continues. The
/// operator's escape hatch when fail-closed has frozen a container on a
/// policy that is now wrong and the fix cannot wait.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Release {
    pub container_id: String,
}

/// Host-level emergency variant: release every container, ack per
/// container. Deliberately its own kind, not a loop airlock might
/// half-complete.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseAll {}

/// Clean-exit request, equivalent to SIGTERM: bathyscaphe stops emitting,
/// leaves all pinned enforcement in place (fail-closed), and exits 0.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Shutdown {}

/// Marks the end of the post-restart reconciliation push: airlock has
/// now re-sent every snapshot it intends to for this session. Anything
/// pinned but not covered between `start` and this message is orphaned.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncComplete {}
