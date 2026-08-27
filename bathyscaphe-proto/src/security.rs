// SPDX-License-Identifier: GPL-3.0-or-later
//! The loud-accounting security record (refinement R1): a first-class
//! `security` up-message for security-relevant conditions (an
//! unenforceable name rule in block mode, sustained event drops, a
//! policy violation, an in-kernel block) shaped after the OpenTelemetry
//! log data model, so it is digestible by both beacon (airlock's alert
//! sink) and bilgeline (tagwright's log pipeline) with no bespoke
//! parsing on either side.
//!
//! `severity_number` follows the OTel severity number scale
//! (`INFO` = 9, `WARN` = 13, `ERROR` = 17) and maps to beacon's `Level`
//! by the same threshold rule beacon itself would apply to any OTel log:
//!
//! | `severity_number` | beacon `Level` |
//! |---|---|
//! | `< 13` | `Info` |
//! | `13..=16` | `Warning` |
//! | `>= 17` | `Error` |
//!
//! so airlock forwards a `security` record to beacon with no remapping
//! beyond that comparison. The same record, unchanged, is what
//! bilgeline's OTel Collector filelog receiver ingests via a stock JSON
//! parser: `timestamp`/`severity_text`/`severity_number`/`body` line up
//! with the OTel log record fields of the same name, and `attributes` is
//! a flat map of OTel-style attribute keys (dotted names like
//! `container.id`, matching OTel semantic conventions) rather than a
//! nested object, which is what a generic JSON-to-log-record mapping
//! expects.
//!
//! bathyscaphe's own stderr operational logs use this same JSON shape by
//! default (a `--log-format=text` flag exists for interactive human use);
//! that choice lives in the daemon crate, not here, but the shape is
//! defined once, in this module, so both paths agree.
//!
//! Loud records are token-bucket throttled (the Falco pattern) by the
//! daemon before they reach this wire, so a drop or violation storm never
//! floods the pipe; throttling policy is a daemon concern, this crate
//! only defines the record shape.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Stable reason codes carried in `attributes.reason`. New reasons are
/// additive; a consumer that does not recognize one still has a usable
/// `severity_number` and `body`.
pub mod reason {
    /// A `type: "name"` rule is active in `mode: block` on a backend (or
    /// against traffic) that cannot enforce it. Per the ratified
    /// unenforceable-name policy, the traffic is failed CLOSED (denied),
    /// loudly, rather than silently failed open.
    pub const POLICY_UNENFORCEABLE_NAME: &str = "policy.unenforceable_name";
    /// The tamper counter (`events_dropped_total`) moved for a container.
    pub const TAMPER_EVENT_DROPS: &str = "tamper.event_drops";
    /// A connection was denied or would have been denied against active
    /// policy.
    pub const POLICY_VIOLATION: &str = "policy.violation";
    /// A connection was actually blocked in-kernel (`mode: block`).
    pub const ENFORCE_BLOCKED: &str = "enforce.blocked";
}

/// OTel severity number scale, restricted to the three levels beacon
/// distinguishes. Any `severity_number` in `9..13` reads as `Info`,
/// `13..17` as `Warning`, `17` and above as `Error`, regardless of
/// whether it was constructed through this enum; the enum exists so
/// callers building a [`SecurityRecord`] don't have to remember the raw
/// numbers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Info,
    Warning,
    Error,
}

impl Severity {
    /// The OTel `severity_number` for this level.
    pub fn number(self) -> u8 {
        match self {
            Severity::Info => 9,
            Severity::Warning => 13,
            Severity::Error => 17,
        }
    }

    /// The OTel short severity text for this level, upper-case per OTel
    /// convention (`INFO`, `WARN`, `ERROR`).
    pub fn text(self) -> &'static str {
        match self {
            Severity::Info => "INFO",
            Severity::Warning => "WARN",
            Severity::Error => "ERROR",
        }
    }

    /// Classify a raw `severity_number` by the same threshold beacon
    /// applies: `< 13` is `Info`, `13..=16` is `Warning`, `>= 17` is
    /// `Error`.
    pub fn from_number(n: u8) -> Severity {
        if n >= 17 {
            Severity::Error
        } else if n >= 13 {
            Severity::Warning
        } else {
            Severity::Info
        }
    }
}

/// An OTel-log-data-model-aligned security record.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SecurityRecord {
    /// RFC3339 with at least microseconds, UTC.
    pub timestamp: String,
    pub severity_text: String,
    pub severity_number: u8,
    /// The human-readable message.
    pub body: String,
    /// Flat map of OTel-style attribute keys. Always includes `reason`
    /// (one of the [`reason`] module's constants or a forward-compat
    /// string) and `container.id` / `container.name` / `container.image`.
    /// `rule_id` and `domain` are present only when relevant to the
    /// record. Use [`SecurityRecord::new`] to build one consistently.
    pub attributes: BTreeMap<String, Value>,
}

/// The container identity fields every [`SecurityRecord`] carries.
pub struct SecurityContainer<'a> {
    pub id: &'a str,
    pub name: Option<&'a str>,
    pub image: Option<&'a str>,
}

impl SecurityRecord {
    /// Build a record with the standard attribute shape: `reason` plus
    /// `container.*`, with optional `rule_id` and `domain` attributes
    /// included only when given. `severity` fills both `severity_text`
    /// and `severity_number` consistently.
    pub fn new(
        timestamp: impl Into<String>,
        severity: Severity,
        body: impl Into<String>,
        reason: &str,
        container: SecurityContainer<'_>,
        rule_id: Option<&str>,
        domain: Option<&str>,
    ) -> Self {
        let mut attributes = BTreeMap::new();
        attributes.insert("reason".to_string(), Value::String(reason.to_string()));
        attributes.insert("container.id".to_string(), Value::String(container.id.to_string()));
        attributes.insert(
            "container.name".to_string(),
            container.name.map(|s| Value::String(s.to_string())).unwrap_or(Value::Null),
        );
        attributes.insert(
            "container.image".to_string(),
            container.image.map(|s| Value::String(s.to_string())).unwrap_or(Value::Null),
        );
        if let Some(rule_id) = rule_id {
            attributes.insert("rule_id".to_string(), Value::String(rule_id.to_string()));
        }
        if let Some(domain) = domain {
            attributes.insert("domain".to_string(), Value::String(domain.to_string()));
        }

        Self {
            timestamp: timestamp.into(),
            severity_text: severity.text().to_string(),
            severity_number: severity.number(),
            body: body.into(),
            attributes,
        }
    }
}
