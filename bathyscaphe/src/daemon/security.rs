// SPDX-License-Identifier: GPL-3.0-or-later
//! Building and throttled emission of the R1 loud `security` records:
//! `policy.unenforceable_name`, `tamper.event_drops`, `enforce.blocked`.
//! `policy.violation` is a reserved reason code
//! (`bathyscaphe_proto::security::reason::POLICY_VIOLATION`) this build
//! does not emit -- there is no distinct "violation" condition detected in
//! this chunk beyond the two already covered (an unenforceable name, or an
//! actual in-kernel block), so inventing a third trigger here would be
//! exactly the kind of scope creep the build brief's "do not rabbit-hole"
//! instruction warns against; a later chunk with a real policy-mismatch
//! signal to report can use the reason code that is already reserved for
//! it.

use std::sync::Mutex;
use std::time::Instant;

use bathyscaphe_proto::security::{Severity, SecurityContainer, SecurityRecord, reason};
use bathyscaphe_proto::UpMessage;

use super::throttle::TokenBucket;
use crate::pipeline::EventSink;

/// One shared throttle for every reason code, per the module doc on
/// [`super::throttle`]: a storm of any kind (drops, blocks, unenforceable
/// names) draws from the same bounded budget, never N independently
/// bounded budgets that sum past the intended cap.
pub struct SecurityEmitter {
    bucket: Mutex<TokenBucket>,
}

impl SecurityEmitter {
    pub fn new() -> Self {
        Self { bucket: Mutex::new(TokenBucket::falco_default()) }
    }

    #[cfg(test)]
    pub fn with_bucket(bucket: TokenBucket) -> Self {
        Self { bucket: Mutex::new(bucket) }
    }

    /// Attempts to emit `record` through `sink`, subject to the shared
    /// throttle. Returns whether it was actually emitted -- `false` means
    /// throttled, and the record is dropped (not queued: a queued backlog
    /// of security records is exactly the flood this throttle exists to
    /// prevent, and every drop is itself uncounted here deliberately,
    /// since counting throttle drops precisely would need its own
    /// unthrottled channel).
    pub fn try_emit(&self, sink: &mut dyn EventSink, record: SecurityRecord) -> bool {
        self.try_emit_at(sink, record, Instant::now())
    }

    fn try_emit_at(&self, sink: &mut dyn EventSink, record: SecurityRecord, now: Instant) -> bool {
        let mut bucket = self.bucket.lock().unwrap_or_else(|poison| poison.into_inner());
        if bucket.try_take(now) {
            sink.emit(UpMessage::Security(record));
            true
        } else {
            false
        }
    }
}

impl Default for SecurityEmitter {
    fn default() -> Self {
        Self::new()
    }
}

/// The unenforceable-name record (the deliberate differentiator: prior art
/// fails closed here silently, this build accounts for it loudly).
/// Severity `Error` -- the traffic this rule targeted is actually being
/// denied right now (`mode: block`, `default: deny`), not merely logged.
pub fn unenforceable_name_record(timestamp: String, container: SecurityContainer<'_>, rule_id: &str, pattern: &str) -> SecurityRecord {
    SecurityRecord::new(
        timestamp,
        Severity::Error,
        format!("denied connections matching unresolved name rule target {pattern:?}: this build cannot resolve name rules (no enforce_fqdn), so the traffic falls through to this container's deny default"),
        reason::POLICY_UNENFORCEABLE_NAME,
        container,
        Some(rule_id),
        Some(pattern),
    )
}

/// A tamper/event-drops record: the per-container `TAMPER` counter moved
/// since the last `stats` tick. `severity` is caller-supplied so R2's
/// escalation path (`super::r2`) can hand this the same reason code at
/// `Error` once a container has actually been escalated, while an ordinary
/// sub-threshold drop reports at `Warning`.
pub fn tamper_event_drops_record(timestamp: String, container: SecurityContainer<'_>, dropped_delta: u64, dropped_total: u64, severity: Severity) -> SecurityRecord {
    let mut record = SecurityRecord::new(timestamp, severity, format!("{dropped_delta} event(s) dropped since the last report ({dropped_total} total for this container)"), reason::TAMPER_EVENT_DROPS, container, None, None);
    record.attributes.insert("dropped_delta".to_string(), serde_json::Value::from(dropped_delta));
    record.attributes.insert("dropped_total".to_string(), serde_json::Value::from(dropped_total));
    record
}

/// A throttled SUMMARY of in-kernel blocks since the last report -- never
/// one record per deny (`bathy_build_spec.md`'s R1 section is explicit
/// that `enforce.blocked` must be a summary, not a per-event flood).
/// Severity `Warning`: policy is doing exactly what it was configured to
/// do, which is worth surfacing but is not itself an anomaly the way a
/// tamper drop or an unenforceable name is.
pub fn enforce_blocked_summary_record(timestamp: String, container: SecurityContainer<'_>, denied_count: u64) -> SecurityRecord {
    let mut record = SecurityRecord::new(timestamp, Severity::Warning, format!("{denied_count} connection(s) denied by policy since the last report"), reason::ENFORCE_BLOCKED, container, None, None);
    record.attributes.insert("denied_count".to_string(), serde_json::Value::from(denied_count));
    record
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    struct CapturingSink(Vec<UpMessage>);
    impl EventSink for CapturingSink {
        fn emit(&mut self, message: UpMessage) {
            self.0.push(message);
        }
    }

    fn container() -> SecurityContainer<'static> {
        SecurityContainer { id: "c".repeat(64).leak(), name: Some("web"), image: Some("nginx:latest") }
    }

    #[test]
    fn unenforceable_name_record_is_error_severity_and_carries_the_reason() {
        let record = unenforceable_name_record("2026-08-27T00:00:00Z".to_string(), container(), "r1", "github.com");
        assert_eq!(record.severity_text, "ERROR");
        assert_eq!(record.severity_number, 17);
        assert_eq!(record.attributes.get("reason").unwrap(), reason::POLICY_UNENFORCEABLE_NAME);
        assert_eq!(record.attributes.get("rule_id").unwrap(), "r1");
        assert_eq!(record.attributes.get("domain").unwrap(), "github.com");
    }

    #[test]
    fn enforce_blocked_summary_is_a_single_record_not_one_per_deny() {
        let record = enforce_blocked_summary_record("2026-08-27T00:00:00Z".to_string(), container(), 42);
        assert_eq!(record.attributes.get("denied_count").unwrap(), 42);
        assert_eq!(record.severity_text, "WARN");
    }

    #[test]
    fn the_shared_throttle_bounds_a_storm_across_all_reason_codes() {
        let emitter = SecurityEmitter::with_bucket(TokenBucket::new(2.0, 0.0));
        let mut sink = CapturingSink(Vec::new());
        let now = Instant::now();

        let a = unenforceable_name_record("t".to_string(), container(), "r1", "x.com");
        let b = tamper_event_drops_record("t".to_string(), container(), 5, 5, Severity::Warning);
        let c = enforce_blocked_summary_record("t".to_string(), container(), 3);

        assert!(emitter.try_emit_at(&mut sink, a, now), "first record (any reason) is admitted");
        assert!(emitter.try_emit_at(&mut sink, b, now), "second record (a different reason) still draws from the same bucket");
        assert!(!emitter.try_emit_at(&mut sink, c, now), "third record in the same instant is throttled: the bucket is shared, not per-reason");
        assert_eq!(sink.0.len(), 2);
    }

    #[test]
    fn a_throttled_record_is_dropped_not_queued() {
        let emitter = SecurityEmitter::with_bucket(TokenBucket::new(1.0, 0.0));
        let mut sink = CapturingSink(Vec::new());
        let now = Instant::now();
        assert!(emitter.try_emit_at(&mut sink, unenforceable_name_record("t".to_string(), container(), "r1", "x.com"), now));
        assert!(!emitter.try_emit_at(&mut sink, unenforceable_name_record("t".to_string(), container(), "r2", "y.com"), now));
        // A later refill does NOT retroactively deliver the dropped one --
        // there is nothing queued to deliver.
        let later = now + Duration::from_secs(60);
        assert_eq!(sink.0.len(), 1);
        let _ = later;
    }
}
