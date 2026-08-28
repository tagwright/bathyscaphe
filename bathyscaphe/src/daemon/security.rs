// SPDX-License-Identifier: GPL-3.0-or-later
//! Building and throttled emission of the R1 loud `security` records:
//! `tamper.event_drops`, `enforce.blocked`, and (build chunk #10)
//! `policy.name_unresolved_block`. `policy.violation` is a reserved reason
//! code (`bathyscaphe_proto::security::reason::POLICY_VIOLATION`) this
//! build does not emit -- there is no distinct "violation" condition
//! detected beyond what's already covered, so inventing a trigger here
//! would be exactly the kind of scope creep the build brief's "do not
//! rabbit-hole" instruction warns against; a later chunk with a real
//! policy-mismatch signal to report can use the reason code that is
//! already reserved for it.
//!
//! `policy.unenforceable_name` (chunk #9's reason for a name rule this
//! build could never evaluate at all) is likewise no longer emitted by
//! this builder module: build chunk #10 always advertises `enforce_fqdn`,
//! so a name rule IS enforceable now -- the analogous failure this build
//! reports is `policy.name_unresolved_block`
//! ([`name_unresolved_block_record`]), a materially different condition
//! (the name rule itself is fine; there's simply no visible DNS answer for
//! the specific destination actually reached). The reason string itself
//! stays defined in `bathyscaphe-proto` (a stable wire vocabulary entry),
//! reserved for a hypothetical build without `enforce_fqdn`.

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

/// Build chunk #10's evolved loud record: a container holding at least one
/// active `Allow` name rule was denied a connection to a destination this
/// build never observed a DNS answer for (raw-IP egress bypassing DNS
/// entirely, or a DoH/DoT/ECH lookup this build structurally cannot see --
/// `docs/DNS.md`'s residual-limitations list). Severity `Error` -- the
/// traffic is actually being denied right now, not merely logged, the same
/// severity rationale chunk #9's now-removed `unenforceable_name_record`
/// used. `dst_addr`/`dst_port` are included as attributes since `domain`
/// is deliberately absent here (the whole point of this record is "we
/// don't have a name for this destination").
pub fn name_unresolved_block_record(timestamp: String, container: SecurityContainer<'_>, dst_addr: std::net::IpAddr, dst_port: u16) -> SecurityRecord {
    let mut record = SecurityRecord::new(
        timestamp,
        Severity::Error,
        format!("denied a connection to {dst_addr}:{dst_port}: this container has an active allow-listed name rule, but no DNS answer was ever observed for this destination (raw-IP egress, or a DoH/DoT/ECH lookup this build cannot see)"),
        reason::POLICY_NAME_UNRESOLVED_BLOCK,
        container,
        None,
        None,
    );
    record.attributes.insert("dst.addr".to_string(), serde_json::Value::from(dst_addr.to_string()));
    record.attributes.insert("dst.port".to_string(), serde_json::Value::from(dst_port));
    record
}

/// Build chunk #11's loud potential-spoofing signal: a DNS answer for
/// `domain` arrived from `src_addr`, which is NOT in the operator-configured
/// trusted-resolver set, yet would have matched one of this container's own
/// active `Allow` name patterns. `daemon::fqdn::on_dns_answer` never inserts
/// anything into `POLICY` because of an untrusted-sourced answer -- this
/// record exists purely to make the attempt visible: a container's own
/// resolver (or something able to inject a reply into its network
/// namespace) answering an allow-listed hostname from an untrusted source
/// is exactly the spoofing scenario `bathyscaphe::dns::trust`'s
/// trusted-resolver allowlist exists to defeat. Severity `Warning`, not
/// `Error`: unlike `policy.name_unresolved_block`, nothing was actually
/// enforced or denied as a direct result of this specific answer -- it is a
/// signal worth an operator's attention, not an active block.
pub fn dns_untrusted_answer_record(timestamp: String, container: SecurityContainer<'_>, src_addr: std::net::IpAddr, domain: &str) -> SecurityRecord {
    let mut record = SecurityRecord::new(
        timestamp,
        Severity::Warning,
        format!("a DNS answer for {domain:?} arrived from {src_addr}, which is not in the trusted-resolver set, and would have matched an active allow-listed name rule; the answer was NOT used to seed enforcement"),
        reason::DNS_UNTRUSTED_ANSWER,
        container,
        None,
        Some(domain),
    );
    record.attributes.insert("resolver.addr".to_string(), serde_json::Value::from(src_addr.to_string()));
    record
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
    fn name_unresolved_block_record_is_error_severity_and_carries_the_reason() {
        let record = name_unresolved_block_record("2026-08-27T00:00:00Z".to_string(), container(), std::net::IpAddr::from([203, 0, 113, 9]), 443);
        assert_eq!(record.severity_text, "ERROR");
        assert_eq!(record.severity_number, 17);
        assert_eq!(record.attributes.get("reason").unwrap(), reason::POLICY_NAME_UNRESOLVED_BLOCK);
        assert_eq!(record.attributes.get("dst.addr").unwrap(), "203.0.113.9");
        assert_eq!(record.attributes.get("dst.port").unwrap(), 443);
        assert!(record.attributes.get("domain").is_none(), "the whole point of this record is that no domain was ever observed");
    }

    #[test]
    fn dns_untrusted_answer_record_is_warning_severity_and_carries_the_reason() {
        let record = dns_untrusted_answer_record("2026-08-28T00:00:00Z".to_string(), container(), std::net::IpAddr::from([203, 0, 113, 53]), "github.com");
        assert_eq!(record.severity_text, "WARN");
        assert_eq!(record.attributes.get("reason").unwrap(), reason::DNS_UNTRUSTED_ANSWER);
        assert_eq!(record.attributes.get("resolver.addr").unwrap(), "203.0.113.53");
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

        let a = name_unresolved_block_record("t".to_string(), container(), std::net::IpAddr::from([1, 2, 3, 4]), 443);
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
        assert!(emitter.try_emit_at(&mut sink, name_unresolved_block_record("t".to_string(), container(), std::net::IpAddr::from([1, 2, 3, 4]), 443), now));
        assert!(!emitter.try_emit_at(&mut sink, name_unresolved_block_record("t".to_string(), container(), std::net::IpAddr::from([5, 6, 7, 8]), 80), now));
        // A later refill does NOT retroactively deliver the dropped one --
        // there is nothing queued to deliver.
        let later = now + Duration::from_secs(60);
        assert_eq!(sink.0.len(), 1);
        let _ = later;
    }
}
