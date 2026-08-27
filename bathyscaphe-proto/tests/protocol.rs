// SPDX-License-Identifier: GPL-3.0-or-later
//! Round-trip and golden-line tests for the frozen wire protocol.
//!
//! Round-trip tests prove every message type survives an encode/decode
//! cycle unchanged. Golden-line tests pin the *exact* JSON string a
//! representative message produces, so the frozen wire shape cannot
//! drift silently: a passing round-trip test alone would not catch a
//! field being renamed to something that still round-trips with itself.

use bathyscaphe_proto::{
    decode_line, encode_line, security::reason, Capability, Container, DefaultVerdict, Domain, DownMessage, Endpoint,
    ErrorMsg, Event, EventKind, EventMeta, Hello, Match, Mode, PinnedContainer, Policy, PolicyAck, PolicyAckStatus,
    Process, Release, ReleaseAck, ReleaseAll, ReleaseStatus, Rule, RuleAction, RuleSource, Runtime, SecurityContainer,
    SecurityRecord, Severity, Shutdown, Start, Stats, ContainerStats, SyncComplete, TransportProto, UpMessage,
    Verdict, PROTO_VERSION,
};

fn sample_hello() -> Hello {
    Hello {
        backend: "bathyscaphe".to_string(),
        backend_version: "0.1.0".to_string(),
        proto_versions: vec![PROTO_VERSION],
        capabilities: vec![Capability::Observe, Capability::Enforce, Capability::EnforceUdp],
        pinned: vec![PinnedContainer {
            container_id: "a1b2c3d4e5f6".to_string(),
            cgroup_id: 48291,
            generation: 42,
            mode: Mode::Block,
            rules: 17,
        }],
    }
}

fn sample_event() -> Event {
    Event {
        ts: "2026-08-27T12:00:03.482910Z".to_string(),
        event: EventKind::Connect,
        proto: TransportProto::Tcp,
        container: Container {
            id: "cid-1".to_string(),
            name: Some("renovate-1".to_string()),
            image: Some("renovate/renovate:41".to_string()),
            runtime: Runtime::Docker,
        },
        process: Process {
            pid: Some(675195),
            tid: Some(675195),
            uid: Some(0),
            gid: Some(0),
            comm: Some("node".to_string()),
        },
        src: Endpoint { addr: "172.17.0.5".parse().unwrap(), port: 51234 },
        dst: Endpoint { addr: "140.82.121.6".parse().unwrap(), port: 443 },
        verdict: Verdict::Allow,
        rule_id: Some("r-gh-api".to_string()),
        domain: Domain::unresolved(),
        meta: EventMeta { dropped_since_last: 0 },
    }
}

fn sample_stats() -> Stats {
    Stats {
        ts: "2026-08-27T12:05:00.000000Z".to_string(),
        seq: 31,
        uptime_s: 310,
        events_emitted: 4821,
        events_dropped_total: 0,
        containers: vec![ContainerStats {
            id: "cid-1".to_string(),
            mode: Mode::Block,
            generation: 43,
            enforcing: true,
            rules_active: 4,
            rules_inert: 1,
            dropped_total: 0,
            orphaned: false,
        }],
    }
}

fn sample_policy_ack() -> PolicyAck {
    PolicyAck {
        container_id: "cid-1".to_string(),
        generation: 43,
        status: PolicyAckStatus::Applied,
        inert_rules: 1,
        error: None,
    }
}

fn sample_release_ack() -> ReleaseAck {
    ReleaseAck { container_id: "cid-1".to_string(), status: ReleaseStatus::Released }
}

fn sample_security() -> SecurityRecord {
    SecurityRecord::new(
        "2026-08-27T12:00:09.001271Z",
        Severity::Error,
        "denied connection to unresolved name rule target",
        reason::POLICY_UNENFORCEABLE_NAME,
        SecurityContainer { id: "cid-2", name: Some("suspicious-1"), image: Some("whoami:latest") },
        Some("r-gh-name"),
        None,
    )
}

fn sample_error() -> ErrorMsg {
    ErrorMsg { message: "kernel floor unmet: cgroup v2 required".to_string() }
}

fn sample_policy() -> Policy {
    Policy {
        container_id: "cid-1".to_string(),
        generation: 43,
        mode: Mode::Block,
        default: DefaultVerdict::Deny,
        rules: vec![Rule {
            id: "r-gh-api".to_string(),
            action: RuleAction::Allow,
            r#match: Match::Cidr {
                cidr: "140.82.121.0/24".to_string(),
                port: Some(443),
                proto: Some(TransportProto::Tcp),
                unknown: serde_json::Map::new(),
            },
            expires_at: None,
            source: RuleSource::Static,
        }],
    }
}

// ---------------------------------------------------------------------
// Round-trip tests: every UpMessage and DownMessage variant.
// ---------------------------------------------------------------------

fn round_trip_up(message: UpMessage) {
    let line = encode_line(&message).expect("encode");
    assert!(!line.contains('\n'));
    let decoded: UpMessage = decode_line(&line).expect("decode");
    assert_eq!(message, decoded);
}

fn round_trip_down(message: DownMessage) {
    let line = encode_line(&message).expect("encode");
    assert!(!line.contains('\n'));
    let decoded: DownMessage = decode_line(&line).expect("decode");
    assert_eq!(message, decoded);
}

#[test]
fn hello_round_trips() {
    round_trip_up(UpMessage::Hello(sample_hello()));
}

#[test]
fn event_round_trips() {
    round_trip_up(UpMessage::Event(sample_event()));
}

#[test]
fn stats_round_trips() {
    round_trip_up(UpMessage::Stats(sample_stats()));
}

#[test]
fn policy_ack_round_trips() {
    round_trip_up(UpMessage::PolicyAck(sample_policy_ack()));
}

#[test]
fn policy_ack_error_round_trips() {
    round_trip_up(UpMessage::PolicyAck(PolicyAck {
        container_id: "cid-1".to_string(),
        generation: 44,
        status: PolicyAckStatus::Error,
        inert_rules: 0,
        error: Some("unknown container".to_string()),
    }));
}

#[test]
fn release_ack_round_trips() {
    round_trip_up(UpMessage::ReleaseAck(sample_release_ack()));
}

#[test]
fn security_round_trips() {
    round_trip_up(UpMessage::Security(sample_security()));
}

#[test]
fn error_round_trips() {
    round_trip_up(UpMessage::Error(sample_error()));
}

#[test]
fn start_round_trips() {
    round_trip_down(DownMessage::Start(Start { proto: PROTO_VERSION, stats_interval_s: 10 }));
}

#[test]
fn policy_round_trips() {
    round_trip_down(DownMessage::Policy(sample_policy()));
}

#[test]
fn policy_with_name_rule_round_trips() {
    round_trip_down(DownMessage::Policy(Policy {
        container_id: "cid-1".to_string(),
        generation: 44,
        mode: Mode::Block,
        default: DefaultVerdict::Deny,
        rules: vec![Rule {
            id: "r-gh-name".to_string(),
            action: RuleAction::Allow,
            r#match: Match::Name {
                pattern: "*.github.com".to_string(),
                port: Some(443),
                proto: Some(TransportProto::Tcp),
                unknown: serde_json::Map::new(),
            },
            expires_at: Some("2026-08-27T12:05:00Z".to_string()),
            source: RuleSource::Dns,
        }],
    }));
}

#[test]
fn release_round_trips() {
    round_trip_down(DownMessage::Release(Release { container_id: "cid-1".to_string() }));
}

#[test]
fn release_all_round_trips() {
    round_trip_down(DownMessage::ReleaseAll(ReleaseAll {}));
}

#[test]
fn shutdown_round_trips() {
    round_trip_down(DownMessage::Shutdown(Shutdown {}));
}

#[test]
fn sync_complete_round_trips() {
    round_trip_down(DownMessage::SyncComplete(SyncComplete {}));
}

// ---------------------------------------------------------------------
// Golden-line tests: pin the exact wire shape of a representative line
// for each of hello, event, policy, security, stats.
// ---------------------------------------------------------------------

#[test]
fn golden_hello_line() {
    let line = encode_line(&UpMessage::Hello(sample_hello())).expect("encode");
    assert_eq!(
        line,
        r#"{"kind":"hello","backend":"bathyscaphe","backend_version":"0.1.0","proto_versions":[1],"capabilities":["observe","enforce","enforce_udp"],"pinned":[{"container_id":"a1b2c3d4e5f6","cgroup_id":48291,"generation":42,"mode":"block","rules":17}]}"#
    );
}

#[test]
fn golden_event_line() {
    let line = encode_line(&UpMessage::Event(sample_event())).expect("encode");
    assert_eq!(
        line,
        r#"{"kind":"event","ts":"2026-08-27T12:00:03.482910Z","event":"connect","proto":"tcp","container":{"id":"cid-1","name":"renovate-1","image":"renovate/renovate:41","runtime":"docker"},"process":{"pid":675195,"tid":675195,"uid":0,"gid":0,"comm":"node"},"src":{"addr":"172.17.0.5","port":51234},"dst":{"addr":"140.82.121.6","port":443},"verdict":"allow","rule_id":"r-gh-api","domain":{"name":null,"source":null,"confidence":null},"meta":{"dropped_since_last":0}}"#
    );
}

#[test]
fn golden_policy_line() {
    let line = encode_line(&DownMessage::Policy(sample_policy())).expect("encode");
    assert_eq!(
        line,
        r#"{"kind":"policy","container_id":"cid-1","generation":43,"mode":"block","default":"deny","rules":[{"id":"r-gh-api","action":"allow","match":{"type":"cidr","cidr":"140.82.121.0/24","port":443,"proto":"tcp"},"expires_at":null,"source":"static"}]}"#
    );
}

#[test]
fn golden_security_line() {
    let line = encode_line(&UpMessage::Security(sample_security())).expect("encode");
    assert_eq!(
        line,
        r#"{"kind":"security","timestamp":"2026-08-27T12:00:09.001271Z","severity_text":"ERROR","severity_number":17,"body":"denied connection to unresolved name rule target","attributes":{"container.id":"cid-2","container.image":"whoami:latest","container.name":"suspicious-1","reason":"policy.unenforceable_name","rule_id":"r-gh-name"}}"#
    );
}

#[test]
fn golden_stats_line() {
    let line = encode_line(&UpMessage::Stats(sample_stats())).expect("encode");
    assert_eq!(
        line,
        r#"{"kind":"stats","ts":"2026-08-27T12:05:00.000000Z","seq":31,"uptime_s":310,"events_emitted":4821,"events_dropped_total":0,"containers":[{"id":"cid-1","mode":"block","generation":43,"enforcing":true,"rules_active":4,"rules_inert":1,"dropped_total":0,"orphaned":false}]}"#
    );
}

// ---------------------------------------------------------------------
// The inert-matcher rule: the one ignore-unknown carve-out.
// ---------------------------------------------------------------------

#[test]
fn unknown_field_inside_match_is_captured_and_inert() {
    let json = r#"{"id":"r-x","action":"allow","match":{"type":"cidr","cidr":"10.0.0.0/8","port":null,"weird_new_field":123},"expires_at":null,"source":"static"}"#;
    let rule: Rule = serde_json::from_str(json).expect("a matcher with an unknown field must still parse");
    assert!(rule.r#match.is_inert(), "unknown field inside match must mark the rule inert");
    match &rule.r#match {
        Match::Cidr { unknown, cidr, .. } => {
            assert_eq!(cidr, "10.0.0.0/8");
            assert_eq!(unknown.get("weird_new_field"), Some(&serde_json::Value::Number(123.into())));
        }
        other => panic!("expected Match::Cidr, got {other:?}"),
    }
}

#[test]
fn known_matcher_with_no_unknown_fields_is_not_inert() {
    match &sample_policy().rules[0].r#match {
        m @ Match::Cidr { .. } => assert!(!m.is_inert()),
        other => panic!("expected Match::Cidr, got {other:?}"),
    }
}

#[test]
fn unrecognized_match_type_is_captured_as_inert_not_a_parse_error() {
    let json = r#"{"id":"r-y","action":"deny","match":{"type":"cidr_range","from":"10.0.0.0","to":"10.0.0.255"},"expires_at":null,"source":"static"}"#;
    let rule: Rule = serde_json::from_str(json).expect("an unrecognized matcher type must still parse");
    assert!(rule.r#match.is_inert());
    assert_eq!(rule.r#match, Match::Unknown);
}

#[test]
fn policy_snapshot_with_a_mix_of_inert_and_live_rules_still_parses_whole() {
    let json = r#"{"container_id":"cid-1","generation":1,"mode":"block","default":"deny","rules":[
        {"id":"r-1","action":"allow","match":{"type":"cidr","cidr":"1.2.3.0/24","port":null},"expires_at":null,"source":"static"},
        {"id":"r-2","action":"allow","match":{"type":"future_matcher","anything":"here"},"expires_at":null,"source":"static"}
    ]}"#;
    let policy: Policy = serde_json::from_str(json).expect("the whole snapshot parses even with one inert rule");
    let inert_count = policy.rules.iter().filter(|r| r.r#match.is_inert()).count();
    assert_eq!(inert_count, 1);
}

// ---------------------------------------------------------------------
// Ignore-unknown at the top level of an ordinary message (the general
// rule, everywhere except inside `match`).
// ---------------------------------------------------------------------

#[test]
fn unknown_top_level_field_on_an_event_is_ignored_without_error() {
    let json = r#"{"kind":"event","ts":"2026-08-27T12:00:03.482910Z","event":"connect","proto":"tcp","container":{"id":"cid-1","name":null,"image":null,"runtime":"docker"},"process":{"pid":null,"tid":null,"uid":null,"gid":null,"comm":null},"src":{"addr":"172.17.0.5","port":51234},"dst":{"addr":"140.82.121.6","port":443},"verdict":"allow","rule_id":null,"domain":{"name":null,"source":null,"confidence":null},"meta":{"dropped_since_last":0},"a_field_from_the_future":"ignore me"}"#;
    let message: UpMessage = serde_json::from_str(json).expect("unknown top-level field must not be a parse error");
    assert!(matches!(message, UpMessage::Event(_)));
}

#[test]
fn unknown_kind_on_up_stream_does_not_panic_the_decoder() {
    let json = r#"{"kind":"future_message","anything":"here"}"#;
    let result: Result<UpMessage, _> = decode_line(json);
    assert!(result.is_err(), "an unrecognized kind is a decode error the daemon counts and skips, not a panic");
}

// ---------------------------------------------------------------------
// The domain object is always present with all-null inner fields on a
// pre-DNS-layer event.
// ---------------------------------------------------------------------

#[test]
fn domain_object_is_always_present_and_all_null_pre_dns_layer() {
    let event = sample_event();
    assert_eq!(event.domain, Domain { name: None, source: None, confidence: None });
    let line = encode_line(&event).expect("encode");
    assert!(line.contains(r#""domain":{"name":null,"source":null,"confidence":null}"#));
}

// ---------------------------------------------------------------------
// Severity -> beacon Level mapping (R1).
// ---------------------------------------------------------------------

#[test]
fn severity_numbers_match_the_otel_scale_documented_for_beacon() {
    assert_eq!(Severity::Info.number(), 9);
    assert_eq!(Severity::Warning.number(), 13);
    assert_eq!(Severity::Error.number(), 17);
    assert_eq!(Severity::from_number(9), Severity::Info);
    assert_eq!(Severity::from_number(12), Severity::Info);
    assert_eq!(Severity::from_number(13), Severity::Warning);
    assert_eq!(Severity::from_number(16), Severity::Warning);
    assert_eq!(Severity::from_number(17), Severity::Error);
    assert_eq!(Severity::from_number(24), Severity::Error);
}

#[test]
fn security_record_attributes_are_sorted_deterministically() {
    let record = sample_security();
    let keys: Vec<&String> = record.attributes.keys().collect();
    let mut sorted = keys.clone();
    sorted.sort();
    assert_eq!(keys, sorted, "BTreeMap must keep attribute keys in sorted order for a stable wire shape");
}
