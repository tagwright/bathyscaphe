// SPDX-License-Identifier: GPL-3.0-or-later
//! Pure directive compilation: a wire [`bathyscaphe_proto::down::Policy`]
//! snapshot -> the bounded set of `POLICY`/`ENFORCEMENT` map writes that
//! implement it. No probe, no map, no I/O -- this is the piece
//! `docs/BUILDING.md`'s two-toolchain split makes worth keeping pure: every
//! rule here is `cargo test`-able on a plain host with no kernel, no
//! bpffs, and no `--privileged` in sight. [`super::apply`] is the thin
//! layer that takes a [`CompiledPolicy`] and actually calls a
//! [`super::probe_api::ProbeApi`].
//!
//! ## Aggregation
//!
//! Rules are grouped by their parsed destination prefix (CIDR text ->
//! `(addr, prefix_bits_over_addr)`, see [`parse_cidr`]): every rule
//! targeting the same prefix becomes port rules inside ONE
//! `bathyscaphe_common::PolicyValue`, per `bathyscaphe_common::policy`'s
//! schema (a `PolicyValue` is a per-*prefix* default action plus up to
//! `MAX_PORT_RULES` port rules, not a per-rule value). A rule with
//! `port: null` and `proto: null` sets that prefix's `cidr_default_action`
//! directly (deny wins if more than one such rule targets the same
//! prefix, matching the wire protocol's own "deny wins at equal
//! specificity" rule -- rules aggregated into the same `PolicyValue` are
//! by definition at equal specificity). A rule with `port: null` but a
//! specific `proto` cannot be folded into `cidr_default_action` (which has
//! no protocol axis), so it becomes a full `0..=65535` port rule instead
//! -- the "or a full-range PortRule" alternative the build brief calls
//! out.
//!
//! ## The synthesized container-wide baseline entry
//!
//! Every compiled snapshot also gets ONE synthesized entry at
//! `prefix_bits_over_addr = 0` (`PolicyKeyData::MIN_PREFIX_LEN` exactly,
//! i.e. "this container, any address at all") carrying the snapshot's own
//! `default` verdict as its `cidr_default_action`, UNLESS the rule set
//! already produced a real entry at that exact key (which is what an
//! explicit `{"type":"cidr","cidr":"::/0"}` rule parses to -- see
//! [`parse_cidr`]'s doc on why `0.0.0.0/0` does NOT collide with this: it
//! parses to `prefix_bits_over_addr = 96`, not `0`). Synthesizing this
//! entry means every lookup for a container with ANY compiled policy
//! always finds a match in the trie itself; `EnforcementState::default_verdict`
//! (consulted only on a true trie miss, i.e. a container with zero policy
//! entries at all) is then a redundant-but-consistent backstop rather than
//! the live fallback path, which keeps "what does an unmatched destination
//! do" answerable by reading the trie alone.
//!
//! ## Expiry of an aggregated entry
//!
//! `PolicyValue` carries exactly one `expires_at_ns` for the whole prefix,
//! not one per port rule, so aggregating several wire rules with different
//! `expires_at` values onto one prefix needs a single number. This
//! implementation takes the SOONEST (minimum) expiry among the
//! constituent rules that specify one, falling back to "never expires"
//! only if none of them do. The conservative direction was chosen
//! deliberately: when the soonest-expiring constituent rule lapses, the
//! whole prefix entry is reaped (`PolicyStore::reap_expired`) and falls
//! through to a broader or default entry rather than silently continuing
//! to enforce a port rule whose own TTL has already passed.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv6Addr};

use bathyscaphe_common::{DefaultVerdict, Mode, PolicyValue, PortRule};
use bathyscaphe_proto::down::{Match, Policy};

/// One compiled `POLICY` map entry: an address prefix plus the value to
/// write there. `prefix_bits_over_addr` follows
/// `probe::policy::build_policy_key`'s convention.
#[derive(Debug, Clone, PartialEq)]
pub struct CompiledEntry {
    pub addr: IpAddr,
    pub prefix_bits_over_addr: u32,
    pub value: PolicyValue,
}

/// One well-formed `type: "name"` rule compiled from a `policy` snapshot
/// (build chunk #10: `enforce_fqdn` is always advertised by this build, so
/// a name rule is now ACTIVE rather than universally inert -- see
/// `docs/PROTOCOL.md` section 4 and `docs/DNS.md`). [`super::apply`]
/// registers the whole `Vec` for a container's `cgroup_id` into
/// `crate::dns::NamePatternStore`, replacing that container's entire prior
/// pattern set (a `policy` snapshot is a full replacement, never a delta --
/// `docs/PROTOCOL.md` section 4). Matching semantics (exact vs. `*.`
/// wildcard) live in `crate::dns::patterns`, not here -- this struct is
/// pure data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledNamePattern {
    pub rule_id: String,
    /// Normalized (lowercased, trailing dot stripped) at compile time so
    /// every consumer (`crate::dns::patterns::pattern_matches`) compares
    /// against the same shape `crate::dns::parse::parse_dns_response`
    /// already normalizes a real DNS answer's name to.
    pub pattern: String,
    pub action: bathyscaphe_common::RuleAction,
    pub port: Option<u16>,
    pub proto: Option<bathyscaphe_common::TransportProto>,
}

/// The compiled form of one `policy` directive, everything
/// [`super::apply`] needs to drive [`super::probe_api::ProbeApi`] plus
/// report `policy_ack`.
#[derive(Debug, Clone, PartialEq)]
pub struct CompiledPolicy {
    pub generation: u64,
    pub mode: Mode,
    pub default: DefaultVerdict,
    pub entries: Vec<CompiledEntry>,
    /// `type` values this build has never heard of, and rules (of any
    /// type, cidr or name) carrying an unrecognized field inside a known
    /// matcher -- exactly `Match::is_inert()` summed across the snapshot's
    /// rules. Build chunk #10: a well-formed `type: "name"` rule no longer
    /// counts here at all -- it is ACTIVE (see [`CompiledNamePattern`]),
    /// not inert, since this build always advertises `enforce_fqdn`.
    pub inert_rules: u32,
    /// Every well-formed `type: "name"` rule from this snapshot, active
    /// under `enforce_fqdn`. See [`CompiledNamePattern`]'s doc.
    pub name_patterns: Vec<CompiledNamePattern>,
}

/// A directive that cannot be represented at all: today, exactly "one
/// destination prefix needs more than `PolicyValue::MAX_PORT_RULES` port
/// rules". Per `docs/PROTOCOL.md` section 4, this rejects the WHOLE
/// snapshot (`policy_ack.status: error`) rather than partially applying
/// it -- the previously applied generation, if any, stays enforced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompileError(pub String);

impl std::fmt::Display for CompileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

fn convert_mode(m: bathyscaphe_proto::Mode) -> Mode {
    match m {
        bathyscaphe_proto::Mode::Audit => Mode::Audit,
        bathyscaphe_proto::Mode::Alert => Mode::Alert,
        bathyscaphe_proto::Mode::Block => Mode::Block,
    }
}

fn convert_default(d: bathyscaphe_proto::DefaultVerdict) -> DefaultVerdict {
    match d {
        bathyscaphe_proto::DefaultVerdict::Allow => DefaultVerdict::Allow,
        bathyscaphe_proto::DefaultVerdict::Deny => DefaultVerdict::Deny,
    }
}

fn convert_action(a: bathyscaphe_proto::RuleAction) -> bathyscaphe_common::RuleAction {
    match a {
        bathyscaphe_proto::RuleAction::Allow => bathyscaphe_common::RuleAction::Allow,
        bathyscaphe_proto::RuleAction::Deny => bathyscaphe_common::RuleAction::Deny,
    }
}

fn convert_action_raw(a: bathyscaphe_proto::RuleAction) -> u8 {
    convert_action(a) as u8
}

fn convert_transport(p: bathyscaphe_proto::TransportProto) -> bathyscaphe_common::TransportProto {
    match p {
        bathyscaphe_proto::TransportProto::Tcp => bathyscaphe_common::TransportProto::Tcp,
        bathyscaphe_proto::TransportProto::Udp => bathyscaphe_common::TransportProto::Udp,
    }
}

fn convert_transport_raw(p: bathyscaphe_proto::TransportProto) -> u8 {
    convert_transport(p) as u8
}

/// Normalizes a wire `Match::Name.pattern` (or any DNS name) to the same
/// lowercase, no-trailing-dot shape `crate::dns::parse::parse_dns_response`
/// produces for a real answer's name, so pattern registration and
/// answer-side matching always compare like-for-like. Duplicated (rather
/// than depended on) here for the same "compile.rs stays free of anything
/// beyond `bathyscaphe_common`/`bathyscaphe_proto`" boundary this module's
/// doc already keeps for `addr_to_rfc4291`.
fn normalize_name(raw: &str) -> String {
    raw.trim_end_matches('.').to_ascii_lowercase()
}

/// Parses a wire `Match::Cidr.cidr` string into `(base address,
/// prefix_bits_over_addr)`, following `probe::policy::build_policy_key`'s
/// convention over the 128-bit RFC 4291-embedded address space: an IPv4
/// prefix of length `p` pins the 96-bit IPv4-mapped prefix plus `p` address
/// bits (`prefix_bits_over_addr = 96 + p`), so `0.0.0.0/0` is
/// `prefix_bits_over_addr = 96` (matches any IPv4 destination, never a
/// native IPv6 one), while an IPv6 prefix of length `p` is
/// `prefix_bits_over_addr = p` directly, so `::/0` is `0` -- the single
/// least specific key this schema can express, which is why the
/// container-wide baseline entry (module doc) is synthesized at that exact
/// key and only when a rule hasn't already claimed it.
fn parse_cidr(cidr: &str) -> Result<(IpAddr, u32), String> {
    let (addr_str, len_str) = cidr.split_once('/').ok_or_else(|| format!("cidr {cidr:?} is missing a /prefix"))?;
    let addr: IpAddr = addr_str.parse().map_err(|error| format!("cidr {cidr:?} has an invalid address: {error}"))?;
    let len: u32 = len_str.parse().map_err(|error| format!("cidr {cidr:?} has an invalid prefix length: {error}"))?;
    match addr {
        IpAddr::V4(_) => {
            if len > 32 {
                return Err(format!("cidr {cidr:?} prefix length {len} exceeds 32 for an IPv4 address"));
            }
            Ok((addr, 96 + len))
        }
        IpAddr::V6(_) => {
            if len > 128 {
                return Err(format!("cidr {cidr:?} prefix length {len} exceeds 128 for an IPv6 address"));
            }
            Ok((addr, len))
        }
    }
}

/// The RFC 4291 embedding `probe::policy::addr_to_rfc4291` also produces,
/// duplicated here (rather than depended on) to keep this module's tests
/// free of any `probe::*` import -- a deliberate boundary, since
/// `probe::policy` is the kernel-touching-adjacent side and this module is
/// meant to compile and test with none of that in scope.
fn addr_to_rfc4291(addr: IpAddr) -> [u8; 16] {
    match addr {
        IpAddr::V4(v4) => {
            let mut bytes = [0u8; 16];
            bytes[10] = 0xff;
            bytes[11] = 0xff;
            bytes[12..16].copy_from_slice(&v4.octets());
            bytes
        }
        IpAddr::V6(v6) => v6.octets(),
    }
}

fn unmap_addr(raw: [u8; 16]) -> IpAddr {
    let v6 = Ipv6Addr::from(raw);
    v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(IpAddr::V6(v6))
}

/// Per-prefix accumulator while folding a snapshot's rules into groups.
#[derive(Default)]
struct Group {
    default_action: Option<u8>,
    /// Keyed by `(port_lo, port_hi, proto)` so a second rule targeting the
    /// exact same port/proto combination updates in place (deny wins on a
    /// conflicting action) rather than appending a redundant entry that
    /// would count twice against `MAX_PORT_RULES`.
    port_rules: BTreeMap<(u16, u16, u8), u8>,
    any_dns_source: bool,
    min_expiry_ns: Option<u64>,
}

fn merge_action_deny_wins(existing: Option<u8>, incoming: u8) -> u8 {
    let deny = bathyscaphe_common::RuleAction::Deny as u8;
    if existing == Some(deny) || incoming == deny {
        deny
    } else {
        existing.unwrap_or(incoming)
    }
}

/// Compiles one `policy` directive. `resolve_expiry` converts a rule's
/// `expires_at` (an `Option<&str>` RFC3339 string, absolute) to an
/// absolute `CLOCK_BOOTTIME` nanosecond value, or `None` for "no expiry" --
/// injected rather than hardcoded so this function stays independent of
/// wall-clock/boottime sampling (`super::apply` supplies the real
/// conversion; tests supply a trivial one).
pub fn compile_policy(policy: &Policy, resolve_expiry: impl Fn(&str) -> Option<u64>) -> Result<CompiledPolicy, CompileError> {
    let mode = convert_mode(policy.mode);
    let default = convert_default(policy.default);
    let default_action_raw = match default {
        DefaultVerdict::Allow => bathyscaphe_common::RuleAction::Allow as u8,
        DefaultVerdict::Deny => bathyscaphe_common::RuleAction::Deny as u8,
    };

    let mut groups: BTreeMap<(u32, [u8; 16]), Group> = BTreeMap::new();
    let mut inert_rules = 0u32;
    let mut name_patterns = Vec::new();

    for rule in &policy.rules {
        match &rule.r#match {
            Match::Name { unknown, .. } if !unknown.is_empty() => {
                // An unrecognized field inside a `type: "name"` matcher --
                // the same inert-and-counted carve-out `Match::Cidr` gets
                // below, per `docs/PROTOCOL.md` section 4's "the one
                // ignore-unknown carve-out".
                inert_rules += 1;
            }
            Match::Name { pattern, port, proto, .. } => {
                name_patterns.push(CompiledNamePattern { rule_id: rule.id.clone(), pattern: normalize_name(pattern), action: convert_action(rule.action), port: *port, proto: proto.map(convert_transport) });
            }
            Match::Unknown => {
                inert_rules += 1;
            }
            Match::Cidr { unknown, .. } if !unknown.is_empty() => {
                inert_rules += 1;
            }
            Match::Cidr { cidr, port, proto, .. } => {
                let (addr, prefix_bits_over_addr) = parse_cidr(cidr).map_err(CompileError)?;
                let key = (prefix_bits_over_addr, addr_to_rfc4291(addr));
                let group = groups.entry(key).or_default();

                let action_raw = convert_action_raw(rule.action);
                let expiry_ns = rule.expires_at.as_deref().and_then(&resolve_expiry);
                group.min_expiry_ns = match (group.min_expiry_ns, expiry_ns) {
                    (Some(a), Some(b)) => Some(a.min(b)),
                    (Some(a), None) => Some(a),
                    (None, Some(b)) => Some(b),
                    (None, None) => None,
                };
                if rule.source == bathyscaphe_proto::RuleSource::Dns {
                    group.any_dns_source = true;
                }

                match (port, proto) {
                    (None, None) => {
                        group.default_action = Some(merge_action_deny_wins(group.default_action, action_raw));
                    }
                    (None, Some(p)) => {
                        let proto_raw = PortRule::encode_proto(convert_transport_raw(*p));
                        let entry_key = (0u16, 65535u16, proto_raw);
                        let merged = merge_action_deny_wins(group.port_rules.get(&entry_key).copied(), action_raw);
                        group.port_rules.insert(entry_key, merged);
                    }
                    (Some(port), proto) => {
                        let proto_raw = proto.map(|p| PortRule::encode_proto(convert_transport_raw(p))).unwrap_or(PortRule::PROTO_ANY);
                        let entry_key = (*port, *port, proto_raw);
                        let merged = merge_action_deny_wins(group.port_rules.get(&entry_key).copied(), action_raw);
                        group.port_rules.insert(entry_key, merged);
                    }
                }
            }
        }
    }

    // The synthesized container-wide baseline: only if no rule already
    // claimed the "any address at all" key (an explicit `::/0` rule).
    let baseline_key = (0u32, [0u8; 16]);
    groups.entry(baseline_key).or_insert_with(|| Group { default_action: Some(default_action_raw), ..Group::default() });

    let mut entries = Vec::with_capacity(groups.len());
    for ((prefix_bits_over_addr, addr_bytes), group) in groups {
        let cidr_default_action = group.default_action.unwrap_or(default_action_raw);
        let source_raw = if group.any_dns_source { bathyscaphe_common::RuleSource::Dns as u8 } else { bathyscaphe_common::RuleSource::Static as u8 };
        let expires_at_ns = group.min_expiry_ns.unwrap_or(PolicyValue::NEVER_EXPIRES);
        let mut value = PolicyValue::new(cidr_default_action, source_raw, expires_at_ns);
        for (port_lo, port_hi, proto_raw) in group.port_rules.keys().copied().collect::<Vec<_>>() {
            let action_raw = group.port_rules[&(port_lo, port_hi, proto_raw)];
            value = value
                .with_port_rule(PortRule::new(port_lo, port_hi, proto_raw, action_raw))
                .map_err(|_| CompileError(format!("destination prefix at {}/{} needs more than {} port rules (MAX_PORT_RULES); split it into an additional, narrower rule instead of relying on aggregation", unmap_addr(addr_bytes), prefix_bits_over_addr, PolicyValue::MAX_PORT_RULES)))?;
        }
        entries.push(CompiledEntry { addr: unmap_addr(addr_bytes), prefix_bits_over_addr, value });
    }

    Ok(CompiledPolicy { generation: policy.generation, mode, default, entries, inert_rules, name_patterns })
}

#[cfg(test)]
mod tests {
    use super::*;
    use bathyscaphe_proto::down::Rule;
    use bathyscaphe_proto::{DefaultVerdict as WireDefault, Mode as WireMode, RuleAction as WireAction, RuleSource as WireSource, TransportProto as WireProto};

    fn no_expiry(_: &str) -> Option<u64> {
        None
    }

    fn cidr_rule(id: &str, cidr: &str, port: Option<u16>, proto: Option<WireProto>, action: WireAction) -> Rule {
        Rule { id: id.to_string(), action, r#match: Match::Cidr { cidr: cidr.to_string(), port, proto, unknown: Default::default() }, expires_at: None, source: WireSource::Static }
    }

    fn name_rule(id: &str, pattern: &str, action: WireAction) -> Rule {
        Rule { id: id.to_string(), action, r#match: Match::Name { pattern: pattern.to_string(), port: None, proto: None, unknown: Default::default() }, expires_at: None, source: WireSource::Static }
    }

    fn base_policy(mode: WireMode, default: WireDefault, rules: Vec<Rule>) -> Policy {
        Policy { container_id: "c".repeat(64), generation: 1, mode, default, rules }
    }

    fn find_entry<'a>(compiled: &'a CompiledPolicy, addr: &str, prefix_bits_over_addr: u32) -> &'a CompiledEntry {
        let addr: IpAddr = addr.parse().unwrap();
        compiled.entries.iter().find(|e| e.addr == addr && e.prefix_bits_over_addr == prefix_bits_over_addr).unwrap_or_else(|| panic!("no compiled entry for {addr}/{prefix_bits_over_addr}"))
    }

    #[test]
    fn cidr_aggregation_folds_two_rules_on_the_same_prefix_into_one_entry() {
        let policy = base_policy(
            WireMode::Block,
            WireDefault::Deny,
            vec![cidr_rule("r1", "10.0.0.0/24", Some(443), Some(WireProto::Tcp), WireAction::Allow), cidr_rule("r2", "10.0.0.0/24", Some(53), Some(WireProto::Udp), WireAction::Allow)],
        );
        let compiled = compile_policy(&policy, no_expiry).expect("compiles");
        // Baseline + exactly one aggregated entry for the /24 (both rules
        // fold into the same PolicyValue, not two entries).
        assert_eq!(compiled.entries.len(), 2);
        let entry = find_entry(&compiled, "10.0.0.0", 96 + 24);
        assert_eq!(entry.value.n_port_rules, 2);
    }

    #[test]
    fn any_port_any_proto_rule_sets_cidr_default_action_not_a_port_rule() {
        let policy = base_policy(WireMode::Block, WireDefault::Deny, vec![cidr_rule("r1", "10.0.0.0/8", None, None, WireAction::Allow)]);
        let compiled = compile_policy(&policy, no_expiry).expect("compiles");
        let entry = find_entry(&compiled, "10.0.0.0", 96 + 8);
        assert_eq!(entry.value.n_port_rules, 0);
        assert_eq!(entry.value.cidr_default_action, bathyscaphe_common::RuleAction::Allow as u8);
    }

    #[test]
    fn any_port_with_proto_becomes_a_full_range_port_rule() {
        let policy = base_policy(WireMode::Block, WireDefault::Deny, vec![cidr_rule("r1", "10.0.0.0/8", None, Some(WireProto::Udp), WireAction::Deny)]);
        let compiled = compile_policy(&policy, no_expiry).expect("compiles");
        let entry = find_entry(&compiled, "10.0.0.0", 96 + 8);
        assert_eq!(entry.value.n_port_rules, 1);
        assert_eq!(entry.value.port_rules[0].port_lo, 0);
        assert_eq!(entry.value.port_rules[0].port_hi, 65535);
        assert!(entry.value.port_rules[0].matches_proto(bathyscaphe_common::TransportProto::Udp as u8));
        assert!(!entry.value.port_rules[0].matches_proto(bathyscaphe_common::TransportProto::Tcp as u8));
    }

    #[test]
    fn deny_wins_over_allow_at_equal_specificity() {
        let policy = base_policy(WireMode::Block, WireDefault::Deny, vec![cidr_rule("r1", "10.0.0.0/8", None, None, WireAction::Allow), cidr_rule("r2", "10.0.0.0/8", None, None, WireAction::Deny)]);
        let compiled = compile_policy(&policy, no_expiry).expect("compiles");
        let entry = find_entry(&compiled, "10.0.0.0", 96 + 8);
        assert_eq!(entry.value.cidr_default_action, bathyscaphe_common::RuleAction::Deny as u8);
    }

    #[test]
    fn port_rule_cap_overflow_is_rejected_never_truncated() {
        let mut rules = Vec::new();
        for port in 0..=8u16 {
            // 9 distinct ports on the same /24 -- one more than MAX_PORT_RULES (8).
            rules.push(cidr_rule(&format!("r{port}"), "10.0.0.0/24", Some(1000 + port), None, WireAction::Allow));
        }
        let policy = base_policy(WireMode::Block, WireDefault::Deny, rules);
        let result = compile_policy(&policy, no_expiry);
        assert!(result.is_err(), "9 port rules on one prefix must be rejected, not silently truncated to 8");
    }

    #[test]
    fn port_rule_cap_at_exactly_the_limit_is_accepted() {
        let mut rules = Vec::new();
        for port in 0..8u16 {
            rules.push(cidr_rule(&format!("r{port}"), "10.0.0.0/24", Some(1000 + port), None, WireAction::Allow));
        }
        let policy = base_policy(WireMode::Block, WireDefault::Deny, rules);
        let compiled = compile_policy(&policy, no_expiry).expect("exactly 8 port rules on one prefix must compile");
        let entry = find_entry(&compiled, "10.0.0.0", 96 + 24);
        assert_eq!(entry.value.n_port_rules, 8);
    }

    #[test]
    fn a_well_formed_name_rule_is_active_not_inert() {
        // Build chunk #10: enforce_fqdn is always advertised, so a
        // well-formed name rule is no longer counted as inert -- it
        // becomes a registered CompiledNamePattern instead.
        let policy = base_policy(WireMode::Alert, WireDefault::Allow, vec![name_rule("r1", "*.example.com", WireAction::Allow)]);
        let compiled = compile_policy(&policy, no_expiry).expect("compiles");
        assert_eq!(compiled.inert_rules, 0);
        assert_eq!(compiled.name_patterns.len(), 1);
        assert_eq!(compiled.name_patterns[0].rule_id, "r1");
        assert_eq!(compiled.name_patterns[0].pattern, "*.example.com");
        assert_eq!(compiled.name_patterns[0].action, bathyscaphe_common::RuleAction::Allow);
        // Baseline entry only -- a name rule contributes no POLICY entry of
        // its own; only a subsequent DNS answer match does that.
        assert_eq!(compiled.entries.len(), 1);
    }

    #[test]
    fn a_name_rule_pattern_is_normalized_to_lowercase_with_no_trailing_dot() {
        let policy = base_policy(WireMode::Alert, WireDefault::Allow, vec![name_rule("r1", "GitHub.COM.", WireAction::Allow)]);
        let compiled = compile_policy(&policy, no_expiry).expect("compiles");
        assert_eq!(compiled.name_patterns[0].pattern, "github.com");
    }

    #[test]
    fn a_name_rule_carries_its_port_and_proto_constraint_through() {
        let mut rule = name_rule("r1", "github.com", WireAction::Allow);
        rule.r#match = Match::Name { pattern: "github.com".to_string(), port: Some(443), proto: Some(WireProto::Tcp), unknown: Default::default() };
        let policy = base_policy(WireMode::Block, WireDefault::Deny, vec![rule]);
        let compiled = compile_policy(&policy, no_expiry).expect("compiles");
        assert_eq!(compiled.name_patterns[0].port, Some(443));
        assert_eq!(compiled.name_patterns[0].proto, Some(bathyscaphe_common::TransportProto::Tcp));
    }

    #[test]
    fn a_name_rule_with_an_unrecognized_field_is_still_inert_and_counted() {
        let mut unknown = serde_json::Map::new();
        unknown.insert("weird_field".to_string(), serde_json::Value::Bool(true));
        let rule = Rule { id: "r1".to_string(), action: WireAction::Allow, r#match: Match::Name { pattern: "github.com".to_string(), port: None, proto: None, unknown }, expires_at: None, source: WireSource::Static };
        let policy = base_policy(WireMode::Alert, WireDefault::Allow, vec![rule]);
        let compiled = compile_policy(&policy, no_expiry).expect("compiles");
        assert_eq!(compiled.inert_rules, 1, "an unrecognized field inside a name matcher is still the one ignore-unknown carve-out");
        assert!(compiled.name_patterns.is_empty(), "a rule marked inert must not also register an active pattern");
    }

    #[test]
    fn a_deny_name_rule_is_still_registered_as_a_pattern() {
        // A `deny` name rule is accepted onto the snapshot like any other
        // (this build does not actively ENFORCE a name-based deny -- see
        // docs/DNS.md's residual limitations -- but it must not be
        // silently discarded or miscounted as inert either).
        let policy = base_policy(WireMode::Block, WireDefault::Deny, vec![name_rule("r1", "evil.example.com", WireAction::Deny)]);
        let compiled = compile_policy(&policy, no_expiry).expect("compiles");
        assert_eq!(compiled.name_patterns.len(), 1);
        assert_eq!(compiled.name_patterns[0].action, bathyscaphe_common::RuleAction::Deny);
        assert_eq!(compiled.inert_rules, 0);
    }

    #[test]
    fn unknown_match_type_is_inert_and_counted() {
        let policy = base_policy(WireMode::Alert, WireDefault::Allow, vec![Rule { id: "r1".to_string(), action: WireAction::Allow, r#match: Match::Unknown, expires_at: None, source: WireSource::Static }]);
        let compiled = compile_policy(&policy, no_expiry).expect("compiles");
        assert_eq!(compiled.inert_rules, 1);
    }

    #[test]
    fn cidr_rule_with_captured_unknown_field_is_inert_and_not_enforced() {
        let mut unknown = serde_json::Map::new();
        unknown.insert("weird_field".to_string(), serde_json::Value::Bool(true));
        let rule = Rule { id: "r1".to_string(), action: WireAction::Allow, r#match: Match::Cidr { cidr: "10.0.0.0/8".to_string(), port: None, proto: None, unknown }, expires_at: None, source: WireSource::Static };
        let policy = base_policy(WireMode::Alert, WireDefault::Allow, vec![rule]);
        let compiled = compile_policy(&policy, no_expiry).expect("compiles");
        assert_eq!(compiled.inert_rules, 1);
        // Only the baseline entry -- the inert cidr rule contributed nothing.
        assert_eq!(compiled.entries.len(), 1);
        assert_eq!(compiled.entries[0].prefix_bits_over_addr, 0);
    }

    #[test]
    fn baseline_entry_carries_the_snapshot_default_verdict() {
        let policy = base_policy(WireMode::Block, WireDefault::Deny, vec![cidr_rule("r1", "10.0.0.0/8", Some(443), None, WireAction::Allow)]);
        let compiled = compile_policy(&policy, no_expiry).expect("compiles");
        let baseline = compiled.entries.iter().find(|e| e.prefix_bits_over_addr == 0).expect("baseline entry always present");
        assert_eq!(baseline.value.cidr_default_action, bathyscaphe_common::RuleAction::Deny as u8);
        assert_eq!(baseline.value.n_port_rules, 0);
    }

    #[test]
    fn an_explicit_native_v6_any_rule_is_not_clobbered_by_the_synthesized_baseline() {
        let policy = base_policy(WireMode::Block, WireDefault::Deny, vec![cidr_rule("r1", "::/0", None, None, WireAction::Allow)]);
        let compiled = compile_policy(&policy, no_expiry).expect("compiles");
        // Exactly one entry at the baseline key, carrying the EXPLICIT
        // rule's allow action, not the snapshot's deny default.
        let entries_at_baseline: Vec<_> = compiled.entries.iter().filter(|e| e.prefix_bits_over_addr == 0).collect();
        assert_eq!(entries_at_baseline.len(), 1);
        assert_eq!(entries_at_baseline[0].value.cidr_default_action, bathyscaphe_common::RuleAction::Allow as u8);
    }

    #[test]
    fn ipv4_any_cidr_does_not_collide_with_the_ipv6_baseline_key() {
        let policy = base_policy(WireMode::Alert, WireDefault::Allow, vec![cidr_rule("r1", "0.0.0.0/0", None, None, WireAction::Deny)]);
        let compiled = compile_policy(&policy, no_expiry).expect("compiles");
        // Two distinct entries: the IPv4 "any" at prefix_bits_over_addr=96,
        // and the synthesized baseline at 0 -- proving they never merge.
        assert_eq!(compiled.entries.len(), 2);
        let v4_any = find_entry(&compiled, "0.0.0.0", 96);
        assert_eq!(v4_any.value.cidr_default_action, bathyscaphe_common::RuleAction::Deny as u8);
        let baseline = find_entry(&compiled, "::", 0);
        assert_eq!(baseline.value.cidr_default_action, bathyscaphe_common::RuleAction::Allow as u8);
    }

    #[test]
    fn generation_is_threaded_through_unmodified() {
        let mut policy = base_policy(WireMode::Audit, WireDefault::Allow, vec![]);
        policy.generation = 42;
        let compiled = compile_policy(&policy, no_expiry).expect("compiles");
        assert_eq!(compiled.generation, 42);
    }

    #[test]
    fn expiry_of_an_aggregated_entry_is_the_soonest_of_its_constituent_rules() {
        let mut r1 = cidr_rule("r1", "10.0.0.0/24", Some(443), None, WireAction::Allow);
        r1.expires_at = Some("2026-01-01T00:00:00Z".to_string());
        let mut r2 = cidr_rule("r2", "10.0.0.0/24", Some(80), None, WireAction::Allow);
        r2.expires_at = Some("2025-01-01T00:00:00Z".to_string());
        let policy = base_policy(WireMode::Alert, WireDefault::Allow, vec![r1, r2]);

        // A trivial resolver: earlier year -> smaller boottime ns.
        let resolve = |s: &str| -> Option<u64> {
            if s.starts_with("2025") {
                Some(100)
            } else {
                Some(200)
            }
        };
        let compiled = compile_policy(&policy, resolve).expect("compiles");
        let entry = find_entry(&compiled, "10.0.0.0", 96 + 24);
        assert_eq!(entry.value.expires_at_ns, 100, "the soonest constituent expiry wins");
    }

    #[test]
    fn no_expiry_on_any_constituent_rule_means_never_expires() {
        let policy = base_policy(WireMode::Alert, WireDefault::Allow, vec![cidr_rule("r1", "10.0.0.0/24", Some(443), None, WireAction::Allow)]);
        let compiled = compile_policy(&policy, no_expiry).expect("compiles");
        let entry = find_entry(&compiled, "10.0.0.0", 96 + 24);
        assert_eq!(entry.value.expires_at_ns, PolicyValue::NEVER_EXPIRES);
    }
}
