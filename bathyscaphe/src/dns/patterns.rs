// SPDX-License-Identifier: GPL-3.0-or-later
//! FQDN name-rule patterns (build chunk #10): [`NamePatternStore`] is the
//! per-container registry of `type: "name"` rule patterns
//! (`docs/PROTOCOL.md` section 4) `daemon::apply` populates from a
//! compiled `policy` directive and `crate::dns` (via `daemon::fqdn`)
//! consults on every DNS answer to decide whether a resolved address
//! should be inserted into the `POLICY` allow-map.
//!
//! ## Wildcard semantics
//!
//! A pattern is either an EXACT name (`api.github.com`) or a single
//! leading wildcard (`*.github.com`), per `docs/PROTOCOL.md` section 4's
//! grammar. [`pattern_matches`] implements the wildcard as a **multi-label
//! suffix match**: `*.github.com` matches `docs.github.com` (one extra
//! label) AND `raw.objects.github.com` (two extra labels) -- ANY name
//! that ends in `.github.com` with at least one more label in front of it.
//! This is deliberately NOT the narrower single-label convention a TLS
//! wildcard certificate (`*.github.com` matching `docs.github.com` but NOT
//! `raw.objects.github.com`) uses. The choice matches Cilium's `toFQDNs`
//! `matchPattern` glob semantics (`prior_art_fqdn.md`'s cloud-native
//! camp), where a leading `*` spans an arbitrary number of DNS labels, and
//! is the more useful default for the common "any subdomain of this
//! domain" intent an operator writing `*.github.com` almost always means.
//! A pattern of `*.github.com` never matches the bare apex `github.com`
//! itself -- if an operator wants both, `docs/PROTOCOL.md`'s grammar
//! expects two separate rules (`github.com` and `*.github.com`), matching
//! every DNS-snooping tool surveyed in `prior_art_fqdn.md` (none of them
//! treat a wildcard as implicitly covering its own apex either).
//!
//! Matching is case-insensitive and dot-normalized on both sides
//! (`super::parse::parse_dns_response`'s `normalize_name` already
//! lowercases and strips the trailing root dot from every name this
//! module ever sees from a real DNS answer; a compiled pattern is
//! normalized the same way at registration time in `daemon::compile`).
//!
//! ## A malformed pattern is inert, not rejected
//!
//! `docs/PROTOCOL.md`'s wire grammar for `Match::Name.pattern` is "exact
//! FQDN or a single leading wildcard" but nothing on the wire actually
//! enforces that shape -- a `pattern` field is just a `String`. A pattern
//! that violates the grammar (more than one `*`, a `*` not at the very
//! start, an empty string) is accepted onto the snapshot like any other
//! well-formed one, but functionally becomes an exact-match test against
//! that literal (odd) string, which in practice will simply never match a
//! real DNS answer's name. This is a deliberate v1 simplification -- an
//! operator error here fails safe (the pattern matches nothing, so no IP
//! is ever inserted for it) rather than failing loud with a rejected
//! snapshot, documented here rather than silently assumed away.

use bathyscaphe_common::{RuleAction, TransportProto};
use std::collections::HashMap;

/// One registered `type: "name"` rule for a container.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamePattern {
    /// Echoed as `rule_id` on a future events/records surface; not itself
    /// used by matching.
    pub rule_id: String,
    /// Normalized (lowercased, no trailing dot) exact name or
    /// `*.`-prefixed wildcard. See this module's doc for wildcard
    /// semantics.
    pub pattern: String,
    pub action: RuleAction,
    /// `None` = any port. Applied to the `POLICY` host-route's `PortRule`s
    /// on a match (`daemon::fqdn::on_dns_answer`) -- see
    /// `docs/PROTOCOL.md` section 4 and `bathy_build_spec.md`'s directive
    /// on carrying a name rule's port/proto constraint through to the
    /// inserted host route.
    pub port: Option<u16>,
    /// `None` = any protocol.
    pub proto: Option<TransportProto>,
}

/// True if `name` (already normalized: lowercase, no trailing dot) matches
/// `pattern` (normalized the same way at registration). See this module's
/// doc for the multi-label wildcard semantics.
pub fn pattern_matches(pattern: &str, name: &str) -> bool {
    match pattern.strip_prefix("*.") {
        Some(suffix) => {
            if suffix.is_empty() {
                return false;
            }
            // `name` must end in `.<suffix>` -- i.e. `suffix` plus at
            // least one more label in front of it, separated by a literal
            // dot immediately before `suffix` begins. A bare `name ==
            // suffix` (the apex) deliberately does not match -- see this
            // module's doc.
            name.len() > suffix.len() && name.ends_with(suffix) && name.as_bytes()[name.len() - suffix.len() - 1] == b'.'
        }
        None => name == pattern,
    }
}

/// The per-container registry: `cgroup_id -> [NamePattern]`. A full
/// replacement on every `set_patterns` call, matching the wire protocol's
/// own "a `policy` directive is a full snapshot, not a delta"
/// convention (`docs/PROTOCOL.md` section 4) -- a container's active name
/// patterns are exactly whatever its MOST RECENT `policy` compiled, never
/// an accumulation across snapshots.
#[derive(Default)]
pub struct NamePatternStore {
    by_cgroup: HashMap<u64, Vec<NamePattern>>,
}

impl NamePatternStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Replaces `cgroup_id`'s entire pattern set. An empty `patterns`
    /// removes the container's entry entirely (matching
    /// `daemon::state::DaemonState`'s own "absence means nothing
    /// registered" convention), so a later `has_active_allow_pattern`
    /// check and a `by_cgroup.len()`-based accounting never have to treat
    /// "explicitly empty" and "never registered" differently.
    pub fn set_patterns(&mut self, cgroup_id: u64, patterns: Vec<NamePattern>) {
        if patterns.is_empty() {
            self.by_cgroup.remove(&cgroup_id);
        } else {
            self.by_cgroup.insert(cgroup_id, patterns);
        }
    }

    /// Drops `cgroup_id`'s entire pattern set -- the `release`/
    /// `release_all` path.
    pub fn remove_container(&mut self, cgroup_id: u64) {
        self.by_cgroup.remove(&cgroup_id);
    }

    /// The first registered `Allow` pattern for `cgroup_id` matching
    /// `name` (already normalized), if any. Only the FIRST match is used
    /// (a v1 simplification, documented on
    /// `daemon::fqdn::on_dns_answer`): a name matching more than one
    /// registered pattern uses whichever pattern was compiled first,
    /// rather than merging every matching pattern's port/proto
    /// constraints into one entry.
    pub fn first_matching_allow(&self, cgroup_id: u64, name: &str) -> Option<&NamePattern> {
        self.by_cgroup.get(&cgroup_id)?.iter().find(|p| p.action == RuleAction::Allow && pattern_matches(&p.pattern, name))
    }

    /// Whether `cgroup_id` has at least one registered `Allow` name
    /// pattern at all (regardless of whether any particular name matches
    /// it). Used by `daemon::fqdn::NameUnresolvedBlockWatcher` to decide
    /// whether a deny-with-no-domain-enrichment event is plausibly this
    /// container's unresolved-name-rule traffic worth a loud record, or an
    /// ordinary CIDR-policy deny with nothing to do with names at all.
    pub fn has_active_allow_pattern(&self, cgroup_id: u64) -> bool {
        self.by_cgroup.get(&cgroup_id).map(|patterns| patterns.iter().any(|p| p.action == RuleAction::Allow)).unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_pattern_matches_only_the_exact_name() {
        assert!(pattern_matches("api.github.com", "api.github.com"));
        assert!(!pattern_matches("api.github.com", "docs.github.com"));
        assert!(!pattern_matches("api.github.com", "sub.api.github.com"));
    }

    #[test]
    fn wildcard_pattern_matches_a_single_leading_label() {
        assert!(pattern_matches("*.github.com", "docs.github.com"));
    }

    #[test]
    fn wildcard_pattern_matches_multiple_leading_labels() {
        assert!(pattern_matches("*.github.com", "raw.objects.github.com"), "multi-label suffix match, not single-label like a TLS wildcard cert");
    }

    #[test]
    fn wildcard_pattern_does_not_match_the_bare_apex() {
        assert!(!pattern_matches("*.github.com", "github.com"));
    }

    #[test]
    fn wildcard_pattern_does_not_match_an_unrelated_suffix() {
        assert!(!pattern_matches("*.github.com", "notgithub.com"));
        assert!(!pattern_matches("*.github.com", "evilgithub.com"));
    }

    #[test]
    fn wildcard_pattern_does_not_match_a_different_domain_entirely() {
        assert!(!pattern_matches("*.github.com", "example.com"));
    }

    #[test]
    fn a_bare_wildcard_with_no_suffix_matches_nothing() {
        assert!(!pattern_matches("*.", ""));
        assert!(!pattern_matches("*.", "anything.com"));
    }

    fn allow_pattern(rule_id: &str, pattern: &str) -> NamePattern {
        NamePattern { rule_id: rule_id.to_string(), pattern: pattern.to_string(), action: RuleAction::Allow, port: None, proto: None }
    }

    #[test]
    fn first_matching_allow_finds_a_registered_wildcard() {
        let mut store = NamePatternStore::new();
        store.set_patterns(1, vec![allow_pattern("r1", "*.github.com")]);
        let hit = store.first_matching_allow(1, "docs.github.com").expect("should match");
        assert_eq!(hit.rule_id, "r1");
    }

    #[test]
    fn first_matching_allow_returns_none_on_a_non_match() {
        let mut store = NamePatternStore::new();
        store.set_patterns(1, vec![allow_pattern("r1", "*.github.com")]);
        assert!(store.first_matching_allow(1, "example.com").is_none());
    }

    #[test]
    fn first_matching_allow_ignores_a_deny_pattern() {
        let mut store = NamePatternStore::new();
        store.set_patterns(1, vec![NamePattern { rule_id: "r1".to_string(), pattern: "github.com".to_string(), action: RuleAction::Deny, port: None, proto: None }]);
        assert!(store.first_matching_allow(1, "github.com").is_none());
    }

    #[test]
    fn a_different_container_never_sees_another_containers_patterns() {
        let mut store = NamePatternStore::new();
        store.set_patterns(1, vec![allow_pattern("r1", "github.com")]);
        assert!(store.first_matching_allow(2, "github.com").is_none());
    }

    #[test]
    fn set_patterns_fully_replaces_the_prior_snapshot() {
        let mut store = NamePatternStore::new();
        store.set_patterns(1, vec![allow_pattern("r1", "old.example.com")]);
        store.set_patterns(1, vec![allow_pattern("r2", "new.example.com")]);
        assert!(store.first_matching_allow(1, "old.example.com").is_none(), "the old snapshot's pattern must be gone, not merged");
        assert!(store.first_matching_allow(1, "new.example.com").is_some());
    }

    #[test]
    fn set_patterns_with_an_empty_vec_clears_the_container() {
        let mut store = NamePatternStore::new();
        store.set_patterns(1, vec![allow_pattern("r1", "github.com")]);
        store.set_patterns(1, vec![]);
        assert!(!store.has_active_allow_pattern(1));
    }

    #[test]
    fn has_active_allow_pattern_is_false_for_an_unregistered_container() {
        let store = NamePatternStore::new();
        assert!(!store.has_active_allow_pattern(99));
    }

    #[test]
    fn remove_container_clears_its_patterns() {
        let mut store = NamePatternStore::new();
        store.set_patterns(1, vec![allow_pattern("r1", "github.com")]);
        store.remove_container(1);
        assert!(!store.has_active_allow_pattern(1));
    }
}
