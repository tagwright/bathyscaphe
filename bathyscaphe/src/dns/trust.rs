// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 techgaud
//! The trusted-resolver allowlist (build chunk #11): closes the passive-DNS
//! spoofing gap `docs/DNS.md` documented under chunks #9/#10 -- `dns_snoop`
//! (`bathyscaphe-ebpf::dns`) trusts *any* UDP:53-sourced datagram it
//! captures, with no opinion of its own on whether the sender is a resolver
//! this container actually ought to be talking to. A process able to inject
//! a spoofed UDP:53 reply into the same network namespace (or a container
//! deliberately pointed at a lying resolver it controls) could otherwise
//! seed its own container's `POLICY` allow-map with an attacker-chosen
//! address, simply by answering a name the container's own active allow
//! rule already trusts.
//!
//! [`TrustedResolvers`] is the userspace side of the fix: an
//! operator-configured set of resolver addresses. `daemon::fqdn::on_dns_answer`
//! (Part A's enforcement gate) only uses a DNS answer to seed the `POLICY`
//! allow/deny map when [`TrustedResolvers::is_trusted`] on the response's
//! own captured source address (`bathyscaphe_common::DnsCapture::src_addr`,
//! new in this chunk) returns `true`. An answer from an untrusted source is
//! never used for enforcement -- see `docs/DNS.md`'s "enforcement versus
//! enrichment trust" section for how [`crate::dns::DomainCache`]'s
//! enrichment path (a materially lower-stakes consumer) is allowed to
//! differ.
//!
//! ## The default set
//!
//! Trust-everything is explicitly rejected (`bathy_build_spec.md`'s build
//! brief: "Do NOT default to trust-everything"). The sensible default this
//! module builds ([`TrustedResolvers::default_set_from`]) is:
//!
//! - [`DOCKER_EMBEDDED_DNS`] (`127.0.0.11`): Docker's embedded
//!   per-container resolver on a user-defined bridge/compose network. Its
//!   replies genuinely originate from `127.0.0.11` regardless of the
//!   destination-port DNAT rewrite `bathyscaphe-ebpf::dns_query`'s own doc
//!   investigates (that rewrite is port-only, address-invariant -- see that
//!   module's "Docker's embedded-DNS DNAT rewrite" section) -- so this
//!   address is the canonical trusted source for any embedded-DNS
//!   container, unconditionally, not just a configurable convenience.
//! - Every `nameserver` line in `/etc/resolv.conf` ([`parse_resolv_conf_nameservers`]):
//!   the HOST's own configured upstream resolvers, on the reasoning that a
//!   container reaching one of ITS host's own configured nameservers
//!   directly (rather than through Docker's embedded resolver) is using a
//!   resolver the operator already implicitly trusts for every other
//!   purpose on this host.
//!
//! `--trusted-resolver <ip>` (repeatable, `cli::RunArgs::trusted_resolver`)
//! adds operator-specified addresses on top of this default set --
//! [`TrustedResolvers::with_extra`].
//!
//! ## The fail-closed direction
//!
//! A container using a resolver OUTSIDE the trusted set (a third-party
//! public resolver reached directly, a container-internal resolver this
//! operator never configured) simply never gets a name rule's resolved IPs
//! seeded into its allow-map. In `mode: block`, that falls straight back to
//! the container's ordinary IP/CIDR default -- normally a deny, per
//! `bathy_build_spec.md`'s "UNENFORCEABLE name in block mode fails closed"
//! stance -- an over-block, never a silent widening. This is the safe
//! direction to err in: a name rule an operator expected to work quietly
//! stops passing traffic (loud, via `policy.name_unresolved_block`, and now
//! also `dns.untrusted_answer` when the untrusted answer would otherwise
//! have matched), rather than an attacker's forged answer quietly buying
//! its way onto the allow-map.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;

/// Docker's embedded per-container DNS resolver on a user-defined
/// bridge/compose network. See this module's doc for why this is always
/// part of the default trusted set, not merely a configurable suggestion.
pub const DOCKER_EMBEDDED_DNS: IpAddr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 11));

/// Parses the `nameserver <ip>` lines of an `/etc/resolv.conf`-shaped
/// text (RFC-ish, `resolv.conf(5)`): one directive per line, `#` or `;`
/// starts a comment that runs to the end of the line, blank/unrecognized
/// lines are ignored, and a `nameserver` line whose address fails to parse
/// (a malformed or IPv6-scoped-zone address this simple parser does not
/// attempt to handle) is skipped rather than aborting the whole file. Takes
/// the file's CONTENTS rather than a path so this stays a pure, unit-testable
/// function with no filesystem access of its own -- see
/// [`TrustedResolvers::default_at`] for the real-filesystem-reading wrapper.
pub fn parse_resolv_conf_nameservers(contents: &str) -> Vec<IpAddr> {
    contents
        .lines()
        .filter_map(|line| {
            let line = line.split('#').next().unwrap_or("");
            let line = line.split(';').next().unwrap_or("").trim();
            let mut parts = line.split_whitespace();
            if parts.next()? != "nameserver" {
                return None;
            }
            parts.next()?.parse().ok()
        })
        .collect()
}

/// The operator-configured set of DNS resolver addresses trusted to seed
/// FQDN name-rule enforcement. See this module's doc for the default set
/// and the fail-closed direction an untrusted answer falls back to.
#[derive(Debug, Clone, Default)]
pub struct TrustedResolvers {
    set: HashSet<IpAddr>,
}

impl TrustedResolvers {
    /// Builds a set from an explicit list of addresses. Deliberately no
    /// "trust everything" constructor exists anywhere in this module --
    /// the only ways to grow a [`TrustedResolvers`] are this constructor,
    /// [`Self::with_extra`], and [`Self::default_set_from`]/[`Self::default_at`],
    /// all of which require the caller (or `/etc/resolv.conf`) to name
    /// specific addresses.
    pub fn new(addrs: impl IntoIterator<Item = IpAddr>) -> Self {
        Self { set: addrs.into_iter().collect() }
    }

    /// The default set: [`DOCKER_EMBEDDED_DNS`] plus every nameserver
    /// parsed from `resolv_conf_contents` ([`parse_resolv_conf_nameservers`]).
    pub fn default_set_from(resolv_conf_contents: &str) -> Self {
        Self::new(std::iter::once(DOCKER_EMBEDDED_DNS).chain(parse_resolv_conf_nameservers(resolv_conf_contents)))
    }

    /// Reads `resolv_conf_path` (typically `/etc/resolv.conf`) and builds
    /// the default set from its contents. A read failure (missing file,
    /// permission denied -- plausible inside a minimal container image)
    /// degrades to "just [`DOCKER_EMBEDDED_DNS`]" rather than failing the
    /// whole daemon: the set this produces is still never empty, still
    /// never "trust everything", and the caller (`cli::run_cmd`) is
    /// expected to log the degraded case loudly using
    /// [`parse_resolv_conf_nameservers`] directly against the same
    /// contents, since this method alone cannot distinguish "no
    /// nameserver lines" from "file unreadable" once it has already
    /// substituted an empty string for either.
    pub fn default_at(resolv_conf_path: &Path) -> Self {
        let contents = std::fs::read_to_string(resolv_conf_path).unwrap_or_default();
        Self::default_set_from(&contents)
    }

    /// Adds operator-specified addresses on top of whatever this set
    /// already holds (typically the default set) -- `--trusted-resolver`.
    pub fn with_extra(mut self, extra: impl IntoIterator<Item = IpAddr>) -> Self {
        self.set.extend(extra);
        self
    }

    /// Whether `addr` (a captured DNS response's own source address) is
    /// trusted to seed FQDN name-rule enforcement.
    pub fn is_trusted(&self, addr: IpAddr) -> bool {
        self.set.contains(&addr)
    }

    pub fn is_empty(&self) -> bool {
        self.set.is_empty()
    }

    pub fn len(&self) -> usize {
        self.set.len()
    }

    pub fn iter(&self) -> impl Iterator<Item = &IpAddr> {
        self.set.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_simple_nameserver_line() {
        let addrs = parse_resolv_conf_nameservers("nameserver 8.8.8.8\n");
        assert_eq!(addrs, vec![IpAddr::from([8, 8, 8, 8])]);
    }

    #[test]
    fn parses_multiple_nameserver_lines() {
        let contents = "nameserver 8.8.8.8\nnameserver 1.1.1.1\n";
        let addrs = parse_resolv_conf_nameservers(contents);
        assert_eq!(addrs, vec![IpAddr::from([8, 8, 8, 8]), IpAddr::from([1, 1, 1, 1])]);
    }

    #[test]
    fn parses_an_ipv6_nameserver() {
        let addrs = parse_resolv_conf_nameservers("nameserver 2001:4860:4860::8888\n");
        assert_eq!(addrs, vec!["2001:4860:4860::8888".parse::<IpAddr>().unwrap()]);
    }

    #[test]
    fn ignores_a_full_line_comment() {
        let addrs = parse_resolv_conf_nameservers("# nameserver 8.8.8.8\n");
        assert!(addrs.is_empty());
    }

    #[test]
    fn strips_a_trailing_comment_on_a_real_directive() {
        let addrs = parse_resolv_conf_nameservers("nameserver 8.8.8.8 # comment\n");
        assert_eq!(addrs, vec![IpAddr::from([8, 8, 8, 8])]);
    }

    #[test]
    fn ignores_unrelated_directives() {
        let contents = "search example.com\noptions ndots:1\nnameserver 8.8.8.8\n";
        let addrs = parse_resolv_conf_nameservers(contents);
        assert_eq!(addrs, vec![IpAddr::from([8, 8, 8, 8])]);
    }

    #[test]
    fn a_malformed_nameserver_address_is_skipped_not_fatal() {
        let contents = "nameserver not-an-ip\nnameserver 8.8.8.8\n";
        let addrs = parse_resolv_conf_nameservers(contents);
        assert_eq!(addrs, vec![IpAddr::from([8, 8, 8, 8])]);
    }

    #[test]
    fn empty_contents_yield_no_nameservers() {
        assert!(parse_resolv_conf_nameservers("").is_empty());
    }

    #[test]
    fn default_set_from_always_includes_the_docker_embedded_resolver() {
        let set = TrustedResolvers::default_set_from("");
        assert!(set.is_trusted(DOCKER_EMBEDDED_DNS));
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn default_set_from_includes_resolv_conf_nameservers_too() {
        let set = TrustedResolvers::default_set_from("nameserver 8.8.8.8\n");
        assert!(set.is_trusted(DOCKER_EMBEDDED_DNS));
        assert!(set.is_trusted(IpAddr::from([8, 8, 8, 8])));
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn with_extra_adds_operator_specified_addresses() {
        let set = TrustedResolvers::new([]).with_extra([IpAddr::from([9, 9, 9, 9])]);
        assert!(set.is_trusted(IpAddr::from([9, 9, 9, 9])));
        assert!(!set.is_trusted(IpAddr::from([1, 1, 1, 1])));
    }

    #[test]
    fn an_untrusted_address_is_not_trusted() {
        let set = TrustedResolvers::default_set_from("nameserver 8.8.8.8\n");
        assert!(!set.is_trusted(IpAddr::from([203, 0, 113, 9])));
    }

    #[test]
    fn a_bare_new_with_no_addresses_is_empty_never_trust_everything() {
        let set = TrustedResolvers::new([]);
        assert!(set.is_empty());
        assert!(!set.is_trusted(IpAddr::from([1, 2, 3, 4])), "an empty set must trust nothing, never fall back to trust-everything");
    }

    #[test]
    fn default_at_degrades_to_just_the_docker_default_on_an_unreadable_path() {
        let set = TrustedResolvers::default_at(Path::new("/nonexistent/definitely-not-a-real-resolv.conf"));
        assert!(set.is_trusted(DOCKER_EMBEDDED_DNS));
        assert_eq!(set.len(), 1, "an unreadable resolv.conf must never widen to trust-everything, only degrade to the built-in Docker default");
    }
}
