// SPDX-License-Identifier: GPL-3.0-or-later
//! The DNS observation domain layer (build chunk #9): parsing captured raw
//! DNS response payloads and the per-container IP->domain cache that
//! feeds today's event enrichment ([`crate::pipeline::map`]) and will feed
//! chunk #10's FQDN-rule enforcement tomorrow. See `docs/DNS.md` for the
//! full, honest account of what this observes and what it structurally
//! cannot (DoH/DoT/ECH, TCP-DNS, spoofing).
//!
//! - [`parse`]: pure, no-map, no-clock DNS message parsing
//!   ([`parse::parse_dns_response`]) using the `simple-dns` crate. See that
//!   module's doc for why this crate was chosen over `hickory-proto` and
//!   `dns-parser`.
//! - [`cache`]: [`cache::DomainCache`], the per-container `dst IP -> {name,
//!   confidence}` store the parser feeds and [`crate::pipeline::map`]
//!   reads. See that module's doc for the exact seam chunk #10 (FQDN
//!   enforcement) plugs into.

pub mod cache;
pub mod parse;

use std::sync::{Arc, Mutex};

use bathyscaphe_common::DnsCapture;

pub use cache::{DomainCache, DomainHit, STALE_GRACE_NS};
pub use parse::{ParsedDnsResponse, parse_dns_response};

/// Builds the `DNS_EVENTS` ring-buffer callback shared by both
/// `daemon::Daemon::run` and the standalone `observe` CLI: parse the
/// captured payload and, on a successful parse, record every resolved
/// answer into `cache`, keyed by the capture's own `cgroup_id` and timed
/// against the capture's own `ktime_ns` (see [`cache::DomainCache::record`]'s
/// doc for why). A capture that fails to parse as DNS, or parses but
/// carries no A/AAAA answers, is silently not recorded -- see
/// [`parse::parse_dns_response`]'s doc and `docs/DNS.md`'s "why domain is
/// null" list for why that is the expected, correct behavior for a
/// meaningful fraction of captured datagrams.
///
/// Returns the exact `Box<dyn FnMut(DnsCapture) + Send + 'static>` shape
/// `probe::dns::DnsCaptureConsumer::spawn` (aliased there as
/// `probe::DnsCallback`) expects, without this module needing to depend
/// on `probe` for a type alias name.
pub fn capture_callback(cache: Arc<Mutex<DomainCache>>) -> Box<dyn FnMut(DnsCapture) + Send + 'static> {
    Box::new(move |capture: DnsCapture| {
        let Some(parsed) = parse::parse_dns_response(capture.captured()) else {
            return;
        };
        let mut cache = cache.lock().unwrap_or_else(|poison| poison.into_inner());
        for (addr, ttl_secs) in parsed.answers {
            cache.record(capture.cgroup_id, parsed.name.clone(), addr, ttl_secs, capture.ktime_ns);
        }
    })
}
