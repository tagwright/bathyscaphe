// SPDX-License-Identifier: GPL-3.0-or-later
//! Parsing a captured, possibly-truncated UDP DNS response payload
//! (`bathyscaphe_common::DnsCapture::captured()`) into the queried name
//! plus every resolved A/AAAA answer address and its TTL.
//!
//! ## Parser choice: `simple-dns`, not `hickory-proto` or `dns-parser`
//!
//! All three are maintained-userspace-viable choices; this crate only
//! ever needs to *decode* an already-captured message (never build,
//! sign, or resolve one), which narrows what "best" means here to
//! "smallest, most stable surface for read-only message parsing":
//!
//! - **`hickory-proto`** (the maintained continuation of `trust-dns`) is
//!   the most actively maintained of the three and the most complete --
//!   full DNSSEC record support, a resolver/client/server-oriented type
//!   hierarchy. That completeness is also the drawback for this use case:
//!   it is designed as the shared protocol crate underneath a full
//!   resolver/server stack (`hickory-resolver`/`hickory-server`), pulling
//!   in a correspondingly larger surface and dependency footprint than a
//!   userspace daemon that only ever calls one read-only parse function
//!   needs.
//! - **`dns-parser`** is small and focused, but its maintenance cadence is
//!   visibly slower than the other two (long gaps between releases, few
//!   recent commits) -- exactly the "MAINTAINED" criterion the build
//!   brief calls out, and the one this crate fails hardest.
//! - **`simple-dns`** (chosen): actively maintained (used as the parser
//!   underneath current mDNS crates, which exercises the same "parse an
//!   untrusted UDP DNS-shaped payload" path this module needs), a small,
//!   single-purpose message-parsing surface with plain public fields
//!   (`Packet::questions`, `Packet::answers`, `ResourceRecord::rdata`) and
//!   no resolver/client baggage, and works unmodified in `std` (no
//!   `no_std` requirement exists here -- this module runs in the
//!   userspace daemon, not `bathyscaphe-ebpf`).
//!
//! ## Malformed input
//!
//! `Packet::parse` returning an error (truncated header, invalid label
//! pointer, garbage bytes -- anything that isn't a well-formed DNS
//! message) is treated as "nothing to learn from this datagram," not a
//! process-level error: [`parse_dns_response`] returns `None` and the
//! caller (the DNS ring-buffer callback) simply does not update the
//! cache for that capture. A capture is, after all, "any UDP datagram
//! whose source port happened to be 53" (`bathyscaphe-ebpf::dns`'s
//! module doc) -- the kernel program does not itself validate that the
//! bytes are really DNS.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use simple_dns::rdata::RData;
use simple_dns::Packet;

/// One parsed DNS response: the name that was originally queried, and
/// every A/AAAA answer address found in the message (in answer-section
/// order) paired with that specific record's own TTL.
///
/// Every resolved address is tagged with the ORIGINAL question name, not
/// the name of the particular resource record that produced it -- this is
/// deliberate and is what makes a CNAME chain "just work" for enrichment
/// purposes without this module reconstructing the chain explicitly: a
/// response for `www.example.com` that CNAMEs to `example-lb.cdn.com`
/// before resolving to an A record still tags that A record's address
/// with `www.example.com`, because that is the name the connecting
/// process (and any policy name-rule matching against it) actually cares
/// about, exactly the same convention every DNS-snooping tool surveyed in
/// `prior_art_fqdn.md` (Cilium, Calico, Antrea, NSX, Illumio) uses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedDnsResponse {
    pub name: String,
    pub answers: Vec<(IpAddr, u32)>,
}

/// Parses `bytes` (typically `DnsCapture::captured()`) as a DNS message.
/// Returns `None` if the bytes do not parse as a well-formed message, if
/// there is no question section to attribute answers to, or if the
/// message carries no A/AAAA answers at all (a response that is purely
/// `NXDOMAIN`, purely a `CNAME` with no further resolution captured, or
/// any other record-type-only answer set has nothing this cache can use).
pub fn parse_dns_response(bytes: &[u8]) -> Option<ParsedDnsResponse> {
    let packet = Packet::parse(bytes).ok()?;
    let name = normalize_name(&packet.questions.first()?.qname.to_string());

    let mut answers = Vec::new();
    for record in &packet.answers {
        match &record.rdata {
            RData::A(a) => answers.push((IpAddr::V4(Ipv4Addr::from(a.address)), record.ttl)),
            RData::AAAA(aaaa) => answers.push((IpAddr::V6(Ipv6Addr::from(aaaa.address)), record.ttl)),
            // CNAME and every other record type carry no address of their
            // own to cache -- see this function's doc on why the
            // ORIGINALLY QUERIED name is what every address gets tagged
            // with regardless, so a CNAME link is silently skipped rather
            // than needing to be followed.
            _ => {}
        }
    }

    if answers.is_empty() {
        return None;
    }
    Some(ParsedDnsResponse { name, answers })
}

/// DNS names are conventionally displayed with a trailing root dot
/// (`"example.com."`) and are case-insensitive on the wire; normalizing
/// both away here means every downstream consumer (the cache, and later
/// chunk #10's name-rule pattern matching) compares against one
/// consistent shape rather than re-deriving it independently.
fn normalize_name(raw: &str) -> String {
    raw.trim_end_matches('.').to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;
    use simple_dns::rdata::{A, AAAA, CNAME, RData as BuildRData};
    use simple_dns::{CLASS, Name, Packet as BuildPacket, PacketFlag, Question, ResourceRecord, TYPE};

    fn packet_bytes(build: impl FnOnce(&mut BuildPacket)) -> Vec<u8> {
        let mut packet = BuildPacket::new_reply(1);
        packet.set_flags(PacketFlag::RESPONSE);
        build(&mut packet);
        packet.build_bytes_vec().expect("test packet should always serialize")
    }

    fn question(name: &str) -> Question<'static> {
        Question::new(Name::new_unchecked(name).into_owned(), TYPE::A.into(), CLASS::IN.into(), false)
    }

    fn a_record<'a>(name: &'a str, ttl: u32, addr: std::net::Ipv4Addr) -> ResourceRecord<'a> {
        ResourceRecord::new(Name::new_unchecked(name), CLASS::IN, ttl, BuildRData::A(A { address: addr.into() }))
    }

    fn aaaa_record<'a>(name: &'a str, ttl: u32, addr: std::net::Ipv6Addr) -> ResourceRecord<'a> {
        ResourceRecord::new(Name::new_unchecked(name), CLASS::IN, ttl, BuildRData::AAAA(AAAA { address: addr.into() }))
    }

    fn cname_record<'a>(name: &'a str, ttl: u32, target: &'a str) -> ResourceRecord<'a> {
        ResourceRecord::new(Name::new_unchecked(name), CLASS::IN, ttl, BuildRData::CNAME(CNAME(Name::new_unchecked(target))))
    }

    #[test]
    fn parses_a_single_a_answer() {
        let bytes = packet_bytes(|packet| {
            packet.questions.push(question("example.com."));
            packet.answers.push(a_record("example.com.", 300, std::net::Ipv4Addr::new(93, 184, 216, 34)));
        });

        let parsed = parse_dns_response(&bytes).expect("a well-formed A response must parse");
        assert_eq!(parsed.name, "example.com");
        assert_eq!(parsed.answers, vec![(IpAddr::V4(std::net::Ipv4Addr::new(93, 184, 216, 34)), 300)]);
    }

    #[test]
    fn parses_an_aaaa_answer() {
        let addr = std::net::Ipv6Addr::new(0x2606, 0x2800, 0x220, 1, 0x248, 0x1893, 0x25c8, 0x1946);
        let bytes = packet_bytes(|packet| {
            packet.questions.push(question("example.com."));
            packet.answers.push(aaaa_record("example.com.", 120, addr));
        });

        let parsed = parse_dns_response(&bytes).expect("a well-formed AAAA response must parse");
        assert_eq!(parsed.name, "example.com");
        assert_eq!(parsed.answers, vec![(IpAddr::V6(addr), 120)]);
    }

    #[test]
    fn parses_multiple_answers_for_one_query() {
        let bytes = packet_bytes(|packet| {
            packet.questions.push(question("multi.example.com."));
            packet.answers.push(a_record("multi.example.com.", 60, std::net::Ipv4Addr::new(10, 0, 0, 1)));
            packet.answers.push(a_record("multi.example.com.", 60, std::net::Ipv4Addr::new(10, 0, 0, 2)));
        });

        let parsed = parse_dns_response(&bytes).expect("multi-answer response must parse");
        assert_eq!(parsed.answers.len(), 2);
        assert!(parsed.answers.contains(&(IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1)), 60)));
        assert!(parsed.answers.contains(&(IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 2)), 60)));
    }

    #[test]
    fn a_cname_chain_tags_the_final_address_with_the_original_query_name() {
        let bytes = packet_bytes(|packet| {
            packet.questions.push(question("www.example.com."));
            packet.answers.push(cname_record("www.example.com.", 300, "edge.cdn.example."));
            packet.answers.push(a_record("edge.cdn.example.", 60, std::net::Ipv4Addr::new(203, 0, 113, 9)));
        });

        let parsed = parse_dns_response(&bytes).expect("a CNAME-then-A chain must still parse");
        assert_eq!(parsed.name, "www.example.com", "the ORIGINAL query name, not the CNAME target, is what every answer is tagged with");
        assert_eq!(parsed.answers, vec![(IpAddr::V4(std::net::Ipv4Addr::new(203, 0, 113, 9)), 60)]);
    }

    #[test]
    fn a_cname_only_response_with_no_further_resolution_yields_no_answers() {
        let bytes = packet_bytes(|packet| {
            packet.questions.push(question("www.example.com."));
            packet.answers.push(cname_record("www.example.com.", 300, "edge.cdn.example."));
        });

        assert_eq!(parse_dns_response(&bytes), None, "a CNAME with nothing resolving it has no address worth caching");
    }

    #[test]
    fn truncated_garbage_is_handled_gracefully_not_a_panic() {
        let garbage = [0xFFu8; 4];
        assert_eq!(parse_dns_response(&garbage), None);
    }

    #[test]
    fn empty_bytes_are_handled_gracefully() {
        assert_eq!(parse_dns_response(&[]), None);
    }

    #[test]
    fn a_response_with_no_question_section_is_not_attributable() {
        let bytes = packet_bytes(|packet| {
            packet.answers.push(a_record("example.com.", 60, std::net::Ipv4Addr::new(1, 2, 3, 4)));
        });
        assert_eq!(parse_dns_response(&bytes), None, "no question means no name to attribute the answer to");
    }

    #[test]
    fn normalize_name_strips_trailing_dot_and_lowercases() {
        assert_eq!(normalize_name("Example.COM."), "example.com");
        assert_eq!(normalize_name("example.com"), "example.com");
    }
}
