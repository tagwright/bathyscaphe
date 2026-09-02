// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 techgaud
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
//!
//! ## The tolerant path: a capped response should yield what it can, not nothing
//!
//! `bathyscaphe_common::DNS_CAPTURE_MAX` bounds every capture (currently
//! 512 bytes -- `docs/DNS.md`'s "Oversized responses" section): a real
//! EDNS0 response larger than the cap is captured truncated, exactly at
//! the boundary, not rejected. Experimentally verified against
//! `simple-dns` 0.12 (this module's chosen parser): `Packet::parse` fails
//! the WHOLE message with `SimpleDnsError::InsufficientData` the instant
//! its header's own `ANCOUNT` promises more answer records than the
//! truncated bytes actually contain -- even when several complete,
//! perfectly well-formed answers sit intact earlier in the buffer. Naively
//! accepting that means a truncated-but-otherwise-healthy response with
//! its FIRST five A records fully present and only a sixth cut off learns
//! NOTHING at all, exactly the outcome build chunk #9's tiered capture bug
//! caused for a different reason (coarse tier granularity) -- this module
//! closes the analogous gap for the (rarer, but real) over-cap case.
//!
//! [`parse_dns_response`]'s fallback ([`recover_capped_answers`]) does NOT
//! reimplement any of `simple-dns`'s own label/compression-pointer
//! handling -- that logic is exactly the kind of easy-to-get-subtly-wrong
//! code this module chose a maintained crate to avoid owning at all, and
//! nothing about `simple-dns`'s own public API (`Packet`, `Question`,
//! `ResourceRecord`) exposes the lower-level per-section parse loop
//! (`Header`, `BytesBuffer`, and its internal `WireFormat` trait are all
//! private to that crate) that would let this module resume it manually.
//! Instead, it retries `Packet::parse` on a byte-for-byte copy with the
//! header's `ANCOUNT` field (RFC 1035 section 4.1.1, a fixed offset every
//! DNS message shares) patched down from its original claimed value,
//! walking downward until one candidate value's promised answer count
//! actually fits in the truncated bytes -- `NSCOUNT`/`ARCOUNT` are zeroed
//! alongside it, since a nonzero claim there would fail the same way the
//! instant the (now correctly-sized) answer section exhausts the buffer.
//! The result is the LARGEST prefix of COMPLETE answer records the
//! capture actually contains, with every byte of actual parsing (name
//! decompression, rdata validation) still done entirely by `simple-dns`
//! itself -- this module only ever edits three well-known, fixed-offset
//! count fields, never a name or a record body.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use simple_dns::rdata::RData;
use simple_dns::{Packet, SimpleDnsError};

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
/// Returns `None` if the bytes do not parse as a well-formed message (even
/// after the tolerant capped-response retry below), if there is no
/// question section to attribute answers to, or if the message carries no
/// A/AAAA answers at all (a response that is purely `NXDOMAIN`, purely a
/// `CNAME` with no further resolution captured, or any other
/// record-type-only answer set has nothing this cache can use).
pub fn parse_dns_response(bytes: &[u8]) -> Option<ParsedDnsResponse> {
    match Packet::parse(bytes) {
        Ok(packet) => response_from_packet(&packet),
        // Only worth retrying when the failure LOOKS like truncation --
        // see this module's doc for why this is the exact error
        // `simple-dns` returns when a message's header promises more
        // answer records than the (capped) bytes actually contain. Any
        // other error (a genuinely malformed/garbage payload) would just
        // fail the same way on every retried `ANCOUNT` candidate too, so
        // there is nothing to gain from attempting it.
        Err(SimpleDnsError::InsufficientData) => recover_capped_answers(bytes),
        Err(_) => None,
    }
}

fn response_from_packet(packet: &Packet) -> Option<ParsedDnsResponse> {
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

/// Byte offsets of the three fixed-width record-count fields in a DNS
/// message's 12-byte header (RFC 1035 section 4.1.1) -- every message
/// shares this exact layout regardless of message content, so these are
/// safe to hard-code rather than needing any parser-crate cooperation.
const DNS_HEADER_LEN: usize = 12;
const ANCOUNT_OFFSET: usize = 6;
const NSCOUNT_OFFSET: usize = 8;
const ARCOUNT_OFFSET: usize = 10;

/// See this module's doc, "The tolerant path", for the full rationale.
/// Walks the header's claimed answer count down from its original value,
/// re-parsing a patched copy of `bytes` at each candidate until one
/// actually fits -- the largest prefix of complete answer records the
/// truncated capture contains. `NSCOUNT`/`ARCOUNT` are zeroed on every
/// attempt (a nonzero claim there would fail the parse again the instant
/// the correctly-sized answer section exhausts the buffer).
fn recover_capped_answers(bytes: &[u8]) -> Option<ParsedDnsResponse> {
    if bytes.len() < DNS_HEADER_LEN {
        return None;
    }
    let original_ancount = u16::from_be_bytes([bytes[ANCOUNT_OFFSET], bytes[ANCOUNT_OFFSET + 1]]);

    for ancount in (0..original_ancount).rev() {
        let mut patched = bytes.to_vec();
        patched[ANCOUNT_OFFSET..ANCOUNT_OFFSET + 2].copy_from_slice(&ancount.to_be_bytes());
        patched[NSCOUNT_OFFSET..NSCOUNT_OFFSET + 2].copy_from_slice(&[0, 0]);
        patched[ARCOUNT_OFFSET..ARCOUNT_OFFSET + 2].copy_from_slice(&[0, 0]);

        if let Ok(packet) = Packet::parse(&patched) {
            // `response_from_packet` itself returns `None` for a
            // zero-answer parse (the `ancount == 0` floor this loop can
            // reach) -- that is not a hard failure of the recovery
            // attempt, just "nothing usable was recoverable," so let it
            // propagate rather than treating it as a reason to keep
            // trying smaller counts (there is nothing smaller than 0).
            return response_from_packet(&packet);
        }
    }
    None
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

    /// Regression test for the build chunk #12 fix: build chunk #9's
    /// tiered eBPF capture (512/384/256/128/64/32-byte literal tiers,
    /// largest-that-fits) truncated any response whose true length fell
    /// STRICTLY BETWEEN two adjacent tiers down to the next SMALLER one --
    /// a genuine ~100-byte answer, observed live, was captured at only 64
    /// bytes and never parsed at all. This fixture is deliberately sized
    /// into that exact gap (`assert!` below pins it there so a future
    /// change to the builder or the fixture can't silently drift out of
    /// the case this test exists to cover). Chunk #12's exact-length
    /// (clamp-then-mask) eBPF capture now captures every one of these
    /// bytes rather than truncating to the smaller tier -- this test
    /// proves that, GIVEN such a full capture, parsing recovers it
    /// completely; `probe::dns`'s live smoke test is what proves the
    /// kernel side now actually produces a full capture at this size.
    #[test]
    fn a_response_between_the_old_64_and_128_byte_tiers_parses_in_full() {
        let bytes = packet_bytes(|packet| {
            packet.questions.push(question("tier-gap.example.com."));
            packet.answers.push(a_record("tier-gap.example.com.", 300, std::net::Ipv4Addr::new(93, 184, 216, 34)));
        });
        assert!(bytes.len() > 64 && bytes.len() < 128, "fixture must land in the old 64/128-byte tier gap, got {} bytes", bytes.len());

        let parsed =
            parse_dns_response(&bytes).expect("a full, untruncated capture at this size must parse completely -- pre-chunk-#12 tier truncation would have lost the tail of even this single answer");
        assert_eq!(parsed.name, "tier-gap.example.com");
        assert_eq!(parsed.answers, vec![(IpAddr::V4(std::net::Ipv4Addr::new(93, 184, 216, 34)), 300)]);
    }

    /// The same regression, in the OTHER old tier gap (384/512), with
    /// multiple answers -- proving the fix isn't specific to the single
    /// gap the live bug happened to land in.
    #[test]
    fn a_multi_answer_response_between_the_old_384_and_512_byte_tiers_parses_in_full() {
        let bytes = packet_bytes(|packet| {
            packet.questions.push(question("mid.example.com."));
            for i in 1..=14u8 {
                packet.answers.push(a_record("mid.example.com.", 60, std::net::Ipv4Addr::new(10, 0, 0, i)));
            }
        });
        assert!(bytes.len() > 384 && bytes.len() < 512, "fixture must land in the old 384/512-byte tier gap, got {} bytes", bytes.len());

        let parsed = parse_dns_response(&bytes).expect("a full, untruncated capture at this size must parse completely");
        assert_eq!(parsed.answers.len(), 14);
    }

    /// Build chunk #12's OTHER fix: the tolerant path for a response that
    /// genuinely exceeds `DNS_CAPTURE_MAX` and is captured truncated at
    /// the cap (a real, if rarer, case than the tier gap above --
    /// `docs/DNS.md`'s "Oversized responses" section). Verified
    /// experimentally against `simple-dns` 0.12 first (see this module's
    /// doc): `Packet::parse` on a buffer cut mid-record fails the WHOLE
    /// message, discarding even fully-intact earlier answers, without the
    /// `recover_capped_answers` fallback this test exercises.
    #[test]
    fn a_response_truncated_mid_record_recovers_the_complete_answers_that_fit() {
        let full = packet_bytes(|packet| {
            packet.questions.push(question("mid.example.com."));
            for i in 1..=3u8 {
                packet.answers.push(a_record("mid.example.com.", 60, std::net::Ipv4Addr::new(10, 0, 0, i)));
            }
        });
        // From this fixture's own construction: header+question is 33
        // bytes, each of the 3 answer records is 31 bytes (64, 95, 126
        // total after 1/2/3 answers respectively) -- 110 lands after the
        // first two complete records but partway through the third.
        assert_eq!(full.len(), 126);
        let truncated = &full[..110];
        assert!(Packet::parse(truncated).is_err(), "sanity: simple-dns must reject this truncated buffer outright, otherwise this test isn't exercising the tolerant path at all");

        let parsed = parse_dns_response(truncated).expect("the two complete answers ahead of the truncation point must still be recovered");
        assert_eq!(parsed.name, "mid.example.com");
        assert_eq!(parsed.answers, vec![(IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1)), 60), (IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 2)), 60)]);
    }

    /// The floor of the tolerant path: a truncation point before even the
    /// FIRST answer record completes has nothing to recover -- `None`,
    /// not a panic and not a spuriously "successful" zero-answer parse.
    #[test]
    fn a_response_truncated_before_any_complete_answer_recovers_nothing() {
        let full = packet_bytes(|packet| {
            packet.questions.push(question("mid.example.com."));
            packet.answers.push(a_record("mid.example.com.", 60, std::net::Ipv4Addr::new(10, 0, 0, 1)));
        });
        assert_eq!(full.len(), 64);
        let truncated = &full[..50]; // past the 33-byte question, short of the first 31-byte answer record
        assert_eq!(parse_dns_response(truncated), None);
    }
}
