<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# DNS observation and FQDN enforcement

Build chunks #9 (DNS observation), #10 (query/response correlation + FQDN
enforcement), #11 (trusted-resolver enforcement + name-based deny), and
#12 (exact-length capture correctness fix) of the sequence in
`bathy_build_spec.md`. This document is the honest account
of what bathyscaphe's DNS layer sees, what it structurally cannot see, and
how the pieces fit together. IP/CIDR policy remains the ground truth
throughout (`bathy_build_spec.md`'s BUILD-THROUGH STANCE); FQDN enforcement
(chunks #10-#11) is best-effort, layered on top of that same ground truth,
never a replacement for it -- stated plainly, not just implied: a name
rule can only ever ADD host routes to the allow-map that IP/CIDR policy
already governs, and every gap documented below falls straight back to the
container's ordinary IP/CIDR default, never to a silent allow.

## What is captured, and how

`dns_snoop` is a `cgroup_skb` eBPF program, attached **ingress** to each
monitored container's cgroup (`bathyscaphe-ebpf::dns`). It recognizes a
UDP datagram whose *source* port is 53 (a DNS response arriving at the
container from its resolver, whether that resolver is an external server
or Docker's embedded resolver at `127.0.0.11:53` reached over loopback)
and copies its EXACT payload length, up to
`bathyscaphe_common::dns::DNS_CAPTURE_MAX` (512) bytes, plus the observing
cgroup id, a kernel timestamp, and (as of build chunk #11) the packet's
own IP-layer SOURCE address, into a dedicated `DNS_EVENTS` ring buffer.
**As of build chunk #12**, this is a single, exact-length
`bpf_skb_load_bytes` call (a verifier-safe clamp-then-mask idiom -- see
"Build chunk #12" below) -- chunks #9-#11 instead used a ladder of six
literal-size tiers (512/384/256/128/64/32 bytes, largest-that-fits), which
silently TRUNCATED any response whose true length fell strictly between
two adjacent tiers to the smaller one, corrupting the message. That bug is
fixed; every response up to the cap is now captured at its own true
length, with no tier-granularity loss. That source address
(`bathyscaphe_common::dns::DnsCapture::src_addr`, IPv4-mapped-into-IPv6 per
RFC 4291, the same embedding `Event::src_addr`/`PolicyKeyData::addr` use)
is what chunk #11's trusted-resolver check (below) is built on -- unlike
`cgroup_id`, which an injected/synthesized reply can misattribute (see
"Chunk #10" below), a packet's own source address is set by whatever real
host sent it and is not something a process sharing the container's
network namespace can rewrite from the receiving side. It never parses the DNS message itself
-- DNS's variable-length labels and compression pointers are a poor fit
for the eBPF verifier's bounded execution model, so parsing happens
entirely in userspace (`bathyscaphe::dns::parse`), using the raw captured
bytes.

Every byte the kernel program reads comes through `SkBuffContext::load`/
`load_bytes`, both safe wrappers around the `bpf_skb_load_bytes()` helper
that the kernel itself bounds-checks against the real packet length --
there is no raw pointer arithmetic on packet data anywhere in this path.

This program is pure observation: it always returns `1` (pass) to the
kernel regardless of what it finds. It never gates traffic, and a full
`DNS_EVENTS` ring or a parsing miss has no effect whatsoever on the
container's actual connectivity.

## What is NOT captured, and why (the honest gaps)

- **DoH (DNS-over-HTTPS) and DoT (DNS-over-TLS)**: never touch UDP or TCP
  port 53 at all -- DoH looks like ordinary HTTPS traffic on port 443, DoT
  uses TLS on port 853. Both are structurally invisible to a program that
  only ever inspects UDP:53-sourced payloads. There is no way to recover
  this visibility short of TLS interception, which this project does not
  do. A container (or an application inside it) using a DoH/DoT resolver
  gets zero domain enrichment for its traffic; its connections are still
  fully observed and, if a name rule can't be resolved for it, still fall
  back to whatever IP/CIDR policy applies -- IP/CIDR enforcement never
  depends on DNS visibility.
- **ECH (Encrypted Client Hello)**: not directly relevant to THIS layer
  (ECH hides the TLS SNI, not the DNS exchange), but is the reason a
  future SNI-enrichment layer (`sni_enrich`, unbuilt) would have the same
  kind of blind spot DoH/DoT gives this one. Documented here for
  completeness since `bathy_ebpf_design.md` and `prior_art_fqdn.md` treat
  the two blind spots as a matched pair.
- **TCP DNS**: `dns_snoop` matches `IPPROTO_UDP` only. A response that
  falls back to TCP:53 (historically triggered by a response over 512
  bytes before EDNS0, or by a resolver that prefers TCP outright) is not
  captured. In practice, the overwhelming majority of a container's real
  DNS traffic -- a single A/AAAA lookup against a typical resolver -- is
  UDP and comfortably fits `DNS_CAPTURE_MAX`. TCP DNS support is a
  documented v1 gap, not a silently missing one.
- **IPv6 extension headers**: the IPv6 parsing path assumes UDP is the
  fixed 40-byte base header's *immediate* next header. A response arriving
  behind a Hop-by-Hop, Routing, or Fragment extension header is not
  recognized. DNS traffic essentially never uses IPv6 extension headers in
  practice.
- **Oversized responses**: a UDP DNS payload longer than
  `DNS_CAPTURE_MAX` (512 bytes) is captured truncated EXACTLY at the cap
  (as of build chunk #12 -- see below for the pre-#12 tier-truncation
  behavior this replaced), not rejected. A message truncated this way
  fails `simple-dns`'s own `Packet::parse` outright (verified
  experimentally: it rejects the whole message the instant its header's
  claimed answer count exceeds what the truncated bytes actually
  contain, even when several complete answers sit intact earlier in the
  buffer) -- `bathyscaphe::dns::parse::parse_dns_response` now retries
  with a tolerant fallback (`recover_capped_answers`) that walks the
  claimed answer count down until a smaller value's worth of records
  actually fits, recovering the largest prefix of COMPLETE answers the
  truncated capture contains, rather than discarding the whole message.
  A message truncated before even its first answer completes (or one
  that fails for a genuinely unrelated reason) still yields nothing, the
  same "nothing learned from this datagram" outcome as any other
  malformed input, never a panic or a process-level error.
- **Injected/synthesized DNS replies can attribute to the wrong cgroup**:
  `dns_snoop`'s cgroup attribution comes from `bpf_get_current_cgroup_id()`
  at the moment the kernel evaluates the ingress hook -- the cgroup of
  whichever TASK is executing at that instant. For a reply delivered over
  a real network path (a real NIC, a real veth pair), that task is the
  receiving process inside the querying container, exactly as intended.
  For a reply that some other component SYNTHESIZES and injects directly
  into the container's netns (observed directly, on a live host, for both
  Docker's own embedded resolver at `127.0.0.11` and a host-level
  DNS-intercepting VPN client's resolver), the injecting component's own
  process may still be the "current task" at delivery time, so the
  capture is attributed to ITS cgroup (`docker.service`,
  `tailscaled.service`, etc.) instead of the querying container's. The
  packets themselves are genuine, complete, well-formed DNS responses --
  this is purely an attribution nuance of how cgroup-scoped eBPF hooks
  interact with in-kernel/injected delivery paths for specific resolver
  implementations, not a parsing or capture defect. `docs/TESTING.md` has
  the full account, including the raw bytes that proved it. **This is
  FIXED as of chunk #10** for the Docker-embedded-DNS case specifically,
  via query/response correlation (`bathyscaphe::dns::pending`) -- see
  "Chunk #10: the query/response correlation fix" below for the full
  design and the empirical proof this fix actually works, and "Full
  residual limitation list" for exactly which attribution paths remain
  uncorrelated (an uncorrelated response still falls back to this
  chunk's original, possibly-wrong, attribution, marked low-confidence).
- **Spoofing (mitigated for the trusted-resolver path as of build chunk
  #11)**: `dns_snoop` still CAPTURES *any* UDP:53-sourced datagram reaching
  the container's ingress path -- capture itself has no opinion on trust,
  matching every other kernel-side program in this codebase. What changed:
  userspace now checks every captured response's own source address
  against an operator-configured trusted-resolver allowlist
  (`bathyscaphe::dns::trust::TrustedResolvers`, see "Build chunk #11" below)
  BEFORE using it to seed enforcement. A process able to inject a spoofed
  UDP:53 reply into the same network namespace can still poison the
  ENRICHMENT cache (a misleading `domain.name`, always floored to
  `Inferred` confidence when untrusted -- see below), but can no longer buy
  its way onto a container's `POLICY` allow-map that way: an untrusted
  answer is never used for that. Residual, explicitly out of scope for
  chunk #11: poisoning a resolver that IS in the trusted set (cache
  poisoning an upstream DNS server this host's operator already trusts) is
  a DNS-protocol-level attack this project does not attempt to defend
  against, matching every DNS-snooping tool `prior_art_fqdn.md` surveys.

### Why `domain` is null on an event

Any of the following collapse to the identical `domain: {name: null,
source: null, confidence: null}` shape on an event -- `pipeline::map`
does not, and cannot, distinguish between them:

1. The destination was never looked up via DNS at all (raw-IP egress).
2. The lookup happened over DoH/DoT/an untrusted resolver
   `dns_snoop` never observes.
3. The lookup happened, but the response fell back to TCP, was
   truncated past `DNS_CAPTURE_MAX`, or arrived behind an IPv6 extension
   header.
4. The lookup happened and was captured, but the cache entry has aged
   past `bathyscaphe::dns::cache::STALE_GRACE_NS` since its answer's TTL
   expired.
5. bathyscaphe's own userspace process was not running (or had not yet
   started draining `DNS_EVENTS`) when the answer arrived -- see "Lifecycle"
   below.
6. A genuine cache miss: this specific `(container, destination IP)` pair
   was never recorded.

## Parser choice: `simple-dns`

Evaluated against `hickory-proto` and `dns-parser`:

- **`hickory-proto`** (the maintained continuation of `trust-dns`) is the
  most actively maintained and most complete of the three, but it is
  designed as the shared protocol crate underneath a full
  resolver/client/server stack. That is more surface and dependency
  weight than a userspace daemon that only ever calls one read-only parse
  function needs.
- **`dns-parser`** is small and focused, but its maintenance cadence
  (release frequency, recent commit activity) is visibly slower than the
  other two -- the one criterion ("a MAINTAINED Rust crate") this option
  fails hardest.
- **`simple-dns`** (chosen): actively maintained, exercised by current
  mDNS crates for the same "parse an untrusted UDP DNS-shaped payload"
  task this module needs, a small single-purpose message-parsing surface
  with plain public fields (`Packet::questions`, `Packet::answers`,
  `ResourceRecord::rdata`), and no resolver/client baggage. `no_std`
  compatibility (which this crate has, incidentally) was not a deciding
  factor -- this parsing happens entirely in the `std` userspace daemon,
  never in `bathyscaphe-ebpf`.

See `bathyscaphe/src/dns/parse.rs`'s module doc for the same comparison
in code-adjacent form.

## The per-container IP -> domain cache

`bathyscaphe::dns::cache::DomainCache` holds, per `cgroup_id`, a map from
destination `IpAddr` to `{domain name, expires_at, purge_at}`. Every
resolved A/AAAA answer in a parsed response is tagged with the
**originally queried name** (the question section), not the name of the
specific resource record that produced it -- so a CNAME chain (name ->
CNAME -> ... -> A) still maps every resulting address back to the name the
connecting process actually looked up, matching the convention every
DNS-snooping tool surveyed in `prior_art_fqdn.md` (Cilium, Calico, Antrea,
NSX, Illumio) uses.

**Confidence rule**: a lookup within the answer's own TTL window is
`Asserted` (a fresh, direct DNS answer). A lookup past TTL but still
within `STALE_GRACE_NS` (15 minutes, a fixed v1 constant) is `Inferred` --
mirroring Cilium's `--tofqdns-idle-connection-grace-period` reasoning: a
container's OS-level connection can keep using an address after its DNS
answer's TTL has technically elapsed, so "just past TTL" is treated as
"less certain," not "wrong." Past the grace window, a lookup returns
`None`, indistinguishable from a cache miss.

**Memory bound**: there is no dedicated background reap thread in this
chunk. `DomainCache::record` opportunistically sweeps its OWN
container's entries past their grace window on every write, so a
container that keeps resolving names bounds its own cache size for free.
A container that stops resolving names (and, since nothing else reads its
cache either, has also effectively stopped connecting to anything newly
learned) leaks a bounded, per-container amount of state until process
restart or an explicit `release` directive. This is an accepted v1 gap: a
few stale map entries per idle container, not an unbounded host-wide
leak.

## Event enrichment

`pipeline::map::map_event` looks up the connect event's destination
address in the cache, keyed by the event's own `cgroup_id`, at the
event's own kernel timestamp (`ktime_ns`, `CLOCK_BOOTTIME`) -- not a
freshly sampled clock reading. This means enrichment answers "was this
DNS answer still fresh AT THE MOMENT of this specific connection," which
is the semantically correct question, rather than "is it fresh right
now, whenever this line happens to be processed."

## Lifecycle: DNS learning needs a live probe; enforcement does not

Unlike connect4/6, sendmsg4/6, and sock_create (whose decisions are
entirely self-contained in the kernel, reading only pinned maps),
`dns_snoop`'s captured payloads are useless until a *live* userspace
process drains `DNS_EVENTS` and updates the cache. If bathyscaphe is dead:

- `dns_snoop` keeps running (it is pinned like every other program) and
  keeps writing captures into the ring, but nothing reads them -- the ring
  fills and the kernel silently drops new captures once full. This is
  deliberately NOT tracked by the security-relevant `TamperCounter`
  (`bathyscaphe_common::counters`) that connect/sendmsg drops use: a lost
  DNS capture degrades enrichment freshness only, never enforcement.
- **Bathyscaphe learns no new domain names while it is down.**
- **Any IP a live probe already inserted into the policy allow-map keeps
  being enforced** (fail-closed, per `bathy_ebpf_design.md` section 3)
  until that specific entry's own TTL expires -- this is chunk #10's
  concern, not this chunk's, but the asymmetry is exactly why chunk #10's
  design (insert DNS-derived IPs into `POLICY` with their own absolute
  kernel-side TTL, a one-time write that outlives the process that made
  it) is the right shape: making NEW allow-list entries needs a live
  daemon, but entries already made do not need one to keep being honored.

## Pin layout addition

`dns_snoop` (a `CgroupSkb` program) and the `dns_events` map (a `RingBuf`)
join the existing pin subtree (`probe::mod`'s module doc has the full
diagram): `progs/dns_snoop`, `maps/dns_events`, and
`links/<cgroup_id>/dns_snoop` per attached container. Fresh-load and
reopen-from-pins both cover it exactly like the five programs before it;
`PROG_NAMES`/`MAP_PIN_NAMES` (`probe::layout`) are the two lists that had
to grow, and every generic (path-based, type-agnostic) piece of pin-state
detection, rollback, and container rediscovery logic picked it up for
free.

## Capability

`hello.capabilities` includes `dns_enrich` (chunk #9, `daemon::hello`) and,
as of chunk #10, `enforce_fqdn` too -- see the "The `enforce_fqdn`
capability" section below for what changed and why it is now safe to
advertise (name rules are genuinely enforced, not merely counted).

## Chunk #10: the query/response correlation fix

### The attribution problem, restated precisely

`dns_snoop`'s ingress capture attributes a DNS RESPONSE to whichever
cgroup `bpf_get_current_cgroup_id()` reports at the moment the hook
fires -- correct for a reply delivered over a real NIC/veth boundary, but
WRONG (the resolver's own cgroup: `docker.service`, `tailscaled.service`)
for a reply synthesized/injected directly into the container's netns, the
common case under Docker's embedded per-container resolver at
`127.0.0.11` (the default for compose/user-defined networks). Since the
CIDR/host-route enforcement layer keys every allow-map entry by
`cgroup_id`, inserting a DNS-derived host route under the wrong cgroup
would either enforce nothing for the container that actually needs it, or
(worse) leak an allow entry onto an unrelated cgroup.

### The fix: correlate against the container's own OUTBOUND query

The insight (validated empirically below, not merely asserted): a
container's DNS QUERY, unlike the response, never suffers this problem.
`bathyscaphe-ebpf::dns_query`'s new EGRESS `cgroup_skb` program
(`dns_query_snoop`, the 7th kernel program) fires on the container's own
`sendto()`/`send()` call on its own UDP socket -- there is no resolver-side
injection on the way OUT, so `bpf_get_current_cgroup_id()` there is
ALWAYS the querying container's real cgroup, by construction.
`dns_query_snoop` captures just enough to identify the query later: the
DNS transaction id (the first two bytes of the UDP payload), the query's
own source port, the correct cgroup id, and a timestamp -- into a new,
dedicated `DNS_QUERIES` ring buffer (`bathyscaphe_common::DnsQueryCapture`,
24 bytes, small enough to build by value on the eBPF stack, unlike the
536-byte `DnsCapture`). It deliberately does NOT parse the query's name --
see that struct's doc for why the response (already fully captured) makes
that redundant.

`bathyscaphe::dns::pending::PendingQueryTable` is the userspace bridge:
every captured query records `(txid, src_port) -> {cgroup_id,
inserted_at}`; every captured response looks up `(txid, dst_port)` -- the
response's destination port IS the original query's source port, since
that is where the resolver addresses its reply -- and, on a hit, recovers
the CORRECT cgroup id, overriding the response hook's own attribution.
`PENDING_QUERY_TTL_NS` was 5 seconds at chunk #10 (cut to 2 seconds by
build chunk #14, see "Build chunk #14" below); sweeping is opportunistic
(mirrors `DomainCache`'s own sweep-on-every-write convention), and a
correlated entry is NOT removed on its first match, so more than one
response datagram for the same query (a duplicate/retransmit, or separate
A/AAAA answers reusing the same transaction id and port) all still
correlate (bounded, as of chunk #14, to `MAX_SERVED_RESPONSES` per entry
rather than lingering the rest of the TTL). The correlation key is
`(txid, port)` only, deliberately without a resolver-address component --
chunk #10 judged the cross-container collision risk this carries
"exceedingly unlikely"; **chunk #13's live integration testing proved that
judgment wrong** (a real, deterministic 5/5 collision), and **chunk #14
fixed the underlying design** -- see "Build chunk #14: cross-container
isolation" below for the empirical investigation into why an
address-based key was NOT the fix, and what was built instead.

**The uncorrelatable fallback**: `crate::dns::capture_callback` falls back
to the response capture's OWN `cgroup_id` whenever no matching query was
ever recorded (the query's own capture was dropped by a full
`DNS_QUERIES` ring, the query used TCP, or the response arrived more than
`PENDING_QUERY_TTL_NS` after it) and marks the resulting
`AttributedAnswer::correlated` field `false` -- callers can see the
confidence signal, though the whole pipeline (cache recording, FQDN
enforcement) still functions identically either way; there is no
"discard an uncorrelated answer" behavior, since the pre-chunk-10
response-hook attribution is still the best available information in that
case, exactly as chunk #9 shipped it.

### Empirical investigation: what actually happened on this host

Per the build brief's mandate, this was investigated directly against a
real Docker container on a real user-defined bridge network (which is
what gets Docker's embedded resolver at `127.0.0.11` -- the default
`bridge` network does not), kernel 6.8.0-136, `--privileged
--cgroupns=host`, three separate container lifetimes.

**A real, unanticipated finding surfaced first**: a naive
`dst_port == 53` match on the egress query snoop captured NOTHING, even
though the corresponding response WAS captured (proving the query really
was sent and answered). A temporary diagnostic build that captured every
egress UDP datagram regardless of port revealed why: the query's
destination port AT THE EGRESS HOOK was a random high port (55561, 55508,
and 48204 across the three runs -- never 53), while its source port
exactly matched the following response's destination port every time
(proving these captures really were the query/response pair, just not
recognizable by port alone). The cause: Docker's embedded resolver is not
actually bound to `127.0.0.11:53`; a per-network-namespace iptables `DNAT`
rule rewrites a query addressed there to an internal, randomly-allocated
port where the real resolver listens, and `cgroup_skb`'s
`BPF_CGROUP_INET_EGRESS` attach point fires AFTER that `LOCAL_OUT`
netfilter NAT processing -- so the program only ever sees the
ALREADY-REWRITTEN port. (`dns_snoop`'s ingress side is unaffected because
conntrack un-NATs the RETURN leg symmetrically before the ingress hook
runs -- the same NAT rule affects the two directions asymmetrically.)

**The fix applied**: `dns_query_snoop` matches EITHER the genuine
port-53 case (a query sent directly to an external resolver over a path
with no local NAT involved) OR a destination address of `127.0.0.11`
(`DOCKER_EMBEDDED_DNS_V4` in `bathyscaphe-ebpf::dns_query`) regardless of
port -- the DNAT rule rewrites the port but never the address, so the
address is a NAT-invariant signal specifically for this one well-known
resolver. This is a targeted, Docker-specific special case, not a general
"any locally-DNAT'd UDP traffic" heuristic; see "Residual limitations"
below for what it does not cover.

**Result after the fix, precisely**: `verifier ACCEPTED` all seven
programs, `attach_container` succeeded, and re-running the SAME test
three times (once immediately after the fix, once alongside every other
`live_smoke` test in one invocation) produced, every time:

- The egress query snoop's captured `cgroup_id` matched the test
  container's real cgroup id EXACTLY, in every captured query, every run
  (`query_cgroup_matched_container=true`, unconditionally) -- the
  foundational claim this whole design rests on, PROVEN, not assumed.
- The response's OWN captured `cgroup_id` matched `docker.service`'s
  cgroup, NOT the container's -- chunk #9's misattribution finding
  reproduced exactly, on demand, every run.
- `PendingQueryTable::correlate`, given the response's own `(txid,
  dst_port)`, recovered the CONTAINER's cgroup id -- overriding the
  response hook's wrong attribution -- in every captured answer, every
  run, with zero misses.

This is the complete, decisive proof the build brief asked for: query/
response correlation demonstrably fixes the Docker-embedded-DNS
attribution problem on a real host, end to end, not merely in a unit
test with synthetic data (`dns::pending::tests::correlation_recovers_the_querying_containers_cgroup_even_when_the_responses_own_cgroup_differs`
proves the same logical claim without a kernel; this proves the kernel
side actually delivers the inputs that logic needs).

## FQDN enforcement

### Name-rule pattern registration and wildcard semantics

`daemon::compile::compile_policy` now treats a well-formed `type: "name"`
rule as ACTIVE, not inert (chunk #9 shipped it universally inert, since
`enforce_fqdn` did not exist yet): every such rule becomes a
`CompiledNamePattern` (pattern, action, port, proto), and
`daemon::apply::apply_policy` registers the whole set into
`crate::dns::patterns::NamePatternStore`, keyed by `cgroup_id`, wholesale
REPLACING that container's entire prior pattern set (a `policy` snapshot
is a full replacement, never a delta, matching every other part of this
protocol). A name rule carrying an unrecognized field inside its matcher
is still the one ignore-unknown carve-out (`docs/PROTOCOL.md` section 4)
and remains inert-and-counted exactly as before.

Wildcard semantics (`crate::dns::patterns::pattern_matches`): `*.example.com`
matches ANY name ending in `.example.com` with at least one more label in
front of it -- `docs.example.com` AND `raw.objects.example.com` both
match (multi-label, not the narrower single-label convention a TLS
wildcard certificate uses), matching Cilium's `toFQDNs` `matchPattern`
glob semantics. A wildcard never matches its own bare apex (`*.example.com`
does not match `example.com` itself); an operator wanting both writes two
rules, matching every DNS-snooping tool `prior_art_fqdn.md` surveyed.

### Resolved-IP insertion into the allow-map

`daemon::fqdn::on_dns_answer` is the hook `crate::dns::capture_callback`
invokes for every `AttributedAnswer` (i.e., after correlation has already
run): it checks `NamePatternStore::first_matching_allow` for the
answer's CORRECTLY-ATTRIBUTED `cgroup_id`, and on a match, inserts the
resolved address into `POLICY` as a host route
(`prefix_bits_over_addr = 128`, `source: RuleSource::Dns`), with
`expires_at_ns` computed by the SAME `crate::dns::cache::expiry_ns(now,
ttl_secs)` helper `DomainCache::record` uses internally -- the enrichment
cache and the enforcement allow-map agree on one absolute expiry instant
by construction, never two independently-derived ones. A pattern with no
port/proto constraint sets the host route's `cidr_default_action: Allow`
(the address is fully open); a pattern WITH a port/proto constraint sets
`cidr_default_action: Deny` plus exactly one `PortRule` granting `Allow`
for that port/proto -- so `github.com:443/tcp` never accidentally opens
other ports/protocols to whatever address `github.com` resolves to, even
though the inserted host route is the single most-specific entry an
`LpmTrie` lookup will ever find for that exact address (there is no
"falls through to a broader CIDR" once a `/128` entry exists for that
address). Only the FIRST matching pattern is used when a name matches more
than one registered pattern for the same container -- a documented v1
simplification (no cross-pattern port/proto merging), acceptable because
the common case is one name rule per domain of interest.

### The reaper: DNS-derived host routes expire and get swept

`probe::policy::PolicyStore::reap_expired` (chunk #4/5) already existed
but was never called by anything before this chunk -- a real gap, since
without it, an expired host route would sit in the trie forever, shadowing
whatever broader, still-valid CIDR entry sits beneath it
(`bathyscaphe_common::policy`'s own documented "expiry lookup limitation").
`daemon::stats::tick` now calls `ProbeApi::reap_expired_policy(now_boottime_ns)`
at the top of every periodic `stats` tick (the same cadence `stats_interval_s`
already drives), reaping every expired `POLICY` entry across every
container, DNS-sourced or not.

### Make-before-break must never evict a DNS-sourced route

A latent correctness issue surfaced while wiring this up: `daemon::apply`'s
make-before-break diff (chunk #7) computed its "old keys to remove" set
from `ProbeApi::tracked_policy_keys` -- ALL tracked keys for a container,
regardless of source. Once `on_dns_answer` starts inserting DNS-derived
host routes into the SAME per-container key pool a static `policy`
snapshot's entries live in, a later static re-push (one that doesn't
happen to mention a given resolved address) would have silently REMOVED
that DNS-derived entry, even though nothing about it had actually
expired -- directly contradicting `bathy_build_spec.md`'s ratified stance
that "the DNS-snoop layer is additive" to static policy. Fixed by
splitting `PolicyStore::container_keys` to track each key's `RuleSource`
alongside it, and adding `tracked_keys_by_source`/
`ProbeApi::tracked_policy_keys_by_source`: `apply::apply_make_before_break`
now diffs only the STATIC subset, leaving any DNS-sourced entry alone
regardless of what a later static snapshot does or doesn't mention. A
DNS-derived entry's only two exits are its own TTL (the reaper) or an
explicit `release`/`release_all` for its container.

### The evolved loud record: `policy.name_unresolved_block`

Chunk #9's `policy.unenforceable_name` reason meant "this build cannot
evaluate name rules at all" -- no longer true once `enforce_fqdn` is
always advertised, so this build never emits that reason (it stays
reserved in `bathyscaphe-proto` for a hypothetical build without the
capability). The analogous but materially different chunk #10 condition:
a container holds an active `Allow` name rule, but a connection was
DENIED to a destination this build never observed a DNS answer for at
all -- raw-IP egress bypassing DNS entirely, or a DoH/DoT/ECH lookup this
build structurally cannot see. `daemon::fqdn::NameUnresolvedBlockWatcher`
(an `EventSink` wrapper composed into the same sink chain
`daemon::stats::CountingSink` already sits in) watches every mapped
`Event` for exactly this shape (`verdict: deny` AND `domain.name: null`
AND the container has at least one active `Allow` name pattern
registered) and fires a throttled `security` record,
`reason: policy.name_unresolved_block`, `severity: Error`, carrying
`dst.addr`/`dst.port` as attributes (deliberately no `domain`, since the
whole point is that none was ever seen).

**Honest imprecision in this heuristic**: there is no kernel-side signal
distinguishing "denied because no name rule ever resolved this exact IP"
from "denied by an unrelated, explicit CIDR deny rule that has nothing to
do with the container's name rules" -- both collapse to the identical
`(verdict: deny, domain: null)` shape this watcher keys on. A container
running both a name-rule allowlist AND an explicit CIDR blocklist will see
this record fire on denies from either source. Distinguishing them
precisely would need the kernel to tag WHY a destination fell through to
default-deny (name-rule-intended vs. never-considered), a materially
larger change this chunk does not make -- documented here as a residual
limitation, not silently assumed away.

### The `enforce_fqdn` capability

`daemon::hello::capabilities()` now unconditionally includes
`Capability::EnforceFqdn` alongside `DnsEnrich`/`Enforce`/`EnforceUdp`/
`Observe`. Per `docs/PROTOCOL.md` section 2, this means a `policy`
directive's `type: "name"` rules are no longer at risk of the sticky
"requested a capability this build doesn't have" validation error --
airlock can rely on them being genuinely enforced. Build chunk #11 adds no
new capability of its own -- the trusted-resolver check and name-based
deny are both refinements of what `enforce_fqdn` already means, not a
separately-advertised feature; the capability set this build advertises
(`observe`, `enforce`, `enforce_udp`, `dns_enrich`, `enforce_fqdn`) is
unchanged from chunk #10.

## Build chunk #11: trusted-resolver enforcement and name-based deny

### The trusted-resolver allowlist (Part A)

Every DNS-snooping tool `prior_art_fqdn.md` surveys in the cloud-native
camp (Calico, NSX) restricts which resolver addresses it trusts before
acting on a snooped answer; chunks #9-#10 shipped without one, explicitly
flagged as the next thing worth revisiting once enforcement started acting
on snooped answers (chunk #10's own "Spoofing" residual limitation). Chunk
#11 closes it: `bathyscaphe::dns::trust::TrustedResolvers` is an
operator-configured set of resolver addresses, and
`crate::dns::capture_callback` checks every captured response's own
`src_addr` (see "What is captured, and how" above) against it, producing a `trusted:
bool` on `AttributedAnswer` that `daemon::fqdn::on_dns_answer` (the
enforcement gate) checks before ever calling `ProbeApi::set_policy`.

**The default set** (`TrustedResolvers::default_at`, built by
`cli::run_cmd::build_config` from `/etc/resolv.conf` at process start):

- `127.0.0.11` (`bathyscaphe::dns::trust::DOCKER_EMBEDDED_DNS`) --
  unconditionally, always. `bathyscaphe-ebpf::dns_query`'s own empirical
  investigation (chunk #10, "Docker's embedded-DNS DNAT rewrite" above)
  already established that Docker's per-container-network-namespace DNAT
  rule rewrites the DESTINATION PORT of a query addressed to
  `127.0.0.11:53` but never the address -- the address is a reliable,
  NAT-invariant signal specifically for this one well-known resolver, and
  by the same DNAT symmetry, the RESPONSE's own source address genuinely
  reads back as `127.0.0.11` too (proven live against a real container on
  a real user-defined bridge network -- `docs/TESTING.md` has the
  `bathyscaphe-itest-dns-src-addr-smoke` live-smoke test's raw captured
  bytes). This makes `127.0.0.11` the canonical trusted source for any
  container using Docker's embedded resolver, unconditionally, not merely
  a configurable convenience.
- Every `nameserver` line in the host's own `/etc/resolv.conf`
  (`bathyscaphe::dns::trust::parse_resolv_conf_nameservers`): the
  reasoning is that a container reaching one of ITS HOST's own configured
  upstream resolvers directly (bypassing Docker's embedded resolver
  entirely -- possible on a container with a custom `--dns` flag, or one
  attached to the host's network namespace) is using a resolver the
  operator already implicitly trusts for every other purpose on this host.

**Operator extension**: `--trusted-resolver <ip>` (repeatable,
`cli::RunArgs::trusted_resolver`) adds addresses on top of the default
set. There is deliberately no flag or code path anywhere in
`bathyscaphe::dns::trust` that trusts everything by default -- the build
brief's explicit instruction ("Do NOT default to trust-everything") is
enforced by construction: `TrustedResolvers::new([])` starts empty, and
every other constructor only ever ADDS specific, named addresses.

**The fail-closed direction**: a container using a resolver OUTSIDE the
trusted set (a public resolver reached directly, an operator-unconfigured
internal one) simply never gets a name rule's resolved IPs seeded into its
allow-map. In `mode: block`, that falls straight back to the container's
ordinary IP/CIDR default (normally deny) -- an over-block an operator will
notice and can fix with `--trusted-resolver`, never a silent widening an
attacker could exploit. `cli::run_cmd::run` logs the resolved trusted set
at startup, and warns loudly (`cli.run.no_resolv_conf_nameservers`) when
`/etc/resolv.conf` yielded zero nameservers, and again, more severely
(`cli.run.trusted_resolvers_empty`), on the pathological case where the
whole resolved set is somehow empty -- both per the build brief's "if the
resolved default set is empty, warn loudly" instruction.

### The loud potential-spoofing signal: `dns.untrusted_answer`

When an untrusted-sourced answer WOULD have matched a container's active
`Allow` name pattern (the pattern match is still evaluated even though the
answer is never used for enforcement), `daemon::fqdn::on_dns_answer` emits
a throttled (same shared token bucket as every other R1 loud record)
`security` record, `reason: dns.untrusted_answer`,
`severity: Warning`, carrying `resolver.addr` (the untrusted source) and
`domain` (the name that would have matched) as attributes
(`daemon::security::dns_untrusted_answer_record`). This is the
differentiator the build brief asked for: a container's own resolver (or
something able to inject traffic into its network namespace) answering an
allow-listed hostname from a source outside the operator's trusted set is
exactly the spoofing attempt a trusted-resolver allowlist exists to
defeat, and it is now visible rather than silently absorbed. A
would-have-matched `Deny` pattern from an untrusted source is deliberately
NOT reported the same way -- failing to enforce a deny an attacker was
trying to defeat by spoofing is a strictly safer outcome than the
allow-spoofing case, so it does not carry the same urgency.

### Enrichment versus enforcement trust: the choice this chunk makes

The build brief drew a distinction: enforcement (seeding `POLICY`) MUST
gate on trust, but enrichment (`DomainCache`, feeding `domain.*` on
regular connect events) MAY still record an untrusted answer, as long as
it is tagged low-confidence so it never silently looks authoritative. This
build's choice: `DomainCache::record` now takes the same `trusted` bit and
FLOORS the entry's confidence at
`DomainConfidence::Inferred` (see "The per-container IP -> domain cache"
above) regardless of how fresh the answer's own TTL says it is -- an untrusted
answer can still put a name on an event (more useful to an operator
skimming bilgeline logs than a null one), but it can never read as
`Asserted`, the wire's strongest confidence value, which stays reserved
for answers this build actually trusts. This is a deliberate widening of
`DomainConfidence`'s existing "less certain past TTL" meaning to also
cover "less certain because untrusted", rather than adding a new wire enum
variant for it -- the frozen protocol gains no new value, and the existing
`Inferred` semantics ("don't treat this as gospel") already fit an
untrusted answer's honest epistemic status. A future chunk with a real
need to distinguish "stale but trusted" from "fresh but untrusted" could
revisit this; chunk #11 judges the collapse acceptable rather than
warranting a wire change.

### Name-based DENY enforcement (Part B)

Chunk #10 shipped `NamePatternStore` accepting and storing a `deny`-action
name rule (never silently dropped or miscounted as inert) but never
actually enforcing it -- flagged as a residual limitation at the time.
Chunk #11 closes it: on a TRUSTED DNS answer matching an active `Deny`
pattern (`NamePatternStore::first_matching_deny`, checked BEFORE the
`Allow` check), `daemon::fqdn::on_dns_answer` inserts the resolved address
into `POLICY` as a `/128` host route with `action: Deny`, `source:
RuleSource::Dns`, and the same `expires_at_ns` derivation (and the same
`probe::policy::PolicyStore::reap_expired` TTL/reaper handling) the
`Allow` path has used since chunk #10 -- no separate lifecycle for a deny
route. A pattern carrying a port/proto constraint applies it symmetrically
to the `Allow` case: an unconstrained `Deny` pattern blocks the address
entirely (`cidr_default_action: Deny`, no port rules); a `Deny` pattern
scoped to a specific port/proto instead defaults the address's OTHER ports
to `Allow` and denies only the named port/proto -- a name-based deny means
"block this address on this port", never "block this address entirely"
once a port/proto constraint narrows it.

**Deny wins**: if the same answer matches BOTH an active `Allow` pattern
and an active `Deny` pattern for a container (a container can legitimately
register both, e.g. a broad `*.example.com` allow alongside a narrower
`evil.example.com` deny), the deny match is checked first and, if present,
is the ONLY thing inserted -- the allow match is ignored entirely, never
producing a second, conflicting `POLICY` entry for the same address. This
matches `docs/PROTOCOL.md`'s wire-level "deny wins at equal specificity"
rule, extended here to name rules.

**The limitation, stated plainly**: this only ever blocks an IP this build
actually SAW via a TRUSTED DNS answer -- the exact same best-effort
envelope the `Allow` path has carried since chunk #10. A container that
never resolves the denied name through a visible, trusted path (DoH/DoT,
an untrusted resolver, or simply never looking it up because it already
knows the IP) is not blocked by the name rule at all; IP/CIDR policy
remains the hard floor an operator relies on for a deny that MUST hold
regardless of how the destination was reached. A name-based deny is a
best-effort narrowing on top of that floor, exactly like a name-based
allow is a best-effort widening on top of it -- never a substitute for
either.

## Build chunk #12: exact-length capture correctness fix

### The bug, as observed live

Chunks #9-#11's `dns_snoop` captured a DNS response payload by trying a
ladder of six LITERAL, compile-time-constant `bpf_skb_load_bytes` lengths
(512, 384, 256, 128, 64, 32 bytes -- the `try_tier!` macro,
`bathyscaphe-ebpf::dns`), largest-first, keeping whichever succeeded. This
was itself a fix for a real eBPF verifier limitation (a COMPUTED length
argument's tracked range could never be proven to exclude zero on this
workspace's toolchain and kernel -- `docs/TESTING.md`'s chunk #9 account
has the full investigation), but it traded that problem for a different
one: a response whose TRUE length fell strictly BETWEEN two adjacent
tiers was captured at the NEXT SMALLER tier, silently truncating it. This
was observed live, not merely reasoned about: a genuine ~90-100-byte DNS
response landed between the 64- and 128-byte tiers and was captured at
only 64 bytes. A truncated DNS message fails to parse in userspace
(`simple-dns`'s `Packet::parse` rejects it outright), so that answer never
reached the domain cache or the FQDN allow-map at all -- the practical
consequence was FQDN enforcement intermittently over-blocking legitimate
name-allowed traffic (fail-closed, per this project's own posture, but
WRONG: the name genuinely had been resolved, the capture just lost the
evidence).

### The fix: clamp-then-mask, not tiers

`bathyscaphe-ebpf::dns::capture_if_dns_response` now issues a SINGLE
`bpf_skb_load_bytes` call whose length is the UDP header's own honest
length, clamped to `DNS_CAPTURE_MAX`, computed via a two-step idiom that
proves the verifier's required "nonzero length" bound WITHOUT depending on
any branch's narrowing surviving the compiler's BPF-target codegen (the
specific failure chunk #9 hit for a runtime-subtraction-derived length):

1. **Clamp**: an ordinary `if`/`else` `min` against the compile-time
   `DNS_CAPTURE_MAX` constant -- no subtraction against any
   skb-context-derived value at all (unlike the earlier, rejected
   `skb_len - offset` attempts).
2. **Mask, then add one**: `((capped - 1) & (DNS_CAPTURE_MAX - 1)) + 1`.
   The eBPF verifier derives a bitwise AND's output range directly from
   the mask operand, independent of the input's own prior tracked range,
   and an addition of a compile-time positive constant has a provably
   positive minimum -- together these prove the final value is in
   `[1, DNS_CAPTURE_MAX]` from the AND/ADD instructions themselves. Given
   the clamp step's actual runtime range (`capped` is always in
   `[1, DNS_CAPTURE_MAX]` once a zero-length payload is special-cased away
   before this code runs), the mask-then-add is a value-preserving
   IDENTITY -- the final length always equals the clamped length exactly,
   so nothing is lost to the trick itself. See
   `bathyscaphe-ebpf::dns`'s own module doc for the full derivation.

This was VERIFIED LIVE against a real kernel 6.8.0-136: `attach_container`
succeeds for all seven programs (the verifier accepts the new capture
code), and real responses of varying sizes -- including ones deliberately
sized into the OLD tier gaps -- are now captured at their own exact
length. See "Privileged smoke test" below for the precise sizes.

### The cap: unchanged at 512 bytes, over-cap behavior documented

`DNS_CAPTURE_MAX` stays 512 bytes (the historical "traditional" UDP DNS
ceiling before EDNS0) rather than raising it toward a modern EDNS0 value
(commonly 1232, per RFC 8467's fragmentation-avoidance recommendation, or
up to 4096) -- the bug this chunk fixes was tier GRANULARITY, not the cap
itself, and 512 bytes comfortably covers the overwhelming majority of a
container's real A/AAAA lookups against a typical resolver. A response
that genuinely exceeds 512 bytes is still captured, truncated EXACTLY at
the cap (not tier-truncated below it) -- see "The tolerant path" in
`bathyscaphe::dns::parse`'s module doc, and "Oversized responses" above,
for how the userspace parser now recovers whatever complete answers fit
within that cap-truncated prefix rather than discarding the whole message
the way it did pre-chunk-#12.

### The userspace parser: a new tolerant path, verified against simple-dns

Verified experimentally (not assumed) against `simple-dns` 0.12: given a
buffer truncated mid-record, `Packet::parse` fails the WHOLE message with
`SimpleDnsError::InsufficientData`, discarding even fully-intact earlier
answers, because its per-section parse loop trusts the header's own
`ANCOUNT` field and always tries to parse that many records regardless of
how many the truncated bytes can actually supply. `simple-dns`'s public
API exposes no lower-level per-record parse loop to resume manually (its
`Header`, `BytesBuffer`, and internal `WireFormat` trait are all private
to that crate), so `bathyscaphe::dns::parse::recover_capped_answers`
instead retries `Packet::parse` on a byte-for-byte copy with the header's
`ANCOUNT` (and `NSCOUNT`/`ARCOUNT`, zeroed) patched down from its original
claimed value -- three well-known, fixed-offset RFC 1035 section 4.1.1
count fields, never a name or a record body -- until one candidate value
actually fits. This recovers the largest prefix of COMPLETE answer
records a capped/truncated capture contains; every byte of actual parsing
(name decompression, rdata validation) is still done entirely by
`simple-dns` itself. See `bathyscaphe::dns::parse`'s module doc for the
full design and `bathyscaphe/src/dns/parse.rs`'s test module for the
regression coverage (a response truncated mid-record recovers exactly the
answers ahead of the cut; one truncated before any answer completes
recovers nothing, not a panic).

### Privileged smoke test -- FULL PROOF, precisely

**Setup**: this test deliberately does NOT go through a Docker container
or real internet DNS traffic (chunks #9-#11's own tests already prove
`dns_snoop` against genuine resolver traffic; EXACT byte-length control
across several sizes is the whole point here, which no real resolver's
answer size can be precisely dialed to). Instead, the test process itself
was moved into a fresh, dedicated cgroup v2 directory (the same
mkdir-and-attach pattern `probe::live_smoke` uses), the real probe (all
seven programs, `dns_snoop` included) attached to it, and two loopback UDP
sockets (one bound to port 53 standing in for "the resolver," one on an
ephemeral port standing in for "the container's own query socket")
exchanged real, hand-built DNS response payloads of chosen sizes over a
real kernel socket path -- still the REAL `dns_snoop` `cgroup_skb` ingress
hook on a REAL `sk_buff` for each size, just with the size fully under the
test's control. Run on the same host, kernel 6.8.0-136,
`bathyscaphe-itest-dnsfix-priv` (`--privileged --cgroupns=host --pid=host`).

**What ran**:
`probe::dns::live_smoke::dns_snoop_captures_the_exact_length_across_varying_sizes_including_the_old_tier_gap`.

**Result, exactly as printed by the passing run**:

```
dns live_smoke (varying sizes): baseline: sent 46 bytes, captured 46 bytes, parsed 1 answer(s)
dns live_smoke (varying sizes): tier_gap: sent 74 bytes, captured 74 bytes, parsed 1 answer(s)
dns live_smoke (varying sizes): mid_gap: sent 467 bytes, captured 467 bytes, parsed 14 answer(s)
dns live_smoke (varying sizes): over_cap: sent 653 bytes, captured 512 bytes, parsed 15 answer(s)
dns live_smoke (varying sizes): FULL PROOF -- clamp-then-mask exact-length capture verified live across 4 sizes, including the old 64/128 and 384/512 tier gaps and one over-cap case
```

This decisively proves, on a real kernel, for a real `sk_buff` at each
size:

- **46 bytes** (`baseline`, sitting cleanly WITHIN the old 32/64-byte
  tier): captured at its own exact length -- a sanity check that the fix
  doesn't regress the case the old scheme already handled correctly.
- **74 bytes** (`tier_gap`, deliberately sized strictly between the OLD
  64- and 128-byte tiers -- the exact shape of the LIVE bug this chunk
  fixes): captured at its own exact length, 74 bytes, and parses
  completely. Pre-chunk-#12, this size would have been truncated to 64
  bytes and failed to parse at all.
- **467 bytes** (`mid_gap`, strictly between the OLD 384- and 512-byte
  tiers, with 14 answer records): captured at its own exact length and
  every one of the 14 answers parses.
- **653 bytes** (`over_cap`, deliberately exceeding `DNS_CAPTURE_MAX`,
  20 answer records): captured truncated EXACTLY at the 512-byte cap (not
  tier-truncated below it), and the tolerant parser recovers 15 of the 20
  answers -- precisely the number whose complete records fit within the
  512-byte prefix, proving the "recover what's actually there, don't
  fabricate what isn't" behavior end to end.

Re-run alongside all four pre-existing privileged live-smoke tests
(`probe::live_smoke::load_attach_pin_reopen_unpin_round_trip`,
`probe::dns::live_smoke::dns_snoop_captures_and_parses_a_real_containers_dns_answer`,
`probe::dns::live_smoke::dns_snoop_captures_the_responses_own_source_address`,
`probe::dns_query::live_smoke::query_response_correlation_recovers_the_correct_container_cgroup`,
`attribution::resolver::live_smoke::resolves_a_real_container_end_to_end`)
in one invocation: all six passed together. Notably, chunk #9's own
`dns_snoop_captures_and_parses_a_real_containers_dns_answer` test --
against genuine `nslookup example.com` traffic on this same run --
reported an 85-byte capture (its own historical account in
`docs/TESTING.md` recorded 64-byte tier-truncated captures for this exact
scenario); the exact-length fix improved a real, non-synthetic capture in
the same test run this chunk's own synthetic test was verifying.

**Cleanup**: the test's own cgroup directory and bpffs pin root were
removed as part of its own teardown (this process is moved back to its
original cgroup first, since a cgroup directory cannot be removed while a
process still lists it as its own). `bathyscaphe-itest-dnsfix-build` and
`bathyscaphe-itest-dnsfix-priv` were removed after use; confirmed via
`docker ps -a` afterward. `/sys/fs/bpf` confirmed empty and no leftover
`bathyscaphe-itest-*` cgroup directories confirmed via
`find /sys/fs/cgroup -maxdepth 1 -iname 'bathyscaphe*'` after the final run.

### Egress query capture: unaffected, confirmed minimal

`bathyscaphe-ebpf::dns_query` (`dns_query_snoop`) never had this problem
and needed no change: every read it performs is a small, fixed-size load
at a fixed offset (IP header fields, both UDP ports, the two-byte DNS
transaction id) -- it never copies a variable-length payload at all, so
none of chunk #9's tiered-length machinery (or this chunk's replacement)
ever applied to it. Confirmed unchanged in this chunk;
`bathyscaphe-ebpf/src/dns_query.rs` was not touched.

## Full residual limitation list (chunks #9-#14, honest and complete)

IP/CIDR policy is the ground-truth floor throughout; every limitation
below describes when FQDN enforcement's best-effort layer has nothing to
add, never a case where IP/CIDR enforcement itself is compromised.

- **DoH/DoT/ECH**: structurally invisible to both `dns_snoop` and
  `dns_query_snoop` (neither touches port 443/853 traffic) -- a name rule
  targeting a domain resolved exclusively via one of these never gets any
  IP inserted into the allow-map, and (per the loud-record section above)
  a subsequent connection to that domain's actual IP is denied loudly if
  no other policy permits it.
- **TCP DNS**: both the query snoop and the response snoop match
  `IPPROTO_UDP` only; a query/response pair that falls back to TCP:53
  (large/truncated messages, or a resolver that prefers TCP outright) is
  invisible to correlation and to caching alike. Documented as a gap in
  chunk #9 already; chunk #10 does not close it for the query side either.
- **IPv6 extension headers**: both snoop programs assume UDP is the IPv6
  fixed header's immediate next header (chunk #9's original gap,
  unchanged by chunk #10).
- **Uncorrelatable responses fall back to the response hook's own
  cgroup_id, low-confidence**: documented above (`AttributedAnswer::correlated`);
  the cache and enforcement pipeline still function, using the same
  attribution chunk #9 shipped.
- **The correlation key is STILL `(txid, port)` only, no resolver-address
  component -- but a collision at that key can no longer cross-attribute
  (FIXED by build chunk #14)**: chunk #10 judged an address-based key
  unnecessary; chunk #13's live testing proved a real collision reaches
  the key deterministically more easily than assumed. Chunk #14
  investigated adding an address component empirically and found it does
  NOT work for the vulnerable case (see "Build chunk #14" below) --
  instead, the table now detects when more than one container's query is
  live at the same key and refuses to attribute the answer to either one,
  rather than silently picking (possibly wrongly) as before. The residual
  that remains: a genuine collision still means NEITHER colliding
  container's answer gets used for enforcement during the overlap (a
  fail-safe availability cost, bounded by the now-shorter 2-second TTL),
  never that the wrong container's policy gets seeded.
- **The Docker-embedded-DNS address special-case is Docker-specific**:
  `dns_query_snoop` recognizes `127.0.0.11` by address as a NAT-invariant
  signal (see the empirical-investigation section above). A different
  container runtime's own embedded resolver, reached through a similar
  local-DNAT scheme but a different well-known address, would need its
  own address added to be recognized the same way -- not automatically
  covered.
- **Only the FIRST matching name pattern drives an insertion**: a name
  matching more than one registered pattern for a container uses
  whichever pattern compiled first; their port/proto constraints are never
  merged.
- **A name-based deny only blocks IPs actually seen via a trusted DNS
  answer** (build chunk #11 closed the "not enforced at all" gap chunk #10
  left open, but the enforcement itself keeps the same best-effort
  envelope the `Allow` path has always had): see "Build chunk #11" above,
  "Name-based DENY enforcement", for the full statement. IP/CIDR policy
  remains the hard floor a deny that MUST hold regardless of DNS
  visibility has to rely on.
- **`policy.name_unresolved_block`'s heuristic imprecision**: documented
  in its own section above -- it can fire on an unrelated CIDR-policy
  deny, not exclusively on a genuinely name-rule-intended one.
- **Spoofing is mitigated for the trusted-resolver path, not eliminated as
  a DNS-protocol concern**: build chunk #11's trusted-resolver allowlist
  (see "Build chunk #11" above) means an untrusted-sourced answer can no
  longer seed `POLICY`, closing the specific gap chunk #9/#10 flagged
  here. What remains explicitly out of scope, matching every DNS-snooping
  tool `prior_art_fqdn.md` surveys: cache-poisoning a resolver that IS in
  the trusted set (an upstream DNS server this host's operator already
  configured and implicitly trusts) is a DNS-protocol-level attack this
  project does not attempt to defend against -- trusting a resolver's
  ADDRESS says nothing about whether that resolver's own upstream answers
  are themselves being poisoned. DoH/DoT/ECH and direct-IP egress remain
  the other two documented ways a container can evade name-rule policy
  entirely, with IP/CIDR staying the hard floor beneath all three, exactly
  as `bathy_build_spec.md`'s BUILD-THROUGH STANCE requires.

## Build chunk #14: cross-container DNS correlation isolation (SECURITY FIX)

Chunk #13's live integration testing escalated a real finding (`docs/TESTING.md`'s
own "Build chunk #13" section, bug #1): the query/response correlation
table (`bathyscaphe::dns::pending::PendingQueryTable`) was a single global
`(txid, dst_port)` map, and a second container's query at the same key
silently OVERWROTE the first's still-live entry -- reproduced deterministically
(5/5) via a stale entry left behind by an already-`release`d container.
This is squarely a security-relevant bug: in `mode: block`, the same
unconditional preference for a correlation-table hit is what seeds a
container's kernel `POLICY` allow-map, so a collision could in principle
attribute one container's DNS answer to a DIFFERENT container's
enforcement map.

### The empirical question this chunk had to answer first

Before choosing a fix, the build brief mandated investigating directly
whether a container-identifying ADDRESS (the query's own source address,
or the response's own destination address) could disambiguate two
colliding containers, since that would be the "obvious" fix. Investigated
against a real `alpine` container on a real user-defined Docker network,
kernel 6.8.0-136, with `tcpdump` run INSIDE the container's own network
namespace during a real `nslookup` against Docker's embedded resolver:

```text
127.0.0.1.35026 > 127.0.0.11.50427: ...   (the QUERY, as observed on the container's own lo)
127.0.0.11.53 > 127.0.0.1.35026: ...       (the RESPONSE)
```

**Finding**: the query's own source address and the response's own
destination address are BOTH `127.0.0.1` -- the container's real
bridge-network IP (confirmed separately as `192.168.16.2` via `ip addr
show eth0` in the same container) never appears on either side of this
exchange at all. This is not a fluke of one run: `127.0.0.1` is
per-network-namespace, and Docker's embedded resolver delivers its answer
via an injected loopback exchange entirely inside the querying container's
own netns (the actual upstream resolution happens elsewhere and is relayed
in) -- so this exact byte pattern is IDENTICAL across every container
using the embedded resolver, regardless of which one it is. **An
address-based correlation key would have added real complexity (new eBPF
loads on `dns_snoop`/`dns_query_snoop`, a wire-size change to
`DnsQueryCapture`) for zero discriminating power in exactly the case that
needed fixing.** (For a response reached over a REAL NIC/veth path -- an
external resolver -- the address genuinely would be the container's own;
but that path's `cgroup_id` attribution is already correct per "Why
ingress" above, so it was never the vulnerable case.)

### The fix actually built

Given that finding, build chunk #14 did NOT add an address component.
Instead, `PendingQueryTable` now tracks every DISTINCT cgroup with a live
query at a `(txid, port)` key (previously: one, silently overwritten), and
`correlate` returns `Resolved(cgroup_id)` only when EXACTLY one candidate
is live; `Ambiguous` when more than one different container's query
collides at that exact key; `Miss` when none do. `crate::dns::capture_callback`
treats `Ambiguous` exactly like `Miss` -- falls back to the response
capture's own attribution, `correlated: false` -- which can never insert a
`POLICY` entry under a real container's cgroup that container's own
traffic didn't earn. **An answer is now either attributed with confidence
or not attributed to any specific container's policy at all -- never
attributed to the WRONG one.** Full derivation:
`bathyscaphe/src/dns/pending.rs`'s module doc.

Three more changes close the rest of chunk #13's own finding:

- **Release cleanup**: `daemon::apply::apply_release`/`apply_release_all`
  now purge a released container's entries from the table
  (`PendingQueryTable::remove_container`) -- the stale-entry half of the
  chunk #13 repro. A released container can no longer be the ghost a later
  container's query collides with.
- **A bounded collision window**: `PENDING_QUERY_TTL_NS` cut from 5s to 2s,
  and a served-response cap (`MAX_SERVED_RESPONSES = 4`) evicts an entry
  immediately once it has answered enough responses rather than lingering
  idle for the rest of its TTL, shrinking how long two containers' queries
  can ever be concurrently live at the same key.
- **A low-rate diagnostic**: `crate::dns::log_ambiguous_correlation` emits
  a throttled (independent of the R1 security-record bucket, since there
  is no single container to attribute an ambiguous answer to) stderr line
  the first time a genuine collision is detected, and no more than once
  per 5 boottime-seconds thereafter.

### Proof

`dns::pending::tests::two_different_containers_colliding_on_the_same_key_never_cross_attribute`
and `dns::tests::capture_callback_never_cross_attributes_a_genuine_two_container_collision`
prove the property without a kernel. Two NEW integration scenarios prove
it against a real kernel: `test/integration/scenarios.py`'s
`scenario_9_cross_container_isolation` forces a DETERMINISTIC `(txid,
port)` collision between two real containers (hand-crafted DNS queries
over `nc -u -p <fixed port>`, not hoping for a natural collision) and
proves neither's `POLICY` map is ever seeded with the other's route, in
either direction, and that the fix self-heals once the collision clears;
`scenario_8_untrusted_resolver_shared_daemon` re-runs scenario 6's exact
logic sharing scenarios 4/5's own daemon session -- the precise chunk #13
live repro -- and proves it PROVEN, not silently suppressed. Full account,
including a second, orthogonal finding this proof surfaced (the R1 shared
security-record token bucket needing a real refill interval when several
DNS-active scenarios share one daemon session -- not a correlation bug):
`docs/TESTING.md`'s "Build chunk #14" section.
