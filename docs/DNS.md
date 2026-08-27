<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# DNS observation

Build chunk #9 of the sequence in `bathy_build_spec.md`. This document is
the honest account of what bathyscaphe's DNS-snoop layer sees, what it
structurally cannot see, and how the pieces fit together. IP/CIDR policy
remains the ground truth throughout (`bathy_build_spec.md`'s BUILD-THROUGH
STANCE); everything here is enrichment now, and in chunk #10 becomes
best-effort FQDN enforcement layered on top of that same ground truth,
never a replacement for it.

## What is captured, and how

`dns_snoop` is a `cgroup_skb` eBPF program, attached **ingress** to each
monitored container's cgroup (`bathyscaphe-ebpf::dns`). It recognizes a
UDP datagram whose *source* port is 53 (a DNS response arriving at the
container from its resolver, whether that resolver is an external server
or Docker's embedded resolver at `127.0.0.11:53` reached over loopback)
and copies up to `bathyscaphe_common::dns::DNS_CAPTURE_MAX` (512) bytes of
its payload, plus the observing cgroup id and a kernel timestamp, into a
dedicated `DNS_EVENTS` ring buffer. It never parses the DNS message itself
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
  `DNS_CAPTURE_MAX` (512 bytes) is captured truncated, not rejected.
  `bathyscaphe::dns::parse::parse_dns_response` handles a message that
  fails to parse as a result the same way it handles any other malformed
  input: as "nothing learned from this datagram," never a panic or a
  process-level error.
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
  the full account, including the raw bytes that proved it.
- **Spoofing**: `dns_snoop` trusts *any* UDP:53-sourced datagram reaching
  the container's ingress path -- there is no allow-list of trusted
  resolver addresses (unlike Calico/NSX's explicit "trusted DNS servers"
  restriction, see `prior_art_fqdn.md`). A process able to inject a UDP
  datagram into the same network namespace with a spoofed source port
  could poison the domain cache this layer feeds. In THIS chunk that is
  purely a display/enrichment integrity concern (a misleading `domain.name`
  on an event, nothing more); it becomes a policy-relevant concern the
  moment chunk #10 starts inserting cache-derived IPs into the
  enforcement allow-map, and is the right point to revisit whether a
  trusted-resolver restriction is worth adding.

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

`hello.capabilities` now includes `dns_enrich` (`daemon::hello`).
`enforce_fqdn` (chunk #10) is deliberately still absent -- see
`docs/PROTOCOL.md` section 2 on why advertising an unbuilt capability
would turn a `policy` sender's `mode: block` on a name rule into a silent
downgrade rather than the sticky validation error the wire protocol
requires.

## What chunk #10 (FQDN enforcement) plugs into

1. **The cache API**: `bathyscaphe::dns::cache::DomainCache::lookup` and
   `::record` are the whole public surface. Chunk #10 does not need to
   rebuild parsing or capture -- it reads (or extends the writer of) the
   same cache this chunk populates.
2. **Where name-rule patterns register**: a container's compiled `type:
   "name"` rules (`docs/PROTOCOL.md` section 4) should be kept alongside
   `daemon::state::ContainerState` (or a sibling structure), so that on
   every `DomainCache::record` call (or a new hook alongside it), chunk
   #10 can check whether the just-observed `domain` matches one of that
   container's enforceable patterns (exact name or `*.wildcard`).
3. **Inserting resolved IPs into the policy allow-map**: on a match,
   chunk #10 writes the resolved address into `POLICY`
   (`bathyscaphe_common::policy`, via `probe::policy::PolicyStore::set_policy`)
   as a host-route entry (`prefix_bits_over_addr = 128`), with
   `source: RuleSource::Dns` and an `expires_at_ns` computed from the
   SAME `(ttl_secs, now_boottime_ns)` pair `DomainCache::record` already
   receives -- the enrichment cache and the enforcement allow-map should
   agree on the exact same absolute expiry instant, not derive it twice.
4. **Unenforceable names in block mode**: per `bathy_build_spec.md`'s
   ratified NAME-RULE RESOLUTION stance, a name rule that has never been
   resolved (DoH bypass, cache miss, grace-window expiry) in `mode: block`
   fails CLOSED on that traffic with loud accounting (R1's `security`
   record, `reason: policy.unenforceable_name`) -- never fail-open. This
   chunk does not implement that decision path; it only makes sure the
   cache chunk #10 needs to consult already exists, is tested, and is
   documented honestly about when it does and does not have an answer.
