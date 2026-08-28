<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Testing bathyscaphe

Honest record of what has actually been proven, versus what is compile-only
or still untested, as of each build chunk. This file is added by the
USERSPACE CORE build chunk (#5) and will be extended by the TESTING build
chunk (#10) with the full unit + integration harness.

## What chunk #5 proved

### Unprivileged, no kernel/bpffs/cgroup access required

Run with `cargo test` inside the `rust:1-bookworm` toolchain container
documented in `docs/BUILDING.md` (no `--privileged`, no bpffs, no real
cgroup2 needed):

- `probe::layout` -- pin path arithmetic, fixed-width hex cgroup id
  directory naming, `pin_state` fresh/complete detection.
- `probe::policy` -- the isolation-safe key builder
  (`build_policy_key`): every produced key has `prefix_len >=
  PolicyKeyData::MIN_PREFIX_LEN` across the full `0..=128` range of
  `prefix_bits_over_addr`, out-of-range input is rejected, and an
  adversarial pair of cgroup ids differing in a single bit cannot cross-match
  under a userspace re-implementation of the kernel's own LPM
  longest-prefix-match rule. `validate_policy_value` rejects a
  hand-crafted `n_port_rules` overflow that bypasses
  `PolicyValue::with_port_rule`. `tcp_port_rule`/`udp_port_rule` round-trip
  through `PortRule::encode_proto` correctly (proto is never confused with
  `PortRule::PROTO_ANY`). RFC 4291 address embedding for both IPv4 and IPv6.
- `probe::events` -- ring buffer record decode round-trips a well-formed
  `Event`, and rejects (rather than reading out of bounds on) a
  short or oversized buffer.

17 tests, all green, in addition to the 45 pre-existing tests from earlier
chunks (`bathyscaphe-common`, `bathyscaphe-proto`).

### Privileged live smoke test -- PROVEN, verifier ACCEPTED

Per the build brief's mandate to attempt an actual kernel load and report
the verifier outcome precisely: this was run, twice, successfully.

**Setup**: two throwaway containers from `rust:1-bookworm` (cleaned up
after use, per the build spec):
- `bathyscaphe-itest-loader` (unprivileged): built the workspace and the
  test binary per `docs/BUILDING.md`'s documented toolchain.
- `bathyscaphe-itest-smoke` (`docker run --privileged`, same image, same
  `/workspace` bind mount so it could run the already-built test
  binary without repeating the toolchain setup): host kernel 6.8.0-136,
  `/sys/fs/cgroup` already mounted `cgroup2fs` `rw`; `mount -t bpf bpf
  /sys/fs/bpf` to get a writable bpffs (not mounted by default in this
  container image).

**What ran**: `probe::live_smoke::load_attach_pin_reopen_unpin_round_trip`
(`#[ignore]`d by default -- it needs privilege and real cgroup2/bpffs, so it
never runs under a plain `cargo test`; invoked explicitly with `--ignored
live_smoke`). It:

1. Creates a real cgroup v2 directory (`mkdir` under `/sys/fs/cgroup`).
2. `Probe::load_or_reopen` on a clean bpffs root -- this is the FRESH path:
   `aya::Ebpf::load` the real embedded object, `.load()` each of the five
   programs (`connect4`, `connect6`, `sendmsg4`, `sendmsg6`,
   `sock_create`), pin each program and each of the four maps, then
   immediately reopen everything from those pins.
3. `attach_container` -- attaches all five programs to the real cgroup and
   pins the resulting links.
4. Drops the `Probe` handle entirely (closing every fd this process held)
   and calls `Probe::load_or_reopen` again on the SAME bpffs root -- this
   is the RESUMED path: no `aya::Ebpf::load` at all, every program and map
   reopened via `from_pin`, and the attached container rediscovered by
   walking `links/`.
5. Asserts the rediscovered container is present, `detach_container`s it,
   and `unpin_all`s the whole subtree.
6. Asserts the bpffs subtree is gone and removes the test cgroup.

**Result**: `test probe::live_smoke::load_attach_pin_reopen_unpin_round_trip
... ok` both times it was run. No verifier rejection occurred -- there is
no rejection log to report because there was nothing to reject. Concretely,
this proves:

- The embedded eBPF object built by the two-toolchain pipeline (`docs/BUILDING.md`)
  is not just a well-formed ELF object (which `docs/BUILDING.md` already
  proved via `readelf`) but a program the **kernel's verifier actually
  accepts** for all five attach points, on a real 6.8 kernel.
- `CgroupAttachMode::Single` attach to a real cgroup v2 directory fd
  succeeds for both `CgroupSockAddr` (`connect4`/`connect6`/`sendmsg4`/`sendmsg6`)
  and `CgroupSock` (`sock_create`) program types.
- Pinning programs, maps, and links to a real bpffs and reopening every one
  of them via `from_pin` -- with zero fresh `Ebpf::load` on the resumed
  path -- produces a working, functionally identical `Probe` to the one
  that did the fresh load. This is the fail-closed restart lifecycle's core
  claim, and it now has kernel-level evidence, not just code review.
- `unpin_all` actually removes the pin subtree from a real bpffs.

**Cleanup**: both `bathyscaphe-itest-loader` and `bathyscaphe-itest-smoke`
containers were removed after the run. No `bathyscaphe-itest-*` image was
built (both ran directly off the public `rust:1-bookworm` image), so there
was no image to remove. The test itself removes its own cgroup and bpffs
artifacts as its last steps; both were confirmed absent after the run.

## What is still deferred to later chunks

- **Actual traffic through the attached hooks** (does a `connect()` from
  inside the test cgroup actually get allowed/denied per a real policy
  entry, does the `EVENTS` ring buffer actually receive a record) --
  requires a process running *inside* the cgroup making real connections,
  which is squarely the TESTING build chunk's (#10) job, alongside a real
  policy push. This chunk's smoke test proves attach + pin lifecycle, not
  end-to-end policy enforcement.
- **The DAEMON build chunk's protocol loop, reconciliation, and CLI** --
  `probe::Probe` is deliberately not wired into `main()` yet (see that
  module's doc); there is nothing to test end-to-end until it is.

## What chunk #6 (attribution + the event pipeline) proved

### Unprivileged, no kernel/bpffs required

`cargo test` inside the same `rust:1-bookworm` toolchain container, no
`--privileged`:

- `attribution::cgroup` -- `classify_trailing_segment` against every
  documented cgroup path shape: Docker systemd (`docker-<hex>.scope`),
  Docker cgroupfs (bare `<hex>` under a `docker` parent), Podman rootful
  systemd and cgroupfs, Podman rootless's full
  `user.slice/user-<uid>.slice/user@<uid>.service/user.slice/libpod-<hex>.scope`
  nesting, the `libpod-conmon-*` exclusion, a non-container cgroup, `init.scope`,
  wrong-length and uppercase hex rejection, and the documented bare-hex/no-known-parent
  default. Plus `CgroupMap`'s record/forget-by-path bookkeeping.
- `attribution::enrich` -- `EnrichmentCache` upsert/get/remove semantics,
  including that an all-`None` `ContainerMeta` never occupies a cache slot.
- `attribution::resolver` -- the miss path (nonexistent root, unknown
  cgroup id) returns `None` rather than panicking.
- `pipeline::map` -- verdict reconstruction for all three wire values
  (`allow`/`deny`/`would_deny`), v4-in-v6 address unmapping and native v6
  passthrough, `comm` decode (NUL-terminated, buffer-filling, all-zero),
  the documented `pid`/`tid`-zero-is-unresolved-but-`uid`/`gid`-zero-is-root
  inference, full and partial attribution mapping (the latter proving a
  lost name/image race still emits, never silently drops), and the one
  true no-attribution-at-all case returning `None`.
- `pipeline::dropped` -- `DroppedTracker`'s first-event-reports-the-whole-baseline
  behavior, steady-state deltas, and independent per-cgroup tracking.
- `pipeline` -- `Pipeline::handle` and `Pipeline::into_callback` proven
  end to end through a real `mpsc` channel with a stub attributor/tamper
  source, plus a sanity check that the sampled boot-time/wall-clock offset
  reconstructs a timestamp within 1s of actual wall time.
- `pipeline::sink` -- the `EventSink` impl for `mpsc::Sender<UpMessage>`
  tolerates a closed receiver without panicking.

37 new tests, all green, alongside the 17 pre-existing `bathyscaphe` tests
and the 45 from `bathyscaphe-common`/`bathyscaphe-proto` (54 total in the
`bathyscaphe` binary crate's own test binary; see the full `cargo test`
output this chunk recorded for the exact tally).

### Live enrichment smoke test -- PROVEN, resolved a real container

Per the build brief's mandate to attempt this and report precisely: it was
run, and it succeeded.

**Setup**: one throwaway container `bathyscaphe-itest-attrib-build`
(`rust:1-bookworm`, unprivileged, cleaned up after use), with
`/workspace` bind-mounted, `/sys/fs/cgroup` bind-mounted read-only
(**resolving to the real HOST cgroup tree**, not this environment's own
namespaced cgroup2 view -- bind-mount source paths in `docker run -v` are
resolved by the Docker daemon, which runs on the bare host, so this is the
same tree a real kernel hook would see `bpf_get_current_cgroup_id()`
against), and `/var/run/docker.sock` bind-mounted read-only.

**What ran**: `attribution::resolver::live_smoke::resolves_a_real_container_end_to_end`
(`#[ignore]`d by default, same convention as `probe::live_smoke`). It:

1. Starts a real `AttributionService` (the real `CgroupWatcher` walking
   and watching the host's actual `/sys/fs/cgroup`, the real
   `EnrichmentWatcher` connecting via `bollard::Docker::connect_with_podman_defaults`
   -- which fell back to the plain Docker socket on this Docker-only host
   -- and subscribing to `events()`).
2. Creates and starts a throwaway container named `bathyscaphe-itest-attrib`
   (`alpine:latest`, `sleep 60`) via a minimal raw HTTP-over-unix-socket
   client talking directly to the Docker Engine API (deliberately not
   `bollard`'s own container-lifecycle calls, since this test's job is to
   prove the *resolver*, not re-test `bollard`'s create/start API).
3. Independently walks the real `/sys/fs/cgroup` (via the same
   `classify_trailing_segment` the resolver itself uses) to find the cgroup
   directory whose container id matches the one just created, and takes
   its inode as `cgroup_id` -- exactly the value a kernel hook would have
   read via `bpf_get_current_cgroup_id()`.
4. Polls `resolver.resolve(cgroup_id)` until it returns a full
   `Attribution` (a short, bounded wait for the cgroup-side inotify watch
   and the enrichment-side `events()` stream to both catch up).
5. Asserts the resolved `container_id` matches the container actually
   created, the `runtime` is `Docker`, the `name` is
   `bathyscaphe-itest-attrib`, and the `image` is `alpine:latest`.
6. Removes the throwaway container and stops the `AttributionService`
   unconditionally (even on assertion failure, via a closure whose `Result`
   is asserted after cleanup runs).

**Result**: `test attribution::resolver::live_smoke::resolves_a_real_container_end_to_end
... ok`, finishing in 2.59s. This proves, against a real Docker socket and
a real host cgroup tree (245 directories on this host, walked in ~10ms):

- The regex-based trailing-segment classifier correctly identifies a real,
  live `docker-<hex>.scope` directory the kernel's own cgroup v2 unified
  hierarchy actually created.
- `bollard::Docker::connect_with_podman_defaults()` connects successfully
  on a Docker-only host with no Podman socket present (the documented
  final-fallback behavior).
- The bootstrap-then-`events()` enrichment path actually observes a
  container's `start` event and populates `name`/`image` from the event's
  `Actor.Attributes`, with no `inspect_container` fallback needed for this
  case.
- The full `resolve()` path -- cgroup-side lookup joined with
  enrichment-side lookup -- produces a complete, correct `Attribution` for
  a container this process only ever learned about through its own
  filesystem walk and its own Docker connection, end to end.

**A real bug this test caught and fixed**: the first run of this test hung
indefinitely. The cause was `CgroupWatcher::stop()` joining a background
thread blocked in `Inotify::read_events_blocking`, which has no timeout --
on a quiet moment with no cgroup churn (exactly what happened when the
test's raw HTTP client hit an early error and tried to tear the service
down), the watcher thread never wakes up on its own, so `handle.join()`
never returns. Fixed by switching `watch_loop` to the same bounded
`poll(2)`-then-non-blocking-`read_events` pattern
`probe::events::EventConsumer` already uses, with the same 250ms timeout
constant. This is not just a test-harness fix: the same hang would have
hit a real daemon's shutdown path on an idle host, so this was a genuine
correctness bug in the shipped code, not a test-only workaround.

**Cleanup**: `bathyscaphe-itest-attrib-build` was removed after the run. No
`bathyscaphe-itest-*` image was built (it ran directly off the public
`rust:1-bookworm` image). The test itself removes its own
`bathyscaphe-itest-attrib` container as its last step (in the success case)
or via the same cleanup path on assertion failure; a pre-run best-effort
removal also guards against a fixed container name colliding with a
previous aborted run. Confirmed absent after the run via `docker ps -a`.

## What is still deferred to later chunks

- **Attribution wired into a running daemon**: `attribution` and
  `pipeline` are fully unit- and live-tested in isolation (this chunk) but
  not yet called from `main()` -- see that file's module-level comment.
  The DAEMON build chunk (#6 in the crate layout's numbering, #7 in the
  master spec's build sequence) is what actually starts an
  `AttributionService`, builds a `Pipeline`, and hands its callback to
  `probe::EventConsumer::spawn` against a real, attached probe.
- **Rootless Podman, and Podman generally, against a real socket**: the
  live smoke test above ran on a Docker-only host (no Podman installed),
  so `bollard::Docker::connect_with_podman_defaults()`'s Podman branches
  and the `libpod-`/rootless cgroup path shapes are proven by the unit
  tests in `attribution::cgroup` (pure path-parsing, no socket needed) but
  not by a live run against an actual Podman daemon. Nothing about this
  chunk's design is Docker-specific, but this is an honest gap in what was
  actually exercised end to end, for lack of a Podman host in the build
  environment.

## What chunk #9 (DNS observation) proved

### Unprivileged, no kernel/bpffs/cgroup access required

`cargo test` inside the same `rust:1-bookworm` toolchain container:

- `bathyscaphe_common::dns` -- `DnsCapture`'s pinned 536-byte size and
  8-byte alignment, `captured()` bounding to `len` even with trailing
  non-zero garbage in `payload`, and clamping a corrupt oversized `len` to
  `DNS_CAPTURE_MAX`.
- `probe::dns` -- ring-buffer record decode round-trips a well-formed
  `DnsCapture` and rejects a short/oversized buffer, mirroring
  `probe::events`'s tests exactly.
- `dns::parse` -- `simple-dns`-based parsing of a hand-built A answer, an
  AAAA answer, multiple answers for one query, a CNAME-then-A chain
  (tagging the resolved address with the ORIGINAL query name, not the
  CNAME target), a CNAME with no further resolution (correctly yields no
  answers), a response with no question section (not attributable, `None`),
  and both empty and garbage input handled gracefully (`None`, never a
  panic).
- `dns::cache` -- `DomainCache`'s miss path, `Asserted` confidence within
  TTL, `Inferred` confidence past TTL but within the grace window, `None`
  past the grace window, per-container isolation, overwrite-on-re-record,
  and the opportunistic per-container sweep on `record()`.
- `pipeline::map` -- two new tests (`map_event_populates_domain_on_a_cache_hit`,
  `map_event_leaves_domain_null_on_a_cache_miss`) alongside the existing
  suite, all passing with the new `DomainLookupSource` parameter threaded
  through.
- `daemon::hello` -- `capabilities()` now asserts `dns_enrich` IS
  advertised, `enforce_fqdn`/`sni_enrich` are NOT.

180 tests in the `bathyscaphe` binary crate (up from 156), 20 in
`bathyscaphe-common`, 29 in `bathyscaphe-proto`, all green; 3 tests
`#[ignore]`d (the two pre-existing live smokes plus this chunk's new one).

### eBPF build: the stack-limit and verifier fights this chunk actually hit

Two distinct, non-obvious problems had to be solved before `dns_snoop`
would load at all, both worth recording precisely since they will recur
for anyone adding another large-record-producing eBPF program to this
codebase:

1. **536-byte `DnsCapture` blew the 512-byte eBPF stack frame limit.**
   The first draft built a whole `DnsCapture` value on the stack
   (`DnsCapture::zeroed_for(...)`) before copying it into the reserved
   `RingBuf` slot via `entry.write(capture)` -- `bpf-linker` failed with
   `LLVM issued diagnostic with error severity` / "Looks like the BPF
   stack limit is exceeded." Fixed by `DnsCapture::init_at` (a `bathyscaphe-common`
   addition): writes every field directly through a raw pointer into the
   ALREADY-RESERVED `RingBuf` memory (`entry.as_mut_ptr()`), never
   materializing a `Self`-sized value on the stack at all.
2. **`bpf_skb_load_bytes`'s length argument rejected any computed,
   possibly-zero range ("R4 invalid zero-sized read").** The natural next
   draft called `SkBuffContext::load_bytes()` (aya's own convenience
   wrapper, which internally computes `(skb_len - offset).min(dst.len())`)
   or, when that was bypassed in favor of a hand-rolled equivalent, an
   explicit `>=` early-return branch immediately before a direct
   `bpf_skb_load_bytes()` call. Both were rejected by the verifier on this
   host's real kernel (6.8.0-136): the length argument's tracked range
   could not be proven to exclude zero by the time it reached the call,
   in one case because a `u32` subtraction's wraparound-truncation codegen
   (`<<32`/`>>32`) reset the tracked lower bound to 0, in another because
   `u64` arithmetic's signed-range tracking came out unrelated to the
   unsigned bound the preceding branch had established. **Fixed** by
   abandoning computed lengths entirely for this one call: a `try_tier!`
   macro expands to several `bpf_skb_load_bytes` calls with LITERAL,
   compile-time lengths (512, 384, 256, 128, 64, 32 bytes), tried largest
   first, keeping whichever succeeds. A literal's verifier-tracked range
   is exactly that one value -- trivially nonzero, no arithmetic involved
   -- so this sidesteps the whole class of problem. The UDP header's own
   length field (read separately, a small fixed-size load) is what keeps
   `DnsCapture::len` accurate to the real payload size despite the tier
   granularity, rather than exposing tier-padding past the true boundary.

### Privileged smoke test -- PARTIALLY PROVEN, precisely

Per the build brief's mandate to attempt this and report precisely.

**Setup**: two throwaway containers from `rust:1-bookworm`, cleaned up
after use:
- `bathyscaphe-itest-dns` (unprivileged): built the workspace per
  `docs/BUILDING.md`.
- `bathyscaphe-itest-dns-priv` (`docker run --privileged --cgroupns=host
  --pid=host`, same image, `/workspace` and `/var/run/docker.sock`
  bind-mounted, `mount -t bpf bpf /sys/fs/bpf`): host kernel 6.8.0-136.
  **`--cgroupns=host` was required** -- without it, this container's own
  `/sys/fs/cgroup` reflects only ITS OWN private cgroup namespace slice
  (a Docker 20.10+ default), which does not contain the sibling
  containers this test creates via the bind-mounted Docker socket; with
  it, the container sees the real host-wide cgroup v2 tree, exactly as
  `bathy_attribution.md` assumes a privileged agent does.

**What ran**: `probe::dns::live_smoke::dns_snoop_captures_and_parses_a_real_containers_dns_answer`
(`#[ignore]`d, invoked with `--ignored --test-threads=1`). It creates a
throwaway user-defined bridge network and an `alpine` container on it
(`nslookup example.com`), attaches the real probe (all six programs,
`dns_snoop` included) to that container's real cgroup, and drains
`DNS_EVENTS` for up to 12 seconds looking for a capture attributed to
that exact cgroup that parses to a usable A/AAAA answer.

**Result**: `test probe::dns::live_smoke::dns_snoop_captures_and_parses_a_real_containers_dns_answer
... ok`, run three times (including alongside both other live-smoke tests
in the same invocation, all three green together). What it decisively
proved, without qualification:

- **The verifier ACCEPTS `dns_snoop`** -- `Probe::load_or_reopen` (a
  fresh load: `aya::Ebpf::load`, `.load()` every one of the six programs
  including `dns_snoop`, pin, reopen) succeeded every time, on a real
  6.8.0-136 kernel, with the literal-tier `bpf_skb_load_bytes` fix in
  place. No rejection to report because there was none.
- **`attach_container` succeeds** against a real, live container's cgroup
  for all six programs together, `dns_snoop` alongside
  connect4/6/sendmsg4/6/sock_create -- the existing
  `probe::live_smoke::load_attach_pin_reopen_unpin_round_trip` test
  (unmodified in behavior, just now attaching/pinning/reopening one more
  program) also still passes, proving the six-program pin layout doesn't
  regress the fail-closed lifecycle chunk #5 proved.
- **`dns_snoop` captures genuine, well-formed DNS response bytes off real
  traffic.** Raw captured payloads from this run (`f2 93 81 a0 00 01 00
  02 00 00 00 00 07 65 78 61 6d 70 6c 65 03 63 6f 6d 00 00 1c 00 01 ...`)
  decode by hand as: transaction id, flags `0x81a0` (response, recursion
  available), 1 question, 2 answers, the literal ASCII labels `example`
  `com`, an AAAA query (`0x001c`) -- unmistakably real DNS traffic
  triggered by the test container's own `nslookup example.com`.

**What did NOT fully prove out on this specific host, and precisely
why**: the capture's `cgroup_id` did not match the querying container's
own cgroup -- it matched `docker.service`'s cgroup (when the container
used Docker's embedded resolver at `127.0.0.11` on a user-defined
network) or `tailscaled.service`'s cgroup (when it used this host's
Tailscale-intercepted external resolver on the default bridge network),
in both cases regardless of which the test tried. Investigated directly
(raw bytes dumped, cgroup inodes cross-referenced via `find -inum`
against `/sys/fs/cgroup`) rather than assumed: `bpf_get_current_cgroup_id()`
reports the cgroup of whichever TASK the kernel is executing AT THE
MOMENT the ingress hook runs, and on this host, BOTH of its DNS-answering
paths (Docker's embedded resolver, and the Tailscale client's
MagicDNS interception) appear to construct and inject their reply packet
into the container's netns synchronously from their OWN process's task
context, rather than the packet crossing a real NIC/veth boundary into a
context switch onto the receiving container's own process. This is a
property of how a cgroup-scoped eBPF hook interacts with these two
specific injected-delivery mechanisms, not a defect in `dns_snoop`'s
capture logic -- see `docs/DNS.md`'s gaps list for the general statement.
Also observed: the captured length topped out at the 64-byte tier for
both queries in this run (never 128+), meaning the underlying `sk_buff`
for these specific injected replies really is that short -- an accurate
observation of a real, small buffer, not a capture bug (a response
arriving over a real NIC path would have a full-size `sk_buff` matching
its real IP length, which the same tiered capture already handles
correctly whenever a larger tier's `bpf_skb_load_bytes` call succeeds).

The test itself reports this outcome honestly rather than papering over
it: it hard-fails only if `attach_container` errors (a verifier problem)
or if `dns_snoop` captures NOTHING at all (a real capture-logic defect);
short of that, an exact-cgroup miss is reported as a **PARTIAL proof**
with the full byte-level evidence printed, and the test still passes.
**Deferred to chunk #12's integration suite**: a fully-scoped exact-cgroup
proof, either on a host without a DNS-intercepting VPN client and against
an EXTERNAL resolver reached over a real NIC path, or accepting
`docker.service`'s cgroup as the documented expected attribution for
Docker's own embedded resolver specifically.

**Cleanup**: both containers, the throwaway `bathyscaphe-itest-dns-smoke`
container, and the throwaway `bathyscaphe-itest-dns-net` network were
removed after each run (the test removes its own container/network as
part of its own teardown in addition to the outer container removal).
Confirmed absent via `docker ps -a` / `docker network ls` after the final
run.

## What chunk #10 (query/response correlation + FQDN enforcement) proved

### Unprivileged, no kernel/bpffs/cgroup access required

`cargo test` inside the same `rust:1-bookworm` toolchain container:

- `bathyscaphe_common::dns` -- `DnsCapture` gained a `dst_port` field with
  the struct's pinned size UNCHANGED (536 bytes, `_pad` shrunk from 6 to 4
  bytes to make room); `DnsQueryCapture`'s own pinned size (24 bytes) and
  alignment, and its trivial by-value constructor (small enough to skip
  `DnsCapture::init_at`'s raw-pointer pattern entirely).
- `probe::dns_query` -- ring-buffer record decode round-trips a
  well-formed `DnsQueryCapture` and rejects a short/oversized buffer,
  mirroring `probe::dns`'s tests exactly.
- `dns::pending` -- `PendingQueryTable`: a fresh query correlates its
  response; wrong txid, wrong port, and past-TTL responses all miss;
  a response exactly at the TTL boundary still correlates; multiple
  responses to one query all correlate (no removal-on-first-match); the
  table sweeps aged-out entries on every write. The key scenario:
  `correlation_recovers_the_querying_containers_cgroup_even_when_the_responses_own_cgroup_differs`
  simulates the Docker-embedded-DNS case directly (a query recorded under
  a "container" cgroup id, a response's own cgroup id set to a
  DIFFERENT, "docker.service"-standing-in value) and asserts correlation
  returns the CORRECT (container's) id, not the response's own -- the
  precise logical claim the privileged live smoke test below re-proves
  against a real kernel.
- `dns::patterns` -- `NamePatternStore`/`pattern_matches`: exact-name
  match, wildcard multi-label match (`*.github.com` matching BOTH
  `docs.github.com` and `raw.objects.github.com`), a wildcard never
  matching its own bare apex, an unrelated-suffix non-match, a
  bare-wildcard-with-no-suffix matching nothing, full-snapshot
  replacement semantics, per-container isolation, and that a `deny`
  pattern is stored but never returned by `first_matching_allow`.
- `dns::mod` -- `capture_callback`'s correlation wiring: a captured
  response with the WRONG `cgroup_id` of its own gets attributed to the
  CORRELATED (correct) cgroup id when a matching query was recorded
  first (proving the whole `dns_snoop` capture -> correlate -> cache
  pipeline, not just the table in isolation), and falls back to the
  capture's own `cgroup_id` (with `correlated: false`) when no query
  ever matched. `query_capture_callback` feeds the pending table
  correctly.
- `daemon::compile` -- a well-formed `type: "name"` rule is now ACTIVE
  (not inert), carries its port/proto constraint through to the compiled
  `CompiledNamePattern`, is normalized to lowercase with no trailing dot,
  and a name rule carrying an unrecognized field is still the one
  ignore-unknown carve-out (inert and counted). A `deny`-action name rule
  is registered (not dropped, not miscounted as inert).
- `daemon::apply` -- `apply_policy` registers a container's compiled name
  patterns into `NamePatternStore` and reports `inert_rules: 0` for a
  well-formed name rule; a re-push with NO name rules clears the prior
  registration wholesale (never leaves a stale pattern behind);
  `apply_release`/`apply_release_all` clear a container's registered
  patterns too. The correctness fix:
  `make_before_break_never_removes_a_dns_sourced_host_route` proves a
  DNS-derived (`source: Dns`) host route inserted directly against the
  probe survives a SECOND static `policy` re-push that mentions neither
  it nor the static rule that originally shared its container -- only the
  stale STATIC entry is removed, exactly the make-before-break diff fix
  this chunk made.
- `daemon::fqdn` -- `on_dns_answer`: inserts an unconstrained host route
  on a pattern match with no port/proto constraint; does nothing on a
  non-match; applies a pattern's port/proto constraint as a `PortRule`
  with `cidr_default_action: Deny` (so only the constrained port/proto is
  actually open on that specific host route); computes the SAME
  `expires_at_ns` `DomainCache`'s own formula would for the identical
  `(ttl_secs, ktime_ns)` pair. `NameUnresolvedBlockWatcher`: fires the
  throttled `policy.name_unresolved_block` record on a deny with no
  domain enrichment when the container has an active allow name pattern;
  stays quiet when the deny DID carry domain enrichment (a resolved name
  still denied by policy is not the "unresolved" signal), when the
  container has no active name rule at all, and on a non-deny verdict.
- `daemon::hello` -- `capabilities()` now asserts `enforce_fqdn` IS
  advertised alongside `dns_enrich`, `sni_enrich` still is not.
- `daemon::security` -- `name_unresolved_block_record` carries `ERROR`
  severity, the new reason code, and `dst.addr`/`dst.port` attributes with
  no `domain` attribute (the record's entire point is that none was ever
  observed); the shared-throttle tests were ported from the retired
  `unenforceable_name_record` onto the new builder with no change in
  throttling behavior.
- `daemon::stats` -- `tick` now takes an explicit `now_boottime_ns` and
  calls the `POLICY` TTL reaper at the top of every tick;
  `a_tick_reaps_an_expired_policy_entry` seeds one never-expiring and one
  short-lived (`RuleSource::Dns`) policy entry, ticks with a synthetic
  "now" past the short-lived entry's expiry, and asserts only that one
  entry was removed.
- `probe::policy` -- `PolicyStore::container_keys` restructured to track
  each key's `RuleSource` alongside it (a `HashMap<TrackedKey, u8>`
  rather than a `HashSet<TrackedKey>`); `tracked_keys_by_source` is the
  new query the make-before-break fix depends on.

226 tests in the `bathyscaphe` binary crate (up from 180), 23 in
`bathyscaphe-common` (up from 20), 29 in `bathyscaphe-proto` (unchanged --
no wire shape changed, only a new reason-code string constant), all
green; 4 tests `#[ignore]`d (the three pre-existing live smokes plus this
chunk's new one).

### eBPF build: verifier acceptance, and the fixed-size-load reuse from chunk #9

`dns_query_snoop` (the 7th program) needed NONE of chunk #9's tiered
literal-length `bpf_skb_load_bytes` machinery: every read it performs is a
small, FIXED-size load at a fixed offset (the IP version nibble, IHL,
protocol byte, the destination address for the Docker-embedded-DNS
special case, both UDP ports, and the two-byte DNS transaction id) --
`SkBuffContext::load::<T>()`'s ordinary safe wrapper handles all of these
with no computed-length argument anywhere, so the entire class of
verifier problem chunk #9 fought through never arose here. `DnsQueryCapture`
(24 bytes) is built by value on the stack and written into its reserved
`RingBuf` slot with a plain `entry.write(...)`, the same shape
`bathyscaphe-ebpf::decide::emit_event` already uses for `Event` -- no
`init_at`-style raw-pointer construction needed, since 24 bytes is
nowhere near the eBPF stack's 512-byte limit. `readelf -s` on the built
object confirms both `dns_snoop` and `dns_query_snoop` compile to
DISTINCT `FUNC` symbols living in the SAME `cgroup/skb` ELF section (aya's
`#[cgroup_skb]` macro does not encode the attach direction into the
section name, since direction is chosen at userspace attach time, not
load time) -- `aya::Ebpf::program_mut("dns_query_snoop")` resolves programs
by symbol name regardless, so this is a normal, harmless ELF layout
detail, not a collision.

### Privileged smoke test -- FULL PROOF, precisely

Per the build brief's mandate to attempt this and report precisely, AND
to investigate the empirical claim rather than assume it.

**Setup**: `bathyscaphe-itest-fqdn-build` (unprivileged, `rust:1-bookworm`,
`/workspace` bind-mounted): built the workspace per
`docs/BUILDING.md`. `bathyscaphe-itest-fqdn-priv` (`docker run --privileged
--cgroupns=host --pid=host`, same image, the same `/workspace` bind
mount so the already-built test binary could run directly, plus
`/var/run/docker.sock` bind-mounted, `mount -t bpf bpf /sys/fs/bpf`): host
kernel 6.8.0-136. `--cgroupns=host` required for the identical reason
chunk #9's own privileged test documents.

**What ran**: `probe::dns_query::live_smoke::query_response_correlation_recovers_the_correct_container_cgroup`
(`#[ignore]`d, invoked with `--ignored --test-threads=1`). It creates a
throwaway user-defined bridge network (`bathyscaphe-itest-fqdn-net`) and
an `alpine` container (`bathyscaphe-itest-fqdn-smoke`, running `sleep 1 &&
nslookup example.com; sleep 4`) on it, attaches the real probe (all
SEVEN programs) to that container's real cgroup, drains BOTH the
`DNS_QUERIES` and `DNS_EVENTS` rings concurrently for up to 12 seconds,
then:

1. Asserts every captured QUERY's `cgroup_id` equals the container's own
   real cgroup id (the foundational claim).
2. Runs the SAME `PendingQueryTable` production code (not a test-only
   reimplementation) against the captured queries and answers.
3. Asserts every captured ANSWER, once correlated, resolves to the
   container's cgroup id.

**A real, unanticipated finding, investigated and fixed before the proof
succeeded**: the FIRST run of this test failed with "`dns_query_snoop`
captured NOTHING at all" -- a genuine capture-logic gap, not a tolerated
confound (unlike chunk #9's exact-cgroup-match caveat, this one hard-fails
the test by design). Rather than accept a `#[ignore]`-worthy shrug, this
was investigated directly: a temporary diagnostic build removed the
`dst_port == 53` filter entirely and logged every captured egress UDP
datagram's ports regardless of value. Run three times against fresh
containers, it showed the query's destination port AT THE EGRESS HOOK was
a random high port every time (55561, then 55508, then 48204 -- never
53), while the query's source port exactly matched the following
response's destination port in every run (proving these really were the
DNS query/response pair). The cause: Docker's embedded resolver at
`127.0.0.11` is reached via a per-network-namespace iptables `DNAT` rule
that rewrites the destination PORT (never the address) to an internal,
randomly-allocated port before the packet reaches the `cgroup_skb`
EGRESS hook (which fires after `LOCAL_OUT` netfilter NAT processing) --
see `bathyscaphe-ebpf::dns_query`'s module doc and `docs/DNS.md` for the
full account. **Fixed** by matching EITHER port 53 OR a destination
address of `127.0.0.11` (NAT-invariant, since the DNAT rule only ever
rewrites the port); re-run after the fix, the test passed cleanly, three
times in a row (once standalone, twice more alongside every other
`live_smoke` test in the same invocation, all four green together with no
interference).

**Result, exactly as printed by the (non-diagnostic) passing run**:

```
fqdn live_smoke: 2 queries captured; cgroup_ids 000000000005b396 (container's real cgroup is 000000000005b396) -- query_cgroup_matched_container=true
fqdn live_smoke: answer txid=2868 dst_port=45647 response's own cgroup_id=0000000000002986 (matched container: false) correlated cgroup_id=Some(373654) (matched container: true)
fqdn live_smoke: answer txid=2869 dst_port=45647 response's own cgroup_id=0000000000002986 (matched container: false) correlated cgroup_id=Some(373654) (matched container: true)
fqdn live_smoke: FULL PROOF -- egress query snoop correctly attributed to the container's own cgroup in every case; response's OWN cgroup attribution matched the container in zero case(s) (chunk #9's docker.service misattribution reproduced exactly as chunk #9 documented); correlation recovered the correct container cgroup in every case regardless
```

This decisively proves, without qualification, on a real 6.8.0-136 kernel
against a real Docker container on a real user-defined network:

- The verifier ACCEPTS all seven programs, `attach_container` succeeds
  for the full set.
- The egress query snoop's cgroup attribution is CORRECT in every
  observed case -- the entire premise the correlation design rests on.
- The response's OWN cgroup attribution is WRONG in every observed case
  (`docker.service`'s cgroup, not the container's) -- chunk #9's finding,
  reproduced on demand.
- Query/response correlation RECOVERS THE CORRECT CGROUP in every
  observed case, overriding the response's own wrong attribution.

Also re-run alongside the three PRE-EXISTING privileged live-smoke tests
(`probe::live_smoke::load_attach_pin_reopen_unpin_round_trip`,
`probe::dns::live_smoke::dns_snoop_captures_and_parses_a_real_containers_dns_answer`,
`attribution::resolver::live_smoke::resolves_a_real_container_end_to_end`)
in one invocation: all four passed together, confirming the new 7th
program and the `DnsCapture::dst_port` field addition did not regress any
prior chunk's proven behavior (chunk #9's own test still reports its
documented PARTIAL proof for the exact-cgroup ingress-only case, unchanged).

**What this does NOT prove** (honestly deferred): a resolver reached over
a real external NIC path rather than Docker's embedded loopback resolver
was not exercised on this host (chunk #9 already noted this same gap for
the response side); TCP-fallback DNS correlation; a second, concurrently
querying container on the same host (to rule out any cross-container
`(txid, port)` collision in practice, beyond the theoretical analysis in
`dns::pending`'s module doc). Deferred to chunk #12's integration suite.

**Cleanup**: `bathyscaphe-itest-fqdn-build` and `bathyscaphe-itest-fqdn-priv`
were removed after use. The test's own throwaway container
(`bathyscaphe-itest-fqdn-smoke`) and network (`bathyscaphe-itest-fqdn-net`)
were removed as part of its own teardown on every run; confirmed absent
via the Docker API afterward. `/sys/fs/bpf` confirmed empty after the
final run (the test's own `unpin_all` call).

## What chunk #11 (trusted-resolver enforcement + name-based deny) proved

### Unprivileged, no kernel/bpffs/cgroup access required

- `dns::trust::tests` (`bathyscaphe`'s own `dns/trust.rs`):
  `parse_resolv_conf_nameservers` against a range of
  `resolv.conf`-shaped text (comments, unrelated directives, IPv6
  nameservers, a malformed address skipped rather than fatal), and
  `TrustedResolvers`'s default-set construction, `with_extra`, and the
  explicit "an empty set trusts nothing, never trust-everything" property.
- `dns::cache::tests`: the new `trusted` bit on `DomainCache::record`
  floors confidence at `Inferred` regardless of TTL freshness, including
  the "overwriting a trusted record with an untrusted one drops the
  confidence" ordering case.
- `dns::tests::capture_callback_marks_an_answer_from_an_untrusted_source_as_untrusted`:
  `capture_callback`'s new `trusted_resolvers` parameter actually gates
  the bit forwarded to both the cache and `AttributedAnswer`, using a
  hand-built real DNS response payload exactly like chunk #10's own
  correlation tests.
- `daemon::fqdn::tests` (ten new/updated tests): the full enforcement gate
  -- an untrusted answer never calls `ProbeApi::set_policy` even on a
  matching allow pattern; the `dns.untrusted_answer` loud record fires
  exactly once for that case and stays quiet on a non-matching or
  deny-only untrusted answer; a trusted answer matching an active `Deny`
  pattern inserts a deny host route (unconstrained and port/proto-scoped
  variants both covered); deny wins over an allow pattern matching the
  same answer, inserting exactly one host route, never two.
- `dns::patterns::tests`: `first_matching_deny` (mirrors
  `first_matching_allow` exactly) plus a test proving a name can match
  both an allow and a deny pattern independently, leaving the winner
  decision to `daemon::fqdn::on_dns_answer`.
- `daemon::security::tests::dns_untrusted_answer_record_is_warning_severity_and_carries_the_reason`:
  the new record builder's shape (severity, `reason`, `resolver.addr`,
  `domain` attributes).
- `cli::tests` (`run_parses_repeated_trusted_resolver_flags`,
  `run_rejects_a_malformed_trusted_resolver_address`,
  `run_defaults_to_no_extra_trusted_resolvers`) and `cli::run_cmd::tests`
  (`build_config_carries_the_given_trusted_resolvers_through_verbatim`):
  the `--trusted-resolver` flag parses, repeats, rejects a malformed
  address, and threads through to `DaemonConfig` unmodified.
- `bathyscaphe-common::dns::tests`: `DnsCapture`'s new pinned size (552
  bytes: the original 536 plus the 16-byte `src_addr` field) and that
  `src_addr` round-trips through `zeroed_for`/direct field assignment
  exactly like `dst_port` already did.
- **The pre-existing bug this chunk's build brief asked to fix** (Part C):
  `daemon::apply::tests::make_before_break_diff_removes_stale_keys_not_in_the_new_snapshot`
  was missing a `probe.seed_path(...)` call before its first
  `apply_policy`. Without it, `MockProbe::attach_container` invents its
  own cgroup id for the unseeded path (rather than the id the test's own
  `lookup_with_one_container` claims), so the test's SECOND
  `apply_policy` call re-attempts an attach under a path that now maps to
  an ALREADY-attached mock id, `MockProbe::attach_container` returns
  `Err("already attached")`, and the second `apply_policy` returns
  `PolicyAckStatus::Error` WITHOUT ever calling `apply_make_before_break`
  at all. The test's two assertions then passed by coincidence rather than
  by exercising the diff: the length check (`== 2`) matched the STALE
  first-generation entry count (also 2), and the ordering check's
  `|| first_remove.is_none()` clause short-circuited true because no
  `RemovePolicyKey` call had ever happened. A SECOND, independent bug
  surfaced once the missing `seed_path` was added and the diff actually
  ran for the first time: the ordering assertion's comparison itself was
  backwards (`last_set > first_remove` instead of `last_set < first_remove`
  for "insert happens before remove"), which the missing-seed_path bug had
  been silently protecting from ever being exercised. Both are fixed
  together; the test now asserts the actual applied ack status
  (`PolicyAckStatus::Applied`) on both pushes, checks the SPECIFIC surviving
  and removed keys (not just a count), and a `first_remove.is_some()`
  assertion that fails loudly if the diff ever again stops running.

### eBPF build: verifier acceptance of the new source-address reads

`bathyscaphe-ebpf::dns::try_dns_snoop_v4`/`try_dns_snoop_v6` gained two new
fixed-offset loads (IPv4 header bytes 12-15, IPv6 fixed-header bytes 8-23)
threaded through to `capture_if_dns_response`'s new `src_addr: [u8; 16]`
parameter, written into the `DnsCapture` record alongside `dst_port`. Built
clean via the same `bathyscaphe-itest-harden` container this chunk's other
work used (`rust:1-bookworm`, nightly + `rust-src`, `bpf-linker` 0.11.0 per
`docs/BUILDING.md`); `cargo build` succeeded with the usual harmless
warnings only, and `readelf`-level section inspection was not re-run since
chunk #9/#10 already established the toolchain proves this reliably and
the privileged smoke test below is the more decisive proof for THIS
chunk's specific change (the verifier accepting the two new loads is a
precondition for `attach_container` succeeding at all, which the smoke
test below hard-fails on if it doesn't).

### Privileged smoke test -- FULL PROOF, precisely

**What ran**: `probe::dns::live_smoke::dns_snoop_captures_the_responses_own_source_address`
(`#[ignore]`d by default, same convention as every other `live_smoke`
test), run inside `bathyscaphe-itest-harden` with `--privileged
--cgroupns=host` and `/var/run/docker.sock` bind-mounted, against a real
Docker container (`bathyscaphe-itest-dns-src-addr-smoke`, alpine, looping
`nslookup example.com` every second for 10s) on a real user-defined bridge
network (`bathyscaphe-itest-dns-net`, the same network chunk #9's own test
uses -- only a real user-defined network gets Docker's embedded resolver),
kernel 6.8.0-136 (matching the host). The test loops `nslookup` repeatedly
(unlike chunk #9's single-shot query) specifically to give
`attach_container` a comfortable window to land before at least one query
fires, avoiding a startup-race false negative.

Deliberately narrow success criterion, matching every other `live_smoke`
test's "do not rabbit-hole" posture: this test does NOT require
`parse_dns_response` to succeed on the captured payload (see "what this
run additionally found" below for why) -- only that `dns_snoop` captures
ONE real item with a nonzero length, from which `src_addr` is read.

**Result**: `test probe::dns::live_smoke::dns_snoop_captures_the_responses_own_source_address
... ok`, with:

```
dns live_smoke (src_addr): full proof -- captured src_addr 127.0.0.11 is Docker's embedded resolver, and the default trusted-resolver set trusts it, exactly as docs/DNS.md describes
```

This decisively proves, on a real kernel against a real container's real
DNS traffic:

- The verifier ACCEPTS `dns_snoop`'s two new source-address reads for both
  the IPv4 and IPv6 paths (only the IPv4 path was exercised live here, but
  both compiled and passed the SAME verifier pass in the eBPF build step
  above), and `attach_container` succeeds.
- `DnsCapture::src_addr` captures the REAL responding resolver's address,
  correctly RFC-4291-embedded (`00*10, ff, ff, 7f, 00, 00, 0b` observed
  raw, unmapping to `127.0.0.11` exactly).
- `TrustedResolvers::default_set_from` (the built-in default, no
  `--trusted-resolver` needed) actually trusts that captured address --
  end to end, the default configuration this chunk ships would have
  seeded enforcement from this exact real answer, had a name rule been
  registered for it.

**What this run additionally found (an orthogonal, pre-existing
characteristic, not a chunk #11 defect)**: every captured item in this
run's raw traffic had its payload truncated at the 32- or 64-byte tier
(`bathyscaphe-ebpf::dns`'s tiered `bpf_skb_load_bytes` load, chunk #9),
short of the full two-answer (A+CNAME or dual-AAAA) response `example.com`
actually returns on this network path -- `payload_len_hint` (the UDP
header's own trusted length) exceeded every tier that successfully loaded
except the smallest ones, because this specific container/network path's
packets carry no trailing padding beyond their real, modest payload size,
and no tier between 65 and 127 bytes exists. `parse_dns_response`
therefore returned `None` for every captured item in this run, even though
`dns_snoop` and `src_addr` capture both worked perfectly. This is
`bathyscaphe-ebpf::dns`'s own documented "tier-granular length, not exact"
characteristic (chunk #9, `docs/DNS.md`) manifesting for a response size
that happens to fall in a gap between adjacent tiers -- unrelated to
`src_addr`, not something chunk #11 introduced or needs to fix, and worth
a future chunk narrowing the tier ladder (e.g. adding a 96-byte tier)
if this proves common in practice. Recorded here rather than silently
worked around, per this document's own honesty mandate.

**Cleanup**: `bathyscaphe-itest-harden` was removed after use, along with
the named `bathyscaphe-itest-cargo-registry` volume it used to cache the
crates.io registry across rebuilds within the same session. The test's own
throwaway container (`bathyscaphe-itest-dns-src-addr-smoke`) and network
(`bathyscaphe-itest-dns-net`) were removed as part of its own teardown;
confirmed absent via the Docker API afterward. `/sys/fs/bpf` confirmed
empty after the final run (the test's own `unpin_all` call).

### What is still deferred to a later chunk

A full end-to-end integration proof that a container configured to use an
UNTRUSTED resolver (a custom `--dns` flag pointing at a resolver outside
the default set, with a real `policy` directive pushed through
`daemon::apply::apply_policy` and a real connect attempt afterward)
genuinely fails to have its allow-map seeded, and that the connect is
denied in `mode: block`, was judged out of scope for this chunk's
timeboxed privileged check -- it needs the FULL daemon wired up as a
subprocess speaking the NDJSON protocol (hello/start/policy/directive
loop), not just a loaded probe, which is next-chunk integration-harness
territory per the build brief's own "full integration is the next chunk"
scoping. The trust-gating LOGIC itself (an untrusted answer never reaches
`ProbeApi::set_policy`) is already fully proven without a kernel by
`daemon::fqdn::tests::on_dns_answer_never_seeds_policy_from_an_untrusted_answer`;
what remains unproven live is only the plumbing from "a container's actual
DNS traffic" through to "the daemon's directive loop sees it," which
chunk #10's own query/response correlation live-smoke test already proves
for the trusted case.

## What chunk #12 (DNS capture correctness fix) proved

Fixes the truncation bug chunk #9's own tiered `bpf_skb_load_bytes`
capture carried from the start (documented plainly at the time, in this
file's own chunk #9 and #11 sections above): a response whose true length
fell strictly between two adjacent literal tiers was captured at the next
SMALLER tier, silently truncating it, which then failed to parse in
userspace entirely. Observed live in production terms, not just in a
test: an intermittent over-block of legitimate name-allowed traffic,
traced back to a genuine ~90-100-byte DNS response landing between the
64- and 128-byte tiers. Full technical account (the clamp-then-mask
verifier-safe idiom, the cap decision, the tolerant userspace parser) is
in `docs/DNS.md`'s "Build chunk #12" section; this section is the test
inventory and exact tallies.

### Unprivileged, no kernel/bpffs/cgroup access required

`cargo test` inside the same `rust:1-bookworm` toolchain container per
`docs/BUILDING.md`:

- `dns::parse::tests` gained four new tests:
  `a_response_between_the_old_64_and_128_byte_tiers_parses_in_full` and
  `a_multi_answer_response_between_the_old_384_and_512_byte_tiers_parses_in_full`
  are the userspace-level regression guards for the exact live bug (a
  fixture deliberately sized into each old tier gap, with a self-check
  `assert!` pinning it there, must parse completely given a FULL,
  untruncated capture -- proving the userspace side is ready for what
  chunk #12's eBPF fix now actually produces; the live smoke test below
  proves the kernel side produces it).
  `a_response_truncated_mid_record_recovers_the_complete_answers_that_fit`
  and `a_response_truncated_before_any_complete_answer_recovers_nothing`
  exercise the new `recover_capped_answers` tolerant path directly: a
  3-answer response cut partway through its 3rd record recovers exactly
  the first 2 complete answers (with a sanity assertion that `simple-dns`
  really does reject the truncated buffer outright first, otherwise the
  test would not be exercising the tolerant path at all); a cut before
  even the first answer completes recovers nothing, not a panic.
- No `bathyscaphe-common` or `bathyscaphe-proto` changes this chunk --
  `DnsCapture`'s wire shape is unchanged (still 552 bytes; only the
  KERNEL-side logic that decides how many of its `payload` bytes to fill
  changed, not the struct itself), and no protocol field changed either.

265 tests in the `bathyscaphe` binary crate (up from 261 pre-chunk-#12,
+4 new), 25 in `bathyscaphe-common` (unchanged), 29 in `bathyscaphe-proto`
(unchanged), all green; 6 `#[ignore]`d (the five pre-existing live smokes
plus this chunk's new one).

### eBPF build: the verifier-safe idiom replacing the tier ladder

`bathyscaphe-ebpf::dns::capture_if_dns_response` no longer contains the
`try_tier!` macro or any literal-length ladder at all: a SINGLE
`bpf_skb_load_bytes` call now requests a length computed as
`((capped - 1) & (DNS_CAPTURE_MAX - 1)) + 1`, where `capped` is the UDP
header's own honest length clamped to `DNS_CAPTURE_MAX` via a plain `if`/
`else`. Built clean via a fresh `bathyscaphe-itest-dnsfix-build` container
(`rust:1-bookworm`, nightly + `rust-src`, `bpf-linker` 0.11.0, identical
toolchain steps to every prior chunk's own proof) -- `cargo build`
succeeded with only the pre-existing harmless dead-code warnings, and
`readelf -S` on the embedded object still shows the `cgroup/skb` section
(the same section `dns_snoop` and `dns_query_snoop` share, per chunk
#10's own account) present and correctly sized. Compile-time acceptance
by `bpf-linker` is necessary but not sufficient proof the KERNEL verifier
accepts the new length computation -- that is what the privileged smoke
test below actually decides.

### Privileged smoke test -- FULL PROOF, precisely

Full account (setup, exact printed output, and what each of the four
tested sizes decisively proves) is in `docs/DNS.md`'s "Build chunk #12"
section, "Privileged smoke test" subsection -- reproduced here only as
the tally this document's own convention keeps:

**Setup**: `bathyscaphe-itest-dnsfix-build` (unprivileged, `rust:1-bookworm`,
`/workspace` bind-mounted): built the workspace and the test binary.
`bathyscaphe-itest-dnsfix-priv` (`docker run --privileged --cgroupns=host
--pid=host`, same image, the same `/workspace` bind mount so the
already-built test binary could run directly, `/var/run/docker.sock`
bind-mounted, `mount -t bpf bpf /sys/fs/bpf`): host kernel 6.8.0-136.
Deliberately does NOT go through a Docker container for the DNS traffic
itself (see `docs/DNS.md` for why exact byte-length control ruled that
out) -- this process was moved into a fresh cgroup v2 directory instead,
with the real probe (all seven programs) attached to it, and two loopback
UDP sockets exchanging hand-built DNS response payloads of chosen sizes.

**What ran**:
`probe::dns::live_smoke::dns_snoop_captures_the_exact_length_across_varying_sizes_including_the_old_tier_gap`
(`#[ignore]`d, invoked with `--ignored --test-threads=1`).

**Result**: `... ok`, with every one of four sizes captured at its exact
expected length (46, 74, 467 bytes captured in full; a 653-byte
over-cap case captured truncated exactly at the 512-byte cap) and parsed
correctly (1, 1, 14, and 15 of 20 answers respectively -- the last being
exactly how many complete records fit within the cap-truncated bytes).
The 74-byte and 467-byte cases are the direct regression proof: both were
deliberately sized into the OLD 64/128 and 384/512 tier gaps respectively
(self-checked by the test's own `assert!`s), and both are now captured at
their own exact length rather than truncated to the smaller tier.

Re-run alongside all four PRE-EXISTING privileged live-smoke tests
(`probe::live_smoke::load_attach_pin_reopen_unpin_round_trip`,
`probe::dns::live_smoke::dns_snoop_captures_and_parses_a_real_containers_dns_answer`,
`probe::dns::live_smoke::dns_snoop_captures_the_responses_own_source_address`,
`probe::dns_query::live_smoke::query_response_correlation_recovers_the_correct_container_cgroup`,
`attribution::resolver::live_smoke::resolves_a_real_container_end_to_end`)
in one invocation: all six passed together, confirming the eBPF capture
change didn't regress attach/pin lifecycle, source-address capture, or
query/response correlation. A genuine bonus finding: chunk #9's own real
`nslookup`-driven test, in this same run, reported an 85-byte capture --
that scenario had historically shown 32/64-byte tier-truncated captures
in this file's own chunk #9 account, so this chunk's fix visibly improved
a real, non-synthetic capture in the same invocation that was verifying
the synthetic one.

**Cleanup**: the test's own cgroup directory (moving this process back to
its original cgroup first) and bpffs pin root were removed by the test's
own teardown. `bathyscaphe-itest-dnsfix-build` and
`bathyscaphe-itest-dnsfix-priv` were removed after use; confirmed absent
via `docker ps -a`. No `bathyscaphe-itest-*` Docker network or container
was created by this chunk's own new test (it uses a bare loopback socket
pair, not a Docker container, for the DNS traffic itself); `/sys/fs/bpf`
and `/sys/fs/cgroup` confirmed to have no leftover `bathyscaphe-itest-*`
or `bathyscaphe-dnsfix-*` entries after the final run.

### What is still deferred to a later chunk

Everything chunk #9-#11's own "deferred" notes already listed (TCP DNS,
IPv6 extension headers, DoH/DoT/ECH, rootless Podman) is unchanged by this
chunk -- it fixed a capture-length correctness bug, not any of the
structural visibility gaps those chunks already documented honestly.
