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
