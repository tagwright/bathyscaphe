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
- **Attribution** (cgroup id -> container id/name/image) -- a later chunk;
  `probe` only ever sees `cgroup_id: u64`.
