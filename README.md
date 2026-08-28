# bathyscaphe

Status: under construction, past scaffold. The workspace builds, the
eBPF programs load and pin, policy compilation and reconciliation work,
the CLI (`run` / `unpin --all` / `observe` / `version`) is wired up, and
the DNS-snoop FQDN layer is built through. Packaged: a multi-stage
Dockerfile, published to `ghcr.io/tagwright/bathyscaphe` on release, see
docs/DEPLOY.md for the required runtime privilege/mounts and the airlock
integration topology. See docs/BUILDING.md for the toolchain that makes
the eBPF side compile at all, since that's the part most likely to need
touching before anything else here is useful.

A bathyscaphe is a crewed deep-sea submersible: a small pressure-hulled
vehicle that descends into the deep ocean under its own ballast, with
nothing but a winch cable and a lot of trust in the hull. This project
descends into the kernel instead of the ocean, to watch what a container
sends out over the network before it leaves. Same family as
[ballast](../ballast): [video](https://www.youtube.com/watch?v=vAgJ9U6GFTk).

bathyscaphe is tagwright's own eBPF egress probe, written in Rust with
[aya](https://aya-rs.dev/). It's
[airlock](../airlock)'s second observation backend. The first backend,
Inspektor Gadget, only observes: it can tell you a container's egress
deviated from policy, but it can't stop the packet. bathyscaphe is the
backend that can, because it hooks the same in-kernel decision point
(`connect()`, via a cgroup/connect4 program) that decides whether the
connection happens at all, not a trace point after the fact.

## Scope

Observation is at parity with what Inspektor Gadget already gives airlock:
same connect events, same container attribution, same src/dst/proto shape.
On top of that, bathyscaphe can enforce, and enforcement is opt-in per
container. A container airlock hasn't told bathyscaphe to enforce keeps
flowing exactly like it would under the Inspektor Gadget backend. Turning
enforcement on for a container is a deliberate decision an operator makes,
not a default.

One hook drives both paths. The connect4/connect6 program runs the same
policy lookup regardless of mode; in observe mode it always returns allow
and just logs what it would have done, in enforce mode the lookup result
also becomes the return value. That's what keeps "what we saw" and "what
we would have blocked" from drifting apart.

## Fail-closed by design

If bathyscaphe's own userspace process dies, enforcement does not stop.
The eBPF program, its link, and its policy map are pinned to bpffs, so the
kernel keeps enforcing whatever policy was last written, independent of
whether anything userspace is alive to feed it new rules. A supervisor
restarts the daemon, and the daemon re-attaches to the pinned state
instead of starting cold. A standalone `bathyscaphe unpin --all` command
is the break-glass path if you need to clear pinned enforcement directly
and can't or don't want to wait for the daemon.

Fresh boot is the one case that starts open, not closed: a probe that has
never received a policy from airlock enforces nothing, so a cold start
never black-holes traffic before anyone has configured it.

### Fail-closed on sustained event drops (opt-in, off by default)

The kernel-side ring buffer that carries events up to userspace can fill
up under load and start dropping. bathyscaphe counts those drops per
container. By default, a drop just gets counted and logged loudly (see
R1 below). There's a second, separate knob: if you configure a drop-rate
threshold and a window, and a container's drop rate stays above that
threshold for that long, bathyscaphe can escalate that container to full
enforcement lockdown instead of just logging. This is off by default, the
same way Falco's own `syscall_event_drops` action defaults to alerting
rather than exiting. Turning it on is a real decision: it trades "keep
running with a known blind spot" for "assume the blind spot might be
someone erasing their tracks and shut the door." Document your reasoning
if you flip it, because the failure mode you're choosing is a frozen
container, not a crash.

Loud accounting is the other half of this: anything security-relevant
(an unenforceable DNS name in block mode, event drops, a policy
violation, an enforced block) gets emitted as a structured record, not
buried in a log line, so airlock and beacon can act on it without
scraping text.

## Usage

Four subcommands:

- `bathyscaphe run` -- the real thing: an airlock-driven subprocess.
  NDJSON events/stats/acks on stdout, directives on stdin, human-ish logs
  on stderr. This is the fail-closed-persistent mode described above.
  Flags: `--bpffs-root`, `--cgroup-root`, and the R2 knobs
  (`--fail-closed-on-drops`, `--drop-threshold-per-sec`,
  `--drop-window-secs`, `--drop-action`).
- `bathyscaphe unpin --all` -- the break-glass. Works standalone, with no
  running probe and no airlock: clears every pinned program, map, and
  per-container link under `--bpffs-root` and prints what it removed.
  `--all` is required on purpose; a bare `unpin` refuses to guess scope.
- `bathyscaphe observe` -- a standalone, observe-only mode for manual
  verification: no airlock, no policy, no enforcement. It attaches to
  whatever containers are already running (and picks up new ones), prints
  egress events to stdout (`--format json|text`, optionally filtered with
  `--container`), and on Ctrl-C detaches everything it attached. If it did
  the initial load itself (the common case: nothing else has this
  bpffs-root pinned), it also removes its own pin subtree on exit, so it
  leaves no trace. This is the opposite of `run`'s persistence, on
  purpose -- see the CLI's own `--help` for the exact scope this draws
  when a `run` daemon is already using the same `--bpffs-root`.
- `bathyscaphe version` -- prints the version, backend name, protocol
  versions, and capabilities.

`--log-format json|text` (default `json`) and `--log-level` are global
flags controlling bathyscaphe's own operational logs on stderr, not the
NDJSON protocol on stdout/stdin (which has its own fixed framing
regardless). `json` is OpenTelemetry-log-data-model shaped, so bilgeline
can ingest it with a stock filelog parser with no bespoke config.

## Requirements

- cgroup v2 (the unified hierarchy). cgroup v1-only hosts are out of
  scope, full stop, since the program types this depends on only attach
  to a v2 cgroup path.
- Kernel 5.8 or newer. That's the floor for `RingBuf`, which the
  connect4/connect6 hooks need for their event stream; the hooks
  themselves only need 4.17, but there's no reason to build a fallback
  event mechanism for kernels that old.
- `CAP_BPF` + `CAP_NET_ADMIN` to load and attach, or `--privileged` in
  practice, which is how most eBPF egress tooling gets deployed today.

## License

Licensed under GPL-3.0-or-later. See [LICENSE](LICENSE) for the full
text. Every source file carries an `SPDX-License-Identifier:
GPL-3.0-or-later` header.
