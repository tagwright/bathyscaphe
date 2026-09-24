# bathyscaphe

bathyscaphe is an eBPF egress probe for containers: it watches what each
container sends out over the network and, when an operator opts a container in,
blocks the connections that violate policy in the kernel before they are made.

Status: functionally complete and packaged. The workspace builds on the
documented two-toolchain image, the eBPF programs load/attach/pin, policy
compilation and reconciliation work, the DNS-snoop FQDN layer is built
through, and the CLI (`run` / `unpin --all` / `observe` / `version`) is
wired up end to end. Published to `ghcr.io/tagwright/bathyscaphe` on
release. See docs/DEPLOY.md for the runtime privilege/mounts and the
airlock integration topology, docs/BUILDING.md for the toolchain that
compiles the eBPF side, and docs/TESTING.md for an honest ledger of
what's been proven against a real kernel versus compile-only.

A bathyscaphe is a crewed deep-sea submersible: a small pressure-hulled
vehicle that descends into the deep ocean under its own ballast, with
nothing but a winch cable and a lot of trust in the hull. This project
descends into the kernel instead of the ocean, to watch (and, opted in,
control) what a container sends out over the network before it leaves.
Same family as [ballast](../ballast): [video](https://www.youtube.com/watch?v=vAgJ9U6GFTk).

bathyscaphe is tagwright's own eBPF egress probe, written in Rust with
[aya](https://aya-rs.dev/). It's [airlock](../airlock)'s second
observation backend. The first backend, Inspektor Gadget, only observes:
it can tell you a container's egress deviated from policy, but it can't
stop the packet. bathyscaphe is the backend that can, because it hooks
the same in-kernel decision points that decide whether the connection
happens at all, not a trace point after the fact.

The boundary with airlock is a separate process, never a library call:
airlock spawns `bathyscaphe run` as a child and talks to it over NDJSON
on stdin/stdout (events/stats/acks up, policy directives down), the same
shape its Inspektor Gadget adapter already uses. No FFI, no shared
memory, no in-process linking. See docs/PROTOCOL.md for the wire format.

## Scope

Observation is at parity with what Inspektor Gadget already gives
airlock: connect events, container attribution, src/dst/proto shape. On
top of that, bathyscaphe can enforce, in kernel, which Inspektor Gadget
cannot do at all. Enforcement is opt-in per container -- a container
airlock hasn't told bathyscaphe to enforce keeps flowing exactly like it
would under the Inspektor Gadget backend. Turning enforcement on for a
container is a deliberate decision an operator makes, not a default.

The hooks: `connect4`/`connect6` (TCP and connected UDP), a UDP
`sendmsg` hook (unconnected UDP, which covers QUIC and HTTP/3 -- traffic
that never calls `connect()` at all), and a `sock_create` hook that
denies `SOCK_RAW` outright on an enforced container (raw sockets bypass
the other two hooks by construction). One policy lookup drives all of
them: in observe mode it always returns allow and just logs what it
would have done, in enforce mode the lookup result also becomes the
return value. That's what keeps "what we saw" and "what we would have
blocked" from drifting apart -- there's no separate enforcement code
path to fall out of sync with the observed one.

Policy itself is IP/CIDR plus port, per container, with an optional FQDN
layer on top: bathyscaphe snoops a container's own DNS query and
response traffic, correlates the pair itself (no trusting the response
packet's own claimed identity), and inserts the resolved address into
that container's allow-map for the answer's TTL. Only a DNS answer whose
source address is in a configured trusted-resolver allowlist gets to
seed a name rule this way -- see docs/DNS.md for the full account,
including why this is a deliberate design choice (local per-container
resolution wins the CDN-divergence race a central resolver loses) and
where it stops working.

## Fail-closed by design

If bathyscaphe's own userspace process dies, enforcement does not stop.
The eBPF programs, their links, and the policy maps are pinned to bpffs,
so the kernel keeps enforcing whatever policy was last written,
independent of whether anything userspace is alive to feed it new
rules. A supervisor restarts the daemon, and the daemon re-attaches to
the pinned state instead of starting cold. A standalone
`bathyscaphe unpin --all` command is the break-glass path if you need to
clear pinned enforcement directly and can't or don't want to wait for
the daemon -- see docs/RECOVERY.md for when and how to reach for it.

Fresh boot is the one case that starts open, not closed: a probe that
has never received a policy from airlock enforces nothing, so a cold
start never black-holes traffic before anyone has configured it.

### Fail-closed on sustained event drops (opt-in, off by default)

The kernel-side ring buffer that carries events up to userspace can fill
up under load and start dropping. bathyscaphe counts those drops per
container. By default, a drop just gets counted and logged loudly. There's
a second, separate knob -- `--fail-closed-on-drops`, `--drop-threshold-per-sec`,
`--drop-window-secs`, `--drop-action` on `bathyscaphe run` -- and it is
**off unless you set it**: if you configure a drop-rate threshold and a
window, and a container's drop rate stays above that threshold for that
long, bathyscaphe escalates that container (lockdown to full enforcement,
or process exit, your choice via `--drop-action`) instead of just logging.
Off by default, matching Falco's own `syscall_event_drops` default of
alert-not-exit. Turning it on is a real decision: it trades "keep running
with a known blind spot" for "assume the blind spot might be someone
erasing their tracks and shut the door." Document your reasoning if you
flip it, because the failure mode you're choosing is a frozen container,
not a crash.

Loud accounting is the other half of this: anything security-relevant
(an unenforceable DNS name in block mode, event drops, a policy
violation, an enforced block) gets emitted as a structured, OpenTelemetry-
log-data-model-shaped record, not buried in a log line, so airlock and
beacon can act on it without scraping text.

## Usage

```sh
# The real thing: an airlock-driven subprocess, NDJSON on stdin/stdout.
bathyscaphe run --trusted-resolver=1.1.1.1

# Manual verification, no airlock: attach to every running container
# and print egress events. Ctrl-C, SIGTERM, or SIGHUP detach and unpin
# cleanly on exit.
bathyscaphe observe --format text

# Scope observe to one container instead of the whole host -- this
# limits which containers actually get an eBPF hook attached, not just
# what gets printed.
bathyscaphe observe --container my-app --format text

# Break-glass: clear every pinned program, map, and per-container link,
# no running probe or airlock required.
bathyscaphe unpin --all

# Version, backend identity, protocol versions, capabilities.
bathyscaphe version
```

Four subcommands:

- `bathyscaphe run` -- the fail-closed-persistent mode described above.
  Flags: `--bpffs-root`, `--cgroup-root`, `--trusted-resolver` (repeatable),
  and the R2 knobs (`--fail-closed-on-drops`, `--drop-threshold-per-sec`,
  `--drop-window-secs`, `--drop-action`).
- `bathyscaphe unpin --all` -- the standalone break-glass. `--all` is
  required on purpose. A bare `unpin` refuses to guess scope. See
  docs/RECOVERY.md.
- `bathyscaphe observe` -- a standalone, observe-only mode for manual
  verification: no airlock, no policy, no enforcement (the probe's
  enforcement map has no entry for anything `observe` attaches, which
  the hooks read as always-allow). With no `--container`, it attaches to
  (and prints events from) every running container and picks up new ones.
  With `--container <id-or-name>`, it attaches ONLY to the matching
  container(s) -- the same flag that scopes what gets printed also scopes
  what gets a live kernel hook. On exit -- Ctrl-C (`SIGINT`), `docker stop`
  (`SIGTERM`), or `SIGHUP` -- it detaches everything it attached this
  session and, if it did the initial load itself, removes its own pin
  subtree too, leaving the host exactly as it found it. This is the
  opposite of `run`'s persistence, on purpose: see the CLI's own
  `--help` for the exact scope this draws when a `run` daemon is already
  using the same `--bpffs-root`.
- `bathyscaphe version` -- prints the version, backend name, protocol
  versions, and capabilities.

`--log-format json|text` (default `json`) and `--log-level` are global
flags controlling bathyscaphe's own operational logs on stderr, not the
NDJSON protocol on stdout/stdin (which has its own fixed framing
regardless). `json` is OpenTelemetry-log-data-model shaped, so bilgeline
can ingest it with a stock filelog parser and no bespoke config.

## Requirements

- cgroup v2 (the unified hierarchy). cgroup v1-only hosts are out of
  scope, full stop, since the program types this depends on only attach
  to a v2 cgroup path. bathyscaphe's kernel-floor check fails loud and
  refuses to start on a v1 or hybrid host rather than attach partway.
- Kernel 5.8 or newer. That's the floor for `RingBuf`, which every event
  path here depends on.
- Privilege: `CAP_BPF` + `CAP_NET_ADMIN` + `CAP_SYS_ADMIN` to load,
  attach, and pin. In practice this means `--privileged`, the same
  posture most eBPF egress tooling (Cilium, Inspektor Gadget) runs
  under today.
- The Docker or Podman socket, mounted read-only, so bathyscaphe can
  enrich a cgroup id with the container's id/name/image. It only reads
  the socket, and never starts, stops, or labels anything.
- A writable bpffs mounted at `--bpffs-root` (default
  `/sys/fs/bpf/bathyscaphe`), ideally the HOST's bpffs bind-mounted in
  rather than a fresh one minted per container, since that's what lets
  pins survive a restart.

See docs/DEPLOY.md for the exact mounts, a compose snippet, and how
airlock vendors the binary into its own image.

## Honest limitations

IP/CIDR-and-port policy is the ground-truth floor. Every limitation
below is a case where the FQDN layer on top has nothing to add, never a
case where the IP/CIDR floor itself is compromised:

- **DoH, DoT, and ECH evade name policy entirely.** None of them touch
  UDP/TCP port 53, so DNS-over-HTTPS, DNS-over-TLS, and Encrypted Client
  Hello traffic are structurally invisible to the DNS snoop. A container
  that resolves a denied domain through one of these gets no name rule
  seeded either way, and a connection to the resulting IP is judged on
  IP/CIDR policy alone.
- **Direct-IP egress bypasses name policy by definition.** A name rule
  only ever inserts IPs it actually observed a trusted DNS answer for. A
  connection straight to an IP address, with no DNS lookup involved,
  was never going to have a name rule apply to it in the first place.
- **TCP-fallback DNS is not observed.** The snoop matches UDP only. A
  query or response that falls back to TCP:53 (oversized or truncated
  messages, or a resolver that prefers TCP outright) is invisible to
  both capture and correlation.
- **IPv6 extension headers aren't walked.** The IPv6 parsing path
  assumes UDP sits immediately after the fixed header. A query or
  response behind a Hop-by-Hop, Routing, or Fragment header is missed.
  DNS traffic essentially never uses these in practice, which is why
  this hasn't been prioritized, not because it's been ruled out as rare
  forever.
- **Docker's embedded resolver (`127.0.0.11`) gets a documented special
  case.** A per-network-namespace DNAT rule rewrites the destination
  port before egress query traffic reaches the snoop, so the query hook
  additionally matches on that well-known address. A different runtime's
  own embedded resolver, reached through a similar local-DNAT scheme at
  a different address, isn't automatically covered.
- **A genuine cross-container DNS correlation collision fails safe, never
  cross-attributes.** The correlation key doesn't include a resolver
  address component. When two containers' queries collide on it inside a
  short window, neither container's answer gets used for enforcement
  during the overlap, rather than risking one container's DNS answer
  seeding another's allow-map. The cost is a brief availability gap, not
  a security gap.

Full technical detail, including exact wire behavior and how each of
these was found and verified against a real kernel, is in docs/DNS.md.

## License

Licensed under GPL-3.0-or-later. See [LICENSE](LICENSE) for the full
text. Every source file carries an `SPDX-License-Identifier:
GPL-3.0-or-later` header.
