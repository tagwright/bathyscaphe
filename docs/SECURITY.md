<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Security

bathyscaphe blocks network connections in the kernel before they are made. That
is an enforcement claim, and an enforcement claim is only worth what the evidence
behind it is worth. This document states the contract, describes the trust the
probe asks you to place in it, and is specific about what has been proven against
a real kernel versus what is still compile-only or untested. Every claim here is
checkable against the code, against [DNS.md](DNS.md), or against the honest
per-scenario ledger in [TESTING.md](TESTING.md).

## The enforcement contract

When an operator opts a container in to enforcement, bathyscaphe decides whether
each outbound connection from that container is allowed, in the kernel, at the
moment the syscall is made. A denied connection returns `EPERM` at `connect()` or
`sendmsg()` time. It is not a trace after the packet left and not a timeout. The
integration harness measured a denied `connect()` failing in 0.05 seconds against
a real container on kernel 6.8, which is a kernel refusal, not a network round
trip that never completed (scenario 2 in [TESTING.md](TESTING.md)).

Five eBPF programs attached to the container's cgroup carry this:
`connect4`/`connect6` for TCP and connected UDP, `sendmsg4`/`sendmsg6` for
unconnected UDP (which is where QUIC and HTTP/3 live, since they never call
`connect()`), and `sock_create`, which denies `SOCK_RAW` outright on an enforced
container because a raw socket would bypass the other four by construction.

Two properties of the design are the ones that matter for trusting the verdict:

- **Observe and enforce share one code path.** A single policy lookup drives every
  hook. In observe mode the lookup always returns allow and records what it would
  have done. In enforce mode the same lookup result becomes the syscall return
  value. There is no separate enforcement branch that can drift out of sync with
  the observed one, so "what we saw" and "what we would have blocked" cannot
  disagree.
- **Enforcement is opt-in, per container, and never a default.** A container that
  airlock has not told bathyscaphe to enforce keeps flowing exactly as it would
  under the observe-only backend. Turning enforcement on is a deliberate operator
  decision, made per container.

## Fail-closed, and the one place it is fail-open on purpose

If bathyscaphe's userspace process dies, enforcement does not stop. The programs,
their links, and the policy maps are pinned to bpffs, and the kernel keeps
enforcing the last policy that was written whether or not anything userspace is
alive to feed it new rules. A supervisor restarts the daemon, and the daemon
re-attaches to the pinned state rather than starting cold, so there is no
enforcement gap across the restart. The harness proved this the hard way: it
`SIGKILL`ed the real process, confirmed nothing bathyscaphe was running anywhere,
and watched the allowed destination still connect and the denied one still fail
(scenario 3 in [TESTING.md](TESTING.md)).

The deliberate exception is a fresh boot. A probe that has never received a
policy from airlock enforces nothing, so a cold start never black-holes a
container's traffic before anyone has configured it. This is a design choice, not
a hole. It is stated here so nobody mistakes an unconfigured cold probe for a
broken enforcing one.

There is a second, separate fail-closed knob for a different failure mode. The
kernel ring buffer that carries events to userspace can fill and drop under load,
which is a blind spot an attacker could try to hide inside. By default a drop is
counted and logged loudly. If you set `--fail-closed-on-drops` with a threshold
and a window, a container whose drop rate stays over the threshold gets escalated
to lockdown or the process exits, your choice. It is off unless you set it,
matching Falco's own alert-not-exit default, because the failure mode you are
choosing when you flip it is a frozen container. The escalation logic is
unit-tested. It has not been exercised live, because forcing a sustained drop
rate on demand was out of the integration harness's scope (noted in
[TESTING.md](TESTING.md)).

## The trust model of the probe

bathyscaphe is a privileged process, and that is the honest center of its threat
model. It loads eBPF programs, attaches them to cgroups, and pins them, which
needs `CAP_BPF`, `CAP_NET_ADMIN`, and `CAP_SYS_ADMIN`. In practice that means
`--privileged`, the same posture Cilium and Inspektor Gadget run under. A
compromise of the bathyscaphe process is a compromise of a highly privileged
component. The suite does not pretend otherwise. What bathyscaphe buys for that
privilege is the ability to stop a connection the observe-only backend can only
report after the fact.

The one thing it does not do with its privilege is act on the container runtime.
It mounts the Docker or Podman socket read-only, and it uses that socket only to
turn a cgroup id into a container's id, name, and image for attribution. It never
starts, stops, restarts, labels, or execs into anything.

The boundary with airlock is a subprocess boundary, not a library call. airlock
spawns `bathyscaphe run` as a child and talks to it over NDJSON on stdin and
stdout. There is no FFI, no shared memory, and no in-process linking, so a fault
in one is not automatically a fault in the other. The wire format is in
[PROTOCOL.md](PROTOCOL.md).

## What is proven, and only on a privileged host

The nature of an eBPF enforcement tool is that the load-bearing proof cannot run
in an ordinary CI container. Verifier acceptance, cgroup attach, pin survival, and
a real `EPERM` all need a privileged host with a real kernel, real cgroup v2, and
a real bpffs. [TESTING.md](TESTING.md) is written around that split, and this
section mirrors it rather than restating it more confidently than it does.

Proven live, against real containers on kernel 6.8.0-136, Docker only:

- In-kernel drop, with a measured `EPERM` at `connect()` time and correct
  allow/deny events (scenario 2).
- Fail-safe across probe death, including the resumed-boot re-attach and the
  break-glass clear (scenario 3).
- FQDN allow and FQDN deny seeded from real DNS resolution (scenarios 4 and 5).
- An untrusted resolver's answer refused as a seed for enforcement (scenario 6).
- Reconciliation and orphan handling across a restart (scenario 7).
- Cross-container DNS isolation under a deterministic forced `(txid, port)`
  collision, added by the chunk that fixed the finding below (scenario 9).

Not yet proven live, and stated as debt:

- **Rootless Podman is unproven.** The build environment was Docker only. The
  Podman runtime path and the rootless cgroup shapes are unit-covered, not run
  against a real Podman daemon.
- **The packaged image is not the tested artifact.** The live suite ran against
  `target/release/bathyscaphe` built by the two-toolchain recipe in
  [BUILDING.md](BUILDING.md), not through the eventual Docker image. The image is
  a separate proof still owed.
- **The opt-in drop-escalation path is unit-only**, as noted above.

## The DNS and FQDN caveats

The IP/CIDR-and-port policy is the ground-truth floor. The FQDN layer sits on top
of it, and every limitation below is a case where the name layer has nothing to
add, never a case where the IP floor is weakened. A connection the name layer
cannot reason about is still judged on IP/CIDR policy.

How the name layer earns a rule matters for trust. bathyscaphe snoops the
container's own DNS query and response traffic, correlates the pair itself, and
does not trust the response packet's claimed identity. Only an answer whose source
address is in a configured trusted-resolver allowlist is allowed to seed a name
rule, and the resolved address goes into that container's allow-map for the
answer's TTL. The untrusted-resolver refusal is proven live (scenario 6).

Where the name layer stops working, precisely:

- **DoH, DoT, and ECH are invisible to it.** None of them touch port 53, so the
  DNS snoop never sees the lookup. A domain resolved over one of these gets no
  name rule, and the resulting connection is judged on IP/CIDR policy alone.
- **Direct-IP egress was never in scope for a name rule.** A name rule only ever
  inserts an address it observed a trusted answer for. A connection straight to an
  IP with no lookup has no name to match.
- **TCP-fallback DNS is not observed.** The snoop matches UDP. A query or response
  that falls back to TCP:53 is invisible to capture and correlation.
- **IPv6 extension headers are not walked.** The parser assumes UDP sits right
  after the fixed header. DNS essentially never uses these in practice, which is
  why it is deprioritized rather than ruled impossible.
- **Under `default: deny`, the DNS query itself needs an explicit allow rule.**
  bathyscaphe applies the same enforcement to a container's outbound DNS query as
  to any other egress. There is no magic port-53 carve-out, because a
  built-in always-allow for port 53 would itself be an exfiltration channel. This
  is the same discipline any default-deny egress firewall imposes, and it is easy
  to be surprised by on a first `mode: block` deployment.

The cross-container correlation collision that was found and fixed is worth naming
directly. The query/response correlation table was once a single global
`(txid, port)` map, and because each container has its own network namespace with
its own ephemeral port allocator, two containers could collide on that key. A
collision could have attributed one container's DNS answer to another's cgroup,
which in enforce mode means seeding the wrong container's kernel allow-map. This
was reproduced deterministically, escalated rather than quietly patched, and then
fixed. Scenario 9 forces the collision on purpose and proves neither container's
policy map is ever seeded with the other's route, in either direction. The full
account is in [TESTING.md](TESTING.md).

## Known limitations

- **cgroup v1 is out of scope, and the probe refuses to start on it.** The program
  types depend on a v2 cgroup path. On a v1 or hybrid host the kernel-floor check
  fails loud rather than attaching partway.
- **Kernel older than 5.8 is unsupported.** That is the floor for the ring buffer
  every event path uses.
- **Loud security records draw from one bounded token bucket.** Anything
  security-relevant is emitted as a structured record, but the emitter is a single
  Falco-style token bucket for the whole daemon session (burst 5, refill 1 per 30
  seconds). Under a storm of loud records of any kind, some records are throttled
  rather than emitted. This is by design, and it surfaced honestly during testing
  when a DNS-heavy scenario session drained the budget. It means the record stream
  is a bounded alerting channel, not a guaranteed audit log of every event.
- **A cross-container correlation collision fails safe, at a small availability
  cost.** When two containers' queries collide inside the correlation window,
  neither container's answer is used to seed enforcement during the overlap. The
  cost is a brief window where a name rule is not seeded, not a security gap.

## Recovery

- **`bathyscaphe unpin --all` is the break-glass.** It clears every pinned
  program, map, and per-container link under the bpffs root, with no dependency on
  airlock being reachable or a probe running. `--all` is required on purpose, and a
  bare `unpin` refuses to guess a scope. Reach for it when airlock is gone and a
  stale policy is still enforcing, when a wrong policy is wedging traffic right
  now, or when you are decommissioning bathyscaphe from a host. It clears the
  kernel's enforced state only. It does not tell airlock anything, so a live
  airlock will re-push and re-enforce on its next reconciliation cycle unless you
  also stop or pause it. Full procedure and ordering in [RECOVERY.md](RECOVERY.md).
- **Stop the daemon before you clear its pins.** `run` deliberately does not clean
  up its own pins on exit, so the correct order is always stop the `run` container
  first, then `unpin --all`, never the reverse. A live daemon holding open
  descriptors to pins you cleared out from under it behaves unpredictably on its
  next attach.
- **A crash-looping `run` is not, by itself, a reason to think egress is open.** A
  container that was attached and enforced before the process died still is. Check
  what was enforced before you assume anything opened.

## Reporting a vulnerability

Report a suspected vulnerability through GitHub's private vulnerability reporting
on this repository: the **Security** tab, then **Report a vulnerability**. That
keeps the report private to the maintainer while it is triaged.

Please give it a chance to be fixed before disclosing it publicly. Coordinated
disclosure, where a fix ships before the details are public, is the outcome we are
asking for, and it is the one that protects the people running the tool.
