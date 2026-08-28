<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Recovery and break-glass

The operations here assume something has already gone wrong, or you're
deliberately removing bathyscaphe from a host. For the normal deploy and
runtime posture, see docs/DEPLOY.md; for the fail-closed design this
document's operations exist to work around, see the README's "Fail-closed
by design" section.

## The core fact to understand first

bathyscaphe's programs, links, and policy maps are pinned to bpffs. Once
`attach_container` has run for a container and the process that did it
exits -- cleanly, via a crash, via a kill signal, whatever -- the kernel
keeps enforcing exactly the policy that was pinned. There is no
"userspace is gone, so enforcement stops" case in `run`'s design. This is
the entire point of fail-closed: an operator or an attacker killing the
daemon does not open the container back up. It also means a wedged or
misconfigured policy does not go away just because you restarted the
process, since a restart re-attaches to the SAME pinned state rather than
starting fresh (see "How a restart reattaches" below).

`bathyscaphe unpin --all` exists because that property needs an escape
hatch. It clears pinned state directly against bpffs, with no dependency
on airlock being reachable or a probe currently running.

## `bathyscaphe unpin --all`

```sh
bathyscaphe unpin --all --bpffs-root /sys/fs/bpf/bathyscaphe
```

What it does: walks `--bpffs-root` (default `/sys/fs/bpf/bathyscaphe`)
and removes every pinned program, every pinned map, and every
per-container link set it finds -- the whole subtree, unconditionally.
It prints a count of what it removed (programs / maps / container link
sets) and, if any container link sets existed, an explicit warning that
every container enforced under that root is now completely unenforced
until something re-attaches and re-pushes policy.

`--all` is required, not defaulted. A bare `bathyscaphe unpin` (no flag)
refuses to act and prints why, rather than guessing at a partial scope.
A container id given as a positional argument is accepted for a future
per-container unpin but is not implemented yet -- today the only
supported scope is everything under the root.

It needs no running `bathyscaphe run` process and no airlock connection
at all. It only needs the same privilege `run` needs (`CAP_BPF` +
`CAP_NET_ADMIN` + `CAP_SYS_ADMIN`, in practice `--privileged`) and a path
to the bpffs root. Running it against a root that doesn't exist is a
clean no-op: it reports nothing was pinned and exits successfully.

### When to reach for it

- **airlock is gone and isn't coming back**, but bathyscaphe is still
  enforcing a policy from before airlock died. If you need the host's
  containers unblocked and airlock isn't going to restart to push a
  release, this is the only way to clear that enforcement without also
  fixing or restarting airlock first.
- **Enforcement is wedged**: a policy got pushed that's wrong (blocking
  traffic that should be allowed, in a way that's breaking something
  operationally important right now), and you need it gone immediately
  rather than waiting on a corrected policy push and reconciliation.
- **An operator is locked out** of something that depends on the
  container's own egress (an update mechanism, a health-check callback,
  a debugging shell that needs to reach out) and no other path exists to
  reach the container and fix it from inside.
- **You are decommissioning bathyscaphe from a host entirely** -- see
  "Removing bathyscaphe completely" below, where this is step one.

### What it does NOT do

It does not tell airlock anything. Airlock's own idea of what's enforced
(its intended policy state) is untouched by this command -- it only
clears the KERNEL's enforced state. If airlock is still running and
reachable, expect it to notice the mismatch on its own reconciliation
cycle (a fresh `run` process reports its pinned inventory in `hello`;
with nothing pinned, airlock sees an empty inventory and re-pushes full
snapshots per container) and re-enforce. If you don't want that, stop or
pause airlock's policy pushes for the affected containers first, or
expect enforcement to come back on its own shortly after you clear it.

It also does not remove `bathyscaphe run` itself if a daemon process
happens to still be alive against the same root -- it only clears what's
pinned in bpffs out from under it. A live daemon holding open file
descriptors to programs/maps you just unpinned will keep running against
its own in-memory handles until it next tries to attach a new container
or exits; expect a live daemon's next operation against the cleared root
to behave unpredictably, so stop the daemon first if one is running
against the root you're clearing (`docker stop` the `run` container, or
send it `SIGTERM`/`SIGKILL` directly -- `run` deliberately does NOT clean
up its own pins on exit, so stopping it first and then running
`unpin --all` is always the correct order, never the reverse).

## How pins survive a probe crash, and how a restart reattaches

This is the mechanism `unpin --all` is the escape hatch for, spelled out:

1. `bathyscaphe run` starts. If `--bpffs-root` is empty, it does a fresh
   load: `aya::Ebpf::load` the embedded object, `.load()` every program,
   pin each program, each map, and (as containers get attached) each
   per-container link, all under `--bpffs-root`.
2. The process dies -- a crash, an OOM kill, a supervisor stopping it,
   anything. The pins are files on bpffs, not process state; they don't
   go anywhere. The kernel's own eBPF subsystem keeps every attached
   program running against every attached cgroup exactly as it was at
   the moment the process died, because a bpffs pin holds a reference
   independent of any process holding an fd.
3. A supervisor restarts `bathyscaphe run` against the SAME
   `--bpffs-root`. This time it takes the RESUMED path, not the fresh
   one: no `aya::Ebpf::load` at all. Every program and every map is
   reopened via `from_pin`, and every previously-attached container is
   rediscovered by walking the `links/` subtree -- the new process ends
   up holding handles to the exact same kernel objects the dead process
   was using, with zero enforcement gap in between.
4. On `hello`, the restarted daemon reports its pinned inventory to
   airlock. Airlock re-pushes a full policy snapshot for every container
   it still considers active. Anything pinned that airlock does NOT
   re-claim in this reconciliation is treated as orphaned and kept
   enforcing its last-known policy (fail-closed) rather than silently
   dropped, until airlock explicitly adopts or releases it.

The practical upshot: a crash-loop, a bad deploy, an OOM kill, or a
deliberate `docker stop`/restart of the `run` container all leave
enforcement intact through the gap. The only thing that removes pinned
enforcement is `unpin --all` (or manually deleting files under the bpffs
root, which is the same operation without the reporting).

## Removing bathyscaphe completely

1. Stop `bathyscaphe run` first, if it's running (`docker stop`, or
   `SIGTERM`/`SIGKILL` directly -- `run` does not clean up its own pins
   on exit, by design, so there's no "clean shutdown" ordering to wait
   for here).
2. `bathyscaphe unpin --all --bpffs-root <the root run was using>` to
   clear every pinned program, map, and container link.
3. Confirm the subtree is gone (`bathyscaphe unpin --all` again is a
   clean no-op once it's empty, or check `--bpffs-root` directly).
4. Remove or stop the bathyscaphe container/service itself. If it was
   vendored into airlock's own image (see docs/DEPLOY.md's "Airlock
   integration topology"), that's airlock's own image/deploy to update,
   not a separate bathyscaphe teardown step.

Every container that was enforced is now completely unenforced the
moment step 2 finishes -- not audited, not observed, nothing. If you're
decommissioning bathyscaphe in favor of a different backend (or in favor
of nothing), make sure that's the intended end state, or have the
replacement's policy ready to push before you clear the old one.

## The fail-closed implications an operator must actually understand

- **A dead or crash-looping `run` process is not, by itself, a reason to
  panic about egress being open.** Check whether the containers you care
  about were already attached and enforced before the process died --
  if they were, they still are. Restarting the daemon (or waiting for a
  supervisor to) reattaches to the same pinned state; it does not need
  to "catch up" on enforcement it already had.
- **`unpin --all` is a hard, immediate, all-or-nothing action.** There is
  no `unpin --container <id>` yet (see the flag's own `--help` for the
  "not yet implemented" refusal). If only one container's policy is
  wrong, fixing it via a corrected policy push through airlock is the
  narrower operation; `unpin --all` clears every container under the
  root, including the ones whose enforcement was fine.
- **Cold start is the one place fail-closed doesn't apply, on purpose.**
  A probe that has never received a policy from airlock enforces
  nothing for a freshly-attached container -- this is deliberate (a cold
  boot never black-holes traffic before anyone has configured it), not a
  gap in the design, and not something `unpin --all` interacts with.
- **Clearing pins does not tell airlock to stop trying.** As noted above,
  if airlock is alive and still considers a container's policy active,
  expect it to re-push and re-enforce on its own reconciliation cycle.
  `unpin --all` buys you a window, not a permanent state, unless airlock
  is also stopped, unreachable, or told to release that container.
