<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Deploying bathyscaphe

This is the packaging build chunk's doc: the image, the runtime posture it
needs, a compose snippet for the privileged container, and the topology
question that actually matters for a real deployment -- how airlock gets
at this binary. See `docs/BUILDING.md` for how the image itself is built,
`docs/TESTING.md` for how the runtime behavior here was proven,
`docs/RECOVERY.md` for the break-glass and full-removal operations, and
the README for what bathyscaphe is and its fail-closed/R2 design.

## Runtime posture

bathyscaphe needs real kernel privilege to load and attach eBPF programs,
and three things mounted into wherever it runs, whether that's a bare
`docker run`, a compose service, or (see below) as a child process
spawned by airlock:

- **Privilege**: `CAP_BPF` + `CAP_NET_ADMIN` + `CAP_SYS_ADMIN` to load,
  attach, and pin the eBPF programs. In practice this means
  `--privileged` -- the same posture most eBPF egress tooling (Cilium,
  Inspektor Gadget) is deployed with today. Capability-only deployment
  without `--privileged` is possible in principle but untested; see
  `docs/TESTING.md` for exactly what was proven under `--privileged`.
- **`/sys/fs/cgroup`**, bind-mounted from the host, **with
  `--cgroupns=host`**. Without `--cgroupns=host`, this container only
  sees its own private cgroup namespace slice, not the host's real
  cgroup v2 tree, and container attribution/attach silently finds
  nothing to attach to. cgroup v2 (the unified hierarchy) is required;
  bathyscaphe's kernel-floor check fails loud and refuses to start
  against a v1 or hybrid host.
- **`/sys/fs/bpf`**, a bpffs, for fail-closed pinning of programs, links,
  and policy maps. If the host doesn't already have one mounted, mount
  it inside the privileged container before starting bathyscaphe:
  `mount -t bpf bpf /sys/fs/bpf`. Bind-mounting the *host's* bpffs
  instead (rather than mounting a fresh one inside the container) is
  what makes pins survive a container restart -- that's the whole point
  of the fail-closed design in the README, so prefer it over a
  container-local bpffs in any deployment that expects `run` to be
  restarted by a supervisor.
- **`/var/run/docker.sock`, read-only**, for the Docker/Podman socket
  bathyscaphe reads via `bollard` to enrich cgroup ids with
  container id/name/image. Read-only is sufficient: bathyscaphe only
  queries the socket, it never starts, stops, or labels anything.
- **Kernel 5.8+**. Floor for `RingBuf` and the post-5.8 `CAP_BPF` split.

None of this is set inside the Dockerfile -- capabilities and mounts are
the caller's `docker run`/compose/pod-spec decision, which is exactly why
they're documented here rather than baked into `CMD`.

## Compose snippet

```yaml
services:
  bathyscaphe:
    image: ghcr.io/tagwright/bathyscaphe:latest
    privileged: true
    cgroup: host          # docker compose's spelling of --cgroupns=host
    pid: host             # attribution's cgroup discovery does not
                           # strictly need this, but most deployments
                           # running an airlock-family backend alongside
                           # other host-visibility tooling already set it
    volumes:
      - /sys/fs/cgroup:/sys/fs/cgroup
      - /sys/fs/bpf:/sys/fs/bpf
      - /var/run/docker.sock:/var/run/docker.sock:ro
    # `mount -t bpf bpf /sys/fs/bpf` once on the host ahead of time (or as
    # part of this service's entrypoint) if /sys/fs/bpf isn't already a
    # bpffs -- see "Runtime posture" above for why bind-mounting a
    # HOST bpffs (not minting a fresh container-local one) is what makes
    # pins survive this container restarting.
    command:
      - run
      - --trusted-resolver=1.1.1.1
      - --fail-closed-on-drops        # opt-in, see the README's R2 section
      - --drop-threshold-per-sec=10
      - --drop-window-secs=60
```

`--trusted-resolver` is repeatable and additive to the built-in default
set (Docker's embedded resolver at `127.0.0.11`, plus every `nameserver`
line in this container's own `/etc/resolv.conf`) -- see `docs/DNS.md` for
why only a DNS answer whose source address is in this set can seed FQDN
name-rule enforcement. The R2 flags (`--fail-closed-on-drops` and its
threshold/window/action knobs) are off by default; see the README before
turning them on in a real deployment, since the failure mode they
introduce is a frozen container, not a crash.

## Standalone `observe` and `unpin --all`

Both work against the bathyscaphe image directly, no airlock involved:

```sh
# Watch egress from every currently-running container, human-readable,
# until Ctrl-C:
docker run --rm -it --privileged --cgroupns=host \
  -v /sys/fs/cgroup:/sys/fs/cgroup \
  -v /sys/fs/bpf:/sys/fs/bpf \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  ghcr.io/tagwright/bathyscaphe:latest observe --format text

# Break-glass: clear every pinned program, map, and per-container link
# under bpffs, no running probe or airlock required:
docker run --rm --privileged \
  -v /sys/fs/bpf:/sys/fs/bpf \
  ghcr.io/tagwright/bathyscaphe:latest unpin --all
```

Two things worth knowing before you run `observe` against a real host:

- **With no `--container`, it attaches to *every* running container,
  immediately.** This is the intended default -- "observe the whole
  host" -- and it's harmless to traffic either way, since observe mode
  always returns allow regardless of what it logs. But it is still a
  live kernel-side attachment to every one of those containers'
  `connect()` calls for as long as `observe` is running, so on a
  production host, scope it with `--container <id-or-name>` unless you
  actually mean to watch everything. `--container` genuinely narrows
  which cgroups get an eBPF hook attached at all, not just which events
  get printed -- the same predicate gates both.
- **Clean exit is `Ctrl-C` (`SIGINT`), `docker stop`'s default `SIGTERM`,
  or `SIGHUP`** -- all three run the identical detach-and-unpin-on-exit
  path. An OOM kill (`SIGKILL`, which can't be caught by any process)
  still skips it and leaves whatever `observe` attached pinned in bpffs
  until something clears it; `bathyscaphe unpin --all` is that
  something (see docs/RECOVERY.md). If `observe` ever goes away via
  `SIGKILL` or a hard crash, run `unpin --all` afterward and don't
  assume "the process exited" means "the hooks are gone."

## Airlock integration topology

This is the real deployment question, not the compose snippet above.
bathyscaphe is not meant to run standalone in the airlock-driven case --
airlock spawns it as a **child process** over stdin/stdout, the same
shape as `ig run` for the Inspektor Gadget backend: NDJSON events/stats
up on stdout, directives down on stdin, human logs on stderr (see
`docs/PROTOCOL.md`). That means airlock needs the bathyscaphe *binary*
available inside its own image, running with the privilege documented
above -- it does not talk to a separate bathyscaphe container over a
socket or an HTTP API.

The clean pattern is a multi-stage `COPY --from` pulling the binary
straight out of the published bathyscaphe image, the same way a
statically-built tool gets vendored into another image without
recompiling it:

```dockerfile
# In airlock's own Dockerfile:
FROM ghcr.io/tagwright/bathyscaphe:v0.1.0 AS bathyscaphe
FROM <airlock's own base> AS runtime
COPY --from=bathyscaphe /usr/local/bin/bathyscaphe /usr/local/bin/bathyscaphe
# ... airlock's own binary, entrypoint, etc.
```

airlock's own container then needs the same privilege and mounts
documented above (`--privileged` or the three caps, `/sys/fs/cgroup` with
`--cgroupns=host`, `/sys/fs/bpf`, `/var/run/docker.sock`), since it's
airlock's process tree that ends up exec'ing `bathyscaphe run` as a
subprocess and inheriting (or needs to hold) that privilege for the
child to load/attach/pin successfully. Pin `ghcr.io/tagwright/bathyscaphe`
at the same tag airlock's own release is built against, not `:latest`,
for the same reason any vendored binary gets pinned.

**This is the airlock chat's side to wire up**: the `COPY --from` line
above and the corresponding privilege/mounts on airlock's own container
definition. This doc and the standalone image are bathyscaphe's half of
the contract; nothing here changes if airlock picks a different base
image or a different mount strategy, as long as the binary lands
somewhere on `PATH` and the process it's exec'd from holds the
privilege.

The standalone bathyscaphe image (this same image, run directly rather
than vendored) is also a complete, directly-runnable tool on its own --
useful for `observe`/`unpin --all` debugging on a host with no airlock
installed at all, or for a CI job that wants to sanity-check a policy
change against a real kernel without going through airlock.
