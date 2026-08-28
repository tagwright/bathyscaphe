#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""The seven end-to-end scenarios from the build agent brief, in priority
order. Each function is self-contained: it creates the `bathyscaphe-itest-*`
Docker objects it needs, drives a real `bathyscaphe run` (or, for scenarios
3 and 7, more than one instance of it across a restart), asserts against
real kernel/network behavior, and cleans up its own objects in a `finally`
block. See `run_integration.py` for how these are invoked and
`docs/TESTING.md` for the honest, human-readable account of what each one
actually proved."""

from __future__ import annotations

import os
import subprocess
import time

from driver import (
    Daemon,
    ScenarioResult,
    cidr_rule,
    docker_exec,
    docker_id,
    docker_ip,
    docker_rm,
    docker_run,
    log,
    name_rule,
    network_create,
    network_rm,
    tcp_probe,
    udp_probe,
    unpin_all,
    wait_until,
)

MAIN_ROOT = "/sys/fs/bpf/bathyscaphe-itest-main"
FAILSAFE_ROOT = "/sys/fs/bpf/bathyscaphe-itest-failsafe"
RECONCILE_ROOT = "/sys/fs/bpf/bathyscaphe-itest-reconcile"
UNTRUSTED_ROOT = "/sys/fs/bpf/bathyscaphe-itest-untrusted"


def scenario_1_observe(daemon: Daemon) -> ScenarioResult:
    name = "bathyscaphe-itest-observe-target"
    docker_rm(name)
    docker_run(name)
    cid = None
    try:
        cid = docker_id(name)
        ack = daemon.push_policy(cid, mode="audit", default="allow", rules=[])
        assert ack["status"] == "applied", ack

        events: list = []
        tcp_probe(name, "1.1.1.1", 443)
        ev_tcp = daemon.wait_for(lambda m: m.get("kind") == "event" and m.get("container", {}).get("id") == cid and m.get("proto") == "tcp" and m.get("dst", {}).get("addr") == "1.1.1.1", timeout=8, drain_into=events)
        udp_probe(name, "1.1.1.1", 53)
        ev_udp = daemon.wait_for(lambda m: m.get("kind") == "event" and m.get("container", {}).get("id") == cid and m.get("proto") == "udp" and m.get("dst", {}).get("addr") == "1.1.1.1", timeout=8, drain_into=events)

        assert ev_tcp is not None, f"no tcp observe event seen; drained: {events}"
        assert ev_udp is not None, f"no udp observe event seen; drained: {events}"
        assert ev_tcp["verdict"] == "allow", ev_tcp
        assert ev_udp["verdict"] == "allow", ev_udp

        c = ev_tcp["container"]
        assert c["id"] == cid, c
        assert c["name"] == name, f"attribution name mismatch: {c['name']!r} != {name!r}"
        assert c["image"] is not None and "alpine" in c["image"], f"attribution image mismatch: {c['image']!r}"
        assert c["runtime"] == "docker", c

        details = f"tcp event dst={ev_tcp['dst']} verdict={ev_tcp['verdict']}; udp event dst={ev_udp['dst']} verdict={ev_udp['verdict']}; attribution container={c}"
        return ScenarioResult("1_observe", "PROVEN", details)
    finally:
        if cid:
            daemon.release(cid)
        docker_rm(name)


def scenario_2_kernel_drop(daemon: Daemon) -> ScenarioResult:
    name = "bathyscaphe-itest-drop-target"
    docker_rm(name)
    docker_run(name)
    cid = None
    try:
        cid = docker_id(name)
        ack = daemon.push_policy(
            cid,
            mode="block",
            default="deny",
            rules=[
                cidr_rule("r-allow-tcp", "allow", "1.1.1.1/32", 443, "tcp"),
                cidr_rule("r-allow-udp", "allow", "1.1.1.1/32", 53, "udp"),
            ],
        )
        assert ack["status"] == "applied", ack

        events: list = []
        allowed = tcp_probe(name, "1.1.1.1", 443)
        ev_allow = daemon.wait_for(lambda m: m.get("kind") == "event" and m.get("container", {}).get("id") == cid and m.get("dst", {}) == {"addr": "1.1.1.1", "port": 443} and m.get("verdict") == "allow", timeout=8, drain_into=events)
        denied = tcp_probe(name, "8.8.8.8", 443)
        ev_deny = daemon.wait_for(lambda m: m.get("kind") == "event" and m.get("container", {}).get("id") == cid and m.get("dst", {}) == {"addr": "8.8.8.8", "port": 443} and m.get("verdict") == "deny", timeout=8, drain_into=events)

        assert allowed.ok, f"allowed TCP connect (1.1.1.1:443) should succeed: rc={allowed.raw.returncode} stderr={allowed.raw.stderr!r}"
        assert not denied.ok, f"disallowed TCP connect (8.8.8.8:443) should be denied: rc={denied.raw.returncode}"
        assert denied.elapsed_s < 2.0, f"kernel denial should be near-instant (EPERM), took {denied.elapsed_s:.2f}s -- looks like a network timeout, not an in-kernel block"
        assert ev_allow is not None, f"no allow event observed for 1.1.1.1:443; drained: {events}"
        assert ev_deny is not None, f"no deny event observed for 8.8.8.8:443; drained: {events}"

        # Bonus, informational only (not gating): the UDP sendmsg hook.
        allowed_udp = udp_probe(name, "1.1.1.1", 53)
        denied_udp = udp_probe(name, "8.8.8.8", 53)

        details = (
            f"TCP: allowed(1.1.1.1:443)={allowed.ok} in {allowed.elapsed_s:.2f}s, denied(8.8.8.8:443)={not denied.ok} in {denied.elapsed_s:.2f}s, "
            f"rule_id on deny event={ev_deny.get('rule_id')!r}, allow event verdict={ev_allow['verdict']}, deny event verdict={ev_deny['verdict']}. "
            f"UDP (informational): allow probe ok={allowed_udp.ok}, deny probe ok={denied_udp.ok}"
        )
        return ScenarioResult("2_kernel_drop", "PROVEN", details)
    finally:
        if cid:
            daemon.release(cid)
        docker_rm(name)


def scenario_3_failsafe() -> ScenarioResult:
    root = FAILSAFE_ROOT
    name = "bathyscaphe-itest-failsafe-target"
    subprocess.run(["rm", "-rf", root])
    docker_rm(name)
    docker_run(name)
    daemon1 = None
    daemon2 = None
    try:
        cid = docker_id(name)

        daemon1 = Daemon(root, stats_interval_s=1)
        hello1 = daemon1.handshake()
        assert hello1["pinned"] == [], f"a fresh bpffs root must start with nothing pinned: {hello1['pinned']}"

        ack = daemon1.push_policy(cid, mode="block", default="deny", rules=[cidr_rule("r-allow", "allow", "1.1.1.1/32", 443, "tcp")])
        assert ack["status"] == "applied", ack

        baseline_allow = tcp_probe(name, "1.1.1.1", 443)
        baseline_deny = tcp_probe(name, "8.8.8.8", 443)
        assert baseline_allow.ok and not baseline_deny.ok, f"baseline enforcement must hold before testing failure paths: allow.ok={baseline_allow.ok} deny.ok={baseline_deny.ok}"

        pid_before = daemon1.pid()
        daemon1.kill()
        assert daemon1.proc.poll() is not None, "the daemon process must actually be dead after SIGKILL"

        # No bathyscaphe process alive anywhere right now -- this is the
        # make-or-break check.
        dead_allow = tcp_probe(name, "1.1.1.1", 443)
        dead_deny = tcp_probe(name, "8.8.8.8", 443)
        assert dead_allow.ok, "the pinned allow entry must keep working with NO userspace process alive"
        assert not dead_deny.ok, f"the pinned deny-by-default must keep blocking with NO userspace process alive (rc={dead_deny.raw.returncode}, {dead_deny.elapsed_s:.2f}s)"

        daemon2 = Daemon(root, stats_interval_s=1)
        hello2 = daemon2.handshake()
        pinned_ids = [p["container_id"] for p in hello2["pinned"]]
        assert cid in pinned_ids, f"resumed hello.pinned must report the surviving container; got {pinned_ids}"
        pinned_entry = next(p for p in hello2["pinned"] if p["container_id"] == cid)
        assert pinned_entry["mode"] == "block", pinned_entry

        resumed_allow = tcp_probe(name, "1.1.1.1", 443)
        resumed_deny = tcp_probe(name, "8.8.8.8", 443)
        assert resumed_allow.ok, "after a supervised restart (reopen from pins), the allow entry must still work"
        assert not resumed_deny.ok, "after a supervised restart (reopen from pins), the deny-by-default must still block"

        daemon2.kill()
        unpin_result = unpin_all(root)
        assert unpin_result.returncode == 0, f"unpin --all failed: {unpin_result.stdout} {unpin_result.stderr}"
        assert not os.path.exists(root), "unpin --all must remove the whole pin subtree"

        cleared = tcp_probe(name, "8.8.8.8", 443)
        assert cleared.ok, "after the break-glass unpin --all, the previously-denied destination must now succeed (fully unenforced)"

        details = (
            f"fresh hello.pinned=[] confirmed; baseline allow={baseline_allow.ok} deny={not baseline_deny.ok}; "
            f"probe SIGKILLed (pid {pid_before}), no-userspace allow={dead_allow.ok} deny={not dead_deny.ok}; "
            f"resumed hello.pinned contained {cid[:12]}.. mode={pinned_entry['mode']}, resumed allow={resumed_allow.ok} deny={not resumed_deny.ok}; "
            f"post-unpin-all previously-denied-now-allowed={cleared.ok}"
        )
        return ScenarioResult("3_failsafe", "PROVEN", details)
    finally:
        if daemon1 is not None and daemon1.proc.poll() is None:
            daemon1.kill()
        if daemon2 is not None and daemon2.proc.poll() is None:
            daemon2.kill()
        docker_rm(name)
        subprocess.run(["rm", "-rf", root])


def scenario_4_fqdn_allow(daemon: Daemon) -> ScenarioResult:
    net = "bathyscaphe-itest-fqdn-net"
    backend = "bathyscaphe-itest-fqdn-backend"
    target = "bathyscaphe-itest-fqdn-target"
    network_rm(net)
    docker_rm(backend)
    docker_rm(target)
    network_create(net)
    docker_run(backend, network=net, cmd=["nc", "-lk", "-p", "8080"])
    docker_run(target, network=net)
    cid = None
    try:
        cid = docker_id(target)
        backend_ip = docker_ip(backend, net)

        # NOTE: under default:deny, the DNS QUERY itself is ordinary UDP:53
        # egress traffic and is subject to the SAME enforcement as anything
        # else -- bathyscaphe carves out no special exemption for DNS (a
        # magic always-allow-port-53 rule would itself be an exfiltration
        # channel and a policy hole). A real deployment doing default:deny
        # with name rules needs an explicit allow for its trusted
        # resolver(s), exactly like any other default-deny egress firewall
        # (iptables, Cilium, a k8s NetworkPolicy) needs a DNS allow rule.
        # First proven live here: an earlier version of this test omitted
        # this rule and the container's own `nslookup` failed with
        # "Operation not permitted" (the udp sendmsg hook denying the query
        # before it ever reached the resolver) -- see docs/TESTING.md.
        ack = daemon.push_policy(
            cid,
            mode="block",
            default="deny",
            rules=[
                name_rule("r-name-allow", "allow", backend, 8080, "tcp"),
                cidr_rule("r-allow-dns", "allow", "127.0.0.11/32", 53, "udp"),
            ],
        )
        assert ack["status"] == "applied", ack

        baseline = tcp_probe(target, backend_ip, 8080)
        assert not baseline.ok, "before any DNS answer is observed, the bare IP must not yet be allowed (proves the allow really comes from the DNS-seeded route, not a coincidental CIDR match)"

        resolved = docker_exec(target, "nslookup", backend + ".", timeout=8)
        assert resolved.returncode == 0 and backend_ip in resolved.stdout, f"nslookup {backend} should resolve to {backend_ip} via the trusted embedded resolver (127.0.0.11): {resolved.stdout} {resolved.stderr}"

        seeded = wait_until(lambda: tcp_probe(target, backend_ip, 8080).ok, timeout=10, interval=1)
        assert seeded, "the name-allow host route was never seeded within 10s of the DNS answer"

        other = tcp_probe(target, "8.8.8.8", 443)
        assert not other.ok, "an unrelated destination must remain denied under default:deny"

        details = f"pre-DNS connect to {backend_ip}:8080 denied={not baseline.ok}; nslookup resolved to {backend_ip}; post-DNS connect allowed={seeded}; unrelated dest still denied={not other.ok}"
        return ScenarioResult("4_fqdn_allow", "PROVEN", details)
    finally:
        if cid:
            daemon.release(cid)
        docker_rm(backend)
        docker_rm(target)
        network_rm(net)


def scenario_5_fqdn_deny(daemon: Daemon) -> ScenarioResult:
    net = "bathyscaphe-itest-fqdn-deny-net"
    backend = "bathyscaphe-itest-fqdn-deny-backend"
    target = "bathyscaphe-itest-fqdn-deny-target"
    network_rm(net)
    docker_rm(backend)
    docker_rm(target)
    network_create(net)
    docker_run(backend, network=net, cmd=["nc", "-lk", "-p", "8080"])
    docker_run(target, network=net)
    cid = None
    try:
        cid = docker_id(target)
        backend_ip = docker_ip(backend, net)

        ack = daemon.push_policy(cid, mode="block", default="allow", rules=[name_rule("r-name-deny", "deny", backend, 8080, "tcp")])
        assert ack["status"] == "applied", ack

        baseline = tcp_probe(target, backend_ip, 8080)
        assert baseline.ok, "before any DNS answer is observed, default:allow means the bare IP connects fine (no host route yet)"

        resolved = docker_exec(target, "nslookup", backend + ".", timeout=8)
        assert resolved.returncode == 0 and backend_ip in resolved.stdout, f"nslookup {backend} should resolve to {backend_ip}: {resolved.stdout} {resolved.stderr}"

        denied = wait_until(lambda: not tcp_probe(target, backend_ip, 8080).ok, timeout=10, interval=1)
        assert denied, "the name-deny host route was never seeded/enforced within 10s of the DNS answer"

        other = tcp_probe(target, "1.1.1.1", 443)
        assert other.ok, "default:allow must still allow an unrelated destination"

        details = f"pre-DNS connect to {backend_ip}:8080 allowed={baseline.ok}; nslookup resolved to {backend_ip}; post-DNS connect denied={denied}; unrelated dest still allowed={other.ok}"
        return ScenarioResult("5_fqdn_deny", "PROVEN", details)
    finally:
        if cid:
            daemon.release(cid)
        docker_rm(backend)
        docker_rm(target)
        network_rm(net)


def scenario_6_untrusted_resolver() -> ScenarioResult:
    # NOTE: this scenario runs against its OWN dedicated daemon/bpffs root
    # (UNTRUSTED_ROOT), NOT the shared MAIN daemon scenarios 1/2/4/5 use.
    # This is deliberate, not incidental: `crate::dns::pending::PendingQueryTable`
    # (the query/response correlation table `daemon::Daemon::run` shares
    # across every container in one process) is a GLOBAL table keyed only
    # by `(txid, dst_port)`, swept on a 5-second TTL, and its own module
    # doc's collision-safety argument ("the OS kernel's own port allocator
    # guarantees uniqueness ... for a single querying process/socket") does
    # not hold across DIFFERENT containers: each container gets its OWN
    # network namespace with its OWN independently-reset ephemeral port
    # allocator, so two different containers' first-ever UDP sockets are
    # actually quite likely to pick the SAME low ephemeral port, and
    # busybox/musl's DNS transaction id generation is not necessarily
    # strongly random either. Running this suite's scenarios 4 and 5
    # (each doing several DNS round trips) immediately before this one, in
    # the SAME daemon session, was found LIVE to reproduce exactly this: a
    # stale `(txid, port)` entry left over from an already-finished,
    # already-`release`d scenario-4/5 container collided with this
    # scenario's own query, `capture_callback` (`crate::dns::mod::capture_callback`)
    # UNCONDITIONALLY preferred the (stale, wrong) correlated cgroup_id
    # over the response capture's own (already-correct, since this
    # scenario's resolver is reached directly with no injection/relay in
    # the way) cgroup_id, `on_dns_answer` looked up name patterns for that
    # wrong, already-`release`d cgroup id (none registered any more), and
    # the `dns.untrusted_answer` record silently never fired -- 5/5
    # repeats after running scenarios 4+5 first, 0/5 failures running
    # standalone or after scenarios that do not touch DNS. This is a real
    # design-level finding (see docs/TESTING.md and the final report for
    # the full account) escalated rather than fixed here, per the build
    # brief's instruction for anything design-level. Isolating this
    # scenario in its own daemon/bpffs root sidesteps it for THIS harness's
    # own purposes (a fresh process starts with an empty correlation
    # table) without masking or working around the underlying issue.
    root = UNTRUSTED_ROOT
    net = "bathyscaphe-itest-untrusted-net"
    rogue = "bathyscaphe-itest-untrusted-rogue"
    target = "bathyscaphe-itest-untrusted-target"
    forbidden_ip = "203.0.113.7"  # TEST-NET-3 (RFC 5737): documentation-only, never a real destination.
    domain = "allowed.itest.internal"
    subprocess.run(["rm", "-rf", root])
    network_rm(net)
    docker_rm(rogue)
    docker_rm(target)
    network_create(net)
    docker_run(rogue, network=net, cmd=["sh", "-c", f"apk add --no-cache dnsmasq >/tmp/apk.log 2>&1 && exec dnsmasq --no-daemon --no-resolv --no-hosts --address=/#/{forbidden_ip} --log-queries"])
    cid = None
    daemon = None
    try:
        daemon = Daemon(root, stats_interval_s=1)
        daemon.handshake()
        rogue_ready = wait_until(lambda: subprocess.run(["docker", "exec", rogue, "pgrep", "dnsmasq"], capture_output=True).returncode == 0, timeout=30, interval=1)
        assert rogue_ready, "the rogue dnsmasq resolver never started (apk install or dnsmasq startup failed)"
        rogue_ip = docker_ip(rogue, net)

        # NOTE: `docker run --dns <ip>` does NOT make the query leave the
        # container's netns addressed to that IP -- Docker still hands the
        # container 127.0.0.11 as its nameserver and has its OWN embedded
        # proxy relay to the given "ExtServers" address, so `dns_snoop`
        # would capture the RELAYED answer's source as 127.0.0.11 (trusted
        # by default), defeating this scenario's entire point. Verified
        # live (`docker exec ... cat /etc/resolv.conf` shows `nameserver
        # 127.0.0.11` even with `--dns` given; `ExtServers` is where the
        # real target moved to). Rewriting /etc/resolv.conf directly after
        # the container starts bypasses Docker's proxy substitution
        # entirely -- the query then genuinely leaves addressed straight at
        # the rogue container's own IP, which is what makes this an actual
        # test of the untrusted-source path rather than an accidental
        # trusted one.
        docker_run(target, network=net)
        cid = docker_id(target)
        rewritten = docker_exec(target, "sh", "-c", f"echo 'nameserver {rogue_ip}' > /etc/resolv.conf")
        assert rewritten.returncode == 0, f"failed to point the target's resolver straight at the rogue container: {rewritten.stderr}"

        # Same DNS-is-ordinary-egress-traffic note as scenario 4: default:deny
        # needs an explicit allow for the query to the (untrusted, but still
        # network-reachable) rogue resolver, or the query itself never leaves.
        ack = daemon.push_policy(
            cid,
            mode="block",
            default="deny",
            rules=[
                name_rule("r-name-allow", "allow", domain, 443, "tcp"),
                cidr_rule("r-allow-dns", "allow", f"{rogue_ip}/32", 53, "udp"),
            ],
        )
        assert ack["status"] == "applied", ack

        baseline_denied = tcp_probe(target, forbidden_ip, 443)
        assert not baseline_denied.ok, "sanity: the forbidden IP must be denied before any DNS traffic happens at all"

        # `dns_snoop` is a best-effort, ring-buffer-based OBSERVATION
        # capture, not a reliable retransmission-backed channel (see
        # docs/DNS.md / docs/TESTING.md chunk #9: a capture can legitimately
        # be missed under load, with no counter tracking that specific
        # loss, since a lost DNS observation is never treated as a
        # security-relevant drop the way a lost connect/sendmsg event is).
        # The client-side resolution itself (the `nslookup` below) is NOT
        # flaky -- it reliably gets the forbidden IP back every time -- but
        # bathyscaphe's own passive capture of that same answer occasionally
        # is, so this retries the query rather than treating one missed
        # capture as a scenario failure.
        events: list = []
        sec = None
        last_resolved = None
        for attempt in range(5):
            last_resolved = docker_exec(target, "nslookup", domain + ".", timeout=8)
            # Not gating on returncode: busybox nslookup queries A then AAAA
            # by default and exits nonzero if EITHER lookup fails; dnsmasq's
            # wildcard `address=/#/<ipv4>` only ever answers the A query, so
            # the AAAA query legitimately comes back REFUSED/NODATA even on
            # a complete, successful A resolution. The forbidden IP actually
            # appearing in the output is what matters here.
            assert forbidden_ip in last_resolved.stdout, f"the rogue resolver should answer with the forbidden IP: {last_resolved.stdout} {last_resolved.stderr}"
            sec = daemon.wait_for(lambda m: m.get("kind") == "security" and m.get("attributes", {}).get("reason") == "dns.untrusted_answer" and m.get("attributes", {}).get("container.id") == cid, timeout=4, drain_into=events)
            if sec is not None:
                break
            log(f"attempt {attempt + 1}/5: client resolved fine but bathyscaphe's own dns_snoop capture missed this answer (a documented best-effort characteristic); retrying the query")
        assert sec is not None, f"expected a dns.untrusted_answer security record for this container after 5 attempts; drained: {events}"

        # No amount of waiting should ever seed it.
        time.sleep(3)
        still_denied = tcp_probe(target, forbidden_ip, 443)
        assert not still_denied.ok, "an untrusted-sourced answer must never seed the allow-map, even though the name pattern matched"

        details = f"security record reason={sec['attributes']['reason']!r} resolver.addr={sec['attributes'].get('resolver.addr')!r} domain={sec['attributes'].get('domain')!r}; forbidden IP denied before={not baseline_denied.ok} and after 3s settle={not still_denied.ok}"
        return ScenarioResult("6_untrusted_resolver", "PROVEN", details)
    finally:
        if daemon is not None:
            daemon.shutdown()
            daemon.wait_exit(timeout=10)
            if daemon.proc.poll() is None:
                daemon.kill()
        docker_rm(rogue)
        docker_rm(target)
        network_rm(net)
        subprocess.run(["rm", "-rf", root])


def scenario_7_reconciliation() -> ScenarioResult:
    root = RECONCILE_ROOT
    name = "bathyscaphe-itest-reconcile-target"
    subprocess.run(["rm", "-rf", root])
    docker_rm(name)
    docker_run(name)
    daemon1 = None
    daemon2 = None
    try:
        cid = docker_id(name)

        daemon1 = Daemon(root, stats_interval_s=1)
        daemon1.handshake()
        ack = daemon1.push_policy(cid, mode="block", default="deny", rules=[cidr_rule("r-allow", "allow", "1.1.1.1/32", 443, "tcp")])
        assert ack["status"] == "applied", ack

        baseline_deny = tcp_probe(name, "8.8.8.8", 443)
        assert not baseline_deny.ok, "sanity: enforcement must be live before we test the restart/reconciliation path"

        daemon1.kill()

        daemon2 = Daemon(root, stats_interval_s=1)
        hello2 = daemon2.handshake()
        pinned_ids = [p["container_id"] for p in hello2["pinned"]]
        assert cid in pinned_ids, f"the pinned inventory must report the surviving container; got {pinned_ids}"

        # Deliberately do NOT re-push policy for this container -- simulate
        # airlock's reconciliation pass covering every OTHER container but
        # this one, then declaring the pass complete anyway.
        daemon2.sync_complete()

        stats_msg = daemon2.wait_for(lambda m: m.get("kind") == "stats" and any(c.get("id") == cid for c in m.get("containers", [])), timeout=8)
        assert stats_msg is not None, "no stats message ever reported this container after sync_complete"
        entry = next(c for c in stats_msg["containers"] if c["id"] == cid)
        assert entry["orphaned"] is True, f"a pinned-but-uncovered container must be marked orphaned: {entry}"
        assert entry["enforcing"] is True, f"an orphaned container must still be enforcing: {entry}"
        assert entry["mode"] == "block", entry

        still_denied = tcp_probe(name, "8.8.8.8", 443)
        assert not still_denied.ok, "orphaned enforcement must still actually block traffic in the kernel"

        details = f"hello.pinned (fresh run) contained {cid[:12]}..; post-sync_complete stats entry={entry}; still enforcing (denied)={not still_denied.ok}"
        return ScenarioResult("7_reconciliation", "PROVEN", details)
    finally:
        if daemon1 is not None and daemon1.proc.poll() is None:
            daemon1.kill()
        if daemon2 is not None and daemon2.proc.poll() is None:
            daemon2.kill()
        docker_rm(name)
        subprocess.run(["rm", "-rf", root])
