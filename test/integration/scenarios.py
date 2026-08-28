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
import struct
import subprocess
import threading
import time

from driver import (
    Daemon,
    ScenarioResult,
    cidr_rule,
    docker_exec,
    docker_exec_stdin,
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
XCORR_ROOT = "/sys/fs/bpf/bathyscaphe-itest-xcorr"


def _build_dns_a_query(txid: int, qname: str) -> bytes:
    """Hand-crafts a minimal, valid DNS query (one question, type A, class
    IN) with an EXPLICIT transaction id -- used by
    `scenario_9_cross_container_isolation` to FORCE a `(txid, port)`
    collision between two different containers deterministically, rather
    than hoping for one to occur naturally."""
    header = struct.pack(">HHHHHH", txid, 0x0100, 1, 0, 0, 0)  # flags: RD set
    labels = [label for label in qname.split(".") if label]
    encoded_name = b"".join(bytes([len(label)]) + label.encode("ascii") for label in labels) + b"\x00"
    question = encoded_name + struct.pack(">HH", 1, 1)  # QTYPE=A, QCLASS=IN
    return header + question


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


def _untrusted_resolver_flow(daemon: Daemon, scenario_name: str, suffix: str) -> ScenarioResult:
    """Shared body for scenario 6 (its own dedicated daemon) and scenario 8
    (the shared MAIN daemon, deliberately run AFTER scenarios 4 and 5 in the
    same process -- see `scenario_8_untrusted_resolver_shared_daemon`'s own
    doc for why). `suffix` keeps each caller's Docker objects from
    colliding when both run in the same suite invocation."""
    net = f"bathyscaphe-itest-untrusted-net{suffix}"
    rogue = f"bathyscaphe-itest-untrusted-rogue{suffix}"
    target = f"bathyscaphe-itest-untrusted-target{suffix}"
    forbidden_ip = "203.0.113.7"  # TEST-NET-3 (RFC 5737): documentation-only, never a real destination.
    domain = "allowed.itest.internal"
    network_rm(net)
    docker_rm(rogue)
    docker_rm(target)
    network_create(net)
    docker_run(rogue, network=net, cmd=["sh", "-c", f"apk add --no-cache dnsmasq >/tmp/apk.log 2>&1 && exec dnsmasq --no-daemon --no-resolv --no-hosts --address=/#/{forbidden_ip} --log-queries"])
    cid = None
    try:
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
        #
        # A SECOND reason this needs real retry budget when `daemon` is the
        # SHARED main daemon (`scenario_8_untrusted_resolver_shared_daemon`):
        # `daemon::security::SecurityEmitter` is ONE shared Falco-pattern
        # token bucket (burst 5, refill 1/30s, `daemon::throttle`) for EVERY
        # loud record this whole daemon session ever emits, by design
        # (`docs/DNS.md`/`security.rs`'s own doc: a storm of ANY reason code
        # draws from the same bounded budget). Scenarios 4 and 5 legitimately
        # drive several `policy.name_unresolved_block`/`enforce.blocked`
        # records of their own (each `wait_until` poll against a still-denied
        # destination is itself a `mode: block` deny with no domain and an
        # active name-allow pattern) before this scenario ever runs, which
        # can leave the shared bucket needing a real refill interval before
        # THIS scenario's own `dns.untrusted_answer` record can be admitted
        # -- an orthogonal, pre-existing throttle-budget characteristic of
        # running many DNS-active scenarios in one session, not a
        # correlation bug, and not something build chunk #14 is trying to
        # fix. The retry budget below (up to ~75s total) comfortably spans
        # two refill intervals so this scenario's PASS/FAIL reflects whether
        # the answer was ever correctly attributed and reported at all, not
        # an accident of exactly which token-bucket instant it landed on.
        events: list = []
        sec = None
        last_resolved = None
        max_attempts = 25
        for attempt in range(max_attempts):
            last_resolved = docker_exec(target, "nslookup", domain + ".", timeout=8)
            # Not gating on returncode: busybox nslookup queries A then AAAA
            # by default and exits nonzero if EITHER lookup fails; dnsmasq's
            # wildcard `address=/#/<ipv4>` only ever answers the A query, so
            # the AAAA query legitimately comes back REFUSED/NODATA even on
            # a complete, successful A resolution. The forbidden IP actually
            # appearing in the output is what matters here.
            assert forbidden_ip in last_resolved.stdout, f"the rogue resolver should answer with the forbidden IP: {last_resolved.stdout} {last_resolved.stderr}"
            sec = daemon.wait_for(lambda m: m.get("kind") == "security" and m.get("attributes", {}).get("reason") == "dns.untrusted_answer" and m.get("attributes", {}).get("container.id") == cid, timeout=3, drain_into=events)
            if sec is not None:
                break
            log(f"attempt {attempt + 1}/{max_attempts}: client resolved fine but bathyscaphe's own dns_snoop capture missed this answer, or the shared R1 throttle hasn't refilled yet; retrying the query")
        assert sec is not None, f"expected a dns.untrusted_answer security record for this container after {max_attempts} attempts; drained: {events}"

        # No amount of waiting should ever seed it.
        time.sleep(3)
        still_denied = tcp_probe(target, forbidden_ip, 443)
        assert not still_denied.ok, "an untrusted-sourced answer must never seed the allow-map, even though the name pattern matched"

        details = f"security record reason={sec['attributes']['reason']!r} resolver.addr={sec['attributes'].get('resolver.addr')!r} domain={sec['attributes'].get('domain')!r}; forbidden IP denied before={not baseline_denied.ok} and after 3s settle={not still_denied.ok}"
        return ScenarioResult(scenario_name, "PROVEN", details)
    finally:
        if cid:
            daemon.release(cid)
        docker_rm(rogue)
        docker_rm(target)
        network_rm(net)


def scenario_6_untrusted_resolver() -> ScenarioResult:
    # This scenario runs against its OWN dedicated daemon/bpffs root
    # (UNTRUSTED_ROOT), NOT the shared MAIN daemon scenarios 1/2/4/5 use --
    # kept that way for isolation (a fresh process starts with an empty
    # correlation table, so this scenario proves its own claim with no
    # dependency on run order at all). Build chunk #13 found (and build
    # chunk #14 FIXED, see `docs/TESTING.md`'s "Build chunk #14" section)
    # a real cross-container DNS correlation bug that made running THIS
    # scenario's logic sharing a daemon session with scenarios 4/5
    # unreliable; `scenario_8_untrusted_resolver_shared_daemon` below is
    # the scenario that specifically re-runs this exact logic against the
    # SHARED main daemon, right after 4 and 5, to prove that bug is now
    # fixed -- this scenario stays isolated as the original, dependency-free
    # proof of the untrusted-resolver behavior itself.
    root = UNTRUSTED_ROOT
    subprocess.run(["rm", "-rf", root])
    daemon = None
    try:
        daemon = Daemon(root, stats_interval_s=1)
        daemon.handshake()
        return _untrusted_resolver_flow(daemon, "6_untrusted_resolver", "")
    finally:
        if daemon is not None:
            daemon.shutdown()
            daemon.wait_exit(timeout=10)
            if daemon.proc.poll() is None:
                daemon.kill()
        subprocess.run(["rm", "-rf", root])


def scenario_8_untrusted_resolver_shared_daemon(daemon: Daemon) -> ScenarioResult:
    """Build chunk #14's regression proof for the chunk #13 finding: runs
    the IDENTICAL untrusted-resolver logic as scenario 6, but against the
    SHARED `daemon` (the same MAIN daemon session scenarios 1/2/4/5 already
    ran against) -- this is the exact live repro chunk #13 documented
    (`docs/TESTING.md`, "Build chunk #13", bug #1): scenarios 4 and 5 each
    do several real DNS round trips and `release()` their containers, which
    used to leave STALE `PendingQueryTable` entries behind that a later,
    unrelated container's query could collide with. Build chunk #14 fixed
    this two ways that both apply here: (a) `apply_release` now purges a
    released container's pending entries (`crate::dns::pending`'s "Cleanup
    on release"), so scenarios 4/5's own entries are gone by the time this
    scenario's query fires; (b) even if a collision still happened, the
    correlation table now detects the ambiguity and refuses to guess rather
    than silently preferring a stale, wrong cgroup id. Depends on the
    DEFAULT run order (`run_integration.py`'s `SCENARIOS` dict runs
    scenarios in ascending number order, so 4 and 5 have already executed
    against this same `daemon` by the time this one starts) -- run in
    isolation (e.g. `run_integration.py 8`) this scenario still passes, it
    just no longer specifically exercises the "after 4/5" ordering that
    used to matter."""
    return _untrusted_resolver_flow(daemon, "8_untrusted_resolver_shared_daemon", "-shared")


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


def scenario_9_cross_container_isolation() -> ScenarioResult:
    """Build chunk #14's direct security proof: two DIFFERENT containers,
    each with its OWN active name-allow pattern for BOTH backends, are made
    to send a DNS query with the EXACT SAME transaction id and source port
    to Docker's embedded resolver at (as close to) the same instant --
    deterministically forcing the exact `(txid, port)` collision
    `docs/TESTING.md`'s chunk #13 finding showed is practically reachable,
    rather than hoping real ephemeral-port/txid randomness produces one.
    Each container only ever queries its OWN backend's name -- so the ONLY
    way either container's `POLICY` map could ever gain a route to the
    OTHER backend's resolved address is a cross-container misattribution of
    the other container's answer. Asserts that never happens, in either
    direction, and that the fix's fail-safe (refuse to guess, in EITHER
    direction, rather than pick one) doesn't silently break normal,
    non-colliding DNS resolution afterward."""
    root = XCORR_ROOT
    net = "bathyscaphe-itest-xcorr-net"
    backend_a = "bathyscaphe-itest-xcorr-backend-a"
    backend_b = "bathyscaphe-itest-xcorr-backend-b"
    target_a = "bathyscaphe-itest-xcorr-a"
    target_b = "bathyscaphe-itest-xcorr-b"
    subprocess.run(["rm", "-rf", root])
    network_rm(net)
    for name in (backend_a, backend_b, target_a, target_b):
        docker_rm(name)
    network_create(net)
    docker_run(backend_a, network=net, cmd=["nc", "-lk", "-p", "8080"])
    docker_run(backend_b, network=net, cmd=["nc", "-lk", "-p", "8080"])
    docker_run(target_a, network=net)
    docker_run(target_b, network=net)
    cid_a = None
    cid_b = None
    daemon = None
    try:
        backend_a_ip = docker_ip(backend_a, net)
        backend_b_ip = docker_ip(backend_b, net)

        daemon = Daemon(root, stats_interval_s=1)
        daemon.handshake()

        cid_a = docker_id(target_a)
        cid_b = docker_id(target_b)

        # BOTH containers register allow patterns for BOTH backend names --
        # deliberately, so that a route to the OTHER backend can ONLY ever
        # appear via cross-attribution of the other container's own answer,
        # never via this container's own genuine traffic (each only ever
        # queries its own name below).
        rules = [
            name_rule("r-allow-a", "allow", backend_a, 8080, "tcp"),
            name_rule("r-allow-b", "allow", backend_b, 8080, "tcp"),
            cidr_rule("r-allow-dns", "allow", "127.0.0.11/32", 53, "udp"),
        ]
        ack_a = daemon.push_policy(cid_a, mode="block", default="deny", rules=rules)
        assert ack_a["status"] == "applied", ack_a
        ack_b = daemon.push_policy(cid_b, mode="block", default="deny", rules=rules)
        assert ack_b["status"] == "applied", ack_b

        baseline_a_to_b = tcp_probe(target_a, backend_b_ip, 8080)
        baseline_b_to_a = tcp_probe(target_b, backend_a_ip, 8080)
        assert not baseline_a_to_b.ok and not baseline_b_to_a.ok, "sanity: neither cross-route exists before any DNS traffic happens at all"

        # Force the collision: an IDENTICAL (txid, source port) DNS query,
        # each container asking for its OWN backend's name, fired as close
        # to simultaneously as this harness can manage.
        forced_txid = 0x5A5A
        forced_port = 44100
        query_a = _build_dns_a_query(forced_txid, backend_a)
        query_b = _build_dns_a_query(forced_txid, backend_b)

        results: dict[str, subprocess.CompletedProcess] = {}

        def fire(name: str, container: str, payload: bytes) -> None:
            results[name] = docker_exec_stdin(container, ["nc", "-u", "-p", str(forced_port), "-w", "2", "127.0.0.11", "53"], payload, timeout=5)

        t_a = threading.Thread(target=fire, args=("a", target_a, query_a))
        t_b = threading.Thread(target=fire, args=("b", target_b, query_b))
        t_a.start()
        t_b.start()
        t_a.join(timeout=6)
        t_b.join(timeout=6)
        assert results["a"].returncode == 0, f"container A's crafted query failed: {results['a']}"
        assert results["b"].returncode == 0, f"container B's crafted query failed: {results['b']}"
        assert len(results["a"].stdout) > 0, "container A's crafted query got no DNS response at all"
        assert len(results["b"].stdout) > 0, "container B's crafted query got no DNS response at all"

        # Give the (best-effort, ring-buffer-based) DNS capture pipeline a
        # moment to actually process both responses.
        time.sleep(2)

        # The security property: NEITHER container ever gets a route to the
        # OTHER's backend, in EITHER direction -- this is the direct proof
        # that container A's answer never seeds container B's POLICY map
        # (and vice versa).
        cross_a_to_b = tcp_probe(target_a, backend_b_ip, 8080)
        cross_b_to_a = tcp_probe(target_b, backend_a_ip, 8080)
        assert not cross_a_to_b.ok, "container A must NEVER be seeded with a route to container B's backend via a forced correlation collision"
        assert not cross_b_to_a.ok, "container B must NEVER be seeded with a route to container A's backend via a forced correlation collision"

        # Recovery: a later, NON-colliding, ordinary DNS lookup (the OS
        # picks a fresh ephemeral port, no forced collision) must still let
        # each container reach its OWN backend -- the fix fails safe during
        # a genuine ambiguity, it does not permanently wedge DNS-derived
        # enforcement.
        resolved_a = docker_exec(target_a, "nslookup", backend_a + ".", timeout=8)
        assert resolved_a.returncode == 0 and backend_a_ip in resolved_a.stdout, f"container A's own (non-colliding) lookup should resolve fine: {resolved_a.stdout} {resolved_a.stderr}"
        resolved_b = docker_exec(target_b, "nslookup", backend_b + ".", timeout=8)
        assert resolved_b.returncode == 0 and backend_b_ip in resolved_b.stdout, f"container B's own (non-colliding) lookup should resolve fine: {resolved_b.stdout} {resolved_b.stderr}"

        seeded_a = wait_until(lambda: tcp_probe(target_a, backend_a_ip, 8080).ok, timeout=10, interval=1)
        seeded_b = wait_until(lambda: tcp_probe(target_b, backend_b_ip, 8080).ok, timeout=10, interval=1)
        assert seeded_a, "container A must recover and reach its OWN backend once its DNS answer is unambiguous"
        assert seeded_b, "container B must recover and reach its OWN backend once its DNS answer is unambiguous"

        # The cross-routes must STILL never have appeared, even after the
        # containers' own (correct) routes were seeded.
        still_cross_a_to_b = tcp_probe(target_a, backend_b_ip, 8080)
        still_cross_b_to_a = tcp_probe(target_b, backend_a_ip, 8080)
        assert not still_cross_a_to_b.ok, "container A must still never reach container B's backend, even after its own backend was correctly seeded"
        assert not still_cross_b_to_a.ok, "container B must still never reach container A's backend, even after its own backend was correctly seeded"

        details = (
            f"forced (txid=0x{forced_txid:04x}, port={forced_port}) collision fired for both containers; "
            f"immediately after: A->B cross-route denied={not cross_a_to_b.ok}, B->A cross-route denied={not cross_b_to_a.ok}; "
            f"after recovery: A->own backend allowed={seeded_a}, B->own backend allowed={seeded_b}, "
            f"A->B still denied={not still_cross_a_to_b.ok}, B->A still denied={not still_cross_b_to_a.ok}"
        )
        return ScenarioResult("9_cross_container_isolation", "PROVEN", details)
    finally:
        if daemon is not None:
            if cid_a:
                daemon.release(cid_a)
            if cid_b:
                daemon.release(cid_b)
            daemon.shutdown()
            daemon.wait_exit(timeout=10)
            if daemon.proc.poll() is None:
                daemon.kill()
        for name in (backend_a, backend_b, target_a, target_b):
            docker_rm(name)
        network_rm(net)
        subprocess.run(["rm", "-rf", root])
