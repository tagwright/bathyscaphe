#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""
Core harness library for bathyscaphe's end-to-end integration tests.

This is what drives ``bathyscaphe run`` the way airlock will: a direct child
process, NDJSON on its stdin/stdout, human logs on its stderr. It is
deliberately not a mock of anything -- ``Daemon`` below spawns the real
release binary, and every helper in this file that touches "a container"
means a real Docker container reached through the real Docker socket.

Meant to be run as root inside a privileged container with a writable
bpffs at /sys/fs/bpf, cgroup v2 at /sys/fs/cgroup (host view, i.e.
--cgroupns=host), and the Docker socket bind-mounted -- see
docs/TESTING.md's "Running the integration suite" section for the exact
setup this was proven against.
"""

from __future__ import annotations

import json
import os
import queue
import subprocess
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Optional

BATHYSCAPHE_BIN = os.environ.get("BATHYSCAPHE_BIN", "/workspace/bathyscaphe/target/release/bathyscaphe")
ITEST_PREFIX = "bathyscaphe-itest-"


def log(msg: str) -> None:
    print(f"[driver] {msg}", flush=True)


# --------------------------------------------------------------------------
# The daemon subprocess: NDJSON stdin/stdout, exactly the shape airlock uses.
# --------------------------------------------------------------------------


class Daemon:
    """Wraps one `bathyscaphe run` subprocess. A direct child of THIS
    process (never through a nested `docker exec`), so `kill()` sends
    SIGKILL straight to the real bathyscaphe process -- no ambiguity about
    what a signal actually reaches, which matters for the fail-safe
    (probe-death) scenario."""

    def __init__(self, bpffs_root: str, cgroup_root: str = "/sys/fs/cgroup", extra_args: Optional[list[str]] = None, stats_interval_s: int = 1):
        self.bpffs_root = bpffs_root
        self.stats_interval_s = stats_interval_s
        args = [BATHYSCAPHE_BIN, "--log-format", "json", "run", "--bpffs-root", bpffs_root, "--cgroup-root", cgroup_root]
        if extra_args:
            args += extra_args
        log(f"spawning: {' '.join(args)}")
        self.proc = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
        self.up_q: "queue.Queue[dict]" = queue.Queue()
        self.err_lines: list[str] = []
        self._t_out = threading.Thread(target=self._read_stdout, daemon=True)
        self._t_err = threading.Thread(target=self._read_stderr, daemon=True)
        self._t_out.start()
        self._t_err.start()

    def _read_stdout(self) -> None:
        assert self.proc.stdout is not None
        for line in self.proc.stdout:
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                log(f"UNPARSEABLE stdout line: {line!r}")
                continue
            self.up_q.put(msg)

    def _read_stderr(self) -> None:
        assert self.proc.stderr is not None
        for line in self.proc.stderr:
            self.err_lines.append(line.rstrip())

    def send(self, obj: dict) -> None:
        assert self.proc.stdin is not None
        line = json.dumps(obj)
        self.proc.stdin.write(line + "\n")
        self.proc.stdin.flush()

    def wait_for(self, predicate: Callable[[dict], bool], timeout: float = 10.0, drain_into: Optional[list] = None) -> Optional[dict]:
        deadline = time.time() + timeout
        while True:
            remaining = deadline - time.time()
            if remaining <= 0:
                return None
            try:
                msg = self.up_q.get(timeout=remaining)
            except queue.Empty:
                return None
            if drain_into is not None:
                drain_into.append(msg)
            if predicate(msg):
                return msg

    def drain_for(self, seconds: float, into: list) -> None:
        """Collects every UpMessage arriving over the next `seconds`
        (does not stop early on a match -- for "did N things happen"
        checks rather than "did the first matching thing happen")."""
        deadline = time.time() + seconds
        while True:
            remaining = deadline - time.time()
            if remaining <= 0:
                return
            try:
                msg = self.up_q.get(timeout=remaining)
            except queue.Empty:
                return
            into.append(msg)

    def handshake(self, timeout: float = 15.0) -> dict:
        hello = self.wait_for(lambda m: m.get("kind") == "hello", timeout=timeout)
        if hello is None:
            raise AssertionError(f"no `hello` received within {timeout}s; stderr tail:\n" + "\n".join(self.err_lines[-40:]))
        self.send({"kind": "start", "proto": 1, "stats_interval_s": self.stats_interval_s})
        return hello

    def push_policy(self, container_id: str, mode: str, default: str, rules: list, generation: int = 1, retries: int = 8, retry_delay: float = 1.0) -> dict:
        """Pushes a policy and waits for its ack, retrying on the
        container-creation race `daemon::apply::resolve_or_attach`
        documents (the target container's cgroup not yet discovered by
        `AttributionService`'s inotify walk)."""
        last_ack: Optional[dict] = None
        for attempt in range(retries):
            self.send({"kind": "policy", "container_id": container_id, "generation": generation, "mode": mode, "default": default, "rules": rules})
            ack = self.wait_for(lambda m: m.get("kind") == "policy_ack" and m.get("container_id") == container_id and m.get("generation") == generation, timeout=5.0)
            if ack is None:
                raise AssertionError("no policy_ack received at all")
            last_ack = ack
            if ack.get("status") == "applied":
                return ack
            log(f"policy_ack error (attempt {attempt + 1}/{retries}): {ack.get('error')}")
            time.sleep(retry_delay)
        raise AssertionError(f"policy never applied after {retries} attempts: {last_ack}")

    def release(self, container_id: str, timeout: float = 10.0) -> Optional[dict]:
        self.send({"kind": "release", "container_id": container_id})
        return self.wait_for(lambda m: m.get("kind") == "release_ack" and m.get("container_id") == container_id, timeout=timeout)

    def sync_complete(self) -> None:
        self.send({"kind": "sync_complete"})

    def shutdown(self) -> None:
        self.send({"kind": "shutdown"})

    def wait_exit(self, timeout: float = 10.0) -> Optional[int]:
        try:
            return self.proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            return None

    def kill(self) -> None:
        """SIGKILL, direct to the real bathyscaphe process (this is a
        direct child, not wrapped by a nested `docker exec`)."""
        try:
            self.proc.kill()
        except ProcessLookupError:
            pass
        self.proc.wait(timeout=10)

    def pid(self) -> int:
        return self.proc.pid


# --------------------------------------------------------------------------
# Rule builders -- plain dicts matching bathyscaphe-proto's wire shapes
# exactly (docs/PROTOCOL.md section 4).
# --------------------------------------------------------------------------


def cidr_rule(rule_id: str, action: str, cidr: str, port: Optional[int] = None, proto: Optional[str] = None, source: str = "static") -> dict:
    match = {"type": "cidr", "cidr": cidr, "port": port}
    if proto is not None:
        match["proto"] = proto
    return {"id": rule_id, "action": action, "match": match, "expires_at": None, "source": source}


def name_rule(rule_id: str, action: str, pattern: str, port: Optional[int] = None, proto: Optional[str] = None, source: str = "static") -> dict:
    match = {"type": "name", "pattern": pattern, "port": port}
    if proto is not None:
        match["proto"] = proto
    return {"id": rule_id, "action": action, "match": match, "expires_at": None, "source": source}


# --------------------------------------------------------------------------
# Docker helpers. Every object this harness creates is named
# `bathyscaphe-itest-*`; `nuke_all_itest_objects` is the one function that
# must be called on every exit path (success or failure).
# --------------------------------------------------------------------------


def _docker(*args: str, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(["docker", *args], check=check, capture_output=True, text=True)


def docker_run(name: str, image: str = "alpine:latest", network: Optional[str] = None, dns: Optional[str] = None, cmd: Optional[list[str]] = None, extra_args: Optional[list[str]] = None) -> str:
    args = ["run", "-d", "--name", name]
    if network:
        args += ["--network", network]
    if dns:
        args += ["--dns", dns]
    if extra_args:
        args += extra_args
    args.append(image)
    if cmd:
        args += cmd
    else:
        args += ["sleep", "600"]
    result = _docker(*args)
    return result.stdout.strip()


def docker_id(name: str) -> str:
    return _docker("inspect", "-f", "{{.Id}}", name).stdout.strip()


def docker_ip(name: str, network: str) -> str:
    return _docker("inspect", "-f", "{{(index .NetworkSettings.Networks \"" + network + "\").IPAddress}}", name).stdout.strip()


def docker_exec(name: str, *cmd: str, timeout: float = 15.0) -> subprocess.CompletedProcess:
    return subprocess.run(["docker", "exec", name, *cmd], capture_output=True, text=True, timeout=timeout)


def docker_rm(name: str) -> None:
    subprocess.run(["docker", "rm", "-f", name], capture_output=True, text=True)


def network_create(name: str) -> None:
    _docker("network", "create", name)


def network_rm(name: str) -> None:
    subprocess.run(["docker", "network", "rm", name], capture_output=True, text=True)


def nuke_all_itest_objects() -> None:
    """Removes every `bathyscaphe-itest-*` container and network. Never
    touches anything else -- this is the one cleanup function every
    scenario's `finally` (and the top-level runner) calls."""
    result = subprocess.run(["docker", "ps", "-a", "--filter", f"name=^/{ITEST_PREFIX}", "--format", "{{.Names}}"], capture_output=True, text=True)
    names = [n for n in result.stdout.splitlines() if n.strip()]
    for name in names:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True, text=True)
    if names:
        log(f"removed containers: {names}")

    result = subprocess.run(["docker", "network", "ls", "--filter", f"name={ITEST_PREFIX}", "--format", "{{.Name}}"], capture_output=True, text=True)
    net_names = [n for n in result.stdout.splitlines() if n.strip()]
    for name in net_names:
        subprocess.run(["docker", "network", "rm", name], capture_output=True, text=True)
    if net_names:
        log(f"removed networks: {net_names}")

    result = subprocess.run(["docker", "images", "--filter", f"reference={ITEST_PREFIX}*", "--format", "{{.Repository}}:{{.Tag}}"], capture_output=True, text=True)
    img_names = [n for n in result.stdout.splitlines() if n.strip()]
    for name in img_names:
        subprocess.run(["docker", "rmi", "-f", name], capture_output=True, text=True)
    if img_names:
        log(f"removed images: {img_names}")


def unpin_all(bpffs_root: str) -> subprocess.CompletedProcess:
    return subprocess.run([BATHYSCAPHE_BIN, "unpin", "--all", "--bpffs-root", bpffs_root], capture_output=True, text=True)


# --------------------------------------------------------------------------
# Small connectivity probes run inside a target container.
# --------------------------------------------------------------------------


@dataclass
class ProbeResult:
    ok: bool
    elapsed_s: float
    raw: subprocess.CompletedProcess


def tcp_probe(container: str, host: str, port: int, timeout: float = 3.0) -> ProbeResult:
    start = time.time()
    result = docker_exec(container, "nc", "-z", "-w", str(int(timeout)), host, str(port), timeout=timeout + 5)
    elapsed = time.time() - start
    return ProbeResult(ok=(result.returncode == 0), elapsed_s=elapsed, raw=result)


def udp_probe(container: str, host: str, port: int, timeout: float = 3.0) -> ProbeResult:
    start = time.time()
    # `-u` UDP, `-w` idle timeout; busybox nc's UDP "probe" only proves
    # sendmsg() didn't fail synchronously (UDP has no handshake) --
    # sufficient for testing the enforce_udp sendmsg hook's own verdict,
    # which is exactly what a `mode: block` deny returns EPERM for at
    # sendmsg() time, before any packet is built.
    result = docker_exec(container, "sh", "-c", f"echo probe | nc -u -w {int(timeout)} {host} {port}", timeout=timeout + 5)
    elapsed = time.time() - start
    return ProbeResult(ok=(result.returncode == 0), elapsed_s=elapsed, raw=result)


@dataclass
class ScenarioResult:
    name: str
    status: str  # "PROVEN" | "PARTIAL" | "DEFERRED" | "FAILED"
    details: str = ""


def wait_until(predicate: Callable[[], bool], timeout: float = 10.0, interval: float = 1.0) -> bool:
    """Polls `predicate` until it returns true or `timeout` elapses.
    Used wherever a DNS-derived host route's insertion happens on a
    background thread with no protocol-level "insert done" ack -- the
    caller has to observe the effect (a connect starting to succeed/fail)
    rather than wait on a message."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return predicate()
