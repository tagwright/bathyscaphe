#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Entry point for bathyscaphe's end-to-end integration suite.

Run inside a privileged container with a writable bpffs at /sys/fs/bpf,
the host cgroup v2 tree at /sys/fs/cgroup (--cgroupns=host), and the Docker
socket bind-mounted -- see docs/TESTING.md for the exact setup this was
proven against. Must run as root.

    python3 test/integration/run_integration.py             # every scenario
    python3 test/integration/run_integration.py 1 2 3        # a subset, by number
"""

from __future__ import annotations

import sys
import traceback

sys.path.insert(0, __file__.rsplit("/", 1)[0])

from driver import Daemon, ScenarioResult, log, nuke_all_itest_objects
import scenarios as S

SCENARIOS = {
    1: ("1_observe", "needs_main_daemon"),
    2: ("2_kernel_drop", "needs_main_daemon"),
    3: ("3_failsafe", "standalone"),
    4: ("4_fqdn_allow", "needs_main_daemon"),
    5: ("5_fqdn_deny", "needs_main_daemon"),
    6: ("6_untrusted_resolver", "standalone"),
    7: ("7_reconciliation", "standalone"),
}


def run_selected(numbers: list[int]) -> list[ScenarioResult]:
    results: list[ScenarioResult] = []
    main_daemon: Daemon | None = None

    def get_main_daemon() -> Daemon:
        nonlocal main_daemon
        if main_daemon is None:
            main_daemon = Daemon(S.MAIN_ROOT, stats_interval_s=1)
            hello = main_daemon.handshake()
            log(f"main daemon hello: backend={hello['backend']} capabilities={hello['capabilities']} pinned={hello['pinned']}")
        return main_daemon

    try:
        for n in numbers:
            entry_name, _ = SCENARIOS[n]
            log(f"=== scenario {n}: {entry_name} ===")
            try:
                if n == 1:
                    result = S.scenario_1_observe(get_main_daemon())
                elif n == 2:
                    result = S.scenario_2_kernel_drop(get_main_daemon())
                elif n == 3:
                    result = S.scenario_3_failsafe()
                elif n == 4:
                    result = S.scenario_4_fqdn_allow(get_main_daemon())
                elif n == 5:
                    result = S.scenario_5_fqdn_deny(get_main_daemon())
                elif n == 6:
                    result = S.scenario_6_untrusted_resolver()
                elif n == 7:
                    result = S.scenario_7_reconciliation()
                else:
                    raise ValueError(f"unknown scenario number {n}")
            except AssertionError as error:
                result = ScenarioResult(entry_name, "FAILED", str(error))
                log(f"FAILED: {error}")
            except Exception:  # noqa: BLE001 -- an unexpected exception is still a scenario failure, not a harness crash
                tb = traceback.format_exc()
                result = ScenarioResult(entry_name, "FAILED", tb)
                log(f"FAILED (unexpected exception):\n{tb}")
            results.append(result)
            log(f"--- {result.name}: {result.status} ---\n{result.details}\n")
            if result.status == "FAILED" and main_daemon is not None:
                log("main daemon stderr tail (diagnostic):\n" + "\n".join(main_daemon.err_lines[-60:]))
    finally:
        if main_daemon is not None:
            main_daemon.shutdown()
            main_daemon.wait_exit(timeout=10)
            if main_daemon.proc.poll() is None:
                main_daemon.kill()
        import subprocess

        subprocess.run(["rm", "-rf", S.MAIN_ROOT])

    return results


def main() -> int:
    args = sys.argv[1:]
    numbers = [int(a) for a in args] if args else sorted(SCENARIOS.keys())

    log("cleaning up any stray bathyscaphe-itest-* objects from a previous run before starting")
    nuke_all_itest_objects()

    try:
        results = run_selected(numbers)
    finally:
        log("final cleanup of every bathyscaphe-itest-* object")
        nuke_all_itest_objects()

    print("\n" + "=" * 72)
    print("SUMMARY")
    print("=" * 72)
    ok = True
    for r in results:
        print(f"[{r.status:>8}] {r.name}")
        if r.status != "PROVEN":
            ok = False
    print("=" * 72)

    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
