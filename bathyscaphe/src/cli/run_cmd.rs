// SPDX-License-Identifier: GPL-3.0-or-later
//! `bathyscaphe run`: the airlock-driven subprocess mode. Maps CLI flags
//! into a [`crate::daemon::DaemonConfig`] and calls
//! [`crate::daemon::Daemon::run`] -- this module owns no protocol I/O, no
//! probe/attribution logic, and no kernel-touching code of its own; see
//! `daemon::mod`'s doc for the actual lifecycle. Its only jobs are the
//! flag-to-config mapping (unit-tested below without a kernel) and mapping
//! the returned [`crate::daemon::ExitReason`] to a process exit code.

use std::process::ExitCode;

use crate::daemon::r2::EscalationAction;
use crate::daemon::{Daemon, DaemonConfig, DropEscalationConfig, ExitReason};

use super::log::Logger;
use super::{DropActionArg, RunArgs};

/// `Shutdown` (a `shutdown` directive, the clean expected exit) is the only
/// zero-exit outcome. `StdinEof` and `FatalDesync` get distinct nonzero
/// codes so a supervisor (or an operator reading `$?`) can tell "airlock
/// hung up on us" apart from "we desynced the protocol" without parsing
/// stderr. A pre-handshake `Err` (most plausibly the kernel-floor check, or
/// a failed load/pin) is its own code again, since it means the probe never
/// even got as far as `hello`.
const EXIT_STDIN_EOF: u8 = 10;
const EXIT_FATAL_DESYNC: u8 = 11;
const EXIT_FATAL_ERROR: u8 = 1;

fn drop_action(arg: DropActionArg) -> EscalationAction {
    match arg {
        DropActionArg::Lockdown => EscalationAction::Lockdown,
        DropActionArg::Exit => EscalationAction::Exit,
    }
}

/// Builds the [`DaemonConfig`] this invocation runs with. A pure function
/// of `args` (plus the one environment read, `VERSION`), so the mapping is
/// unit-testable with no daemon/kernel involved.
fn build_config(args: &RunArgs, backend_version: &str) -> DaemonConfig {
    DaemonConfig {
        bpffs_root: args.bpffs_root.clone().unwrap_or_else(|| std::path::PathBuf::from(crate::probe::DEFAULT_BPFFS_ROOT)),
        cgroup_root: args.cgroup_root.clone().unwrap_or_else(|| std::path::PathBuf::from(crate::attribution::cgroup::DEFAULT_CGROUP_ROOT)),
        backend_version: backend_version.to_string(),
        r2: DropEscalationConfig { enabled: args.fail_closed_on_drops, threshold_per_sec: args.drop_threshold_per_sec, window_s: args.drop_window_secs, action: drop_action(args.drop_action) },
    }
}

pub fn run(args: RunArgs, logger: &Logger) -> ExitCode {
    let config = build_config(&args, super::VERSION.trim());

    if config.r2.enabled {
        logger.info("cli.run.r2_enabled", &format!("fail-closed-on-sustained-drops is ON: threshold {:.2}/s over {}s, action {:?}", config.r2.threshold_per_sec, config.r2.window_s, config.r2.action));
    } else {
        logger.info("cli.run.r2_disabled", "fail-closed-on-sustained-drops is OFF (default): sustained drops are counted and logged loudly, never escalated");
    }
    logger.info("cli.run.start", &format!("starting run mode: bpffs_root={} cgroup_root={}", config.bpffs_root.display(), config.cgroup_root.display()));

    match Daemon::run(crate::EBPF_OBJECT, config) {
        Ok(ExitReason::Shutdown) => {
            logger.info("cli.run.exit", "received shutdown directive; exiting cleanly (pins preserved)");
            ExitCode::SUCCESS
        }
        Ok(ExitReason::StdinEof) => {
            logger.warn("cli.run.exit", "stdin closed with no shutdown directive first (airlock's own process most likely exited); pins preserved");
            ExitCode::from(EXIT_STDIN_EOF)
        }
        Ok(ExitReason::FatalDesync) => {
            logger.error("cli.run.exit", "three consecutive malformed stdin lines: fatal protocol desync; pins preserved, exiting for a supervised restart");
            ExitCode::from(EXIT_FATAL_DESYNC)
        }
        Err(error) => {
            logger.error("cli.run.fatal", &format!("{error:#}"));
            ExitCode::from(EXIT_FATAL_ERROR)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn base_args() -> RunArgs {
        RunArgs { bpffs_root: None, cgroup_root: None, fail_closed_on_drops: false, drop_threshold_per_sec: 10.0, drop_window_secs: 60, drop_action: DropActionArg::Lockdown }
    }

    #[test]
    fn default_config_uses_the_probe_and_attribution_defaults() {
        let config = build_config(&base_args(), "00.01.00b1");
        assert_eq!(config.bpffs_root, PathBuf::from(crate::probe::DEFAULT_BPFFS_ROOT));
        assert_eq!(config.cgroup_root, PathBuf::from(crate::attribution::cgroup::DEFAULT_CGROUP_ROOT));
        assert_eq!(config.backend_version, "00.01.00b1");
        assert!(!config.r2.enabled, "R2 must be off by default end to end through the CLI mapping");
    }

    #[test]
    fn overridden_roots_pass_through_verbatim() {
        let mut args = base_args();
        args.bpffs_root = Some(PathBuf::from("/custom/bpffs"));
        args.cgroup_root = Some(PathBuf::from("/custom/cgroup"));
        let config = build_config(&args, "v");
        assert_eq!(config.bpffs_root, PathBuf::from("/custom/bpffs"));
        assert_eq!(config.cgroup_root, PathBuf::from("/custom/cgroup"));
    }

    #[test]
    fn r2_knobs_map_through_when_enabled() {
        let mut args = base_args();
        args.fail_closed_on_drops = true;
        args.drop_threshold_per_sec = 5.0;
        args.drop_window_secs = 30;
        args.drop_action = DropActionArg::Exit;
        let config = build_config(&args, "v");
        assert!(config.r2.enabled);
        assert_eq!(config.r2.threshold_per_sec, 5.0);
        assert_eq!(config.r2.window_s, 30);
        assert_eq!(config.r2.action, EscalationAction::Exit);
    }

    #[test]
    fn drop_action_maps_both_variants() {
        assert_eq!(drop_action(DropActionArg::Lockdown), EscalationAction::Lockdown);
        assert_eq!(drop_action(DropActionArg::Exit), EscalationAction::Exit);
    }

    #[test]
    fn exit_codes_are_distinct() {
        // Cheap guard against a future edit accidentally colliding two of
        // these -- a supervisor's exit-code branching depends on them
        // staying distinct.
        let codes = [0u8, EXIT_STDIN_EOF, EXIT_FATAL_DESYNC, EXIT_FATAL_ERROR];
        for (i, a) in codes.iter().enumerate() {
            for (j, b) in codes.iter().enumerate() {
                if i != j {
                    assert_ne!(a, b, "exit codes must be pairwise distinct");
                }
            }
        }
    }
}
