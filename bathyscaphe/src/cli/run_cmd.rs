// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 techgaud
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

/// The real host path `run` reads its trusted-resolver default set from.
/// Named as a constant (rather than inlined at each call site) purely so
/// [`run`]'s two references to it -- the one that reads the file and the
/// one embedded in a log message -- can never drift apart.
const RESOLV_CONF_PATH: &str = "/etc/resolv.conf";

/// Builds the [`DaemonConfig`] this invocation runs with. A pure function
/// of `args`, `backend_version`, and the already-built `trusted_resolvers`
/// (build chunk #11 -- deliberately NOT read from `/etc/resolv.conf`
/// inside this function itself, so it stays unit-testable with no real
/// filesystem state leaking into an assertion), so the mapping is
/// unit-testable with no daemon/kernel involved.
fn build_config(args: &RunArgs, backend_version: &str, trusted_resolvers: crate::dns::TrustedResolvers) -> DaemonConfig {
    DaemonConfig {
        bpffs_root: args.bpffs_root.clone().unwrap_or_else(|| std::path::PathBuf::from(crate::probe::DEFAULT_BPFFS_ROOT)),
        cgroup_root: args.cgroup_root.clone().unwrap_or_else(|| std::path::PathBuf::from(crate::attribution::cgroup::DEFAULT_CGROUP_ROOT)),
        backend_version: backend_version.to_string(),
        r2: DropEscalationConfig { enabled: args.fail_closed_on_drops, threshold_per_sec: args.drop_threshold_per_sec, window_s: args.drop_window_secs, action: drop_action(args.drop_action) },
        trusted_resolvers,
    }
}

pub fn run(args: RunArgs, logger: &Logger) -> ExitCode {
    // Build chunk #11: read /etc/resolv.conf exactly once, here, so the
    // "how many nameservers did we find" log line and the trusted set
    // itself are guaranteed to agree (both are derived from the SAME
    // contents string, never two separate reads that could race a
    // resolv.conf rewrite mid-startup).
    let resolv_conf_contents = std::fs::read_to_string(RESOLV_CONF_PATH).unwrap_or_default();
    let resolv_conf_nameserver_count = crate::dns::parse_resolv_conf_nameservers(&resolv_conf_contents).len();
    let trusted_resolvers = crate::dns::TrustedResolvers::default_set_from(&resolv_conf_contents).with_extra(args.trusted_resolver.iter().copied());

    if resolv_conf_nameserver_count == 0 {
        logger.warn(
            "cli.run.no_resolv_conf_nameservers",
            &format!("{RESOLV_CONF_PATH} had no nameserver lines (or could not be read); the trusted-resolver set falls back to Docker's embedded resolver (127.0.0.11) plus any --trusted-resolver given -- a container reaching an external resolver outside that set will get no FQDN name-rule enforcement seeded from its DNS traffic (fail-closed in mode: block, never a silent widening)"),
        );
    }
    if trusted_resolvers.is_empty() {
        logger.error(
            "cli.run.trusted_resolvers_empty",
            "the trusted-resolver set resolved to EMPTY -- no DNS answer from any source will ever seed FQDN name-rule enforcement until --trusted-resolver is set; IP/CIDR policy is unaffected and enforcement never silently widens, but every name rule in mode: block will fail closed for every container until this is fixed",
        );
    } else {
        logger.info(
            "cli.run.trusted_resolvers",
            &format!("trusted DNS resolver set ({} address(es)): {:?}", trusted_resolvers.len(), trusted_resolvers.iter().map(|a| a.to_string()).collect::<Vec<_>>()),
        );
    }

    let config = build_config(&args, super::VERSION.trim(), trusted_resolvers);

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
        RunArgs {
            bpffs_root: None,
            cgroup_root: None,
            fail_closed_on_drops: false,
            drop_threshold_per_sec: 10.0,
            drop_window_secs: 60,
            drop_action: DropActionArg::Lockdown,
            trusted_resolver: Vec::new(),
        }
    }

    fn empty_trusted_resolvers() -> crate::dns::TrustedResolvers {
        crate::dns::TrustedResolvers::new([])
    }

    #[test]
    fn default_config_uses_the_probe_and_attribution_defaults() {
        let config = build_config(&base_args(), "00.01.00b1", empty_trusted_resolvers());
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
        let config = build_config(&args, "v", empty_trusted_resolvers());
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
        let config = build_config(&args, "v", empty_trusted_resolvers());
        assert!(config.r2.enabled);
        assert_eq!(config.r2.threshold_per_sec, 5.0);
        assert_eq!(config.r2.window_s, 30);
        assert_eq!(config.r2.action, EscalationAction::Exit);
    }

    #[test]
    fn build_config_carries_the_given_trusted_resolvers_through_verbatim() {
        let resolvers = crate::dns::TrustedResolvers::new([std::net::IpAddr::from([9, 9, 9, 9])]);
        let config = build_config(&base_args(), "v", resolvers);
        assert!(config.trusted_resolvers.is_trusted(std::net::IpAddr::from([9, 9, 9, 9])));
        assert!(!config.trusted_resolvers.is_trusted(std::net::IpAddr::from([1, 1, 1, 1])));
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
