// SPDX-License-Identifier: GPL-3.0-or-later
//! `bathyscaphe unpin --all`: the standalone break-glass
//! (`bathy_build_spec.md`'s ratified architecture section). Calls
//! [`crate::probe::Probe::unpin_all_at`] directly -- no [`crate::daemon::Daemon::run`],
//! no attribution service, no kernel-floor check gating it, and critically
//! no requirement that a probe is currently running or that airlock is
//! reachable. An operator whose airlock process is gone (or was never
//! reachable in the first place) still needs to be able to clear wedged
//! fail-closed enforcement, so this path is deliberately independent of
//! everything `run` depends on.
//!
//! `--all` is required (not merely defaulted) precisely because this is a
//! full, unscoped clear: every pinned program, map, and per-container link
//! under `--bpffs-root` goes away in one call. A bare `unpin` with no flag
//! is refused with a clear message rather than silently doing nothing or
//! guessing at partial scope.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use crate::probe::Probe;

use super::UnpinArgs;
use super::log::Logger;

const EXIT_USAGE: u8 = 2;
const EXIT_FATAL_ERROR: u8 = 1;

/// What was found pinned under `root` before it gets removed, purely for
/// the operator-facing "here is what this actually cleared" report --
/// [`Probe::unpin_all_at`] itself just does the removal, with no inventory
/// of its own. A best-effort count: a directory that vanishes mid-walk (a
/// concurrent unpin, most plausibly this same command run twice) just
/// reads as fewer entries, never an error.
struct Inventory {
    programs: usize,
    maps: usize,
    containers: usize,
}

fn inventory(root: &Path) -> Inventory {
    let count_entries = |dir: PathBuf| std::fs::read_dir(&dir).map(|entries| entries.filter_map(Result::ok).count()).unwrap_or(0);
    Inventory { programs: count_entries(root.join("progs")), maps: count_entries(root.join("maps")), containers: count_entries(root.join("links")) }
}

pub fn run(args: UnpinArgs, logger: &Logger) -> ExitCode {
    if let Some(container_id) = &args.container {
        logger.error("cli.unpin.unimplemented", &format!("per-container unpin ({container_id}) is not implemented yet; use `bathyscaphe unpin --all`"));
        return ExitCode::from(EXIT_USAGE);
    }

    if !args.all {
        logger.error("cli.unpin.usage", "refusing to unpin without --all: this clears ALL pinned enforcement under --bpffs-root, and that scope must be spelled out explicitly, not assumed. Run `bathyscaphe unpin --all` to proceed");
        return ExitCode::from(EXIT_USAGE);
    }

    let bpffs_root = args.bpffs_root.unwrap_or_else(|| PathBuf::from(crate::probe::DEFAULT_BPFFS_ROOT));

    if !bpffs_root.exists() {
        logger.info("cli.unpin.noop", &format!("{} does not exist; nothing was pinned, nothing to clear", bpffs_root.display()));
        println!("bathyscaphe unpin --all: {} does not exist, nothing to clear", bpffs_root.display());
        return ExitCode::SUCCESS;
    }

    let before = inventory(&bpffs_root);

    match Probe::unpin_all_at(&bpffs_root) {
        Ok(()) => {
            logger.info(
                "cli.unpin.cleared",
                &format!("cleared {} under {}: {} program(s), {} map(s), {} container link set(s)", "the pin subtree", bpffs_root.display(), before.programs, before.maps, before.containers),
            );
            println!("bathyscaphe unpin --all: cleared {}", bpffs_root.display());
            println!("  programs removed:        {}", before.programs);
            println!("  maps removed:             {}", before.maps);
            println!("  container link sets removed: {}", before.containers);
            if before.containers > 0 {
                println!("  every container that was enforced under this root is now completely unenforced (fail-open) until airlock re-attaches and re-pushes policy.");
            }
            ExitCode::SUCCESS
        }
        Err(error) => {
            logger.error("cli.unpin.failed", &format!("failed to clear {}: {error:#}", bpffs_root.display()));
            ExitCode::from(EXIT_FATAL_ERROR)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_args() -> UnpinArgs {
        UnpinArgs { all: false, container: None, bpffs_root: None }
    }

    #[test]
    fn refuses_without_all() {
        let logger = Logger::new(super::super::log::LogFormat::Text, super::super::log::LogLevel::Error);
        let code = run(base_args(), &logger);
        assert_eq!(code, ExitCode::from(EXIT_USAGE));
    }

    #[test]
    fn refuses_a_per_container_id_as_not_yet_implemented() {
        let mut args = base_args();
        args.container = Some("c".repeat(64));
        let logger = Logger::new(super::super::log::LogFormat::Text, super::super::log::LogLevel::Error);
        let code = run(args, &logger);
        assert_eq!(code, ExitCode::from(EXIT_USAGE));
    }

    #[test]
    fn is_a_clean_noop_on_a_nonexistent_bpffs_root() {
        let dir = std::env::temp_dir().join(format!("bathyscaphe-unpin-cmd-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut args = base_args();
        args.all = true;
        args.bpffs_root = Some(dir.clone());
        let logger = Logger::new(super::super::log::LogFormat::Text, super::super::log::LogLevel::Error);
        let code = run(args, &logger);
        assert_eq!(code, ExitCode::SUCCESS);
        assert!(!dir.exists());
    }

    #[test]
    fn removes_an_existing_pin_subtree_and_reports_its_contents() {
        let dir = std::env::temp_dir().join(format!("bathyscaphe-unpin-cmd-test-populated-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("progs")).unwrap();
        std::fs::create_dir_all(dir.join("maps")).unwrap();
        std::fs::create_dir_all(dir.join("links").join("0000000000000001")).unwrap();
        std::fs::write(dir.join("progs").join("connect4"), b"").unwrap();
        std::fs::write(dir.join("maps").join("policy"), b"").unwrap();

        let inv = inventory(&dir);
        assert_eq!(inv.programs, 1);
        assert_eq!(inv.maps, 1);
        assert_eq!(inv.containers, 1);

        let mut args = base_args();
        args.all = true;
        args.bpffs_root = Some(dir.clone());
        let logger = Logger::new(super::super::log::LogFormat::Text, super::super::log::LogLevel::Error);
        let code = run(args, &logger);
        assert_eq!(code, ExitCode::SUCCESS);
        assert!(!dir.exists(), "unpin --all must remove the whole subtree");
    }
}
