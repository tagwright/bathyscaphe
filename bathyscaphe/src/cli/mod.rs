// SPDX-License-Identifier: GPL-3.0-or-later
//! The CLI build chunk: `bathyscaphe run` / `unpin --all` / `observe` /
//! `version`, per `bathy_build_spec.md`'s build sequence step 7. Each
//! subcommand's body is deliberately thin -- it maps flags into the
//! `daemon`/`probe` types those modules already define and delegates to
//! them, per that spec's instruction to keep the kernel-touching path
//! unit-tested at the arg-to-config mapping, not the kernel path itself
//! (that needs a privileged host, out of scope for `cargo test`; see
//! `docs/TESTING.md`).
//!
//! - [`log`]: the global `--log-format`/`--log-level` stderr logger.
//! - [`run_cmd`]: `run`, the airlock-driven subprocess mode
//!   ([`crate::daemon::Daemon::run`]).
//! - [`unpin_cmd`]: `unpin --all`, the standalone break-glass
//!   ([`crate::probe::Probe::unpin_all_at`]), which works with no running
//!   probe and no airlock.
//! - [`observe_cmd`]: `observe`, the standalone observe-only mode for
//!   manual verification -- ephemeral (detaches/unpins on exit) and
//!   distinct from `run`'s fail-closed-persistent posture; see that
//!   module's doc for exactly where the line is drawn.

pub mod log;
pub mod observe_cmd;
pub mod run_cmd;
pub mod unpin_cmd;

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand, ValueEnum};

use log::{LogFormat, LogLevel, Logger};

#[derive(Debug, Parser)]
#[command(name = "bathyscaphe", about = "tagwright's eBPF egress observe-and-enforce probe", long_about = None)]
pub struct Cli {
    /// Shape of bathyscaphe's own operational logs on stderr. `json` is
    /// OTel-log-data-model aligned (see `cli::log`'s doc) so bilgeline can
    /// route it with a stock filelog parser; `text` is for a human at a
    /// terminal. Never affects the NDJSON protocol on stdout/stdin, which
    /// has its own fixed framing regardless of this flag.
    #[arg(long, global = true, value_enum, default_value_t = LogFormat::Json)]
    pub log_format: LogFormat,

    /// Minimum severity written to stderr. Messages below this level are
    /// dropped, not buffered.
    #[arg(long, global = true, value_enum, default_value_t = LogLevel::Info)]
    pub log_level: LogLevel,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// The airlock-driven subprocess mode: NDJSON on stdin/stdout, human
    /// logs on stderr, fail-closed-persistent enforcement.
    Run(RunArgs),
    /// The standalone break-glass: clears pinned enforcement directly via
    /// bpffs, with no airlock and no running probe required.
    Unpin(UnpinArgs),
    /// Standalone observe-only mode for manual verification and
    /// debugging: no airlock, no enforcement, ephemeral.
    Observe(ObserveArgs),
    /// Prints the version and this build's backend identity.
    Version,
}

#[derive(Debug, Clone, Args)]
pub struct RunArgs {
    /// Root of the bpffs pin subtree. Must be a writable bpffs mount.
    #[arg(long)]
    pub bpffs_root: Option<PathBuf>,

    /// Root of the cgroup v2 unified hierarchy to walk/watch for
    /// container attribution.
    #[arg(long)]
    pub cgroup_root: Option<PathBuf>,

    /// Refinement R2 (`bathy_build_spec.md`): opt in to escalating a
    /// container to full enforcement lockdown (or exiting the process)
    /// once its sustained ring-buffer drop rate stays above
    /// `--drop-threshold-per-sec` for `--drop-window-secs`. OFF by
    /// default, matching Falco's own default of log+alert rather than
    /// exit -- see the README for the full trade-off this makes.
    #[arg(long)]
    pub fail_closed_on_drops: bool,

    /// Drops per second, sustained over the window, before escalating.
    /// Only takes effect with `--fail-closed-on-drops`.
    #[arg(long, default_value_t = 10.0)]
    pub drop_threshold_per_sec: f64,

    /// How long the drop rate must stay over threshold, in seconds,
    /// before escalating. Only takes effect with `--fail-closed-on-drops`.
    #[arg(long, default_value_t = 60)]
    pub drop_window_secs: u64,

    /// What to do once a container's sustained drop rate crosses the
    /// threshold: lock that one container down to full enforcement, or
    /// exit this whole process (pins are preserved either way -- see the
    /// README's fail-closed section). Only takes effect with
    /// `--fail-closed-on-drops`.
    #[arg(long, value_enum, default_value_t = DropActionArg::Lockdown)]
    pub drop_action: DropActionArg,

    /// An additional trusted DNS resolver address (build chunk #11,
    /// repeatable), on top of the built-in default set (Docker's embedded
    /// resolver at 127.0.0.11, plus every `nameserver` line in this host's
    /// `/etc/resolv.conf`). Only a DNS answer whose SOURCE address is in
    /// the trusted set can seed FQDN name-rule enforcement -- a container
    /// using a resolver outside this set gets no name-allow/deny seeded
    /// from its own DNS traffic (fail-closed in `mode: block`, never a
    /// silent widening). See `docs/DNS.md`.
    #[arg(long = "trusted-resolver")]
    pub trusted_resolver: Vec<std::net::IpAddr>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
#[value(rename_all = "lowercase")]
pub enum DropActionArg {
    Lockdown,
    Exit,
}

#[derive(Debug, Clone, Args)]
pub struct UnpinArgs {
    /// Required: clears every pinned program, map, and per-container link
    /// under `--bpffs-root`. Spelled out explicitly (not a default) so an
    /// operator cannot clear enforcement by fat-fingering a bare `unpin`.
    #[arg(long)]
    pub all: bool,

    /// Not yet implemented: a single container's pins only. `--all` is
    /// the v1 requirement (`bathy_build_spec.md`); accepted here so the
    /// eventual per-container break-glass is an additive flag, not a
    /// wire-incompatible reshuffle of this subcommand's args.
    pub container: Option<String>,

    /// Root of the bpffs pin subtree to clear.
    #[arg(long)]
    pub bpffs_root: Option<PathBuf>,
}

#[derive(Debug, Clone, Args)]
pub struct ObserveArgs {
    /// Root of the bpffs pin subtree. Defaults to the same root `run`
    /// uses -- see [`observe_cmd`]'s doc on why running `observe`
    /// concurrently with a live `run` daemon against the same root is
    /// unsupported, not just undocumented.
    #[arg(long)]
    pub bpffs_root: Option<PathBuf>,

    /// Root of the cgroup v2 unified hierarchy to walk/watch for
    /// container attribution.
    #[arg(long)]
    pub cgroup_root: Option<PathBuf>,

    /// Output shape for printed events.
    #[arg(long, value_enum, default_value_t = ObserveFormat::Json)]
    pub format: ObserveFormat,

    /// Only print events for this container (matched against the full
    /// container id, an id prefix, or the container's name).
    #[arg(long)]
    pub container: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
#[value(rename_all = "lowercase")]
pub enum ObserveFormat {
    Json,
    Text,
}

const VERSION: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../VERSION"));

/// Parses `argv` and dispatches to the selected subcommand. The one entry
/// point `main.rs` calls.
pub fn main() -> ExitCode {
    let cli = Cli::parse();
    let logger = Logger::new(cli.log_format, cli.log_level);

    match cli.command {
        Command::Run(args) => run_cmd::run(args, &logger),
        Command::Unpin(args) => unpin_cmd::run(args, &logger),
        Command::Observe(args) => observe_cmd::run(args, &logger),
        Command::Version => {
            print_version();
            ExitCode::SUCCESS
        }
    }
}

fn print_version() {
    println!("bathyscaphe {}", VERSION.trim());
    println!("backend: bathyscaphe");
    println!("proto_versions: {:?}", [bathyscaphe_proto::PROTO_VERSION]);
    println!("capabilities: {:?}", crate::daemon::hello::capabilities());
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    fn parse(args: &[&str]) -> Cli {
        Cli::try_parse_from(std::iter::once("bathyscaphe").chain(args.iter().copied())).expect("args should parse")
    }

    #[test]
    fn the_clap_command_graph_is_well_formed() {
        // `debug_assert()` walks the whole derived command graph (every
        // subcommand, every arg) and panics on a clap-level inconsistency
        // (duplicate arg ids, conflicting short flags, etc.) -- cheaper and
        // more thorough than parsing every possible combination by hand.
        Cli::command().debug_assert();
    }

    #[test]
    fn run_parses_with_defaults() {
        let cli = parse(&["run"]);
        let Command::Run(args) = cli.command else { panic!("expected Run") };
        assert!(args.bpffs_root.is_none());
        assert!(args.cgroup_root.is_none());
        assert!(!args.fail_closed_on_drops, "R2 must default to off");
        assert_eq!(args.drop_threshold_per_sec, 10.0);
        assert_eq!(args.drop_window_secs, 60);
        assert_eq!(args.drop_action, DropActionArg::Lockdown);
        assert_eq!(cli.log_format, LogFormat::Json, "logs default to JSON so bilgeline can route them with no config");
        assert_eq!(cli.log_level, LogLevel::Info);
    }

    #[test]
    fn run_defaults_to_no_extra_trusted_resolvers() {
        let cli = parse(&["run"]);
        let Command::Run(args) = cli.command else { panic!("expected Run") };
        assert!(args.trusted_resolver.is_empty());
    }

    #[test]
    fn run_parses_repeated_trusted_resolver_flags() {
        let cli = parse(&["run", "--trusted-resolver", "8.8.8.8", "--trusted-resolver", "1.1.1.1"]);
        let Command::Run(args) = cli.command else { panic!("expected Run") };
        assert_eq!(args.trusted_resolver, vec![std::net::IpAddr::from([8, 8, 8, 8]), std::net::IpAddr::from([1, 1, 1, 1])]);
    }

    #[test]
    fn run_rejects_a_malformed_trusted_resolver_address() {
        let result = Cli::try_parse_from(["bathyscaphe", "run", "--trusted-resolver", "not-an-ip"]);
        assert!(result.is_err(), "an unparseable --trusted-resolver value must be a parse error, not silently ignored");
    }

    #[test]
    fn run_parses_every_r2_knob() {
        let cli = parse(&[
            "run",
            "--bpffs-root",
            "/tmp/bpffs",
            "--cgroup-root",
            "/tmp/cgroup",
            "--fail-closed-on-drops",
            "--drop-threshold-per-sec",
            "42.5",
            "--drop-window-secs",
            "120",
            "--drop-action",
            "exit",
        ]);
        let Command::Run(args) = cli.command else { panic!("expected Run") };
        assert_eq!(args.bpffs_root, Some(PathBuf::from("/tmp/bpffs")));
        assert_eq!(args.cgroup_root, Some(PathBuf::from("/tmp/cgroup")));
        assert!(args.fail_closed_on_drops);
        assert_eq!(args.drop_threshold_per_sec, 42.5);
        assert_eq!(args.drop_window_secs, 120);
        assert_eq!(args.drop_action, DropActionArg::Exit);
    }

    #[test]
    fn global_log_flags_parse_after_the_subcommand_too() {
        let cli = parse(&["--log-format", "text", "--log-level", "debug", "version"]);
        assert_eq!(cli.log_format, LogFormat::Text);
        assert_eq!(cli.log_level, LogLevel::Debug);
    }

    #[test]
    fn unpin_parses_all_and_bpffs_root() {
        let cli = parse(&["unpin", "--all", "--bpffs-root", "/tmp/bpffs"]);
        let Command::Unpin(args) = cli.command else { panic!("expected Unpin") };
        assert!(args.all);
        assert_eq!(args.bpffs_root, Some(PathBuf::from("/tmp/bpffs")));
        assert_eq!(args.container, None);
    }

    #[test]
    fn unpin_without_all_still_parses_clap_side_but_defaults_all_to_false() {
        // clap itself does not enforce `--all` as required (a bool flag
        // has no "required" concept -- it is either present or absent);
        // `unpin_cmd::run` is what refuses to act without it. This test
        // pins the parse-level default so that refusal has something to
        // check.
        let cli = parse(&["unpin"]);
        let Command::Unpin(args) = cli.command else { panic!("expected Unpin") };
        assert!(!args.all);
    }

    #[test]
    fn unpin_accepts_a_future_container_id_positional() {
        let id = "c".repeat(64);
        let cli = parse(&["unpin", &id]);
        let Command::Unpin(args) = cli.command else { panic!("expected Unpin") };
        assert_eq!(args.container, Some(id));
        assert!(!args.all);
    }

    #[test]
    fn observe_parses_defaults() {
        let cli = parse(&["observe"]);
        let Command::Observe(args) = cli.command else { panic!("expected Observe") };
        assert_eq!(args.format, ObserveFormat::Json);
        assert_eq!(args.container, None);
    }

    #[test]
    fn observe_parses_format_and_container_filter() {
        let cli = parse(&["observe", "--format", "text", "--container", "web"]);
        let Command::Observe(args) = cli.command else { panic!("expected Observe") };
        assert_eq!(args.format, ObserveFormat::Text);
        assert_eq!(args.container.as_deref(), Some("web"));
    }

    #[test]
    fn observe_rejects_an_unknown_format() {
        let result = Cli::try_parse_from(["bathyscaphe", "observe", "--format", "yaml"]);
        assert!(result.is_err(), "an unrecognized --format value must be a parse error, not silently ignored");
    }

    #[test]
    fn version_parses_with_no_args() {
        let cli = parse(&["version"]);
        assert!(matches!(cli.command, Command::Version));
    }

    #[test]
    fn an_unknown_subcommand_is_a_parse_error() {
        let result = Cli::try_parse_from(["bathyscaphe", "not-a-real-command"]);
        assert!(result.is_err());
    }
}
