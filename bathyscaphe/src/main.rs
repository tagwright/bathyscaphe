// SPDX-License-Identifier: GPL-3.0-or-later
//! `bathyscaphe`: the userspace loader/daemon binary.
//!
//! The CLI build chunk (`bathy_build_spec.md`'s build sequence step 7) is
//! what finally wires every earlier chunk together into an actual entry
//! point: `cli::main()` parses `run` / `unpin --all` / `observe` /
//! `version` and delegates to [`daemon::Daemon::run`],
//! [`probe::Probe::unpin_all_at`], or a standalone observe loop built
//! directly on [`probe`]/[`attribution`]/[`pipeline`]. See `cli`'s module
//! doc for the CLI surface itself.

mod attribution;
mod cli;
mod daemon;
mod pipeline;
mod probe;

/// The compiled eBPF object for bathyscaphe-ebpf's programs, embedded at
/// build time. `probe::Probe::load_or_reopen` is the one thing that ever
/// loads it into the kernel.
static EBPF_OBJECT: &[u8] = aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/bathyscaphe"));

fn main() -> std::process::ExitCode {
    cli::main()
}
