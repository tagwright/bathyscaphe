// SPDX-License-Identifier: GPL-3.0-or-later
//! The DAEMON + PROTOCOL I/O build chunk: where the probe (chunk #5) and
//! the attribution/pipeline (chunk #6) become a running process airlock
//! actually drives over stdin/stdout/stderr per `docs/PROTOCOL.md`.
//! [`Daemon::run`] is the one entry point a later chunk's CLI `run`
//! subcommand calls; this module owns no `clap`/CLI surface itself.
//!
//! ## Module map
//!
//! - [`probe_api`]: [`probe_api::ProbeApi`], the seam between this module
//!   and the kernel-touching [`crate::probe::Probe`], plus
//!   [`probe_api::MockProbe`] for kernel-free unit tests.
//! - [`compile`]: pure wire-`Policy` -> kernel-map-writes compilation
//!   (CIDR aggregation, the port-rule cap, name-rule inertness, the
//!   synthesized container-wide baseline entry).
//! - [`apply`]: drives [`probe_api::ProbeApi`] from a
//!   [`compile::CompiledPolicy`] -- resolve/attach, make-before-break,
//!   `release`/`release_all`.
//! - [`state`]: [`state::DaemonState`], the daemon's own per-container
//!   bookkeeping (kernel maps don't know "orphaned").
//! - [`reconcile`]: the `sync_complete` orphan-marking pass.
//! - [`hello`]: building the `hello` handshake message and its `pinned`
//!   inventory.
//! - [`stdin`]: the NDJSON directive reader, codec-limit enforcement, and
//!   the desync/shutdown/EOF exit decision.
//! - [`stdout`]: the NDJSON writer thread.
//! - [`stats`]: the periodic heartbeat, R1's tamper-drop and
//!   enforce-blocked-summary accounting, and driving R2.
//! - [`throttle`] / [`security`]: the shared token-bucket throttle and the
//!   R1 loud-record builders.
//! - [`r2`]: the opt-in fail-closed-on-sustained-drops decision logic.
//!
//! ## Threading model
//!
//! One process, five points of concurrency, coordinated through two
//! shared, mutex-guarded pieces of state plus one `mpsc` channel:
//!
//! - **The probe**: `Arc<Mutex<Probe>>`. Every kernel map mutation (from
//!   directive application, on the main/stdin thread) or read (from the
//!   ring-buf consumer's tamper lookups during event mapping, and from the
//!   stats thread's per-tick tamper/enforcement reads and R2's occasional
//!   `set_enforcement` lockdown) goes through one short-held lock. Kernel
//!   map operations are cheap syscalls, so contention here is not a
//!   concern at the cadence any of these three sites operate at.
//! - **The daemon's own bookkeeping**: `Arc<Mutex<DaemonState>>`, written
//!   by directive application and the `sync_complete` reconciliation pass
//!   (both on the main thread), read by the stats thread every tick.
//! - **Everything bound for stdout**: one `mpsc::Sender<UpMessage>`,
//!   cloned to the ring-buf pipeline (wrapped in [`stats::CountingSink`]
//!   for `events_emitted`/deny tallying), the stats thread, and the main
//!   thread's directive dispatcher (for `policy_ack`/`release_ack`). ONE
//!   dedicated writer thread ([`stdout::run`]) owns the actual stdout
//!   handle and drains the shared receiver, so lines from different
//!   producers can never interleave mid-write.
//! - The ring-buffer consumer ([`crate::probe::EventConsumer`], chunk #5)
//!   and the attribution watchers ([`crate::attribution::AttributionService`],
//!   chunk #6) run their own already-established background threads
//!   underneath this.
//!
//! The main thread runs [`stdin::run`] directly (blocking on stdin) after
//! the handshake; when it returns, this function tears down every other
//! thread in dependency order (stats -> ring-buf consumer -> attribution
//! -> drop the last stdout sender -> join the writer) and returns the
//! [`ExitReason`] a CLI wraps into a process exit code. **No step in this
//! shutdown sequence calls `detach_container`, `release_policy_container`,
//! `clear_enforcement`, or `unpin_all`** -- pins are preserved on every
//! exit path (`Shutdown`, `StdinEof`, `FatalDesync` alike) simply because
//! nothing here is given the means to tear them down; only an explicit
//! `release`/`release_all` directive (handled by [`apply`], while the
//! process is still running) or the standalone break-glass CLI (a later
//! chunk) ever does that.

pub mod apply;
pub mod compile;
pub mod hello;
pub mod probe_api;
pub mod r2;
pub mod reconcile;
pub mod security;
pub mod state;
pub mod stats;
pub mod stdin;
pub mod stdout;
pub mod throttle;

use std::io::BufRead;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result};
use bathyscaphe_proto::down::DownMessage;
use bathyscaphe_proto::UpMessage;

use crate::attribution::{Attributor, AttributionService};
use crate::dns::DomainCache;
use crate::pipeline::{EventSink, Pipeline};
use crate::probe::{DnsCaptureConsumer, EventConsumer, Probe};

use probe_api::ProbeApi;
pub use r2::DropEscalationConfig;
use security::SecurityEmitter;
use state::DaemonState;

/// How long a background loop (the stats thread's sleep, in particular)
/// waits between shutdown-flag checks. Matches
/// `probe::events::POLL_TIMEOUT_MS`'s rationale exactly: bounds shutdown
/// latency without affecting the real cadence, since the loop only ever
/// waits the full remaining interval when nothing asked it to stop early.
const SHUTDOWN_POLL: Duration = Duration::from_millis(250);

/// Configuration for one [`Daemon::run`] invocation. A later chunk's CLI
/// is expected to populate this from flags/env and its own `VERSION`
/// constant; every field has a sane standalone default for direct
/// programmatic use (tests, `observe`-style standalone invocations).
#[derive(Debug, Clone)]
pub struct DaemonConfig {
    pub bpffs_root: PathBuf,
    pub cgroup_root: PathBuf,
    /// This build's own semver, echoed in `hello.backend_version`.
    pub backend_version: String,
    /// Refinement R2 (`bathy_build_spec.md`): OFF by default
    /// ([`DropEscalationConfig::default`]). Documented here, in
    /// `docs/PROTOCOL.md`, and (chunk #12) the README, per Nate's explicit
    /// ask that it stay evident, not just discoverable by reading source.
    pub r2: DropEscalationConfig,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self { bpffs_root: PathBuf::from(crate::probe::DEFAULT_BPFFS_ROOT), cgroup_root: PathBuf::from(crate::attribution::cgroup::DEFAULT_CGROUP_ROOT), backend_version: env!("CARGO_PKG_VERSION").to_string(), r2: DropEscalationConfig::default() }
    }
}

/// Why [`Daemon::run`] returned. A CLI maps this to a process exit code;
/// every variant preserves pins (see this module's doc).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitReason {
    /// A `shutdown` directive was received: the clean, expected exit.
    Shutdown,
    /// stdin closed with no `shutdown` first (most plausibly airlock's own
    /// process exiting).
    StdinEof,
    /// Three consecutive malformed stdin lines: a fatal protocol desync.
    FatalDesync,
}

impl From<stdin::StdinOutcome> for ExitReason {
    fn from(outcome: stdin::StdinOutcome) -> Self {
        match outcome {
            stdin::StdinOutcome::Shutdown => ExitReason::Shutdown,
            stdin::StdinOutcome::Eof => ExitReason::StdinEof,
            stdin::StdinOutcome::FatalDesync => ExitReason::FatalDesync,
        }
    }
}

/// Samples the wall-clock/`CLOCK_BOOTTIME` offset once, at daemon startup,
/// the same convention `pipeline::map`'s (private) `sample_boot_offset_ns`
/// uses -- duplicated here (rather than depended on) so `pipeline` does
/// not need to widen that helper's visibility for one caller outside its
/// own module.
fn sample_boot_offset_ns() -> Result<i128> {
    let boot_now_ns = crate::probe::clock::now_boottime_ns().context("sampling CLOCK_BOOTTIME for the daemon's wall-clock offset failed")?;
    let wall_now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).context("system wall clock is before the Unix epoch")?;
    Ok(wall_now.as_nanos() as i128 - i128::from(boot_now_ns))
}

pub struct Daemon;

impl Daemon {
    /// Runs the full daemon lifecycle against real stdin/stdout: load or
    /// reopen the probe, start attribution, hello/start handshake, then
    /// the directive loop until shutdown/EOF/desync. `ebpf_object` is the
    /// embedded BPF object (`EBPF_OBJECT` in `main.rs`); a later chunk's
    /// CLI owns reading flags into `config` and mapping the returned
    /// [`ExitReason`] to a process exit code.
    pub fn run(ebpf_object: &[u8], config: DaemonConfig) -> Result<ExitReason> {
        let mut probe = Probe::load_or_reopen(ebpf_object, config.bpffs_root.clone()).context("failed to load or reopen the probe")?;
        let attribution = AttributionService::start_at(config.cgroup_root.clone()).context("failed to start container attribution")?;
        let resolver = Arc::clone(&attribution.resolver);

        let hello = hello::build_hello(&probe as &dyn ProbeApi, |cgroup_id| resolver.resolve(cgroup_id).map(|a| a.container_id), &config.backend_version);

        let ring = probe.take_events().context("the probe's ring buffer was already taken (this should never happen on a freshly loaded/reopened probe)")?;
        let dns_ring = probe.take_dns_events().context("the probe's DNS ring buffer was already taken (this should never happen on a freshly loaded/reopened probe)")?;
        let boot_offset_ns = sample_boot_offset_ns()?;

        let (tx, rx) = mpsc::channel::<UpMessage>();
        let stdout_handle = thread::spawn(move || stdout::run(rx, std::io::stdout()));

        if tx.send(UpMessage::Hello(hello)).is_err() {
            anyhow::bail!("stdout writer thread died before `hello` could be sent");
        }

        // Blocking read of exactly one line for `start`. Nothing else has
        // been spawned yet (no ring-buf consumer, no stats thread), so
        // "bathyscaphe emits nothing after hello until start arrives"
        // (docs/PROTOCOL.md section 2) holds structurally: there is
        // nothing here yet that could emit anything else.
        let stdin = std::io::stdin();
        let mut first_line = String::new();
        stdin.lock().read_line(&mut first_line).context("failed to read the `start` handshake line from stdin")?;
        let decoded: DownMessage = bathyscaphe_proto::decode_line(first_line.trim_end()).map_err(|error| anyhow::anyhow!("failed to decode the `start` handshake line: {error}"))?;
        let start = match decoded {
            DownMessage::Start(start) => start,
            other => anyhow::bail!("expected `start` as the first stdin line, got {other:?}"),
        };
        if start.proto != bathyscaphe_proto::PROTO_VERSION {
            anyhow::bail!("airlock selected protocol version {} but this build only speaks {}", start.proto, bathyscaphe_proto::PROTO_VERSION);
        }
        let stats_interval_s = u64::from(start.stats_interval_s.max(1));

        let shared_probe = Arc::new(Mutex::new(probe));
        let shared_state = Arc::new(Mutex::new(DaemonState::new()));
        let security = Arc::new(SecurityEmitter::new());
        let domain_cache = Arc::new(Mutex::new(DomainCache::new()));

        let (counting_sink, events_emitted, denies_since_last) = stats::CountingSink::new(tx.clone());
        let pipeline = Pipeline::new(Arc::clone(&resolver), Arc::clone(&shared_probe), Arc::clone(&domain_cache), counting_sink).context("failed to construct the event pipeline")?;
        let consumer = EventConsumer::spawn(ring, pipeline.into_callback());
        let dns_consumer = DnsCaptureConsumer::spawn(dns_ring, crate::dns::capture_callback(Arc::clone(&domain_cache)));

        let stats_shutdown = Arc::new(AtomicBool::new(false));
        let stats_handle = spawn_stats_thread(Arc::clone(&shared_probe), Arc::clone(&shared_state), Arc::clone(&resolver), Arc::clone(&security), tx.clone(), Arc::clone(&stats_shutdown), events_emitted, denies_since_last, config.r2, stats_interval_s);

        let outcome = run_directive_loop(stdin.lock(), Arc::clone(&shared_probe), Arc::clone(&shared_state), Arc::clone(&resolver), Arc::clone(&security), tx.clone(), boot_offset_ns);

        // Shutdown, in dependency order. Deliberately no probe mutation
        // anywhere in this sequence -- see the module doc.
        stats_shutdown.store(true, Ordering::Relaxed);
        let _ = stats_handle.join();
        consumer.stop();
        dns_consumer.stop();
        attribution.stop();
        drop(tx);
        let _ = stdout_handle.join();

        Ok(outcome.into())
    }
}

#[allow(clippy::too_many_arguments)]
fn spawn_stats_thread(
    shared_probe: Arc<Mutex<Probe>>,
    shared_state: Arc<Mutex<DaemonState>>,
    resolver: Arc<crate::attribution::Resolver>,
    security: Arc<SecurityEmitter>,
    sink: mpsc::Sender<UpMessage>,
    shutdown: Arc<AtomicBool>,
    events_emitted: Arc<std::sync::atomic::AtomicU64>,
    denies_since_last: Arc<Mutex<std::collections::HashMap<String, u64>>>,
    r2_config: DropEscalationConfig,
    stats_interval_s: u64,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let mut runtime = stats::StatsRuntime::new(events_emitted, denies_since_last);
        let mut sink = sink;
        let interval = Duration::from_secs(stats_interval_s.max(1));

        loop {
            let mut waited = Duration::ZERO;
            while waited < interval {
                if shutdown.load(Ordering::Relaxed) {
                    return;
                }
                let step = SHUTDOWN_POLL.min(interval - waited);
                thread::sleep(step);
                waited += step;
            }
            if shutdown.load(Ordering::Relaxed) {
                return;
            }

            let stats_message = {
                let mut probe_guard = shared_probe.lock().unwrap_or_else(|poison| poison.into_inner());
                let mut state_guard = shared_state.lock().unwrap_or_else(|poison| poison.into_inner());
                stats::tick(&mut runtime, &mut *probe_guard, &mut *state_guard, resolver.as_ref(), &security, &mut sink, &r2_config, stats_interval_s)
            };
            sink.emit(UpMessage::Stats(stats_message));
        }
    })
}

/// Runs the stdin directive loop on the calling (main) thread, dispatching
/// every non-`shutdown` directive against the shared probe/state.
fn run_directive_loop(stdin_lock: std::io::StdinLock<'_>, shared_probe: Arc<Mutex<Probe>>, shared_state: Arc<Mutex<DaemonState>>, resolver: Arc<crate::attribution::Resolver>, security: Arc<SecurityEmitter>, sink: mpsc::Sender<UpMessage>, boot_offset_ns: i128) -> stdin::StdinOutcome {
    let mut sink = sink;
    stdin::run(stdin_lock, move |message| {
        let mut probe_guard = shared_probe.lock().unwrap_or_else(|poison| poison.into_inner());
        let mut state_guard = shared_state.lock().unwrap_or_else(|poison| poison.into_inner());

        match message {
            DownMessage::Start(_) => {
                eprintln!("bathyscaphe: unexpected second `start` directive after the handshake; ignoring");
            }
            DownMessage::Policy(policy) => {
                let ack = apply::apply_policy(&mut *probe_guard, &mut *state_guard, resolver.as_ref(), resolver.as_ref(), &security, &mut sink, boot_offset_ns, &policy);
                sink.emit(UpMessage::PolicyAck(ack));
            }
            DownMessage::Release(release) => {
                let ack = apply::apply_release(&mut *probe_guard, &mut *state_guard, resolver.as_ref(), &release.container_id);
                sink.emit(UpMessage::ReleaseAck(ack));
            }
            DownMessage::ReleaseAll(_) => {
                for ack in apply::apply_release_all(&mut *probe_guard, &mut *state_guard) {
                    sink.emit(UpMessage::ReleaseAck(ack));
                }
            }
            DownMessage::SyncComplete(_) => {
                reconcile::mark_orphans(&mut state_guard, &*probe_guard, |cgroup_id| resolver.resolve(cgroup_id).map(|a| a.container_id));
            }
            DownMessage::Shutdown(_) => unreachable!("intercepted by stdin::run itself before `handle` is ever called"),
        }
    })
}
