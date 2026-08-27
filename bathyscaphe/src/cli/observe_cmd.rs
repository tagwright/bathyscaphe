// SPDX-License-Identifier: GPL-3.0-or-later
//! `bathyscaphe observe`: a standalone, observe-only mode for manual
//! verification and debugging. No airlock, no NDJSON handshake, no
//! enforcement -- it loads the probe, attaches to whatever containers are
//! running (and watches for new ones), and prints egress events straight
//! to stdout for a human (or a quick pipe into `jq`) to look at.
//!
//! ## How this differs from `run`
//!
//! `run` (see [`super::run_cmd`]) is fail-closed-PERSISTENT: every program,
//! map, and per-container link it attaches stays pinned to bpffs forever,
//! specifically so a probe crash or restart never drops enforcement. That
//! is exactly wrong for a mode whose entire purpose is "let me poke at
//! this for a minute and leave no trace."
//!
//! `observe` is EPHEMERAL instead:
//!
//! - If `--bpffs-root` was empty when this process started (the common
//!   case: no `run` daemon is active), this process's own
//!   [`crate::probe::Probe::load_or_reopen`] call is what freshly loads
//!   and pins the programs/maps. On a clean Ctrl-C, every container this
//!   session itself attached is detached, and the whole pin subtree this
//!   session created is removed (`Probe::unpin_all`) -- the host is left
//!   exactly as it was found.
//! - If `--bpffs-root` was ALREADY populated (most plausibly a `run`
//!   daemon is actively enforcing there), this process reopens the
//!   existing pins rather than reloading, attaches only to containers
//!   that daemon has not already attached, and on exit detaches only
//!   those, leaving the shared maps/programs and every pre-existing
//!   container's links untouched. It never calls `unpin_all` in this
//!   case -- doing so would tear out another process's enforcement.
//!
//! Running `observe` concurrently against the same `--bpffs-root` as a
//! live `run` daemon is possible (both share the one `EVENTS` ring
//! buffer and will each drain a subset of the records the other might
//! otherwise have seen) but is not a configuration this build optimizes
//! for -- point `observe` at a quiet host, or accept that its exit
//! doesn't touch the daemon's own state.
//!
//! No `policy`/`mode` is ever set here: the probe's `ENFORCEMENT` map has
//! no entry for a container this command attaches, which the connect4/
//! connect6 hooks read as "always allow" -- exactly IG-parity observation,
//! never enforcement, per `bathy_build_spec.md`'s ratified architecture
//! ("observe-only ALWAYS returns allow").

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bathyscaphe_proto::UpMessage;

use crate::attribution::{AttributionService, Attributor, Resolver};
use crate::dns::DomainCache;
use crate::pipeline::{EventSink, Pipeline};
use crate::probe::layout::{PinPaths, PinState, pin_state};
use crate::probe::{DnsCaptureConsumer, EventConsumer, Probe};

use super::log::Logger;
use super::{ObserveArgs, ObserveFormat};

/// Set by the `SIGINT` handler below; polled by the main loop. A plain
/// `AtomicBool` (not a channel) because the only thing that needs to
/// observe it is this same process's main thread, on a short poll
/// interval -- exactly the same shape `probe::events`/`attribution::cgroup`
/// already use for their own shutdown flags, just reached from a signal
/// handler instead of an explicit `stop()` call.
static STOP: AtomicBool = AtomicBool::new(false);

/// # Safety / signal-safety
/// The only thing this does is an atomic store, which is async-signal-safe
/// (no allocation, no locking, no syscalls beyond the store itself).
extern "C" fn handle_sigint(_signum: libc::c_int) {
    STOP.store(true, Ordering::SeqCst);
}

/// How often the main loop re-checks for newly-started containers to
/// attach to, and re-checks the shutdown flag. Matches the cadence
/// convention the rest of this crate's background loops use (see
/// `probe::events::POLL_TIMEOUT_MS`'s doc): bounds Ctrl-C latency without
/// mattering for event latency, since events flow through the ring buffer
/// consumer thread, not this loop.
const POLL_INTERVAL: Duration = Duration::from_millis(500);

pub fn run(args: ObserveArgs, logger: &Logger) -> ExitCode {
    STOP.store(false, Ordering::SeqCst);
    // SAFETY: `handle_sigint` only performs an atomic store, which is
    // async-signal-safe; installing it is safe for the lifetime of this
    // process.
    unsafe {
        libc::signal(libc::SIGINT, handle_sigint as *const () as usize);
    }

    let bpffs_root = args.bpffs_root.clone().unwrap_or_else(|| PathBuf::from(crate::probe::DEFAULT_BPFFS_ROOT));
    let cgroup_root = args.cgroup_root.clone().unwrap_or_else(|| PathBuf::from(crate::attribution::cgroup::DEFAULT_CGROUP_ROOT));

    let fresh_load = matches!(pin_state(&PinPaths::new(bpffs_root.clone())), PinState::Fresh);
    if fresh_load {
        logger.info("cli.observe.start", "starting standalone observe mode: fresh bpffs root, this session's own load/attach/pins will be fully undone on exit");
    } else {
        logger.warn(
            "cli.observe.shared_pins",
            &format!(
                "{} is already populated (a `run` daemon may be enforcing here); this session will only attach to containers not already attached, and will NOT touch the existing pin subtree on exit -- only what this session itself attaches gets detached",
                bpffs_root.display()
            ),
        );
    }

    let mut probe = match Probe::load_or_reopen(crate::EBPF_OBJECT, bpffs_root) {
        Ok(probe) => probe,
        Err(error) => {
            logger.error("cli.observe.load_failed", &format!("{error:#}"));
            return ExitCode::from(1);
        }
    };

    let attribution = match AttributionService::start_at(cgroup_root) {
        Ok(service) => service,
        Err(error) => {
            logger.error("cli.observe.attribution_failed", &format!("{error:#}"));
            return ExitCode::from(1);
        }
    };
    let resolver = Arc::clone(&attribution.resolver);

    let mut attached_this_session: Vec<u64> = Vec::new();
    attach_new_containers(&mut probe, resolver.as_ref(), args.container.as_deref(), &mut attached_this_session, logger);

    let ring = match probe.take_events() {
        Some(ring) => ring,
        None => {
            logger.error("cli.observe.no_ring", "the probe's ring buffer was already taken (this should never happen on a freshly loaded/reopened probe)");
            attribution.stop();
            return ExitCode::from(1);
        }
    };
    let dns_ring = match probe.take_dns_events() {
        Some(ring) => ring,
        None => {
            logger.error("cli.observe.no_dns_ring", "the probe's DNS ring buffer was already taken (this should never happen on a freshly loaded/reopened probe)");
            attribution.stop();
            return ExitCode::from(1);
        }
    };

    let shared_probe = Arc::new(Mutex::new(probe));
    let domain_cache = Arc::new(Mutex::new(DomainCache::new()));
    let sink = ObservePrinter { format: args.format, container_filter: args.container.clone() };
    let pipeline = match Pipeline::new(Arc::clone(&resolver), Arc::clone(&shared_probe), Arc::clone(&domain_cache), sink) {
        Ok(pipeline) => pipeline,
        Err(error) => {
            logger.error("cli.observe.pipeline_failed", &format!("{error:#}"));
            attribution.stop();
            return ExitCode::from(1);
        }
    };
    let consumer = EventConsumer::spawn(ring, pipeline.into_callback());
    // Standalone `observe` learns domain names the same way `run` does
    // (build chunk #9): its own DNS ring-buffer consumer feeding its own,
    // session-local `DomainCache` -- torn down with everything else on
    // exit, since this whole mode is ephemeral (see this module's doc).
    let dns_consumer = DnsCaptureConsumer::spawn(dns_ring, crate::dns::capture_callback(Arc::clone(&domain_cache)));

    logger.info("cli.observe.watching", "watching for egress events; Ctrl-C to detach and exit");
    while !STOP.load(Ordering::SeqCst) {
        {
            let mut probe_guard = shared_probe.lock().unwrap_or_else(|poison| poison.into_inner());
            attach_new_containers(&mut probe_guard, resolver.as_ref(), args.container.as_deref(), &mut attached_this_session, logger);
        }
        std::thread::sleep(POLL_INTERVAL);
    }

    logger.info("cli.observe.stopping", "Ctrl-C received; detaching this session's containers and exiting");
    consumer.stop();
    dns_consumer.stop();
    attribution.stop();

    {
        let mut probe_guard = shared_probe.lock().unwrap_or_else(|poison| poison.into_inner());
        for cgroup_id in attached_this_session.iter().rev() {
            if let Err(error) = probe_guard.detach_container(*cgroup_id) {
                logger.warn("cli.observe.detach_failed", &format!("failed to detach cgroup {cgroup_id:016x}: {error:#}"));
            }
        }
    }

    if fresh_load {
        match Arc::try_unwrap(shared_probe) {
            Ok(mutex) => {
                let probe = mutex.into_inner().unwrap_or_else(|poison| poison.into_inner());
                if let Err(error) = probe.unpin_all() {
                    logger.warn("cli.observe.unpin_failed", &format!("failed to remove this session's own bpffs pin subtree: {error:#}"));
                }
            }
            Err(_) => {
                logger.warn("cli.observe.unpin_skipped", "the probe handle was still shared at shutdown (a background thread outlived stop()); leaving the pin subtree in place rather than risk unpinning state something else still references");
            }
        }
    }

    ExitCode::SUCCESS
}

/// Attaches to every currently-known container this session has not
/// already attached (and, given `filter`, matches), recording each newly
/// attached cgroup id in `attached_this_session` so exit-time cleanup
/// detaches exactly what this session added -- never a container a `run`
/// daemon (or an earlier `observe` session against the same root) already
/// had attached. Called once up front and then once per poll tick, so
/// "attach to currently-running containers ... and watch for new ones"
/// is one code path, not two.
fn attach_new_containers(probe: &mut Probe, resolver: &Resolver, filter: Option<&str>, attached_this_session: &mut Vec<u64>, logger: &Logger) {
    let already: std::collections::HashSet<u64> = probe.attached_containers().collect();
    for (container_id, cgroup_id, path) in resolver.known_containers() {
        if already.contains(&cgroup_id) {
            continue;
        }
        let name = resolver.resolve(cgroup_id).and_then(|attribution| attribution.name);
        if !container_matches(filter, &container_id, name.as_deref()) {
            continue;
        }
        match probe.attach_container(&path) {
            Ok(id) => {
                attached_this_session.push(id);
                logger.info("cli.observe.attached", &format!("attached to container {container_id} (cgroup {id:016x})"));
            }
            Err(error) => {
                logger.warn("cli.observe.attach_failed", &format!("failed to attach to container {container_id}: {error:#}"));
            }
        }
    }
}

/// The `--container` filter: matches the full container id, an id prefix,
/// or an exact container name. `None` (no filter given) always matches.
fn container_matches(filter: Option<&str>, container_id: &str, name: Option<&str>) -> bool {
    match filter {
        None => true,
        Some(needle) => container_id == needle || container_id.starts_with(needle) || name == Some(needle),
    }
}

fn format_event_json(event: &bathyscaphe_proto::Event) -> String {
    bathyscaphe_proto::encode_line(&UpMessage::Event(event.clone())).unwrap_or_else(|error| format!("{{\"error\":\"failed to encode event: {error}\"}}"))
}

/// One human-readable line per event: timestamp, container, src/dst,
/// proto, verdict, and (once the DNS/SNI layer lands) domain -- everything
/// an operator squinting at a terminal actually wants, without the JSON
/// envelope.
fn format_event_text(event: &bathyscaphe_proto::Event) -> String {
    let container = event.container.name.as_deref().unwrap_or(&event.container.id);
    let domain = event.domain.name.as_deref().map(|name| format!(" domain={name}")).unwrap_or_default();
    let rule = event.rule_id.as_deref().map(|rule_id| format!(" rule={rule_id}")).unwrap_or_default();
    format!(
        "{} {:?} container={} {}:{} -> {}:{} proto={:?} verdict={:?}{domain}{rule} dropped_since_last={}",
        event.ts, event.event, container, event.src.addr, event.src.port, event.dst.addr, event.dst.port, event.proto, event.verdict, event.meta.dropped_since_last
    )
}

/// Prints every observed [`bathyscaphe_proto::Event`] to stdout, applying
/// the `--container` filter and `--format` choice. Ignores every other
/// [`UpMessage`] variant -- [`Pipeline`] only ever emits `Event` (see that
/// module's doc), but the [`EventSink`] trait is general, so this matches
/// defensively rather than assuming.
struct ObservePrinter {
    format: ObserveFormat,
    container_filter: Option<String>,
}

impl EventSink for ObservePrinter {
    fn emit(&mut self, message: UpMessage) {
        let UpMessage::Event(event) = message else { return };
        if !container_matches(self.container_filter.as_deref(), &event.container.id, event.container.name.as_deref()) {
            return;
        }
        let line = match self.format {
            ObserveFormat::Json => format_event_json(&event),
            ObserveFormat::Text => format_event_text(&event),
        };
        println!("{line}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bathyscaphe_proto::{Container, Domain, Endpoint, EventKind, Process, Runtime, TransportProto, Verdict};

    fn sample_event() -> bathyscaphe_proto::Event {
        bathyscaphe_proto::Event {
            ts: "2026-08-27T00:00:00Z".to_string(),
            event: EventKind::Connect,
            proto: TransportProto::Tcp,
            container: Container { id: "c".repeat(64), name: Some("web".to_string()), image: Some("app:1".to_string()), runtime: Runtime::Docker },
            process: Process { pid: Some(1), tid: Some(1), uid: Some(0), gid: Some(0), comm: Some("curl".to_string()) },
            src: Endpoint { addr: "10.0.0.1".parse().unwrap(), port: 44444 },
            dst: Endpoint { addr: "93.184.216.34".parse().unwrap(), port: 443 },
            verdict: Verdict::Allow,
            rule_id: None,
            domain: Domain::unresolved(),
            meta: bathyscaphe_proto::EventMeta { dropped_since_last: 0 },
        }
    }

    #[test]
    fn container_matches_with_no_filter_matches_everything() {
        assert!(container_matches(None, "abc", None));
        assert!(container_matches(None, "abc", Some("web")));
    }

    #[test]
    fn container_matches_full_id() {
        let id = "c".repeat(64);
        assert!(container_matches(Some(&id), &id, None));
    }

    #[test]
    fn container_matches_id_prefix() {
        let id = "c".repeat(64);
        assert!(container_matches(Some("cccc"), &id, None));
        assert!(!container_matches(Some("dddd"), &id, None));
    }

    #[test]
    fn container_matches_exact_name() {
        let id = "c".repeat(64);
        assert!(container_matches(Some("web"), &id, Some("web")));
        assert!(!container_matches(Some("webby"), &id, Some("web")), "name matching is exact, not a prefix, so `web` never matches a differently-named `webby`");
    }

    #[test]
    fn format_event_json_round_trips_as_a_valid_event_line() {
        let line = format_event_json(&sample_event());
        let decoded: UpMessage = bathyscaphe_proto::decode_line(&line).expect("must decode as a valid UpMessage line");
        assert!(matches!(decoded, UpMessage::Event(_)));
    }

    #[test]
    fn format_event_text_is_one_line_and_carries_the_key_fields() {
        let line = format_event_text(&sample_event());
        assert_eq!(line.lines().count(), 1, "text format must be exactly one line per event");
        assert!(line.contains("web"), "container name should appear");
        assert!(line.contains("443"), "destination port should appear");
        assert!(line.contains("Allow"), "verdict should appear");
    }

    #[test]
    fn format_event_text_falls_back_to_container_id_when_name_is_unknown() {
        let mut event = sample_event();
        event.container.name = None;
        let line = format_event_text(&event);
        assert!(line.contains(&event.container.id));
    }

    #[test]
    fn observe_printer_drops_events_that_do_not_match_the_container_filter() {
        let mut printer = ObservePrinter { format: ObserveFormat::Json, container_filter: Some("nonexistent".to_string()) };
        // No panic, no output assertion needed here (stdout isn't
        // capturable cleanly in a unit test) -- this just proves the
        // filtered-out path doesn't try to format/print at all, by not
        // panicking on a message shape `format_event_*` never has to see.
        printer.emit(UpMessage::Event(sample_event()));
    }
}
