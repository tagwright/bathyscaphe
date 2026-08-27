// SPDX-License-Identifier: GPL-3.0-or-later
//! The event pipeline: turns a decoded `bathyscaphe_common::Event` (chunk
//! #5's `probe::events::EventConsumer` output) into a
//! `bathyscaphe_proto::up::Event` (the wire type) and hands it to a sink.
//!
//! [`map::map_event`] is the pure mapping logic (verdict reconstruction,
//! v4-in-v6 unmapping, process/comm decode, container attribution). This
//! module wraps it into [`Pipeline`], a stateful `FnMut(Event)`-shaped
//! adapter (via [`Pipeline::into_callback`]) that is exactly what
//! `probe::events::EventConsumer::spawn`'s `EventCallback` parameter
//! expects -- so chunk #7's daemon wires the ring buffer straight to the
//! wire protocol with one call:
//!
//! ```text
//! let attribution = attribution::AttributionService::start()?;
//! let pipeline = pipeline::Pipeline::new(attribution.resolver.clone(), tamper_source, sink)?;
//! let consumer = probe::EventConsumer::spawn(ring, pipeline.into_callback());
//! ```
//!
//! [`sink::EventSink`] and [`sink::TamperSource`] are the two seams this
//! chunk defines and chunk #7 plugs into; see that module's doc.

pub mod dropped;
pub mod map;
pub mod sink;

use anyhow::{Context, Result};
use bathyscaphe_common::Event as KernelEvent;
use bathyscaphe_proto::UpMessage;

use crate::attribution::Attributor;
use crate::probe::EventCallback;

pub use dropped::DroppedTracker;
pub use map::map_event;
pub use sink::{EventSink, TamperSource};

/// Samples the wall-clock/`CLOCK_BOOTTIME` offset once, at pipeline
/// construction time: `wall_now_ns - boot_now_ns`. Adding this to any
/// later `Event::ktime_ns` (also `CLOCK_BOOTTIME`, per that struct's own
/// doc) recovers a wall-clock instant without needing to resample a clock
/// pair per event. Reuses `probe::clock::now_boottime_ns` rather than a
/// second implementation, so the pipeline and the loader agree on exactly
/// which clock "boot time" means (`CLOCK_BOOTTIME`, not `CLOCK_MONOTONIC`
/// -- see that module's doc on why the distinction matters across a
/// suspend/resume).
fn sample_boot_offset_ns() -> Result<i128> {
    let boot_now_ns = crate::probe::clock::now_boottime_ns().context("sampling CLOCK_BOOTTIME for the pipeline's wall-clock offset failed")?;
    let wall_now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).context("system wall clock is before the Unix epoch")?;
    Ok(wall_now.as_nanos() as i128 - i128::from(boot_now_ns))
}

/// The stateful adapter: one per running probe, owns the attribution
/// resolver, the tamper-counter source, the dropped-event tracker, and the
/// sink every mapped event goes to.
pub struct Pipeline<A, T, S> {
    attributor: A,
    tamper: T,
    dropped: DroppedTracker,
    boot_offset_ns: i128,
    sink: S,
}

impl<A, T, S> Pipeline<A, T, S>
where
    A: Attributor,
    T: TamperSource,
    S: EventSink,
{
    pub fn new(attributor: A, tamper: T, sink: S) -> Result<Self> {
        let boot_offset_ns = sample_boot_offset_ns()?;
        Ok(Self { attributor, tamper, dropped: DroppedTracker::new(), boot_offset_ns, sink })
    }

    /// Maps one kernel event and hands it to the sink, or silently skips it
    /// (with a stderr note) on the narrow total-attribution-failure case
    /// [`map::map_event`]'s doc describes. This does not increment any
    /// tamper/drop accounting itself -- that would double-count against
    /// the kernel's own `TAMPER` counter, which is the ground truth for
    /// ring-buffer loss; this is a distinct, expected-to-be-vanishingly-rare
    /// failure mode at the userspace attribution boundary instead.
    pub fn handle(&mut self, kernel_event: KernelEvent) {
        match map_event(&kernel_event, &self.attributor, &self.tamper, &self.dropped, self.boot_offset_ns) {
            Some(wire_event) => self.sink.emit(UpMessage::Event(wire_event)),
            None => {
                eprintln!("bathyscaphe: dropping one event with no resolvable container attribution at all for cgroup {:016x} (not a ring-buffer loss; see pipeline::map::map_event's doc)", kernel_event.cgroup_id);
            }
        }
    }
}

impl<A, T, S> Pipeline<A, T, S>
where
    A: Attributor + Send + 'static,
    T: TamperSource + Send + 'static,
    S: EventSink + Send + 'static,
{
    /// Consumes this pipeline into the exact callback shape
    /// `probe::events::EventConsumer::spawn` expects.
    pub fn into_callback(mut self) -> EventCallback {
        Box::new(move |event| self.handle(event))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc;
    use std::sync::{Arc, Mutex};

    use bathyscaphe_common::TamperCounter;

    use crate::attribution::Attribution;

    use super::*;

    struct StubAttributor(Attribution);
    impl Attributor for StubAttributor {
        fn resolve(&self, _cgroup_id: u64) -> Option<Attribution> {
            Some(self.0.clone())
        }
    }

    struct StubTamper;
    impl TamperSource for StubTamper {
        fn read_tamper(&self, _cgroup_id: u64) -> anyhow::Result<TamperCounter> {
            Ok(TamperCounter::zero())
        }
    }

    /// A capturing sink for tests: every emitted `UpMessage` lands in a
    /// shared `Vec`, inspectable after handing a clone into something that
    /// takes ownership (the pipeline, or an `EventConsumer`).
    #[derive(Clone, Default)]
    struct CapturingSink(Arc<Mutex<Vec<UpMessage>>>);
    impl EventSink for CapturingSink {
        fn emit(&mut self, message: UpMessage) {
            self.0.lock().unwrap().push(message);
        }
    }

    fn attribution() -> Attribution {
        Attribution { container_id: "c".repeat(64), name: Some("api".to_string()), image: Some("app:1".to_string()), runtime: bathyscaphe_proto::Runtime::Docker }
    }

    #[test]
    fn pipeline_handle_emits_a_mapped_wire_event_to_the_sink() {
        let sink = CapturingSink::default();
        let mut pipeline = Pipeline::new(StubAttributor(attribution()), StubTamper, sink.clone()).expect("sampling the boot offset should succeed on any real host");

        let mut kernel_event = KernelEvent::default();
        kernel_event.dst_port = 8080u16.to_be_bytes();
        pipeline.handle(kernel_event);

        let captured = sink.0.lock().unwrap();
        assert_eq!(captured.len(), 1);
        let UpMessage::Event(wire_event) = &captured[0] else { panic!("expected an Event message") };
        assert_eq!(wire_event.dst.port, 8080);
        assert_eq!(wire_event.container.id, "c".repeat(64));
    }

    /// The exact wiring chunk #7 uses: `into_callback()` produces the
    /// `EventCallback` shape `probe::events::EventConsumer::spawn` takes.
    /// This proves that callback, invoked directly with synthetic kernel
    /// events (standing in for what `EventConsumer`'s ring-buffer decode
    /// loop would hand it), reaches a real `mpsc` sink end to end. A live
    /// ring buffer needs a loaded eBPF program and a real cgroup/bpffs,
    /// which is privileged, kernel-dependent setup out of scope for a unit
    /// test -- see docs/TESTING.md for exactly what this proves versus
    /// what a later privileged integration test would.
    #[test]
    fn into_callback_matches_event_consumer_wiring_end_to_end_through_an_mpsc_sink() {
        let (tx, rx) = mpsc::channel::<UpMessage>();
        let pipeline = Pipeline::new(StubAttributor(attribution()), StubTamper, tx).expect("sampling the boot offset should succeed on any real host");

        let mut callback: EventCallback = pipeline.into_callback();
        callback(KernelEvent::default());
        callback(KernelEvent::default());

        let first = rx.try_recv().expect("first event should have reached the sink");
        let second = rx.try_recv().expect("second event should have reached the sink");
        assert!(matches!(first, UpMessage::Event(_)));
        assert!(matches!(second, UpMessage::Event(_)));
        assert!(rx.try_recv().is_err(), "exactly two events were sent");
    }

    #[test]
    fn sample_boot_offset_ns_produces_a_ts_close_to_now() {
        // Not a unit test of a pure function (it reads real clocks), but a
        // cheap sanity check that the offset it produces round-trips to a
        // timestamp within a generous window of "now" -- catches a sign
        // error or a unit mixup (ns vs ms) far more usefully than not
        // testing this arithmetic at all.
        let offset = sample_boot_offset_ns().expect("clocks should be readable in any test environment");
        let boot_now_ns = crate::probe::clock::now_boottime_ns().unwrap();
        let reconstructed_wall_ns = offset + i128::from(boot_now_ns);
        let actual_wall_ns = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos() as i128;
        let drift_ns = (reconstructed_wall_ns - actual_wall_ns).abs();
        assert!(drift_ns < 1_000_000_000, "offset-reconstructed wall time drifted more than 1s from actual wall time: {drift_ns}ns");
    }
}
