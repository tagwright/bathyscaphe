// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 techgaud
//! The two seams a later chunk plugs into: [`EventSink`] (where mapped
//! wire events go) and [`TamperSource`] (where the per-cgroup drop count
//! comes from). Both are plain traits over what this chunk already has in
//! hand -- `probe::tamper::TamperStore` and an `mpsc::Sender` -- so chunk
//! #7's daemon needs no adapter code, just the concrete types it already
//! owns.

use std::net::IpAddr;
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};

use bathyscaphe_common::TamperCounter;
use bathyscaphe_proto::UpMessage;

use crate::dns::DomainHit;

/// Where a mapped wire `Event` (wrapped in its `UpMessage::Event` envelope,
/// so a sink can just as well carry `hello`/`stats`/other kinds down the
/// same channel) goes once [`super::Pipeline`] has built it.
///
/// `&mut self`: the pipeline owns its sink exclusively (see
/// [`super::Pipeline`]'s field), so there is no need for interior
/// mutability here -- an `mpsc::Sender` clone per producer, or a
/// `Mutex`-wrapped sink shared some other way, are both callers'
/// choices, not this trait's concern.
pub trait EventSink: Send {
    fn emit(&mut self, message: UpMessage);
}

/// The expected shape for chunk #7's wiring: build one `mpsc::channel()`,
/// hand a `Sender` clone to the pipeline (this impl) and to anything else
/// that also writes `UpMessage`s (a `hello`/`stats` emitter, the
/// token-bucket-throttled `security` records), and have one dedicated
/// writer thread draining the paired `Receiver`, `bathyscaphe_proto::
/// encode_line`-ing each message and writing it to stdout per
/// `docs/PROTOCOL.md` section 1's framing rules (one line, prompt flush).
/// `Sender` is already `Clone`, so this needs no wrapper type.
///
/// A closed receiver (the writer thread has already torn down, e.g. during
/// shutdown) has nowhere left to report a send failure to, so it is
/// dropped silently here rather than panicking the ring-buffer consumer
/// thread this runs on.
impl EventSink for Sender<UpMessage> {
    fn emit(&mut self, message: UpMessage) {
        let _ = self.send(message);
    }
}

/// Where [`super::dropped::DroppedTracker`]'s input comes from: the
/// kernel's per-cgroup `TAMPER` counter. A trait (rather than depending on
/// `probe::tamper::TamperStore` directly) so [`super::map::map_event`] is
/// unit-testable against a stub with no bpffs/kernel map in sight.
pub trait TamperSource: Send {
    fn read_tamper(&self, cgroup_id: u64) -> anyhow::Result<TamperCounter>;
}

impl TamperSource for crate::probe::TamperStore {
    fn read_tamper(&self, cgroup_id: u64) -> anyhow::Result<TamperCounter> {
        crate::probe::TamperStore::read_tamper(self, cgroup_id)
    }
}

/// Lets chunk #7 share one `TamperStore` between the pipeline (this trait)
/// and whatever else reads it (the periodic `stats` emitter needs the same
/// counter for `ContainerStats.dropped_total`) across the two different
/// threads those live on, without this crate needing to know how that
/// sharing is arranged beyond "some `Mutex`."
impl<T: TamperSource> TamperSource for Arc<Mutex<T>> {
    fn read_tamper(&self, cgroup_id: u64) -> anyhow::Result<TamperCounter> {
        let guard = self.lock().map_err(|_| anyhow::anyhow!("tamper store mutex poisoned"))?;
        guard.read_tamper(cgroup_id)
    }
}

/// Where [`super::map::map_event`]'s `domain.*` enrichment comes from
/// (build chunk #9): the per-container IP->domain cache
/// (`crate::dns::DomainCache`), populated by the DNS ring-buffer consumer
/// on a different thread than the one that reads it -- same
/// trait-over-a-shared-store shape as [`TamperSource`], for the same
/// reason (unit-testable against a stub with no ring buffer, no DNS
/// parser, no lock in sight).
pub trait DomainLookupSource: Send {
    fn lookup_domain(&self, cgroup_id: u64, addr: IpAddr, now_boottime_ns: u64) -> Option<DomainHit>;
}

impl DomainLookupSource for crate::dns::DomainCache {
    fn lookup_domain(&self, cgroup_id: u64, addr: IpAddr, now_boottime_ns: u64) -> Option<DomainHit> {
        crate::dns::DomainCache::lookup(self, cgroup_id, addr, now_boottime_ns)
    }
}

/// Lets the daemon share one `DomainCache` between the DNS ring-buffer
/// consumer thread (writer) and the connect-event pipeline (reader) --
/// the identical `Arc<Mutex<T>>` sharing convention as [`TamperSource`]'s
/// blanket impl above.
impl<T: DomainLookupSource> DomainLookupSource for Arc<Mutex<T>> {
    fn lookup_domain(&self, cgroup_id: u64, addr: IpAddr, now_boottime_ns: u64) -> Option<DomainHit> {
        let guard = self.lock().unwrap_or_else(|poison| poison.into_inner());
        guard.lookup_domain(cgroup_id, addr, now_boottime_ns)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sender_sink_forwards_and_tolerates_a_closed_receiver() {
        let (tx, rx) = std::sync::mpsc::channel::<UpMessage>();
        let mut sink: Box<dyn EventSink> = Box::new(tx);
        sink.emit(UpMessage::Error(bathyscaphe_proto::ErrorMsg { message: "test".to_string() }));
        assert!(matches!(rx.recv().unwrap(), UpMessage::Error(_)));

        drop(rx);
        // Must not panic even though nothing is listening any more.
        sink.emit(UpMessage::Error(bathyscaphe_proto::ErrorMsg { message: "after close".to_string() }));
    }
}
