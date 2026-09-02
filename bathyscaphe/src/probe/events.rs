// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 techgaud
//! The `EVENTS` `RingBuf` consumer: plumbing only. Decoding a raw
//! `bathyscaphe_common::Event` off the wire and handing it to a callback is
//! this chunk's job; enriching `cgroup_id` into container attribution and
//! mapping onto `bathyscaphe_proto::up::Event` is a later chunk's (the
//! protocol/event pipeline), which is exactly why the callback type here is
//! `FnMut(Event)` and nothing fancier -- see the module doc on
//! `bathyscaphe_common::event` for the kernel-vs-userspace attribution
//! split this boundary follows.
//!
//! No async runtime is in this workspace, so this is a dedicated OS thread
//! blocking on `poll(2)` against the ring buffer's fd, draining with
//! [`aya::maps::RingBuf::next`] whenever it wakes, exactly the pattern the
//! `RingBuf` doc's own "Polling" section describes for a non-`tokio`
//! consumer.

use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};

use aya::maps::{MapData, RingBuf};
use bathyscaphe_common::Event;

/// Callback invoked once per decoded kernel event, on the consumer thread.
/// Must not block for long -- there is exactly one reader thread per
/// `EventConsumer`, and a slow callback delays draining the ring, which is
/// exactly the condition that trips the kernel's own tamper counter
/// (`bathyscaphe_common::counters::TamperCounter`) for every container
/// sharing this one ring buffer.
pub type EventCallback = Box<dyn FnMut(Event) + Send + 'static>;

/// How long a drained-empty consumer thread blocks in `poll(2)` before
/// re-checking its shutdown flag. Bounds shutdown latency; does not affect
/// event latency, since `poll` returns immediately once the fd is readable.
const POLL_TIMEOUT_MS: i32 = 250;

/// Owns the consumer thread. Dropping this without calling [`Self::stop`]
/// detaches the thread (it keeps running, silently, forever) rather than
/// panicking or blocking in `Drop` -- callers that care about a clean
/// shutdown must call `stop` explicitly.
pub struct EventConsumer {
    shutdown: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl EventConsumer {
    /// Spawns the consumer thread, taking ownership of `ring` (typically via
    /// [`crate::probe::Probe::take_events`]) and `callback`.
    pub fn spawn(ring: RingBuf<MapData>, mut callback: EventCallback) -> Self {
        let shutdown = Arc::new(AtomicBool::new(false));
        let shutdown_thread = Arc::clone(&shutdown);
        let handle = thread::spawn(move || {
            let mut ring = ring;
            let fd = ring.as_raw_fd();
            loop {
                while let Some(item) = ring.next() {
                    if let Some(event) = decode_event(&item) {
                        callback(event);
                    }
                }
                if shutdown_thread.load(Ordering::Relaxed) {
                    break;
                }
                let mut pfd = libc::pollfd { fd, events: libc::POLLIN, revents: 0 };
                // SAFETY: `pfd` is a single, valid `pollfd` for the duration
                // of the call. A negative return (error) or a spurious
                // wakeup both just loop back around to `ring.next()`, which
                // is always safe to call whether or not data is actually
                // available.
                unsafe {
                    libc::poll(&mut pfd, 1, POLL_TIMEOUT_MS);
                }
            }
        });
        Self { shutdown, handle: Some(handle) }
    }

    /// Signals the consumer thread to stop after draining whatever is
    /// currently in the ring, and joins it. Blocks for at most
    /// [`POLL_TIMEOUT_MS`] beyond whatever the callback itself takes.
    pub fn stop(mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// Decodes one ring buffer record as a [`Event`]. Returns `None` (and logs
/// to stderr) on a size mismatch rather than reading out of bounds or
/// panicking -- a size mismatch here means the userspace and kernel-side
/// `Event` layouts have drifted (an ABI bug), not a value this process
/// should crash trying to interpret.
fn decode_event(item: &[u8]) -> Option<Event> {
    if item.len() != Event::WIRE_SIZE {
        eprintln!("bathyscaphe: ringbuf event has unexpected size {} (expected {}); dropping it", item.len(), Event::WIRE_SIZE);
        return None;
    }
    // SAFETY: `Event` is `#[repr(C)]` and `aya::Pod` (every bit pattern of
    // its size is a valid value), the length was just checked above, and
    // `read_unaligned` makes no assumption about `item`'s alignment (the
    // ring buffer's mmap'd slots are not guaranteed to satisfy `Event`'s
    // natural 8-byte alignment).
    let event = unsafe { std::ptr::read_unaligned(item.as_ptr().cast::<Event>()) };
    Some(event)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event_bytes(event: &Event) -> Vec<u8> {
        // SAFETY: `Event` is `#[repr(C)]` and `Pod`; reading its bytes for a
        // test fixture is exactly what the kernel side does when it writes
        // one into the ring buffer.
        unsafe { std::slice::from_raw_parts((event as *const Event).cast::<u8>(), Event::WIRE_SIZE).to_vec() }
    }

    #[test]
    fn decode_event_round_trips_a_well_formed_record() {
        let mut event = Event::default();
        event.cgroup_id = 0x1234_5678;
        event.dst_port = 443u16.to_be_bytes();
        let bytes = event_bytes(&event);

        let decoded = decode_event(&bytes).expect("well-formed event decodes");
        assert_eq!(decoded, event);
    }

    #[test]
    fn decode_event_rejects_a_short_buffer_instead_of_reading_out_of_bounds() {
        let short = vec![0u8; Event::WIRE_SIZE - 1];
        assert!(decode_event(&short).is_none());
    }

    #[test]
    fn decode_event_rejects_an_oversized_buffer() {
        let long = vec![0u8; Event::WIRE_SIZE + 1];
        assert!(decode_event(&long).is_none());
    }
}
