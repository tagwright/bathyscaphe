// SPDX-License-Identifier: GPL-3.0-or-later
//! The stdout writer: drains the shared `mpsc::Receiver<UpMessage>` fed by
//! the ring-buf pipeline (`pipeline::sink::EventSink for Sender<UpMessage>`,
//! chunk #6), the stats/heartbeat thread, and the throttled `security`
//! emitter, encoding each message to exactly one NDJSON line
//! (`bathyscaphe_proto::encode_line`) and writing it with a prompt flush
//! per `docs/PROTOCOL.md` section 1 ("writers flush promptly"). One
//! dedicated thread owns the whole stdout handle for the life of the
//! process, so messages from every producer are serialized through this
//! single `recv()` loop and lines from different sources can never
//! interleave mid-write.

use std::io::Write;
use std::sync::mpsc::Receiver;

use bathyscaphe_proto::UpMessage;

/// Drains `receiver` until every sender has dropped (the normal shutdown
/// path: the daemon drops its `Sender` clones once every producer thread
/// has stopped), writing one line per message to `writer`. A single
/// message that fails to encode (should not happen for any type this
/// crate's own `UpMessage` variants can hold, but caught rather than
/// panicking the writer thread over it) is logged to stderr and skipped;
/// a write/flush failure (the far more likely real-world case: airlock
/// closed its read end) stops the loop, since there is no one left to
/// write to.
pub fn run(receiver: Receiver<UpMessage>, mut writer: impl Write) {
    while let Ok(message) = receiver.recv() {
        match bathyscaphe_proto::encode_line(&message) {
            Ok(line) => {
                if let Err(error) = writeln!(writer, "{line}") {
                    eprintln!("bathyscaphe: stdout write failed ({error}); stopping the writer thread");
                    return;
                }
                if let Err(error) = writer.flush() {
                    eprintln!("bathyscaphe: stdout flush failed ({error}); stopping the writer thread");
                    return;
                }
            }
            Err(error) => {
                eprintln!("bathyscaphe: failed to encode an outgoing {message:?} line ({error}); dropping it");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bathyscaphe_proto::{ErrorMsg, ReleaseAck, ReleaseStatus};
    use std::sync::mpsc;

    #[test]
    fn each_message_becomes_exactly_one_newline_terminated_line_in_order() {
        let (tx, rx) = mpsc::channel();
        tx.send(UpMessage::Error(ErrorMsg { message: "first".to_string() })).unwrap();
        tx.send(UpMessage::ReleaseAck(ReleaseAck { container_id: "abc".to_string(), status: ReleaseStatus::Released })).unwrap();
        drop(tx);

        let mut buf = Vec::new();
        run(rx, &mut buf);

        let output = String::from_utf8(buf).unwrap();
        let lines: Vec<&str> = output.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("\"kind\":\"error\""));
        assert!(lines[0].contains("first"));
        assert!(lines[1].contains("\"kind\":\"release_ack\""));
        assert!(output.ends_with('\n'), "every line, including the last, is newline-terminated");
    }

    #[test]
    fn no_messages_produces_no_output() {
        let (tx, rx) = mpsc::channel::<UpMessage>();
        drop(tx);
        let mut buf = Vec::new();
        run(rx, &mut buf);
        assert!(buf.is_empty());
    }

    #[test]
    fn a_write_failure_stops_the_loop_without_panicking() {
        struct FailingWriter;
        impl Write for FailingWriter {
            fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("simulated broken pipe"))
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let (tx, rx) = mpsc::channel();
        tx.send(UpMessage::Error(ErrorMsg { message: "x".to_string() })).unwrap();
        // Never dropped, but the writer error should still return from
        // `run` rather than looping/panicking.
        run(rx, FailingWriter);
    }
}
