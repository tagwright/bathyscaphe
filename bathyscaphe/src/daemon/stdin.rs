// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 techgaud
//! The stdin directive reader: one NDJSON line per [`DownMessage`],
//! enforcing `docs/PROTOCOL.md` section 1's codec limits
//! (`bathyscaphe_proto::MAX_LINE_BYTES`,
//! `bathyscaphe_proto::MAX_CONSECUTIVE_MALFORMED_LINES`) and returning a
//! [`StdinOutcome`] the caller uses to decide how the process exits.
//! **Every exit path here preserves pins** -- this module never calls
//! anything on a [`super::probe_api::ProbeApi`] at all, so there is
//! nothing here that COULD unpin or detach; "fail-closed on desync" is
//! achieved simply by this reader never being given the means to tear
//! anything down.

use std::io::BufRead;

use bathyscaphe_proto::down::DownMessage;
use bathyscaphe_proto::{MAX_CONSECUTIVE_MALFORMED_LINES, MAX_LINE_BYTES};

/// Why [`run`] returned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StdinOutcome {
    /// A `shutdown` directive was received: graceful, pins preserved.
    Shutdown,
    /// The stream closed (EOF) with no `shutdown` first -- most plausibly
    /// airlock's own process exiting. Pins are still preserved (this
    /// reader never tears anything down); the caller decides the process
    /// exit code.
    Eof,
    /// [`MAX_CONSECUTIVE_MALFORMED_LINES`] consecutive malformed lines: a
    /// fatal protocol desync per `docs/PROTOCOL.md` section 1. Fail loud,
    /// never limp along on a desynced stream; pins preserved, airlock is
    /// expected to kill and respawn this process.
    FatalDesync,
}

/// One line's read result, before JSON decoding.
enum RawLine {
    Eof,
    /// `too_long` is set when the raw line (excluding the terminator)
    /// exceeded [`MAX_LINE_BYTES`]; `bytes` is truncated/empty in that
    /// case (no point buffering megabytes we're about to discard as
    /// malformed anyway).
    Line {
        bytes: Vec<u8>,
        too_long: bool,
    },
}

/// Reads one `\n`-terminated line from `reader`, bounding how much of an
/// over-length line is actually buffered: once the accumulated length
/// would exceed `MAX_LINE_BYTES`, further bytes up to the next `\n` are
/// consumed and discarded rather than appended, so a hostile or buggy
/// sender streaming an unbounded line cannot grow this process's memory
/// without bound while this reader looks for the terminator.
fn read_raw_line(reader: &mut impl BufRead) -> std::io::Result<RawLine> {
    let mut bytes = Vec::new();
    let mut too_long = false;
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            return Ok(if bytes.is_empty() && !too_long { RawLine::Eof } else { RawLine::Line { bytes, too_long } });
        }
        if let Some(pos) = available.iter().position(|&b| b == b'\n') {
            if !too_long {
                if bytes.len() + pos > MAX_LINE_BYTES {
                    too_long = true;
                    bytes.clear();
                } else {
                    bytes.extend_from_slice(&available[..pos]);
                }
            }
            reader.consume(pos + 1);
            return Ok(RawLine::Line { bytes, too_long });
        } else {
            if !too_long {
                if bytes.len() + available.len() > MAX_LINE_BYTES {
                    too_long = true;
                    bytes.clear();
                } else {
                    bytes.extend_from_slice(available);
                }
            }
            let consumed = available.len();
            reader.consume(consumed);
        }
    }
}

/// Runs the directive read loop against `reader`, calling `handle` for
/// every successfully decoded directive OTHER than `shutdown` (which this
/// loop intercepts itself, since it is a control-flow signal, not
/// something a directive handler applies to state).
pub fn run(mut reader: impl BufRead, mut handle: impl FnMut(DownMessage)) -> StdinOutcome {
    let mut consecutive_malformed: u32 = 0;

    loop {
        let raw = match read_raw_line(&mut reader) {
            Ok(raw) => raw,
            Err(error) => {
                eprintln!("bathyscaphe: stdin read error ({error}); treating as fatal desync");
                return StdinOutcome::FatalDesync;
            }
        };

        let (bytes, too_long) = match raw {
            RawLine::Eof => return StdinOutcome::Eof,
            RawLine::Line { bytes, too_long } => (bytes, too_long),
        };

        if too_long {
            eprintln!("bathyscaphe: stdin line exceeded {MAX_LINE_BYTES} bytes; counting as malformed");
            consecutive_malformed += 1;
            if consecutive_malformed >= MAX_CONSECUTIVE_MALFORMED_LINES {
                return StdinOutcome::FatalDesync;
            }
            continue;
        }

        let line = match std::str::from_utf8(&bytes) {
            Ok(line) => line,
            Err(error) => {
                eprintln!("bathyscaphe: stdin line was not valid UTF-8 ({error}); counting as malformed");
                consecutive_malformed += 1;
                if consecutive_malformed >= MAX_CONSECUTIVE_MALFORMED_LINES {
                    return StdinOutcome::FatalDesync;
                }
                continue;
            }
        };

        match bathyscaphe_proto::decode_line::<DownMessage>(line) {
            Ok(DownMessage::Shutdown(_)) => return StdinOutcome::Shutdown,
            Ok(message) => {
                consecutive_malformed = 0;
                handle(message);
            }
            Err(error) => {
                eprintln!("bathyscaphe: {error}; counting as malformed ({}/{MAX_CONSECUTIVE_MALFORMED_LINES})", consecutive_malformed + 1);
                consecutive_malformed += 1;
                if consecutive_malformed >= MAX_CONSECUTIVE_MALFORMED_LINES {
                    return StdinOutcome::FatalDesync;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bathyscaphe_proto::down::{Release, SyncComplete};
    use std::io::Cursor;

    fn line(json: &str) -> String {
        format!("{json}\n")
    }

    #[test]
    fn a_shutdown_directive_stops_the_loop_gracefully() {
        let input = line(r#"{"kind":"shutdown"}"#);
        let mut seen = Vec::new();
        let outcome = run(Cursor::new(input), |m| seen.push(m));
        assert_eq!(outcome, StdinOutcome::Shutdown);
        assert!(seen.is_empty());
    }

    #[test]
    fn eof_with_no_shutdown_is_reported_as_eof() {
        let outcome = run(Cursor::new(""), |_| {});
        assert_eq!(outcome, StdinOutcome::Eof);
    }

    #[test]
    fn well_formed_directives_are_handled_and_reset_the_malformed_streak() {
        let mut input = String::new();
        input.push_str(&line(r#"{"kind":"bogus"#)); // 1 malformed
        input.push_str(&line(r#"{"kind":"release","container_id":"abc"}"#)); // valid, resets streak
        input.push_str(&line(r#"{"kind":"also-bogus"#)); // 1 malformed again (streak was reset)
        input.push_str(&line(r#"{"kind":"sync_complete"}"#));

        let mut seen = Vec::new();
        let outcome = run(Cursor::new(input), |m| seen.push(m));
        assert_eq!(outcome, StdinOutcome::Eof);
        assert_eq!(seen.len(), 2);
        assert!(matches!(seen[0], DownMessage::Release(Release { .. })));
        assert!(matches!(seen[1], DownMessage::SyncComplete(SyncComplete {})));
    }

    #[test]
    fn three_consecutive_malformed_lines_is_a_fatal_desync() {
        let mut input = String::new();
        input.push_str(&line("not json at all"));
        input.push_str(&line("{}")); // valid JSON, but no `kind` -- still malformed
        input.push_str(&line(r#"{"kind":"unknown_kind_entirely"}"#));

        let mut seen = Vec::new();
        let outcome = run(Cursor::new(input), |m| seen.push(m));
        assert_eq!(outcome, StdinOutcome::FatalDesync);
        assert!(seen.is_empty(), "no directive should be handled once desync is declared");
    }

    #[test]
    fn two_consecutive_malformed_lines_do_not_yet_desync() {
        let mut input = String::new();
        input.push_str(&line("garbage"));
        input.push_str(&line("more garbage"));
        input.push_str(&line(r#"{"kind":"sync_complete"}"#));

        let mut seen = Vec::new();
        let outcome = run(Cursor::new(input), |m| seen.push(m));
        assert_eq!(outcome, StdinOutcome::Eof);
        assert_eq!(seen.len(), 1);
    }

    #[test]
    fn an_oversized_line_counts_as_malformed_without_buffering_it_all() {
        let huge = "x".repeat(MAX_LINE_BYTES + 100);
        let mut input = format!("{huge}\n");
        input.push_str(&line("also garbage"));
        input.push_str(&line("still garbage"));

        let outcome = run(Cursor::new(input), |_| {});
        assert_eq!(outcome, StdinOutcome::FatalDesync);
    }

    #[test]
    fn desync_and_eof_paths_never_call_a_probe_at_all() {
        // The strongest statement this module can make about "preserving
        // pins on desync/EOF" is structural: this loop's `handle` callback
        // is the only place a caller COULD plug in a ProbeApi, and it is
        // never invoked once desync is declared (see the test above) or on
        // a bare EOF with nothing to handle. There is no separate
        // "cleanup" path in this module that touches anything -- the
        // caller (daemon::mod) is the one place pins could be preserved
        // wrongly, and it simply never calls unpin/detach on these two
        // outcomes (see `daemon::mod`'s own doc and `apply`'s tests, which
        // show every ProbeApi mutation goes through directive handling
        // only).
        let outcome = run(Cursor::new(""), |_: DownMessage| panic!("handle must not be called on a bare EOF with no lines"));
        assert_eq!(outcome, StdinOutcome::Eof);
    }
}
