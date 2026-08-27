// SPDX-License-Identifier: GPL-3.0-or-later
//! A thin NDJSON line codec. This crate owns the message types and the
//! single-line encode/decode step; the daemon owns the actual I/O loop
//! (reading stdin line by line, writing stdout, counting consecutive
//! malformed lines, deciding when to give up and exit).

use std::fmt;

/// Maximum accepted line length, in bytes. A longer line is a protocol
/// error per `bathy_protocol_draft.md` section 1: the daemon counts it
/// toward the consecutive-malformed-line budget rather than trying to
/// salvage a partial parse.
pub const MAX_LINE_BYTES: usize = 1024 * 1024;

/// Three consecutive malformed lines on either stream is a fatal
/// protocol error: the reader terminates the session (airlock kills and
/// respawns bathyscaphe; bathyscaphe exits nonzero on its stdin side).
/// This crate only documents the threshold; the daemon's I/O loop
/// enforces it.
pub const MAX_CONSECUTIVE_MALFORMED_LINES: u32 = 3;

/// A failure to decode one line.
#[derive(Debug)]
pub enum CodecError {
    /// The line exceeded [`MAX_LINE_BYTES`], given in bytes.
    TooLong(usize),
    /// The line was not valid JSON for the requested type (bad syntax,
    /// missing `kind`, or an unrecognized top-level `kind`. Ignore-unknown
    /// applies to fields, per section 7, not to being unable to decode
    /// the line at all).
    Json(serde_json::Error),
}

impl fmt::Display for CodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CodecError::TooLong(len) => {
                write!(f, "line of {len} bytes exceeds the {MAX_LINE_BYTES}-byte cap")
            }
            CodecError::Json(err) => write!(f, "malformed protocol line: {err}"),
        }
    }
}

impl std::error::Error for CodecError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            CodecError::TooLong(_) => None,
            CodecError::Json(err) => Some(err),
        }
    }
}

/// Encode one message to a single-line, `\n`-free JSON string. Callers
/// append the line terminator themselves when writing to the stream. A
/// conformant JSON encoder never emits a raw newline inside a string (it
/// is escaped), so the "no embedded newlines" property holds for any
/// valid input; the assertion below only guards against a future field
/// type that bypasses `serde_json`'s string escaping.
pub fn encode_line<T: serde::Serialize>(message: &T) -> Result<String, serde_json::Error> {
    let line = serde_json::to_string(message)?;
    debug_assert!(!line.contains('\n'), "encoded protocol line contained a raw newline");
    Ok(line)
}

/// Decode one line into a message. Rejects lines over [`MAX_LINE_BYTES`]
/// before attempting to parse.
pub fn decode_line<T: for<'de> serde::Deserialize<'de>>(line: &str) -> Result<T, CodecError> {
    if line.len() > MAX_LINE_BYTES {
        return Err(CodecError::TooLong(line.len()));
    }
    serde_json::from_str(line).map_err(CodecError::Json)
}
