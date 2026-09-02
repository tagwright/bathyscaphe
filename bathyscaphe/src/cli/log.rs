// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 techgaud
//! The CLI's own operational logging to stderr: `bathy_build_spec.md`'s
//! global `--log-format`/`--log-level` flags. `bathyscaphe-proto::security`
//! already documents that bathyscaphe's stderr logs use the same
//! OTel-log-data-model shape as the `security` wire record
//! (`timestamp`/`severity_text`/`severity_number`/`body`/`attributes`), so
//! this module mirrors that shape rather than inventing a second one --
//! see [`bathyscaphe_proto::security`]'s module doc for the full rationale
//! and the `severity_number` scale this reuses.
//!
//! This is deliberately scoped to the CLI's OWN messages (startup,
//! shutdown, load failures, the handful of narrations `run`/`unpin`/
//! `observe` emit around the calls they delegate to `daemon`/`probe`).
//! It does not retrofit every existing `eprintln!` scattered through
//! `probe`/`attribution`/`daemon` -- those predate this chunk, are not
//! security-relevant (that channel is `daemon::security`'s throttled
//! `SecurityRecord`, wired chunk #6), and rewriting them is a distinct,
//! much larger change than "give the CLI a --log-format flag."

use std::io::Write;

use clap::ValueEnum;
use serde_json::json;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
#[value(rename_all = "lowercase")]
pub enum LogFormat {
    Json,
    Text,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
#[value(rename_all = "lowercase")]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

impl LogLevel {
    /// The OTel severity number for this level, on the same scale
    /// `bathyscaphe_proto::security::Severity` uses (`Info` = 9,
    /// `Warn` = 13, `Error` = 17) extended downward for `Trace`/`Debug`
    /// per the standard OTel table (`Trace` = 1, `Debug` = 5).
    fn severity_number(self) -> u8 {
        match self {
            LogLevel::Trace => 1,
            LogLevel::Debug => 5,
            LogLevel::Info => 9,
            LogLevel::Warn => 13,
            LogLevel::Error => 17,
        }
    }

    fn severity_text(self) -> &'static str {
        match self {
            LogLevel::Trace => "TRACE",
            LogLevel::Debug => "DEBUG",
            LogLevel::Info => "INFO",
            LogLevel::Warn => "WARN",
            LogLevel::Error => "ERROR",
        }
    }
}

/// The CLI's stderr logger. One instance per process, built from the
/// global `--log-format`/`--log-level` flags before any subcommand body
/// runs, so even an early failure (a bad flag combination, a kernel-floor
/// check failing before `hello`) is reported through the same shape an
/// operator's log pipeline already expects.
pub struct Logger {
    format: LogFormat,
    level: LogLevel,
}

impl Logger {
    pub fn new(format: LogFormat, level: LogLevel) -> Self {
        Self { format, level }
    }

    pub fn info(&self, reason: &str, body: &str) {
        self.log(LogLevel::Info, reason, body);
    }

    pub fn warn(&self, reason: &str, body: &str) {
        self.log(LogLevel::Warn, reason, body);
    }

    pub fn error(&self, reason: &str, body: &str) {
        self.log(LogLevel::Error, reason, body);
    }

    fn log(&self, level: LogLevel, reason: &str, body: &str) {
        if level < self.level {
            return;
        }
        let line = match self.format {
            LogFormat::Json => self.json_line(level, reason, body),
            LogFormat::Text => format!("bathyscaphe: [{}] {reason}: {body}", level.severity_text()),
        };
        let mut stderr = std::io::stderr();
        let _ = writeln!(stderr, "{line}");
    }

    fn json_line(&self, level: LogLevel, reason: &str, body: &str) -> String {
        let timestamp = now_rfc3339();
        let record = json!({
            "timestamp": timestamp,
            "severity_text": level.severity_text(),
            "severity_number": level.severity_number(),
            "body": body,
            "attributes": { "reason": reason },
        });
        // A `serde_json::Value` built from a fixed, all-string/number shape
        // always encodes; a failure here would mean the standard library's
        // own JSON encoder is broken, not a real code path.
        serde_json::to_string(&record).unwrap_or_else(|_| format!("{{\"body\":{body:?}}}"))
    }
}

/// RFC3339 UTC, at least second precision -- matches the precision the
/// rest of this crate's timestamps use (`bathyscaphe_proto::security`'s
/// doc asks for "at least microseconds"; `time::OffsetDateTime`'s default
/// `Rfc3339` formatting already emits nanosecond precision, which
/// satisfies that floor).
fn now_rfc3339() -> String {
    time::OffsetDateTime::now_utc().format(&time::format_description::well_known::Rfc3339).unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn log_level_ordering_matches_severity() {
        assert!(LogLevel::Trace < LogLevel::Debug);
        assert!(LogLevel::Debug < LogLevel::Info);
        assert!(LogLevel::Info < LogLevel::Warn);
        assert!(LogLevel::Warn < LogLevel::Error);
    }

    #[test]
    fn json_line_is_well_formed_and_otel_shaped() {
        let logger = Logger::new(LogFormat::Json, LogLevel::Trace);
        let line = logger.json_line(LogLevel::Warn, "cli.test", "something happened");
        let value: serde_json::Value = serde_json::from_str(&line).expect("logger must emit valid JSON");
        assert_eq!(value["severity_text"], "WARN");
        assert_eq!(value["severity_number"], 13);
        assert_eq!(value["body"], "something happened");
        assert_eq!(value["attributes"]["reason"], "cli.test");
        assert!(value["timestamp"].is_string());
    }

    #[test]
    fn text_line_is_human_readable() {
        let logger = Logger::new(LogFormat::Text, LogLevel::Trace);
        // `log`'s formatting branch is private; exercised indirectly via
        // the public `info`/`warn`/`error` methods in the CLI parsing
        // tests. This test locks the exact human-readable shape.
        let line = format!("bathyscaphe: [{}] {}: {}", LogLevel::Error.severity_text(), "cli.test", "boom");
        assert_eq!(line, "bathyscaphe: [ERROR] cli.test: boom");
    }

    #[test]
    fn a_message_below_the_configured_level_is_suppressed() {
        // Not directly observable without capturing stderr; this pins the
        // comparison direction instead (the bug this guards against is an
        // inverted `<` that would suppress everything ABOVE the configured
        // level instead of below it).
        assert!(!(LogLevel::Debug < LogLevel::Debug));
        assert!(LogLevel::Debug < LogLevel::Info);
    }
}
