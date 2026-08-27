// SPDX-License-Identifier: GPL-3.0-or-later
//! `bathyscaphe-proto`: the frozen airlock wire protocol.
//!
//! NDJSON, one JSON object per line, on two of bathyscaphe's three
//! standard streams: [`up::UpMessage`] lines on stdout (bathyscaphe ->
//! airlock), [`down::DownMessage`] lines on stdin (airlock ->
//! bathyscaphe). stderr carries free-text human logs and is never
//! parsed; it is not modeled here.
//!
//! This crate owns the wire TYPES and the line codec
//! ([`codec::encode_line`] / [`codec::decode_line`]). It does not own the
//! I/O loop, the malformed-line counting, the reconciliation state
//! machine, or the token-bucket throttling of [`security::SecurityRecord`]
//! lines: those are the userspace daemon's job, built on top of these
//! types.
//!
//! See `docs/PROTOCOL.md` for the full human-readable protocol spec
//! (framing, handshake, every message and field, the reconciliation
//! model, the inert-matcher rule, and the security-record mapping to
//! beacon/bilgeline), and `bathy_protocol_draft.md` in the build
//! scratchpad for the ratification record this crate implements.

pub mod codec;
pub mod common;
pub mod down;
pub mod security;
pub mod up;

pub use codec::{decode_line, encode_line, CodecError, MAX_CONSECUTIVE_MALFORMED_LINES, MAX_LINE_BYTES};
pub use common::{
    Capability, Container, DefaultVerdict, Domain, DomainConfidence, DomainSource, Endpoint, EventKind, Mode, Process,
    Runtime, RuleAction, RuleSource, TransportProto, Verdict, PROTO_VERSION,
};
pub use down::{DownMessage, Match, Policy, Release, ReleaseAll, Rule, Shutdown, Start, SyncComplete};
pub use security::{Severity, SecurityContainer, SecurityRecord};
pub use up::{
    AttributeMap, ContainerStats, ErrorMsg, Event, EventMeta, Hello, PinnedContainer, PolicyAck, PolicyAckStatus,
    ReleaseAck, ReleaseStatus, Stats, UpMessage,
};
