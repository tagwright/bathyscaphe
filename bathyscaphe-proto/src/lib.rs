// SPDX-License-Identifier: GPL-3.0-or-later
//! `bathyscaphe-proto`: the frozen airlock wire protocol types (NDJSON,
//! one object per line, per `bathy_protocol_draft.md`).
//!
//! This crate is a placeholder for build chunk #1 (scaffold + toolchain
//! proof). The full hello/event/directive/stats/security-record shapes
//! land in build chunk #2, field-for-field against the protocol draft,
//! with golden-line tests pinning the frozen wire shapes. What's here now
//! is a minimal serde round-trip so the toolchain proof covers a std+serde
//! crate too, not just the no_std side.

use serde::{Deserialize, Serialize};

/// Placeholder wire type. Stands in for `Hello`/`Event`/`Directive`/etc.
/// until the PROTO crate build chunk lands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlaceholderMessage {
    pub kind: String,
    pub sequence: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placeholder_message_round_trips_through_json() {
        let original = PlaceholderMessage {
            kind: "placeholder".to_string(),
            sequence: 1,
        };
        let encoded = serde_json::to_string(&original).expect("serialize");
        let decoded: PlaceholderMessage = serde_json::from_str(&encoded).expect("deserialize");
        assert_eq!(original, decoded);
    }
}
