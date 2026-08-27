// SPDX-License-Identifier: GPL-3.0-or-later
//! Shared `repr(u8)` enums for values that cross the kernel/user boundary
//! as raw bytes inside the [`crate::event`] and [`crate::policy`] structs.
//!
//! None of these types themselves implement `aya::Pod`, and none of them
//! is ever used directly as a map key/value type parameter or as a field
//! type inside a `#[repr(C)]` map struct. A `repr(u8)` enum only has as
//! many valid bit patterns as it has variants (2 or 3 here, out of 256
//! possible byte values); `unsafe impl Pod` on a type like that would be
//! unsound, because `Pod` promises every bit pattern of the type's size is
//! a valid value, and a map read (or a stray ring buffer entry written
//! before a field is set) can and eventually will hand back a byte that
//! doesn't correspond to any variant. Every `#[repr(C)]` struct in this
//! crate therefore stores these as plain `u8` fields, and the enums here
//! exist purely as a typed, documented decode/encode layer for the
//! daemon (build chunks #5-#8) and the eBPF programs (#4) to use at the
//! edges via [`TryFrom<u8>`] and `as u8`.
//!
//! **Numeric equivalence with `bathyscaphe-proto`**: this crate is
//! `no_std` and must not depend on `bathyscaphe-proto` (a `std` + serde
//! crate), so there is no `From`/`Into` impl bridging the two — the
//! daemon crate (which depends on both) is the bridge. Every enum below
//! is deliberately given discriminants in the *same declaration order* as
//! its `bathyscaphe-proto::common` counterpart, so the mapping is "same
//! variant position" and a daemon-side `match` that lists both enums'
//! variants side by side will not silently drift if either enum's variant
//! order ever changes (the match becomes non-exhaustive instead, a
//! compile error). The exact correspondences are documented per enum
//! below; nothing here reads or re-exports `bathyscaphe-proto`.

/// A single reserved discriminant value is never assigned, so a caller
/// decoding an unexpected byte gets a typed error rather than a panic or
/// a guess.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidDiscriminant(pub u8);

/// Transport used for a connection or a policy matcher.
///
/// Maps 1:1 to `bathyscaphe_proto::common::TransportProto` (`Tcp`, `Udp`
/// in that declaration order).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TransportProto {
    Tcp = 0,
    Udp = 1,
}

impl TryFrom<u8> for TransportProto {
    type Error = InvalidDiscriminant;

    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            0 => Ok(Self::Tcp),
            1 => Ok(Self::Udp),
            other => Err(InvalidDiscriminant(other)),
        }
    }
}

/// The verdict a policy lookup produced, or that a rule expresses as its
/// action. This three-valued form matches
/// `bathyscaphe_proto::common::Verdict` (`Allow`, `Deny`, `WouldDeny` in
/// that order) exactly, but the kernel-written [`crate::event::Event`]
/// struct does NOT store this enum directly in its `verdict` field: that
/// field only ever holds `Allow` or `Deny`, the action the kernel actually
/// took, with a separate `would_deny` byte carrying whether the policy
/// lookup would have denied it regardless of what was actually returned.
/// The daemon reconstructs the three-valued wire `Verdict` from those two
/// kernel fields: `Deny` if `verdict == Deny`, else `WouldDeny` if
/// `would_deny != 0`, else `Allow`. See `event.rs` for the field-level
/// rationale.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Verdict {
    Allow = 0,
    Deny = 1,
    WouldDeny = 2,
}

impl TryFrom<u8> for Verdict {
    type Error = InvalidDiscriminant;

    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            0 => Ok(Self::Allow),
            1 => Ok(Self::Deny),
            2 => Ok(Self::WouldDeny),
            other => Err(InvalidDiscriminant(other)),
        }
    }
}

/// A policy rule's action. Maps 1:1 to
/// `bathyscaphe_proto::common::RuleAction` (`Allow`, `Deny`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RuleAction {
    Allow = 0,
    Deny = 1,
}

impl TryFrom<u8> for RuleAction {
    type Error = InvalidDiscriminant;

    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            0 => Ok(Self::Allow),
            1 => Ok(Self::Deny),
            other => Err(InvalidDiscriminant(other)),
        }
    }
}

/// Provenance of a policy rule. Maps 1:1 to
/// `bathyscaphe_proto::common::RuleSource` (`Static`, `Dns`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RuleSource {
    Static = 0,
    Dns = 1,
}

impl TryFrom<u8> for RuleSource {
    type Error = InvalidDiscriminant;

    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            0 => Ok(Self::Static),
            1 => Ok(Self::Dns),
            other => Err(InvalidDiscriminant(other)),
        }
    }
}

/// Per-container enforcement posture. Maps 1:1 to
/// `bathyscaphe_proto::common::Mode` (`Audit`, `Alert`, `Block`). On the
/// kernel side `Audit` and `Alert` behave identically (always allow,
/// honest `would_deny` accounting); the distinction is airlock-side
/// alerting policy, carried through in [`crate::enforcement::EnforcementState`]
/// only so `stats`/`hello.pinned` can report the operator-visible truth.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Mode {
    Audit = 0,
    Alert = 1,
    Block = 2,
}

impl TryFrom<u8> for Mode {
    type Error = InvalidDiscriminant;

    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            0 => Ok(Self::Audit),
            1 => Ok(Self::Alert),
            2 => Ok(Self::Block),
            other => Err(InvalidDiscriminant(other)),
        }
    }
}

/// Verdict applied when no policy rule matches. Maps 1:1 to
/// `bathyscaphe_proto::common::DefaultVerdict` (`Allow`, `Deny`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DefaultVerdict {
    Allow = 0,
    Deny = 1,
}

impl TryFrom<u8> for DefaultVerdict {
    type Error = InvalidDiscriminant;

    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            0 => Ok(Self::Allow),
            1 => Ok(Self::Deny),
            other => Err(InvalidDiscriminant(other)),
        }
    }
}

/// The observed lifecycle point of a connection. Maps 1:1 to
/// `bathyscaphe_proto::common::EventKind` (`Connect`, `Accept`, `Close`).
/// v1 kernel programs emit `Connect` only; the other two discriminants
/// are reserved now so a later build (accept-side / close-side hooks) is
/// additive with no ABI break.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum EventType {
    Connect = 0,
    Accept = 1,
    Close = 2,
}

impl TryFrom<u8> for EventType {
    type Error = InvalidDiscriminant;

    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            0 => Ok(Self::Connect),
            1 => Ok(Self::Accept),
            2 => Ok(Self::Close),
            other => Err(InvalidDiscriminant(other)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_every_valid_discriminant() {
        assert_eq!(TransportProto::try_from(0u8).unwrap(), TransportProto::Tcp);
        assert_eq!(TransportProto::try_from(1u8).unwrap(), TransportProto::Udp);
        assert!(TransportProto::try_from(2u8).is_err());

        assert_eq!(Verdict::try_from(0u8).unwrap(), Verdict::Allow);
        assert_eq!(Verdict::try_from(1u8).unwrap(), Verdict::Deny);
        assert_eq!(Verdict::try_from(2u8).unwrap(), Verdict::WouldDeny);
        assert!(Verdict::try_from(3u8).is_err());

        assert_eq!(RuleAction::try_from(0u8).unwrap(), RuleAction::Allow);
        assert_eq!(RuleAction::try_from(1u8).unwrap(), RuleAction::Deny);
        assert!(RuleAction::try_from(2u8).is_err());

        assert_eq!(RuleSource::try_from(0u8).unwrap(), RuleSource::Static);
        assert_eq!(RuleSource::try_from(1u8).unwrap(), RuleSource::Dns);
        assert!(RuleSource::try_from(2u8).is_err());

        assert_eq!(Mode::try_from(0u8).unwrap(), Mode::Audit);
        assert_eq!(Mode::try_from(1u8).unwrap(), Mode::Alert);
        assert_eq!(Mode::try_from(2u8).unwrap(), Mode::Block);
        assert!(Mode::try_from(3u8).is_err());

        assert_eq!(DefaultVerdict::try_from(0u8).unwrap(), DefaultVerdict::Allow);
        assert_eq!(DefaultVerdict::try_from(1u8).unwrap(), DefaultVerdict::Deny);
        assert!(DefaultVerdict::try_from(2u8).is_err());

        assert_eq!(EventType::try_from(0u8).unwrap(), EventType::Connect);
        assert_eq!(EventType::try_from(1u8).unwrap(), EventType::Accept);
        assert_eq!(EventType::try_from(2u8).unwrap(), EventType::Close);
        assert!(EventType::try_from(3u8).is_err());
    }
}
