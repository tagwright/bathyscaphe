// SPDX-License-Identifier: GPL-3.0-or-later
//! [`ProbeApi`]: the seam between the daemon's directive-compilation and
//! reconciliation logic and the real, kernel-touching [`crate::probe::Probe`].
//! Every daemon module that needs to read or write a kernel map depends on
//! this trait, never on `Probe` directly, so the compilation/reconciliation
//! logic is unit-testable with [`MockProbe`] (an in-memory recorder) and
//! never needs root, a real cgroup v2 host, or a loaded eBPF program to run
//! under `cargo test`.

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use anyhow::Result;
use bathyscaphe_common::{DefaultVerdict, EnforcementState, Mode, PolicyValue, TamperCounter};

/// Everything the daemon needs from a loaded probe: attach/detach,
/// per-container policy entries, per-container enforcement posture, and
/// the read-only tamper counter. Mirrors [`crate::probe::Probe`]'s public
/// surface (plus the `PolicyStore::tracked_keys`/`remove_key` pair added
/// alongside this chunk) one to one -- this trait adds no new concepts,
/// only a name a mock can also implement.
pub trait ProbeApi: Send {
    fn attach_container(&mut self, cgroup_path: &Path) -> Result<u64>;
    fn detach_container(&mut self, cgroup_id: u64) -> Result<()>;
    fn attached_containers(&self) -> Vec<u64>;

    /// Inserts (or overwrites) one policy entry. `prefix_bits_over_addr`
    /// follows `probe::policy::build_policy_key`'s convention: bits of the
    /// 128-bit RFC 4291 address to pin, beyond the always-fully-matched
    /// `cgroup_id`.
    fn set_policy(&mut self, cgroup_id: u64, addr: IpAddr, prefix_bits_over_addr: u32, value: PolicyValue) -> Result<()>;
    /// Snapshot of the raw `(prefix_len, addr)` keys currently tracked for
    /// `cgroup_id`, for make-before-break diffing.
    fn tracked_policy_keys(&self, cgroup_id: u64) -> Vec<(u32, [u8; 16])>;
    /// Removes exactly one previously-inserted key.
    fn remove_policy_key(&mut self, cgroup_id: u64, prefix_len: u32, addr: [u8; 16]) -> Result<bool>;
    /// Removes every tracked policy entry for `cgroup_id`.
    fn release_policy_container(&mut self, cgroup_id: u64) -> Result<usize>;

    fn set_enforcement(&mut self, cgroup_id: u64, mode: Mode, default_verdict: DefaultVerdict, generation: u64) -> Result<()>;
    fn clear_enforcement(&mut self, cgroup_id: u64) -> Result<()>;
    fn get_enforcement(&self, cgroup_id: u64) -> Result<Option<EnforcementState>>;

    fn read_tamper(&self, cgroup_id: u64) -> Result<TamperCounter>;
}

impl ProbeApi for crate::probe::Probe {
    fn attach_container(&mut self, cgroup_path: &Path) -> Result<u64> {
        crate::probe::Probe::attach_container(self, cgroup_path)
    }

    fn detach_container(&mut self, cgroup_id: u64) -> Result<()> {
        crate::probe::Probe::detach_container(self, cgroup_id)
    }

    fn attached_containers(&self) -> Vec<u64> {
        crate::probe::Probe::attached_containers(self).collect()
    }

    fn set_policy(&mut self, cgroup_id: u64, addr: IpAddr, prefix_bits_over_addr: u32, value: PolicyValue) -> Result<()> {
        self.policy.set_policy(cgroup_id, addr, prefix_bits_over_addr, value)
    }

    fn tracked_policy_keys(&self, cgroup_id: u64) -> Vec<(u32, [u8; 16])> {
        self.policy.tracked_keys(cgroup_id)
    }

    fn remove_policy_key(&mut self, cgroup_id: u64, prefix_len: u32, addr: [u8; 16]) -> Result<bool> {
        self.policy.remove_key(cgroup_id, prefix_len, addr)
    }

    fn release_policy_container(&mut self, cgroup_id: u64) -> Result<usize> {
        self.policy.release_container(cgroup_id)
    }

    fn set_enforcement(&mut self, cgroup_id: u64, mode: Mode, default_verdict: DefaultVerdict, generation: u64) -> Result<()> {
        self.enforcement.set_enforcement(cgroup_id, mode, default_verdict, generation)
    }

    fn clear_enforcement(&mut self, cgroup_id: u64) -> Result<()> {
        self.enforcement.clear_enforcement(cgroup_id)
    }

    fn get_enforcement(&self, cgroup_id: u64) -> Result<Option<EnforcementState>> {
        self.enforcement.get(cgroup_id)
    }

    fn read_tamper(&self, cgroup_id: u64) -> Result<TamperCounter> {
        self.tamper.read_tamper(cgroup_id)
    }
}

/// Lets `daemon::mod` share one `Arc<Mutex<Probe>>` between the directive
/// loop (needs `&mut dyn ProbeApi`, above) and the event pipeline (needs a
/// `pipeline::sink::TamperSource`, chunk #6's seam for the ring-buf
/// consumer's per-event tamper-delta lookups): `pipeline::sink` already
/// provides `impl<T: TamperSource> TamperSource for Arc<Mutex<T>>`, so this
/// one delegating impl is all that is needed to make `Arc<Mutex<Probe>>`
/// itself a valid `TamperSource`.
impl crate::pipeline::TamperSource for crate::probe::Probe {
    fn read_tamper(&self, cgroup_id: u64) -> Result<TamperCounter> {
        self.tamper.read_tamper(cgroup_id)
    }
}

/// An in-memory, no-kernel-required stand-in for [`crate::probe::Probe`],
/// used by every unit test in `daemon::*` that exercises directive
/// compilation, make-before-break diffing, or reconciliation. Every call
/// is also appended to [`Self::calls`] so a test can assert not just the
/// end state but the exact sequence of destructive-vs-non-destructive
/// operations issued (the desync/shutdown "preserves pins" tests depend on
/// this: they assert zero `Detach`/`ReleasePolicy`/`ClearEnforcement`
/// calls happened).
#[derive(Default)]
pub struct MockProbe {
    pub attached: std::collections::HashSet<u64>,
    pub next_cgroup_id: u64,
    pub path_to_cgroup_id: HashMap<PathBuf, u64>,
    pub policy_keys: HashMap<u64, HashMap<(u32, [u8; 16]), PolicyValue>>,
    pub enforcement: HashMap<u64, EnforcementState>,
    pub tamper: HashMap<u64, TamperCounter>,
    pub calls: Vec<MockCall>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MockCall {
    Attach(u64),
    Detach(u64),
    SetPolicy(u64),
    RemovePolicyKey(u64),
    ReleasePolicyContainer(u64),
    SetEnforcement(u64),
    ClearEnforcement(u64),
}

impl MockProbe {
    pub fn new() -> Self {
        Self::default()
    }

    /// Test helper: pre-seed a cgroup id for a given path, standing in for
    /// what a real host's inode-derived id would be, without actually
    /// stat-ing a filesystem path.
    pub fn seed_path(&mut self, path: &Path, cgroup_id: u64) {
        self.path_to_cgroup_id.insert(path.to_path_buf(), cgroup_id);
    }

    /// True iff no call in [`Self::calls`] ever tore down enforcement or
    /// detached a container -- the property the desync/shutdown tests
    /// check.
    pub fn made_no_destructive_calls(&self) -> bool {
        !self.calls.iter().any(|c| matches!(c, MockCall::Detach(_) | MockCall::RemovePolicyKey(_) | MockCall::ReleasePolicyContainer(_) | MockCall::ClearEnforcement(_)))
    }
}

impl ProbeApi for MockProbe {
    fn attach_container(&mut self, cgroup_path: &Path) -> Result<u64> {
        let cgroup_id = *self.path_to_cgroup_id.entry(cgroup_path.to_path_buf()).or_insert_with(|| {
            self.next_cgroup_id += 1;
            self.next_cgroup_id
        });
        if !self.attached.insert(cgroup_id) {
            anyhow::bail!("cgroup {cgroup_id} already attached");
        }
        self.calls.push(MockCall::Attach(cgroup_id));
        Ok(cgroup_id)
    }

    fn detach_container(&mut self, cgroup_id: u64) -> Result<()> {
        if !self.attached.remove(&cgroup_id) {
            anyhow::bail!("cgroup {cgroup_id} not attached");
        }
        self.calls.push(MockCall::Detach(cgroup_id));
        Ok(())
    }

    fn attached_containers(&self) -> Vec<u64> {
        self.attached.iter().copied().collect()
    }

    fn set_policy(&mut self, cgroup_id: u64, addr: IpAddr, prefix_bits_over_addr: u32, value: PolicyValue) -> Result<()> {
        let addr_bytes = crate::probe::policy::addr_to_rfc4291(addr);
        let prefix_len = bathyscaphe_common::PolicyKeyData::MIN_PREFIX_LEN + prefix_bits_over_addr;
        self.policy_keys.entry(cgroup_id).or_default().insert((prefix_len, addr_bytes), value);
        self.calls.push(MockCall::SetPolicy(cgroup_id));
        Ok(())
    }

    fn tracked_policy_keys(&self, cgroup_id: u64) -> Vec<(u32, [u8; 16])> {
        self.policy_keys.get(&cgroup_id).map(|m| m.keys().copied().collect()).unwrap_or_default()
    }

    fn remove_policy_key(&mut self, cgroup_id: u64, prefix_len: u32, addr: [u8; 16]) -> Result<bool> {
        let removed = self.policy_keys.get_mut(&cgroup_id).map(|m| m.remove(&(prefix_len, addr)).is_some()).unwrap_or(false);
        self.calls.push(MockCall::RemovePolicyKey(cgroup_id));
        Ok(removed)
    }

    fn release_policy_container(&mut self, cgroup_id: u64) -> Result<usize> {
        let removed = self.policy_keys.remove(&cgroup_id).map(|m| m.len()).unwrap_or(0);
        self.calls.push(MockCall::ReleasePolicyContainer(cgroup_id));
        Ok(removed)
    }

    fn set_enforcement(&mut self, cgroup_id: u64, mode: Mode, default_verdict: DefaultVerdict, generation: u64) -> Result<()> {
        self.enforcement.insert(cgroup_id, EnforcementState::new(generation, mode as u8, default_verdict as u8));
        self.calls.push(MockCall::SetEnforcement(cgroup_id));
        Ok(())
    }

    fn clear_enforcement(&mut self, cgroup_id: u64) -> Result<()> {
        self.enforcement.remove(&cgroup_id);
        self.calls.push(MockCall::ClearEnforcement(cgroup_id));
        Ok(())
    }

    fn get_enforcement(&self, cgroup_id: u64) -> Result<Option<EnforcementState>> {
        Ok(self.enforcement.get(&cgroup_id).copied())
    }

    fn read_tamper(&self, cgroup_id: u64) -> Result<TamperCounter> {
        Ok(self.tamper.get(&cgroup_id).copied().unwrap_or(TamperCounter::zero()))
    }
}
