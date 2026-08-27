// SPDX-License-Identifier: GPL-3.0-or-later
//! The userspace eBPF lifecycle: load-or-reopen, attach/detach a container's
//! cgroup, fail-closed bpffs pinning, and the typed map APIs
//! ([`policy::PolicyStore`], [`enforcement::EnforcementStore`],
//! [`tamper::TamperStore`]) plus the [`events::EventConsumer`] ring buffer
//! reader. Not wired to a CLI or the airlock protocol loop yet -- that's a
//! later build chunk; this one is the foundation it sits on.
//!
//! # Pin layout
//!
//! ```text
//! <bpffs_root>/                     default: /sys/fs/bpf/bathyscaphe
//!   maps/
//!     policy                        LpmTrie<PolicyKeyData, PolicyValue> -- shared, all containers
//!     enforcement                   HashMap<u64 cgroup_id, EnforcementState>
//!     tamper                        HashMap<u64 cgroup_id, TamperCounter>
//!     events                        RingBuf -- shared event stream
//!     dns_events                    RingBuf -- shared DNS-observation stream (build chunk #9)
//!   progs/
//!     connect4  connect6  sendmsg4  sendmsg6  sock_create  dns_snoop
//!                                   the six GLOBAL programs: one loaded instance each,
//!                                   attached to every enforced container's cgroup. dns_snoop
//!                                   (a CgroupSkb program, attached ingress) is pure DNS
//!                                   observation -- see bathyscaphe-ebpf::dns's module doc.
//!   links/
//!     <cgroup_id, 16 lowercase hex digits>/
//!       connect4  connect6  sendmsg4  sendmsg6  sock_create  dns_snoop
//!                                   per-container attach links, pinned individually so one
//!                                   container's detach never touches another's
//! ```
//!
//! # DNS observation only runs while userspace is alive
//!
//! Unlike the connect4/6, sendmsg4/6, and sock_create hooks (whose
//! enforcement/observation decisions are entirely self-contained in the
//! kernel, reading only pinned maps), `dns_snoop`'s captured payloads are
//! useless until a *live* userspace process drains `DNS_EVENTS`, parses
//! them, and updates the IP->domain cache (`crate::dns::DomainCache`). If
//! bathyscaphe is dead, `dns_snoop` keeps running (it is pinned like every
//! other program here) and keeps writing into the ring, but nothing reads
//! it: the ring fills and the kernel starts dropping new captures the
//! moment it's full, with no counter tracking that loss (deliberately not
//! sharing `bathyscaphe_common::counters::TamperCounter`, since a dropped
//! DNS capture is never a security-relevant loss the way a dropped
//! connect/sendmsg event is -- see `bathyscaphe-ebpf::dns`'s module doc).
//! Concretely: **a dead probe stops learning new domain names**, but
//! **any IP already inserted into the policy allow-map by a live probe
//! before it died keeps being enforced** (fail-closed, per the module
//! doc above) until that entry's own TTL expires. This asymmetry --
//! enforcement survives a dead probe, DNS learning does not -- is exactly
//! why chunk #10 (FQDN enforcement) inserting DNS-derived IPs into the
//! POLICY map with their own absolute TTL is the right design: the
//! insertion is a one-time kernel-side write that outlives the userspace
//! process that made it, even though *making new ones* requires that
//! process to be running.
//!
//! Maps and programs are GLOBAL: one loaded instance each, shared by every
//! container (see `bathyscaphe_common::policy`'s module doc for why the
//! policy map itself is one flat, cgroup-id-prefixed `LpmTrie` rather than
//! per-container map-in-map -- that toolchain gap is exactly why isolation
//! is enforced in [`policy`] instead of by the map structure). Only LINKS
//! are per-container.
//!
//! # Restart lifecycle (the fail-closed guarantee)
//!
//! [`Probe::load_or_reopen`] is the only entry point:
//!
//! - **Fresh boot** (`<bpffs_root>` absent or empty): loads the embedded
//!   object with `aya::Ebpf::load`, `.load()`s and `.pin()`s every program,
//!   `.pin()`s every map, then immediately re-opens everything straight
//!   back out of those pins. Fresh boot and resumed boot deliberately end
//!   up building the identical in-memory `Probe` the identical way -- there
//!   is one code path for "how do I get a working `Probe`", not two that
//!   can silently drift apart.
//! - **Resumed boot** (`<bpffs_root>` fully populated): `aya::Ebpf::load` is
//!   never called at all. Loading the object again would create brand-new,
//!   empty map instances alongside the ones already enforcing in the
//!   kernel -- exactly the bug pinning exists to prevent. Instead: the four
//!   maps are re-opened via `MapData::from_pin` + `Map::from_map_data`, the
//!   five programs via `<Type>::from_pin(path, attach_type)`, and `links/`
//!   is walked to rediscover every still-enforcing container so
//!   [`Probe::detach_container`] and a later reconciliation layer know
//!   what's already live. The pinned LINKS themselves were never touched by
//!   any of this -- they kept every program attached and enforcing,
//!   in-kernel, for the entire time this process was not running. That is
//!   the fail-closed guarantee in its entirety (`bathy_ebpf_design.md`
//!   section 3): a probe crash freezes enforcement at last-known-good, and
//!   a supervised restart resumes managing it without ever having stopped
//!   enforcing.
//! - **Partially-populated** `<bpffs_root>` (some but not all expected pins
//!   present -- most plausibly a crash partway through a fresh load):
//!   `load_or_reopen` refuses to guess which half of a broken state to
//!   trust, and returns an error naming exactly what's missing. The
//!   break-glass [`Probe::unpin_all_at`] is the documented recovery path
//!   (a later chunk wires it up as `bathyscaphe unpin --all`).

pub mod cgroup;
pub mod clock;
pub mod dns;
pub mod enforcement;
pub mod events;
pub mod kernel_floor;
pub mod layout;
pub mod policy;
pub mod tamper;

use std::collections::HashMap;
use std::fs::File;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use aya::maps::lpm_trie::LpmTrie;
use aya::maps::{HashMap as BpfHashMap, Map, MapData, RingBuf};
use aya::programs::links::{FdLink, PinnedLink};
use aya::programs::{CgroupAttachMode, CgroupSkb, CgroupSkbAttachType, CgroupSock, CgroupSockAddr, CgroupSockAddrAttachType, CgroupSockAttachType};
use bathyscaphe_common::{EnforcementState, PolicyKeyData, PolicyValue, TamperCounter};

pub use dns::{DnsCallback, DnsCaptureConsumer};
pub use enforcement::EnforcementStore;
pub use events::{EventCallback, EventConsumer};
pub use layout::{DEFAULT_BPFFS_ROOT, PinPaths};
pub use policy::PolicyStore;
pub use tamper::TamperStore;

use layout::{MAP_PIN_NAMES, PROG_NAMES, PinState};

/// The per-container link pin paths this process is currently tracking,
/// either because it attached them itself this run or because it
/// rediscovered them under `links/` on a resumed boot.
struct ContainerLinks {
    pins: Vec<PathBuf>,
}

/// The live handle on a loaded (or reopened) bathyscaphe probe.
pub struct Probe {
    paths: PinPaths,
    connect4: CgroupSockAddr,
    connect6: CgroupSockAddr,
    sendmsg4: CgroupSockAddr,
    sendmsg6: CgroupSockAddr,
    sock_create: CgroupSock,
    /// DNS observation (build chunk #9). A `CgroupSkb` program, attached
    /// **ingress** -- see `bathyscaphe-ebpf::dns`'s module doc for the
    /// program-type/direction choice.
    dns_snoop: CgroupSkb,
    pub policy: PolicyStore,
    pub enforcement: EnforcementStore,
    pub tamper: TamperStore,
    events_map: Option<RingBuf<MapData>>,
    dns_events_map: Option<RingBuf<MapData>>,
    containers: HashMap<u64, ContainerLinks>,
}

impl Probe {
    /// Loads or reopens the probe. See the module doc for the full
    /// fresh-vs-resumed-vs-partial decision tree. `ebpf_object` is the
    /// embedded BPF ELF object (`bathyscaphe`'s `EBPF_OBJECT` constant);
    /// `bpffs_root` is normally [`DEFAULT_BPFFS_ROOT`].
    pub fn load_or_reopen(ebpf_object: &[u8], bpffs_root: impl Into<PathBuf>) -> Result<Self> {
        kernel_floor::check().context("kernel floor check failed")?;

        let paths = PinPaths::new(bpffs_root);
        std::fs::create_dir_all(paths.maps_dir()).context("failed to create the maps/ pin directory")?;
        std::fs::create_dir_all(paths.progs_dir()).context("failed to create the progs/ pin directory")?;
        std::fs::create_dir_all(paths.links_dir()).context("failed to create the links/ pin directory")?;

        match layout::pin_state(&paths) {
            PinState::Fresh => load_fresh_and_pin(ebpf_object, &paths)?,
            PinState::Complete => {}
            PinState::Partial(missing) => {
                anyhow::bail!(
                    "the bathyscaphe pin subtree at {} is incomplete (missing: {}); this looks \
                     like a crash partway through a fresh load. Refusing to guess which half of \
                     a broken state to trust -- run the break-glass `unpin --all` to clear it and \
                     start over.",
                    paths.root.display(),
                    missing.join(", ")
                );
            }
        }

        reopen_from_pins(paths)
    }

    /// Attaches all five programs to `cgroup_path` (a cgroup v2 directory)
    /// and pins each resulting link under `links/<cgroup_id>/`. Returns the
    /// cgroup id (the caller's key into [`Self::policy`],
    /// [`Self::enforcement`], and [`Self::tamper`] from here on).
    pub fn attach_container(&mut self, cgroup_path: &Path) -> Result<u64> {
        let cgroup_id = cgroup::cgroup_id_of(cgroup_path).with_context(|| format!("failed to determine cgroup id for {}", cgroup_path.display()))?;
        if self.containers.contains_key(&cgroup_id) {
            anyhow::bail!("cgroup {cgroup_id:016x} ({}) is already attached", cgroup_path.display());
        }

        let cgroup_fd = File::open(cgroup_path).with_context(|| format!("failed to open cgroup directory {}", cgroup_path.display()))?;
        let link_dir = self.paths.container_links_dir(cgroup_id);
        std::fs::create_dir_all(&link_dir).with_context(|| format!("failed to create link pin directory {}", link_dir.display()))?;

        match self.attach_all_programs(&cgroup_fd, cgroup_id) {
            Ok(pins) => {
                self.containers.insert(cgroup_id, ContainerLinks { pins });
                Ok(cgroup_id)
            }
            Err(error) => {
                // Best-effort rollback: never leave a half-attached
                // container's links lying around pinned. Failures here are
                // logged, not propagated -- the original error is what the
                // caller needs to see.
                for prog_name in PROG_NAMES {
                    let path = self.paths.container_link_path(cgroup_id, prog_name);
                    if let Ok(pinned) = PinnedLink::from_pin(&path) {
                        let _ = pinned.unpin();
                    }
                }
                let _ = std::fs::remove_dir(&link_dir);
                Err(error)
            }
        }
    }

    /// Attaches all five programs to `cgroup_fd` and pins each resulting
    /// link, stopping at the first failure. A plain method rather than a
    /// closure over `self` -- it needs simultaneous `&mut` access to five
    /// disjoint fields (`connect4` .. `sock_create`) plus a `&` borrow of
    /// `paths`, which a method's ordinary field access expresses directly
    /// instead of leaning on closure capture inference.
    fn attach_all_programs(&mut self, cgroup_fd: &File, cgroup_id: u64) -> Result<Vec<PathBuf>> {
        let mut pinned = Vec::with_capacity(PROG_NAMES.len());
        pinned.push(attach_and_pin_sock_addr(&mut self.connect4, "connect4", cgroup_fd, cgroup_id, &self.paths)?);
        pinned.push(attach_and_pin_sock_addr(&mut self.connect6, "connect6", cgroup_fd, cgroup_id, &self.paths)?);
        pinned.push(attach_and_pin_sock_addr(&mut self.sendmsg4, "sendmsg4", cgroup_fd, cgroup_id, &self.paths)?);
        pinned.push(attach_and_pin_sock_addr(&mut self.sendmsg6, "sendmsg6", cgroup_fd, cgroup_id, &self.paths)?);
        pinned.push(attach_and_pin_sock(&mut self.sock_create, "sock_create", cgroup_fd, cgroup_id, &self.paths)?);
        pinned.push(attach_and_pin_cgroup_skb(&mut self.dns_snoop, "dns_snoop", CgroupSkbAttachType::Ingress, cgroup_fd, cgroup_id, &self.paths)?);
        Ok(pinned)
    }

    /// Unpins every link for `cgroup_id` (which is what actually detaches
    /// the programs, once the pin is gone and the last fd reference drops)
    /// and forgets it. Errors on individual links are collected and
    /// reported together rather than stopping at the first one, so a
    /// partial failure doesn't leave the rest silently un-detached.
    pub fn detach_container(&mut self, cgroup_id: u64) -> Result<()> {
        let Some(entry) = self.containers.remove(&cgroup_id) else {
            anyhow::bail!("cgroup {cgroup_id:016x} is not currently attached");
        };

        let mut errors = Vec::new();
        for path in &entry.pins {
            match PinnedLink::from_pin(path) {
                Ok(pinned) => {
                    // `unpin` removes the bpffs file and returns the
                    // FdLink; dropping it here closes the last fd reference,
                    // which is what actually detaches the program now that
                    // nothing else pins it.
                    if let Err(error) = pinned.unpin() {
                        errors.push(format!("{}: {error}", path.display()));
                    }
                }
                Err(error) => errors.push(format!("{}: {error}", path.display())),
            }
        }
        let _ = std::fs::remove_dir(self.paths.container_links_dir(cgroup_id));

        if errors.is_empty() { Ok(()) } else { anyhow::bail!("detach_container({cgroup_id:016x}) had {} error(s): {}", errors.len(), errors.join("; ")) }
    }

    /// Every cgroup id currently tracked as attached (attached this run, or
    /// rediscovered from `links/` on a resumed boot).
    pub fn attached_containers(&self) -> impl Iterator<Item = u64> + '_ {
        self.containers.keys().copied()
    }

    /// Takes ownership of the `EVENTS` ring buffer, for handing to
    /// [`EventConsumer::spawn`]. Returns `None` if already taken.
    pub fn take_events(&mut self) -> Option<RingBuf<MapData>> {
        self.events_map.take()
    }

    /// Takes ownership of the `DNS_EVENTS` ring buffer, for handing to
    /// [`DnsCaptureConsumer::spawn`]. Returns `None` if already taken. See
    /// this module's doc for why nothing reads it if the caller never does.
    pub fn take_dns_events(&mut self) -> Option<RingBuf<MapData>> {
        self.dns_events_map.take()
    }

    /// Deletes every policy entry in the shared trie whose `expires_at_ns`
    /// has passed, using the real `CLOCK_BOOTTIME` clock. See
    /// [`PolicyStore::reap_expired`] for why this matters beyond simple
    /// cleanup.
    pub fn reap_expired_policy(&mut self) -> Result<usize> {
        let now = clock::now_boottime_ns()?;
        self.policy.reap_expired(now)
    }

    /// Standalone break-glass: removes the entire pin subtree at `root`,
    /// detaching every program from every container and freeing every map,
    /// with no running probe and no airlock required. This is what a later
    /// chunk's `bathyscaphe unpin --all` CLI calls directly.
    pub fn unpin_all_at(root: &Path) -> Result<()> {
        match std::fs::remove_dir_all(root) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error).with_context(|| format!("failed to remove bpffs pin subtree {}", root.display())),
        }
    }

    /// Instance-method convenience over [`Self::unpin_all_at`]: tears down
    /// this probe's own pin subtree. Consumes `self` since every handle it
    /// holds refers to state this call is about to invalidate.
    pub fn unpin_all(self) -> Result<()> {
        let root = self.paths.root.clone();
        drop(self);
        Self::unpin_all_at(&root)
    }
}

fn load_fresh_and_pin(ebpf_object: &[u8], paths: &PinPaths) -> Result<()> {
    let mut ebpf = aya::Ebpf::load(ebpf_object).context("aya::Ebpf::load failed")?;

    load_and_pin_sock_addr(&mut ebpf, "connect4", paths)?;
    load_and_pin_sock_addr(&mut ebpf, "connect6", paths)?;
    load_and_pin_sock_addr(&mut ebpf, "sendmsg4", paths)?;
    load_and_pin_sock_addr(&mut ebpf, "sendmsg6", paths)?;
    load_and_pin_sock(&mut ebpf, "sock_create", paths)?;
    load_and_pin_cgroup_skb(&mut ebpf, "dns_snoop", paths)?;

    for (ebpf_name, pin_basename) in MAP_PIN_NAMES {
        let map = ebpf.take_map(ebpf_name).with_context(|| format!("map `{ebpf_name}` not found in the embedded eBPF object"))?;
        map.pin(paths.map_path(pin_basename)).with_context(|| format!("failed to pin map `{ebpf_name}`"))?;
    }

    Ok(())
}

fn load_and_pin_sock_addr(ebpf: &mut aya::Ebpf, name: &str, paths: &PinPaths) -> Result<()> {
    let prog: &mut CgroupSockAddr = ebpf
        .program_mut(name)
        .with_context(|| format!("program `{name}` not found in the embedded eBPF object"))?
        .try_into()
        .with_context(|| format!("program `{name}` is not a CgroupSockAddr program"))?;
    prog.load().with_context(|| format!("verifier rejected program `{name}`"))?;
    prog.pin(paths.prog_path(name)).with_context(|| format!("failed to pin program `{name}`"))?;
    Ok(())
}

fn load_and_pin_sock(ebpf: &mut aya::Ebpf, name: &str, paths: &PinPaths) -> Result<()> {
    let prog: &mut CgroupSock = ebpf
        .program_mut(name)
        .with_context(|| format!("program `{name}` not found in the embedded eBPF object"))?
        .try_into()
        .with_context(|| format!("program `{name}` is not a CgroupSock program"))?;
    prog.load().with_context(|| format!("verifier rejected program `{name}`"))?;
    prog.pin(paths.prog_path(name)).with_context(|| format!("failed to pin program `{name}`"))?;
    Ok(())
}

fn load_and_pin_cgroup_skb(ebpf: &mut aya::Ebpf, name: &str, paths: &PinPaths) -> Result<()> {
    let prog: &mut CgroupSkb = ebpf
        .program_mut(name)
        .with_context(|| format!("program `{name}` not found in the embedded eBPF object"))?
        .try_into()
        .with_context(|| format!("program `{name}` is not a CgroupSkb program"))?;
    prog.load().with_context(|| format!("verifier rejected program `{name}`"))?;
    prog.pin(paths.prog_path(name)).with_context(|| format!("failed to pin program `{name}`"))?;
    Ok(())
}

fn reopen_from_pins(paths: PinPaths) -> Result<Probe> {
    let connect4 = reopen_sock_addr(&paths, "connect4", CgroupSockAddrAttachType::Connect4)?;
    let connect6 = reopen_sock_addr(&paths, "connect6", CgroupSockAddrAttachType::Connect6)?;
    let sendmsg4 = reopen_sock_addr(&paths, "sendmsg4", CgroupSockAddrAttachType::UDPSendMsg4)?;
    let sendmsg6 = reopen_sock_addr(&paths, "sendmsg6", CgroupSockAddrAttachType::UDPSendMsg6)?;
    let sock_create = reopen_sock(&paths, "sock_create", CgroupSockAttachType::SockCreate)?;
    let dns_snoop = reopen_cgroup_skb(&paths, "dns_snoop", CgroupSkbAttachType::Ingress)?;

    let policy_trie: LpmTrie<MapData, PolicyKeyData, PolicyValue> = reopen_map(&paths, "policy")?;
    let enforcement_map: BpfHashMap<MapData, u64, EnforcementState> = reopen_map(&paths, "enforcement")?;
    let tamper_map: BpfHashMap<MapData, u64, TamperCounter> = reopen_map(&paths, "tamper")?;
    let events_map: RingBuf<MapData> = reopen_map(&paths, "events")?;
    let dns_events_map: RingBuf<MapData> = reopen_map(&paths, "dns_events")?;

    let containers = discover_containers(&paths)?;

    Ok(Probe {
        paths,
        connect4,
        connect6,
        sendmsg4,
        sendmsg6,
        sock_create,
        dns_snoop,
        policy: PolicyStore::new(policy_trie),
        enforcement: EnforcementStore::new(enforcement_map),
        tamper: TamperStore::new(tamper_map),
        events_map: Some(events_map),
        dns_events_map: Some(dns_events_map),
        containers,
    })
}

fn reopen_sock_addr(paths: &PinPaths, name: &str, attach_type: CgroupSockAddrAttachType) -> Result<CgroupSockAddr> {
    CgroupSockAddr::from_pin(paths.prog_path(name), attach_type).with_context(|| format!("failed to reopen pinned program `{name}`"))
}

fn reopen_sock(paths: &PinPaths, name: &str, attach_type: CgroupSockAttachType) -> Result<CgroupSock> {
    CgroupSock::from_pin(paths.prog_path(name), attach_type).with_context(|| format!("failed to reopen pinned program `{name}`"))
}

fn reopen_cgroup_skb(paths: &PinPaths, name: &str, attach_type: CgroupSkbAttachType) -> Result<CgroupSkb> {
    CgroupSkb::from_pin(paths.prog_path(name), attach_type).with_context(|| format!("failed to reopen pinned program `{name}`"))
}

fn reopen_map<M>(paths: &PinPaths, pin_basename: &str) -> Result<M>
where
    M: TryFrom<Map, Error = aya::maps::MapError>,
{
    let map_data = MapData::from_pin(paths.map_path(pin_basename)).with_context(|| format!("failed to reopen pinned map `{pin_basename}`"))?;
    let map = Map::from_map_data(map_data).with_context(|| format!("failed to read metadata for pinned map `{pin_basename}`"))?;
    M::try_from(map).with_context(|| format!("pinned map `{pin_basename}` is not the expected map/key/value type"))
}

fn attach_and_pin_sock_addr(prog: &mut CgroupSockAddr, name: &str, cgroup_fd: &File, cgroup_id: u64, paths: &PinPaths) -> Result<PathBuf> {
    let link_id = prog.attach(cgroup_fd, CgroupAttachMode::Single).with_context(|| format!("failed to attach `{name}` to cgroup {cgroup_id:016x}"))?;
    let link = prog.take_link(link_id).with_context(|| format!("failed to take ownership of the `{name}` link"))?;
    let fd_link: FdLink = link.try_into().with_context(|| format!("`{name}` link is not fd-based (pre-5.7 kernel ProgAttachLink fallback is not pinnable)"))?;
    let pin_path = paths.container_link_path(cgroup_id, name);
    fd_link.pin(&pin_path).with_context(|| format!("failed to pin `{name}` link to {}", pin_path.display()))?;
    Ok(pin_path)
}

fn attach_and_pin_sock(prog: &mut CgroupSock, name: &str, cgroup_fd: &File, cgroup_id: u64, paths: &PinPaths) -> Result<PathBuf> {
    let link_id = prog.attach(cgroup_fd, CgroupAttachMode::Single).with_context(|| format!("failed to attach `{name}` to cgroup {cgroup_id:016x}"))?;
    let link = prog.take_link(link_id).with_context(|| format!("failed to take ownership of the `{name}` link"))?;
    let fd_link: FdLink = link.try_into().with_context(|| format!("`{name}` link is not fd-based (pre-5.7 kernel ProgAttachLink fallback is not pinnable)"))?;
    let pin_path = paths.container_link_path(cgroup_id, name);
    fd_link.pin(&pin_path).with_context(|| format!("failed to pin `{name}` link to {}", pin_path.display()))?;
    Ok(pin_path)
}

/// `CgroupSkb` variant of the two helpers above: same attach/take_link/pin
/// shape, but `attach` additionally takes an explicit `attach_type`
/// (`Ingress` in this workspace's only caller so far -- unlike
/// `CgroupSockAddr`/`CgroupSock`, one loaded `CgroupSkb` program can be
/// attached at either direction, chosen here rather than at load time; see
/// `bathyscaphe-ebpf::dns`'s module doc).
fn attach_and_pin_cgroup_skb(prog: &mut CgroupSkb, name: &str, attach_type: CgroupSkbAttachType, cgroup_fd: &File, cgroup_id: u64, paths: &PinPaths) -> Result<PathBuf> {
    let link_id = prog.attach(cgroup_fd, attach_type, CgroupAttachMode::Single).with_context(|| format!("failed to attach `{name}` to cgroup {cgroup_id:016x}"))?;
    let link = prog.take_link(link_id).with_context(|| format!("failed to take ownership of the `{name}` link"))?;
    let fd_link: FdLink = link.try_into().with_context(|| format!("`{name}` link is not fd-based (pre-5.7 kernel ProgAttachLink fallback is not pinnable)"))?;
    let pin_path = paths.container_link_path(cgroup_id, name);
    fd_link.pin(&pin_path).with_context(|| format!("failed to pin `{name}` link to {}", pin_path.display()))?;
    Ok(pin_path)
}

/// Walks `links/` to rediscover already-attached containers on a resumed
/// boot. A container directory missing one or more of the five expected
/// link files is left alone (whatever links it does have keep enforcing --
/// pinned links don't need this process to notice them to stay attached)
/// but is not added to the tracked set, since `detach_container` needs the
/// complete set of pin paths to safely tear one down; a loud stderr note
/// flags it for manual investigation rather than silently adopting a
/// possibly-inconsistent directory.
fn discover_containers(paths: &PinPaths) -> Result<HashMap<u64, ContainerLinks>> {
    let mut out = HashMap::new();
    let links_dir = paths.links_dir();
    if !links_dir.exists() {
        return Ok(out);
    }

    for entry in std::fs::read_dir(&links_dir).context("failed to read the links/ pin directory")? {
        let entry = entry.context("failed to read a links/ pin directory entry")?;
        if !entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
            continue;
        }
        let file_name = entry.file_name();
        let Some(name) = file_name.to_str() else {
            continue;
        };
        let Ok(cgroup_id) = u64::from_str_radix(name, 16) else {
            eprintln!("bathyscaphe: skipping unrecognized entry under links/: {name}");
            continue;
        };

        let mut pins = Vec::with_capacity(PROG_NAMES.len());
        let mut complete = true;
        for prog_name in PROG_NAMES {
            let path = entry.path().join(prog_name);
            if path.exists() {
                pins.push(path);
            } else {
                complete = false;
            }
        }

        if complete {
            out.insert(cgroup_id, ContainerLinks { pins });
        } else {
            eprintln!(
                "bathyscaphe: cgroup {cgroup_id:016x} has a partial link pin set under {}; its \
                 remaining pinned links keep enforcing as-is, but this process will not track it \
                 for detach_container -- investigate manually",
                entry.path().display()
            );
        }
    }

    Ok(out)
}

/// The live smoke test: an actual kernel load + attach + verifier pass +
/// pin/reopen/unpin round trip. Requires root, cgroup2, and a writable
/// bpffs -- none of which a normal `cargo test` run provides, so this is
/// `#[ignore]`d by default. See docs/TESTING.md for how it was run and what
/// it proved.
#[cfg(test)]
mod live_smoke {
    use std::path::PathBuf;

    use super::Probe;

    /// Crude but sufficient privilege check: everything this test needs
    /// (loading BPF programs, writing to bpffs, creating a cgroup) requires
    /// at minimum CAP_BPF + CAP_NET_ADMIN + CAP_SYS_ADMIN in practice, which
    /// in a container context means running as root. A non-root run skips
    /// rather than fails, since "not privileged" is an environment fact,
    /// not a code defect.
    fn running_as_root() -> bool {
        // SAFETY: geteuid() takes no arguments and cannot fail.
        unsafe { libc::geteuid() == 0 }
    }

    #[test]
    #[ignore = "requires --privileged, a real cgroup2 hierarchy, and a writable bpffs -- see docs/TESTING.md"]
    fn load_attach_pin_reopen_unpin_round_trip() {
        if !running_as_root() {
            eprintln!("live_smoke: skipping, not running as root");
            return;
        }

        let cgroup_path = PathBuf::from("/sys/fs/cgroup/bathyscaphe-smoke-test");
        std::fs::create_dir_all(&cgroup_path).expect("create the test cgroup v2 directory");
        let bpffs_root = PathBuf::from("/sys/fs/bpf/bathyscaphe-smoke-test");
        // Clean slate in case a previous aborted run left pins behind.
        let _ = Probe::unpin_all_at(&bpffs_root);

        let mut probe = Probe::load_or_reopen(crate::EBPF_OBJECT, bpffs_root.clone()).expect("fresh load_or_reopen should load, pin, and reopen cleanly -- a verifier rejection surfaces here");

        let cgroup_id = probe.attach_container(&cgroup_path).expect("attach_container should succeed: each program attaches under the verifier");
        assert!(probe.attached_containers().any(|id| id == cgroup_id));

        // Simulate a restart: drop this handle (closing all its fds) and
        // reopen from the pins alone, with no fresh `aya::Ebpf::load`.
        drop(probe);
        let mut probe2 = Probe::load_or_reopen(crate::EBPF_OBJECT, bpffs_root.clone()).expect("resumed load_or_reopen should reopen from pins without reloading");
        assert!(probe2.attached_containers().any(|id| id == cgroup_id), "a resumed boot must rediscover the container that was attached before the restart");

        probe2.detach_container(cgroup_id).expect("detach_container should succeed");
        probe2.unpin_all().expect("unpin_all should remove the whole pin subtree");
        assert!(!bpffs_root.exists(), "unpin_all should leave nothing behind");

        let _ = std::fs::remove_dir(&cgroup_path);
    }
}
