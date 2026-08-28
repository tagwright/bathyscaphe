// SPDX-License-Identifier: GPL-3.0-or-later
//! `cgroup_id -> container_id` resolution: the deterministic half of
//! attribution. `bathy_attribution.md` section 1 is the authority; this
//! module implements it directly, with no BPF map round trip needed for
//! discovery (`cgroup_id` IS the cgroup v2 directory's inode number, so a
//! plain `stat()` on a path found by walking `/sys/fs/cgroup` gives the
//! same value the kernel hook sees via `bpf_get_current_cgroup_id()`).
//!
//! Two pieces:
//! - [`classify_trailing_segment`]: pure path -> `Option<ContainerRef>`
//!   parsing, no filesystem access, unit-testable against every documented
//!   cgroup path shape.
//! - [`CgroupMap`] + [`CgroupWatcher`]: the stateful discovery half --
//!   walk-and-stat for bootstrap, inotify (add on mkdir, remove on rmdir)
//!   to keep the map fresh afterward, plus a synchronous targeted rescan
//!   fallback for the short-lived-container race (`bathy_attribution.md`
//!   section 4, edge case 1).

use std::collections::HashMap;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use bathyscaphe_proto::Runtime;
use inotify::{Inotify, WatchDescriptor, WatchMask};
use regex::Regex;

/// Default cgroup v2 unified mountpoint. A later CLI chunk may expose this
/// as a flag; nothing below hardcodes it beyond this one default.
pub const DEFAULT_CGROUP_ROOT: &str = "/sys/fs/cgroup";

/// What a container-shaped cgroup directory's trailing path segment told
/// us, with no runtime-API enrichment yet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerRef {
    pub container_id: String,
    pub runtime: Runtime,
}

/// One regex, one alternation, covering every documented shape
/// (`bathy_attribution.md` 1c): `docker-<64hex>.scope`, `libpod-<64hex>.scope`
/// (any parent, rootful or rootless, systemd or not), or a bare `<64hex>`
/// directory name (the cgroupfs-driver case). Applied to the trailing path
/// segment only, never to full-path depth, since rootless Podman's extra
/// `user.slice/user-<uid>.slice/user@<uid>.service/user.slice` prefix
/// segments make positional depth unreliable.
fn container_pattern() -> &'static Regex {
    static PATTERN: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    PATTERN.get_or_init(|| Regex::new(r"^(?:(?P<docker>docker)-|(?P<libpod>libpod)-)?(?P<hex>[0-9a-f]{64})(?:\.scope)?$").expect("container_pattern is a fixed, valid regex"))
}

/// Parses a cgroup v2 directory's trailing path segment into a
/// [`ContainerRef`], or `None` if it names something other than a
/// container's own scope (a non-container cgroup, an intermediate slice
/// directory, or a `libpod-conmon-*` companion scope).
///
/// `libpod-conmon-<64hex>.scope` is excluded explicitly even though the
/// fixed regex above would already fail to match it (the literal string
/// between `libpod-` and the trailing hex run is `conmon-<64hex>`, not
/// 64 bare hex digits, so it can never satisfy `hex`) -- the explicit guard
/// stays as documentation of intent and a defense against the pattern
/// loosening later, per the build brief's explicit call-out.
pub fn classify_trailing_segment(path: &Path) -> Option<ContainerRef> {
    let name = path.file_name()?.to_str()?;
    if name.starts_with("libpod-conmon-") {
        return None;
    }

    let caps = container_pattern().captures(name)?;
    let hex = caps.name("hex")?.as_str().to_string();

    let runtime = if caps.name("docker").is_some() {
        Runtime::Docker
    } else if caps.name("libpod").is_some() {
        Runtime::Podman
    } else {
        // Bare 64-hex directory name: `bathy_attribution.md` 1c documents
        // this only for Docker's cgroupfs driver (`docker/<64hex>`) --
        // Podman's cgroupfs variant keeps the `libpod-`/`.scope` decoration
        // per 1b even without systemd. Use the immediate parent directory
        // name as a defensive tie-breaker in case a bare-hex Podman layout
        // exists after all, defaulting to Docker (the only concretely
        // documented case) when the parent gives no signal. Flagged for
        // Nate: this is an inference filling a real ambiguity in the
        // attribution brief, not a confirmed shape.
        match path.parent().and_then(Path::file_name).and_then(|s| s.to_str()) {
            Some("libpod") => Runtime::Podman,
            _ => Runtime::Docker,
        }
    };

    Some(ContainerRef { container_id: hex, runtime })
}

/// The live `cgroup_id -> ContainerRef` map, guarded by one mutex so the
/// inotify watcher thread and any number of resolver reads never race.
pub struct CgroupMap {
    root: PathBuf,
    inner: Mutex<Inner>,
}

#[derive(Default)]
struct Inner {
    by_id: HashMap<u64, ContainerRef>,
    /// Reverse index for O(1) removal on `rmdir`: inotify's `DELETE` event
    /// carries the removed name, not the inode that's already gone by the
    /// time userspace sees the event.
    by_path: HashMap<PathBuf, u64>,
    /// `container_id -> (cgroup_id, cgroup path)`, for the daemon's
    /// directive path (build chunk #7): airlock's `policy`/`release`
    /// directives carry a `container_id`, but the POLICY/ENFORCEMENT/TAMPER
    /// maps are all keyed by `cgroup_id`, and attaching a not-yet-attached
    /// container needs its cgroup directory PATH, not just the id. Kept as
    /// a third index alongside `by_id`/`by_path` rather than derived by
    /// scanning `by_id` on every directive, since a directive is exactly
    /// the hot path this index exists for.
    by_container_id: HashMap<String, (u64, PathBuf)>,
}

impl CgroupMap {
    pub fn new(root: impl Into<PathBuf>) -> Arc<Self> {
        Arc::new(Self { root: root.into(), inner: Mutex::new(Inner::default()) })
    }

    /// A fast, lock-only lookup against whatever the walker/watcher has
    /// already discovered.
    pub fn get(&self, cgroup_id: u64) -> Option<ContainerRef> {
        self.inner.lock().unwrap_or_else(|poison| poison.into_inner()).by_id.get(&cgroup_id).cloned()
    }

    /// The reverse direction of [`Self::get`]: `container_id -> cgroup_id`.
    /// `None` when this process has not (yet) discovered that container's
    /// cgroup directory -- the daemon's directive path treats this as "not
    /// attachable yet", not a hard error, since a `policy` directive can
    /// race a container's cgroup creation.
    pub fn cgroup_id_for_container(&self, container_id: &str) -> Option<u64> {
        self.inner.lock().unwrap_or_else(|poison| poison.into_inner()).by_container_id.get(container_id).map(|(id, _)| *id)
    }

    /// `container_id -> cgroup path`, for [`crate::probe::Probe::attach_container`],
    /// which needs the directory, not just its inode.
    pub fn cgroup_path_for_container(&self, container_id: &str) -> Option<PathBuf> {
        self.inner.lock().unwrap_or_else(|poison| poison.into_inner()).by_container_id.get(container_id).map(|(_, path)| path.clone())
    }

    /// A snapshot of every container-shaped cgroup discovered so far:
    /// `(container_id, cgroup_id, cgroup_path)`. For the CLI build chunk's
    /// standalone `observe` mode, which needs to enumerate and attach to
    /// every currently-running container up front, then diff against this
    /// same snapshot on a poll interval to pick up ones that started since
    /// (`bathy_build_spec.md`'s CLI brief: "attach to currently-running
    /// containers ... and watch for new ones"). Nothing else in this crate
    /// needs a full listing -- the daemon's directive path always looks up
    /// one container id at a time -- so this stays a small, explicit
    /// addition rather than a general-purpose iterator API.
    pub fn snapshot(&self) -> Vec<(String, u64, PathBuf)> {
        let inner = self.inner.lock().unwrap_or_else(|poison| poison.into_inner());
        inner.by_container_id.iter().map(|(container_id, (cgroup_id, path))| (container_id.clone(), *cgroup_id, path.clone())).collect()
    }

    /// The short-lived-container race fallback (`bathy_attribution.md`
    /// section 4, edge case 1): a targeted, synchronous full walk of
    /// `/sys/fs/cgroup` looking for the one directory whose inode matches
    /// `cgroup_id`, used only on a cache miss. A full walk is "low
    /// single-digit milliseconds" per that doc even at a few thousand
    /// cgroups, and this path is only ever hit for a cgroup this process
    /// has not yet learned about any other way.
    pub fn get_or_rescan(&self, cgroup_id: u64) -> Option<ContainerRef> {
        if let Some(found) = self.get(cgroup_id) {
            return Some(found);
        }
        let path = find_by_inode(&self.root, cgroup_id)?;
        self.observe_path(&path, cgroup_id)
    }

    /// Bootstrap: walk the whole tree once, classifying every directory and
    /// recording every container match. Returns every directory visited
    /// (not just container matches) so a caller wiring up inotify can seed
    /// its initial watch set from the same single walk.
    pub fn bootstrap(&self) -> Result<Vec<PathBuf>> {
        let mut all_dirs = Vec::new();
        walk_dirs(&self.root, &mut all_dirs).with_context(|| format!("failed to walk {}", self.root.display()))?;
        for dir in &all_dirs {
            self.observe_dir(dir);
        }
        Ok(all_dirs)
    }

    /// Records a newly-seen directory if (and only if) it stats as a
    /// container-shaped cgroup. Safe to call for every directory the
    /// watcher sees created, container-shaped or not -- non-matches are a
    /// no-op.
    fn observe_dir(&self, path: &Path) -> Option<u64> {
        let meta = std::fs::symlink_metadata(path).ok()?;
        if !meta.is_dir() {
            return None;
        }
        self.observe_path(path, meta.ino()).map(|_| meta.ino())
    }

    pub(crate) fn observe_path(&self, path: &Path, cgroup_id: u64) -> Option<ContainerRef> {
        let container_ref = classify_trailing_segment(path)?;
        let mut inner = self.inner.lock().unwrap_or_else(|poison| poison.into_inner());
        inner.by_path.insert(path.to_path_buf(), cgroup_id);
        inner.by_container_id.insert(container_ref.container_id.clone(), (cgroup_id, path.to_path_buf()));
        inner.by_id.insert(cgroup_id, container_ref.clone());
        Some(container_ref)
    }

    /// Forgets `path` (its `cgroup_id`, if any, along with it). Called on
    /// `rmdir`; a no-op if `path` was never a container match (most
    /// removals aren't).
    fn forget_path(&self, path: &Path) {
        let mut inner = self.inner.lock().unwrap_or_else(|poison| poison.into_inner());
        if let Some(cgroup_id) = inner.by_path.remove(path) {
            if let Some(container_ref) = inner.by_id.remove(&cgroup_id) {
                inner.by_container_id.remove(&container_ref.container_id);
            }
        }
    }
}

/// Recursively collects every directory under `dir` (inclusive of `dir`
/// itself is NOT included; only descendants), for the initial inotify watch
/// seed and for [`CgroupMap::bootstrap`]'s classification pass. A directory
/// that disappears mid-walk (a container exiting concurrently) is logged
/// and skipped rather than failing the whole walk.
fn walk_dirs(dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error).with_context(|| format!("failed to read directory {}", dir.display())),
    };
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                eprintln!("bathyscaphe: skipping a directory entry under {} ({error})", dir.display());
                continue;
            }
        };
        let path = entry.path();
        let is_dir = entry.file_type().map(|t| t.is_dir()).unwrap_or(false);
        if !is_dir {
            continue;
        }
        out.push(path.clone());
        walk_dirs(&path, out)?;
    }
    Ok(())
}

/// Walks `root` looking for the one directory whose inode is `target_ino`.
/// Used only by [`CgroupMap::get_or_rescan`]'s race fallback.
fn find_by_inode(root: &Path, target_ino: u64) -> Option<PathBuf> {
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else { continue };
        for entry in entries.flatten() {
            let Ok(file_type) = entry.file_type() else { continue };
            if !file_type.is_dir() {
                continue;
            }
            let path = entry.path();
            if let Ok(meta) = std::fs::symlink_metadata(&path) {
                if meta.ino() == target_ino {
                    return Some(path);
                }
            }
            stack.push(path);
        }
    }
    None
}

/// Events big enough to hold several `inotify` records with a path each; a
/// single 4 KiB read comfortably drains a burst of container churn without
/// looping.
const INOTIFY_BUFFER_LEN: usize = 4096;

fn watch_mask() -> WatchMask {
    WatchMask::CREATE | WatchMask::DELETE | WatchMask::MOVED_FROM | WatchMask::MOVED_TO
}

/// Owns the inotify fd and the dedicated OS thread draining it. Mirrors
/// `probe::events::EventConsumer`'s shape (a `shutdown` flag plus a joined
/// thread) deliberately -- this crate has one established pattern for "a
/// background OS-thread reader with clean shutdown," and this is the second
/// user of it.
pub struct CgroupWatcher {
    shutdown: Arc<std::sync::atomic::AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl CgroupWatcher {
    /// Bootstraps `map` from a full walk, installs a watch on every
    /// directory found (plus `root` itself), and spawns the thread that
    /// keeps both the watch set and `map` current as containers come and
    /// go. Directories created after a watch is installed on their parent
    /// are picked up as `CREATE` events arrive; each new directory gets its
    /// own watch (recursively, so a directory arriving with pre-existing
    /// children -- e.g. via `MOVED_TO` -- is walked and watched in full).
    pub fn spawn(map: Arc<CgroupMap>) -> Result<Self> {
        let root = map.root.clone();
        let mut inotify = Inotify::init().context("Inotify::init failed (is this host running Linux with inotify support?)")?;

        let mut path_to_wd: HashMap<PathBuf, WatchDescriptor> = HashMap::new();
        let mut wd_to_path: HashMap<WatchDescriptor, PathBuf> = HashMap::new();

        let existing_dirs = map.bootstrap().context("initial cgroup tree walk failed")?;
        add_watch(&mut inotify, &root, &mut path_to_wd, &mut wd_to_path);
        for dir in &existing_dirs {
            add_watch(&mut inotify, dir, &mut path_to_wd, &mut wd_to_path);
        }

        let shutdown = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let shutdown_thread = Arc::clone(&shutdown);
        let map_thread = Arc::clone(&map);

        let handle = std::thread::spawn(move || {
            watch_loop(inotify, map_thread, path_to_wd, wd_to_path, shutdown_thread);
        });

        Ok(Self { shutdown, handle: Some(handle) })
    }

    /// Signals the watcher thread to stop and joins it. Bounded by
    /// [`POLL_TIMEOUT_MS`] beyond whatever the thread's current iteration
    /// is doing, the same shape as `probe::events::EventConsumer::stop`.
    pub fn stop(mut self) {
        self.shutdown.store(true, std::sync::atomic::Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

fn add_watch(inotify: &mut Inotify, path: &Path, path_to_wd: &mut HashMap<PathBuf, WatchDescriptor>, wd_to_path: &mut HashMap<WatchDescriptor, PathBuf>) {
    match inotify.watches().add(path, watch_mask()) {
        Ok(wd) => {
            path_to_wd.insert(path.to_path_buf(), wd.clone());
            wd_to_path.insert(wd, path.to_path_buf());
        }
        Err(error) => {
            // A directory can legitimately vanish between being listed and
            // being watched (a container exiting concurrently); not fatal.
            eprintln!("bathyscaphe: failed to watch {} ({error}); its contents will only be seen via a future rescan", path.display());
        }
    }
}

/// How long [`watch_loop`] blocks in `poll(2)` before re-checking its
/// shutdown flag. Same value and same rationale as
/// `probe::events::POLL_TIMEOUT_MS`: bounds shutdown latency without
/// affecting event latency, since `poll` returns immediately once the
/// inotify fd is readable. Using a bounded poll here (rather than
/// `Inotify::read_events_blocking`, which has no timeout at all) is what
/// makes [`CgroupWatcher::stop`] able to return promptly on a host with no
/// cgroup churn during shutdown -- an all-too-real case, not just a
/// theoretical one: an idle test host between container events is exactly
/// where an unconditional blocking read would hang forever.
const POLL_TIMEOUT_MS: i32 = 250;

fn watch_loop(
    mut inotify: Inotify,
    map: Arc<CgroupMap>,
    mut path_to_wd: HashMap<PathBuf, WatchDescriptor>,
    mut wd_to_path: HashMap<WatchDescriptor, PathBuf>,
    shutdown: Arc<std::sync::atomic::AtomicBool>,
) {
    use std::os::fd::AsRawFd;

    let mut buffer = [0u8; INOTIFY_BUFFER_LEN];
    loop {
        if shutdown.load(std::sync::atomic::Ordering::Relaxed) {
            return;
        }

        let mut pfd = libc::pollfd { fd: inotify.as_raw_fd(), events: libc::POLLIN, revents: 0 };
        // SAFETY: `pfd` is a single, valid `pollfd` for the duration of the
        // call. A negative return (error) or a spurious wakeup both just
        // loop back around to the shutdown check above, which is always
        // safe.
        let poll_rc = unsafe { libc::poll(&mut pfd, 1, POLL_TIMEOUT_MS) };
        if poll_rc <= 0 {
            continue;
        }

        let events = match inotify.read_events(&mut buffer) {
            Ok(events) => events,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(error) => {
                eprintln!("bathyscaphe: cgroup inotify read failed ({error}); cgroup discovery is no longer live, only rescan-on-miss remains");
                return;
            }
        };

        for event in events {
            if event.mask.contains(inotify::EventMask::IGNORED) {
                // The kernel auto-removed this watch (its directory is
                // gone); drop our bookkeeping for it.
                if let Some(path) = wd_to_path.remove(&event.wd) {
                    path_to_wd.remove(&path);
                }
                continue;
            }
            if !event.mask.contains(inotify::EventMask::ISDIR) {
                continue;
            }
            let Some(name) = event.name else { continue };
            let Some(parent) = wd_to_path.get(&event.wd).cloned() else { continue };
            let path = parent.join(name);

            let created = event.mask.contains(inotify::EventMask::CREATE) || event.mask.contains(inotify::EventMask::MOVED_TO);
            let removed = event.mask.contains(inotify::EventMask::DELETE) || event.mask.contains(inotify::EventMask::MOVED_FROM);

            if created {
                map.observe_dir(&path);
                add_watch(&mut inotify, &path, &mut path_to_wd, &mut wd_to_path);
                // A directory can arrive with pre-existing children (e.g.
                // `MOVED_TO` relocating a populated subtree); walk it so
                // nothing nested is missed.
                if let Ok(mut nested) = {
                    let mut v = Vec::new();
                    walk_dirs(&path, &mut v).map(|()| v)
                } {
                    for child in nested.drain(..) {
                        map.observe_dir(&child);
                        add_watch(&mut inotify, &child, &mut path_to_wd, &mut wd_to_path);
                    }
                }
            } else if removed {
                map.forget_path(&path);
                if let Some(wd) = path_to_wd.remove(&path) {
                    wd_to_path.remove(&wd);
                    let _ = inotify.watches().remove(wd);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(byte: u8) -> String {
        // A deterministic, obviously-fake 64-hex id built by repeating one
        // byte -- readable in test failure output, unambiguous length.
        format!("{byte:02x}").repeat(32)
    }

    #[test]
    fn docker_systemd_scope() {
        let id = hex(0xab);
        let path = PathBuf::from(format!("/sys/fs/cgroup/system.slice/docker-{id}.scope"));
        let got = classify_trailing_segment(&path).expect("docker systemd scope should classify");
        assert_eq!(got, ContainerRef { container_id: id, runtime: Runtime::Docker });
    }

    #[test]
    fn docker_cgroupfs_bare_hex_under_docker_parent() {
        let id = hex(0x11);
        let path = PathBuf::from(format!("/sys/fs/cgroup/docker/{id}"));
        let got = classify_trailing_segment(&path).expect("bare-hex docker cgroupfs dir should classify");
        assert_eq!(got, ContainerRef { container_id: id, runtime: Runtime::Docker });
    }

    #[test]
    fn podman_rootful_systemd_scope() {
        let id = hex(0x22);
        let path = PathBuf::from(format!("/sys/fs/cgroup/machine.slice/libpod-{id}.scope"));
        let got = classify_trailing_segment(&path).expect("podman rootful systemd scope should classify");
        assert_eq!(got, ContainerRef { container_id: id, runtime: Runtime::Podman });
    }

    #[test]
    fn podman_rootful_cgroupfs_scope_under_arbitrary_parent() {
        let id = hex(0x33);
        let path = PathBuf::from(format!("/sys/fs/cgroup/libpod_parent/libpod-{id}.scope"));
        let got = classify_trailing_segment(&path).expect("podman rootful cgroupfs scope should classify regardless of parent name");
        assert_eq!(got, ContainerRef { container_id: id, runtime: Runtime::Podman });
    }

    #[test]
    fn podman_rootless_deep_user_service_nesting() {
        let id = hex(0x44);
        let path = PathBuf::from(format!("/sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service/user.slice/libpod-{id}.scope"));
        let got = classify_trailing_segment(&path).expect("rootless podman's deep nesting must not defeat suffix matching");
        assert_eq!(got, ContainerRef { container_id: id, runtime: Runtime::Podman });
    }

    #[test]
    fn podman_conmon_scope_is_excluded() {
        let id = hex(0x55);
        let path = PathBuf::from(format!("/sys/fs/cgroup/machine.slice/libpod-conmon-{id}.scope"));
        assert_eq!(classify_trailing_segment(&path), None, "conmon's own scope must never be attributed to the container");
    }

    #[test]
    fn non_container_cgroup_is_none() {
        let path = PathBuf::from("/sys/fs/cgroup/system.slice/ssh.service");
        assert_eq!(classify_trailing_segment(&path), None);
    }

    #[test]
    fn init_scope_is_none() {
        let path = PathBuf::from("/sys/fs/cgroup/init.scope");
        assert_eq!(classify_trailing_segment(&path), None);
    }

    #[test]
    fn wrong_length_hex_is_none() {
        let short = PathBuf::from(format!("/sys/fs/cgroup/docker-{}.scope", "a".repeat(63)));
        let long = PathBuf::from(format!("/sys/fs/cgroup/docker-{}.scope", "a".repeat(65)));
        assert_eq!(classify_trailing_segment(&short), None);
        assert_eq!(classify_trailing_segment(&long), None);
    }

    #[test]
    fn uppercase_hex_is_none() {
        // Container ids on the wire and in cgroup names are lowercase; an
        // uppercase run is not a shape any real runtime produces.
        let path = PathBuf::from(format!("/sys/fs/cgroup/docker-{}.scope", "AB".repeat(32)));
        assert_eq!(classify_trailing_segment(&path), None);
    }

    #[test]
    fn bare_hex_under_unrecognized_parent_defaults_to_docker() {
        // Documented inference (see classify_trailing_segment's doc): the
        // attribution brief leaves the runtime for a bare-hex match under a
        // non-"docker"/"libpod" parent ambiguous. This pins the chosen
        // default so a future change to it is a visible, deliberate diff.
        let id = hex(0x66);
        let path = PathBuf::from(format!("/sys/fs/cgroup/some-other-parent/{id}"));
        let got = classify_trailing_segment(&path).expect("a bare 64-hex name should still classify even under an unrecognized parent");
        assert_eq!(got, ContainerRef { container_id: id, runtime: Runtime::Docker });
    }

    #[test]
    fn cgroup_map_records_and_forgets_by_path() {
        let map = CgroupMap::new("/sys/fs/cgroup");
        let id = hex(0x77);
        let path = Path::new("/sys/fs/cgroup/system.slice").join(format!("docker-{id}.scope"));
        map.observe_path(&path, 12345).expect("a valid docker scope path should classify");
        assert_eq!(map.get(12345), Some(ContainerRef { container_id: id, runtime: Runtime::Docker }));

        map.forget_path(&path);
        assert_eq!(map.get(12345), None);
    }

    #[test]
    fn cgroup_map_ignores_non_container_directories() {
        let map = CgroupMap::new("/sys/fs/cgroup");
        assert_eq!(map.observe_path(Path::new("/sys/fs/cgroup/system.slice/ssh.service"), 999), None);
        assert_eq!(map.get(999), None);
    }

    #[test]
    fn reverse_lookup_resolves_container_id_to_cgroup_id_and_path() {
        let map = CgroupMap::new("/sys/fs/cgroup");
        let id = hex(0x88);
        let path = Path::new("/sys/fs/cgroup/system.slice").join(format!("docker-{id}.scope"));
        map.observe_path(&path, 424242).expect("a valid docker scope path should classify");

        assert_eq!(map.cgroup_id_for_container(&id), Some(424242));
        assert_eq!(map.cgroup_path_for_container(&id), Some(path.clone()));

        map.forget_path(&path);
        assert_eq!(map.cgroup_id_for_container(&id), None);
        assert_eq!(map.cgroup_path_for_container(&id), None);
    }

    #[test]
    fn reverse_lookup_is_none_for_an_unknown_container_id() {
        let map = CgroupMap::new("/sys/fs/cgroup");
        assert_eq!(map.cgroup_id_for_container(&hex(0x99)), None);
        assert_eq!(map.cgroup_path_for_container(&hex(0x99)), None);
    }

    #[test]
    fn snapshot_lists_every_discovered_container_once() {
        let map = CgroupMap::new("/sys/fs/cgroup");
        let a = hex(0xaa);
        let b = hex(0xbb);
        let path_a = Path::new("/sys/fs/cgroup/system.slice").join(format!("docker-{a}.scope"));
        let path_b = Path::new("/sys/fs/cgroup/system.slice").join(format!("docker-{b}.scope"));
        map.observe_path(&path_a, 1).expect("a valid docker scope path should classify");
        map.observe_path(&path_b, 2).expect("a valid docker scope path should classify");

        let mut snapshot = map.snapshot();
        snapshot.sort_by(|x, y| x.1.cmp(&y.1));
        assert_eq!(snapshot, vec![(a, 1, path_a), (b, 2, path_b)]);
    }

    #[test]
    fn snapshot_is_empty_for_a_fresh_map() {
        let map = CgroupMap::new("/sys/fs/cgroup");
        assert!(map.snapshot().is_empty());
    }
}
