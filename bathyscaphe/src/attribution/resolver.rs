// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 techgaud
//! The combined `cgroup_id -> Attribution` resolver, and
//! [`AttributionService`], the one-call bundle a later chunk's daemon wires
//! up: start the cgroup watcher and the enrichment watcher together, get
//! back a resolver to hand to [`crate::pipeline`].

use std::path::PathBuf;
use std::sync::Arc;

use bathyscaphe_proto::Runtime;

use super::cgroup::{CgroupMap, CgroupWatcher, DEFAULT_CGROUP_ROOT};
use super::enrich::{EnrichmentCache, EnrichmentWatcher};

/// Full attribution for one event: always carries a real `container_id`
/// and `runtime` (deterministic, filesystem-derived), `name`/`image` are
/// best-effort and `None` on a lost enrichment race -- never a reason to
/// withhold the rest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attribution {
    pub container_id: String,
    pub name: Option<String>,
    pub image: Option<String>,
    pub runtime: Runtime,
}

/// The seam [`crate::pipeline`] depends on, so its mapping logic can be
/// unit-tested against a stub rather than a real cgroup tree and a real
/// Docker socket.
pub trait Attributor: Send {
    fn resolve(&self, cgroup_id: u64) -> Option<Attribution>;
}

impl<T: Attributor + ?Sized + Sync> Attributor for Arc<T> {
    fn resolve(&self, cgroup_id: u64) -> Option<Attribution> {
        (**self).resolve(cgroup_id)
    }
}

/// The reverse-direction seam the daemon (build chunk #7) depends on: a
/// `policy`/`release` directive off the wire carries a `container_id`, but
/// every kernel map is keyed by `cgroup_id`, and attaching a not-yet-seen
/// container needs its cgroup PATH. A separate trait from [`Attributor`]
/// (rather than folding this into it) because the two are used from
/// different call sites for different reasons -- events flow cgroup_id ->
/// attribution on the ring-buf consumer thread, directives flow
/// container_id -> cgroup_id/path on the stdin thread -- and keeping them
/// separate lets daemon code depend on only the direction it needs, mockable
/// independently in tests.
pub trait ContainerLookup: Send + Sync {
    /// `None` when this process has not (yet) discovered `container_id`'s
    /// cgroup directory -- a `policy` directive can race a container's
    /// cgroup creation; the daemon treats this as "not attachable yet", not
    /// a hard error.
    fn cgroup_id_for_container(&self, container_id: &str) -> Option<u64>;
    /// The cgroup directory backing `container_id`, for
    /// [`crate::probe::Probe::attach_container`]. `None` under the same
    /// condition as [`Self::cgroup_id_for_container`].
    fn cgroup_path_for_container(&self, container_id: &str) -> Option<PathBuf>;
}

impl ContainerLookup for Resolver {
    fn cgroup_id_for_container(&self, container_id: &str) -> Option<u64> {
        self.cgroups.cgroup_id_for_container(container_id)
    }

    fn cgroup_path_for_container(&self, container_id: &str) -> Option<PathBuf> {
        self.cgroups.cgroup_path_for_container(container_id)
    }
}

impl<T: ContainerLookup + ?Sized> ContainerLookup for Arc<T> {
    fn cgroup_id_for_container(&self, container_id: &str) -> Option<u64> {
        (**self).cgroup_id_for_container(container_id)
    }

    fn cgroup_path_for_container(&self, container_id: &str) -> Option<PathBuf> {
        (**self).cgroup_path_for_container(container_id)
    }
}

/// Joins [`CgroupMap`] (deterministic `cgroup_id -> container_id`/`runtime`)
/// with [`EnrichmentCache`] (best-effort `container_id -> name`/`image`).
pub struct Resolver {
    cgroups: Arc<CgroupMap>,
    enrichment: Arc<EnrichmentCache>,
}

impl Resolver {
    pub fn new(cgroups: Arc<CgroupMap>, enrichment: Arc<EnrichmentCache>) -> Self {
        Self { cgroups, enrichment }
    }

    /// A snapshot of every container-shaped cgroup discovered so far:
    /// `(container_id, cgroup_id, cgroup_path)`. See
    /// [`super::cgroup::CgroupMap::snapshot`] -- this is the one caller
    /// outside `attribution` that needs it, the CLI build chunk's
    /// standalone `observe` mode.
    pub fn known_containers(&self) -> Vec<(String, u64, PathBuf)> {
        self.cgroups.snapshot()
    }
}

impl Attributor for Resolver {
    /// `None` only when `cgroup_id` cannot be traced to any container
    /// cgroup at all, even after the synchronous rescan fallback -- a
    /// cgroup this process was never told to attach to in the first place,
    /// which should not happen for an event that came off bathyscaphe's own
    /// `EVENTS` ring buffer (every hook is attached per-container), but is
    /// handled without panicking regardless. Everything short of that
    /// returns `Some`, with `name`/`image` null when the enrichment race is
    /// lost -- see the module doc on [`Attribution`].
    fn resolve(&self, cgroup_id: u64) -> Option<Attribution> {
        let container_ref = self.cgroups.get_or_rescan(cgroup_id)?;
        let meta = self.enrichment.get(&container_ref.container_id).unwrap_or_default();
        Some(Attribution { container_id: container_ref.container_id, name: meta.name, image: meta.image, runtime: container_ref.runtime })
    }
}

/// Bundles the cgroup walker/watcher and the enrichment watcher behind one
/// `start`/`stop` pair, so a daemon chunk needs exactly one call to stand up
/// attribution and one to tear it down.
pub struct AttributionService {
    pub resolver: Arc<Resolver>,
    cgroup_watcher: CgroupWatcher,
    enrichment_watcher: EnrichmentWatcher,
}

impl AttributionService {
    /// Starts both watchers against [`DEFAULT_CGROUP_ROOT`]. The cgroup
    /// side's initial bootstrap walk runs synchronously before this
    /// returns (so [`Self::resolver`] is immediately usable for any
    /// already-existing container); the enrichment side's bootstrap runs on
    /// its own background thread and may still be warming up when this
    /// returns -- exactly the best-effort race [`Attribution`] documents.
    pub fn start() -> anyhow::Result<Self> {
        Self::start_at(DEFAULT_CGROUP_ROOT)
    }

    pub fn start_at(cgroup_root: impl Into<PathBuf>) -> anyhow::Result<Self> {
        let cgroups = CgroupMap::new(cgroup_root);
        let cgroup_watcher = CgroupWatcher::spawn(Arc::clone(&cgroups))?;

        let enrichment = EnrichmentCache::new();
        let enrichment_watcher = EnrichmentWatcher::spawn(Arc::clone(&enrichment));

        let resolver = Arc::new(Resolver::new(cgroups, enrichment));

        Ok(Self { resolver, cgroup_watcher, enrichment_watcher })
    }

    pub fn stop(self) {
        self.cgroup_watcher.stop();
        self.enrichment_watcher.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolver_returns_none_for_a_cgroup_id_absent_from_a_nonexistent_root() {
        // A resolver over a root that doesn't exist on this machine can
        // never find anything via bootstrap or rescan; this proves the
        // miss path returns `None` cleanly rather than panicking, without
        // depending on the test host's real cgroup tree contents.
        let cgroups = CgroupMap::new("/no/such/cgroup/root/bathyscaphe-test-fixture");
        let enrichment = EnrichmentCache::new();
        let resolver = Resolver::new(cgroups, enrichment);
        assert_eq!(resolver.resolve(0xdead_beef), None);
    }

    #[test]
    fn container_lookup_reverses_a_discovered_container() {
        let cgroups = CgroupMap::new("/sys/fs/cgroup");
        let id = "c".repeat(64);
        let path = std::path::Path::new("/sys/fs/cgroup/system.slice").join(format!("docker-{id}.scope"));
        cgroups.observe_path(&path, 0xabc).expect("a valid docker scope path should classify");

        let enrichment = EnrichmentCache::new();
        let resolver = Resolver::new(cgroups, enrichment);

        assert_eq!(ContainerLookup::cgroup_id_for_container(&resolver, &id), Some(0xabc));
        assert_eq!(ContainerLookup::cgroup_path_for_container(&resolver, &id), Some(path));
    }

    #[test]
    fn container_lookup_is_none_for_an_unknown_container_id() {
        let cgroups = CgroupMap::new("/sys/fs/cgroup");
        let enrichment = EnrichmentCache::new();
        let resolver = Resolver::new(cgroups, enrichment);
        assert_eq!(ContainerLookup::cgroup_id_for_container(&resolver, "never-seen"), None);
    }
}

/// The live enrichment smoke test the build brief asks this chunk to
/// attempt: a real throwaway container, resolved end to end through the
/// real cgroup walker/watcher and the real bollard connection, against
/// whatever Docker or Podman socket is reachable from wherever `cargo test`
/// runs. `#[ignore]`d for the same reason as `probe::live_smoke` --
/// requires a real cgroup v2 host and a reachable engine socket, neither of
/// which a plain `cargo test` run provides. See docs/TESTING.md for what
/// this proved when it was actually run.
#[cfg(test)]
mod live_smoke {
    use std::io::Read;
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::net::UnixStream;
    use std::path::{Path, PathBuf};
    use std::time::{Duration, Instant};

    use super::*;
    use crate::attribution::cgroup::classify_trailing_segment;

    const TEST_CONTAINER_NAME: &str = "bathyscaphe-itest-attrib";
    const DOCKER_SOCKET: &str = "/var/run/docker.sock";
    const API_VERSION: &str = "v1.44";

    fn docker_socket_reachable() -> bool {
        UnixStream::connect(DOCKER_SOCKET).is_ok()
    }

    /// A deliberately tiny HTTP/1.0-over-unix-socket client: this test's
    /// job is to prove the ATTRIBUTION resolver against a real container,
    /// not to exercise bollard's own container-lifecycle API surface (which
    /// the [`super::super::enrich`] module already covers for the read
    /// side). One raw request/response round trip keeps the setup/teardown
    /// half of this test legible without pulling in an HTTP client crate
    /// just for `POST`/`DELETE`.
    fn docker_api(method: &str, path: &str, body: &str) -> Result<(u16, String), std::io::Error> {
        let mut stream = UnixStream::connect(DOCKER_SOCKET)?;
        let request = if body.is_empty() {
            format!("{method} {path} HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        } else {
            format!("{method} {path} HTTP/1.0\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len())
        };
        std::io::Write::write_all(&mut stream, request.as_bytes())?;
        let mut response = String::new();
        stream.read_to_string(&mut response)?;

        let mut lines = response.splitn(2, "\r\n");
        let status_line = lines.next().unwrap_or_default();
        let status: u16 = status_line.split_whitespace().nth(1).and_then(|s| s.parse().ok()).unwrap_or(0);
        let rest = lines.next().unwrap_or_default();
        let json_body = rest.rsplit_once("\r\n\r\n").map(|(_, body)| body).unwrap_or(rest);
        Ok((status, json_body.trim().to_string()))
    }

    fn create_and_start_test_container() -> Result<String, String> {
        let create_body = r#"{"Image":"alpine:latest","Cmd":["sleep","60"],"Tty":false}"#;
        let (status, body) = docker_api("POST", &format!("/{API_VERSION}/containers/create?name={TEST_CONTAINER_NAME}"), create_body).map_err(|e| e.to_string())?;
        if status != 201 {
            return Err(format!("container create failed: HTTP {status}: {body}"));
        }
        let parsed: serde_json::Value = serde_json::from_str(&body).map_err(|e| format!("create response was not JSON ({e}): {body}"))?;
        let container_id = parsed.get("Id").and_then(|v| v.as_str()).ok_or_else(|| format!("create response had no Id: {body}"))?.to_string();

        let (status, body) = docker_api("POST", &format!("/{API_VERSION}/containers/{container_id}/start"), "").map_err(|e| e.to_string())?;
        if status != 204 {
            return Err(format!("container start failed: HTTP {status}: {body}"));
        }
        Ok(container_id)
    }

    fn remove_test_container(container_id: &str) {
        let _ = docker_api("DELETE", &format!("/{API_VERSION}/containers/{container_id}?force=true"), "");
    }

    /// Finds the cgroup v2 directory whose trailing segment names
    /// `container_id`, and returns its inode -- exactly the discovery this
    /// test needs to independently derive the `cgroup_id` a real kernel
    /// hook would see, without assuming a specific cgroup driver's path
    /// shape (systemd vs. cgroupfs) ahead of time.
    fn find_cgroup_id_for(root: &Path, container_id: &str) -> Option<u64> {
        let mut stack = vec![root.to_path_buf()];
        while let Some(dir) = stack.pop() {
            let Ok(entries) = std::fs::read_dir(&dir) else { continue };
            for entry in entries.flatten() {
                let Ok(file_type) = entry.file_type() else { continue };
                if !file_type.is_dir() {
                    continue;
                }
                let path = entry.path();
                if let Some(found) = classify_trailing_segment(&path) {
                    if found.container_id == container_id {
                        return std::fs::metadata(&path).ok().map(|m| m.ino());
                    }
                }
                stack.push(path);
            }
        }
        None
    }

    #[test]
    #[ignore = "requires a reachable Docker/Podman socket and a real cgroup v2 host -- see docs/TESTING.md"]
    fn resolves_a_real_container_end_to_end() {
        if !docker_socket_reachable() {
            eprintln!("live_smoke: skipping, {DOCKER_SOCKET} is not reachable in this environment");
            return;
        }

        // Best-effort pre-clean in case a previous aborted run left the
        // fixed-name container behind.
        remove_test_container(TEST_CONTAINER_NAME);

        let service = AttributionService::start().expect("AttributionService::start should succeed against a real cgroup v2 host");
        // Give the enrichment watcher's background thread time to connect
        // and subscribe to the events() stream before the container this
        // test creates actually starts -- Docker's event stream only
        // delivers events from the moment of subscription onward, so
        // creating the container too early would race the subscription
        // itself, not just the (much faster) cgroup-side inotify watch.
        std::thread::sleep(Duration::from_millis(800));

        let container_id = match create_and_start_test_container() {
            Ok(id) => id,
            Err(error) => {
                service.stop();
                panic!("failed to create the throwaway test container: {error}");
            }
        };

        let result = (|| -> Result<(), String> {
            let deadline = Instant::now() + Duration::from_secs(10);
            let cgroup_id = loop {
                if let Some(id) = find_cgroup_id_for(Path::new(super::DEFAULT_CGROUP_ROOT), &container_id) {
                    break id;
                }
                if Instant::now() > deadline {
                    return Err("timed out waiting for the container's cgroup directory to appear".to_string());
                }
                std::thread::sleep(Duration::from_millis(100));
            };

            let deadline = Instant::now() + Duration::from_secs(10);
            loop {
                if let Some(attribution) = service.resolver.resolve(cgroup_id) {
                    if attribution.container_id != container_id {
                        return Err(format!("resolved container id {} does not match the created container {container_id}", attribution.container_id));
                    }
                    if attribution.runtime != Runtime::Docker {
                        return Err(format!("expected runtime Docker, got {:?}", attribution.runtime));
                    }
                    if attribution.name.as_deref() == Some(TEST_CONTAINER_NAME) && attribution.image.as_deref() == Some("alpine:latest") {
                        return Ok(());
                    }
                    if Instant::now() > deadline {
                        return Err(format!("enrichment never completed within the deadline: last seen name={:?} image={:?}", attribution.name, attribution.image));
                    }
                } else if Instant::now() > deadline {
                    return Err("resolver never returned any attribution for the container's cgroup id".to_string());
                }
                std::thread::sleep(Duration::from_millis(200));
            }
        })();

        remove_test_container(&container_id);
        service.stop();

        result.expect("end-to-end attribution of a real container should succeed");
    }
}
