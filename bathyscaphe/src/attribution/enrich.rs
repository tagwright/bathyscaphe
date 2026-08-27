// SPDX-License-Identifier: GPL-3.0-or-later
//! `container_id -> name/image` enrichment over the Docker/Podman socket
//! (`bathy_attribution.md` section 2). This is the racy, best-effort half
//! of attribution: [`super::cgroup`] gives a `container_id` deterministically
//! from the filesystem the moment a container's cgroup exists, but its
//! name and image only become known once bollard's bootstrap listing or
//! event stream has actually reached this process.
//!
//! ## Why a dedicated thread and a `current_thread` runtime
//!
//! `bollard` is async (tokio/hyper), and nothing else in this workspace is
//! (`probe::events`'s `EventConsumer` is a plain OS thread blocking on
//! `poll(2)`, matching aya's own non-tokio `RingBuf` consumer pattern). The
//! build brief's instruction, given that mismatch, is to confine tokio to
//! this module rather than pull an executor into the whole binary. A
//! single-threaded (`current_thread`) runtime, owned entirely by one
//! background OS thread, does that: bollard's futures run on it, nothing
//! outside this module ever touches a `Handle` or a `#[tokio::main]`, and
//! the rest of the crate (the ring-buf consumer, the cgroup watcher, the
//! eventual protocol I/O loop) stays exactly as thread-based as chunk #5
//! left it. The cache the runtime populates ([`EnrichmentCache`]) is a
//! plain `Mutex<HashMap>`, readable synchronously from any thread with no
//! `.await` anywhere outside this file.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use bollard::Docker;
use bollard::query_parameters::{EventsOptionsBuilder, InspectContainerOptions, ListContainersOptionsBuilder};
use futures_util::StreamExt;

/// What bollard can tell us about a container id, independent of how it was
/// learned (bootstrap listing vs. live event). Both fields are `None`
/// rather than the struct being absent when nothing is known yet -- see
/// [`EnrichmentCache::get`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ContainerMeta {
    pub name: Option<String>,
    pub image: Option<String>,
}

/// The live `container_id -> ContainerMeta` cache. Cheap to read from any
/// thread (a `Mutex<HashMap>` lock, no I/O); only the background enrichment
/// thread ever writes it.
#[derive(Default)]
pub struct EnrichmentCache {
    inner: Mutex<HashMap<String, ContainerMeta>>,
}

impl EnrichmentCache {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Best-effort lookup. `None` (not an error) means "not cached yet" --
    /// the short-lived-container race, or a container whose `start`/`create`
    /// event just hasn't reached the watcher thread yet. Callers combine
    /// this with the always-available `container_id` from [`super::cgroup`]
    /// rather than treating a cache miss as attribution failure.
    pub fn get(&self, container_id: &str) -> Option<ContainerMeta> {
        self.inner.lock().unwrap_or_else(|poison| poison.into_inner()).get(container_id).cloned()
    }

    fn upsert(&self, container_id: String, meta: ContainerMeta) {
        if meta.name.is_none() && meta.image.is_none() {
            return;
        }
        self.inner.lock().unwrap_or_else(|poison| poison.into_inner()).insert(container_id, meta);
    }

    fn remove(&self, container_id: &str) {
        self.inner.lock().unwrap_or_else(|poison| poison.into_inner()).remove(container_id);
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.inner.lock().unwrap().len()
    }
}

/// Owns the background thread. Same shutdown-flag-plus-join shape as
/// [`super::cgroup::CgroupWatcher`] and `probe::events::EventConsumer`.
pub struct EnrichmentWatcher {
    shutdown: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl EnrichmentWatcher {
    /// Spawns the background thread: connects (Docker or Podman, rootful or
    /// rootless -- see [`connect`]), bootstraps `cache` from a bulk listing,
    /// then keeps it warm off the `events()` stream indefinitely, filtered
    /// to `type: container`, reconnecting with a short backoff if the
    /// stream ever ends or errors (a daemon restart, a socket hiccup). If
    /// the initial connect itself fails, this logs to stderr and returns
    /// with the cache left empty rather than failing the whole process --
    /// enrichment is best-effort by design; every event still carries a
    /// real `container_id` from `cgroup` attribution regardless.
    pub fn spawn(cache: Arc<EnrichmentCache>) -> Self {
        let shutdown = Arc::new(AtomicBool::new(false));
        let shutdown_thread = Arc::clone(&shutdown);

        let handle = thread::spawn(move || {
            let runtime = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
                Ok(runtime) => runtime,
                Err(error) => {
                    eprintln!("bathyscaphe: failed to start the attribution enrichment runtime ({error}); name/image enrichment is unavailable this run");
                    return;
                }
            };
            runtime.block_on(run(cache, shutdown_thread));
        });

        Self { shutdown, handle: Some(handle) }
    }

    pub fn stop(mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// One bollard client, pointed at `connect_with_podman_defaults`, handles
/// every case `bathy_attribution.md` section 2 enumerates: it probes
/// `$DOCKER_HOST`, then rootless Podman's socket, then rootful Podman's
/// socket, then falls back to the plain Docker socket -- so a Docker-only
/// host (the common case) is served by the same call as a Podman host,
/// rootful or rootless, with no engine-specific branch in this module.
fn connect() -> Result<Docker, bollard::errors::Error> {
    Docker::connect_with_podman_defaults()
}

async fn run(cache: Arc<EnrichmentCache>, shutdown: Arc<AtomicBool>) {
    let docker = match connect() {
        Ok(docker) => docker,
        Err(error) => {
            eprintln!("bathyscaphe: could not connect to a Docker or Podman socket ({error}); attribution will carry container ids only, with name/image left null");
            return;
        }
    };

    if let Err(error) = bootstrap(&docker, &cache).await {
        eprintln!("bathyscaphe: initial container listing failed ({error}); enrichment continues from the live event stream alone");
    }

    while !shutdown.load(Ordering::Relaxed) {
        let mut filters: HashMap<String, Vec<String>> = HashMap::new();
        filters.insert("type".to_string(), vec!["container".to_string()]);
        let options = EventsOptionsBuilder::new().filters(&filters).build();
        let mut stream = docker.events(Some(options));

        loop {
            tokio::select! {
                item = stream.next() => {
                    match item {
                        Some(Ok(message)) => handle_event(&docker, &cache, message).await,
                        Some(Err(error)) => {
                            eprintln!("bathyscaphe: docker/podman events stream error ({error}); reconnecting");
                            break;
                        }
                        None => break,
                    }
                }
                _ = tokio::time::sleep(Duration::from_millis(250)) => {
                    if shutdown.load(Ordering::Relaxed) {
                        return;
                    }
                }
            }
        }

        if shutdown.load(Ordering::Relaxed) {
            return;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

async fn bootstrap(docker: &Docker, cache: &EnrichmentCache) -> Result<(), bollard::errors::Error> {
    let options = ListContainersOptionsBuilder::default().all(true).build();
    let containers = docker.list_containers(Some(options)).await?;
    for container in containers {
        let Some(id) = container.id else { continue };
        let name = container.names.and_then(|names| names.into_iter().next()).map(|n| n.trim_start_matches('/').to_string());
        let image = container.image;
        cache.upsert(id, ContainerMeta { name, image });
    }
    Ok(())
}

/// Updates `cache` from one `type: container` event. Docker/Podman populate
/// `Actor.Attributes` with `name`/`image` directly on the events that
/// matter (`create`/`start`), avoiding a follow-up API call in the common
/// case; `inspect_container` is only used as a fallback when those
/// attributes come back sparse. `destroy` evicts the cache entry entirely
/// (the container id is gone for good); `die`/`stop` deliberately do NOT
/// evict, so a connection's final teardown accounting racing the
/// container's own exit can still resolve name/image for a few more
/// events, per `bathy_attribution.md` section 2's "keep briefly" guidance.
async fn handle_event(docker: &Docker, cache: &EnrichmentCache, message: bollard::models::EventMessage) {
    let Some(actor) = message.actor else { return };
    let Some(id) = actor.id else { return };

    if message.action.as_deref() == Some("destroy") {
        cache.remove(&id);
        return;
    }

    let attributes = actor.attributes.unwrap_or_default();
    let mut name = attributes.get("name").cloned();
    let mut image = attributes.get("image").cloned();

    if name.is_none() || image.is_none() {
        if let Ok(inspected) = docker.inspect_container(&id, None::<InspectContainerOptions>).await {
            name = name.or_else(|| inspected.name.map(|n| n.trim_start_matches('/').to_string()));
            image = image.or_else(|| inspected.config.and_then(|c| c.image));
        }
    }

    cache.upsert(id, ContainerMeta { name, image });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upsert_and_get_round_trip() {
        let cache = EnrichmentCache::default();
        cache.upsert("deadbeef".to_string(), ContainerMeta { name: Some("web".to_string()), image: Some("nginx:latest".to_string()) });
        assert_eq!(cache.get("deadbeef"), Some(ContainerMeta { name: Some("web".to_string()), image: Some("nginx:latest".to_string()) }));
    }

    #[test]
    fn miss_is_none_not_a_default_struct() {
        let cache = EnrichmentCache::default();
        assert_eq!(cache.get("never-seen"), None);
    }

    #[test]
    fn upsert_with_nothing_learned_is_a_no_op() {
        let cache = EnrichmentCache::default();
        cache.upsert("deadbeef".to_string(), ContainerMeta::default());
        assert_eq!(cache.len(), 0, "an all-None ContainerMeta should never occupy a cache slot");
    }

    #[test]
    fn remove_evicts() {
        let cache = EnrichmentCache::default();
        cache.upsert("deadbeef".to_string(), ContainerMeta { name: Some("web".to_string()), image: None });
        cache.remove("deadbeef");
        assert_eq!(cache.get("deadbeef"), None);
    }
}
