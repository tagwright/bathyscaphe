// SPDX-License-Identifier: GPL-3.0-or-later
//! Container attribution: `cgroup_id -> containerId/containerName/
//! containerImageName`, entirely in Rust with no dependency on
//! `github.com/tagwright/core` (`bathy_attribution.md` is the authority).
//!
//! Two independent halves, joined in [`resolver::Resolver`]:
//!
//! - [`cgroup`]: `cgroup_id -> container_id`/`runtime`. Deterministic and
//!   always available once a container's cgroup directory exists (the
//!   cgroup id IS that directory's inode number) -- an inotify-driven
//!   walk-and-watch of `/sys/fs/cgroup`, no BPF map round trip needed for
//!   discovery.
//! - [`enrich`]: `container_id -> name`/`image`, over the Docker/Podman
//!   socket via `bollard`. Best-effort: a bootstrap listing plus a live
//!   `events()` stream keep it warm, but a very short-lived container can
//!   race ahead of both.
//!
//! [`resolver::AttributionService`] is the one call a later chunk's daemon
//! needs: start both watchers, get back a [`resolver::Resolver`] to hand to
//! [`crate::pipeline`].

pub mod cgroup;
pub mod enrich;
pub mod resolver;

pub use resolver::{Attribution, AttributionService, Attributor, Resolver};
