# SPDX-License-Identifier: GPL-3.0-or-later
#
# Build from the bathyscaphe repository root:
#
#   docker build -t ghcr.io/tagwright/bathyscaphe:dev .
#
# bathyscaphe has no tagwright module dependencies (unlike ballast/airlock,
# this is a plain crates.io + in-workspace Rust build, nothing GOPRIVATE-shaped
# to route around). The eBPF object is compiled by bathyscaphe-ebpf via
# aya-build's build.rs and embedded into the userspace binary at build time
# (aya::include_bytes_aligned! in src/main.rs) -- there is no separate .o file
# to ship alongside it.
#
# The two-toolchain build (stable userspace + nightly bpf-linker cross-compile
# for the ebpf crate) is proven step-by-step in docs/BUILDING.md. This stage
# is that proof, made reproducible: exact base image digest, exact bpf-linker
# version, no floating tags.

FROM rust@sha256:82150a52ec202c1b14d7817e14516c392bb7f5cfebd88f1ed531cb37ebd39922 AS build
# ^ rust:1-bookworm at the digest resolved when this Dockerfile was written
# (2026-08-28). Re-pin deliberately on a toolchain bump, never let this float.

# Pinned per docs/BUILDING.md's explicit warning: `cargo install bpf-linker`
# pulls in llvm-sys and needs a matching system LLVM (LLVM 23) to build 0.11.0
# from source. The prebuilt musl release tarball sidesteps that entirely and
# runs fine on this glibc host.
ARG BPF_LINKER_VERSION=0.11.0
ARG BPF_LINKER_SHA256_URL=https://github.com/aya-rs/bpf-linker/releases/download/v0.11.0/bpf-linker-x86_64-unknown-linux-musl.tar.zst

# zstd: not present in the base image, needed to unpack the bpf-linker
# release tarball. binutils' `strip` is already present on rust:1-bookworm.
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends zstd \
    && rm -rf /var/lib/apt/lists/*

RUN curl -sL -o /tmp/bpf-linker.tar.zst "${BPF_LINKER_SHA256_URL}" \
    && tar --zstd -C /tmp -xf /tmp/bpf-linker.tar.zst \
    && install -m 0755 /tmp/bpf-linker /usr/local/bin/bpf-linker \
    && rm -f /tmp/bpf-linker.tar.zst /tmp/bpf-linker

# nightly + rust-src: the -ebpf crate's build-std=core cross-compile.
# Do NOT set CARGO_HOME here (docs/BUILDING.md's gotcha) -- rustup expects
# to manage /usr/local/cargo itself on this image, tracked separately from
# RUSTUP_HOME=/usr/local/rustup, both of which are already set by the base
# image. Overriding CARGO_HOME breaks rustup's own bookkeeping.
RUN rustup toolchain install nightly --component rust-src

WORKDIR /src
COPY . .

# One `cargo build` at the workspace root builds bathyscaphe,
# bathyscaphe-common, and bathyscaphe-proto on stable directly, and as a
# side effect of bathyscaphe's build.rs (an aya-build dependency), cross-
# compiles bathyscaphe-ebpf on nightly via bpf-linker and hands the
# resulting BPF object back to OUT_DIR for aya::include_bytes_aligned! to
# embed. No separate "build the ebpf crate" step -- see docs/BUILDING.md.
RUN cargo build --release --locked \
    && strip --strip-unneeded target/release/bathyscaphe

# --- runtime image ---
#
# Needs glibc (aya/libc syscalls, bollard's unix-socket client) and CA
# certificates are carried for parity with other tagwright images even
# though bathyscaphe's own network use is a local Docker/Podman socket, not
# TLS. debian:bookworm-slim matches the build stage's userland with no Rust
# toolchain along for the ride.
FROM debian@sha256:abd67ffcfa541b485a3dff59865ab629aa048a6c613e639d36e7456b0b229241

RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /src/target/release/bathyscaphe /usr/local/bin/bathyscaphe

# --- required runtime posture (see docs/DEPLOY.md for the full compose example) ---
#
# Privilege: CAP_BPF + CAP_NET_ADMIN + CAP_SYS_ADMIN to load/attach the eBPF
# programs and pin them to bpffs, or --privileged in practice (the common
# posture for eBPF egress tooling deployed today -- IG and Cilium both do
# the same). Not settable from inside a Dockerfile; the caller's `docker
# run` / compose service grants it.
#
# Mounts the caller must provide:
#   - /sys/fs/cgroup  (the host's cgroup v2 unified hierarchy, so bathyscaphe
#     can open a container's cgroup directory to attach the connect4/connect6
#     hooks -- --cgroupns=host is required too, or this container only ever
#     sees its own private cgroup namespace slice, not sibling containers'.)
#   - /sys/fs/bpf     (a bpffs, for fail-closed pinning of programs, links,
#     and policy maps. If the host doesn't already have one mounted there,
#     `mount -t bpf bpf /sys/fs/bpf` inside the privileged container before
#     starting bathyscaphe; a bind-mount of the host's own bpffs works too
#     and is what makes pins survive a container restart.)
#   - /var/run/docker.sock (ro)  (the Docker/Podman socket bathyscaphe reads
#     via bollard for id -> name/image container attribution. Read-only is
#     sufficient -- bathyscaphe only queries, it never starts/stops/labels
#     anything.)
#
# Kernel 5.8+ and cgroup v2 (the unified hierarchy) are hard floors --
# bathyscaphe's own kernel-floor check fails loud and refuses to start on
# an older kernel or a v1/hybrid cgroup host rather than silently degrading.
#
# `run` is the default CMD (the airlock-driven subprocess mode). Override
# CMD to `observe` or `unpin --all` for the standalone modes -- see
# docs/DEPLOY.md and `bathyscaphe --help`.
ENTRYPOINT ["bathyscaphe"]
CMD ["run"]
