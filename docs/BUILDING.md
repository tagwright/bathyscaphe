<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Building bathyscaphe

There is no host Rust toolchain for this project. Everything here was
proven inside a throwaway Docker container (`bathyscaphe-itest-toolchain`,
cleaned up after use), and the same setup is what a real Dockerfile should
do for CI and for building the runtime image. This document is the record
of that proof: the exact image, the exact steps, and the two things that
have to both be true for `cargo build` to succeed.

## Why there are two toolchains

`bathyscaphe`, `bathyscaphe-common`, and `bathyscaphe-proto` are ordinary
`std` Rust and build on stable. `bathyscaphe-ebpf` is `no_std`, compiles
to a `bpfel-unknown-none` (or `bpfeb-unknown-none` on big-endian targets)
BPF object, and needs the nightly compiler with `-Z build-std=core` plus a
non-rustc linker (`bpf-linker`) that understands how to produce a BPF ELF
object. `aya-build`'s `build.rs` integration (used in `bathyscaphe/build.rs`)
drives the nightly compile as a build dependency of the stable userspace
crate, so a single `cargo build` at the workspace root builds both sides.
You don't invoke the nightly compiler yourself.

## The proven base image

`rust:1-bookworm` (resolved to Rust 1.98.0 stable at the time this was
proven, Debian bookworm userland). Nothing eBPF-specific about the choice;
it's just a current, glibc-based Rust image with `curl` and `tar` already
present.

## Toolchain install, step by step

```sh
# 1. nightly + rust-src, for the -ebpf crate's build-std=core compile.
rustup toolchain install nightly --component rust-src

# 2. zstd, to unpack the bpf-linker release tarball (not present in the
#    base image).
apt-get update -qq && apt-get install -y -qq zstd

# 3. bpf-linker itself. Do NOT `cargo install bpf-linker` -- as of 0.11.0
#    that pulls in llvm-sys and needs a matching system LLVM (LLVM 23) to
#    build from source, which the bpf-linker README itself warns regular
#    users off doing. There's a prebuilt static (musl) x86_64 Linux binary
#    on the GitHub release instead, and it runs fine on a glibc host:
curl -sL -o /tmp/bpf-linker.tar.zst \
  https://github.com/aya-rs/bpf-linker/releases/download/v0.11.0/bpf-linker-x86_64-unknown-linux-musl.tar.zst
tar --zstd -C /tmp -xf /tmp/bpf-linker.tar.zst
install -m 0755 /tmp/bpf-linker /usr/local/bin/bpf-linker
```

That's the whole toolchain. No LLVM install, no `cargo-generate` needed at
build time (only for scaffolding new crates), no `bpftool` needed for this
chunk (it's only needed later, for `aya-tool`-generated kernel struct
bindings against a running kernel's BTF -- not used yet).

## The two build commands

```sh
cd bathyscaphe   # workspace root
cargo build      # builds bathyscaphe, bathyscaphe-common, bathyscaphe-proto
                 # (the default-members) on stable, and as a side effect of
                 # bathyscaphe's build.rs, cross-compiles bathyscaphe-ebpf
                 # on nightly via bpf-linker and embeds the resulting BPF
                 # object into the bathyscaphe binary.
cargo test       # unit tests across the default-members workspace.
```

There is no separate "build the ebpf crate" command to remember: building
`bathyscaphe` always builds `bathyscaphe-ebpf` too, because `bathyscaphe`'s
`build.rs` depends on it (see `bathyscaphe-ebpf` listed under
`[build-dependencies]` in `bathyscaphe/Cargo.toml`). Running
`cargo build -p bathyscaphe-ebpf` directly, on the plain stable/host
target, is *not* expected to work and isn't how this crate is meant to be
built standalone.

## What actually got proven (2026-08-27)

Run inside `bathyscaphe-itest-toolchain` (a container from `rust:1-bookworm`,
with `/workspace` bind-mounted so the workspace and sibling repos are
visible, working directory `/workspace/bathyscaphe`):

- `cargo build` from a clean `target/` finished in ~23s, no errors, only
  the usual "Compiling ..." noise (see the "known harmless warning" below).
- The nightly cross-compile step produced
  `target/debug/build/bathyscaphe-*/out/aya-build/target/bathyscaphe-ebpf/bpfel-unknown-none/release/build/bathyscaphe-ebpf/*/out/bathyscaphe`,
  linked by `bpf-linker` into
  `target/debug/build/bathyscaphe-*/out/bathyscaphe` (the file `aya-build`
  copies into `OUT_DIR` for the userspace crate to embed).
- `readelf -h` on that file confirms it's a real BPF object: `Machine:
  Linux BPF`, `Type: REL (Relocatable file)`.
- `readelf -S` shows a `cgroup/connect4` section and a `license` section,
  confirming the actual `#[cgroup_sock_addr(connect4)]` program got
  compiled and linked, not just the crate metadata.
- `cargo run` printed:
  ```
  bathyscaphe 00.01.00b1
  eBPF object embedded: 79608 bytes
  bathyscaphe-common and bathyscaphe-proto skeleton types constructed OK
  ```
- `cargo test` passed 2 unit tests (a repr(C) size assertion in
  `bathyscaphe-common`, a serde round-trip in `bathyscaphe-proto`) plus
  the (empty, expected) doctest suites.

None of this loads the eBPF program into a real kernel or attaches it to
a cgroup -- that's runtime behavior, not a build-time one, and it needs a
privileged container with a real cgroup v2 path, which is out of scope
for a toolchain proof. `bathyscaphe`'s `main.rs` has a `load_probe()`
stub that calls `aya::Ebpf::load()` on the embedded bytes but is never
invoked yet. Compile-proven, not runtime-proven; that's the TESTING build
chunk's job.

## Gotchas hit along the way

- **`serde` needs `std` explicitly.** The workspace pins
  `default-features = false` on `serde` (matching the aya-template
  convention of trimming default features everywhere), but `String`'s
  `Serialize`/`Deserialize` impls live behind serde's `std` feature.
  Forgetting it fails with "the trait bound `String: serde::Serialize` is
  not satisfied" pointing at the derive, which reads confusingly like a
  missing derive rather than a missing feature. Fixed by adding `"std"`
  to `bathyscaphe-proto`'s `serde` feature list in the workspace
  `Cargo.toml`.
- **A harmless warning you will see every build:** `ignoring invalid
  dependency 'bathyscaphe-ebpf' which is missing a lib target`. This is
  cargo noticing that `bathyscaphe-ebpf` is listed as a build-dependency
  but only has a `[[bin]]`, no `[lib]` -- which is correct, since
  `aya-build` shells out to build it as a separate `cargo` invocation
  rather than linking it in as a library. The upstream aya-template has
  the identical shape and presumably the identical warning. Nothing to
  fix.
- **`bpf-linker`'s own `cargo install` path is a trap.** The 0.11.0
  README is explicit that building from source needs a specific LLVM
  version (`llvm-sys-23`, LLVM 23) and isn't recommended for regular use.
  Earlier bpf-linker releases (0.10.x) had a `rust-llvm-*` feature that
  linked against the LLVM already bundled with rustc to dodge this, but
  that feature is gone as of 0.11.0. The prebuilt release tarball sidesteps
  the whole question and is what's documented above.
- **`CARGO_HOME` must not be overridden on the `rust:1-bookworm` image.**
  Setting a container-level `CARGO_HOME` env var (tried `/root/.cargo`
  while poking at this) breaks `rustup` internals -- it expects `rustup`
  itself to live under the image's default `/usr/local/cargo`, tracked
  separately from `RUSTUP_HOME=/usr/local/rustup`. Leave both alone.
- **Don't use `bash -lc` for `docker exec`** on this image if you've
  customized `PATH` -- a login shell can reload `/etc/profile` and step on
  the image's `PATH` export. Plain `bash -c` was reliable throughout.

## For the eventual Dockerfile (PACKAGING build chunk)

This proof used an interactive container with `apt-get install` and a
manual `curl`/`tar`/`install` sequence. The multi-stage Dockerfile should
pin the exact `bpf-linker` version (`v0.11.0` here) and the exact
`rust:1-bookworm` digest rather than floating tags, so the build doesn't
silently pick up a future bpf-linker that reintroduces an LLVM
requirement or changes its default target support.
