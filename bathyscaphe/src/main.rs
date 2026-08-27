// SPDX-License-Identifier: GPL-3.0-or-later
//! `bathyscaphe`: the userspace loader/daemon binary.
//!
//! This chunk (SCAFFOLD + TOOLCHAIN PROOF) exists to prove the
//! two-toolchain build pipeline end to end: the stable-Rust userspace
//! crate pulls in the nightly + bpf-linker build of `bathyscaphe-ebpf` as
//! a build dependency (via `aya-build`, see build.rs) and embeds the
//! resulting BPF object. Nothing is loaded into the kernel yet -- the
//! real loader (fail-closed pinning, attribution, map management,
//! reconciliation) is the USERSPACE CORE and DAEMON build chunks in
//! bathy_build_spec.md's build sequence.

// USERSPACE CORE build chunk: the real loader/attach/pinning/map-API/ringbuf
// lifecycle. Not wired into `main()` yet -- see `probe`'s module doc. The
// `load_probe()` stub below predates it and stays as-is (still unused) until
// the DAEMON build chunk replaces both with the real protocol loop. As a
// binary crate (no `[lib]` target) nothing outside this crate can reference
// `probe`'s public API yet either, so the whole module is expected-dead
// code until that wiring lands -- same rationale as `load_probe`'s own
// `#[allow(dead_code)]` below.
#[allow(dead_code, unused_imports)]
mod probe;

// CONTAINER ATTRIBUTION + EVENT PIPELINE build chunk: cgroup_id ->
// container attribution (attribution) and the kernel-Event -> wire-Event
// mapping that plugs into probe::events::EventConsumer (pipeline). Neither
// is wired into `main()` yet -- that is the DAEMON build chunk's job (the
// full protocol loop, `hello`/`start`, and the CLI that actually runs a
// probe). Both modules are fully exercised by their own unit tests
// (`cargo test`), which is what proves them out at this stage; see each
// module's doc and docs/TESTING.md.
#[allow(dead_code, unused_imports)]
mod attribution;
#[allow(dead_code, unused_imports)]
mod pipeline;

const VERSION: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../VERSION"));

/// The compiled eBPF object for bathyscaphe-ebpf's `connect4` program,
/// embedded at build time. Proves the nightly/bpf-linker compile
/// succeeded and produced a real BPF ELF object, not just that the
/// userspace crate itself compiles.
static EBPF_OBJECT: &[u8] = aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/bathyscaphe"));

fn main() {
    println!("bathyscaphe {}", VERSION.trim());
    println!("eBPF object embedded: {} bytes", EBPF_OBJECT.len());

    // Prove bathyscaphe-common (the real map/event ABI types as of the
    // COMMON build chunk) and bathyscaphe-proto (the real, frozen wire
    // protocol as of the PROTO build chunk) are both wired in and usable
    // from the userspace binary, including the `user`-feature `aya::Pod`
    // impls.
    let _shared_event = bathyscaphe_common::Event::default();
    let _shared_policy_key = bathyscaphe_common::PolicyKeyData::default();
    let hello = bathyscaphe_proto::Hello {
        backend: "bathyscaphe".to_string(),
        backend_version: VERSION.trim().to_string(),
        proto_versions: vec![bathyscaphe_proto::PROTO_VERSION],
        capabilities: vec![bathyscaphe_proto::Capability::Observe],
        pinned: Vec::new(),
    };
    let _wire_line = bathyscaphe_proto::encode_line(&bathyscaphe_proto::UpMessage::Hello(hello))
        .expect("hello message encodes");
    println!("bathyscaphe-common ABI types and bathyscaphe-proto wire types constructed OK");
}

/// Stub for the real loader. Not called yet -- see `bathy_ebpf_design.md`
/// section 3 (fail-closed pinning) and the USERSPACE CORE build chunk.
/// Kept here so the eventual entry point's shape is visible from this
/// chunk onward, and so `aya::Ebpf` shows up as a used type (not just a
/// build-time embed) even before real attach/load logic exists.
#[allow(dead_code)]
fn load_probe() -> anyhow::Result<aya::Ebpf> {
    let ebpf = aya::Ebpf::load(EBPF_OBJECT)?;
    Ok(ebpf)
}
