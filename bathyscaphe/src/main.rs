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

const VERSION: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../VERSION"));

/// The compiled eBPF object for bathyscaphe-ebpf's `connect4` program,
/// embedded at build time. Proves the nightly/bpf-linker compile
/// succeeded and produced a real BPF ELF object, not just that the
/// userspace crate itself compiles.
static EBPF_OBJECT: &[u8] = aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/bathyscaphe"));

fn main() {
    println!("bathyscaphe {}", VERSION.trim());
    println!("eBPF object embedded: {} bytes", EBPF_OBJECT.len());

    // Prove bathyscaphe-common and bathyscaphe-proto are wired in and
    // usable from the userspace binary, even though both are still
    // placeholder types at this build chunk.
    let _shared_type = bathyscaphe_common::PlaceholderRecord::default();
    let _wire_type = bathyscaphe_proto::PlaceholderMessage {
        kind: "toolchain-proof".to_string(),
        sequence: 0,
    };
    println!("bathyscaphe-common and bathyscaphe-proto skeleton types constructed OK");
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
