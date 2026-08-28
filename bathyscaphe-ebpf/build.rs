// SPDX-License-Identifier: GPL-3.0-or-later
//! Building this crate has an undeclared dependency on the `bpf-linker`
//! binary. This would be better expressed by artifact-dependencies
//! (https://doc.rust-lang.org/nightly/cargo/reference/unstable.html#artifact-dependencies)
//! but https://github.com/rust-lang/cargo/issues/12385 makes their use
//! impractical for now.
//!
//! This causes cargo to rebuild the crate whenever the mtime of `which
//! bpf-linker` changes, which is an imperfect but workable proxy for "the
//! linker changed." Lifted from the aya-template convention (see
//! docs/BUILDING.md).
use which::which;

fn main() {
    let bpf_linker = which("bpf-linker").expect("bpf-linker not found in PATH");
    println!("cargo:rerun-if-changed={}", bpf_linker.to_str().expect("bpf-linker path is not UTF-8"));
}
