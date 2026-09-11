//! Embeds the git commit (plus a `-dirty` suffix if the tree had
//! uncommitted changes) the binary was built from, via `git describe`.
//! Falls back to `"unknown"` when git isn't available (e.g. building
//! from a source tarball with no `.git`), rather than failing the
//! build.

use std::path::Path;
use std::process::Command;

fn main() {
    let git_sha = git_describe().unwrap_or_else(|| "unknown".to_string());
    println!("cargo:rustc-env=NOCAP_CRYPT_GIT_SHA={git_sha}");

    let manifest_dir =
        std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR set by cargo");
    let git_dir = Path::new(&manifest_dir).join("../../.git");
    println!("cargo:rerun-if-changed={}", git_dir.join("HEAD").display());
    println!("cargo:rerun-if-changed={}", git_dir.join("index").display());
}

fn git_describe() -> Option<String> {
    let output = Command::new("git")
        .args(["describe", "--always", "--dirty", "--abbrev=12"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let sha = String::from_utf8(output.stdout).ok()?;
    let sha = sha.trim();
    (!sha.is_empty()).then(|| sha.to_string())
}
