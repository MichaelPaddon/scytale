//! Clone and build the OpenSSL we benchmark against.
//!
//! OpenSSL is never vendored into this repository; it is fetched here and
//! built into a cache directory. It is built twice, because a fair
//! comparison needs a counterpart of the same kind for each of scytale's
//! implementations:
//!
//! - `no-asm` gives OpenSSL's pure C AES, which is what scytale's portable
//!   T-table cipher should be measured against.
//! - the default configuration gives its assembly, including the AES-NI
//!   kernels that scytale's own AES-NI backend should be measured against.
//!
//! Both archives define `AES_encrypt`, so they are copied under distinct
//! names and the C one is listed first: the accelerated symbols we want
//! from the assembly build are spelled `aesni_*` and do not collide.

use std::path::{Path, PathBuf};
use std::process::Command;

const OPENSSL_REPO: &str = "https://github.com/openssl/openssl.git";
const OPENSSL_TAG: &str = "openssl-4.0.1";

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=SCYTALE_BENCH_SKIP_OPENSSL");
    println!("cargo:rustc-check-cfg=cfg(openssl_available)");

    if std::env::var_os("SCYTALE_BENCH_SKIP_OPENSSL").is_some() {
        println!("cargo:warning=skipping OpenSSL build on request");
        return;
    }

    // The reference library is built for the machine running the build,
    // so it cannot be linked into a binary for any other target. Skip it
    // and let the crate compile without a comparison, rather than
    // handing the linker two archives of the wrong architecture.
    let target = std::env::var("TARGET").expect("cargo sets TARGET");
    let host = std::env::var("HOST").expect("cargo sets HOST");
    if target != host {
        println!(
            "cargo:warning=cross compiling to {target}: skipping the \
             OpenSSL comparison, which is built for {host}"
        );
        return;
    }

    let out_dir =
        PathBuf::from(std::env::var("OUT_DIR").expect("cargo sets OUT_DIR"));
    // Keep the build outside OUT_DIR's per-profile churn so cleaning this
    // crate does not force another full OpenSSL build.
    let root =
        out_dir.ancestors().nth(3).unwrap_or(&out_dir).join("openssl");
    let src = root.join(format!("src-{OPENSSL_TAG}"));
    let src_asm = root.join(format!("src-{OPENSSL_TAG}-asm"));
    let noasm = root.join(format!("install-{OPENSSL_TAG}-noasm"));
    let asm = root.join(format!("install-{OPENSSL_TAG}-asm"));

    if !installed(&noasm) {
        clone(&src);
        build(&src, &noasm, &["no-asm"]);
    }
    if !installed(&asm) {
        clone(&src_asm);
        build(&src_asm, &asm, &[]);
    }

    // One directory holding both archives under names that do not collide.
    let staged = root.join("lib");
    std::fs::create_dir_all(&staged).expect("creating the link directory");
    stage(&noasm, &staged, "libcrypto_noasm.a");
    stage(&asm, &staged, "libcrypto_asm.a");

    println!("cargo:rustc-link-search=native={}", staged.display());
    // The C archive first, so the plain AES_* symbols resolve to it.
    println!("cargo:rustc-link-lib=static=crypto_noasm");
    println!("cargo:rustc-link-lib=static=crypto_asm");
    println!("cargo:rustc-cfg=openssl_available");
}

fn installed(prefix: &Path) -> bool {
    lib_dir(prefix).join("libcrypto.a").exists()
}

fn lib_dir(prefix: &Path) -> PathBuf {
    let lib64 = prefix.join("lib64");
    if lib64.exists() { lib64 } else { prefix.join("lib") }
}

/// Copy an archive under a name that says which build it came from.
fn stage(prefix: &Path, staged: &Path, name: &str) {
    let from = lib_dir(prefix).join("libcrypto.a");
    let to = staged.join(name);
    let fresh = std::fs::metadata(&to)
        .and_then(|d| d.modified())
        .ok()
        .zip(std::fs::metadata(&from).and_then(|m| m.modified()).ok())
        .map(|(dst, src)| dst >= src)
        .unwrap_or(false);
    if !fresh {
        std::fs::copy(&from, &to)
            .unwrap_or_else(|e| panic!("staging {}: {e}", from.display()));
    }
}

fn run(what: &str, cmd: &mut Command) {
    let status = cmd
        .status()
        .unwrap_or_else(|e| panic!("failed to start {what}: {e}"));
    assert!(status.success(), "{what} failed with {status}");
}

fn clone(src: &Path) {
    if src.join(".git").exists() {
        return;
    }
    std::fs::create_dir_all(src.parent().expect("source path has a parent"))
        .expect("creating the OpenSSL build directory");

    run(
        "git clone",
        Command::new("git").args([
            "clone",
            "--depth",
            "1",
            "--branch",
            OPENSSL_TAG,
            OPENSSL_REPO,
            &src.display().to_string(),
        ]),
    );
}

fn build(src: &Path, install: &Path, extra: &[&str]) {
    // `extra` carries no-asm for the C build and nothing for the assembly
    // one. The rest is trimmed purely to keep the build short.
    run(
        "OpenSSL Configure",
        Command::new("perl")
            .current_dir(src)
            .arg("./Configure")
            .args(extra)
            .arg("no-shared")
            .arg("no-tests")
            .arg("no-docs")
            .arg("no-apps")
            .arg(format!("--prefix={}", install.display())),
    );

    let jobs = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    run(
        "make",
        Command::new("make")
            .current_dir(src)
            .arg(format!("-j{jobs}"))
            .arg("build_libs"),
    );
    run(
        "make install_dev",
        Command::new("make").current_dir(src).arg("install_dev"),
    );
}
