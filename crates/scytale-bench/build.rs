//! Clone and build the OpenSSL we benchmark against.
//!
//! OpenSSL is never vendored into this repository; it is fetched here and
//! built into a cache directory. The build is configured `no-asm` so its AES
//! is the pure C path, which is the like-for-like comparison while scytale
//! has only software implementations. A default OpenSSL build would use
//! AES-NI and beat a software T-table on hardware grounds alone.

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

    let out_dir =
        PathBuf::from(std::env::var("OUT_DIR").expect("cargo sets OUT_DIR"));
    // Keep the build outside OUT_DIR's per-profile churn so cleaning this
    // crate does not force another full OpenSSL build.
    let root =
        out_dir.ancestors().nth(3).unwrap_or(&out_dir).join("openssl");
    let src = root.join(format!("src-{OPENSSL_TAG}"));
    let install = root.join(format!("install-{OPENSSL_TAG}-noasm"));

    if !install.join("lib").exists() && !install.join("lib64").exists() {
        clone(&src);
        build(&src, &install);
    }

    let lib_dir = if install.join("lib64").exists() {
        install.join("lib64")
    } else {
        install.join("lib")
    };

    println!("cargo:rustc-link-search=native={}", lib_dir.display());
    println!("cargo:rustc-link-lib=static=crypto");
    println!("cargo:rustc-cfg=openssl_available");
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

fn build(src: &Path, install: &Path) {
    // no-asm is the point of this build: it selects OpenSSL's C AES rather
    // than AES-NI. The rest is trimmed purely to keep the build short.
    run(
        "OpenSSL Configure",
        Command::new("perl")
            .current_dir(src)
            .arg("./Configure")
            .arg("no-asm")
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
