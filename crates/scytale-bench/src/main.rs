//! Compare scytale against OpenSSL, like for like.
//!
//! Exits non-zero when any case is slower, so the rule that OpenSSL must
//! never be faster is machine-checkable.

use std::process::ExitCode;

use scytale_bench::harness::{Row, compare, report};

#[cfg(openssl_available)]
use scytale::symmetric::aes::{
    Aes128Dec, Aes128Enc, Aes192Dec, Aes192Enc, Aes256Dec, Aes256Enc,
};
#[cfg(openssl_available)]
use scytale_bench::openssl::OpensslAes;

/// The message sizes `openssl speed` uses for symmetric ciphers. The short
/// end measures per-call overhead, the long end the steady-state rate.
const SIZES: [usize; 6] = [16, 64, 256, 1024, 8 * 1024, 16 * 1024];

#[cfg(openssl_available)]
fn cases() -> Result<Vec<Row>, String> {
    let bad = |e| format!("OpenSSL rejected the key: {e:?}");

    // One ladder per key size and direction. Each row is scytale against
    // OpenSSL doing identical work on identically sized buffers.
    macro_rules! ladder {
        ($rows:expr, $enc:ty, $dec:ty, $bits:expr, $key_len:expr) => {{
            let key = [0x2bu8; $key_len];
            let enc = <$enc>::new(&key);
            let dec = <$dec>::new(&key);
            let openssl_enc = OpensslAes::try_new_encrypt(&key).map_err(bad)?;
            let openssl_dec = OpensslAes::try_new_decrypt(&key).map_err(bad)?;

            for bytes in SIZES {
                let mut ours = vec![0u8; bytes];
                let mut theirs = vec![0u8; bytes];
                $rows.push(compare(
                    &format!(concat!("aes", $bits, "-encrypt/{}"), bytes),
                    bytes,
                    || {
                        enc.encrypt(&mut ours);
                    },
                    || {
                        openssl_enc.encrypt(&mut theirs);
                    },
                ));
            }
            for bytes in SIZES {
                let mut ours = vec![0u8; bytes];
                let mut theirs = vec![0u8; bytes];
                $rows.push(compare(
                    &format!(concat!("aes", $bits, "-decrypt/{}"), bytes),
                    bytes,
                    || {
                        dec.decrypt(&mut ours);
                    },
                    || {
                        openssl_dec.decrypt(&mut theirs);
                    },
                ));
            }
        }};
    }

    let mut rows = Vec::with_capacity(6 * SIZES.len());
    ladder!(rows, Aes128Enc, Aes128Dec, "128", 16);
    ladder!(rows, Aes192Enc, Aes192Dec, "192", 24);
    ladder!(rows, Aes256Enc, Aes256Dec, "256", 32);
    Ok(rows)
}

#[cfg(not(openssl_available))]
fn cases() -> Result<Vec<Row>, String> {
    Err("OpenSSL was not built, so there is nothing to compare against"
        .to_string())
}

/// Report anything about the machine that would make the numbers untrustworthy.
fn describe_machine() {
    // available_parallelism reports the affinity mask, which is 1 under
    // taskset, so the machine's size is counted separately.
    let cpus = std::fs::read_dir("/sys/devices/system/cpu")
        .map(|d| {
            d.filter_map(Result::ok)
                .filter(|e| {
                    let name = e.file_name();
                    let name = name.to_string_lossy();
                    name.starts_with("cpu")
                        && name[3..].chars().all(|c| c.is_ascii_digit())
                        && name.len() > 3
                })
                .count()
        })
        .unwrap_or(0);
    let allowed = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(0);

    let governor = std::fs::read_to_string(
        "/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor",
    )
    .map(|s| s.trim().to_string())
    .unwrap_or_else(|_| "unknown".to_string());

    // no_turbo is 1 when turbo is disabled, which is the reproducible state.
    let turbo = match std::fs::read_to_string(
        "/sys/devices/system/cpu/intel_pstate/no_turbo",
    ) {
        Ok(s) if s.trim() == "1" => "off",
        Ok(_) => "on",
        Err(_) => "unknown",
    };

    // A hybrid CPU runs its cores at different clocks, so a benchmark left
    // free to migrate between them is measuring the scheduler.
    let pinned = std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("Cpus_allowed_list:"))
                .map(|l| l.split_whitespace().count() == 2
                    && !l.contains(',')
                    && !l.contains('-'))
        })
        .unwrap_or(false);

    println!(
        "{cpus} cpus, {allowed} allowed, governor {governor}, turbo {turbo}"
    );
    if !pinned {
        println!("not pinned: run under `taskset -c <cpu>` for stable ratios");
    }
    println!();
}

fn main() -> ExitCode {
    let verbose = std::env::args().any(|a| a == "--verbose" || a == "-v");

    describe_machine();

    match cases() {
        Ok(rows) => {
            if report(&rows, verbose) {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        Err(message) => {
            eprintln!("error: {message}");
            ExitCode::FAILURE
        }
    }
}
