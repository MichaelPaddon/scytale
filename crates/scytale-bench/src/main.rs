//! Compare scytale against OpenSSL, like for like.
//!
//! Exits non-zero when any case is slower, so the rule that OpenSSL must
//! never be faster is machine-checkable.

use std::process::ExitCode;

use scytale_bench::harness::{Row, compare, report};


/// The message sizes `openssl speed` uses for symmetric ciphers. The short
/// end measures per-call overhead, the long end the steady-state rate.
const SIZES: [usize; 6] = [16, 64, 256, 1024, 8 * 1024, 16 * 1024];

#[cfg(openssl_available)]
fn cases(portable: bool) -> Result<(&'static str, Vec<Row>), String> {
    use scytale::symmetric::aes::arch::portable::ttable;
    use scytale_bench::openssl::OpensslAes;

    let bad = |e| format!("OpenSSL rejected the key: {e:?}");

    // One ladder per key size and direction. Each row is scytale against
    // OpenSSL doing identical work on identically sized buffers.
    macro_rules! ladder {
        ($rows:expr, $enc:ty, $dec:ty, $oe:ty, $od:ty, $bits:expr, $len:expr)
        => {{
            let key = [0x2bu8; $len];
            let enc = <$enc>::new(&key);
            let dec = <$dec>::new(&key);
            let openssl_enc = <$oe>::try_new_encrypt(&key).map_err(bad)?;
            let openssl_dec = <$od>::try_new_decrypt(&key).map_err(bad)?;

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

    if portable {
        // Scytale's T-table cipher against OpenSSL's C AES. Both sides are
        // named explicitly: the dispatching types would pick the
        // accelerated backend and make this a different comparison.
        ladder!(rows, ttable::Aes128Enc, ttable::Aes128Dec,
                OpensslAes, OpensslAes, "128", 16);
        ladder!(rows, ttable::Aes192Enc, ttable::Aes192Dec,
                OpensslAes, OpensslAes, "192", 24);
        ladder!(rows, ttable::Aes256Enc, ttable::Aes256Dec,
                OpensslAes, OpensslAes, "256", 32);
        return Ok(("portable: T-table against OpenSSL C", rows));
    }

    accelerated(&mut rows, &bad)?;
    Ok(("accelerated: AES-NI against OpenSSL AES-NI", rows))
}

/// The accelerated ladder, on targets that have an accelerated backend.
#[cfg(all(openssl_available, target_arch = "x86_64"))]
fn accelerated(
    rows: &mut Vec<Row>,
    bad: &dyn Fn(scytale_bench::openssl::BadKeyLength) -> String,
) -> Result<(), String> {
    use scytale::symmetric::aes::arch::x86_64::aesni;
    use scytale_bench::openssl::OpensslAesni;

    if !aesni::supported() {
        return Err("this CPU has no AES instructions".to_string());
    }

    macro_rules! ladder {
        ($enc:ty, $dec:ty, $bits:expr, $len:expr) => {{
            let key = [0x2bu8; $len];
            let enc = <$enc>::new(&key);
            let dec = <$dec>::new(&key);
            let openssl_enc =
                OpensslAesni::try_new_encrypt(&key).map_err(bad)?;
            let openssl_dec =
                OpensslAesni::try_new_decrypt(&key).map_err(bad)?;

            for bytes in SIZES {
                let mut ours = vec![0u8; bytes];
                let mut theirs = vec![0u8; bytes];
                rows.push(compare(
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
                rows.push(compare(
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

    ladder!(aesni::Aes128Enc, aesni::Aes128Dec, "128", 16);
    ladder!(aesni::Aes192Enc, aesni::Aes192Dec, "192", 24);
    ladder!(aesni::Aes256Enc, aesni::Aes256Dec, "256", 32);
    Ok(())
}

#[cfg(all(openssl_available, not(target_arch = "x86_64")))]
fn accelerated(
    _rows: &mut Vec<Row>,
    _bad: &dyn Fn(scytale_bench::openssl::BadKeyLength) -> String,
) -> Result<(), String> {
    Err("no accelerated backend on this target; try --portable".to_string())
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
    let args: Vec<String> = std::env::args().collect();
    let verbose = args.iter().any(|a| a == "--verbose" || a == "-v");
    let portable = args.iter().any(|a| a == "--portable");

    describe_machine();

    match cases(portable) {
        Ok((title, rows)) => {
            println!("{title}");
            println!();
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
