//! Compare scytale against OpenSSL, like for like.
//!
//! Exits non-zero when any case is slower, so the rule that OpenSSL must
//! never be faster is machine-checkable.

use std::process::ExitCode;

use scytale_bench::harness::{
    Messages, Meter, Row, Verdict, compare, report,
};


/// The message sizes `openssl speed` uses for symmetric ciphers. The short
/// end measures per-call overhead, the long end the steady-state rate.
const BLOCK: usize = 16;

const SIZES: [usize; 6] = [16, 64, 256, 1024, 8 * 1024, 16 * 1024];

type Tier = (&'static str, &'static str, &'static str, Verdict, Vec<Row>);

#[cfg(openssl_available)]
fn cases(meter: &Meter, tier: &str) -> Result<Tier, String> {
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
                let mut ours = Messages::new(bytes);
                let mut theirs = Messages::new(bytes);
                $rows.push(compare(
                    meter,
                    &format!(concat!("aes", $bits, "-encrypt/{}"), bytes),
                    bytes,
                    || {
                        enc.encrypt(ours.next());
                    },
                    || {
                        openssl_enc.encrypt(theirs.next());
                    },
                ));
            }
            for bytes in SIZES {
                let mut ours = Messages::new(bytes);
                let mut theirs = Messages::new(bytes);
                $rows.push(compare(
                    meter,
                    &format!(concat!("aes", $bits, "-decrypt/{}"), bytes),
                    bytes,
                    || {
                        dec.decrypt(ours.next());
                    },
                    || {
                        openssl_dec.decrypt(theirs.next());
                    },
                ));
            }
        }};
    }

    let mut rows = Vec::with_capacity(6 * SIZES.len());

    // CTR against OpenSSL's generic CTR over the same scalar cipher:
    // the same shape of work, a mode loop driving a block function, with
    // the same streaming state carried between calls.
    macro_rules! ctr_ladder {
        ($rows:expr, $enc:ty, $bits:expr, $len:expr) => {{
            use scytale::symmetric::Ctr;
            use scytale_bench::openssl::OpensslCtr;

            let key = [0x2bu8; $len];
            let iv = [0u8; 16];
            for bytes in SIZES {
                let mut ours = Messages::new(bytes);
                let mut theirs = Messages::new(bytes);
                let mut ctr = Ctr::try_new(<$enc>::new(&key), &iv)
                    .map_err(|e| format!("IV rejected: {e}"))?;
                let mut openssl =
                    OpensslCtr::try_new(&key, &iv).map_err(bad)?;
                $rows.push(compare(
                    meter,
                    &format!(concat!("aes", $bits, "-ctr/{}"), bytes),
                    bytes,
                    || {
                        ctr.apply_keystream(ours.next());
                    },
                    || {
                        openssl.apply_keystream(theirs.next());
                    },
                ));
            }
        }};
    }

    if tier == "portable" {
        // Scytale's T-table cipher against OpenSSL's C AES. Both sides are
        // named explicitly: the dispatching types would pick the
        // accelerated backend and make this a different comparison.
        ladder!(rows, ttable::Aes128Enc, ttable::Aes128Dec,
                OpensslAes, OpensslAes, "128", 16);
        ladder!(rows, ttable::Aes192Enc, ttable::Aes192Dec,
                OpensslAes, OpensslAes, "192", 24);
        ladder!(rows, ttable::Aes256Enc, ttable::Aes256Dec,
                OpensslAes, OpensslAes, "256", 32);
        ctr_ladder!(rows, ttable::Aes128Enc, "128", 16);
        ctr_ladder!(rows, ttable::Aes192Enc, "192", 24);
        ctr_ladder!(rows, ttable::Aes256Enc, "256", 32);
        return Ok((
            "portable: scytale T-table against OpenSSL C",
            "scytale",
            "openssl",
            Verdict::Parity,
            rows,
        ));
    }

    if tier == "vector" {
        vector(meter, &mut rows)?;
        return Ok((
            "vector: scytale VAES against scytale AES-NI \n\
             (OpenSSL has no VAES kernel for ECB, so there is nothing of \
             the same kind to compare against)",
            "VAES",
            "AES-NI",
            Verdict::Speedup,
            rows,
        ));
    }

    accelerated(meter, &mut rows, &bad)?;
    Ok((
        "accelerated: scytale AES-NI against OpenSSL AES-NI",
        "scytale",
        "openssl",
        Verdict::Parity,
        rows,
    ))
}

/// The accelerated ladder, on targets that have an accelerated backend.
#[cfg(all(openssl_available, target_arch = "x86_64"))]
fn accelerated(
    meter: &Meter,
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
                let mut ours = Messages::new(bytes);
                let mut theirs = Messages::new(bytes);
                let name =
                    format!(concat!("aes", $bits, "-encrypt/{}"), bytes);
                // One block goes through each side's single block entry.
                // Through the bulk entry it would be measuring OpenSSL's
                // length dispatch against our own, which is a comparison
                // of interfaces rather than of ciphers.
                if bytes == BLOCK {
                    rows.push(compare(
                        meter,
                        &name,
                        bytes,
                        || {
                            enc.encrypt_block(ours.next_block());
                        },
                        || {
                            openssl_enc.encrypt_block(theirs.next_block());
                        },
                    ));
                } else {
                    rows.push(compare(
                        meter,
                        &name,
                        bytes,
                        || {
                            enc.encrypt(ours.next());
                        },
                        || {
                            openssl_enc.encrypt(theirs.next());
                        },
                    ));
                }
            }
            for bytes in SIZES {
                let mut ours = Messages::new(bytes);
                let mut theirs = Messages::new(bytes);
                let name =
                    format!(concat!("aes", $bits, "-decrypt/{}"), bytes);
                // One block goes through each side's single block entry.
                // Through the bulk entry it would be measuring OpenSSL's
                // length dispatch against our own, which is a comparison
                // of interfaces rather than of ciphers.
                if bytes == BLOCK {
                    rows.push(compare(
                        meter,
                        &name,
                        bytes,
                        || {
                            dec.decrypt_block(ours.next_block());
                        },
                        || {
                            openssl_dec.decrypt_block(theirs.next_block());
                        },
                    ));
                } else {
                    rows.push(compare(
                        meter,
                        &name,
                        bytes,
                        || {
                            dec.decrypt(ours.next());
                        },
                        || {
                            openssl_dec.decrypt(theirs.next());
                        },
                    ));
                }
            }
        }};
    }

    ladder!(aesni::Aes128Enc, aesni::Aes128Dec, "128", 16);
    ladder!(aesni::Aes192Enc, aesni::Aes192Dec, "192", 24);
    ladder!(aesni::Aes256Enc, aesni::Aes256Dec, "256", 32);
    Ok(())
}

/// VAES against AES-NI, both ours.
#[cfg(all(openssl_available, target_arch = "x86_64"))]
fn vector(meter: &Meter, rows: &mut Vec<Row>) -> Result<(), String> {
    use scytale::symmetric::aes::arch::x86_64::{aesni, vaes};

    if !vaes::supported() {
        return Err("this CPU has no VAES".to_string());
    }

    macro_rules! ladder {
        ($v:ty, $a:ty, $bits:expr, $len:expr, $op:ident) => {{
            let key = [0x2bu8; $len];
            let wide = <$v>::new(&key);
            let narrow = <$a>::new(&key);
            for bytes in SIZES {
                let mut ours = Messages::new(bytes);
                let mut theirs = Messages::new(bytes);
                rows.push(compare(
                    meter,
                    &format!(
                        concat!("aes", $bits, "-", stringify!($op), "/{}"),
                        bytes
                    ),
                    bytes,
                    || {
                        wide.$op(ours.next());
                    },
                    || {
                        narrow.$op(theirs.next());
                    },
                ));
            }
        }};
    }

    ladder!(vaes::Aes128Enc, aesni::Aes128Enc, "128", 16, encrypt);
    ladder!(vaes::Aes128Dec, aesni::Aes128Dec, "128", 16, decrypt);
    ladder!(vaes::Aes192Enc, aesni::Aes192Enc, "192", 24, encrypt);
    ladder!(vaes::Aes192Dec, aesni::Aes192Dec, "192", 24, decrypt);
    ladder!(vaes::Aes256Enc, aesni::Aes256Enc, "256", 32, encrypt);
    ladder!(vaes::Aes256Dec, aesni::Aes256Dec, "256", 32, decrypt);
    Ok(())
}

#[cfg(all(openssl_available, not(target_arch = "x86_64")))]
fn vector(
    _meter: &Meter,
    _rows: &mut Vec<Row>,
) -> Result<(), String> {
    Err("no vector backend on this target".to_string())
}

#[cfg(all(openssl_available, not(target_arch = "x86_64")))]
fn accelerated(
    _meter: &Meter,
    _rows: &mut Vec<Row>,
    _bad: &dyn Fn(scytale_bench::openssl::BadKeyLength) -> String,
) -> Result<(), String> {
    Err("no accelerated backend on this target; try --portable".to_string())
}

/// Report anything about the machine that would make the numbers untrustworthy.
fn describe_machine(meter: &Meter) {
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
    println!("measuring {}", meter.describe());
    if !pinned {
        println!("not pinned: run under `taskset -c <cpu>` for stable ratios");
    }
    if randomized_layout() {
        println!(
            "layout randomized: run under `setarch -R` so the addresses \
             are the same every time"
        );
    }
    if let Some(sibling) = busy_sibling() {
        println!(
            "cpu{sibling} shares this core: work there spends our cycles too"
        );
    }
    println!();
}

/// Whether this process got a randomized address space.
///
/// Where the buffers and key schedules land decides which of them share
/// cache sets and which alias each other, and randomizing that changes
/// the answer by a couple of percent from one run to the next. It is the
/// largest remaining source of movement once the clock is out of the
/// measurement.
fn randomized_layout() -> bool {
    /// `ADDR_NO_RANDOMIZE`, which `setarch -R` sets.
    const ADDR_NO_RANDOMIZE: u64 = 0x0004_0000;

    std::fs::read_to_string("/proc/self/personality")
        .ok()
        .and_then(|s| u64::from_str_radix(s.trim(), 16).ok())
        .map(|p| p & ADDR_NO_RANDOMIZE == 0)
        .unwrap_or(false)
}

/// The other thread of the core we are pinned to, if it is online.
///
/// Two threads of one core share its execution units, so anything running
/// on the sibling is charged to our cycle count as contention. This does
/// not say the sibling is busy, only that it could be.
fn busy_sibling() -> Option<usize> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let line = status
        .lines()
        .find(|l| l.starts_with("Cpus_allowed_list:"))?;
    let cpu: usize = line.split_whitespace().nth(1)?.parse().ok()?;

    let path = format!(
        "/sys/devices/system/cpu/cpu{cpu}/topology/thread_siblings_list"
    );
    let siblings = std::fs::read_to_string(path).ok()?;
    siblings
        .trim()
        .split([',', '-'])
        .filter_map(|s| s.parse::<usize>().ok())
        .find(|&s| s != cpu)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let verbose = args.iter().any(|a| a == "--verbose" || a == "-v");
    let tier = if args.iter().any(|a| a == "--portable") {
        "portable"
    } else if args.iter().any(|a| a == "--vector") {
        "vector"
    } else {
        "accelerated"
    };

    let meter = Meter::new();
    describe_machine(&meter);

    match cases(&meter, tier) {
        Ok((title, left, right, verdict, rows)) => {
            println!("{title}");
            println!();
            if report(&rows, meter.unit(), left, right, &verdict, verbose)
            {
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
