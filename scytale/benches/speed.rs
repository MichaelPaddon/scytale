//! Throughput of the symmetric primitives, in the manner of
//! `openssl speed`.
//!
//! Each operation is run over a buffer of a fixed size for a fixed
//! slice of CPU time, and the count of completed operations gives a
//! rate. Six sizes are reported, from one block to sixteen kilobytes:
//! the small end shows what a call costs before any data moves, the
//! large end the steady state, and the distance between them is what
//! says whether a faster bulk path would need a short-message
//! fallback beside it.
//!
//! Every AES implementation the processor supports gets its own
//! section, named, rather than only the one `Aes::try_new` picks,
//! which is how the vector suites already treat them. The `auto`
//! section is `Aes` itself, so the cost of its dispatch shows as the
//! distance between it and the implementation it chose. The SHA-2
//! implementations are treated the same way, in sections of their
//! own after the ciphers.
//!
//! ```text
//! cargo bench --bench speed                    # everything
//! cargo bench --bench speed -- gcm aesni       # rows matching both
//! cargo bench --bench speed -- sha             # the hashes only
//! cargo bench --bench speed -- --seconds 0.25  # a quicker sweep
//! cargo bench --bench speed -- --self-test     # check the harness
//! ```
//!
//! # Reading the numbers
//!
//! Counter mode and GMAC are the two halves of GCM measured apart:
//! the keystream without the hash, and the hash without the
//! keystream. If the reciprocal of the GCM rate is close to the sum
//! of their reciprocals, the two halves are running one after the
//! other and a single loop that interleaved them would have the whole
//! of that difference to win. If GCM already beats that sum, the
//! processor is overlapping them on its own.

use std::env;
use std::fmt::Write as _;
use std::hint::black_box;
use std::process::ExitCode;
use std::time::Duration;

use cpu_time::ThreadTime;

use scytale::hash::sha2;
use scytale::hash::Hash;
use scytale::mac::hmac::Hmac;
use scytale::mac::Mac;
use scytale::symmetric::aes::portable;
use scytale::symmetric::mode::{Cbc, Ctr, Gcm, GcmSiv, Xts};
use scytale::symmetric::{aes, Block, BlockCipher};
use scytale::Error;

/// Buffer sizes reported, the ones `openssl speed` uses.
const SIZES: [usize; 6] = [16, 64, 256, 1024, 8192, 16384];

/// CPU time spent on each cell unless `--seconds` says otherwise.
const DEFAULT_BUDGET: Duration = Duration::from_millis(1000);

/// How long a calibration batch should last. Long enough that the two
/// clock reads around it are lost in the noise, short enough that
/// finding the batch size costs little.
const CALIBRATION: Duration = Duration::from_millis(10);

/// Ceiling on the calibrated batch, so that an operation too quick to
/// reach [`CALIBRATION`] cannot spin the search forever.
const MAX_BATCH: u64 = 1 << 32;

/// One operation, ready to run over a buffer.
///
/// Boxed and called through the vtable, which costs a couple of
/// nanoseconds an iteration. That is invisible at the larger sizes
/// and a few percent at sixteen bytes, and it falls on every row
/// alike, so rows stay comparable with each other.
type Operation<'a> = Box<dyn FnMut(&mut [u8]) + 'a>;

/// A named operation.
type Task<'a> = (&'static str, Operation<'a>);

fn main() -> ExitCode {
    let options = match Options::parse(env::args().skip(1)) {
        Ok(Some(options)) => options,
        Ok(None) => return ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("speed: {message}");
            return ExitCode::FAILURE;
        }
    };
    if options.self_test {
        return self_test();
    }
    // A build with debug assertions left on is not the release
    // profile that `cargo bench` uses, so any figure it produced
    // would describe the unoptimised code rather than the shipped
    // code. That is also how `cargo test --benches` arrives here, and
    // a five minute sweep is not what asking for tests means.
    if cfg!(debug_assertions) {
        println!(
            "speed: this build has debug assertions on, so any figure\n\
             would describe unoptimised code. Checking the harness\n\
             instead; `cargo bench --bench speed` measures."
        );
        return self_test();
    }
    report(&options)
}

/// What the command line asked for.
struct Options {
    /// CPU time to spend on each cell.
    budget: Duration,
    /// Words that a row's name must all contain to be run.
    filters: Vec<String>,
    /// Check the harness itself instead of benchmarking.
    self_test: bool,
}

impl Options {
    /// Parses arguments, or returns `None` when the work is done
    /// already, as it is for `--help`.
    fn parse(
        args: impl Iterator<Item = String>,
    ) -> Result<Option<Self>, String> {
        let mut options = Options {
            budget: DEFAULT_BUDGET,
            filters: Vec::new(),
            self_test: false,
        };
        let mut args = args.peekable();
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--help" | "-h" => {
                    print!("{USAGE}");
                    return Ok(None);
                }
                "--self-test" => options.self_test = true,
                "--seconds" => {
                    let value = args
                        .next()
                        .ok_or("--seconds wants a number of seconds")?;
                    let seconds: f64 = value
                        .parse()
                        .map_err(|_| format!("not a number: {value}"))?;
                    if !(seconds.is_finite() && seconds > 0.0) {
                        return Err(format!("not a duration: {value}"));
                    }
                    options.budget = Duration::from_secs_f64(seconds);
                }
                // Cargo appends this when it runs a bench target,
                // saying only that this is a benchmark run, which is
                // what the target does anyway.
                "--bench" => {}
                // Cargo appends this one instead when a bench
                // target is reached through `cargo test`.
                "--test" => options.self_test = true,
                other if other.starts_with('-') => {
                    return Err(format!("unknown option: {other}"));
                }
                other => options.filters.push(other.to_ascii_lowercase()),
            }
        }
        Ok(Some(options))
    }

    /// Whether a row belongs in this run. Every filter word must
    /// appear somewhere in the implementation or algorithm name, so
    /// `gcm aesni` narrows to one implementation's GCM rows.
    fn wants(&self, implementation: &str, algorithm: &str) -> bool {
        let name = format!("{implementation} {algorithm}");
        self.filters.iter().all(|filter| name.contains(filter))
    }
}

const USAGE: &str = "\
usage: cargo bench --bench speed -- [options] [filter...]

  --seconds N   CPU time to spend on each measurement (default 1)
  --self-test   check the harness instead of benchmarking
  --help        this text

A filter is a bare word; a row runs when its implementation and
algorithm names together contain every filter given.
";

/// Runs every implementation the processor supports.
fn report(options: &Options) -> ExitCode {
    println!(
        "Throughput in megabytes a second (10^6), by buffer size in \
         bytes.\nEach figure is CPU time on this thread, over \
         {:.3} seconds of work.",
        options.budget.as_secs_f64()
    );

    // Hardware implementations are named only on the architecture
    // that has them; each still checks the processor when its key is
    // expanded, and a section is skipped when it says no.
    let mut ran = false;
    ran |= section::<aes::Aes>("auto", options);
    #[cfg(target_arch = "x86_64")]
    {
        use scytale::symmetric::aes::x86_64;
        ran |= section::<x86_64::vaes::Aes>("vaes", options);
        ran |= section::<x86_64::aesni::Aes>("aesni", options);
    }
    #[cfg(target_arch = "aarch64")]
    {
        use scytale::symmetric::aes::aarch64;
        ran |= section::<aarch64::armv8::Aes>("armv8", options);
    }
    #[cfg(target_arch = "riscv64")]
    {
        use scytale::symmetric::aes::riscv64;
        ran |= section::<riscv64::zvkned::Aes>("zvkned", options);
        ran |= section::<riscv64::zkn::Aes>("zkn", options);
    }
    ran |= section::<portable::Aes>("ttable", options);
    ran |= section::<portable::bitsliced::Aes>("bitsliced", options);

    // The hashes, likewise. SHA-224 and SHA-384 cost the same as
    // SHA-256 and SHA-512 and are not measured separately.
    ran |= hash_section::<sha2::Sha256, sha2::Sha512>("auto", options);
    #[cfg(target_arch = "x86_64")]
    {
        ran |= hash_section::<sha2::x86_64::Sha256, sha2::portable::Sha512>(
            "shani", options,
        );
    }
    #[cfg(target_arch = "aarch64")]
    {
        ran |= hash_section::<sha2::aarch64::Sha256, sha2::aarch64::Sha512>(
            "armv8", options,
        );
    }
    #[cfg(target_arch = "riscv64")]
    {
        ran |= hash_section::<sha2::riscv64::Sha256, sha2::riscv64::Sha512>(
            "zknh", options,
        );
    }
    ran |= hash_section::<sha2::portable::Sha256, sha2::portable::Sha512>(
        "portable", options,
    );

    if !ran {
        eprintln!("speed: nothing matched");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

/// Measures one implementation, returning whether it ran anything.
///
/// An implementation the processor cannot run is left out rather than
/// reported as nothing, and so is one every filter rejected.
fn section<C: BlockCipher<Block = [u8; 16]>>(
    implementation: &str,
    options: &Options,
) -> bool {
    let wanted: Vec<&'static str> = ALGORITHMS
        .iter()
        .copied()
        .filter(|name| options.wants(implementation, name))
        .collect();
    if wanted.is_empty() {
        return false;
    }

    let mut keys = match Keys::<C>::try_new() {
        Ok(keys) => keys,
        // No such instructions here.
        Err(Error::NotSupported) => return false,
        Err(e) => {
            eprintln!("speed: {implementation}: {e}");
            return false;
        }
    };
    let mut tasks = keys.tasks();
    tasks.retain(|(name, _)| wanted.contains(name));

    println!("\n{implementation}");
    println!("{}", heading());
    for (name, operation) in &mut tasks {
        println!("{}", row(name, operation, options.budget));
    }
    true
}

/// The hash rows: each family, and HMAC over it.
const HASHES: [&str; 4] =
    ["sha-256", "sha-512", "hmac-sha-256", "hmac-sha-512"];

/// Measures one pair of hash implementations, one per family,
/// returning whether it ran anything. A family the processor cannot
/// run is left out, as with the ciphers; on x86-64 the SHA-NI
/// section pairs its SHA-256 with the portable SHA-512, there being
/// no instruction for the latter.
fn hash_section<S256, S512>(implementation: &str, options: &Options) -> bool
where
    S256: Hash<Output = [u8; 32]>,
    S512: Hash<Output = [u8; 64]>,
{
    let wanted: Vec<&'static str> = HASHES
        .iter()
        .copied()
        .filter(|name| options.wants(implementation, name))
        .collect();
    if wanted.is_empty() {
        return false;
    }
    let (mut sha256, mut sha512) = match (S256::try_new(), S512::try_new()) {
        (Ok(a), Ok(b)) => (a, b),
        (Err(Error::NotSupported), _) | (_, Err(Error::NotSupported)) => {
            return false
        }
        (Err(e), _) | (_, Err(e)) => {
            eprintln!("speed: {implementation}: {e}");
            return false;
        }
    };
    // The hashes exist, so keying cannot fail.
    let mut hmac256 = Hmac::<S256>::try_new(&KEY128).expect("hmac");
    let mut hmac512 = Hmac::<S512>::try_new(&KEY128).expect("hmac");
    let mut tasks: Vec<Task<'_>> = vec![
        (
            "sha-256",
            Box::new(|d: &mut [u8]| {
                sha256.reset();
                sha256.update(d);
                black_box(sha256.clone().finalize());
            }) as Operation<'_>,
        ),
        (
            "sha-512",
            Box::new(|d: &mut [u8]| {
                sha512.reset();
                sha512.update(d);
                black_box(sha512.clone().finalize());
            }),
        ),
        (
            "hmac-sha-256",
            Box::new(|d: &mut [u8]| {
                hmac256.reset();
                hmac256.update(d);
                black_box(hmac256.clone().finalize());
            }),
        ),
        (
            "hmac-sha-512",
            Box::new(|d: &mut [u8]| {
                hmac512.reset();
                hmac512.update(d);
                black_box(hmac512.clone().finalize());
            }),
        ),
    ];
    tasks.retain(|(name, _)| wanted.contains(name));

    println!("\n{implementation}");
    println!("{}", heading());
    for (name, operation) in &mut tasks {
        println!("{}", row(name, operation, options.budget));
    }
    true
}

/// The rows, in the order they are printed. Kept beside the tasks
/// they name so that a filter can be applied before any key is
/// expanded, which is what lets an unsupported implementation be
/// skipped silently.
const ALGORITHMS: [&str; 12] = [
    "aes-128-ecb-enc",
    "aes-128-ecb-dec",
    "aes-256-ecb-enc",
    "aes-128-cbc-enc",
    "aes-128-cbc-dec",
    "aes-128-ctr",
    "aes-128-gmac",
    "aes-128-gcm-enc",
    "aes-128-gcm-dec",
    "aes-256-gcm-enc",
    "aes-128-gcm-siv-enc",
    "aes-128-xts-enc",
];

/// Everything an implementation's rows are built from, held together
/// so that the borrows in [`Keys::tasks`] all have one owner.
struct Keys<C: BlockCipher> {
    ecb128: C,
    ecb256: C,
    cbc: Cbc<C>,
    ctr: Ctr<C>,
    gcm128: Gcm<C>,
    gcm256: Gcm<C>,
    siv: GcmSiv<C>,
    xts: Xts<C>,
    /// A tag buffer for each row that writes one; separate buffers so
    /// the rows borrow disjointly.
    tags: [[u8; 16]; 4],
}

/// Key material. Fixed rather than drawn, so that a run repeats.
const KEY128: [u8; 16] = [
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
    0xcc, 0xdd, 0xee, 0xff,
];
const KEY256: [u8; 32] = [
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
    0xcc, 0xdd, 0xee, 0xff, 0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78,
    0x87, 0x96, 0xa5, 0xb4, 0xc3, 0xd2, 0xe1, 0xf0,
];
/// XTS takes both halves at once, and they must differ.
const KEY_XTS: [u8; 32] = KEY256;
const NONCE: [u8; 12] = [0xa5; 12];
const IV: [u8; 16] = [0x5a; 16];
const TWEAK: [u8; 16] = [0x3c; 16];
/// The tag a decryption is checked against. It will not match after
/// the first iteration, which costs a comparison and changes nothing
/// else: the keystream and the hash are the same work either way, and
/// going through the streaming type rather than `Gcm::decrypt` keeps
/// the wipe on a bad tag out of the measurement.
const CHECKED_TAG: [u8; 16] = [0; 16];

impl<C: BlockCipher<Block = [u8; 16]>> Keys<C> {
    fn try_new() -> Result<Self, Error> {
        Ok(Keys {
            ecb128: C::try_new(&KEY128)?,
            ecb256: C::try_new(&KEY256)?,
            cbc: Cbc::new(C::try_new(&KEY128)?),
            ctr: Ctr::new(C::try_new(&KEY128)?),
            gcm128: Gcm::try_new(C::try_new(&KEY128)?)?,
            gcm256: Gcm::try_new(C::try_new(&KEY256)?)?,
            siv: GcmSiv::try_new(&KEY128)?,
            xts: Xts::try_new(&KEY_XTS)?,
            tags: [[0u8; 16]; 4],
        })
    }

    /// One closure per row. Results are discarded: every call here is
    /// given arguments it accepts, and a mode that started failing
    /// would show as an impossible rate rather than pass unnoticed.
    fn tasks(&mut self) -> Vec<Task<'_>> {
        let Keys {
            ecb128,
            ecb256,
            cbc,
            ctr,
            gcm128,
            gcm256,
            siv,
            xts,
            tags,
        } = self;
        // Split so that each row that writes a tag borrows its own.
        let (gmac_tag, tags) = tags.split_first_mut().expect("four tags");
        let (gcm_tag, tags) = tags.split_first_mut().expect("three tags");
        let (gcm256_tag, tags) = tags.split_first_mut().expect("two tags");
        let (siv_tag, _) = tags.split_first_mut().expect("one tag");
        vec![
            (
                "aes-128-ecb-enc",
                Box::new(|d: &mut [u8]| {
                    ecb128.encrypt_blocks(blocks_of(d));
                }) as Operation<'_>,
            ),
            (
                "aes-128-ecb-dec",
                Box::new(|d: &mut [u8]| {
                    ecb128.decrypt_blocks(blocks_of(d));
                }),
            ),
            (
                "aes-256-ecb-enc",
                Box::new(|d: &mut [u8]| {
                    ecb256.encrypt_blocks(blocks_of(d));
                }),
            ),
            (
                "aes-128-cbc-enc",
                Box::new(|d: &mut [u8]| {
                    let _ = cbc.encrypt(&IV, d);
                }),
            ),
            (
                "aes-128-cbc-dec",
                Box::new(|d: &mut [u8]| {
                    let _ = cbc.decrypt(&IV, d);
                }),
            ),
            (
                "aes-128-ctr",
                Box::new(|d: &mut [u8]| {
                    let _ = ctr.encrypt(&IV, d);
                }),
            ),
            // The buffer is the additional data and the message is
            // empty, which is GHASH and nothing else.
            (
                "aes-128-gmac",
                Box::new(|d: &mut [u8]| {
                    let _ = gcm128.encrypt(&NONCE, d, &mut [], gmac_tag);
                }),
            ),
            (
                "aes-128-gcm-enc",
                Box::new(|d: &mut [u8]| {
                    let _ = gcm128.encrypt(&NONCE, &[], d, gcm_tag);
                }),
            ),
            (
                "aes-128-gcm-dec",
                Box::new(|d: &mut [u8]| {
                    let Ok(mut state) = gcm128.decryptor(&NONCE) else {
                        return;
                    };
                    let _ = state.update(d);
                    let _ = state.verify(&CHECKED_TAG);
                }),
            ),
            (
                "aes-256-gcm-enc",
                Box::new(|d: &mut [u8]| {
                    let _ = gcm256.encrypt(&NONCE, &[], d, gcm256_tag);
                }),
            ),
            (
                "aes-128-gcm-siv-enc",
                Box::new(|d: &mut [u8]| {
                    let _ = siv.encrypt(&NONCE, &[], d, siv_tag);
                }),
            ),
            (
                "aes-128-xts-enc",
                Box::new(|d: &mut [u8]| {
                    let _ = xts.encrypt(&TWEAK, d);
                }),
            ),
        ]
    }
}

/// The whole blocks of `data`. Every size the benchmark uses is a
/// multiple of the block, so nothing is ever left over.
fn blocks_of(data: &mut [u8]) -> &mut [[u8; 16]] {
    let (blocks, rest) = <[u8; 16]>::split_mut(data);
    debug_assert!(rest.is_empty());
    blocks
}

/// The column headings, the buffer sizes.
fn heading() -> String {
    let mut line = format!("{:20}", "");
    for size in SIZES {
        let _ = write!(line, "{size:>9}");
    }
    line
}

/// One row: the name, then a rate for each size.
fn row(name: &str, operation: &mut Operation<'_>, budget: Duration) -> String {
    let mut line = format!("  {name:18}");
    for size in SIZES {
        match rate(operation, size, budget) {
            Some(bytes) => {
                let _ = write!(line, "{:>9.1}", bytes / 1e6);
            }
            // The clock refused, which is the same answer at every
            // size, so say so once per cell rather than give up.
            None => {
                let _ = write!(line, "{:>9}", "-");
            }
        }
    }
    line
}

/// Bytes a second for one operation at one size.
///
/// The clock is read once around a batch of iterations rather than
/// around each one, so its own cost is divided by the batch. The
/// batch is chosen first, by doubling until a batch lasts
/// [`CALIBRATION`], which also serves as the warm-up: by the time the
/// measurement starts the buffer is resident and the processor has
/// settled.
fn rate(
    operation: &mut Operation<'_>,
    size: usize,
    budget: Duration,
) -> Option<f64> {
    let mut buffer = pattern(size);
    let mut once = |batch: u64| -> Duration {
        time_batch(batch, &mut buffer, operation)
            .unwrap_or(Duration::from_secs(1))
    };
    let batch = calibrate(CALIBRATION, &mut once);

    let mut iterations: u64 = 0;
    let mut elapsed = Duration::ZERO;
    while elapsed < budget {
        elapsed += time_batch(batch, &mut buffer, operation)?;
        iterations = iterations.saturating_add(batch);
    }
    Some(throughput(iterations, size, elapsed))
}

/// Runs `batch` iterations and returns the CPU time they took, or
/// `None` where the clock is unavailable.
fn time_batch(
    batch: u64,
    buffer: &mut [u8],
    operation: &mut Operation<'_>,
) -> Option<Duration> {
    let start = ThreadTime::try_now().ok()?;
    for _ in 0..batch {
        // Hides the buffer from the optimiser going in and its
        // contents coming out. Without this a mode whose result is
        // discarded is dead code, and with the release profile's
        // link-time optimisation it would be removed.
        operation(black_box(buffer));
        black_box(&buffer);
    }
    start.try_elapsed().ok()
}

/// Chooses how many iterations to time at once: the smallest power of
/// two whose run reaches `target`.
///
/// Separated from the clock so it can be checked against a made-up
/// one. An operation too quick to reach the target within
/// [`MAX_BATCH`] stops there rather than doubling forever.
fn calibrate(target: Duration, mut once: impl FnMut(u64) -> Duration) -> u64 {
    let mut batch: u64 = 1;
    while batch < MAX_BATCH {
        if once(batch) >= target {
            break;
        }
        batch *= 2;
    }
    batch
}

/// Bytes a second, and zero rather than infinity where no time
/// passed, which is what a clock too coarse to see the work reports.
fn throughput(iterations: u64, size: usize, elapsed: Duration) -> f64 {
    let seconds = elapsed.as_secs_f64();
    if seconds <= 0.0 {
        return 0.0;
    }
    iterations as f64 * size as f64 / seconds
}

/// A buffer of `size` bytes, filled so that it is not all zeros.
/// Nothing measured here is data-dependent; this only keeps the
/// pages real and the contents recognisable in a debugger.
fn pattern(size: usize) -> Vec<u8> {
    (0..size).map(|i| (i % 251) as u8).collect()
}

/// Checks the parts of the harness that have an answer to be right
/// about, since a bench target with its own harness is never reached
/// by `cargo test`.
fn self_test() -> ExitCode {
    let mut failures = Vec::new();
    let mut check = |name: &str, ok: bool| {
        if !ok {
            failures.push(name.to_string());
        }
    };

    // A fast operation calibrates upwards until a batch is long
    // enough, and a slow one stays at a single iteration.
    let fast = calibrate(Duration::from_millis(10), |batch| {
        Duration::from_nanos(batch)
    });
    check("calibrate reaches the target", fast >= 10_000_000);
    check("calibrate stops at the target", fast <= 20_000_000);
    let slow =
        calibrate(Duration::from_millis(10), |_| Duration::from_millis(50));
    check("calibrate leaves a slow operation alone", slow == 1);
    // One that never gets there stops rather than doubling forever.
    let never = calibrate(Duration::from_secs(1), |_| Duration::ZERO);
    check("calibrate gives up", never == MAX_BATCH);

    // A thousand iterations of a thousand bytes in a second.
    let rate = throughput(1000, 1000, Duration::from_secs(1));
    check("throughput counts bytes", (rate - 1e6).abs() < 1.0);
    check(
        "throughput survives a stopped clock",
        throughput(1000, 1000, Duration::ZERO) == 0.0,
    );

    // Filters are conjunctive and case-insensitive.
    let options =
        Options::parse(["GCM", "aesni"].into_iter().map(String::from))
            .ok()
            .flatten()
            .expect("filters parse");
    check(
        "both filters match",
        options.wants("aesni", "aes-128-gcm-enc"),
    );
    check(
        "one filter is not enough",
        !options.wants("vaes", "aes-128-gcm-enc"),
    );
    check(
        "a filter must appear",
        !options.wants("aesni", "aes-128-ctr"),
    );

    check(
        "--seconds is rejected when it is not a duration",
        Options::parse(["--seconds", "-1"].into_iter().map(String::from))
            .is_err(),
    );

    // Every named row is built, or a filter would silently drop it.
    let mut keys = Keys::<portable::Aes>::try_new().expect("portable keys");
    let built = keys.tasks();
    check(
        "every algorithm has a task",
        built.len() == ALGORITHMS.len(),
    );
    check(
        "the tasks are the algorithms, in order",
        built.iter().map(|(name, _)| *name).eq(ALGORITHMS),
    );

    // The layout has to hold: the checks above are worthless if the
    // table is unreadable.
    check("the heading fits 80 columns", heading().len() <= 80);

    if failures.is_empty() {
        println!("speed: self-test passed");
        return ExitCode::SUCCESS;
    }
    for failure in &failures {
        eprintln!("speed: FAILED: {failure}");
    }
    ExitCode::FAILURE
}
