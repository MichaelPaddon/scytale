//! A/B comparison, measured in core cycles.
//!
//! The two implementations are measured alternately, sample by sample,
//! rather than in separate blocks, so anything that drifts during a run
//! lands on both equally instead of on the comparison.
//!
//! Cycles rather than wall time, because the core clock moves under a
//! frequency governor and under turbo: a stopwatch there measures the
//! machine's power state as much as the code. A cycle count does not
//! change when the clock does, so it needs neither a fixed governor nor a
//! long averaging window to be reproducible. Kernel and interrupt cycles
//! are excluded from the count, which removes the other large source of
//! movement between runs.
//!
//! The reported figure per side is the smallest sample, not the mean or
//! the median. Interference can only add cycles to a measurement, never
//! remove them, so with enough samples the smallest is the one that met
//! the least of it. The median is kept alongside it, and a gap between
//! the two is the sign of a machine that was not quiet.

use std::hint::black_box;
use std::io::Write;
use std::time::{Duration, Instant};

#[cfg(target_os = "linux")]
use crate::cycles::Cycles;

/// Shown against every row, and on the closing verdict.
const PASS_MARK: &str = "\u{2705}";
const FAIL_MARK: &str = "\u{274c}";

/// Samples taken per side, per case.
///
/// Odd, so the median is a measured value. A sample is short enough that
/// this is a few milliseconds of work in total.
const SAMPLES: usize = 201;

/// How long one sample should be, in cycles.
///
/// Long enough that reading the counter twice is lost in the noise: the
/// read pair costs tens of cycles, so a window of this size carries well
/// under a tenth of a percent of measurement in it. Short enough that a
/// timer interrupt lands in only a few samples out of the set, leaving
/// the rest clean.
const SAMPLE_CYCLES: u64 = 200_000;

/// Samples run before any are kept, to pay for cold caches and to let the
/// branch predictors settle.
const WARMUP_SAMPLES: usize = 3;

/// How much memory one side's messages are spread over.
///
/// Calls have to be independent of each other or the loop measures the
/// wait for the previous call's stores rather than the cipher: at one
/// block that wait is most of the measurement. So each call takes the
/// next message from a ring rather than rewriting one buffer.
///
/// Both sides' rings have to sit in the first level cache together, or
/// the measurement buys independence at the price of cache misses. A few
/// slots is all it takes to break the dependency: the gain is already
/// there at two, so the ring is kept short rather than large.
const WORKING_SET: usize = 8 * 1024;

/// The most messages a ring holds, whatever the message size.
const MAX_SLOTS: usize = 8;

/// A ring of separate messages of `bytes` each.
///
/// The cursor is a pointer rather than an index because the next call's
/// address must not wait on the previous call's store: a counter in
/// memory puts a store to load forward on the critical path, which at
/// one block is a quarter of what is being measured.
pub struct Messages {
    buf: Vec<u8>,
    bytes: usize,
    cursor: *mut u8,
    end: *mut u8,
}

impl Messages {
    /// A ring of `bytes` sized messages, no larger than the working set.
    pub fn new(bytes: usize) -> Self {
        let bytes = bytes.max(1);
        let slots = (WORKING_SET / bytes).clamp(1, MAX_SLOTS);
        let mut buf = vec![0u8; bytes * slots];
        let cursor = buf.as_mut_ptr();
        // SAFETY: one past the last message, which is the end of the
        // allocation and a valid pointer to compare against.
        let end = unsafe { cursor.add(bytes * slots) };
        Self { buf, bytes, cursor, end }
    }

    /// The next message, as a fixed size block.
    ///
    /// # Panics
    ///
    /// In debug builds, if the ring was not built for `N` byte messages.
    #[inline(always)]
    pub fn next_block<const N: usize>(&mut self) -> &mut [u8; N] {
        debug_assert_eq!(self.bytes, N, "ring holds a different size");
        let at = self.next();
        // SAFETY: the ring's messages are self.bytes long, which the
        // assertion above ties to N.
        unsafe { &mut *at.as_mut_ptr().cast::<[u8; N]>() }
    }

    /// The next message in the ring.
    #[inline(always)]
    pub fn next(&mut self) -> &mut [u8] {
        let at = self.cursor;
        // SAFETY: at points at a whole message inside buf, and the
        // cursor is wrapped before it can reach the end.
        unsafe {
            let after = at.add(self.bytes);
            self.cursor = if after == self.end {
                self.buf.as_mut_ptr()
            } else {
                after
            };
            std::slice::from_raw_parts_mut(at, self.bytes)
        }
    }
}

/// How a tier's ratio should be read.
pub enum Verdict {
    /// The two sides are the same kind of code, so the ratio is a parity
    /// gate and anything below 1.0 is a failure.
    Parity,
    /// The two sides are not comparable in that sense, so the ratio is
    /// reported as a speedup and gates nothing. Used where the reference
    /// has no counterpart to measure against.
    Speedup,
}

/// What the counter counts, which is not always cycles.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Unit {
    /// Core cycles, from the CPU's own counter.
    Cycles,
    /// Nanoseconds, where no cycle counter could be opened.
    Nanoseconds,
}

impl Unit {
    /// The column heading for a per byte figure.
    pub fn per_byte(self) -> &'static str {
        match self {
            Unit::Cycles => "cyc/B",
            Unit::Nanoseconds => "ns/B",
        }
    }

    /// The column heading for a per message figure.
    pub fn per_message(self) -> &'static str {
        match self {
            Unit::Cycles => "cyc/msg",
            Unit::Nanoseconds => "ns/msg",
        }
    }
}

/// One case's result.
pub struct Row {
    pub name: String,
    pub bytes: usize,
    pub left: Sample,
    pub right: Sample,
    /// The right side's cost over the left side's, so above 1.0 means the
    /// left side is the faster of the two.
    ratio: f64,
}

/// The measured cost of one call to one implementation.
pub struct Sample {
    /// The smallest sample, in units per message.
    pub best: f64,
    /// The middle sample, in units per message.
    pub median: f64,
    /// Throughput at whatever clock the run happened to see. Reported
    /// because it is the figure people have a feel for; not compared,
    /// because the clock is not held still.
    pub mbps: f64,
}

impl Sample {
    /// How far the median sits above the best, as a fraction.
    ///
    /// Zero would mean every sample was identical. A large value means
    /// the machine was busy and the median is measuring that.
    pub fn dispersion(&self) -> f64 {
        if self.best == 0.0 {
            return 0.0;
        }
        (self.median - self.best) / self.best
    }
}

impl Row {
    /// Above 1.0 means the left side is faster.
    pub fn ratio(&self) -> f64 {
        self.ratio
    }

    pub fn is_faster(&self) -> bool {
        self.ratio() >= 1.0
    }

    /// Cost per byte for the left side, in whatever unit was measured.
    pub fn left_per_byte(&self) -> f64 {
        self.left.best / self.bytes as f64
    }

    /// Cost per byte for the right side.
    pub fn right_per_byte(&self) -> f64 {
        self.right.best / self.bytes as f64
    }
}

/// The instrument, opened once and reused for every case.
pub struct Meter {
    #[cfg(target_os = "linux")]
    counter: Option<Cycles>,
    /// What two back to back reads of the counter cost, which is
    /// subtracted from every sample.
    overhead: u64,
}

impl Meter {
    /// Open the best instrument this machine offers.
    pub fn new() -> Self {
        #[cfg(target_os = "linux")]
        {
            let counter = Cycles::try_new();
            let overhead = match &counter {
                Some(c) => read_overhead(c),
                None => 0,
            };
            Self { counter, overhead }
        }
        #[cfg(not(target_os = "linux"))]
        Self { overhead: 0 }
    }

    /// What this meter counts.
    pub fn unit(&self) -> Unit {
        #[cfg(target_os = "linux")]
        if self.counter.is_some() {
            return Unit::Cycles;
        }
        Unit::Nanoseconds
    }

    /// How the measurement is being taken, for the run's header.
    pub fn describe(&self) -> &'static str {
        #[cfg(target_os = "linux")]
        if let Some(counter) = &self.counter {
            return if counter.is_direct() {
                "core cycles, read with rdpmc"
            } else {
                "core cycles, read through the kernel"
            };
        }
        "wall clock: no cycle counter, so the ratios move with the clock"
    }

    /// The cost of running `f` once, in this meter's unit.
    ///
    /// Returns the raw reading for `iters` calls, with the cost of taking
    /// the measurement itself already removed.
    #[inline]
    fn sample(&self, f: &mut impl FnMut(), iters: usize) -> u64 {
        #[cfg(target_os = "linux")]
        if let Some(counter) = &self.counter {
            let before = counter.read().unwrap_or(0);
            for _ in 0..iters {
                f();
                black_box(());
            }
            let after = counter.read().unwrap_or(0);
            return after.saturating_sub(before).saturating_sub(self.overhead);
        }

        let start = Instant::now();
        for _ in 0..iters {
            f();
            black_box(());
        }
        start.elapsed().as_nanos() as u64
    }

    /// How many calls make one sample last about [`SAMPLE_CYCLES`].
    fn calibrate(&self, f: &mut impl FnMut()) -> usize {
        let mut iters = 1usize;
        loop {
            let cost = self.sample(f, iters);
            if cost >= SAMPLE_CYCLES {
                return iters;
            }
            // A zero reading means one pass is below the counter's
            // resolution, so there is nothing to scale from yet.
            iters = if cost == 0 {
                iters.saturating_mul(64)
            } else {
                let scale = SAMPLE_CYCLES as f64 / cost as f64;
                (((iters as f64) * scale * 1.1).ceil() as usize)
                    .max(iters + 1)
            };
            if iters >= 1 << 28 {
                return iters;
            }
        }
    }
}

impl Default for Meter {
    fn default() -> Self {
        Self::new()
    }
}

/// What a pair of counter reads costs with nothing between them.
#[cfg(target_os = "linux")]
fn read_overhead(counter: &Cycles) -> u64 {
    let mut best = u64::MAX;
    for _ in 0..1000 {
        let a = counter.read().unwrap_or(0);
        let b = counter.read().unwrap_or(0);
        best = best.min(b.saturating_sub(a));
    }
    if best == u64::MAX { 0 } else { best }
}

fn summarize(mut samples: Vec<f64>, bytes: usize, wall: Duration) -> Sample {
    samples.sort_by(f64::total_cmp);
    let best = samples.first().copied().unwrap_or(0.0);
    let median = samples.get(samples.len() / 2).copied().unwrap_or(0.0);
    let calls = samples.len() as f64;
    let secs = wall.as_secs_f64();
    let mbps = if secs > 0.0 {
        (bytes as f64) * calls / secs / 1e6
    } else {
        0.0
    };
    Sample { best, median, mbps }
}

/// Measure two implementations of the same work against each other.
///
/// Each closure must process exactly `bytes` bytes per call, or the
/// comparison is not like for like.
pub fn compare(
    meter: &Meter,
    name: &str,
    bytes: usize,
    mut left: impl FnMut(),
    mut right: impl FnMut(),
) -> Row {
    let left_iters = meter.calibrate(&mut left);
    let right_iters = meter.calibrate(&mut right);

    for _ in 0..WARMUP_SAMPLES {
        meter.sample(&mut left, left_iters);
        meter.sample(&mut right, right_iters);
    }

    let mut left_samples = Vec::with_capacity(SAMPLES);
    let mut right_samples = Vec::with_capacity(SAMPLES);
    let mut left_wall = Duration::ZERO;
    let mut right_wall = Duration::ZERO;

    for i in 0..SAMPLES {
        // Alternate which side goes first, so whatever it costs to be the
        // second measurement in a pair falls on both equally.
        if i % 2 == 0 {
            left_wall += timed(meter, &mut left, left_iters, &mut left_samples);
            right_wall +=
                timed(meter, &mut right, right_iters, &mut right_samples);
        } else {
            right_wall +=
                timed(meter, &mut right, right_iters, &mut right_samples);
            left_wall += timed(meter, &mut left, left_iters, &mut left_samples);
        }
    }

    let left = summarize(left_samples, bytes * left_iters, left_wall);
    let right = summarize(right_samples, bytes * right_iters, right_wall);
    // Cost per message, so the cheaper side is the faster one and the
    // ratio has to be the right side's cost over the left side's.
    let ratio = if left.best > 0.0 { right.best / left.best } else { 0.0 };

    Row { name: name.to_string(), bytes, left, right, ratio }
}

/// Take one sample, recording its cost per call and the time it took.
fn timed(
    meter: &Meter,
    f: &mut impl FnMut(),
    iters: usize,
    into: &mut Vec<f64>,
) -> Duration {
    let start = Instant::now();
    let cost = meter.sample(f, iters);
    let elapsed = start.elapsed();
    into.push(cost as f64 / iters as f64);
    elapsed
}

/// Print the table and return true when every case is at least at parity.
pub fn report(
    rows: &[Row],
    unit: Unit,
    left: &str,
    right: &str,
    verdict: &Verdict,
    verbose: bool,
) -> bool {
    // Written rather than printed: a closed pipe, from `| head` or similar,
    // should end the output rather than panic.
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    macro_rules! line {
        ($($arg:tt)*) => {
            if writeln!(out, $($arg)*).is_err() {
                return rows.iter().all(Row::is_faster);
            }
        };
    }

    line!("{:<22}{:>18}{:>18}{:>9}", "", left, right, "");
    line!(
        "{:<22}{:>9}{:>9}{:>9}{:>9}{:>9}",
        "",
        unit.per_byte(),
        "MB/s",
        unit.per_byte(),
        "MB/s",
        "ratio"
    );
    for row in rows {
        let mark = match verdict {
            Verdict::Speedup => "",
            _ if row.is_faster() => PASS_MARK,
            _ => FAIL_MARK,
        };
        line!(
            "{:<22}{:>9.4}{:>9.0}{:>9.4}{:>9.0}{:>9.3}  {}",
            row.name,
            row.left_per_byte(),
            row.left.mbps,
            row.right_per_byte(),
            row.right.mbps,
            row.ratio(),
            mark
        );
        if verbose {
            line!(
                "{:<22}{:>9.1}{:>9}{:>9.1}{:>9}   {} best, \
                 median +{:.1}%/+{:.1}%",
                "",
                row.left.best,
                "",
                row.right.best,
                "",
                unit.per_message(),
                row.left.dispersion() * 100.0,
                row.right.dispersion() * 100.0,
            );
        }
    }

    let n = rows.len();
    let noun = if n == 1 { "case" } else { "cases" };
    line!("");
    if let Verdict::Speedup = verdict {
        let ratios: Vec<f64> = rows.iter().map(Row::ratio).collect();
        let (lo, hi) = ratios.iter().fold((f64::MAX, 0.0f64), |(l, h), &r| {
            (l.min(r), h.max(r))
        });
        line!("{n} {noun}, {lo:.2}x to {hi:.2}x; no parity gate here");
        return true;
    }

    let slower = rows.iter().filter(|r| !r.is_faster()).count();
    if slower == 0 {
        line!("{PASS_MARK} {n} of {n} {noun} at or above parity");
        true
    } else {
        line!("{FAIL_MARK} {slower} of {n} {noun} slower than {right}");
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(left: f64, right: f64) -> Row {
        Row {
            name: "x".into(),
            bytes: 16,
            left: Sample { best: left, median: left, mbps: 0.0 },
            right: Sample { best: right, median: right, mbps: 0.0 },
            ratio: right / left,
        }
    }

    #[test]
    fn cheaper_left_side_is_faster() {
        let row = row(50.0, 100.0);
        assert!((row.ratio() - 2.0).abs() < 1e-9);
        assert!(row.is_faster());
    }

    #[test]
    fn dearer_left_side_is_slower() {
        let row = row(100.0, 50.0);
        assert!(!row.is_faster());
    }

    #[test]
    fn parity_counts_as_not_slower() {
        assert!(row(100.0, 100.0).is_faster());
    }

    #[test]
    fn per_byte_divides_by_the_message() {
        let row = row(32.0, 64.0);
        assert!((row.left_per_byte() - 2.0).abs() < 1e-9);
        assert!((row.right_per_byte() - 4.0).abs() < 1e-9);
    }

    #[test]
    fn best_is_the_smallest_sample_and_median_the_middle() {
        let s = summarize(vec![3.0, 1.0, 2.0], 16, Duration::from_secs(1));
        assert_eq!(s.best, 1.0);
        assert_eq!(s.median, 2.0);
        // Three calls of sixteen bytes in a second.
        assert!((s.mbps - 48e-6).abs() < 1e-9);
    }

    #[test]
    fn dispersion_is_the_median_above_the_best() {
        let s = Sample { best: 100.0, median: 110.0, mbps: 0.0 };
        assert!((s.dispersion() - 0.1).abs() < 1e-9);
    }

    /// The meter has to agree with a known amount of work. A loop of
    /// dependent integer operations cannot retire faster than one per
    /// cycle, and will not be far above that.
    #[test]
    fn meter_measures_something_plausible() {
        let meter = Meter::new();
        if meter.unit() != Unit::Cycles {
            return;
        }
        let mut sink = 0u64;
        let mut work = || {
            for _ in 0..1000 {
                sink = black_box(sink).wrapping_mul(6364136223846793005);
            }
        };
        let iters = meter.calibrate(&mut work);
        let cost = meter.sample(&mut work, iters) as f64 / iters as f64;
        let per_op = cost / 1000.0;
        assert!(
            (1.0..20.0).contains(&per_op),
            "a dependent multiply measured {per_op} cycles"
        );
    }
}
