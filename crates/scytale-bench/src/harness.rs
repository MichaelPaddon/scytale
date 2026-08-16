//! A/B comparison timing.
//!
//! The two implementations are measured alternately inside each round rather
//! than in separate blocks, so thermal drift and turbo state affect both
//! equally instead of landing on the comparison. The reported figure is the
//! median across rounds.

use std::hint::black_box;
use std::io::Write;
use std::time::{Duration, Instant};

/// Shown against every row, and on the closing verdict.
const PASS_MARK: &str = "\u{2705}";
const FAIL_MARK: &str = "\u{274c}";

/// Rounds per case. Odd, so the median is a measured value.
const ROUNDS: usize = 21;

/// How long one measurement should take.
///
/// Long enough that each side reaches steady state before the round ends:
/// shorter windows switch between the two implementations more often, and
/// the cold instruction cache on each switch is a cost no real caller pays.
/// Measured at 2 ms the ratio drops by 0.06 for that reason alone.
const TARGET: Duration = Duration::from_millis(10);

/// One case's result.
pub struct Row {
    pub name: String,
    pub bytes: usize,
    pub scytale: Sample,
    pub openssl: Sample,
    /// Median of the per-round ratios, not the ratio of the medians.
    ///
    /// The two sides of a round are measured microseconds apart, so their
    /// ratio cancels whatever the clock was doing at that moment. Dividing
    /// two independently taken medians does not.
    ratio: f64,
}

/// The measured throughputs for one implementation, in MB/s.
pub struct Sample {
    pub median: f64,
    pub low: f64,
    pub high: f64,
}

impl Sample {
    /// Spread as a fraction of the median. A noisy machine shows up here.
    pub fn spread(&self) -> f64 {
        if self.median == 0.0 {
            return 0.0;
        }
        (self.high - self.low) / self.median
    }
}

impl Row {
    /// Above 1.0 means scytale is faster.
    pub fn ratio(&self) -> f64 {
        self.ratio
    }

    pub fn is_faster(&self) -> bool {
        self.ratio() >= 1.0
    }
}

/// Pick an iteration count that makes one measurement last about `TARGET`.
fn calibrate(f: &mut impl FnMut()) -> usize {
    let mut iters = 1usize;
    loop {
        let elapsed = time_iterations(f, iters);
        if elapsed >= TARGET {
            return iters;
        }
        // A zero reading means the timer cannot see one iteration at all.
        iters = if elapsed.is_zero() {
            iters.saturating_mul(100)
        } else {
            let scale = TARGET.as_secs_f64() / elapsed.as_secs_f64();
            (((iters as f64) * scale * 1.2).ceil() as usize).max(iters + 1)
        };
        if iters >= 1 << 30 {
            return iters;
        }
    }
}

fn time_iterations(f: &mut impl FnMut(), iters: usize) -> Duration {
    let start = Instant::now();
    for _ in 0..iters {
        f();
        black_box(());
    }
    start.elapsed()
}

fn throughput_mbps(bytes: usize, iters: usize, elapsed: Duration) -> f64 {
    let secs = elapsed.as_secs_f64();
    if secs == 0.0 {
        return 0.0;
    }
    (bytes as f64) * (iters as f64) / secs / 1e6
}

fn summarize(mut samples: Vec<f64>) -> Sample {
    samples.sort_by(f64::total_cmp);
    let median = samples.get(samples.len() / 2).copied().unwrap_or(0.0);
    Sample {
        median,
        low: samples.first().copied().unwrap_or(0.0),
        high: samples.last().copied().unwrap_or(0.0),
    }
}

/// Measure two implementations of the same work against each other.
///
/// Each closure must process exactly `bytes` bytes per call, or the
/// comparison is not like for like.
pub fn compare(
    name: &str,
    bytes: usize,
    mut scytale: impl FnMut(),
    mut openssl: impl FnMut(),
) -> Row {
    let scytale_iters = calibrate(&mut scytale);
    let openssl_iters = calibrate(&mut openssl);

    // Warm-up round, discarded: the first pass pays for cold caches and any
    // frequency ramp.
    time_iterations(&mut scytale, scytale_iters);
    time_iterations(&mut openssl, openssl_iters);

    let mut scytale_samples = Vec::with_capacity(ROUNDS);
    let mut openssl_samples = Vec::with_capacity(ROUNDS);
    let mut ratios = Vec::with_capacity(ROUNDS);
    for round in 0..ROUNDS {
        // Alternate which side goes first, so any cost of being the second
        // measurement in a round falls on both equally.
        let (a, b) = if round % 2 == 0 {
            let a = time_iterations(&mut scytale, scytale_iters);
            let b = time_iterations(&mut openssl, openssl_iters);
            (a, b)
        } else {
            let b = time_iterations(&mut openssl, openssl_iters);
            let a = time_iterations(&mut scytale, scytale_iters);
            (a, b)
        };

        let ours = throughput_mbps(bytes, scytale_iters, a);
        let theirs = throughput_mbps(bytes, openssl_iters, b);
        if theirs > 0.0 {
            ratios.push(ours / theirs);
        }
        scytale_samples.push(ours);
        openssl_samples.push(theirs);
    }

    ratios.sort_by(f64::total_cmp);
    let ratio = ratios.get(ratios.len() / 2).copied().unwrap_or(0.0);

    Row {
        name: name.to_string(),
        bytes,
        scytale: summarize(scytale_samples),
        openssl: summarize(openssl_samples),
        ratio,
    }
}

/// Print the table and return true when every case is at least at parity.
pub fn report(rows: &[Row], verbose: bool) -> bool {
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

    line!("{:<22}{:>13}{:>13}{:>9}", "", "scytale", "openssl", "ratio");
    for row in rows {
        let mark = if row.is_faster() { PASS_MARK } else { FAIL_MARK };
        line!(
            "{:<22}{:>8.0} MB/s{:>8.0} MB/s{:>9.2}  {}",
            row.name,
            row.scytale.median,
            row.openssl.median,
            row.ratio(),
            mark
        );
        if verbose {
            line!(
                "{:<22}{:>10.1}%{:>10.1}%   spread over {ROUNDS} rounds",
                "",
                row.scytale.spread() * 100.0,
                row.openssl.spread() * 100.0,
            );
        }
    }

    let slower = rows.iter().filter(|r| !r.is_faster()).count();
    let n = rows.len();
    let noun = if n == 1 { "case" } else { "cases" };
    line!("");
    if slower == 0 {
        line!("{PASS_MARK} {n} of {n} {noun} at or above parity");
        true
    } else {
        line!("{FAIL_MARK} {slower} of {n} {noun} slower than OpenSSL");
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ratio_is_scytale_over_openssl() {
        let row = Row {
            name: "x".into(),
            bytes: 16,
            scytale: Sample { median: 50.0, low: 49.0, high: 51.0 },
            openssl: Sample { median: 100.0, low: 99.0, high: 101.0 },
            ratio: 0.5,
        };
        assert!((row.ratio() - 0.5).abs() < 1e-9);
        assert!(!row.is_faster());
    }

    #[test]
    fn parity_counts_as_not_slower() {
        let row = Row {
            name: "x".into(),
            bytes: 16,
            scytale: Sample { median: 100.0, low: 100.0, high: 100.0 },
            openssl: Sample { median: 100.0, low: 100.0, high: 100.0 },
            ratio: 1.0,
        };
        assert!(row.is_faster());
    }

    #[test]
    fn median_is_the_middle_sample() {
        let s = summarize(vec![3.0, 1.0, 2.0]);
        assert_eq!(s.median, 2.0);
        assert_eq!(s.low, 1.0);
        assert_eq!(s.high, 3.0);
    }

    #[test]
    fn spread_is_relative_to_the_median() {
        let s = Sample { median: 100.0, low: 95.0, high: 105.0 };
        assert!((s.spread() - 0.1).abs() < 1e-9);
    }

    #[test]
    fn throughput_is_bytes_times_iterations_over_time() {
        let mbps = throughput_mbps(1_000_000, 2, Duration::from_secs(1));
        assert!((mbps - 2.0).abs() < 1e-9);
    }
}
