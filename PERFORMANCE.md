# Performance

Scytale is measured against OpenSSL, on the same machine, in the same
process, in the same measurement loop.

## The rule

**A ratio is only printed when both sides are the same kind of code.**

Not merely the same algorithm at the same size, but the same kind of
implementation. Every unfair comparison flatters one side, and every one of
them reads as a meaningful number to somebody who does not know how it was
produced.

Scytale has two AES implementations, so OpenSSL is built twice and each is
measured against its own counterpart:

| Tier | scytale | OpenSSL |
| --- | --- | --- |
| accelerated | AES-NI | AES-NI, from a default build |
| portable | T-table | C, from a `no-asm` build |

Neither pairing is arbitrary. Putting our AES-NI against OpenSSL's C would
flatter us by five to ten times on hardware grounds alone; putting our
T-table against its AES-NI would do the reverse. The accelerated tier also
avoids OpenSSL's `AES_encrypt`, which in an assembly build is its assembly
T-table rather than its AES-NI, and avoids EVP, which would add dispatch and
context handling to the measurement.

The corollary: **if OpenSSL is ever faster, work stops until it is not.**
The benchmark exits non-zero when any row falls below parity, so this is
machine checkable rather than a matter of reading the table carefully.

## Method

- The tool links libcrypto directly and drives both implementations through
  one measurement loop, with the same buffers and the same timer.
- Message sizes are 16, 64, 256, 1024, 8192 and 16384 bytes.
- Each case runs 21 rounds after a discarded warm up. A round times each
  implementation for about 10 ms, and which one goes first alternates so
  neither systematically gets the better half of a round.
- The reported ratio is the median of the per round ratios, not the ratio of
  the two medians. The two sides of a round are measured milliseconds apart,
  so dividing them cancels whatever the clock was doing at that moment.
- The 10 ms window is deliberate. Switching between implementations more
  often makes each pay a cold instruction cache over less work, which is a
  cost no real caller meets; at 2 ms the ratio falls by 0.06 for that reason
  alone.
- Run pinned to one core. On a hybrid CPU the performance and efficiency
  cores run at different clocks, so an unpinned benchmark is partly
  measuring the scheduler. The tool warns when it is not pinned.
- Correctness gates the timing. The agreement tests require byte identical
  output from scytale and from both OpenSSL builds, across all three key
  sizes, both directions, and buffer lengths from 1 to 64 blocks.
- Both sides are driven through the same in place bulk signature, so neither
  pays for a wrapper the other does not.

## Reproducing

```
cargo build -p scytale-bench --release
taskset -c 2 target/release/scytale-bench             # accelerated
taskset -c 2 target/release/scytale-bench --portable  # portable
```

Pick a core of a single type; on a hybrid CPU
`/sys/devices/system/cpu/cpu*/cpufreq/cpuinfo_max_freq` distinguishes them.
Running without `taskset` still works and still reports, but the ratios move
about three times as much between runs.

The build script clones and builds both reference OpenSSL configurations; it
never vendors them. The first run therefore takes several minutes, and later
runs reuse the built libraries.

## Results

Measured on a 13th Gen Intel Core i7-1355U pinned to one performance core,
`x86_64-unknown-linux-gnu`, rustc 1.97.1, against OpenSSL 4.0.1. Each figure
is the median of four runs of the tool, each of which is itself a median
over 21 interleaved rounds.

Absolute throughput here is lower than the same code reaches unpinned,
because a pinned core does not get the scheduler's pick of clock speed. The
ratio is unaffected, which is the point of reporting one.

### Accelerated: AES-NI against OpenSSL AES-NI

This is what runs on any x86_64 CPU with the AES instructions, which is
almost all of them made since 2010. Selection is at run time, so a binary
built for a baseline target still uses them when it lands on such a CPU.


| Algorithm | Bytes | scytale MB/s | OpenSSL MB/s | Ratio | |
| --- | ---: | ---: | ---: | ---: | :---: |
| AES-128-ECB encrypt | 16 | 2146 | 2130 | 1.01 | ✅ |
| AES-128-ECB encrypt | 64 | 7974 | 7782 | 1.03 | ✅ |
| AES-128-ECB encrypt | 256 | 15058 | 14713 | 1.02 | ✅ |
| AES-128-ECB encrypt | 1024 | 15306 | 14842 | 1.03 | ✅ |
| AES-128-ECB encrypt | 8192 | 15425 | 15157 | 1.02 | ✅ |
| AES-128-ECB encrypt | 16384 | 15457 | 15258 | 1.01 | ✅ |
| AES-128-ECB decrypt | 16 | 2138 | 2114 | 1.01 | ✅ |
| AES-128-ECB decrypt | 64 | 8016 | 7994 | 1.00 | ✅ |
| AES-128-ECB decrypt | 256 | 15020 | 14579 | 1.03 | ✅ |
| AES-128-ECB decrypt | 1024 | 15242 | 14941 | 1.02 | ✅ |
| AES-128-ECB decrypt | 8192 | 15182 | 14964 | 1.02 | ✅ |
| AES-128-ECB decrypt | 16384 | 15387 | 15080 | 1.02 | ✅ |
| AES-192-ECB encrypt | 16 | 1845 | 1832 | 1.00 | ✅ |
| AES-192-ECB encrypt | 64 | 6956 | 6655 | 1.04 | ✅ |
| AES-192-ECB encrypt | 256 | 12607 | 12321 | 1.02 | ✅ |
| AES-192-ECB encrypt | 1024 | 12666 | 12496 | 1.02 | ✅ |
| AES-192-ECB encrypt | 8192 | 12712 | 12524 | 1.02 | ✅ |
| AES-192-ECB encrypt | 16384 | 12740 | 12528 | 1.01 | ✅ |
| AES-192-ECB decrypt | 16 | 1842 | 1828 | 1.01 | ✅ |
| AES-192-ECB decrypt | 64 | 6926 | 6822 | 1.01 | ✅ |
| AES-192-ECB decrypt | 256 | 12575 | 12282 | 1.03 | ✅ |
| AES-192-ECB decrypt | 1024 | 12708 | 12446 | 1.02 | ✅ |
| AES-192-ECB decrypt | 8192 | 12677 | 12492 | 1.02 | ✅ |
| AES-192-ECB decrypt | 16384 | 12700 | 12434 | 1.02 | ✅ |
| AES-256-ECB encrypt | 16 | 1618 | 1602 | 1.01 | ✅ |
| AES-256-ECB encrypt | 64 | 6124 | 5930 | 1.04 | ✅ |
| AES-256-ECB encrypt | 256 | 10824 | 10628 | 1.02 | ✅ |
| AES-256-ECB encrypt | 1024 | 10892 | 10732 | 1.02 | ✅ |
| AES-256-ECB encrypt | 8192 | 10874 | 10664 | 1.02 | ✅ |
| AES-256-ECB encrypt | 16384 | 10872 | 10715 | 1.02 | ✅ |
| AES-256-ECB decrypt | 16 | 1615 | 1584 | 1.01 | ✅ |
| AES-256-ECB decrypt | 64 | 6078 | 6068 | 1.00 | ✅ |
| AES-256-ECB decrypt | 256 | 10802 | 10503 | 1.03 | ✅ |
| AES-256-ECB decrypt | 1024 | 10866 | 10666 | 1.02 | ✅ |
| AES-256-ECB decrypt | 8192 | 10919 | 10692 | 1.02 | ✅ |
| AES-256-ECB decrypt | 16384 | 10896 | 10670 | 1.02 | ✅ |

### Portable: T-table against OpenSSL C

This is what runs where the instructions are absent.


| Algorithm | Bytes | scytale MB/s | OpenSSL MB/s | Ratio | |
| --- | ---: | ---: | ---: | ---: | :---: |
| AES-128-ECB encrypt | 16 | 474 | 410 | 1.15 | ✅ |
| AES-128-ECB encrypt | 64 | 540 | 478 | 1.13 | ✅ |
| AES-128-ECB encrypt | 256 | 544 | 480 | 1.14 | ✅ |
| AES-128-ECB encrypt | 1024 | 544 | 478 | 1.14 | ✅ |
| AES-128-ECB encrypt | 8192 | 543 | 480 | 1.13 | ✅ |
| AES-128-ECB encrypt | 16384 | 544 | 480 | 1.13 | ✅ |
| AES-128-ECB decrypt | 16 | 469 | 418 | 1.12 | ✅ |
| AES-128-ECB decrypt | 64 | 537 | 492 | 1.09 | ✅ |
| AES-128-ECB decrypt | 256 | 544 | 494 | 1.10 | ✅ |
| AES-128-ECB decrypt | 1024 | 541 | 494 | 1.10 | ✅ |
| AES-128-ECB decrypt | 8192 | 540 | 496 | 1.10 | ✅ |
| AES-128-ECB decrypt | 16384 | 542 | 496 | 1.10 | ✅ |
| AES-192-ECB encrypt | 16 | 403 | 352 | 1.14 | ✅ |
| AES-192-ECB encrypt | 64 | 446 | 400 | 1.12 | ✅ |
| AES-192-ECB encrypt | 256 | 448 | 403 | 1.12 | ✅ |
| AES-192-ECB encrypt | 1024 | 450 | 403 | 1.12 | ✅ |
| AES-192-ECB encrypt | 8192 | 450 | 404 | 1.11 | ✅ |
| AES-192-ECB encrypt | 16384 | 451 | 404 | 1.12 | ✅ |
| AES-192-ECB decrypt | 16 | 398 | 360 | 1.10 | ✅ |
| AES-192-ECB decrypt | 64 | 446 | 414 | 1.08 | ✅ |
| AES-192-ECB decrypt | 256 | 448 | 415 | 1.08 | ✅ |
| AES-192-ECB decrypt | 1024 | 449 | 414 | 1.08 | ✅ |
| AES-192-ECB decrypt | 8192 | 451 | 416 | 1.08 | ✅ |
| AES-192-ECB decrypt | 16384 | 450 | 414 | 1.09 | ✅ |
| AES-256-ECB encrypt | 16 | 350 | 310 | 1.13 | ✅ |
| AES-256-ECB encrypt | 64 | 383 | 346 | 1.11 | ✅ |
| AES-256-ECB encrypt | 256 | 385 | 348 | 1.11 | ✅ |
| AES-256-ECB encrypt | 1024 | 385 | 346 | 1.11 | ✅ |
| AES-256-ECB encrypt | 8192 | 386 | 347 | 1.11 | ✅ |
| AES-256-ECB encrypt | 16384 | 386 | 348 | 1.11 | ✅ |
| AES-256-ECB decrypt | 16 | 347 | 316 | 1.10 | ✅ |
| AES-256-ECB decrypt | 64 | 382 | 356 | 1.07 | ✅ |
| AES-256-ECB decrypt | 256 | 384 | 358 | 1.07 | ✅ |
| AES-256-ECB decrypt | 1024 | 384 | 357 | 1.08 | ✅ |
| AES-256-ECB decrypt | 8192 | 384 | 358 | 1.07 | ✅ |
| AES-256-ECB decrypt | 16384 | 386 | 358 | 1.08 | ✅ |

✅ at or above parity with OpenSSL, ❌ below it.

## Reading the tables

**Acceleration is worth about 26 times the portable cipher**, 15.4 GB/s
against 544 MB/s for AES-128. That gap, not the ratios, is the reason the
accelerated backend exists.

**The accelerated lead is 1.00 to 1.04**, and the portable one 1.07 to 1.15.
The portable margin is larger because there is more room to differ in
software; two implementations of the same handful of instructions have
almost nowhere left to go, and a couple of points there is close to the
measurement floor.

**Both leads are flat across key sizes.** AES-192 and AES-256 run more of
the same rounds, so a per round gain shows up unchanged as a ratio.

**The 16 byte row is the odd one.** At one block there is nothing to
amortise a call over, so it mostly measures per call overhead. In the
accelerated tier a single block cannot fill the pipeline either, which is
why 2.1 GB/s is so far below the 15.4 GB/s the same code reaches at 256
bytes.

## Caveats

**The floor on what this can resolve is about 1%.** Across four pinned runs
of an unchanged binary, rows move by roughly that much, so a change
measuring under a point has not been shown to do anything. Unpinned that
figure is about three times larger. Going below a point would need the
`performance` governor and turbo disabled as well, neither of which the tool
can arrange for itself.

**These are ECB single block kernels.** They measure the cipher, not a mode.
A real mode adds its own work, and CTR in particular can overlap more than
ECB can.

**The T-table cipher is not constant time.** Its table indices depend on the
key, so which cache lines are touched depends on the key, and that is
recoverable by an attacker who can observe cache state. This is inherent to
the construction rather than a defect in the code.

**The AES-NI backend is constant time**, and is chosen automatically wherever
the instructions exist. The portable cipher is the fallback, and where it is
the one that runs, the caveat above applies.
