# Performance

Scytale is measured against OpenSSL, on the same machine, in the same
process, in the same measurement loop.

## The rule

**A ratio is only printed when both sides are the same kind of code.**

Not merely the same algorithm at the same size, but the same kind of
implementation: a T-table cipher belongs opposite a T-table cipher, and
scalar portable code belongs opposite scalar portable code. Every unfair
comparison flatters one side, and every one of them reads as a meaningful
number to somebody who does not know how it was produced.

Scytale currently has only its portable T-table AES, so the reference is
built with `no-asm`, which selects OpenSSL's C AES rather than AES-NI. A
default OpenSSL build would beat a software T-table by roughly five to ten
times on hardware grounds alone, and that number would say nothing about
either implementation. When scytale grows an AES-NI backend, a second
reference built with assembly gets added for it, and the two pairs stay
separate.

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
  cores run at different clocks, so an unpinned benchmark is partly measuring
  the scheduler. The tool warns when it is not pinned.
- Correctness gates the timing. The agreement test requires byte identical
  output from both sides across all three key sizes, both directions, and
  buffer lengths from 1 to 64 blocks.
- Both sides are driven through the same in place bulk signature, so neither
  pays for a wrapper the other does not.

## Reproducing

```
cargo build -p scytale-bench --release
taskset -c 2 target/release/scytale-bench
```

Pick a core of a single type; on a hybrid CPU
`/sys/devices/system/cpu/cpu*/cpufreq/cpuinfo_max_freq` distinguishes them.
Running without `taskset` still works and still reports, but the ratios move
about three times as much between runs.

The build script clones and builds the reference OpenSSL; it is never
vendored. The first run therefore takes several minutes, and later runs
reuse the built library.

## Results

Measured on a 13th Gen Intel Core i7-1355U pinned to one performance core,
`x86_64-unknown-linux-gnu`, rustc 1.97.1, against OpenSSL 4.0.1 built
`no-asm`. Each figure is the median of four runs of the tool, each of which
is itself a median over 21 interleaved rounds.

Absolute throughput here is lower than the same code reaches unpinned,
because a pinned core does not get the scheduler's pick of clock speed. The
ratio is unaffected, which is the point of reporting one.

| Algorithm | Bytes | scytale MB/s | OpenSSL MB/s | Ratio | |
| --- | ---: | ---: | ---: | ---: | :---: |
| AES-128-ECB encrypt | 16 | 494 | 429 | 1.15 | ✅ |
| AES-128-ECB encrypt | 64 | 564 | 498 | 1.13 | ✅ |
| AES-128-ECB encrypt | 256 | 569 | 500 | 1.14 | ✅ |
| AES-128-ECB encrypt | 1024 | 569 | 500 | 1.14 | ✅ |
| AES-128-ECB encrypt | 8192 | 570 | 500 | 1.14 | ✅ |
| AES-128-ECB encrypt | 16384 | 570 | 500 | 1.14 | ✅ |
| AES-128-ECB decrypt | 16 | 488 | 434 | 1.12 | ✅ |
| AES-128-ECB decrypt | 64 | 562 | 512 | 1.10 | ✅ |
| AES-128-ECB decrypt | 256 | 568 | 514 | 1.10 | ✅ |
| AES-128-ECB decrypt | 1024 | 567 | 514 | 1.10 | ✅ |
| AES-128-ECB decrypt | 8192 | 567 | 514 | 1.10 | ✅ |
| AES-128-ECB decrypt | 16384 | 568 | 514 | 1.10 | ✅ |
| AES-192-ECB encrypt | 16 | 419 | 367 | 1.14 | ✅ |
| AES-192-ECB encrypt | 64 | 466 | 419 | 1.11 | ✅ |
| AES-192-ECB encrypt | 256 | 469 | 421 | 1.12 | ✅ |
| AES-192-ECB encrypt | 1024 | 468 | 420 | 1.12 | ✅ |
| AES-192-ECB encrypt | 8192 | 470 | 421 | 1.12 | ✅ |
| AES-192-ECB encrypt | 16384 | 470 | 420 | 1.12 | ✅ |
| AES-192-ECB decrypt | 16 | 414 | 374 | 1.11 | ✅ |
| AES-192-ECB decrypt | 64 | 464 | 428 | 1.08 | ✅ |
| AES-192-ECB decrypt | 256 | 466 | 430 | 1.08 | ✅ |
| AES-192-ECB decrypt | 1024 | 466 | 428 | 1.08 | ✅ |
| AES-192-ECB decrypt | 8192 | 468 | 430 | 1.08 | ✅ |
| AES-192-ECB decrypt | 16384 | 467 | 430 | 1.09 | ✅ |
| AES-256-ECB encrypt | 16 | 362 | 322 | 1.13 | ✅ |
| AES-256-ECB encrypt | 64 | 399 | 360 | 1.11 | ✅ |
| AES-256-ECB encrypt | 256 | 402 | 362 | 1.11 | ✅ |
| AES-256-ECB encrypt | 1024 | 402 | 361 | 1.11 | ✅ |
| AES-256-ECB encrypt | 8192 | 402 | 362 | 1.11 | ✅ |
| AES-256-ECB encrypt | 16384 | 402 | 361 | 1.11 | ✅ |
| AES-256-ECB decrypt | 16 | 360 | 328 | 1.10 | ✅ |
| AES-256-ECB decrypt | 64 | 396 | 369 | 1.07 | ✅ |
| AES-256-ECB decrypt | 256 | 400 | 370 | 1.08 | ✅ |
| AES-256-ECB decrypt | 1024 | 400 | 370 | 1.08 | ✅ |
| AES-256-ECB decrypt | 8192 | 399 | 371 | 1.08 | ✅ |
| AES-256-ECB decrypt | 16384 | 400 | 372 | 1.08 | ✅ |

✅ at or above parity with OpenSSL, ❌ below it.

## Reading the table

**The lead is flat across key sizes**, around 1.10 everywhere. That is what
an advantage in the round itself looks like: AES-192 and AES-256 run more of
the same rounds, so a per round gain shows up unchanged as a ratio. Absolute
throughput falls with the round count as expected, roughly 570, 470 and 400
MB/s for 10, 12 and 14 rounds.

**Decrypt trails encrypt by about two points** at every key size, on both
sides. The forward tables happen to carry a plain `S[x]` byte that the final
round can mask out; the inverse tables carry no plain `S^-1[x]`, so inverse
final rounds read a separate S-box and assemble the bytes. Both
implementations pay it.

**16 bytes is the best row in every group.** At one block there is nothing to
amortise a call over, so that row mostly measures per call overhead, where
the lead is largest.

## Caveats

**The floor on what this can resolve is about 1%.** Across four pinned runs
of an unchanged binary, rows move by 0.008 on average and 0.03 at worst, so
a change measuring under a point has not been shown to do anything. Unpinned
that figure is three times larger. Going below a point would need the
`performance` governor and turbo disabled as well, neither of which the tool
can arrange for itself.

**These are ECB single block kernels.** They measure the cipher, not a mode.
A real mode adds its own work, and CTR in particular can overlap more than
ECB can.

**The T-table cipher is not constant time.** Its table indices depend on the
key, so which cache lines are touched depends on the key, and that is
recoverable by an attacker who can observe cache state. This is inherent to
the construction rather than a defect in the code. It is the fast portable
choice, not the safe one; treat the numbers above as the cost of a cipher
that should not be used where a local or co-resident attacker is in the
threat model.
