# Performance

Scytale is measured against OpenSSL, on the same machine, in the same
process, in the same measurement loop, in core cycles.

## The rule

**A ratio is only printed when both sides are the same kind of code.**

Not merely the same algorithm at the same size, but the same kind of
implementation. Every unfair comparison flatters one side, and every one of
them reads as a meaningful number to somebody who does not know how it was
produced.

Scytale has three AES implementations on x86_64, which is the target
measured here, so OpenSSL is built twice and each is measured against its
own counterpart where one exists:

| Tier | scytale | OpenSSL |
| --- | --- | --- |
| vector | VAES | none: it has no VAES kernel for ECB or CTR |
| accelerated | AES-NI | AES-NI, from a default build |
| portable | T-table | C, from a `no-asm` build |

None of these pairings is arbitrary. Putting our AES-NI against OpenSSL's C
would flatter us by five to ten times on hardware grounds alone; putting our
T-table against its AES-NI would do the reverse. The accelerated tier also
avoids OpenSSL's `AES_encrypt`, which in an assembly build is its assembly
T-table rather than its AES-NI, and avoids EVP, which would add dispatch and
context handling to the measurement.

The same rule decides which entry point each side is called through. A one
block message goes through each side's own single block entry,
`encrypt_block` against `aesni_encrypt`; everything longer goes through each
side's bulk entry, ours against `aesni_ecb_encrypt`. Measuring one block
through the bulk entry would charge OpenSSL for a length dispatch that a
caller with one block does not use, which is a comparison of interfaces
rather than of ciphers.

CTR is paired the same way, on each tier against the counterpart of its own
kind:

| Tier | scytale | OpenSSL |
| --- | --- | --- |
| vector | VAES counter kernel | none, as for ECB |
| accelerated | AES-NI counter kernel | `aesni_ctr32_encrypt_blocks` |
| portable | generic mode over the T-table cipher | `CRYPTO_ctr128_encrypt` driven by `AES_encrypt` |

Every CTR row goes through the bulk entry on both sides, at one block as
well as at a thousand, because neither side has a single block counter
entry to call instead. The portable pairing is a mode loop in C driving a
scalar block function against a mode loop in Rust doing the same, which is
why `AES_encrypt` is passed explicitly rather than left to a build that
might supply an assembly one.

OpenSSL's kernel counts in the low 32 bits of the counter where ours counts
in all 128. The two agree exactly whenever a message neither reaches 2^32
blocks nor starts within that distance of the boundary, so the benchmark
starts every counter with its low 32 bits zero and its longest message is
1024 blocks. The agreement test holds both sides to byte identical output
under those conditions before any timing is believed; it is a restriction
on the benchmark, not a claim that the two modes are the same.

The vector tier has no honest counterpart at all. OpenSSL 4.0.1 uses VAES
for CFB, XTS and GCM, but its only ECB kernel is `aesni_ecb_encrypt` and
its only bare counter kernel is `aesni_ctr32_encrypt_blocks`, both of which
are SSE. Its VAES counter code exists only inside GCM, fused with the
authentication it is there to serve, so it cannot be called on its own or
be compared with a bare mode. Rather than print a flattering ratio against
narrower code, that tier is reported against scytale's own AES-NI, is
labelled a speedup rather than a comparison, and gates nothing.

There is a fourth implementation, on the ARMv8 Cryptographic Extension.
No figure for it appears here, because it has only ever run under an
emulator: qemu proves what the instructions compute and nothing about
what they cost. It gets a tier of its own once it runs on hardware.

The corollary: **if OpenSSL is ever faster, work stops until it is not.**
The benchmark exits non-zero when any row falls below parity, so this is
machine checkable rather than a matter of reading the table carefully.

## Method

The tool links libcrypto directly and drives both implementations through
one measurement loop, with the same message sizes and the same instrument.
Message sizes are 16, 64, 256, 1024, 8192 and 16384 bytes.

**Core cycles, not wall time.** The core clock moves under a frequency
governor and under turbo, so a stopwatch measures the machine's power state
along with the code. Cycles come from `perf_event_open`, read with `rdpmc`
on the page the kernel maps for it, which costs tens of cycles rather than
the microsecond a syscall would. Kernel and interrupt cycles are excluded
from the count. On a hybrid CPU the performance and efficiency cores have
separate counters, and an event opened on the wrong one is accepted and
then counts nothing, so the tool opens each in turn and keeps the one that
demonstrably counts.

**Independent messages.** Each call takes the next message from a short
ring rather than rewriting one buffer. Encrypting one buffer over and over
makes each call wait on the previous call's stores, and at one block that
wait is most of what gets measured: the same AES-128 block costs 6.2 cycles
when calls are independent and 37 when they are chained. The ring is held
to 8 KB, which stays in the first level cache, so independence is not
bought with cache misses.

**The minimum of many short samples.** Each side is measured 201 times, in
windows of about 200000 cycles, alternating so that anything drifting
during a run lands on both equally. The reported figure is the smallest
sample: interference can only add cycles to a measurement, never remove
them, so with enough samples the smallest is the one that met the least of
it. The median is kept alongside and printed under `--verbose`; a gap
between the two is the sign of a machine that was not quiet.

**A fixed machine.** Run pinned to one core: on a hybrid CPU the two core
types run different clocks and have different counters. Run under
`setarch -R` as well, because where the buffers and key schedules land
decides which of them share cache sets, and randomizing that moves a short
message row by a couple of percent from one run to the next. The tool
reports what it is measuring with and warns when either is missing, and
notes the sibling thread of the core it is pinned to, since work there
spends the same core's cycles.

**Correctness gates the timing.** The agreement tests require byte
identical output from scytale and from both OpenSSL builds, across all
three key sizes, both directions, and buffer lengths from 1 to 64 blocks.
CTR is held to the same standard, including lengths that are not a whole
number of blocks and messages fed in pieces, since a mode that only agrees
when handed a whole message is not the mode it claims to be. The full ACVP
vector set runs under `cargo test --features extended-tests`.

## Reproducing

```
cargo build -p scytale-bench --release
setarch -R taskset -c 2 target/release/scytale-bench             # accelerated
setarch -R taskset -c 2 target/release/scytale-bench --portable  # portable
setarch -R taskset -c 2 target/release/scytale-bench --vector    # VAES
```

Pick a core of a single type; on a hybrid CPU
`/sys/devices/system/cpu/cpu*/cpufreq/cpuinfo_max_freq` distinguishes them.
A tier takes under a second. Reading the cycle counter needs
`perf_event_paranoid` of 2 or less; without it the tool falls back to the
clock, says so, and the ratios move with the governor.

The build script clones and builds both reference OpenSSL configurations; it
never vendors them. The first run therefore takes several minutes, and later
runs reuse the built libraries.

## Results

Measured on a 13th Gen Intel Core i7-1355U pinned to one performance core,
`x86_64-unknown-linux-gnu`, rustc 1.97.1, against OpenSSL 4.0.1. Each figure
is the median of five runs of the tool, each of which is itself the smallest
of 201 samples.

Cycles per byte is the number to compare: it does not depend on the clock,
and multiplying by 16 gives cycles per block. MB/s is given for a sense of
scale, at whatever clock the run happened to see, and is not what the ratio
is taken from.

### Accelerated: AES-NI against OpenSSL AES-NI

What runs on an x86_64 CPU with the AES instructions but without VAES.

| Algorithm | Bytes | scytale cyc/B | scytale MB/s | OpenSSL cyc/B | OpenSSL MB/s | Ratio | |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | :---: |
| AES-128-ECB encrypt | 16 | 0.3906 | 12531 | 1.2655 | 3914 | 3.240 | ✅ |
| AES-128-ECB encrypt | 64 | 0.3163 | 15190 | 0.3633 | 13274 | 1.148 | ✅ |
| AES-128-ECB encrypt | 256 | 0.3125 | 15872 | 0.3128 | 15791 | 1.001 | ✅ |
| AES-128-ECB encrypt | 1024 | 0.3125 | 15938 | 0.3138 | 15452 | 1.004 | ✅ |
| AES-128-ECB encrypt | 8192 | 0.3125 | 15905 | 0.3135 | 15827 | 1.003 | ✅ |
| AES-128-ECB encrypt | 16384 | 0.3128 | 15931 | 0.3130 | 15918 | 1.001 | ✅ |
| AES-128-ECB decrypt | 16 | 0.3984 | 10586 | 1.2655 | 3875 | 3.176 | ✅ |
| AES-128-ECB decrypt | 64 | 0.3168 | 15234 | 0.3790 | 12010 | 1.196 | ✅ |
| AES-128-ECB decrypt | 256 | 0.3125 | 15882 | 0.3130 | 15824 | 1.002 | ✅ |
| AES-128-ECB decrypt | 1024 | 0.3125 | 15897 | 0.3141 | 15442 | 1.005 | ✅ |
| AES-128-ECB decrypt | 8192 | 0.3125 | 15934 | 0.3134 | 15893 | 1.003 | ✅ |
| AES-128-ECB decrypt | 16384 | 0.3127 | 15864 | 0.3129 | 15897 | 1.001 | ✅ |
| AES-192-ECB encrypt | 16 | 0.4448 | 10670 | 1.3905 | 3546 | 3.126 | ✅ |
| AES-192-ECB encrypt | 64 | 0.3786 | 12752 | 0.3912 | 12236 | 1.033 | ✅ |
| AES-192-ECB encrypt | 256 | 0.3750 | 13204 | 0.3754 | 13184 | 1.001 | ✅ |
| AES-192-ECB encrypt | 1024 | 0.3750 | 13284 | 0.3763 | 13192 | 1.003 | ✅ |
| AES-192-ECB encrypt | 8192 | 0.3750 | 13241 | 0.3761 | 13154 | 1.003 | ✅ |
| AES-192-ECB encrypt | 16384 | 0.3752 | 13260 | 0.3756 | 13231 | 1.001 | ✅ |
| AES-192-ECB decrypt | 16 | 0.4421 | 10820 | 1.4139 | 3475 | 3.198 | ✅ |
| AES-192-ECB decrypt | 64 | 0.3786 | 12881 | 0.3897 | 11818 | 1.029 | ✅ |
| AES-192-ECB decrypt | 256 | 0.3750 | 13206 | 0.3770 | 13107 | 1.005 | ✅ |
| AES-192-ECB decrypt | 1024 | 0.3750 | 13245 | 0.3775 | 13166 | 1.007 | ✅ |
| AES-192-ECB decrypt | 8192 | 0.3750 | 13281 | 0.3773 | 13195 | 1.006 | ✅ |
| AES-192-ECB decrypt | 16384 | 0.3752 | 13265 | 0.3770 | 13197 | 1.005 | ✅ |
| AES-256-ECB encrypt | 16 | 0.5194 | 9246 | 1.6827 | 2898 | 3.240 | ✅ |
| AES-256-ECB encrypt | 64 | 0.4419 | 11070 | 0.4551 | 10759 | 1.030 | ✅ |
| AES-256-ECB encrypt | 256 | 0.4379 | 11284 | 0.4383 | 11283 | 1.001 | ✅ |
| AES-256-ECB encrypt | 1024 | 0.4377 | 11372 | 0.4392 | 11311 | 1.003 | ✅ |
| AES-256-ECB encrypt | 8192 | 0.4375 | 11375 | 0.4391 | 11312 | 1.004 | ✅ |
| AES-256-ECB encrypt | 16384 | 0.4377 | 11305 | 0.4385 | 11267 | 1.002 | ✅ |
| AES-256-ECB decrypt | 16 | 0.5200 | 9420 | 1.8904 | 2620 | 3.629 | ✅ |
| AES-256-ECB decrypt | 64 | 0.4422 | 11024 | 0.4550 | 10678 | 1.029 | ✅ |
| AES-256-ECB decrypt | 256 | 0.4377 | 11304 | 0.4399 | 11218 | 1.005 | ✅ |
| AES-256-ECB decrypt | 1024 | 0.4376 | 11363 | 0.4398 | 11291 | 1.005 | ✅ |
| AES-256-ECB decrypt | 8192 | 0.4375 | 11384 | 0.4400 | 11279 | 1.006 | ✅ |
| AES-256-ECB decrypt | 16384 | 0.4379 | 11370 | 0.4391 | 11291 | 1.003 | ✅ |
| AES-128-CTR | 16 | 1.0548 | 4620 | 3.2466 | 1513 | 3.078 | ✅ |
| AES-128-CTR | 64 | 0.4869 | 9750 | 0.9821 | 4850 | 2.018 | ✅ |
| AES-128-CTR | 256 | 0.4671 | 10410 | 0.5076 | 9606 | 1.086 | ✅ |
| AES-128-CTR | 1024 | 0.3650 | 13485 | 0.3936 | 12463 | 1.078 | ✅ |
| AES-128-CTR | 8192 | 0.3367 | 14590 | 0.3607 | 13621 | 1.071 | ✅ |
| AES-128-CTR | 16384 | 0.3327 | 14728 | 0.3580 | 13704 | 1.076 | ✅ |
| AES-192-CTR | 16 | 1.0860 | 4433 | 3.6211 | 1346 | 3.334 | ✅ |
| AES-192-CTR | 64 | 0.5263 | 9039 | 1.0960 | 4377 | 2.083 | ✅ |
| AES-192-CTR | 256 | 0.5258 | 9350 | 0.5684 | 8683 | 1.081 | ✅ |
| AES-192-CTR | 1024 | 0.4265 | 11560 | 0.4485 | 10949 | 1.052 | ✅ |
| AES-192-CTR | 8192 | 0.3993 | 12382 | 0.4138 | 11898 | 1.036 | ✅ |
| AES-192-CTR | 16384 | 0.3948 | 12496 | 0.4108 | 11997 | 1.040 | ✅ |
| AES-256-CTR | 16 | 1.1384 | 4260 | 3.9956 | 1222 | 3.510 | ✅ |
| AES-256-CTR | 64 | 0.5859 | 8214 | 1.1840 | 4067 | 2.021 | ✅ |
| AES-256-CTR | 256 | 0.5934 | 8306 | 0.6265 | 7827 | 1.056 | ✅ |
| AES-256-CTR | 1024 | 0.4900 | 10057 | 0.5097 | 9620 | 1.040 | ✅ |
| AES-256-CTR | 8192 | 0.4619 | 10723 | 0.4767 | 10409 | 1.032 | ✅ |
| AES-256-CTR | 16384 | 0.4576 | 10859 | 0.4740 | 10491 | 1.036 | ✅ |

CTR has one direction: encrypting and decrypting are the same operation,
so there is one row per size rather than two.

### Portable: T-table against OpenSSL C

What runs where neither is available.

| Algorithm | Bytes | scytale cyc/B | scytale MB/s | OpenSSL cyc/B | OpenSSL MB/s | Ratio | |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | :---: |
| AES-128-ECB encrypt | 16 | 8.5484 | 579 | 9.4422 | 522 | 1.105 | ✅ |
| AES-128-ECB encrypt | 64 | 8.2939 | 587 | 9.2534 | 527 | 1.115 | ✅ |
| AES-128-ECB encrypt | 256 | 8.2454 | 590 | 9.1391 | 533 | 1.108 | ✅ |
| AES-128-ECB encrypt | 1024 | 8.2403 | 590 | 9.1345 | 532 | 1.108 | ✅ |
| AES-128-ECB encrypt | 8192 | 8.2147 | 591 | 9.1071 | 537 | 1.108 | ✅ |
| AES-128-ECB encrypt | 16384 | 8.2165 | 593 | 9.1076 | 536 | 1.108 | ✅ |
| AES-128-ECB decrypt | 16 | 8.5775 | 567 | 9.2796 | 524 | 1.082 | ✅ |
| AES-128-ECB decrypt | 64 | 8.3291 | 584 | 8.9987 | 541 | 1.080 | ✅ |
| AES-128-ECB decrypt | 256 | 8.2814 | 586 | 8.8576 | 548 | 1.069 | ✅ |
| AES-128-ECB decrypt | 1024 | 8.2749 | 584 | 8.8473 | 547 | 1.069 | ✅ |
| AES-128-ECB decrypt | 8192 | 8.2484 | 590 | 8.8207 | 554 | 1.069 | ✅ |
| AES-128-ECB decrypt | 16384 | 8.2607 | 589 | 8.8227 | 552 | 1.068 | ✅ |
| AES-192-ECB encrypt | 16 | 10.2544 | 472 | 11.2098 | 433 | 1.093 | ✅ |
| AES-192-ECB encrypt | 64 | 10.0737 | 483 | 10.9862 | 441 | 1.091 | ✅ |
| AES-192-ECB encrypt | 256 | 9.9854 | 484 | 10.8728 | 446 | 1.089 | ✅ |
| AES-192-ECB encrypt | 1024 | 9.9791 | 487 | 10.8601 | 448 | 1.088 | ✅ |
| AES-192-ECB encrypt | 8192 | 9.9591 | 490 | 10.8371 | 451 | 1.088 | ✅ |
| AES-192-ECB encrypt | 16384 | 9.9644 | 489 | 10.8370 | 448 | 1.088 | ✅ |
| AES-192-ECB decrypt | 16 | 10.3052 | 473 | 11.0006 | 445 | 1.067 | ✅ |
| AES-192-ECB decrypt | 64 | 10.1222 | 480 | 10.7135 | 453 | 1.058 | ✅ |
| AES-192-ECB decrypt | 256 | 10.0301 | 486 | 10.5759 | 463 | 1.055 | ✅ |
| AES-192-ECB decrypt | 1024 | 10.0208 | 488 | 10.5598 | 463 | 1.054 | ✅ |
| AES-192-ECB decrypt | 8192 | 10.0004 | 489 | 10.5341 | 463 | 1.054 | ✅ |
| AES-192-ECB decrypt | 16384 | 10.0039 | 488 | 10.5394 | 464 | 1.053 | ✅ |
| AES-256-ECB encrypt | 16 | 11.9805 | 406 | 12.9736 | 374 | 1.083 | ✅ |
| AES-256-ECB encrypt | 64 | 11.7768 | 414 | 12.7506 | 379 | 1.082 | ✅ |
| AES-256-ECB encrypt | 256 | 11.6823 | 419 | 12.6401 | 387 | 1.082 | ✅ |
| AES-256-ECB encrypt | 1024 | 11.6693 | 417 | 12.6322 | 384 | 1.083 | ✅ |
| AES-256-ECB encrypt | 8192 | 11.6554 | 416 | 12.6105 | 386 | 1.082 | ✅ |
| AES-256-ECB encrypt | 16384 | 11.6548 | 419 | 12.6082 | 387 | 1.081 | ✅ |
| AES-256-ECB decrypt | 16 | 12.0200 | 405 | 12.7122 | 383 | 1.057 | ✅ |
| AES-256-ECB decrypt | 64 | 11.8446 | 413 | 12.4340 | 392 | 1.050 | ✅ |
| AES-256-ECB decrypt | 256 | 11.7380 | 415 | 12.2958 | 398 | 1.048 | ✅ |
| AES-256-ECB decrypt | 1024 | 11.7304 | 418 | 12.2817 | 398 | 1.047 | ✅ |
| AES-256-ECB decrypt | 8192 | 11.7052 | 415 | 12.2595 | 397 | 1.047 | ✅ |
| AES-256-ECB decrypt | 16384 | 11.7028 | 419 | 12.2549 | 400 | 1.047 | ✅ |
| AES-128-CTR | 16 | 9.8250 | 480 | 11.8226 | 395 | 1.203 | ✅ |
| AES-128-CTR | 64 | 9.4967 | 495 | 11.8367 | 397 | 1.247 | ✅ |
| AES-128-CTR | 256 | 9.4651 | 498 | 11.7981 | 400 | 1.246 | ✅ |
| AES-128-CTR | 1024 | 9.3207 | 504 | 11.8049 | 400 | 1.266 | ✅ |
| AES-128-CTR | 8192 | 9.2866 | 507 | 11.7998 | 400 | 1.271 | ✅ |
| AES-128-CTR | 16384 | 9.2834 | 509 | 11.7954 | 401 | 1.271 | ✅ |
| AES-192-CTR | 16 | 11.5259 | 407 | 13.5655 | 345 | 1.177 | ✅ |
| AES-192-CTR | 64 | 11.2686 | 418 | 13.6006 | 347 | 1.207 | ✅ |
| AES-192-CTR | 256 | 11.1772 | 423 | 13.5645 | 348 | 1.213 | ✅ |
| AES-192-CTR | 1024 | 11.0376 | 429 | 13.5659 | 347 | 1.229 | ✅ |
| AES-192-CTR | 8192 | 11.0025 | 430 | 13.5566 | 347 | 1.232 | ✅ |
| AES-192-CTR | 16384 | 11.0026 | 428 | 13.5552 | 346 | 1.232 | ✅ |
| AES-256-CTR | 16 | 13.5038 | 349 | 15.3294 | 306 | 1.135 | ✅ |
| AES-256-CTR | 64 | 12.8961 | 365 | 15.3657 | 306 | 1.191 | ✅ |
| AES-256-CTR | 256 | 12.8761 | 368 | 15.3250 | 309 | 1.190 | ✅ |
| AES-256-CTR | 1024 | 12.7284 | 372 | 15.3338 | 309 | 1.204 | ✅ |
| AES-256-CTR | 8192 | 12.6993 | 373 | 15.3166 | 310 | 1.206 | ✅ |
| AES-256-CTR | 16384 | 12.6898 | 373 | 15.3095 | 309 | 1.206 | ✅ |

### Vector: VAES against scytale's own AES-NI

What runs on this machine, and on anything since Ice Lake or Alder Lake.
The ratio is a speedup over our narrower kernels, not a comparison with
OpenSSL, which has nothing of this kind for ECB.

| Algorithm | Bytes | VAES cyc/B | VAES MB/s | AES-NI cyc/B | AES-NI MB/s | Speedup |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| AES-128-ECB encrypt | 16 | 0.6595 | 7323 | 0.5782 | 7851 | 0.877 |
| AES-128-ECB encrypt | 64 | 0.3185 | 15150 | 0.3162 | 15313 | 0.993 |
| AES-128-ECB encrypt | 256 | 0.1563 | 31449 | 0.3125 | 15750 | 2.000 |
| AES-128-ECB encrypt | 1024 | 0.1565 | 31620 | 0.3125 | 15785 | 1.997 |
| AES-128-ECB encrypt | 8192 | 0.1563 | 31704 | 0.3125 | 15898 | 2.000 |
| AES-128-ECB encrypt | 16384 | 0.1563 | 31768 | 0.3126 | 15909 | 2.001 |
| AES-128-ECB decrypt | 16 | 0.6487 | 7164 | 0.6112 | 7308 | 0.942 |
| AES-128-ECB decrypt | 64 | 0.3168 | 15151 | 0.3167 | 15203 | 0.999 |
| AES-128-ECB decrypt | 256 | 0.1563 | 31691 | 0.3125 | 15842 | 2.000 |
| AES-128-ECB decrypt | 1024 | 0.1565 | 31689 | 0.3125 | 15902 | 1.997 |
| AES-128-ECB decrypt | 8192 | 0.1563 | 31571 | 0.3125 | 15860 | 2.000 |
| AES-128-ECB decrypt | 16384 | 0.1563 | 31666 | 0.3126 | 15835 | 2.001 |
| AES-192-ECB encrypt | 16 | 0.7033 | 6673 | 0.7734 | 6175 | 1.100 |
| AES-192-ECB encrypt | 64 | 0.3808 | 12698 | 0.3784 | 12846 | 0.994 |
| AES-192-ECB encrypt | 256 | 0.1876 | 26391 | 0.3750 | 13187 | 1.999 |
| AES-192-ECB encrypt | 1024 | 0.1879 | 26483 | 0.3750 | 13249 | 1.996 |
| AES-192-ECB encrypt | 8192 | 0.1875 | 26493 | 0.3750 | 13248 | 2.000 |
| AES-192-ECB encrypt | 16384 | 0.1875 | 26501 | 0.3752 | 13250 | 2.001 |
| AES-192-ECB decrypt | 16 | 0.6957 | 6809 | 0.7734 | 6215 | 1.112 |
| AES-192-ECB decrypt | 64 | 0.3804 | 12854 | 0.3785 | 12905 | 0.995 |
| AES-192-ECB decrypt | 256 | 0.1876 | 26438 | 0.3750 | 13210 | 1.999 |
| AES-192-ECB decrypt | 1024 | 0.1879 | 26453 | 0.3750 | 13289 | 1.996 |
| AES-192-ECB decrypt | 8192 | 0.1875 | 26526 | 0.3750 | 13275 | 2.000 |
| AES-192-ECB decrypt | 16384 | 0.1875 | 26385 | 0.3751 | 13211 | 2.001 |
| AES-256-ECB encrypt | 16 | 0.7455 | 6309 | 0.7001 | 6701 | 0.940 |
| AES-256-ECB encrypt | 64 | 0.4424 | 10885 | 0.4422 | 11007 | 1.000 |
| AES-256-ECB encrypt | 256 | 0.2189 | 22708 | 0.4380 | 11351 | 2.001 |
| AES-256-ECB encrypt | 1024 | 0.2193 | 22719 | 0.4377 | 11367 | 1.996 |
| AES-256-ECB encrypt | 8192 | 0.2188 | 22653 | 0.4375 | 11273 | 2.000 |
| AES-256-ECB encrypt | 16384 | 0.2188 | 22670 | 0.4377 | 11321 | 2.001 |
| AES-256-ECB decrypt | 16 | 0.7451 | 6353 | 0.7074 | 6774 | 0.950 |
| AES-256-ECB decrypt | 64 | 0.4427 | 10985 | 0.4424 | 10955 | 0.999 |
| AES-256-ECB decrypt | 256 | 0.2189 | 22758 | 0.4377 | 11359 | 2.000 |
| AES-256-ECB decrypt | 1024 | 0.2193 | 22694 | 0.4376 | 11385 | 1.996 |
| AES-256-ECB decrypt | 8192 | 0.2188 | 22662 | 0.4375 | 11326 | 2.000 |
| AES-256-ECB decrypt | 16384 | 0.2188 | 22600 | 0.4379 | 11304 | 2.002 |
| AES-128-CTR | 16 | 1.4194 | 3038 | 1.0548 | 4042 | 0.743 |
| AES-128-CTR | 64 | 0.5336 | 8254 | 0.4863 | 9074 | 0.911 |
| AES-128-CTR | 256 | 0.3790 | 12644 | 0.4681 | 10251 | 1.235 |
| AES-128-CTR | 1024 | 0.2207 | 22037 | 0.3652 | 13328 | 1.655 |
| AES-128-CTR | 8192 | 0.1757 | 26527 | 0.3367 | 14298 | 1.917 |
| AES-128-CTR | 16384 | 0.1704 | 26905 | 0.3327 | 14536 | 1.953 |
| AES-192-CTR | 16 | 1.4610 | 2914 | 1.0861 | 3918 | 0.743 |
| AES-192-CTR | 64 | 0.5842 | 7586 | 0.5271 | 8382 | 0.901 |
| AES-192-CTR | 256 | 0.4418 | 10859 | 0.5255 | 9244 | 1.189 |
| AES-192-CTR | 1024 | 0.2446 | 19751 | 0.4260 | 11355 | 1.742 |
| AES-192-CTR | 8192 | 0.1977 | 24379 | 0.3994 | 12114 | 2.020 |
| AES-192-CTR | 16384 | 0.1944 | 24703 | 0.3948 | 12167 | 2.031 |
| AES-256-CTR | 16 | 1.5132 | 2847 | 1.1383 | 3784 | 0.752 |
| AES-256-CTR | 64 | 0.6340 | 7086 | 0.5857 | 7691 | 0.924 |
| AES-256-CTR | 256 | 0.4563 | 10659 | 0.5935 | 8214 | 1.301 |
| AES-256-CTR | 1024 | 0.2741 | 17804 | 0.4901 | 10003 | 1.788 |
| AES-256-CTR | 8192 | 0.2264 | 21546 | 0.4619 | 10523 | 2.041 |
| AES-256-CTR | 16384 | 0.2230 | 21624 | 0.4576 | 10564 | 2.052 |

✅ at or above parity with OpenSSL, ❌ below it.

## Reading the tables

**The bulk kernels run at the instruction throughput limit.** The AES
instructions retire two per cycle, so AES-128's ten rounds cannot cost less
than five cycles a block, AES-192's twelve less than six, and AES-256's
fourteen less than seven. From 256 bytes up scytale measures 0.3125, 0.3750
and 0.4375 cycles per byte, which is 5.000, 6.000 and 7.000 cycles a block.
There is nothing left in those rows: the round instructions are the whole
cost, and everything around them has been amortised away. OpenSSL is 0.1 to
0.7% above the same floor, which is what the ratios of 1.001 to 1.007 are.

**VAES doubles AES-NI exactly for ECB**, 2.000 from 256 bytes up, because
two blocks per instruction against a kernel already at the instruction
limit can give exactly that and no more. Below sixteen blocks the vector
types delegate to AES-NI and pay a check for the privilege, which is the
0.88 to 1.11 at the short end; those rows gate nothing and are the same
code on both sides.

**The portable ECB lead is 1.05 to 1.12**, and roughly flat across sizes.
The margin is larger than the accelerated tier's because there is more
room to differ in software: two implementations of the same handful of
instructions have almost nowhere left to go.

**Short messages are dominated by the call, not the cipher.** At one block
scytale costs 6.2 cycles against OpenSSL's 20.2, a factor of 3.2. Almost
all of that is the interface: our call inlines into the caller, theirs
crosses the C ABI into a function that reloads the schedule pointer and the
round count. It is a real difference to a caller with single blocks to
encrypt, and it is not a statement about the cipher, which is why the row
is worth reading separately from the rest.

**CTR costs a third of a cycle a block more than ECB**, and the same third
at all three key sizes: 5.32, 6.32 and 7.32 cycles a block against ECB's
5.00, 6.00 and 7.00. The counter blocks are built in registers and the
keystream is exclusive-ored into the data as it leaves the last round, so
the keystream is never written to memory and read back; what remains is
the counter arithmetic and one extra load and store per block, and none of
that depends on how many rounds it is spread across. OpenSSL pays 0.73,
0.57 and 0.58 on the same rows, which is where the ratios of 1.03 to 1.08
come from.

**The vector counter kernel can beat the factor of two** that ECB is
pinned at: 1.95 at AES-128, but 2.03 and 2.05 at AES-192 and AES-256. Two
blocks per round instruction halves the counter arithmetic per block as
well as the round work, and a longer schedule leaves more issue slots for
that arithmetic to hide in, so its overhead falls from 0.23 cycles a block
at AES-128 to 0.07 at AES-256 while the narrower kernel it is measured
against stays flat at 0.32. Below a sixteen block group the vector types
delegate to AES-NI, which is the 0.74 to 0.92 at the short end.

**The portable mode overhead is 1.07 cycles a byte**, 9.28 against the
T-table cipher's 8.22, or seventeen cycles a block to stage a keystream
block and exclusive-or it in. OpenSSL pays 2.69 on the same comparison,
forty-three cycles a block. Both loops stage the keystream through memory
and combine it a word at a time; the difference is that ours reaches the
cipher through a direct call that inlines and theirs through the function
pointer the interface is built around, once per block. That is most of why
the portable CTR lead of 1.14 to 1.27 is wider than the portable ECB lead
of 1.05 to 1.12: the ciphers underneath are closer than the loops around
them.

**The one block CTR row tells the same story twice over.** It costs 16.9
cycles against OpenSSL's 51.9, which takes a rolled loop over the round
keys for a length its wide path never sees. Against our own ECB single
block entry at 6.2 cycles, the difference is the counter driver and its
write-back paid whole with one block to amortise them over. The ladder
from 16.9 down to 5.3 cycles a block as the message grows is that fixed
cost being spread, not the cipher getting faster.

**Hardware is worth about 54 times the portable cipher**, 31.7 GB/s against
593 MB/s for AES-128. That gap, not the ratios against OpenSSL, is the
reason the accelerated backends exist.

## Caveats

**What this can resolve is about 0.1%.** Across five runs of an unchanged
binary, pinned and with a fixed layout, the bulk rows usually move by less
than that, and so does our own figure at four blocks.

OpenSSL's four block figure does not. It settles on one of two values
about 3% apart, from one run to the next and from one build of this
benchmark to the next, depending on where its key schedule lands relative
to the messages. On AES-256 decryption the two implementations are close
enough for that to decide the row: scytale measures 28.3 cycles a message
against OpenSSL's 28.3 or 29.1, where the instruction throughput limit is
28.0.

**The accelerated ECB verdicts are not the same on every run.** Both sides
sit at the instruction throughput limit on the bulk rows, so which of them
measures faster is settled by less than the tool can resolve. Over
thirty-nine runs of an unchanged binary the gate tripped ten times, on
fourteen different ECB rows across all three key sizes and both
directions, every one of them at a ratio between 0.990 and 1.000. These
are ties at the hardware floor rather than deficits, and the tables above
report medians of five runs, but a single run is not enough to conclude
that a change made an accelerated ECB row slower.

No CTR row has tripped in any of those runs. Their narrowest margin is
3%, which is well outside what the measurement can confuse, so the counter
kernels are the part of the tier where a single run does mean something.

**The ECB rows measure a cipher; the CTR rows measure a mode.** From 256
bytes up the ECB rows are the round instructions and nothing else. The CTR
rows carry a mode's own work as well: counter arithmetic, an extra load
and store per block, and a partial block to carry between calls. That work
costs 0.32 cycles a block on the accelerated tier and seventeen on the
portable one, and it belongs to the mode rather than to the cipher
underneath it.

**The measurement is of a hot cache.** The messages are in the first level
cache and so is the key schedule. A caller whose data comes from memory
will not see these numbers, and neither implementation would be the reason.

**The T-table cipher is not constant time.** Its table indices depend on the
key, so which cache lines are touched depends on the key, and that is
recoverable by an attacker who can observe cache state. This is inherent to
the construction rather than a defect in the code.

**The AES-NI and VAES backends are constant time**, and the widest
available is chosen automatically. The portable cipher is the fallback, and
where it is the one that runs, the caveat above applies.
