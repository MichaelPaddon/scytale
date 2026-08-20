# scytale

Correct and fast cryptography in Rust.

**Early days.** AES is the only algorithm implemented so far. The API shape
described below is settled; the list of things behind it is not.

## Using it

```rust
use scytale::symmetric::aes::Aes128Enc;

let cipher = Aes128Enc::new(&[0u8; 16]);

let mut buffer = [0u8; 64];
let consumed = cipher.encrypt(&mut buffer);
assert_eq!(consumed, 64);
```

## Naming an implementation

An algorithm has one name for "the best available" and a path for each
specific implementation:

```rust
use scytale::symmetric::aes::Aes128Enc;                          // best
use scytale::symmetric::aes::arch::x86_64::vaes::Aes128Enc;      // pinned
use scytale::symmetric::aes::arch::x86_64::aesni::Aes128Enc;     // pinned
use scytale::symmetric::aes::arch::aarch64::armv8::Aes128Enc;   // pinned
use scytale::symmetric::aes::arch::portable::ttable::Aes128Enc;  // pinned
```

The unqualified name selects at run time, on the machine the code is
actually running on. A binary built for a baseline target still uses
whatever the silicon it lands on supports, so compiling on an old laptop
does not cost you the new instructions on a new chip. Selection happens
once, when the key is expanded, not per call.

Today that means VAES on an x86_64 CPU that has it and AES-NI on one that
does not, the Cryptographic Extension on ARMv8, and the portable T-table
cipher everywhere else. `implementation()` reports which was chosen.

Reach for an `arch` path only when you need one exact implementation and
can guarantee the target supports it.

## Bulk is the primitive

Every cipher call takes a whole buffer and returns how many bytes it
consumed:

```rust
fn encrypt(&self, data: &mut [u8]) -> usize;
```

The count is always a whole number of blocks. A trailing partial block is
left untouched, so a caller streaming arbitrary chunks carries the
remainder into the next call.

Pass as much data as you have. Handing over one block at a time leaves a
pipelined or vectorized implementation with nothing to overlap, and there
is no way for the library to recover what the interface threw away. The
single block call exists, but it is a convenience wrapper over the bulk
one rather than the other way round.

## Key schedules

Each key size comes in three types:

| Type | Holds |
| --- | --- |
| `Aes128Enc` | encryption schedule only |
| `Aes128Dec` | decryption schedule only |
| `Aes128` | both |

Deriving a decryption schedule costs about as much again as the
encryption one, so name the direction you need. Counter based modes never
decrypt.

`new` takes a fixed size array, so a wrong key length is a compile error.
`KeyInit::try_new` takes a slice and returns a `Result`, for ciphers whose
key length is not known until run time.

Round keys are zeroized when the value is dropped.

## Testing

```
cargo test            # fast tier, a few seconds per algorithm
cargo test-extended   # everything, including the slow tier
cargo test -p scytale # the library alone, which needs nothing external
```

The slow tests are marked `#[ignore]` rather than hidden behind a
feature, so a plain `cargo test` still compiles them and they cannot rot.
`cargo test -- --ignored` runs only those. The alias ends in `--`, so
cargo's own flags cannot follow it: scope with
`cargo test -p scytale -- --include-ignored` instead.

A bare `cargo test` covers the workspace, and the benchmark crate builds
OpenSSL to compare against, which needs `git`, `perl`, `make` and the
network once. `cargo test -p scytale` is the library on its own and
depends on none of that.

Correctness is checked against the NIST ACVP vectors vendored in
`vectors/`. The Algorithm Functional Test groups, 2138 cases for AES-ECB
and 150 for AES-CTR, run in the fast tier, and every one of them runs
through every implementation the machine can reach rather than only the
one a dispatching type picks. Monte Carlo groups, random key sweeps and
bit influence checks run in the slow tier.

The ARMv8 backend has no hardware here, so it is exercised by cross
compiling and running under emulation. That is a deliberate one-off
rather than something configured into every build:

```
CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc \
CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_RUNNER="qemu-aarch64 -L /usr/aarch64-linux-gnu" \
cargo test -p scytale --target aarch64-unknown-linux-gnu
```

## Performance

Measured against OpenSSL on the same machine, in the same process, in the
same measurement loop, in core cycles, each implementation against its own
counterpart:

| Tier | scytale | vs OpenSSL | Throughput |
| --- | --- | ---: | ---: |
| vector | VAES | no counterpart | 31.8 GB/s |
| accelerated | AES-NI | 1.00 to 1.20 | 15.9 GB/s |
| portable | T-table | 1.05 to 1.12 | 593 MB/s |

At or above parity on all 72 comparable cases. The accelerated bulk
kernels run at the instruction throughput limit, five cycles a block for
AES-128, so the margin there is the fraction of a percent OpenSSL sits
above the same floor; the wider margins are at short messages, where a
single block costs 6.2 cycles against 20.2 through OpenSSL's own single
block entry. VAES has no OpenSSL counterpart for ECB, so it is reported as
a speedup over our own AES-NI: exactly 2.00x. AES-128, pinned to one core.

See [PERFORMANCE.md](PERFORMANCE.md) for the method, the rules that keep
the comparison honest, and the full results.

```
cargo build -p scytale-bench --release
setarch -R taskset -c 2 target/release/scytale-bench             # accelerated
setarch -R taskset -c 2 target/release/scytale-bench --portable  # portable
setarch -R taskset -c 2 target/release/scytale-bench --vector    # VAES
```

## A warning about the T-table cipher

The portable AES implementation indexes its tables with key dependent
bytes. Which cache lines it touches therefore depends on the key, and that
is recoverable by an attacker who can observe cache state. This is inherent
to the T-table construction, not a defect in this code.

The hardware backends have no such problem: their round transformation is
a single instruction with no data dependent memory access, and the widest
available is chosen automatically. On ARMv8 the key schedule takes its
substitution from the same instruction rather than from a table, so it is
constant time too. The T-table cipher is the fallback for everywhere else,
and there this caveat applies.

## Layout

| Crate | What |
| --- | --- |
| `scytale` | the library |
| `scytale-ring` | a `ring` compatibility layer |
| `scytale-bench` | the OpenSSL comparison |

## License

BSD 2-Clause. See [LICENSE](LICENSE).

The vendored test vectors are NIST's work and carry their own notice; see
[vectors/acvp/LICENSE](vectors/acvp/LICENSE).
