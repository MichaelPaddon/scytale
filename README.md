# scytale

Correct and fast cryptography in Rust.

**Early days.** AES is the only algorithm implemented so far, and only as
a portable T-table cipher. The API shape described below is settled; the
list of things behind it is not.

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
use scytale::symmetric::aes::arch::portable::ttable::Aes128Enc;  // pinned
```

The unqualified name selects at run time, on the machine the code is
actually running on. A binary built for a baseline target still uses
whatever the silicon it lands on supports, so compiling on an old laptop
does not cost you the new instructions on a new chip. Selection happens
once, not per call.

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
cargo test           # fast tier, a few seconds per algorithm
cargo extended-test  # everything else
```

Correctness is checked against the NIST ACVP vectors vendored in
`vectors/`. The Algorithm Functional Test groups, 2138 cases for AES-ECB,
run in the fast tier. Monte Carlo groups, random key sweeps and bit
influence checks run in the extended tier.

## Performance

Measured against OpenSSL on the same machine, in the same process, in the
same measurement loop. Currently 1.07 to 1.15 times OpenSSL's C AES
across key sizes, directions and message lengths.

See [PERFORMANCE.md](PERFORMANCE.md) for the method, the rules that keep
the comparison honest, and the full results.

```
cargo build -p scytale-bench --release
taskset -c 2 target/release/scytale-bench
```

## A warning about the T-table cipher

The only AES implementation here today indexes its tables with key
dependent bytes. Which cache lines it touches therefore depends on the
key, and that is recoverable by an attacker who can observe cache state.
This is inherent to the T-table construction, not a defect in this code.

It is the fast portable choice, not the safe one. Do not use it where a
local or co-resident attacker is in your threat model.

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
