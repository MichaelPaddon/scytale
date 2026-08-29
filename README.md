# scytale

Cryptographic primitives in Rust.

This is early work. It has AES and the block cipher modes built on
it, the SHA-2 hashes with HMAC, HKDF and PBKDF2 over them, and random
numbers.

## Goals

**Correct.** Every implementation is checked against the standard
test vectors and against the NIST Automated Cryptographic Validation
Program (ACVP) vectors: 14,765 one-shot cases and 3600 Monte Carlo
steps, the latter being 3.6 million chained cipher calls with the key
re-derived at each step. Each case runs against every implementation
the processor supports, not just one. Every implementation is also
compared byte for byte against the portable one across a range of
buffer lengths, so the paths that only some processors take get the
same scrutiny as the rest.

**Fast.** Where a processor has instructions for a primitive, scytale
uses them, through hand-written assembly rather than compiler
intrinsics, so the instruction order and register use can be tuned.
The block loops interleave enough independent work to keep pipelined
units busy, and a short buffer is handled in a single pass of the
right width rather than one block at a time.

**Portable.** Every primitive has a pure Rust implementation that
works anywhere, with no lookup tables and no data-dependent branches,
so it is constant time. The accelerated versions are additions to
that, never a requirement.

**No setup.** The library is `no_std`, has two dependencies
(`zeroize`, and `getrandom` where there is an operating system to
ask), and builds with nothing but a stable Rust toolchain: no
C compiler, no build script, no feature flags, no target-specific
compiler options. Which implementation to run is decided at run time,
by asking the processor what it supports, so one binary works across
a whole architecture.

## Supported algorithms

| Algorithm | Key sizes | Notes |
| --- | --- | --- |
| AES (FIPS 197) | 128, 192, 256 | the block cipher itself |

| Hash | Digest | Notes |
| --- | --- | --- |
| SHA-224, SHA-256 (FIPS 180-4) | 28, 32 bytes | the 32-bit family |
| SHA-384, SHA-512 | 48, 64 bytes | the 64-bit family |
| SHA-512/224, SHA-512/256 | 28, 32 bytes | truncated; no length extension |

All six take bit strings as well as bytes, as the standard defines
them. Built on any of them:

| Construction | Kind | Notes |
| --- | --- | --- |
| HMAC (FIPS 198-1) | message authentication | constant-time verify |
| HKDF (RFC 5869) | key derivation | from a secret that is already random |
| PBKDF2 (SP 800-132) | key derivation | from a password |

Every mode below is generic: it wraps any block cipher, and AES is
simply the one there is so far.

| Mode | Kind | Notes |
| --- | --- | --- |
| CBC | confidentiality | whole blocks only; no padding |
| CFB1, CFB8, CFB128 | confidentiality | the three NIST segment sizes |
| OFB | confidentiality | |
| CTR | confidentiality | |
| GCM | authenticated | GMAC is GCM with no plaintext |
| GCM-SIV | authenticated | survives a repeated nonce (RFC 8452) |
| XPN | authenticated | GCM under a MACsec extended packet number |
| XTS | disk sectors | ciphertext stealing for a partial block |
| FF1, FF3-1 | format preserving | see their documentation first |
| KW, KWP | key wrapping | deterministic; for keys, not messages |

## Random numbers

Keys and initialisation vectors need randomness, so `scytale::random`
provides a generator you hold:

```rust
use scytale::random::{Random, Rng, System};

let mut rng = Rng::try_new(System::try_new()?)?;
let mut key = [0u8; 32];
rng.fill(&mut key)?;
```

It is the CTR_DRBG of NIST SP 800-90A: AES-256 driven by a counter,
with its key and counter replaced after every request, checked
against the ACVP vectors for that mechanism alongside everything
else. Seed material of any length and any density is condensed by the
standard's derivation function, so entropy from a slow or biased
source is worth its full weight.

| Where it runs | What seeds it |
| --- | --- |
| Linux, Apple systems, the BSDs, Solaris, Windows | the operating system, through `getrandom` |
| Wasm | the host's crypto object, through the same |
| No operating system | `rdseed` or `rdrand`, `rndr`, or the `seed` register |
| Anywhere | entropy you supply, or hardware of your own |

The operating system is asked through the `getrandom` crate rather
than by writing out each kernel's interface here, which is the one
dependency beyond `zeroize`. It is not pulled in at all for a target
with no operating system, and on Linux with no C library it still
makes the system call directly. On wasm it reaches the surrounding
JavaScript, which costs every other target nothing: the binding is
asked for only on that target.

With no operating system there is nobody to ask but the processor.
Those instructions can fail without saying so, and parts have shipped
that return all ones while reporting success, so the raw samples are
health tested in the manner of SP 800-90B: a startup test of a
thousand samples when the source is constructed, and a repetition
count and adaptive proportion test on every sample after that. A
processor whose generator is dead or stuck yields no generator at all
rather than one that hands out its output.

Where the processor has no such instruction either, construction
fails and the program does not start, rather than every later call
failing. That is not the end of the road on such a board: a hardware
generator on a bus, a ring oscillator or a chip on I2C is supplied
through the `random::Entropy` trait, and entropy gathered some other
way goes in through `Rng::from_seed`. Either is served exactly as
well as a machine with an instruction for it.

Because the generator has state, it is yours to look after. After a
`fork`, or after a virtual machine is restored from a snapshot, the
state has been duplicated and the child must reseed or start again;
nothing here can detect that without asking the kernel on every call,
which is most of the reason to hold a generator at all. The state is
wiped when the generator is dropped.

Most initialisation vectors need to be *unique* rather than random,
which is a stronger requirement. `mode::Nonces` counts nonces for GCM
and GCM-SIV so a repeat is impossible rather than merely unlikely.

`encrypt_blocks` on the cipher itself encrypts each block
independently, which is ECB. On its own that is not a safe way to
encrypt a message, because equal blocks produce equal ciphertext. Use
a mode.

Key wrapping is the odd one out: it takes no nonce and is
deterministic, so wrapping the same key twice gives the same answer.
That is safe for a key, which cannot be guessed, and unsafe for
anything an attacker might guess and confirm. Its output is eight
bytes longer than its input, which is where the check value lives.

The two format-preserving modes are not constant time: they do
arithmetic in the caller's radix, and division is not a constant-time
instruction on any of these processors. Their documentation says so
too.

## Supported architectures

| Architecture | Acceleration used | For | Verified |
| --- | --- | --- | --- |
| x86-64 | VAES on 256-bit registers | AES | on hardware |
| x86-64 | AES-NI on 128-bit registers | AES | on hardware |
| x86-64 | PCLMULQDQ | GHASH | on hardware |
| aarch64 | ARMv8 cryptography extension | AES | under emulation |
| aarch64 | PMULL | GHASH | under emulation |
| riscv64 | vector cryptography (Zvkned) | AES | under emulation |
| riscv64 | scalar cryptography (Zkne, Zknd) | AES | under emulation |
| riscv64 | vector GHASH (Zvkg) | GHASH | under emulation |
| x86-64 | SHA-NI | SHA-256 | on hardware |
| aarch64 | ARMv8 SHA2 extension | SHA-256 | under emulation |
| aarch64 | ARMv8 SHA512 extension | SHA-512 | under emulation |
| riscv64 | scalar cryptography (Zknh) | SHA-256, SHA-512 | under emulation |
| any | none needed; portable Rust | all | on hardware |

GHASH is the hash inside GCM, GCM-SIV and XPN. Without a carry-less
multiply instruction it costs more than the cipher does. SHA-224 and
SHA-384 and the SHA-512/t pair use the SHA-256 and SHA-512 code, so
whatever accelerates those accelerates them. x86-64 has no SHA-512
instruction in common use, so SHA-512 is portable there.

Support is detected while the program runs: on x86-64 with CPUID, on
aarch64 by reading the ID registers, on RISC-V through the kernel's
`riscv_hwprobe` call. A processor without the instructions falls back
to the portable code.

## Using it

```rust
use scytale::symmetric::aes::Aes;

let aes = Aes::try_new(&key)?;

let mut block = [0u8; 16];
aes.encrypt_block(&mut block);
aes.decrypt_block(&mut block);

// Any whole number of blocks, each encrypted independently.
aes.encrypt_blocks(&mut buffer)?;
```

A mode wraps the cipher. Authenticated encryption returns a tag, and
decryption checks it before the plaintext is worth anything:

```rust
use scytale::symmetric::{aes::Aes, mode::Gcm};

let gcm = Gcm::try_new(Aes::try_new(&key)?)?;

let mut tag = [0u8; 16];
gcm.encrypt(&nonce, associated_data, &mut buffer, &mut tag)?;
gcm.decrypt(&nonce, associated_data, &mut buffer, &tag)?;
```

Every mode also has an incremental form for data that arrives in
pieces. Note that incremental decryption hands back plaintext before
the tag has been checked; the one-shot call above is the safe
default.

Hashes and MACs take their message in pieces or in one call, and a
MAC is checked with `verify`, never by comparing bytes yourself:

```rust
use scytale::hash::{sha2::Sha256, Hash};
use scytale::mac::{hmac::HmacSha256, Mac};

let digest = Sha256::digest(message)?;

let tag = HmacSha256::mac(&key, message)?;
let mut mac = HmacSha256::try_new(&key)?;
mac.update(message);
mac.verify(&tag)?;
```

`Sha256` and the rest pick the best implementation the processor
supports, as `Aes` does, and each implementation is reachable by name
under `hash::sha2::portable`, `x86_64`, `aarch64` and `riscv64`.

`Aes` picks the best implementation the processor supports, probing
once on first use. Each implementation can also be named directly:

| Type | Uses |
| --- | --- |
| `symmetric::aes::Aes` | the best of the below for this processor |
| `aes::x86_64::vaes::Aes` | VAES |
| `aes::x86_64::aesni::Aes` | AES-NI |
| `aes::aarch64::armv8::Aes` | ARMv8 cryptography extension |
| `aes::riscv64::zvkned::Aes` | RISC-V vector cryptography |
| `aes::riscv64::zkn::Aes` | RISC-V scalar cryptography |
| `aes::portable::bitsliced::Aes` | portable, constant time |
| `aes::portable::Aes` | portable, table driven; see below |

The architecture-specific types exist only on their architecture, and
their `try_new` returns `Error::NotSupported` when the processor
lacks the instructions. Every implementation wipes its expanded key
when dropped.

### Choosing an implementation

Prefer `Aes` unless you have a reason not to.

It never chooses `portable::Aes`, the table-driven version. That one
is about twice the speed of the bitsliced code, but its memory access
pattern depends on the key, which leaks the key to an attacker who
can measure the timing, typically by running code on the same
processor. Use it only where nothing untrusted runs, and read the
notes in its documentation first.

## Speed

Measured on a 13th Gen Intel Core i7-1355U, encrypting 4 KB buffers:

| Implementation | AES-128 | AES-256 |
| --- | --- | --- |
| `vaes` | 30 GB/s | 21 GB/s |
| `aesni` | 15 GB/s | 11 GB/s |
| `portable` (tables) | 500 MB/s | 360 MB/s |
| `portable::bitsliced` | 290 MB/s | 210 MB/s |

Short messages are not an afterthought: a buffer of eight blocks or
fewer costs 8 to 11 ns per call with AES-NI.

The modes, on the same processor with AES-128 and 16 KB buffers.
Rates are bytes, counted in millions and thousands of millions:

| Mode | Speed |
| --- | --- |
| CBC decrypt | 16 GB/s |
| CTR | 3.5 GB/s |
| XTS | 2.6 GB/s |
| GCM | 2.7 GB/s |

CBC encryption, OFB and CFB encryption are serial by definition: each
block waits for the one before it, so they run at the speed of single
blocks and no amount of interleaving helps.

The ARM and RISC-V implementations have only been run under
emulation, so there are no timings for them.

## Testing

```sh
cargo test              # unit tests and the one-shot vector suites
cargo test-extended     # adds the Monte Carlo suites, which are slow
scripts/test-all-arches # every architecture, foreign ones emulated
```

The ACVP vectors live in `scytale/tests/vectors` and are not shipped
in the published crate, to keep it small. Building and using the
library never needs them; running the tests from a downloaded crate
skips the ACVP suites and leaves the FIPS 197 and NIST SP 800-38A
vectors, which are built into the tests, as the check.

`scripts/test-all-arches` runs the host architecture directly and the
others with [cross](https://github.com/cross-rs/cross), which needs
Podman or Docker. It is a development convenience; nothing about it
affects users of the library.

## License

BSD 2-Clause. See `LICENSE`.

The test vectors under `scytale/tests/vectors` come from the NIST
ACVP-Server project and carry their own notice, in `LICENSE.txt`
beside them.
