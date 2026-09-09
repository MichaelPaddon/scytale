# scytale

[![CI][ci-badge]][ci]
[![crates.io][version-badge]][crate]
[![docs.rs][docs-badge]][docs]
[![MSRV][msrv-badge]][crate]
[![BSD-2-Clause][license-badge]][license]

[ci-badge]: https://github.com/MichaelPaddon/scytale/actions/workflows/ci.yml/badge.svg?branch=main
[ci]: https://github.com/MichaelPaddon/scytale/actions/workflows/ci.yml
[version-badge]: https://img.shields.io/crates/v/scytale.svg
[crate]: https://crates.io/crates/scytale
[docs-badge]: https://docs.rs/scytale/badge.svg
[docs]: https://docs.rs/scytale
[msrv-badge]: https://img.shields.io/crates/msrv/scytale.svg
[license-badge]: https://img.shields.io/crates/l/scytale.svg
[license]: https://github.com/MichaelPaddon/scytale/blob/main/LICENSE

Correct, fast, portable cryptography in Rust: ciphers and the modes
over them, hashes, message authentication, key derivation, key
agreement, public-key encryption, signatures, post-quantum key
encapsulation and signatures, and random numbers. It is `no_std`, has
two dependencies, needs no C compiler and no build script, and has no
feature flags to get wrong.

## The name

A [scytale][wiki] is a rod. The Spartans wound a strip of leather
around one and wrote the message along the rod, so that unwound the
strip carries a column of unrelated letters and reads again only when
it is wound on a rod of the same diameter. The key is a physical
dimension, and the ciphertext is a strip of leather a courier can
wear.

Whether it was ever really used to keep a secret is disputed: the
surviving accounts fit a device for proving that a message came from
whoever held the matching rod at least as well as they fit a cipher.
The earliest cryptographic instrument we have a name for may have
been a message authentication code.

Say it SKIT-uh-lee, to rhyme with Italy: that is what the
dictionaries give and what the author says.

The Greek is σκυτάλη, skutale, a staff or a baton, from σκύταλον,
skutalon, the same thing. An Athenian would have said it about
sku-TA-leh: the first vowel is the rounded one English lacks and
French writes as the u of tu, the last is a long open e, and the mark
over the alpha was a rise in pitch rather than a stress, so the word
lifted in the middle instead of leaning on it. It is still a living
word. In modern Greek, said skee-TAH-lee, a skutale is the baton a
relay runner hands to the next, which is very nearly where the
English ended up.

[wiki]: https://en.wikipedia.org/wiki/Scytale

## Status

The algorithm set is complete enough to build serious applications
on: encryption and authenticated encryption, hashes and MACs, key
derivation, key agreement, public-key encryption, signatures, the
three post-quantum families, a validated random generator, and the
key formats other software stores keys in.

It is tested to the same extent. The standards' own vectors are built
into the unit tests, and on top of them run the NIST ACVP suites and
the Project Wycheproof files, close to sixty thousand vector cases
before the Monte Carlo suites add several million chained calls of
their own. Every implementation of a primitive is put through the
whole vector set for it, at every key size, and the whole suite runs
on x86-64, aarch64 and riscv64 hardware rather than on the machine
that happens to be to hand. The Goals section below says exactly what that
means.

Work from here goes into speed and into algorithms that are still
missing, not into rearranging what is already here. API changes will
be avoided; the version number is below one, but the shape of the
library is not expected to move.

It builds on stable Rust 1.88 or later, on any architecture,
with or without an operating system under it.

## Trying it

```sh
cargo add scytale
```

```rust
use scytale::cipher::{aes::Aes256, mode::Gcm};
use scytale::random::{Rng, System};
use scytale::{KeyType, Random};

let mut rng = Rng::try_new(System::try_new()?)?;
let key = Aes256::random_key(&mut rng)?;
let mut nonce = [0u8; 12];
rng.fill(&mut nonce)?;

let gcm = Gcm::<Aes256>::new(&key);
let header = b"to: alice";
let mut message = *b"attack at dawn";
let mut tag = [0u8; 16];

gcm.encrypt(&nonce, header, &mut message, &mut tag)?;
gcm.decrypt(&nonce, header, &mut message, &tag)?;
assert_eq!(&message, b"attack at dawn");
```

That is the whole setup: no builder, no context object, no global
state to initialise, and no choice to make about which implementation
to run. `Aes256` asks the processor what it can do the first time a
key is expanded, and every call after that is one predictable branch.
The same binary does that on a laptop with VAES and on a board with
no cryptographic instructions at all.

The API documentation is on [docs.rs](https://docs.rs/scytale), and
`cargo doc --open` builds it locally with your own processor's
modules in it.

## Goals

**Correct.** Every implementation is checked against the standard
test vectors, against the NIST Automated Cryptographic Validation
Program (ACVP) vectors, and against Project Wycheproof, whose cases
are chosen to break implementations rather than to exercise them:
56,078 one-shot cases and 3600 Monte Carlo steps, the latter being
3.6 million chained cipher calls with the key re-derived at each
step. Every implementation of a primitive is put through the whole
vector set for it, at every key size; the modes and constructions
built on top run once each, on the implementation the processor
picks. Every implementation is also compared byte for byte against
the portable one across a range of buffer lengths, so the paths that
only some processors take get the same scrutiny as the rest.

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

Every public module is named for the job a caller wants done, not for
the machinery behind it:

| Module | Job | Algorithms |
| --- | --- | --- |
| `cipher` | encryption | AES, ChaCha20, and the modes built on them |
| `hash` | digests | SHA-2, SHA-3, SHAKE; SHA-1 for what still names it |
| `mac` | message authentication | HMAC, Poly1305 |
| `kdf` | key derivation | HKDF, PBKDF2 |
| `kem` | key encapsulation | ML-KEM-512, -768 and -1024 |
| `kex` | key agreement | X25519, ECDH over P-256 and P-384 |
| `pke` | public-key encryption | RSA-OAEP |
| `sig` | signatures | Ed25519, ECDSA over P-256 and P-384, ML-DSA, SLH-DSA, RSA-PSS, RSA PKCS#1 v1.5 |
| `random` | random numbers | CTR_DRBG over AES-256, and what seeds it |

### Ciphers

| Algorithm | Key sizes | Notes |
| --- | --- | --- |
| AES (FIPS 197) | 128, 192, 256 | the block cipher itself |
| ChaCha20 (RFC 8439) | 256 | a stream cipher; no tables, no AES needed |

Every mode below is generic: it wraps any block cipher, and AES is
simply the one there is so far. The key width is part of the type,
`Aes128`, `Aes192` or `Aes256`, so a key of the wrong length is a
compile error rather than a run-time one.

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

And one that wraps no block cipher:

| Mode | Kind | Notes |
| --- | --- | --- |
| ChaCha20-Poly1305 (RFC 8439) | authenticated | GCM's equal; faster without AES hardware |

`encrypt_blocks` on the cipher itself encrypts each block
independently, which is ECB. On its own that is not a safe way to
encrypt a message, because equal blocks produce equal ciphertext. Use
a mode.

Most initialisation vectors need to be *unique* rather than random,
which is a stronger requirement. `mode::Nonces` counts nonces for GCM
and GCM-SIV so a repeat is impossible rather than merely unlikely.

Key wrapping is the odd one out: it takes no nonce and is
deterministic, so wrapping the same key twice gives the same answer.
That is safe for a key, which cannot be guessed, and unsafe for
anything an attacker might guess and confirm. Its output is eight
bytes longer than its input, which is where the check value lives.

The two format-preserving modes are not constant time: they do
arithmetic in the caller's radix, and division is not a constant-time
instruction on any of these processors. Their documentation says so
too.

### Hashes

| Hash | Digest | Notes |
| --- | --- | --- |
| SHA-224, SHA-256 (FIPS 180-4) | 28, 32 bytes | the 32-bit family |
| SHA-384, SHA-512 | 48, 64 bytes | the 64-bit family |
| SHA-512/224, SHA-512/256 | 28, 32 bytes | truncated; no length extension |
| SHA3-224 to SHA3-512 (FIPS 202) | 28 to 64 bytes | no length extension |
| SHAKE128, SHAKE256 | any length | extendable output |
| SHA-1 (FIPS 180-4) | 20 bytes | broken for collisions; for HMAC, HKDF and OAEP in old protocols only |

All of them take bit strings as well as bytes, as the standards
define them.

### Message authentication

| Construction | Notes |
| --- | --- |
| HMAC (FIPS 198-1) | over any hash; constant-time verify |
| Poly1305 (RFC 8439) | one-time key; for the AEAD |

### Key derivation

| Construction | Notes |
| --- | --- |
| HKDF (RFC 5869) | over any hash; from a secret that is already random |
| PBKDF2 (SP 800-132) | over any hash; from a password |

### Key encapsulation, key agreement, public-key encryption and signatures

Four jobs, four modules. RSA does two of them, and its signing and
encryption keys are distinct types: a key does one job.

| Algorithm | Module | Notes |
| --- | --- | --- |
| ML-KEM (FIPS 203), all three sets | `kem` | post-quantum; implicit rejection; seed and expanded keys |
| X25519 (RFC 7748) | `kex` | shared secret needs HKDF; refuses low-order keys |
| ECDH (SP 800-56A) over P-256, P-384 | `kex` | every public key checked on the curve; compressed points read |
| RSA-OAEP (RFC 8017) | `pke` | constant-time unpadding; no v1.5 decryption, ever |
| Ed25519 (RFC 8032) | `sig` | deterministic; refuses malleable signatures |
| ECDSA (FIPS 186-5) over P-256, P-384 | `sig` | RFC 6979 nonces; r \|\| s and DER signature forms |
| RSA-PSS, RSA PKCS#1 v1.5 (RFC 8017) | `sig` | any width; CRT signing and key generation |
| ML-DSA (FIPS 204), all three sets | `sig` | post-quantum; hedged or deterministic; context strings |
| SLH-DSA (FIPS 205), all twelve sets | `sig` | post-quantum, hash-based; hedged or deterministic; context strings |
| RSA primitives (RFC 8017) | `sig`, `pke` | raw, unpadded; for building schemes and for validation |

Every key reads and writes the formats other software stores it in:
a public key as a DER `SubjectPublicKeyInfo`, a private key as
PKCS#8, RSA keys in the bare PKCS#1 forms too, and any of them in
PEM. Encrypted keys are not read.

## Random numbers

Keys and initialisation vectors need randomness, so `scytale::random`
provides a generator you hold:

```rust
use scytale::cipher::aes::Aes256;
use scytale::random::{Rng, System};
use scytale::{KeyType, Random};

let mut rng = Rng::try_new(System::try_new()?)?;

// A key of the right width for the cipher, which wipes itself.
let key = Aes256::random_key(&mut rng)?;

// Or bytes for anything else.
let mut nonce = [0u8; 12];
rng.fill(&mut nonce)?;
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

## Supported architectures

| Architecture | Acceleration used | For |
| --- | --- | --- |
| x86-64 | VAES on 256-bit registers | AES |
| x86-64 | AES-NI on 128-bit registers | AES |
| x86-64 | PCLMULQDQ | GHASH |
| aarch64 | ARMv8 cryptography extension | AES |
| aarch64 | PMULL | GHASH |
| riscv64 | vector cryptography (Zvkned) | AES |
| riscv64 | scalar cryptography (Zkne, Zknd) | AES |
| riscv64 | vector GHASH (Zvkg) | GHASH |
| x86-64 | SHA-NI | SHA-256 |
| aarch64 | ARMv8 SHA2 extension | SHA-256 |
| aarch64 | ARMv8 SHA512 extension | SHA-512 |
| riscv64 | scalar cryptography (Zknh) | SHA-256, SHA-512 |
| aarch64 | ARMv8 SHA3 extension | SHA-3, SHAKE |
| x86-64 | AVX2 | ChaCha20 |
| aarch64 | NEON | ChaCha20 |
| riscv64 | vector extension with Zvbb | ChaCha20 |
| any | none needed; portable Rust | all |

Every row is exercised on real silicon: the continuous integration
matrix runs the whole test suite natively on x86-64, arm64 and
riscv64 runners, with no emulation, so the assembly for each is run
by the processor it was written for.

GHASH is the hash inside GCM, GCM-SIV and XPN. Without a carry-less
multiply instruction it costs more than the cipher does. SHA-224 and
SHA-384 and the SHA-512/t pair use the SHA-256 and SHA-512 code, so
whatever accelerates those accelerates them. x86-64 has no SHA-512
instruction in common use, so SHA-512 is portable there. Every SHA-3
and SHAKE function is the one Keccak permutation, which only AArch64
has instructions for; elsewhere it is portable. ChaCha20 needs no
special instructions, only a vector unit: several blocks are computed
at once, eight with AVX2, four with NEON, and as many as a register
holds on RISC-V. Poly1305 is portable everywhere.

Support is detected while the program runs: on x86-64 with CPUID, on
aarch64 by reading the ID registers, on RISC-V through the kernel's
`riscv_hwprobe` call. A processor without the instructions falls back
to the portable code.

## Documentation

The API documentation for the main branch, one copy per architecture
so that each processor's own modules can be read, is at
<https://michaelpaddon.github.io/scytale/>. Released versions are on
[docs.rs](https://docs.rs/scytale). Locally, `cargo doc --open`.

## Using it

```rust
use scytale::cipher::aes::Aes128;

let aes = Aes128::try_new(&key)?; // key: [u8; 16]

let mut block = [0u8; 16];
aes.encrypt_block(&mut block);
aes.decrypt_block(&mut block);

// Any number of blocks, each encrypted independently.
aes.encrypt_blocks(&mut blocks); // blocks: [[u8; 16]; N]
```

A mode wraps the cipher. Authenticated encryption returns a tag, and
decryption checks it before the plaintext is worth anything:

```rust
use scytale::cipher::{aes::Aes128, mode::Gcm};

let gcm = Gcm::<Aes128>::new(&key);

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

### One type per algorithm

`Aes128`, `Aes192` and `Aes256` are the ciphers; `Sha256`,
`Sha3_256`, `Shake128` and the rest are the hashes. Each picks the
best implementation this processor supports, probing once on first
use, and then dispatches with a single predictable branch.

Which implementation that is is not a choice a caller makes. The
implementations are private: hardware instructions where the
processor has them, otherwise constant-time portable code. There is a
table-driven AES in the crate that is about twice the speed of the
constant-time portable one, and it is never chosen, because it
indexes tables with bytes derived from the key and so leaks the key
to an attacker who can measure cache timing. A way for an application
that runs nothing untrusted to ask for it by name is still to be
designed.

### Keys wipe themselves

A key is a `Key<[u8; 16]>`, not a `[u8; 16]`. It wipes itself when
it goes out of scope, and it is not `Copy`, so a second copy of a
key is something someone wrote rather than something that happened.
The type carries the width, so the wrong one will not compile.

```rust
use scytale::cipher::aes::Aes128;
use scytale::{Key, KeyType};

let key = Aes128::random_key(&mut rng)?;   // drawn and protected
let key = Key::from([0u8; 16]);            // from bytes you have
let key = Key::take(&mut bytes);           // and wipe where they were
```

`Key::take` is the one worth reaching for when a key arrives in a
buffer of your own: the buffer is the copy that nothing else would
erase.

The expanded key inside a cipher is wiped when the cipher is
dropped, as it always was, and the generator wipes its state.

## Speed

Measured on a 13th Gen Intel Core i7-1355U, one thread, on mains
power. The benchmark ships with the library, so these are numbers you
can reproduce: `scripts/bench`. Every figure below is a
row it prints, and it prints rather more than are quoted here. On a
laptop running on battery, expect about half of each of them.

### The ciphers

AES itself, over 8 KB buffers:

| Implementation | AES-128 | AES-256 |
| --- | --- | --- |
| `vaes` | 28 GB/s | 20 GB/s |
| `aesni` | 14 GB/s | 10 GB/s |
| `ttable` | 490 MB/s | 360 MB/s |
| `bitsliced` | 280 MB/s | 210 MB/s |

Short messages are not an afterthought: a buffer of eight blocks or
fewer costs 8 to 11 ns per call with AES-NI.

ChaCha20 needs no cipher instructions, only a vector unit: 2.8 GB/s
with AVX2 and 790 MB/s portable. On a processor with no AES hardware
it is several times faster than any AES here, which is what it is
for.

### The modes

AES-128 over 16 KB buffers, on the implementation the processor
picks. Rates are bytes, counted in millions and thousands of
millions:

| Mode | Speed |
| --- | --- |
| CBC encrypt | 1.9 GB/s |
| CBC decrypt | 15 GB/s |
| CFB1 | 7.4 MB/s |
| CFB8 | 83 MB/s |
| CFB128 | 1.6 GB/s |
| OFB | 2.0 GB/s |
| CTR | 12 GB/s |
| GMAC | 11 GB/s |
| GCM | 5.9 GB/s |
| GCM-SIV | 1.3 GB/s |
| XPN | 5.5 GB/s |
| XTS | 8.4 GB/s |
| KW, KWP | 116 MB/s |
| ChaCha20-Poly1305 | 1.4 GB/s |

CBC encryption, OFB and the CFB modes are serial by definition: each
block waits for the one before it, so they run at the speed of single
blocks and no amount of interleaving helps. CFB1 is a block operation
per bit, which is the two orders of magnitude between it and CFB128.
Key wrapping passes over its input six times, by construction, and is
meant for keys rather than for messages.

### Hashes and message authentication

Over 16 KB buffers:

| Function | Implementation | Speed |
| --- | --- | --- |
| SHA-1 | `portable` | 560 MB/s |
| SHA-256 | `shani` | 2.4 GB/s |
| SHA-256 | `portable` | 330 MB/s |
| SHA-512 | `portable` | 520 MB/s |
| SHA3-256 | `portable` | 540 MB/s |
| SHA3-512 | `portable` | 270 MB/s |
| SHAKE128 | `portable` | 640 MB/s |
| SHAKE256 | `portable` | 520 MB/s |
| HMAC-SHA-256 | `shani` | 2.3 GB/s |
| HMAC-SHA-512 | `portable` | 540 MB/s |
| Poly1305 | `portable` | 3.0 GB/s |
| CTR_DRBG | `vaes` | 930 MB/s |

SHA-224, SHA-384 and the SHA-512/t pair run at the speed of the
function whose code they share.

### Key derivation

One derivation of a 32-byte key:

| Function | Time |
| --- | --- |
| HKDF-SHA-256 | 0.6 us |
| HKDF-SHA-512 | 2.6 us |
| PBKDF2-HMAC-SHA-256, 100,000 iterations | 13 ms |
| PBKDF2-HMAC-SHA-512, 100,000 iterations | 63 ms |

PBKDF2 is slow on purpose, and its cost is the iteration count and
nothing else. The two figures are what a login path costs at a round
number of iterations; choose the count from the time you are willing
to spend, not from this table.

### Key agreement, signatures and encryption

One operation, in microseconds:

| Operation | Time |
| --- | --- |
| X25519 key generation | 29 us |
| X25519 agreement | 29 us |
| ECDH P-256 key generation | 40 us |
| ECDH P-256 agreement | 97 us |
| ECDH P-384 key generation | 107 us |
| ECDH P-384 agreement | 290 us |
| Ed25519 key generation | 57 us |
| Ed25519 sign | 115 us |
| Ed25519 verify | 113 us |
| ECDSA P-256 sign | 50 us |
| ECDSA P-256 verify | 135 us |
| ECDSA P-384 sign | 140 us |
| ECDSA P-384 verify | 393 us |
| RSA-2048 PSS sign | 910 us |
| RSA-2048 PSS verify | 158 us |
| RSA-2048 OAEP encrypt | 159 us |
| RSA-2048 OAEP decrypt | 915 us |

Signing and key generation on the prime curves multiply the base
point, which is known in advance and has a table of its multiples
built in; agreement and verification multiply a point that arrives at
run time and cannot. That is the whole distance between the 50 us
ECDSA signature and the 135 us verification of it, and it is why
Ed25519, which has no such table here yet, signs more slowly than
P-256 while verifying faster.

### Post-quantum

| Parameter set | Key generation | Encapsulate | Decapsulate |
| --- | --- | --- | --- |
| ML-KEM-512 | 23 us | 25 us | 32 us |
| ML-KEM-768 | 40 us | 40 us | 49 us |
| ML-KEM-1024 | 60 us | 60 us | 72 us |

| Parameter set | Key generation | Sign | Verify |
| --- | --- | --- | --- |
| ML-DSA-44 | 65 us | 607 us | 65 us |
| ML-DSA-65 | 126 us | 385 us | 105 us |
| ML-DSA-87 | 182 us | 332 us | 178 us |
| SLH-DSA-SHA2-128s | 33 ms | 252 ms | 246 us |
| SLH-DSA-SHA2-128f | 503 us | 11.7 ms | 699 us |

ML-DSA signing repeats until a candidate passes, so its cost depends
on the message and not only on the parameter set: ML-DSA-44 being the
slowest to sign here is that, not a mistake. SLH-DSA has twelve
parameter sets; the two shown are the small and the fast end of the
128-bit ones, and they are the whole trade the family offers, a
signature small and slow or large and quick.

### Format-preserving encryption

| Mode | Time |
| --- | --- |
| FF1, sixteen digits base 10 | 1.2 ms |
| FF3-1, sixteen digits base 10 | 362 us |

Both are ten rounds of a Feistel network over the caller's radix, and
FF1 does more work per round.

The benchmark has only been run on this x86-64 machine, so there are
no timings for the ARM and RISC-V implementations.

## Testing

```sh
cargo test              # unit tests and the one-shot vector suites
cargo test-extended     # adds the Monte Carlo and large data suites
scripts/test-all-arches # every architecture, foreign ones emulated
scripts/bench           # measures rather than checks
```

The suites live inside the crate, under `#[cfg(test)]`, rather than
in `tests/`: an integration test is a separate crate and would see
only the public types, and each implementation behind them is meant
to be validated in its own right. The benchmark is there for the same
reason, and runs as an ignored test that `scripts/bench` starts.

The ACVP and Project Wycheproof vectors live in
`scytale/tests/vectors` and are not shipped in the published crate,
to keep it small. Building and using the library never needs them;
running the tests from a downloaded crate skips those suites and
leaves the standards' own vectors, which are built into the unit
tests, as the check. The public-key algorithms run against both:
ACVP's ML-KEM, ML-DSA, SLH-DSA, RSA, KTS-IFC, ECDSA, EDDSA, XECDH and
KDA suites, and Wycheproof's ML-KEM, ML-DSA, ECDH, ECDSA, X25519,
Ed25519, RSA signature and RSA-OAEP files, whose deliberately twisted
cases are the point. The
deterministic ECDSA suite checks signatures byte for byte, since RFC
6979 fixes the nonce. RSA is the one algorithm whose raw
primitives NIST publishes vectors for, and those run too: they are the
only external check on a value the crate produces under a private
exponent rather than merely verifies.

`scripts/test-all-arches` runs the host architecture directly and the
others with [cross](https://github.com/cross-rs/cross), which needs
Podman or Docker. It is a development convenience; nothing about it
affects users of the library.

## License

BSD 2-Clause. See `LICENSE`.

The test vectors under `scytale/tests/vectors` come from the NIST
ACVP-Server project and carry their own notice, in `LICENSE.txt`
beside them.
