# scytale-ring

[ring](https://crates.io/crates/ring) 0.17's API, with the work done by
[scytale](https://crates.io/crates/scytale).

This is not a fork of ring. None of ring's implementation is here, and
there is no C or assembly to build: every operation is a call into
scytale, which is portable Rust with hardware acceleration chosen at
run time. The library is named `ring`, so code written against ring
compiles unchanged.

## Which ring

The version number is scytale's, since the two are released together,
so it says nothing about ring. This table does:

| scytale-ring | ring API | Tested with |
| --- | --- | --- |
| 0.8 | 0.17, checked against 0.17.14 | rustls 0.23.45, rustls-webpki 0.103.15 |

A new ring API arrives in a new scytale-ring minor version, and a row
here says so.

## Using it

Replace ring in your own manifest:

```toml
[dependencies]
ring = { package = "scytale-ring", version = "0.8" }
```

That reaches your crate's own calls. It does not reach a dependency
that names ring itself, such as rustls or rustls-webpki: cargo's
`[patch]` matches a replacement by its real package name, and this
package is not called `ring`. Substituting it under such a crate means
editing that crate's manifest the same way.

## What is tested

- ring's own test suite, every file of it, vendored unchanged under
  `ring-tests/` with its vector files and ring's licence beside them.
  Every test passes; nothing is skipped or altered.
- Unit tests for every module, against published vectors (FIPS 180,
  RFC 4231, RFC 5869, RFC 7748, RFC 8032, RFC 8439, RFC 9001) and
  against keys and signatures made by OpenSSL.
- rustls-webpki 0.103 and rustls 0.23 run their own test suites with
  this crate as their ring, by `scripts/test-ring-downstream` in the
  scytale repository.

## Where it differs from ring

- **ECDSA signatures are deterministic** (RFC 6979). ring draws a
  random nonce. Signatures from either verify under the other, but
  a test that compares signature bytes with stored ones will not
  match. The random source ring's signing calls take is accepted and
  not used.
- **Keys ring's old versions wrote are read.** ring 0.16 wrote Ed25519
  PKCS#8 with the public key under the wrong tag, and ring still reads
  them; so does this crate, by repairing that one element before
  scytale reads the key. scytale itself refuses them.
- **Minimum Rust is 1.88**, scytale's, where ring's is 1.66.

## Licence

BSD-2-Clause, as scytale.
