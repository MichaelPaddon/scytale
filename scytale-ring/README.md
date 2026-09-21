# scytale-ring

[ring](https://crates.io/crates/ring) 0.17's API, with the work done by
[scytale](https://crates.io/crates/scytale).

This is not a fork of ring. None of ring's implementation is here, and
there is no C or assembly to build: every operation is a call into
scytale, which is portable Rust with hardware acceleration chosen at
run time. The library is named `ring`, so code written against ring
compiles unchanged.

## Using it

Replace ring in your own manifest:

```toml
[dependencies]
ring = { package = "scytale-ring", version = "0.17" }
```

That reaches your crate's own calls. It does not reach a dependency
that names ring itself, such as rustls or rustls-webpki: cargo's
`[patch]` matches a replacement by its real package name, and this
package is not called `ring`. Substituting it under such a crate means
editing that crate's manifest the same way.

## What is tested

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
- **Some key rejections give a different reason.** A key ring refuses
  is refused here too, but for a malformed PKCS#8 key the reason may be
  `InvalidEncoding` where ring names a more specific cause.
- **An ECDSA PKCS#8 key with no public key is accepted.** ring requires
  it; RFC 5915 makes it optional.
- **Not yet provided:** `aead::chacha20_poly1305_openssh`, `pbkdf2`,
  `pkcs8`, `io`, key generation into PKCS#8 (`generate_pkcs8`),
  `Ed25519KeyPair::from_pkcs8` (the version 2 only form), and ring's
  deprecated `test` and `constant_time` modules.
- **Minimum Rust is 1.88**, scytale's, where ring's is 1.66.

## Licence

BSD-2-Clause, as scytale.
