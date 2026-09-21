//! Hashes: SHA-1 for old protocols, and SHA-2.
//!
//! An [`Algorithm`] is a `static` that names a hash; a [`Context`]
//! hashes with it.

use core::fmt;

use scytale::hash::Hash;
use scytale::hash::sha1::Sha1;
use scytale::hash::sha2::{Sha256, Sha384, Sha512, Sha512_256};

/// Which hash an [`Algorithm`] is. It is also what [`Debug`] prints,
/// in ring's spelling.
#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Id {
    SHA1,
    SHA256,
    SHA384,
    SHA512,
    SHA512_256,
}

/// A hash algorithm. The only values are the `static`s in this
/// module.
pub struct Algorithm {
    pub(crate) id: Id,
    output_len: usize,
    chaining_len: usize,
    block_len: usize,
}

impl Algorithm {
    /// The length of the block the hash compresses, in bytes.
    pub fn block_len(&self) -> usize {
        self.block_len
    }

    /// The length of the hash's internal state, in bytes: more than the
    /// output for the truncated SHA-512 forms.
    pub fn chaining_len(&self) -> usize {
        self.chaining_len
    }

    /// The length of a digest, in bytes.
    pub fn output_len(&self) -> usize {
        self.output_len
    }
}

impl PartialEq for Algorithm {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for Algorithm {}

impl fmt::Debug for Algorithm {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(&self.id, f)
    }
}

/// SHA-1. Broken for collision resistance; only for protocols that
/// still require it.
pub static SHA1_FOR_LEGACY_USE_ONLY: Algorithm = Algorithm {
    id: Id::SHA1,
    output_len: SHA1_OUTPUT_LEN,
    chaining_len: SHA1_OUTPUT_LEN,
    block_len: 64,
};

/// SHA-256.
pub static SHA256: Algorithm = Algorithm {
    id: Id::SHA256,
    output_len: SHA256_OUTPUT_LEN,
    chaining_len: SHA256_OUTPUT_LEN,
    block_len: 64,
};

/// SHA-384.
pub static SHA384: Algorithm = Algorithm {
    id: Id::SHA384,
    output_len: SHA384_OUTPUT_LEN,
    chaining_len: SHA512_OUTPUT_LEN,
    block_len: 128,
};

/// SHA-512.
pub static SHA512: Algorithm = Algorithm {
    id: Id::SHA512,
    output_len: SHA512_OUTPUT_LEN,
    chaining_len: SHA512_OUTPUT_LEN,
    block_len: 128,
};

/// SHA-512/256.
pub static SHA512_256: Algorithm = Algorithm {
    id: Id::SHA512_256,
    output_len: SHA512_256_OUTPUT_LEN,
    chaining_len: SHA512_OUTPUT_LEN,
    block_len: 128,
};

/// The longest block of any algorithm here.
pub const MAX_BLOCK_LEN: usize = 128;

/// The longest digest of any algorithm here.
pub const MAX_OUTPUT_LEN: usize = 64;

/// The longest internal state of any algorithm here.
pub const MAX_CHAINING_LEN: usize = MAX_OUTPUT_LEN;

/// The length of a SHA-1 digest.
pub const SHA1_OUTPUT_LEN: usize = 20;

/// The length of a SHA-256 digest.
pub const SHA256_OUTPUT_LEN: usize = 32;

/// The length of a SHA-384 digest.
pub const SHA384_OUTPUT_LEN: usize = 48;

/// The length of a SHA-512 digest.
pub const SHA512_OUTPUT_LEN: usize = 64;

/// The length of a SHA-512/256 digest.
pub const SHA512_256_OUTPUT_LEN: usize = 32;

/// The hash itself, one arm per algorithm.
#[derive(Clone)]
enum State {
    Sha1(Sha1),
    Sha256(Sha256),
    Sha384(Sha384),
    Sha512(Sha512),
    Sha512_256(Sha512_256),
}

/// A hash under way. Cloning it forks the computation, which is how a
/// running transcript hash is read without ending it.
#[derive(Clone)]
pub struct Context {
    state: State,
    algorithm: &'static Algorithm,
}

impl Context {
    /// A fresh hash with `algorithm`.
    pub fn new(algorithm: &'static Algorithm) -> Self {
        let state = match algorithm.id {
            Id::SHA1 => State::Sha1(Sha1::new()),
            Id::SHA256 => State::Sha256(Sha256::new()),
            Id::SHA384 => State::Sha384(Sha384::new()),
            Id::SHA512 => State::Sha512(Sha512::new()),
            Id::SHA512_256 => State::Sha512_256(Sha512_256::new()),
        };
        Context { state, algorithm }
    }

    /// Adds `data` to the message.
    pub fn update(&mut self, data: &[u8]) {
        match &mut self.state {
            State::Sha1(h) => h.update(data),
            State::Sha256(h) => h.update(data),
            State::Sha384(h) => h.update(data),
            State::Sha512(h) => h.update(data),
            State::Sha512_256(h) => h.update(data),
        }
    }

    /// The digest of everything added.
    pub fn finish(mut self) -> Digest {
        let out: &[u8] = match &mut self.state {
            State::Sha1(h) => &h.finalize(),
            State::Sha256(h) => &h.finalize(),
            State::Sha384(h) => &h.finalize(),
            State::Sha512(h) => &h.finalize(),
            State::Sha512_256(h) => &h.finalize(),
        };
        Digest::from_bytes(self.algorithm, out)
    }

    /// The algorithm this hashes with.
    pub fn algorithm(&self) -> &'static Algorithm {
        self.algorithm
    }
}

/// The digest of `data` with `algorithm`.
pub fn digest(algorithm: &'static Algorithm, data: &[u8]) -> Digest {
    let mut ctx = Context::new(algorithm);
    ctx.update(data);
    ctx.finish()
}

/// A finished digest.
#[derive(Clone, Copy)]
pub struct Digest {
    value: [u8; MAX_OUTPUT_LEN],
    algorithm: &'static Algorithm,
}

impl Digest {
    /// A digest scytale computed. `bytes` is one output long.
    pub(crate) fn from_bytes(
        algorithm: &'static Algorithm,
        bytes: &[u8],
    ) -> Self {
        let mut value = [0u8; MAX_OUTPUT_LEN];
        value[..bytes.len()].copy_from_slice(bytes);
        Digest { value, algorithm }
    }

    /// The algorithm that produced it.
    pub fn algorithm(&self) -> &'static Algorithm {
        self.algorithm
    }
}

impl AsRef<[u8]> for Digest {
    fn as_ref(&self) -> &[u8] {
        &self.value[..self.algorithm.output_len]
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}:", self.algorithm)?;
        crate::debug::write_hex_bytes(f, self.as_ref())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    extern crate std;
    use std::format;

    #[test]
    fn each_algorithm_gives_the_published_digest_of_abc() {
        let cases: [(&'static Algorithm, &str); 5] = [
            (
                &SHA1_FOR_LEGACY_USE_ONLY,
                "a9993e364706816aba3e25717850c26c9cd0d89d",
            ),
            (
                &SHA256,
                "ba7816bf8f01cfea414140de5dae2223\
                 b00361a396177a9cb410ff61f20015ad",
            ),
            (
                &SHA384,
                "cb00753f45a35e8bb5a03d699ac65007\
                 272c32ab0eded1631a8b605a43ff5bed\
                 8086072ba1e7cc2358baeca134c825a7",
            ),
            (
                &SHA512,
                "ddaf35a193617abacc417349ae204131\
                 12e6fa4e89a97ea20a9eeee64b55d39a\
                 2192992a274fc1a836ba3c23a3feebbd\
                 454d4423643ce80e2a9ac94fa54ca49f",
            ),
            (
                &SHA512_256,
                "53048e2681941ef99b2e29b76b4c7dab\
                 e4c2d0c634fc6d46e0e2f13107e7af23",
            ),
        ];
        for (algorithm, want) in cases {
            let d = digest(algorithm, b"abc");
            assert_eq!(d.as_ref().len(), algorithm.output_len());
            assert_eq!(format!("{:?}", d), format!("{algorithm:?}:{want}"));
        }
    }

    #[test]
    fn a_clone_continues_where_it_was_taken() {
        let mut ctx = Context::new(&SHA256);
        ctx.update(b"a");
        let fork = ctx.clone();
        ctx.update(b"bc");
        assert_eq!(ctx.finish().as_ref(), digest(&SHA256, b"abc").as_ref());
        assert_eq!(fork.finish().as_ref(), digest(&SHA256, b"a").as_ref());
    }

    #[test]
    fn algorithms_compare_and_print_by_name() {
        assert_eq!(SHA256, SHA256);
        assert_ne!(SHA256, SHA512_256);
        assert_eq!(format!("{SHA512_256:?}"), "SHA512_256");
        assert_eq!(SHA384.chaining_len(), 64);
        assert_eq!(SHA384.block_len(), 128);
    }
}
