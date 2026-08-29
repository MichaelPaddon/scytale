//! The SHA-2 family (FIPS 180-4): SHA-224, SHA-256, SHA-384 and
//! SHA-512.
//!
//! Two functions, really. SHA-256 works in 32-bit words over 64-byte
//! blocks and SHA-512 in 64-bit words over 128-byte blocks; SHA-224
//! and SHA-384 are those two with a different starting value and a
//! shortened digest. The four types here pick the best implementation
//! the processor has, and each implementation is also reachable by
//! name under [`portable`] and the architecture modules beside it.
//!
//! ```
//! use scytale::hash::sha2::Sha256;
//! use scytale::hash::Hash;
//!
//! # fn main() -> Result<(), scytale::Error> {
//! let mut hash = Sha256::new();
//! hash.update(b"ab");
//! hash.update(b"c");
//! assert_eq!(hash.finalize(), Sha256::digest(b"abc")?);
//! # Ok(())
//! # }
//! ```
//!
//! SHA-512/224 and SHA-512/256 (FIPS 180-4 section 5.3.6) are
//! SHA-512 with another starting value and a shorter digest, which
//! makes them the same cost as SHA-512: on a 64-bit processor without
//! SHA-256 instructions that is faster than SHA-256, and their output
//! cannot be extended the way SHA-256's can, since most of the final
//! state is thrown away.
//!
//! # Bit strings
//!
//! SHA-2 is defined over bit strings. A message that is not a whole
//! number of bytes ends with [`BitHash::finalize_bits`], which takes
//! the last few bits; everything before them goes through
//! [`Hash::update`] as bytes. That is where the standard puts the
//! difference too: only the padding counts bits, so the byte path
//! costs nothing for it.
//!
//! # Speed
//!
//! Each block's state depends on the one before it, so a single
//! message cannot be spread across lanes; the processors that have
//! SHA instructions (SHA-NI on x86-64, the ARMv8 SHA2 and SHA512
//! extensions, RISC-V Zknh) make each round cheaper instead, and are
//! several times the speed of the portable code. x86-64 has no
//! SHA-512 instruction in common use yet, so SHA-384 and SHA-512 are
//! portable there.
//!
//! # Not a MAC
//!
//! See [the module above](crate::hash#not-a-mac): a key in front of
//! the message does not make a MAC.

#[cfg(target_arch = "aarch64")]
pub mod aarch64;
pub mod engine;
pub mod portable;
#[cfg(target_arch = "riscv64")]
pub mod riscv64;
#[cfg(target_arch = "x86_64")]
pub mod x86_64;

use core::fmt;
use core::sync::atomic::{AtomicU8, Ordering};

#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
use engine::Compress64;
use engine::{Compress32, Engine32, Engine64, Variant32, Variant64};

use crate::hash::{BitHash, Hash};
use crate::Error;

/// The members of the family, as markers the engines are generic
/// over. Each says only where the hash starts and how much of the
/// final state is the digest.
pub mod variant {
    use super::engine::Sealed;
    use super::{Variant32, Variant64};

    impl Sealed for Sha224 {}
    impl Sealed for Sha256 {}
    impl Sealed for Sha384 {}
    impl Sealed for Sha512 {}
    impl Sealed for Sha512_224 {}
    impl Sealed for Sha512_256 {}

    /// SHA-224.
    #[derive(Clone, Copy, Debug)]
    pub struct Sha224;

    /// SHA-256.
    #[derive(Clone, Copy, Debug)]
    pub struct Sha256;

    /// SHA-384.
    #[derive(Clone, Copy, Debug)]
    pub struct Sha384;

    /// SHA-512.
    #[derive(Clone, Copy, Debug)]
    pub struct Sha512;

    /// SHA-512/224.
    #[derive(Clone, Copy, Debug)]
    pub struct Sha512_224;

    /// SHA-512/256.
    #[derive(Clone, Copy, Debug)]
    pub struct Sha512_256;

    impl Variant32 for Sha224 {
        // The low halves of SHA-384's initial value.
        const IV: [u32; 8] = [
            0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31,
            0x68581511, 0x64f98fa7, 0xbefa4fa4,
        ];
        type Output = [u8; 28];
    }

    impl Variant32 for Sha256 {
        // The fractional parts of the square roots of the first eight
        // primes.
        const IV: [u32; 8] = [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f,
            0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
        ];
        type Output = [u8; 32];
    }

    impl Variant64 for Sha384 {
        // The ninth to sixteenth primes.
        const IV: [u64; 8] = [
            0xcbbb9d5dc1059ed8,
            0x629a292a367cd507,
            0x9159015a3070dd17,
            0x152fecd8f70e5939,
            0x67332667ffc00b31,
            0x8eb44a8768581511,
            0xdb0c2e0d64f98fa7,
            0x47b5481dbefa4fa4,
        ];
        type Output = [u8; 48];
    }

    impl Variant64 for Sha512 {
        const IV: [u64; 8] = [
            0x6a09e667f3bcc908,
            0xbb67ae8584caa73b,
            0x3c6ef372fe94f82b,
            0xa54ff53a5f1d36f1,
            0x510e527fade682d1,
            0x9b05688c2b3e6c1f,
            0x1f83d9abfb41bd6b,
            0x5be0cd19137e2179,
        ];
        type Output = [u8; 64];
    }

    // The SHA-512/t values are SHA-512 of the string "SHA-512/t",
    // started from SHA-512's value with every byte xored with 0xa5;
    // the tests below derive them again.
    impl Variant64 for Sha512_224 {
        const IV: [u64; 8] = [
            0x8c3d37c819544da2,
            0x73e1996689dcd4d6,
            0x1dfab7ae32ff9c82,
            0x679dd514582f9fcf,
            0x0f6d2b697bd44da8,
            0x77e36f7304c48942,
            0x3f9d85a86a1d36c8,
            0x1112e6ad91d692a1,
        ];
        type Output = [u8; 28];
    }

    impl Variant64 for Sha512_256 {
        const IV: [u64; 8] = [
            0x22312194fc2bf72c,
            0x9f555fa3c84c64c2,
            0x2393b86b6f53b151,
            0x963877195940eabd,
            0x96283ee2a88effe3,
            0xbe5e1e2553863992,
            0x2b0199fc2c85b8aa,
            0x0eb72ddc81c52ca2,
        ];
        type Output = [u8; 32];
    }
}

/// SHA-224 using the best implementation the processor supports.
pub type Sha224 = Auto32<variant::Sha224>;
/// SHA-256 using the best implementation the processor supports.
pub type Sha256 = Auto32<variant::Sha256>;
/// SHA-384 using the best implementation the processor supports.
pub type Sha384 = Auto64<variant::Sha384>;
/// SHA-512 using the best implementation the processor supports.
pub type Sha512 = Auto64<variant::Sha512>;
/// SHA-512/224 using the best implementation the processor supports.
pub type Sha512_224 = Auto64<variant::Sha512_224>;
/// SHA-512/256 using the best implementation the processor supports.
pub type Sha512_256 = Auto64<variant::Sha512_256>;

/// The implementation the processor gets, chosen once per family.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Choice {
    ShaNi,
    Armv8,
    Zknh,
    Portable,
}

/// Candidates in order of preference: hardware first, then the
/// portable code, which is always last so the search always ends.
const CHOICES: [Choice; 4] =
    [Choice::ShaNi, Choice::Armv8, Choice::Zknh, Choice::Portable];

/// One probe result per family, since the processor may have an
/// instruction for one and not the other: 0 until probed, then one
/// plus the index into `CHOICES`. Probing is idempotent, so a race
/// between two first callers is harmless.
static PROBED32: AtomicU8 = AtomicU8::new(0);
static PROBED64: AtomicU8 = AtomicU8::new(0);

/// Asks the processor once; afterwards a single atomic load.
fn probe(probed: &AtomicU8, supported: fn(Choice) -> bool) -> Choice {
    match probed.load(Ordering::Relaxed) {
        0 => {
            let found = CHOICES
                .into_iter()
                .enumerate()
                .find(|&(_, c)| supported(c))
                .unwrap_or((3, Choice::Portable));
            probed.store(found.0 as u8 + 1, Ordering::Relaxed);
            found.1
        }
        n => CHOICES
            .get(usize::from(n) - 1)
            .copied()
            .unwrap_or(Choice::Portable),
    }
}

/// Whether the processor can run `choice`'s SHA-256.
fn supported32(choice: Choice) -> bool {
    match choice {
        #[cfg(target_arch = "x86_64")]
        Choice::ShaNi => <x86_64::ShaNi as Compress32>::supported(),
        #[cfg(target_arch = "aarch64")]
        Choice::Armv8 => <aarch64::Armv8 as Compress32>::supported(),
        #[cfg(target_arch = "riscv64")]
        Choice::Zknh => <riscv64::Zknh as Compress32>::supported(),
        Choice::Portable => true,
        #[allow(unreachable_patterns)]
        _ => false,
    }
}

/// Whether the processor can run `choice`'s SHA-512.
fn supported64(choice: Choice) -> bool {
    match choice {
        #[cfg(target_arch = "aarch64")]
        Choice::Armv8 => <aarch64::Armv8 as Compress64>::supported(),
        #[cfg(target_arch = "riscv64")]
        Choice::Zknh => <riscv64::Zknh as Compress64>::supported(),
        Choice::Portable => true,
        #[allow(unreachable_patterns)]
        _ => false,
    }
}

/// Defines a family's dispatching type: an enum of the engines the
/// architecture has, chosen at construction, and each method fanned
/// over them with one predictable branch.
macro_rules! automatic {
    (
        $(#[$doc:meta])*
        $name:ident, $inner:ident, $engine:ident, $compress:ident,
        $variant:ident, $probed:ident, $supported:ident, $block:literal,
        [$( ($arch:literal, $choice:ident, $path:path) ),*]
    ) => {
        $(#[$doc])*
        #[derive(Clone)]
        pub struct $name<V: $variant>($inner<V>);

        #[derive(Clone)]
        enum $inner<V: $variant> {
            $(
                #[cfg(target_arch = $arch)]
                $choice($engine<$path, V>),
            )*
            Portable($engine<portable::Compress, V>),
        }

        impl<V: $variant> $name<V> {
            /// Starts a hash with the best implementation the
            /// processor supports.
            ///
            /// The processor is probed the first time; every later
            /// call reads the cached answer.
            // The hardware engines skip their own processor check
            // because the probe has already made it.
            #[allow(unsafe_code)]
            pub fn new() -> Self {
                // SAFETY: `probe` only names hardware after confirming
                // the processor supports it.
                let inner = unsafe {
                    match probe(&$probed, $supported) {
                        $(
                            #[cfg(target_arch = $arch)]
                            Choice::$choice => {
                                $inner::$choice($engine::new_unchecked())
                            }
                        )*
                        _ => $inner::Portable($engine::new_unchecked()),
                    }
                };
                $name(inner)
            }
        }

        impl<V: $variant> Default for $name<V> {
            fn default() -> Self {
                Self::new()
            }
        }

        impl<V: $variant> fmt::Debug for $name<V> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                match &self.0 {
                    $(
                        #[cfg(target_arch = $arch)]
                        $inner::$choice(engine) => engine.fmt(f),
                    )*
                    $inner::Portable(engine) => engine.fmt(f),
                }
            }
        }

        impl<V: $variant> Hash for $name<V> {
            const BLOCK_SIZE: usize = $block;
            type Output = V::Output;

            fn try_new() -> Result<Self, Error> {
                Ok(Self::new())
            }

            fn reset(&mut self) {
                match &mut self.0 {
                    $(
                        #[cfg(target_arch = $arch)]
                        $inner::$choice(engine) => engine.reset(),
                    )*
                    $inner::Portable(engine) => engine.reset(),
                }
            }

            #[inline]
            fn update(&mut self, data: &[u8]) {
                match &mut self.0 {
                    $(
                        #[cfg(target_arch = $arch)]
                        $inner::$choice(engine) => engine.update(data),
                    )*
                    $inner::Portable(engine) => engine.update(data),
                }
            }

            fn finalize(self) -> Self::Output {
                match self.0 {
                    $(
                        #[cfg(target_arch = $arch)]
                        $inner::$choice(engine) => engine.finalize(),
                    )*
                    $inner::Portable(engine) => engine.finalize(),
                }
            }
        }

        impl<V: $variant> BitHash for $name<V> {
            fn finalize_bits(
                self,
                last: u8,
                bits: u32,
            ) -> Result<Self::Output, Error> {
                match self.0 {
                    $(
                        #[cfg(target_arch = $arch)]
                        $inner::$choice(engine) => {
                            engine.finalize_bits(last, bits)
                        }
                    )*
                    $inner::Portable(engine) => {
                        engine.finalize_bits(last, bits)
                    }
                }
            }
        }
    };
}

automatic!(
    /// SHA-224 or SHA-256 using the best implementation the processor
    /// supports; see [`Sha256`].
    Auto32, Inner32, Engine32, Compress32, Variant32, PROBED32,
    supported32, 64,
    [
        ("x86_64", ShaNi, x86_64::ShaNi),
        ("aarch64", Armv8, aarch64::Armv8),
        ("riscv64", Zknh, riscv64::Zknh)
    ]
);

automatic!(
    /// SHA-384 or SHA-512 using the best implementation the processor
    /// supports; see [`Sha512`].
    Auto64, Inner64, Engine64, Compress64, Variant64, PROBED64,
    supported64, 128,
    [
        ("aarch64", Armv8, aarch64::Armv8),
        ("riscv64", Zknh, riscv64::Zknh)
    ]
);

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use zeroize::ZeroizeOnDrop;

    /// Decodes a hex digest.
    fn hex(s: &str) -> [u8; 64] {
        let mut out = [0u8; 64];
        for (i, pair) in s.as_bytes().chunks(2).enumerate() {
            let s = core::str::from_utf8(pair).unwrap();
            out[i] = u8::from_str_radix(s, 16).unwrap();
        }
        out
    }

    /// One FIPS 180-4 example message and its four digests.
    struct Example {
        message: &'static [u8],
        repeat: usize,
        sha224: &'static str,
        sha256: &'static str,
        sha384: &'static str,
        sha512: &'static str,
    }

    const EXAMPLES: [Example; 5] = [
        Example {
            message: b"",
            repeat: 1,
            sha224: "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f",
            sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b\
                7852b855",
            sha384: "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf\
                63f6e1da274edebfe76f65fbd51ad2f14898b95b",
            sha512: "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921\
                d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81\
                a538327af927da3e",
        },
        Example {
            message: b"abc",
            repeat: 1,
            sha224: "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7",
            sha256: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61\
                f20015ad",
            sha384: "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a\
                43ff5bed8086072ba1e7cc2358baeca134c825a7",
            sha512: "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee6\
                4b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e\
                2a9ac94fa54ca49f",
        },
        Example {
            message: b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnop\
                        nopq",
            repeat: 1,
            sha224: "75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525",
            sha256: "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd4\
                19db06c1",
            sha384: "3391fdddfc8dc7393707a65b1b4709397cf8b1d162af05abfe8f450d\
                e5f36bc6b0455a8520bc4e6f5fe95b1fe3c8452b",
            sha512: "204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331\
                a703c33596fd15c13b1b07f9aa1d3bea57789ca031ad85c7a71dd703\
                54ec631238ca3445",
        },
        Example {
            message: b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghij\
                        klmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrst\
                        nopqrstu",
            repeat: 1,
            sha224: "c97ca9a559850ce97a04a96def6d99a9e0e0e2ab14e6b8df265fc0b3",
            sha256: "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac4503\
                7afee9d1",
            sha384: "09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086\
                e3b0f712fcc7c71a557e2db966c3e9fa91746039",
            sha512: "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aead\
                b6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd2654\
                5e96e55b874be909",
        },
        Example {
            message: b"a",
            repeat: 1_000_000,
            sha224: "20794655980c91d8bbb4c1ea97618a4bf03f42581948b2ee4ee7ad67",
            sha256: "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39cc\
                c7112cd0",
            sha384: "9d0e1809716474cb086e834e310a4a1ced149e9c00f248527972cec5\
                704c2a5b07b8b3dc38ecc4ebae97ddd87f3d8985",
            sha512: "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803\
                afa973ebde0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e\
                4eadb217ad8cc09b",
        },
    ];

    /// Hashes a message given as a repeated piece, in pieces.
    fn digest<H: Hash>(example: &Example) -> H::Output {
        let mut hash = H::try_new().unwrap();
        for _ in 0..example.repeat {
            hash.update(example.message);
        }
        hash.finalize()
    }

    /// Checks the four variants of one implementation against the
    /// FIPS 180-4 examples.
    pub(crate) fn check_known_answers<A, B, C, D>()
    where
        A: Hash<Output = [u8; 28]>,
        B: Hash<Output = [u8; 32]>,
        C: Hash<Output = [u8; 48]>,
        D: Hash<Output = [u8; 64]>,
    {
        for example in &EXAMPLES {
            assert_eq!(digest::<A>(example), hex(example.sha224)[..28]);
            assert_eq!(digest::<B>(example), hex(example.sha256)[..32]);
            assert_eq!(digest::<C>(example), hex(example.sha384)[..48]);
            assert_eq!(digest::<D>(example), hex(example.sha512)[..64]);
        }
    }

    /// Checks one implementation against the portable one over every
    /// length up to a few blocks, fed in every way.
    pub(crate) fn check_matches_portable<H, P>()
    where
        H: Hash,
        P: Hash<Output = H::Output>,
        H::Output: PartialEq + core::fmt::Debug,
    {
        let data: [u8; 300] = core::array::from_fn(|i| (i * 7 + i / 3) as u8);
        for len in 0..data.len() {
            let message = &data[..len];
            let expected = P::digest(message).unwrap();
            assert_eq!(H::digest(message).unwrap(), expected, "len {len}");
            // Split at each point, and in threes at a few.
            for split in (0..len).step_by(13) {
                let mut hash = H::try_new().unwrap();
                hash.update(&message[..split]);
                hash.update(&message[split..]);
                assert_eq!(hash.finalize(), expected, "len {len} at {split}");
            }
        }
    }

    #[test]
    fn known_answers() {
        check_known_answers::<Sha224, Sha256, Sha384, Sha512>();
    }

    /// The SHA-512/t starting values are SHA-512 of "SHA-512/t" from
    /// a modified starting value (FIPS 180-4 section 5.3.6).
    #[test]
    fn sha512_t_ivs_derive() {
        fn derive(name: &[u8]) -> [u64; 8] {
            let iv = variant::Sha512::IV.map(|w| w ^ 0xa5a5a5a5a5a5a5a5);
            let mut hash = portable::Sha512::with_iv(iv);
            hash.update(name);
            let digest = hash.finalize();
            core::array::from_fn(|i| {
                u64::from_be_bytes(digest[8 * i..8 * i + 8].try_into().unwrap())
            })
        }
        assert_eq!(derive(b"SHA-512/224"), variant::Sha512_224::IV);
        assert_eq!(derive(b"SHA-512/256"), variant::Sha512_256::IV);
    }

    #[test]
    fn sha512_t_known_answers() {
        assert_eq!(
            Sha512_224::digest(b"abc").unwrap(),
            hex("4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa")
                [..28]
        );
        assert_eq!(
            Sha512_256::digest(b"abc").unwrap(),
            hex(
                "53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7\
                 af23"
            )[..32]
        );
        assert_eq!(
            Sha512_224::digest(b"").unwrap(),
            hex("6ed0dd02806fa89e25de060c19d3ac86cabb87d6a0ddd05c333b84f4")
                [..28]
        );
        assert_eq!(
            Sha512_256::digest(b"").unwrap(),
            hex(
                "c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0\
                 967a"
            )[..32]
        );
    }

    #[test]
    fn matches_portable() {
        check_matches_portable::<Sha512_224, portable::Sha512_224>();
        check_matches_portable::<Sha512_256, portable::Sha512_256>();
        check_matches_portable::<Sha224, portable::Sha224>();
        check_matches_portable::<Sha256, portable::Sha256>();
        check_matches_portable::<Sha384, portable::Sha384>();
        check_matches_portable::<Sha512, portable::Sha512>();
    }

    #[test]
    fn splitting_does_not_matter() {
        let data: [u8; 517] = core::array::from_fn(|i| (i * 31) as u8);
        let expected = Sha256::digest(&data).unwrap();
        for chunk in [1, 3, 7, 63, 64, 65, 128, 200] {
            let mut hash = Sha256::new();
            for piece in data.chunks(chunk) {
                hash.update(piece);
            }
            assert_eq!(hash.finalize(), expected, "chunk {chunk}");
        }
    }

    #[test]
    fn reset_starts_over() {
        let mut hash = Sha512::new();
        hash.update(b"not this");
        hash.reset();
        hash.update(b"abc");
        assert_eq!(hash.finalize(), Sha512::digest(b"abc").unwrap());
    }

    #[test]
    fn clone_forks_the_state() {
        let mut hash = Sha256::new();
        hash.update(b"ab");
        let fork = hash.clone();
        hash.update(b"c");
        assert_eq!(hash.finalize(), Sha256::digest(b"abc").unwrap());
        assert_eq!(fork.finalize(), Sha256::digest(b"ab").unwrap());
    }

    /// The SHAVS bit-oriented vectors: the one-bit message 0, and the
    /// seven-bit message 1110 010.
    #[test]
    fn bit_strings() {
        let hash = Sha256::new();
        assert_eq!(
            hash.finalize_bits(0x00, 1).unwrap(),
            hex(
                "bd4f9e98beb68c6ead3243b1b4c7fed75fa4feaab1f84795cbd8a98676a2\
                 a375"
            )[..32]
        );
        // Bits beyond the count are ignored.
        let mut hash = Sha256::new();
        hash.update(b"abc");
        let with_junk = hash.clone().finalize_bits(0xff, 1).unwrap();
        assert_eq!(hash.finalize_bits(0x80, 1).unwrap(), with_junk);
    }

    #[test]
    fn bit_count_is_checked() {
        for bits in [0, 8, 9, 100] {
            assert_eq!(
                Sha256::new().finalize_bits(0, bits),
                Err(Error::InvalidBitCount(bits))
            );
        }
    }

    /// A partial last byte after a message that fills the block to
    /// within the length field exercises the second padding block.
    #[test]
    fn bit_strings_across_the_padding_boundary() {
        for len in [54usize, 55, 56, 63, 64, 111, 112, 127, 128] {
            let data = [0x5au8; 128];
            let mut hash = Sha384::new();
            hash.update(&data[..len]);
            let bits = hash.finalize_bits(0xa0, 3).unwrap();
            // The same bit string, hashed by the portable code with
            // the bits fed the same way, must agree; and it must
            // differ from the message without them.
            let mut p = portable::Sha384::try_new().unwrap();
            p.update(&data[..len]);
            assert_eq!(p.finalize_bits(0xa0, 3).unwrap(), bits);
            let mut whole = Sha384::new();
            whole.update(&data[..len]);
            assert_ne!(whole.finalize(), bits);
        }
    }

    #[test]
    fn digest_is_the_same_as_update_then_finalize() {
        let mut hash = Sha224::new();
        hash.update(b"abc");
        assert_eq!(hash.finalize(), Sha224::digest(b"abc").unwrap());
        assert_eq!(
            <Sha224 as Hash>::digest(b"abc").unwrap(),
            Sha224::digest(b"abc").unwrap()
        );
    }

    /// Compiles only if every engine wipes itself on drop.
    #[test]
    fn every_implementation_zeroizes() {
        fn wipes<T: ZeroizeOnDrop>() {}
        wipes::<portable::Sha224>();
        wipes::<portable::Sha256>();
        wipes::<portable::Sha384>();
        wipes::<portable::Sha512>();
        wipes::<portable::Sha512_224>();
        wipes::<portable::Sha512_256>();
        #[cfg(target_arch = "x86_64")]
        {
            wipes::<x86_64::Sha224>();
            wipes::<x86_64::Sha256>();
        }
        #[cfg(target_arch = "aarch64")]
        {
            wipes::<aarch64::Sha224>();
            wipes::<aarch64::Sha256>();
            wipes::<aarch64::Sha384>();
            wipes::<aarch64::Sha512>();
        }
        #[cfg(target_arch = "riscv64")]
        {
            wipes::<riscv64::Sha224>();
            wipes::<riscv64::Sha256>();
            wipes::<riscv64::Sha384>();
            wipes::<riscv64::Sha512>();
        }
    }

    #[test]
    fn picks_best_supported() {
        let choice32 = probe(&PROBED32, supported32);
        let choice64 = probe(&PROBED64, supported64);
        for c in CHOICES {
            if supported32(c) {
                assert_eq!(choice32, c);
                break;
            }
        }
        for c in CHOICES {
            if supported64(c) {
                assert_eq!(choice64, c);
                break;
            }
        }
        // Probing again gives the same answer from the cache.
        assert_eq!(probe(&PROBED32, supported32), choice32);
        assert_eq!(probe(&PROBED64, supported64), choice64);
    }

    #[test]
    fn debug_omits_the_message() {
        let mut hash = Sha256::new();
        hash.update(b"secret");
        // No allocator in a `no_std` test, so format into a buffer.
        struct Buffer([u8; 128], usize);
        impl core::fmt::Write for Buffer {
            fn write_str(&mut self, s: &str) -> core::fmt::Result {
                let end = self.1 + s.len();
                self.0[self.1..end].copy_from_slice(s.as_bytes());
                self.1 = end;
                Ok(())
            }
        }
        let mut buffer = Buffer([0; 128], 0);
        core::fmt::write(&mut buffer, format_args!("{hash:?}")).unwrap();
        let text = core::str::from_utf8(&buffer.0[..buffer.1]).unwrap();
        assert!(!text.contains("secret"));
        assert!(text.contains("bytes: 6"));
    }
}
