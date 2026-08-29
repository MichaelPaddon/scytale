//! SHA-3 (FIPS 202): SHA3-224, SHA3-256, SHA3-384 and SHA3-512, and
//! the extendable-output functions SHAKE128 and SHAKE256.
//!
//! One function underneath, really: the Keccak-f\[1600\] permutation
//! used as a sponge. The six differ in how much of the 1600-bit
//! state the message goes into at a time, the rate, and in the bits
//! that end the message. The digests give a fixed output; the SHAKE
//! functions give as much as is asked for, through [`Xof`]. The types
//! here pick the best implementation the processor has, and each is
//! also reachable by name under [`portable`] and the architecture
//! module beside it.
//!
//! ```
//! use scytale::hash::sha3::{Sha3_256, Shake128};
//! use scytale::hash::{Hash, Xof, XofReader};
//!
//! # fn main() -> Result<(), scytale::Error> {
//! let digest = Sha3_256::digest(b"abc")?;
//! assert_eq!(digest[..4], [0x3a, 0x98, 0x5d, 0xa7]);
//!
//! let mut shake = Shake128::new();
//! shake.update(b"abc");
//! let mut reader = shake.finalize_xof();
//! let mut out = [0u8; 64];
//! reader.squeeze(&mut out[..32]);
//! reader.squeeze(&mut out[32..]);
//! assert_eq!(out[..4], [0x58, 0x81, 0x09, 0x2d]);
//! # Ok(())
//! # }
//! ```
//!
//! # Choosing
//!
//! SHA-3 is not a replacement for SHA-2, which is unbroken; it is a
//! different design, for protocols that name it and for anyone who
//! wants a hash that cannot be length-extended: a SHA-3 digest gives
//! away nothing about the state that made it. SHAKE is the choice
//! where the output length is the caller's to decide, and is what
//! the newer standards build key derivation on. SHA3-256 and
//! SHAKE128 are the usual picks; the larger digests cost more per
//! byte because less of each permutation is message.
//!
//! # Bit strings
//!
//! Like SHA-2, defined over bit strings, with the last few bits
//! taken by [`BitHash::finalize_bits`] and
//! [`BitXof::finalize_bits_xof`]. FIPS 202 numbers bits from the
//! least significant end of a byte, and so do these.
//!
//! # Speed
//!
//! The permutation is the whole cost, and a message advances the
//! state one permutation per rate of bytes. AArch64 processors with
//! the SHA3 extension have instructions for the permutation's steps,
//! used in the `aarch64` module, and are two to three times the
//! portable speed. Nothing else has such instructions; x86-64 and
//! RISC-V run the portable code, which on a 64-bit processor is a
//! little slower than SHA-256 with no hardware and much slower than
//! SHA-256 with it.

#[cfg(target_arch = "aarch64")]
pub mod aarch64;
pub mod engine;
pub mod portable;

use core::fmt;
use core::sync::atomic::{AtomicU8, Ordering};

use engine::{DigestVariant, Reader, Sponge, XofVariant};

use crate::hash::{BitHash, BitXof, Hash, Xof, XofReader};
use crate::Error;

/// The six functions, as markers the sponge is generic over.
pub mod variant {
    use super::engine::{DigestVariant, Sealed, Variant, XofVariant};

    /// Defines a marker with its rate and suffix.
    macro_rules! variant {
        ($(#[$doc:meta])* $name:ident, $rate:literal, $suffix:literal) => {
            $(#[$doc])*
            #[derive(Clone, Copy, Debug)]
            pub struct $name;

            impl Sealed for $name {}

            impl Variant for $name {
                const RATE: usize = $rate;
                const SUFFIX: u8 = $suffix;
            }
        };
    }

    variant!(/** SHA3-224. */ Sha3_224, 144, 0x06);
    variant!(/** SHA3-256. */ Sha3_256, 136, 0x06);
    variant!(/** SHA3-384. */ Sha3_384, 104, 0x06);
    variant!(/** SHA3-512. */ Sha3_512, 72, 0x06);
    variant!(/** SHAKE128. */ Shake128, 168, 0x1f);
    variant!(/** SHAKE256. */ Shake256, 136, 0x1f);

    impl DigestVariant for Sha3_224 {
        type Output = [u8; 28];
    }
    impl DigestVariant for Sha3_256 {
        type Output = [u8; 32];
    }
    impl DigestVariant for Sha3_384 {
        type Output = [u8; 48];
    }
    impl DigestVariant for Sha3_512 {
        type Output = [u8; 64];
    }
    impl XofVariant for Shake128 {}
    impl XofVariant for Shake256 {}
}

/// SHA3-224 using the best implementation the processor supports.
pub type Sha3_224 = Auto<variant::Sha3_224>;
/// SHA3-256 using the best implementation the processor supports.
pub type Sha3_256 = Auto<variant::Sha3_256>;
/// SHA3-384 using the best implementation the processor supports.
pub type Sha3_384 = Auto<variant::Sha3_384>;
/// SHA3-512 using the best implementation the processor supports.
pub type Sha3_512 = Auto<variant::Sha3_512>;
/// SHAKE128 using the best implementation the processor supports.
pub type Shake128 = Auto<variant::Shake128>;
/// SHAKE256 using the best implementation the processor supports.
pub type Shake256 = Auto<variant::Shake256>;

/// The implementation the processor gets, chosen once.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Choice {
    Armv8,
    Portable,
}

/// Candidates in order of preference; the portable code is last so
/// the search always ends.
const CHOICES: [Choice; 2] = [Choice::Armv8, Choice::Portable];

/// The probe result: 0 until probed, then one plus the index into
/// `CHOICES`. Probing is idempotent, so a race between two first
/// callers is harmless.
static PROBED: AtomicU8 = AtomicU8::new(0);

/// Asks the processor once; afterwards a single atomic load.
fn probe() -> Choice {
    match PROBED.load(Ordering::Relaxed) {
        0 => {
            let found = CHOICES
                .into_iter()
                .enumerate()
                .find(|&(_, c)| supported(c))
                .unwrap_or((1, Choice::Portable));
            PROBED.store(found.0 as u8 + 1, Ordering::Relaxed);
            found.1
        }
        n => CHOICES
            .get(usize::from(n) - 1)
            .copied()
            .unwrap_or(Choice::Portable),
    }
}

/// Whether the processor can run `choice`.
fn supported(choice: Choice) -> bool {
    match choice {
        #[cfg(target_arch = "aarch64")]
        Choice::Armv8 => <aarch64::Armv8 as engine::Permutation>::supported(),
        Choice::Portable => true,
        #[allow(unreachable_patterns)]
        _ => false,
    }
}

/// Applies a method to whichever implementation is in use.
macro_rules! dispatch {
    ($value:expr, $inner:ident, $x:ident => $body:expr) => {
        match $value {
            #[cfg(target_arch = "aarch64")]
            $inner::Armv8($x) => $body,
            $inner::Portable($x) => $body,
        }
    };
}

/// A SHA-3 function using the best implementation the processor
/// supports; see [`Sha3_256`] and [`Shake128`].
///
/// The processor is probed the first time; every later call reads
/// the cached answer.
#[derive(Clone)]
pub struct Auto<V: engine::Variant>(Inner<V>);

#[derive(Clone)]
enum Inner<V: engine::Variant> {
    #[cfg(target_arch = "aarch64")]
    Armv8(Sponge<aarch64::Armv8, V>),
    Portable(Sponge<portable::Keccak, V>),
}

impl<V: engine::Variant> Auto<V> {
    /// Starts a function with the best implementation the processor
    /// supports.
    // The hardware sponge skips its own processor check because the
    // probe has already made it.
    #[allow(unsafe_code)]
    pub fn new() -> Self {
        // SAFETY: `probe` only names hardware after confirming the
        // processor supports it.
        let inner = unsafe {
            match probe() {
                #[cfg(target_arch = "aarch64")]
                Choice::Armv8 => Inner::Armv8(Sponge::new_unchecked()),
                _ => Inner::Portable(Sponge::new_unchecked()),
            }
        };
        Auto(inner)
    }
}

impl<V: engine::Variant> Default for Auto<V> {
    fn default() -> Self {
        Self::new()
    }
}

impl<V: engine::Variant> fmt::Debug for Auto<V> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        dispatch!(&self.0, Inner, s => s.fmt(f))
    }
}

impl<V: DigestVariant> Hash for Auto<V> {
    const BLOCK_SIZE: usize = V::RATE;
    type Output = V::Output;

    fn try_new() -> Result<Self, Error> {
        Ok(Self::new())
    }

    fn reset(&mut self) {
        dispatch!(&mut self.0, Inner, s => Hash::reset(s))
    }

    #[inline]
    fn update(&mut self, data: &[u8]) {
        dispatch!(&mut self.0, Inner, s => Hash::update(s, data))
    }

    fn finalize(self) -> Self::Output {
        dispatch!(self.0, Inner, s => s.finalize())
    }
}

impl<V: DigestVariant> BitHash for Auto<V> {
    fn finalize_bits(self, last: u8, bits: u32) -> Result<Self::Output, Error> {
        dispatch!(self.0, Inner, s => s.finalize_bits(last, bits))
    }
}

/// The output of a SHAKE function from [`Auto`].
#[derive(Clone, Debug)]
pub struct AutoReader<V: XofVariant>(InnerReader<V>);

#[derive(Clone, Debug)]
enum InnerReader<V: XofVariant> {
    #[cfg(target_arch = "aarch64")]
    Armv8(Reader<aarch64::Armv8, V>),
    Portable(Reader<portable::Keccak, V>),
}

impl<V: XofVariant> XofReader for AutoReader<V> {
    fn squeeze(&mut self, out: &mut [u8]) {
        dispatch!(&mut self.0, InnerReader, r => r.squeeze(out))
    }
}

impl<V: XofVariant> Xof for Auto<V> {
    const BLOCK_SIZE: usize = V::RATE;
    type Reader = AutoReader<V>;

    fn try_new() -> Result<Self, Error> {
        Ok(Self::new())
    }

    fn reset(&mut self) {
        dispatch!(&mut self.0, Inner, s => Xof::reset(s))
    }

    #[inline]
    fn update(&mut self, data: &[u8]) {
        dispatch!(&mut self.0, Inner, s => Xof::update(s, data))
    }

    fn finalize_xof(self) -> Self::Reader {
        AutoReader(match self.0 {
            #[cfg(target_arch = "aarch64")]
            Inner::Armv8(s) => InnerReader::Armv8(s.finalize_xof()),
            Inner::Portable(s) => InnerReader::Portable(s.finalize_xof()),
        })
    }
}

impl<V: XofVariant> BitXof for Auto<V> {
    fn finalize_bits_xof(
        self,
        last: u8,
        bits: u32,
    ) -> Result<Self::Reader, Error> {
        Ok(AutoReader(match self.0 {
            #[cfg(target_arch = "aarch64")]
            Inner::Armv8(s) => {
                InnerReader::Armv8(s.finalize_bits_xof(last, bits)?)
            }
            Inner::Portable(s) => {
                InnerReader::Portable(s.finalize_bits_xof(last, bits)?)
            }
        }))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use zeroize::ZeroizeOnDrop;

    fn hex(s: &str) -> [u8; 64] {
        let mut out = [0u8; 64];
        for (i, pair) in s.as_bytes().chunks(2).enumerate() {
            let s = core::str::from_utf8(pair).unwrap();
            out[i] = u8::from_str_radix(s, 16).unwrap();
        }
        out
    }

    /// The NIST example values for the empty message and "abc"; the
    /// SHAKE ones are the first 32 and 64 bytes.
    struct Example {
        message: &'static [u8],
        sha3_224: &'static str,
        sha3_256: &'static str,
        sha3_384: &'static str,
        sha3_512: &'static str,
        shake128: &'static str,
        shake256: &'static str,
    }

    const EXAMPLES: [Example; 2] = [
        Example {
            message: b"",
            sha3_224:
                "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7",
            sha3_256:
                "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b\
                80f8434a",
            sha3_384:
                "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bb\
                ee983a2ac3713831264adb47fb6bd1e058d5f004",
            sha3_512:
                "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1\
                475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e3\
                01758586281dcd26",
            shake128:
                "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eac\
                fa66ef26",
            shake256:
                "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c2764\
                6ed5762fd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab486\
                40292eacb3b7c4be",
        },
        Example {
            message: b"abc",
            sha3_224:
                "e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf",
            sha3_256:
                "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe245\
                11431532",
            sha3_384:
                "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0\
                e49be4b298d88cea927ac7f539f1edf228376d25",
            sha3_512:
                "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d02\
                40d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a5\
                6592f8274eec53f0",
            shake128:
                "5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351\
                940f2cc8",
            shake256:
                "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37\
                e78b5739d5a15bef186a5386c75744c0527e1faa9f8726e462a12a4f\
                eb06bd8801e751e4",
        },
    ];

    fn squeeze<X: Xof>(message: &[u8], n: usize) -> [u8; 64] {
        let mut x = X::try_new().unwrap();
        x.update(message);
        let mut out = [0u8; 64];
        x.finalize_xof().squeeze(&mut out[..n]);
        out
    }

    /// Checks the six functions of one implementation against the
    /// NIST examples.
    pub(crate) fn check_known_answers<A, B, C, D, E, F>()
    where
        A: Hash<Output = [u8; 28]>,
        B: Hash<Output = [u8; 32]>,
        C: Hash<Output = [u8; 48]>,
        D: Hash<Output = [u8; 64]>,
        E: Xof,
        F: Xof,
    {
        for e in &EXAMPLES {
            assert_eq!(A::digest(e.message).unwrap(), hex(e.sha3_224)[..28]);
            assert_eq!(B::digest(e.message).unwrap(), hex(e.sha3_256)[..32]);
            assert_eq!(C::digest(e.message).unwrap(), hex(e.sha3_384)[..48]);
            assert_eq!(D::digest(e.message).unwrap(), hex(e.sha3_512)[..64]);
            assert_eq!(
                squeeze::<E>(e.message, 32)[..32],
                hex(e.shake128)[..32]
            );
            assert_eq!(squeeze::<F>(e.message, 64), hex(e.shake256));
        }
    }

    /// Checks one implementation against the portable one over every
    /// length up to a few blocks, fed in every way, digest and XOF.
    pub(crate) fn check_matches_portable<H, P, X, Y>()
    where
        H: Hash,
        P: Hash<Output = H::Output>,
        H::Output: PartialEq + core::fmt::Debug,
        X: Xof,
        Y: Xof,
    {
        let data: [u8; 400] = core::array::from_fn(|i| (i * 7 + i / 3) as u8);
        for len in 0..data.len() {
            let message = &data[..len];
            let expected = P::digest(message).unwrap();
            assert_eq!(H::digest(message).unwrap(), expected, "len {len}");
            for split in (0..len).step_by(17) {
                let mut hash = H::try_new().unwrap();
                hash.update(&message[..split]);
                hash.update(&message[split..]);
                assert_eq!(hash.finalize(), expected, "len {len} at {split}");
            }
            assert_eq!(
                squeeze::<X>(message, 64),
                squeeze::<Y>(message, 64),
                "xof len {len}"
            );
        }
    }

    #[test]
    fn known_answers() {
        check_known_answers::<
            Sha3_224,
            Sha3_256,
            Sha3_384,
            Sha3_512,
            Shake128,
            Shake256,
        >();
    }

    #[test]
    fn matches_portable() {
        check_matches_portable::<
            Sha3_256,
            portable::Sha3_256,
            Shake256,
            portable::Shake256,
        >();
    }

    /// Two bit-string cases from the NIST ACVP SHA3-256 vectors: 22
    /// bits (two bytes and six bits) and 13 bits (one byte and five).
    /// ACVP left-aligns the last bits in their byte; FIPS 202, and
    /// this API, number bits from the least significant end, so they
    /// are shifted down before being passed.
    #[test]
    fn bit_strings() {
        let mut hash = Sha3_256::new();
        hash.update(&[0xf1, 0x3d]);
        assert_eq!(
            hash.finalize_bits(0x64 >> 2, 6).unwrap(),
            hex(
                "f561e056b721fcd859ba37efc08431ccf70fde1cf9f13dc95385daa6a082\
                 55f6"
            )[..32]
        );
        let mut hash = Sha3_256::new();
        hash.update(&[0x26]);
        assert_eq!(
            hash.finalize_bits(0x58 >> 3, 5).unwrap(),
            hex(
                "e2976b7527ff3d52a3c3fb6a6df4e56d1876427f6304a0a7a194582920481\
                 de0"
            )[..32]
        );
        // Bits beyond the count are ignored.
        let a = Sha3_256::new().finalize_bits(0x1f, 5).unwrap();
        let b = Sha3_256::new().finalize_bits(0xff, 5).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn bit_count_is_checked() {
        for bits in [0, 8, 9] {
            assert_eq!(
                Sha3_256::new().finalize_bits(0, bits),
                Err(Error::InvalidBitCount(bits))
            );
            assert!(Shake128::new().finalize_bits_xof(0, bits).is_err());
        }
    }

    #[test]
    fn squeezing_in_pieces_is_the_same_stream() {
        let whole = squeeze::<Shake128>(b"abc", 64);
        let mut x = Shake128::new();
        x.update(b"abc");
        let mut reader = x.finalize_xof();
        let mut out = [0u8; 64];
        reader.squeeze(&mut out[..1]);
        reader.squeeze(&mut out[1..3]);
        reader.squeeze(&mut out[3..40]);
        reader.squeeze(&mut out[40..]);
        assert_eq!(out, whole);
        // Well past one rate of output, against a fresh reader.
        let mut long = [0u8; 500];
        let mut again = [0u8; 500];
        let mut x = Shake128::new();
        x.update(b"abc");
        x.finalize_xof().squeeze(&mut long);
        let mut x = Shake128::new();
        x.update(b"abc");
        let mut reader = x.finalize_xof();
        reader.squeeze(&mut again[..167]);
        reader.squeeze(&mut again[167..169]);
        reader.squeeze(&mut again[169..]);
        assert_eq!(long[..], again[..]);
    }

    #[test]
    fn splitting_does_not_matter() {
        let data: [u8; 617] = core::array::from_fn(|i| (i * 31) as u8);
        let expected = Sha3_512::digest(&data).unwrap();
        for chunk in [1, 3, 7, 71, 72, 73, 144, 200] {
            let mut hash = Sha3_512::new();
            for piece in data.chunks(chunk) {
                hash.update(piece);
            }
            assert_eq!(hash.finalize(), expected, "chunk {chunk}");
        }
    }

    #[test]
    fn reset_and_clone() {
        let mut hash = Sha3_224::new();
        hash.update(b"not this");
        hash.reset();
        hash.update(b"ab");
        let fork = hash.clone();
        hash.update(b"c");
        assert_eq!(hash.finalize(), Sha3_224::digest(b"abc").unwrap());
        assert_eq!(fork.finalize(), Sha3_224::digest(b"ab").unwrap());
    }

    #[test]
    fn every_implementation_zeroizes() {
        fn wipes<T: ZeroizeOnDrop>() {}
        wipes::<portable::Sha3_256>();
        wipes::<portable::Shake128>();
        wipes::<<portable::Shake128 as Xof>::Reader>();
        #[cfg(target_arch = "aarch64")]
        {
            wipes::<aarch64::Sha3_256>();
            wipes::<aarch64::Shake128>();
        }
    }

    #[test]
    fn picks_best_supported() {
        let choice = probe();
        for c in CHOICES {
            if supported(c) {
                assert_eq!(choice, c);
                break;
            }
        }
        assert_eq!(probe(), choice);
    }

    #[test]
    fn debug_omits_the_message() {
        struct Buffer([u8; 128], usize);
        impl core::fmt::Write for Buffer {
            fn write_str(&mut self, s: &str) -> core::fmt::Result {
                let end = self.1 + s.len();
                self.0[self.1..end].copy_from_slice(s.as_bytes());
                self.1 = end;
                Ok(())
            }
        }
        let mut hash = Sha3_256::new();
        hash.update(b"secret");
        let mut buffer = Buffer([0; 128], 0);
        core::fmt::write(&mut buffer, format_args!("{hash:?}")).unwrap();
        let text = core::str::from_utf8(&buffer.0[..buffer.1]).unwrap();
        assert!(!text.contains("secret"));
        assert!(text.contains("used: 6"));
    }
}
