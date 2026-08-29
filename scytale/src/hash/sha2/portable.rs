//! SHA-2 in plain Rust, for any processor.
//!
//! Straight from FIPS 180-4. The message schedule is kept as a ring
//! of the last sixteen words rather than expanded in full, which is
//! the same arithmetic in a quarter of the space. There are no
//! lookup tables, so the time taken depends on nothing but the
//! length of the message.
//!
//! The round functions are generic over the six bitwise functions of
//! each family, so that an architecture with instructions for those
//! functions and nothing more (RISC-V Zknh) can reuse the loop.

// Only the trait impls are unsafe, and they call safe code.
#![allow(unsafe_code)]

use super::engine::{Compress32, Compress64, Engine32, Engine64};
use super::variant;

/// SHA-224, portably.
pub type Sha224 = Engine32<Compress, variant::Sha224>;
/// SHA-256, portably.
pub type Sha256 = Engine32<Compress, variant::Sha256>;
/// SHA-384, portably.
pub type Sha384 = Engine64<Compress, variant::Sha384>;
/// SHA-512, portably.
pub type Sha512 = Engine64<Compress, variant::Sha512>;
/// SHA-512/224, portably.
pub type Sha512_224 = Engine64<Compress, variant::Sha512_224>;
/// SHA-512/256, portably.
pub type Sha512_256 = Engine64<Compress, variant::Sha512_256>;

/// The SHA-256 round constants: the fractional parts of the cube
/// roots of the first 64 primes.
pub(crate) static K256: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// The SHA-512 round constants: the fractional parts of the cube
/// roots of the first 80 primes.
pub(crate) static K512: [u64; 80] = [
    0x428a2f98d728ae22,
    0x7137449123ef65cd,
    0xb5c0fbcfec4d3b2f,
    0xe9b5dba58189dbbc,
    0x3956c25bf348b538,
    0x59f111f1b605d019,
    0x923f82a4af194f9b,
    0xab1c5ed5da6d8118,
    0xd807aa98a3030242,
    0x12835b0145706fbe,
    0x243185be4ee4b28c,
    0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f,
    0x80deb1fe3b1696b1,
    0x9bdc06a725c71235,
    0xc19bf174cf692694,
    0xe49b69c19ef14ad2,
    0xefbe4786384f25e3,
    0x0fc19dc68b8cd5b5,
    0x240ca1cc77ac9c65,
    0x2de92c6f592b0275,
    0x4a7484aa6ea6e483,
    0x5cb0a9dcbd41fbd4,
    0x76f988da831153b5,
    0x983e5152ee66dfab,
    0xa831c66d2db43210,
    0xb00327c898fb213f,
    0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2,
    0xd5a79147930aa725,
    0x06ca6351e003826f,
    0x142929670a0e6e70,
    0x27b70a8546d22ffc,
    0x2e1b21385c26c926,
    0x4d2c6dfc5ac42aed,
    0x53380d139d95b3df,
    0x650a73548baf63de,
    0x766a0abb3c77b2a8,
    0x81c2c92e47edaee6,
    0x92722c851482353b,
    0xa2bfe8a14cf10364,
    0xa81a664bbc423001,
    0xc24b8b70d0f89791,
    0xc76c51a30654be30,
    0xd192e819d6ef5218,
    0xd69906245565a910,
    0xf40e35855771202a,
    0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8,
    0x1e376c085141ab53,
    0x2748774cdf8eeb99,
    0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63,
    0x4ed8aa4ae3418acb,
    0x5b9cca4f7763e373,
    0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc,
    0x78a5636f43172f60,
    0x84c87814a1f0ab72,
    0x8cc702081a6439ec,
    0x90befffa23631e28,
    0xa4506cebde82bde9,
    0xbef9a3f7b2c67915,
    0xc67178f2e372532b,
    0xca273eceea26619c,
    0xd186b8c721c0c207,
    0xeada7dd6cde0eb1e,
    0xf57d4f7fee6ed178,
    0x06f067aa72176fba,
    0x0a637dc5a2c898a6,
    0x113f9804bef90dae,
    0x1b710b35131c471b,
    0x28db77f523047d84,
    0x32caab7b40c72493,
    0x3c9ebe0a15c9bebc,
    0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6,
    0x597f299cfc657e2a,
    0x5fcb6fab3ad6faec,
    0x6c44198c4a475817,
];

/// The six bitwise functions of the SHA-256 family, as FIPS 180-4
/// names them.
pub(crate) trait Functions32 {
    fn ch(x: u32, y: u32, z: u32) -> u32;
    fn maj(x: u32, y: u32, z: u32) -> u32;
    fn big_sigma0(x: u32) -> u32;
    fn big_sigma1(x: u32) -> u32;
    fn small_sigma0(x: u32) -> u32;
    fn small_sigma1(x: u32) -> u32;
}

/// The six bitwise functions of the SHA-512 family.
pub(crate) trait Functions64 {
    fn ch(x: u64, y: u64, z: u64) -> u64;
    fn maj(x: u64, y: u64, z: u64) -> u64;
    fn big_sigma0(x: u64) -> u64;
    fn big_sigma1(x: u64) -> u64;
    fn small_sigma0(x: u64) -> u64;
    fn small_sigma1(x: u64) -> u64;
}

/// Defines a compression function over a family's word type and one
/// set of its bitwise functions.
macro_rules! compress {
    ($name:ident, $functions:ident, $word:ty, $block:literal,
     $rounds:literal, $k:ident) => {
        /// Folds every block into `state`.
        #[inline(always)]
        pub(crate) fn $name<F: $functions>(
            state: &mut [$word; 8],
            blocks: &[[u8; $block]],
        ) {
            const WIDTH: usize = core::mem::size_of::<$word>();
            for block in blocks {
                // The schedule as a ring: word t lives at t % 16.
                let mut w = [0 as $word; 16];
                for (w, bytes) in w.iter_mut().zip(block.chunks_exact(WIDTH)) {
                    let mut buf = [0u8; WIDTH];
                    buf.copy_from_slice(bytes);
                    *w = <$word>::from_be_bytes(buf);
                }

                let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] =
                    *state;
                for t in 0..$rounds {
                    let i = t % 16;
                    if t >= 16 {
                        w[i] = F::small_sigma1(w[(i + 14) % 16])
                            .wrapping_add(w[(i + 9) % 16])
                            .wrapping_add(F::small_sigma0(w[(i + 1) % 16]))
                            .wrapping_add(w[i]);
                    }
                    let t1 = h
                        .wrapping_add(F::big_sigma1(e))
                        .wrapping_add(F::ch(e, f, g))
                        .wrapping_add($k[t])
                        .wrapping_add(w[i]);
                    let t2 = F::big_sigma0(a).wrapping_add(F::maj(a, b, c));
                    h = g;
                    g = f;
                    f = e;
                    e = d.wrapping_add(t1);
                    d = c;
                    c = b;
                    b = a;
                    a = t1.wrapping_add(t2);
                }

                for (s, v) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
                    *s = s.wrapping_add(v);
                }
            }
        }
    };
}

compress!(compress256, Functions32, u32, 64, 64, K256);
compress!(compress512, Functions64, u64, 128, 80, K512);

/// The bitwise functions in plain shifts and rotates.
pub struct Compress;

impl Functions32 for Compress {
    #[inline(always)]
    fn ch(x: u32, y: u32, z: u32) -> u32 {
        (x & y) ^ (!x & z)
    }
    #[inline(always)]
    fn maj(x: u32, y: u32, z: u32) -> u32 {
        (x & y) ^ (x & z) ^ (y & z)
    }
    #[inline(always)]
    fn big_sigma0(x: u32) -> u32 {
        x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22)
    }
    #[inline(always)]
    fn big_sigma1(x: u32) -> u32 {
        x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25)
    }
    #[inline(always)]
    fn small_sigma0(x: u32) -> u32 {
        x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3)
    }
    #[inline(always)]
    fn small_sigma1(x: u32) -> u32 {
        x.rotate_right(17) ^ x.rotate_right(19) ^ (x >> 10)
    }
}

impl Functions64 for Compress {
    #[inline(always)]
    fn ch(x: u64, y: u64, z: u64) -> u64 {
        (x & y) ^ (!x & z)
    }
    #[inline(always)]
    fn maj(x: u64, y: u64, z: u64) -> u64 {
        (x & y) ^ (x & z) ^ (y & z)
    }
    #[inline(always)]
    fn big_sigma0(x: u64) -> u64 {
        x.rotate_right(28) ^ x.rotate_right(34) ^ x.rotate_right(39)
    }
    #[inline(always)]
    fn big_sigma1(x: u64) -> u64 {
        x.rotate_right(14) ^ x.rotate_right(18) ^ x.rotate_right(41)
    }
    #[inline(always)]
    fn small_sigma0(x: u64) -> u64 {
        x.rotate_right(1) ^ x.rotate_right(8) ^ (x >> 7)
    }
    #[inline(always)]
    fn small_sigma1(x: u64) -> u64 {
        x.rotate_right(19) ^ x.rotate_right(61) ^ (x >> 6)
    }
}

impl Compress32 for Compress {
    fn supported() -> bool {
        true
    }

    unsafe fn compress(state: &mut [u32; 8], blocks: &[[u8; 64]]) {
        compress256::<Compress>(state, blocks)
    }
}

impl Compress64 for Compress {
    fn supported() -> bool {
        true
    }

    unsafe fn compress(state: &mut [u64; 8], blocks: &[[u8; 128]]) {
        compress512::<Compress>(state, blocks)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::sha2::tests::check_known_answers;

    #[test]
    fn known_answers() {
        check_known_answers::<Sha224, Sha256, Sha384, Sha512>();
    }
}
