//! SHA-2 (Secure Hash Algorithm 2) is a family of hash algorithms based on the
//! [Merkle–Damgård construction](https://en.wikipedia.org/wiki/Merkle%E2%80%93Damg%C3%A5rd_construction).
//! It was designed by the United States
//! [National Security Agency](https://en.wikipedia.org/wiki/National_Security_Agency)
//! and first published in 2001.
//! The latest specification is provided in
//! [FIPS 180-4](https://csrc.nist.gov/pubs/fips/180-4/upd1/final).

use core::marker::PhantomData;
use core::mem::size_of;
use core::num::Wrapping;
use core::ops::Add;
use core::ptr::{read_unaligned, write_unaligned};
use core::slice;
use delegate::delegate;
use num_traits::{AsPrimitive, PrimInt};
use std::io::Write;
use crate::block::{Buffer, Blocks};
use crate::hash::Hash;

type State<Word> = [Word; 8];

trait Sha2Initializer<Word> {
    const H: State<Word>;
}

#[derive(Clone, Copy, Debug)]
struct Sha224Initializer;
impl Sha2Initializer<u32> for Sha224Initializer {
    const H: State<u32> = [
        0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939,
        0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4
    ];
}

#[derive(Clone, Copy, Debug)]
struct Sha256Initializer;
impl Sha2Initializer<u32> for Sha256Initializer {
    const H: State<u32> = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    ];
}

#[derive(Clone, Copy, Debug)]
struct Sha384Initializer;
impl Sha2Initializer<u64> for Sha384Initializer {
    const H: State<u64> = [
        0xcbbb9d5dc1059ed8, 0x629a292a367cd507, 0x9159015a3070dd17,
        0x152fecd8f70e5939, 0x67332667ffc00b31, 0x8eb44a8768581511,
        0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4
    ];
}

#[derive(Clone, Copy, Debug)]
struct Sha512Initializer;
impl Sha2Initializer<u64> for Sha512Initializer {
    const H: State<u64> = [
        0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b,
        0xa54ff53a5f1d36f1, 0x510e527fade682d1, 0x9b05688c2b3e6c1f,
        0x1f83d9abfb41bd6b, 0x5be0cd19137e2179
    ];
}

#[derive(Clone, Copy, Debug)]
struct Sha512_224Initializer;
impl Sha2Initializer<u64> for Sha512_224Initializer {
    const H: State<u64> = [
        0x8c3d37c819544da2, 0x73e1996689dcd4d6, 0x1dfab7ae32ff9c82,
        0x679dd514582f9fcf, 0x0f6d2b697bd44da8, 0x77e36f7304c48942,
        0x3f9d85a86a1d36c8, 0x1112e6ad91d692a1
    ];
}

#[derive(Clone, Copy, Debug)]
struct Sha512_256Initializer;
impl Sha2Initializer<u64> for Sha512_256Initializer {
    const H: State<u64> = [
        0x22312194FC2BF72C, 0x9f555fa3c84c64c2, 0x2393b86b6f53b151,
        0x963877195940eabd, 0x96283ee2a88effe3, 0xbe5e1e2553863992,
        0x2b0199fc2c85b8aa, 0x0eb72ddc81c52ca2
    ];
}

trait Sha2Constants<Word, const N: usize> {
    const K: [Word; N];
}

#[derive(Clone, Copy, Debug)]
struct Sha256Constants;
impl Sha2Constants<u32, 64> for Sha256Constants {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ];
}

#[derive(Clone, Copy, Debug)]
struct Sha512Constants;
impl Sha2Constants<u64, 80> for Sha512Constants {
    const K: [u64; 80] = [
        0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f,
        0xe9b5dba58189dbbc, 0x3956c25bf348b538, 0x59f111f1b605d019,
        0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242,
        0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
        0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 
        0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3,
        0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65, 0x2de92c6f592b0275,
        0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
        0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f,
        0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725, 
        0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc,
        0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
        0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6,
        0x92722c851482353b, 0xa2bfe8a14cf10364, 0xa81a664bbc423001,
        0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218, 
        0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
        0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99,
        0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb,
        0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc,
        0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec, 
        0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915,
        0xc67178f2e372532b, 0xca273eceea26619c, 0xd186b8c721c0c207,
        0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba,
        0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
        0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 
        0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a,
        0x5fcb6fab3ad6faec, 0x6c44198c4a475817
    ];
}

trait Sha2Functions<Word: PrimInt> {
    #[inline(always)]
    fn ch(x: Word, y: Word, z: Word) -> Word {
        (x & y) ^ (!x & z)
    }

    #[inline(always)]
    fn maj(x: Word, y: Word, z: Word) -> Word {
        (x & y) ^ (x & z) ^ (y & z)
    }

    #[allow(non_snake_case)]
    fn Σ0(x: Word) -> Word;
    #[allow(non_snake_case)]
    fn Σ1(x: Word) -> Word;
    fn σ0(x: Word) -> Word;
    fn σ1(x: Word) -> Word;
}

#[derive(Clone, Copy, Debug)]
struct Sha256Functions;
impl<Word: PrimInt> Sha2Functions<Word> for Sha256Functions {
    #[inline(always)]
    fn Σ0(x: Word) -> Word {
        x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22)
    }

    #[inline(always)]
    fn Σ1(x: Word) -> Word {
        x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25)
    }

    #[inline(always)]
    fn σ0(x: Word) -> Word {
        x.rotate_right(7) ^ x.rotate_right(18) ^ x >> 3
    }

    #[inline(always)]
    fn σ1(x: Word) -> Word {
        x.rotate_right(17) ^ x.rotate_right(19) ^ x >> 10
    }
}

#[derive(Clone, Copy, Debug)]
struct Sha512Functions;
impl<Word: PrimInt> Sha2Functions<Word> for Sha512Functions {
    #[inline(always)]
    fn Σ0(x: Word) -> Word {
        x.rotate_right(28) ^ x.rotate_right(34) ^ x.rotate_right(39)
    }

    #[inline(always)]
    fn Σ1(x: Word) -> Word {
        x.rotate_right(14) ^ x.rotate_right(18) ^ x.rotate_right(41)
    }

    #[inline(always)]
    fn σ0(x: Word) -> Word {
        x.rotate_right(1) ^ x.rotate_right(8) ^ x >> 7
    }

    #[inline(always)]
    fn σ1(x: Word) -> Word {
        x.rotate_right(19) ^ x.rotate_right(61) ^ x >> 6
    }
}

trait Sha2Core<Word, const BLOCK_SIZE: usize> {
    fn new(h: &State<Word>) -> Self;
    fn reset(&mut self, h: &State<Word>);
    fn update(&mut self, bytes: &[u8; BLOCK_SIZE]);
    fn finalize<'a>(&'a mut self) -> &'a [u8];
}

#[derive(Clone, Copy, Debug)]
struct Core<
    Word,
    Functions,
    Constants,
    const BLOCK_SIZE: usize,
    const ROUNDS: usize
>
{
    h: State<Word>,
    _functions: PhantomData<Functions>,
    _constants: PhantomData<Constants>
}

impl <
    Word,
    Functions,
    Constants,
    const BLOCK_SIZE: usize,
    const ROUNDS: usize
> Sha2Core<Word, BLOCK_SIZE>
    for Core<Word, Functions, Constants, BLOCK_SIZE, ROUNDS>
where 
    Word: PrimInt,
    State<Word>: Default,
    Wrapping<Word>: Add<Output = Wrapping<Word>>,
    Functions: Sha2Functions<Word>,
    Constants: Sha2Constants<Word, ROUNDS>
{
    fn new(h: &State<Word>) -> Self {
        Self {
            h: *h,
            _functions: PhantomData,
            _constants: PhantomData
        }
    }

    fn reset(&mut self, h: &State<Word>) {
        self.h = *h;
    }

    #[inline(always)]
    fn update(&mut self, block: &[u8; BLOCK_SIZE]) {
        let mut w = [Word::zero(); ROUNDS];

        let n = BLOCK_SIZE / size_of::<Word>();
        let mut src: *const Word = block.as_ptr().cast();
        for t in 0..n {
            let word = unsafe {
                read_unaligned(src)
            };
            src = unsafe {
                src.offset(1)
            };
            w[t] = Word::from_be(word);
        }

        for t in n..ROUNDS {
            w[t] = (
                Wrapping(Functions::σ1(w[t-2]))
                    + Wrapping(w[t-7])
                    + Wrapping(Functions::σ0(w[t-15]))
                    + Wrapping(w[t-16])
            ).0;
        }

        let mut a = self.h[0];
        let mut b = self.h[1];
        let mut c = self.h[2];
        let mut d = self.h[3];
        let mut e = self.h[4];
        let mut f = self.h[5];
        let mut g = self.h[6];
        let mut h = self.h[7];

        for t in 0..ROUNDS {
            let t1 = (
                Wrapping(h)
                    + Wrapping(Functions::Σ1(e))
                    + Wrapping(Functions::ch(e, f, g))
                    + Wrapping(Constants::K[t])
                    + Wrapping(w[t])
            ).0;
            let t2 = (
                Wrapping(Functions::Σ0(a))
                    + Wrapping(Functions::maj(a, b, c))
            ).0;
            h = g;
            g = f;
            f = e;
            e = (Wrapping(d) + Wrapping(t1)).0;
            d = c;
            c = b;
            b = a;
            a = (Wrapping(t1) + Wrapping(t2)).0;
        }

        self.h[0] = (Wrapping(self.h[0]) + Wrapping(a)).0;
        self.h[1] = (Wrapping(self.h[1]) + Wrapping(b)).0;
        self.h[2] = (Wrapping(self.h[2]) + Wrapping(c)).0;
        self.h[3] = (Wrapping(self.h[3]) + Wrapping(d)).0;
        self.h[4] = (Wrapping(self.h[4]) + Wrapping(e)).0;
        self.h[5] = (Wrapping(self.h[5]) + Wrapping(f)).0;
        self.h[6] = (Wrapping(self.h[6]) + Wrapping(g)).0;
        self.h[7] = (Wrapping(self.h[7]) + Wrapping(h)).0;
    }

    fn finalize<'a>(&'a mut self) -> &'a [u8] {
        for i in 0..8 {
            self.h[i] = Word::to_be(self.h[i]);
        }

        let ptr: *const u8 = self.h.as_ptr().cast();
        let length = size_of::<Word>() * 8;
        unsafe {
            slice::from_raw_parts(ptr, length)
        }
    }
}

#[derive(Clone, Debug)]
struct Sha2Variant<
    Word,
    Length,
    Core,
    Initializer,
    const BLOCK_SIZE: usize,
    const DIGEST_SIZE: usize>
{
    core: Core,
    length: Length,
    buffer: Buffer<u8, BLOCK_SIZE>,
    _word: PhantomData<Word>,
    _initializer: PhantomData<Initializer>
}

impl<
    Word,
    Length,
    Core,
    Initializer,
    const BLOCK_SIZE: usize,
    const DIGEST_SIZE: usize
> Sha2Variant<Word, Length, Core, Initializer, BLOCK_SIZE, DIGEST_SIZE> 
where
    Core: Sha2Core<Word, BLOCK_SIZE>,
    Length: PrimInt + 'static,
    usize: AsPrimitive<Length>,
    Initializer: Sha2Initializer<Word>
{
    fn new() -> Self {
        Self {
            core: Core::new(&Initializer::H),
            length: Length::zero(),
            buffer: Buffer::default(),
            _word: PhantomData,
            _initializer: PhantomData
        }
    }

    fn block_size() -> usize {
        BLOCK_SIZE
    }

    fn reset(&mut self) {
        self.core.reset(&Initializer::H);
        self.length = Length::zero();
        self.buffer.clear();
    }

    fn update(&mut self, data: &[u8]) {
        self.length = self.length + data.len().as_();
        for block in Blocks::new(&mut self.buffer, data) {
            self.core.update(block)
        }
    }

    fn pad(&mut self) {
        let length = self.length << 3;

        let mut block = [0u8; BLOCK_SIZE];
        let mut offset = self.buffer.len();

        block[offset] = 0x80;
        if BLOCK_SIZE - offset < size_of::<Length>() + 1 {
            self.update(&block[offset..]);
            block[offset] = 0;
            offset = 0;
        }

        let field: *mut Length =
            (&mut block[BLOCK_SIZE - size_of::<Length>()] as *mut u8).cast();
        unsafe {
            write_unaligned(field, length.to_be());
        }
        self.update(&block[offset..]);
    }

    fn finalize<'a>(&'a mut self) -> &'a [u8] {
        self.pad();
        let digest = self.core.finalize();
        &digest[..DIGEST_SIZE]
    }
}

impl<
    Word,
    Length,
    Core,
    Initializer,
    const BLOCK_SIZE: usize,
    const DIGEST_SIZE: usize
> Default
    for Sha2Variant<Word, Length, Core, Initializer, BLOCK_SIZE, DIGEST_SIZE>
where
    Core: Sha2Core<Word, BLOCK_SIZE>,
    Length: PrimInt + 'static,
    usize: AsPrimitive<Length>,
    Initializer: Sha2Initializer<Word>
{
    fn default() -> Self {
        Self::new()
    }
}

type Sha256Core = Core<u32, Sha256Functions, Sha256Constants, 64, 64>;
type Sha512Core = Core<u64, Sha512Functions, Sha512Constants, 128, 80>;

type Sha224Variant =
    Sha2Variant<u32, u64, Sha256Core, Sha224Initializer, 64, 28>;
type Sha256Variant =
    Sha2Variant<u32, u64, Sha256Core, Sha256Initializer, 64, 32>;
type Sha384Variant =
    Sha2Variant<u64, u128, Sha512Core, Sha384Initializer, 128, 48>;
type Sha512Variant =
    Sha2Variant<u64, u128, Sha512Core, Sha512Initializer, 128, 64>;
type Sha512_224Variant =
    Sha2Variant<u64, u128, Sha512Core, Sha512_224Initializer, 128, 28>;
type Sha512_256Variant =
    Sha2Variant<u64, u128, Sha512Core, Sha512_256Initializer, 128, 32>;

macro_rules! hash_newtype {
    ($name: ident, $inner: ty, $doc: tt) => {
        #[doc = $doc]
        #[derive(Clone, Debug, Default)]
        pub struct $name($inner);
        
        impl Hash for $name {
            #[inline(always)]
            fn new() -> Self {
                Self(<$inner>::new())
            }

            delegate! {
                to $inner {
                    fn block_size() -> usize;
                }
                to self.0 {
                    fn reset(&mut self);
                    fn update(&mut self, data: &[u8]);
                    fn finalize<'a>(&'a mut self) -> &'a [u8];
                }
            }
        }

        impl Write for $name {
            #[inline]
            fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
                self.0.update(data);
                Ok(data.len())
            }

            #[inline]
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
    }
}

hash_newtype!{Sha224, Sha224Variant, "SHA-224 hash algorithm"}
hash_newtype!{Sha256, Sha256Variant, "SHA-256 hash algorithm"}
hash_newtype!{Sha384, Sha384Variant, "SHA-384 hash algorithm"}
hash_newtype!{Sha512, Sha512Variant, "SHA-512 hash algorithm"}
hash_newtype!{Sha512_224, Sha512_224Variant, "SHA-512/224 hash algorithm"}
hash_newtype!{Sha512_256, Sha512_256Variant, "SHA-512/256 hash algorithm"}

#[cfg(test)]
mod test;
