//! Hardware accelerated of AES for Intel x86 and x86_64.
//!
//! This implementation uses the
//! [AES-NI instructions](https://www.intel.com/content/dam/doc/white-paper/advanced-encryption-standard-new-instructions-set-paper.pdf),
//! if supported.
//! Otherwise, it falls back to a software only implementation.

#[cfg(target_arch = "x86")]
use core::arch::x86::*;

#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

use core::mem::{self, MaybeUninit};
use hybrid_array::Array;
use once_cell::race::OnceBool;
use paste::paste;
use seq_macro::seq;
use typenum::U;
use crate::cipher::{
    KeySize,
    BlockSize,
    NewUsingKey,
    Rekey,
    EncryptBlocks,
    DecryptBlocks,
    EncryptingBlockCipher,
    DecryptingBlockCipher,
    BlockCipher
};
use crate::cipher::aes::soft;
use crate::error::Error;

cpufeatures::new!{cpu_aes, "aes", "sse2"}

fn is_aes_detected() -> bool {
    static DETECTED: OnceBool = OnceBool::new();
    DETECTED.get_or_init(|| {
        let token: cpu_aes::InitToken = cpu_aes::init();
        token.get()
    })
}

fn expand_key128(key: &[u8; 16]) -> [__m128i; 11] {
    unsafe {
        let assist = |a, b| {
            let b = _mm_shuffle_epi32 (b, 0xff);
            let c = _mm_slli_si128 (a, 0x4);
            let a = _mm_xor_si128 (a, c);
            let c = _mm_slli_si128 (c, 0x4);
            let a = _mm_xor_si128 (a, c);
            let c = _mm_slli_si128 (c, 0x4);
            let a = _mm_xor_si128 (a, c);
            _mm_xor_si128 (a, b)
        };

        let mut w = [MaybeUninit::<__m128i>::uninit(); 11];
        let t = _mm_loadu_si128(key.as_ptr().cast());
        w[0].write(t);
        let t = assist(t, _mm_aeskeygenassist_si128(t, 0x01));
        w[1].write(t);
        let t = assist(t, _mm_aeskeygenassist_si128(t, 0x02));
        w[2].write(t);
        let t = assist(t, _mm_aeskeygenassist_si128(t, 0x04));
        w[3].write(t);
        let t = assist(t, _mm_aeskeygenassist_si128(t, 0x08));
        w[4].write(t);
        let t = assist(t, _mm_aeskeygenassist_si128(t, 0x10));
        w[5].write(t);
        let t = assist(t, _mm_aeskeygenassist_si128(t, 0x20));
        w[6].write(t);
        let t = assist(t, _mm_aeskeygenassist_si128(t, 0x40));
        w[7].write(t);
        let t = assist(t, _mm_aeskeygenassist_si128(t, 0x80));
        w[8].write(t);
        let t = assist(t, _mm_aeskeygenassist_si128(t, 0x1b));
        w[9].write(t);
        let t = assist(t, _mm_aeskeygenassist_si128(t, 0x36));
        w[10].write(t);

        mem::transmute(w)
    }
}

fn expand_key192(key: &[u8; 24]) -> [__m128i; 13] {
    unsafe fn shuffle<const MASK: i32>(a: __m128i, b: __m128i) -> __m128i {
        let a = _mm_castsi128_pd(a);
        let b = _mm_castsi128_pd(b);
        _mm_castpd_si128(_mm_shuffle_pd(a, b, MASK))
    }

    unsafe {
        let assist = |a, b, c| {
            let b = _mm_shuffle_epi32(b, 0x55);
            let d = _mm_slli_si128(a, 0x4);
            let a = _mm_xor_si128(a, d);
            let d = _mm_slli_si128(d, 0x4);
            let a = _mm_xor_si128(a, d);
            let d = _mm_slli_si128(d, 0x4);
            let a = _mm_xor_si128(a, d);
            let a = _mm_xor_si128(a, b);
            let b = _mm_shuffle_epi32(a, 0xff);
            let d = _mm_slli_si128(c, 0x4);
            let c = _mm_xor_si128(c, d);
            let c = _mm_xor_si128(c, b);
            (a, c)
        };

        let mut w = [MaybeUninit::<__m128i>::uninit(); 13];

        let k  = key.as_ptr();
        let a = _mm_loadu_si128(k.cast());
        let b = _mm_loadu_si64(k.add(16));

        w[0].write(a);
        let c = b;
        let (a, b) = assist(a, _mm_aeskeygenassist_si128(b, 0x1), b);
        w[1].write(shuffle::<0>(c, a));
        w[2].write(shuffle::<1>(a, b));
        let (a, b) = assist(a, _mm_aeskeygenassist_si128(b, 0x2), b);
        w[3].write(a);
        let c = b;
        let (a, b) = assist(a, _mm_aeskeygenassist_si128(b, 0x4), b);
        w[4].write(shuffle::<0>(c, a));
        w[5].write(shuffle::<1>(a, b));
        let (a, b) = assist(a, _mm_aeskeygenassist_si128(b, 0x8), b);
        w[6].write(a);
        let c = b;
        let (a, b) = assist(a, _mm_aeskeygenassist_si128(b, 0x10), b);
        w[7].write(shuffle::<0>(c, a));
        w[8].write(shuffle::<1>(a, b));
        let (a, b) = assist(a, _mm_aeskeygenassist_si128(b, 0x20), b);
        w[9].write(a);
        let c = b;
        let (a, b) = assist(a, _mm_aeskeygenassist_si128(b, 0x40), b);
        w[10].write(shuffle::<0>(c, a));
        w[11].write(shuffle::<1>(a, b));
        let (a, _) = assist(a, _mm_aeskeygenassist_si128(b, 0x80), b);
        w[12].write(a);

        mem::transmute(w)
    }
}

fn expand_key256(key: &[u8; 32]) -> [__m128i; 15] {
    unsafe {
        let assist1 = |a, b| {
            let b = _mm_shuffle_epi32(b, 0xff);
            let c = _mm_slli_si128(a, 0x04);
            let a = _mm_xor_si128(a, c);
            let c = _mm_slli_si128(c, 0x04);
            let a = _mm_xor_si128(a, c);
            let c = _mm_slli_si128(c, 0x04);
            let a = _mm_xor_si128(a, c);
            _mm_xor_si128(a, b)
        };

        let assist2 = |a, b| {
            let c = _mm_aeskeygenassist_si128(a, 0x00);
            let d = _mm_shuffle_epi32(c, 0xaa);
            let c = _mm_slli_si128(b, 0x04);
            let b = _mm_xor_si128(b, c);
            let c = _mm_slli_si128(c, 0x04);
            let b = _mm_xor_si128(b, c);
            let c = _mm_slli_si128(c, 0x04);
            let b = _mm_xor_si128(b, c);
            let b = _mm_xor_si128(b, d);
            (a, b)
        };

        let mut w = [MaybeUninit::<__m128i>::uninit(); 15];

        let a = _mm_loadu_si128(key.as_ptr().cast());
        let b = _mm_loadu_si128(key.as_ptr().add(16).cast());
        w[0].write(a);
        w[1].write(b);
        let a = assist1(a, _mm_aeskeygenassist_si128(b, 0x01));
        w[2].write(a);
        let (a, b) = assist2(a, b);
        w[3].write(b);
        let a = assist1(a, _mm_aeskeygenassist_si128(b, 0x02));
        w[4].write(a);
        let (a, b) = assist2(a, b);
        w[5].write(b);
        let a = assist1(a, _mm_aeskeygenassist_si128(b, 0x04));
        w[6].write(a);
        let (a, b) = assist2(a, b);
        w[7].write(b);
        let a = assist1(a, _mm_aeskeygenassist_si128(b, 0x08));
        w[8].write(a);
        let (a, b) = assist2(a, b);
        w[9].write(b);
        let a = assist1(a, _mm_aeskeygenassist_si128(b, 0x10));
        w[10].write(a);
        let (a, b) = assist2(a, b);
        w[11].write(b);
        let a = assist1(a, _mm_aeskeygenassist_si128(b, 0x20));
        w[12].write(a);
        let (a, b) = assist2(a, b);
        w[13].write(b);
        let a = assist1(a, _mm_aeskeygenassist_si128(b, 0x40));
        w[14].write(a);

        mem::transmute(w)
    }
}

fn invert_key<const N: usize>(w: &[__m128i; N]) -> [__m128i; N]
{
    let mut dw: [MaybeUninit<__m128i>; N] =
        [const { MaybeUninit::uninit() }; N];

    unsafe {
        dw[0].write(w[N - 1]);
        for i in 1..(N - 1) {
            dw[i].write(_mm_aesimc_si128(w[N - 1 - i]));
        }
        dw[N - 1].write(w[0]);

        *(dw.as_ptr().cast())
    }
}


macro_rules! crypt {
    ($name: ident, $op: ident, $n: literal) => {
        #[target_feature(enable = "aes")]
        unsafe fn $name<const ROUNDS: usize>(
            mut key: *const __m128i,
            mut src: *const __m128i,
            mut dst: *mut __m128i
        ) -> (*const __m128i, *mut __m128i) {
            seq!(N in 0..$n {
                let mut r~N = _mm_loadu_si128(src);
                src = src.add(1);
            });

            seq!(N in 0..$n {
                r~N = _mm_xor_si128(r~N, *key);
            });
            key = key.add(1);

            for _ in 1..ROUNDS {
                seq!(N in 0..$n {
                    r~N = paste!([<_mm_ $op _si128>])(r~N, *key);
                });
                key = key.add(1);
            }
            seq!(N in 0..$n {
                r~N = paste!([<_mm_ $op last _si128>])(r~N, *key);
            });

            seq!(N in 0..$n {
                _mm_storeu_si128(dst, r~N);
                dst = dst.add(1);
            });

            (src, dst)
        }
    }
}

crypt!{encrypt8, aesenc, 8}
crypt!{encrypt7, aesenc, 7}
crypt!{encrypt6, aesenc, 6}
crypt!{encrypt5, aesenc, 5}
crypt!{encrypt4, aesenc, 4}
crypt!{encrypt3, aesenc, 3}
crypt!{encrypt2, aesenc, 2}
crypt!{encrypt1, aesenc, 1}

crypt!{decrypt8, aesdec, 8}
crypt!{decrypt7, aesdec, 7}
crypt!{decrypt6, aesdec, 6}
crypt!{decrypt5, aesdec, 5}
crypt!{decrypt4, aesdec, 4}
crypt!{decrypt3, aesdec, 3}
crypt!{decrypt2, aesdec, 2}
crypt!{decrypt1, aesdec, 1}

macro_rules! def_encrypt_blocks {
    (
        $name: ident,
        $rounds: literal
    ) => {
        impl EncryptBlocks for $name {
            fn encrypt_blocks(
                &self,
                plaintext: &[Array<u8, Self::BlockSize>],
                ciphertext: &mut [Array<u8, Self::BlockSize>]
            ) {
                assert_eq!(plaintext.len(), ciphertext.len());

                let w = self.w.as_ptr();
                let mut src: *const __m128i = plaintext.as_ptr().cast();
                let mut dst: *mut __m128i = ciphertext.as_mut_ptr().cast();
                let mut blocks = plaintext.len();
                unsafe {
                    while blocks >= 8 {
                        (src, dst) = encrypt8::<$rounds>(w, src, dst);
                        blocks = blocks - 8;
                    }
                    match blocks {
                        7 => { encrypt7::<$rounds>(w, src, dst); },
                        6 => { encrypt6::<$rounds>(w, src, dst); },
                        5 => { encrypt5::<$rounds>(w, src, dst); },
                        4 => { encrypt4::<$rounds>(w, src, dst); },
                        3 => { encrypt3::<$rounds>(w, src, dst); },
                        2 => { encrypt2::<$rounds>(w, src, dst); },
                        1 => { encrypt1::<$rounds>(w, src, dst); },
                        _ => ()
                    };
                }
            }
        }
    }
}

macro_rules! def_decrypt_blocks {
    (
        $name: ident,
        $rounds: literal
    ) => {
        impl DecryptBlocks for $name {
            fn decrypt_blocks(
                &self,
                ciphertext: &[Array<u8, Self::BlockSize>],
                plaintext: &mut [Array<u8, Self::BlockSize>]
            ) {
                assert_eq!(ciphertext.len(), plaintext.len());

                let dw = self.dw.as_ptr();
                let mut src: *const __m128i = ciphertext.as_ptr().cast();
                let mut dst: *mut __m128i = plaintext.as_mut_ptr().cast();
                let mut blocks = plaintext.len();
                unsafe {
                    while blocks >= 8 {
                        (src, dst) = decrypt8::<$rounds>(dw, src, dst);
                        blocks = blocks - 8;
                    }
                    match blocks {
                        7 => { decrypt7::<$rounds>(dw, src, dst); },
                        6 => { decrypt6::<$rounds>(dw, src, dst); },
                        5 => { decrypt5::<$rounds>(dw, src, dst); },
                        4 => { decrypt4::<$rounds>(dw, src, dst); },
                        3 => { decrypt3::<$rounds>(dw, src, dst); },
                        2 => { decrypt2::<$rounds>(dw, src, dst); },
                        1 => { decrypt1::<$rounds>(dw, src, dst); },
                        _ => ()
                    };
                }
            }
        }
    }
}

macro_rules! def_aes_encrypt {
    (
        $name: ident,
        $key_size: literal,
        $rounds: literal,
        $expand_key: ident
    ) => {
        pub struct $name {
            w: [__m128i; $rounds + 1],
        }

        impl KeySize for $name {
            type KeySize = U<$key_size>;
        }

        impl BlockSize for $name {
            type BlockSize = U<16>;
        }

        impl NewUsingKey for $name {
            fn new(key: &[u8]) -> Result<Self, Error> {
                let key: &[u8; $key_size] = key.try_into()
                    .map_err(|_| Error::InvalidKeyLength)?;
                let w = $expand_key(key);
                Ok(Self { w })
            }
        }

        impl Rekey for $name {
            fn rekey(&mut self, key: &[u8]) -> Result<(), Error> {
                let key: &[u8; $key_size] = key.try_into()
                    .map_err(|_| Error::InvalidKeyLength)?;
                self.w = $expand_key(key);
                Ok(())
            }
        }

        def_encrypt_blocks!{$name, $rounds}

        impl EncryptingBlockCipher for $name {}
    }
}

macro_rules! def_aes {
    (
        $name: ident,
        $key_size: literal,
        $rounds: literal,
        $expand_key: ident
    ) => {
        pub struct $name {
            w: [__m128i; $rounds + 1],
            dw: [__m128i; $rounds + 1],
        }

        impl KeySize for $name {
            type KeySize = U<$key_size>;
        }

        impl BlockSize for $name {
            type BlockSize = U<16>;
        }

        impl NewUsingKey for $name {
            fn new(key: &[u8]) -> Result<Self, Error> {
                let key: &[u8; $key_size] = key.try_into()
                    .map_err(|_| Error::InvalidKeyLength)?;
                let w = $expand_key(key);
                let dw = invert_key(&w);
                Ok(Self { w, dw })
            }
        }

        impl Rekey for $name {
            fn rekey(&mut self, key: &[u8]) -> Result<(), Error> {
                let key: &[u8; $key_size] = key.try_into()
                    .map_err(|_| Error::InvalidKeyLength)?;
                self.w = $expand_key(key);
                self.dw = invert_key(&self.w);
                Ok(())
            }
        }

        def_encrypt_blocks!{$name, $rounds}
        def_decrypt_blocks!{$name, $rounds}

        impl EncryptingBlockCipher for $name {}
        impl DecryptingBlockCipher for $name {}
        impl BlockCipher for $name {}
    }
}

def_aes_encrypt!{AcceleratedAes128Encrypt, 16, 10, expand_key128}
def_aes_encrypt!{AcceleratedAes192Encrypt, 24, 12, expand_key192}
def_aes_encrypt!{AcceleratedAes256Encrypt, 32, 14, expand_key256}
def_aes!{AcceleratedAes128, 16, 10, expand_key128}
def_aes!{AcceleratedAes192, 24, 12, expand_key192}
def_aes!{AcceleratedAes256, 32, 14, expand_key256}

define_encrypting_block_cipher_enum!{
    pub, Aes128Encrypt,
    if is_aes_detected() => Hw(AcceleratedAes128Encrypt),
    Sw(soft::Aes128)
}

define_encrypting_block_cipher_enum!{
    pub, Aes192Encrypt,
    if is_aes_detected() => Hw(AcceleratedAes192Encrypt),
    Sw(soft::Aes192)
}

define_encrypting_block_cipher_enum!{
    pub, Aes256Encrypt,
    if is_aes_detected() => Hw(AcceleratedAes256Encrypt),
    Sw(soft::Aes256)
}

define_block_cipher_enum!{
    pub, Aes128,
    if is_aes_detected() => Hw(AcceleratedAes128),
    Sw(soft::Aes128)
}

define_block_cipher_enum!{
    pub, Aes192,
    if is_aes_detected() => Hw(AcceleratedAes192),
    Sw(soft::Aes192)
}

define_block_cipher_enum!{
    pub, Aes256,
    if is_aes_detected() => Hw(AcceleratedAes256),
    Sw(soft::Aes256)
}

#[cfg(test)]
mod test {
    use crate::test::acvp::block;
    use super::{Aes128, Aes192, Aes256};

    #[test]
    fn test_aes128() {
        block::test::<Aes128>("aes_ecb");
    }

    #[test]
    fn test_aes192() {
        block::test::<Aes192>("aes_ecb");
    }

    #[test]
    fn test_aes256() {
        block::test::<Aes256>("aes_ecb");
    }
}
