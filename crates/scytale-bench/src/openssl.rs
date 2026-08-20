//! The narrowest possible binding to OpenSSL's AES.
//!
//! Only the low-level `AES_*` interface is declared. Using EVP would measure
//! OpenSSL's dispatch and context machinery as well as its cipher, which is
//! not what we are comparing.

#![cfg(openssl_available)]

use std::os::raw::{c_int, c_uchar, c_uint};

#[repr(C)]
#[derive(Clone, Copy)]
struct AesKey {
    // AES_KEY is { unsigned int rd_key[4 * (AES_MAXNR + 1)]; int rounds; }
    // with AES_MAXNR 14, so 60 words plus the round count.
    rd_key: [c_uint; 60],
    rounds: c_int,
}

impl Default for AesKey {
    fn default() -> Self {
        Self { rd_key: [0; 60], rounds: 0 }
    }
}

unsafe extern "C" {
    fn AES_set_encrypt_key(
        user_key: *const c_uchar,
        bits: c_int,
        key: *mut AesKey,
    ) -> c_int;

    fn AES_set_decrypt_key(
        user_key: *const c_uchar,
        bits: c_int,
        key: *mut AesKey,
    ) -> c_int;

    fn AES_encrypt(
        input: *const c_uchar,
        out: *mut c_uchar,
        key: *const AesKey,
    );

    fn AES_decrypt(
        input: *const c_uchar,
        out: *mut c_uchar,
        key: *const AesKey,
    );
}

/// An OpenSSL AES key schedule for one direction.
pub struct OpensslAes {
    key: AesKey,
    encrypting: bool,
}

/// A key length OpenSSL rejected.
#[derive(Debug)]
pub struct BadKeyLength(pub usize);

impl OpensslAes {
    /// Build an encryption schedule. `key` must be 16, 24 or 32 bytes.
    pub fn try_new_encrypt(key: &[u8]) -> Result<Self, BadKeyLength> {
        let mut schedule = AesKey::default();
        let bits = (key.len() * 8) as c_int;
        // SAFETY: key points to key.len() bytes and bits describes exactly
        // that length; schedule is a valid, correctly sized AES_KEY.
        let rc =
            unsafe { AES_set_encrypt_key(key.as_ptr(), bits, &mut schedule) };
        if rc != 0 {
            return Err(BadKeyLength(key.len()));
        }
        Ok(Self { key: schedule, encrypting: true })
    }

    /// Build a decryption schedule.
    pub fn try_new_decrypt(key: &[u8]) -> Result<Self, BadKeyLength> {
        let mut schedule = AesKey::default();
        let bits = (key.len() * 8) as c_int;
        // SAFETY: as for try_new_encrypt.
        let rc =
            unsafe { AES_set_decrypt_key(key.as_ptr(), bits, &mut schedule) };
        if rc != 0 {
            return Err(BadKeyLength(key.len()));
        }
        Ok(Self { key: schedule, encrypting: false })
    }

    /// Encrypt whole blocks in place, returning bytes consumed.
    ///
    /// Deliberately mirrors scytale's bulk signature so both sides of the
    /// comparison do the same work per call.
    pub fn encrypt(&self, data: &mut [u8]) -> usize {
        debug_assert!(self.encrypting, "schedule is for decryption");
        let (blocks, _tail) = data.as_chunks_mut::<16>();
        for block in blocks.iter_mut() {
            let src = *block;
            // SAFETY: src and block are both 16 bytes, the size AES_encrypt
            // reads and writes, and self.key is an initialized schedule.
            unsafe {
                AES_encrypt(src.as_ptr(), block.as_mut_ptr(), &self.key);
            }
        }
        blocks.len() * 16
    }

    /// Decrypt whole blocks in place, returning bytes consumed.
    pub fn decrypt(&self, data: &mut [u8]) -> usize {
        debug_assert!(!self.encrypting, "schedule is for encryption");
        let (blocks, _tail) = data.as_chunks_mut::<16>();
        for block in blocks.iter_mut() {
            let src = *block;
            // SAFETY: as for encrypt.
            unsafe {
                AES_decrypt(src.as_ptr(), block.as_mut_ptr(), &self.key);
            }
        }
        blocks.len() * 16
    }
}

/// The block function `CRYPTO_ctr128_encrypt` drives.
type Block128 =
    unsafe extern "C" fn(*const c_uchar, *mut c_uchar, *const AesKey);

unsafe extern "C" {
    // Both vendored archives define this; the C one is linked first, so
    // it resolves there. It is the same portable C source in both, and
    // the cipher it runs is whichever block function is passed in.
    fn CRYPTO_ctr128_encrypt(
        input: *const c_uchar,
        out: *mut c_uchar,
        len: usize,
        key: *const AesKey,
        ivec: *mut c_uchar,
        ecount_buf: *mut c_uchar,
        num: *mut c_uint,
        block: Block128,
    );
}

/// OpenSSL's generic CTR mode over its C AES.
///
/// This is the counterpart to scytale's generic `Ctr` over the portable
/// T-table cipher: the same shape of code, a mode loop in C calling a
/// scalar block function, holding the same streaming state.
pub struct OpensslCtr {
    key: AesKey,
    ivec: [u8; 16],
    ecount: [u8; 16],
    num: c_uint,
}

impl OpensslCtr {
    /// Build the schedule and set the initial counter block.
    pub fn try_new(key: &[u8], iv: &[u8; 16]) -> Result<Self, BadKeyLength> {
        let mut schedule = AesKey::default();
        let bits = (key.len() * 8) as c_int;
        // SAFETY: key points to key.len() bytes and bits describes
        // exactly that length; schedule is a valid AES_KEY.
        let rc =
            unsafe { AES_set_encrypt_key(key.as_ptr(), bits, &mut schedule) };
        if rc != 0 {
            return Err(BadKeyLength(key.len()));
        }
        Ok(Self {
            key: schedule,
            ivec: *iv,
            ecount: [0u8; 16],
            num: 0,
        })
    }

    /// XOR the keystream into `data`, advancing the stream. Any length;
    /// resumable, exactly like scytale's `apply_keystream`.
    pub fn apply_keystream(&mut self, data: &mut [u8]) {
        let ptr = data.as_mut_ptr();
        // SAFETY: input and output are the same buffer, which CTR
        // permits since each byte is read before it is written; ivec and
        // ecount are the 16-byte blocks the function expects and num is
        // its offset into ecount; AES_encrypt matches the schedule.
        unsafe {
            CRYPTO_ctr128_encrypt(
                ptr,
                ptr,
                data.len(),
                &self.key,
                self.ivec.as_mut_ptr(),
                self.ecount.as_mut_ptr(),
                &mut self.num,
                AES_encrypt,
            );
        }
    }
}

unsafe extern "C" {
    fn aesni_set_encrypt_key(
        user_key: *const c_uchar,
        bits: c_int,
        key: *mut AesKey,
    ) -> c_int;

    fn aesni_set_decrypt_key(
        user_key: *const c_uchar,
        bits: c_int,
        key: *mut AesKey,
    ) -> c_int;

    fn aesni_encrypt(
        input: *const c_uchar,
        out: *mut c_uchar,
        key: *const AesKey,
    );

    fn aesni_decrypt(
        input: *const c_uchar,
        out: *mut c_uchar,
        key: *const AesKey,
    );

    fn aesni_ecb_encrypt(
        input: *const c_uchar,
        out: *mut c_uchar,
        length: usize,
        key: *const AesKey,
        enc: c_int,
    );

    fn aesni_ctr32_encrypt_blocks(
        input: *const c_uchar,
        out: *mut c_uchar,
        blocks: usize,
        key: *const AesKey,
        ivec: *const c_uchar,
    );
}

/// OpenSSL's AES-NI kernels.
///
/// This is the counterpart to scytale's own AES-NI backend. It is
/// deliberately not `AES_encrypt`, which in an assembly build is OpenSSL's
/// assembly T-table cipher rather than its AES-NI one, and not EVP, which
/// would add dispatch and context handling to the measurement.
pub struct OpensslAesni {
    key: AesKey,
    encrypting: bool,
}

impl OpensslAesni {
    /// Build an encryption schedule. `key` must be 16, 24 or 32 bytes.
    pub fn try_new_encrypt(key: &[u8]) -> Result<Self, BadKeyLength> {
        let mut schedule = AesKey::default();
        let bits = (key.len() * 8) as c_int;
        // SAFETY: key points to key.len() bytes and bits describes exactly
        // that length; schedule is a valid, correctly sized AES_KEY.
        let rc =
            unsafe { aesni_set_encrypt_key(key.as_ptr(), bits, &mut schedule) };
        if rc != 0 {
            return Err(BadKeyLength(key.len()));
        }
        Ok(Self { key: schedule, encrypting: true })
    }

    /// Build a decryption schedule.
    pub fn try_new_decrypt(key: &[u8]) -> Result<Self, BadKeyLength> {
        let mut schedule = AesKey::default();
        let bits = (key.len() * 8) as c_int;
        // SAFETY: as for try_new_encrypt.
        let rc =
            unsafe { aesni_set_decrypt_key(key.as_ptr(), bits, &mut schedule) };
        if rc != 0 {
            return Err(BadKeyLength(key.len()));
        }
        Ok(Self { key: schedule, encrypting: false })
    }

    /// Encrypt whole blocks in place, returning bytes consumed.
    pub fn encrypt(&self, data: &mut [u8]) -> usize {
        debug_assert!(self.encrypting, "schedule is for decryption");
        self.run(data, 1)
    }

    /// Decrypt whole blocks in place, returning bytes consumed.
    pub fn decrypt(&self, data: &mut [u8]) -> usize {
        debug_assert!(!self.encrypting, "schedule is for encryption");
        self.run(data, 0)
    }

    /// Encrypt exactly one block in place.
    ///
    /// OpenSSL's own single block entry, which is what scytale's
    /// `encrypt_block` should be measured against: going through the ECB
    /// entry instead would charge it for a length dispatch that a caller
    /// with one block to encrypt does not use.
    pub fn encrypt_block(&self, block: &mut [u8; 16]) {
        debug_assert!(self.encrypting, "schedule is for decryption");
        let src = *block;
        // SAFETY: both pointers are to sixteen bytes, the size this
        // reads and writes, and self.key is an initialized schedule.
        unsafe {
            aesni_encrypt(src.as_ptr(), block.as_mut_ptr(), &self.key);
        }
    }

    /// Decrypt exactly one block in place.
    pub fn decrypt_block(&self, block: &mut [u8; 16]) {
        debug_assert!(!self.encrypting, "schedule is for encryption");
        let src = *block;
        // SAFETY: as for encrypt_block.
        unsafe {
            aesni_decrypt(src.as_ptr(), block.as_mut_ptr(), &self.key);
        }
    }

    fn run(&self, data: &mut [u8], enc: c_int) -> usize {
        let whole = data.len() - data.len() % 16;
        if whole == 0 {
            return 0;
        }
        let ptr = data.as_mut_ptr();
        // SAFETY: whole is a multiple of the block size and no larger than
        // the buffer; ECB has no chaining, so input and output may alias.
        unsafe {
            aesni_ecb_encrypt(ptr, ptr, whole, &self.key, enc);
        }
        whole
    }
}

/// OpenSSL's fused AES-NI counter kernel.
///
/// This is the counterpart to scytale's own fused AES-NI CTR. The
/// kernel increments only the low 32 bits of the counter and does not
/// write it back, so this wrapper advances it between calls. With an
/// IV whose low 32 bits are zero and messages up to 2^32 blocks, its
/// output is byte identical to a full 128-bit counter's, which the
/// agreement tests rely on and the benchmark stays within.
pub struct OpensslAesniCtr {
    key: AesKey,
    ivec: [u8; 16],
}

impl OpensslAesniCtr {
    /// Build the schedule and set the initial counter block.
    pub fn try_new(key: &[u8], iv: &[u8; 16]) -> Result<Self, BadKeyLength> {
        let mut schedule = AesKey::default();
        let bits = (key.len() * 8) as c_int;
        // SAFETY: key points to key.len() bytes and bits describes
        // exactly that length; schedule is a valid AES_KEY.
        let rc = unsafe {
            aesni_set_encrypt_key(key.as_ptr(), bits, &mut schedule)
        };
        if rc != 0 {
            return Err(BadKeyLength(key.len()));
        }
        Ok(Self { key: schedule, ivec: *iv })
    }

    /// Encrypt whole counter blocks into `data` in place, returning
    /// bytes consumed. Mirrors scytale's fused `ctr` signature shape so
    /// both sides of the comparison do the same work per call.
    pub fn ctr(&mut self, data: &mut [u8]) -> usize {
        let blocks = data.len() / 16;
        if blocks == 0 {
            return 0;
        }
        let ptr = data.as_mut_ptr();
        // SAFETY: the buffer holds `blocks` whole blocks; input and
        // output may alias because each block is read before it is
        // written; ivec is the 16-byte counter the kernel expects.
        unsafe {
            aesni_ctr32_encrypt_blocks(
                ptr,
                ptr,
                blocks,
                &self.key,
                self.ivec.as_ptr(),
            );
        }
        // The kernel leaves the counter untouched; advance its low 32
        // bits the way the kernel itself counted.
        let low = u32::from_be_bytes([
            self.ivec[12],
            self.ivec[13],
            self.ivec[14],
            self.ivec[15],
        ]);
        let low = low.wrapping_add(blocks as u32).to_be_bytes();
        self.ivec[12..16].copy_from_slice(&low);
        blocks * 16
    }
}
