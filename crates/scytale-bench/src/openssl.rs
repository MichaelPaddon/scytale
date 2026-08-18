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

    fn aesni_ecb_encrypt(
        input: *const c_uchar,
        out: *mut c_uchar,
        length: usize,
        key: *const AesKey,
        enc: c_int,
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
