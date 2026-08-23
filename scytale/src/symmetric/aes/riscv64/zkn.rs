//! AES using the RISC-V scalar cryptography extension (Zkne/Zknd),
//! with the key schedule and block loops in hand-written assembly.
//!
//! A block is held in two 64-bit registers. `aes64esm` computes one
//! half of a middle round (ShiftRows, SubBytes, MixColumns) from both
//! halves, so a round is two of those plus two xors for the key;
//! `aes64es` is the final round without MixColumns. `aes64dsm`,
//! `aes64ds` and `aes64im` are the decryption counterparts, and
//! `aes64ks1i`/`aes64ks2` build the key schedule. The loops handle one
//! block at a time.
//!
//! The S-box lives in hardware, so this implementation does not leak
//! key material through cache timing.
//!
//! # Availability
//!
//! [`Aes::try_new`] accepts when the crate was compiled with the
//! `zkne` and `zknd` target features, or, on Linux, when
//! `riscv_hwprobe` reports them. Otherwise it returns
//! [`Error::NotSupported`].
//!
//! # Example
//!
//! ```
//! use scytale::symmetric::aes::riscv64::zkn::Aes;
//! use scytale::symmetric::Error;
//!
//! # fn main() -> Result<(), Error> {
//! match Aes::try_new(&[0u8; 16]) {
//!     Ok(aes) => {
//!         let mut block = [0u8; 16];
//!         aes.encrypt_block(&mut block);
//!         aes.decrypt_block(&mut block);
//!         assert_eq!(block, [0u8; 16]);
//!     }
//!     Err(Error::NotSupported) => {} // no Zkn on this machine
//!     Err(e) => return Err(e),
//! }
//! # Ok(())
//! # }
//! ```

use core::fmt;

use super::has_zkn;
use crate::symmetric::aes::{KeySize, BLOCK_SIZE};
use crate::symmetric::{as_block, BlockCipher, Error};
use zeroize::ZeroizeOnDrop;

/// 64-bit halves in the longest key schedule (15 round keys).
const MAX_HALVES: usize = 30;

/// An AES cipher with an expanded key, using the Zkn instructions.
///
/// Supports 128, 192 and 256 bit keys. Key expansion happens once in
/// [`Aes::try_new`]; the key is wiped on drop.
#[derive(Clone, ZeroizeOnDrop)]
pub struct Aes {
    /// Round keys as (low, high) 64-bit halves.
    enc: [u64; MAX_HALVES],
    /// Inverse-cipher round keys: reversed, inner ones through
    /// InvMixColumns.
    dec: [u64; MAX_HALVES],
    #[zeroize(skip)]
    size: KeySize,
}

impl fmt::Debug for Aes {
    /// Deliberately omits the key material.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Aes")
            .field("rounds", &self.rounds())
            .finish()
    }
}

impl Aes {
    /// Expands `key`, which must be 16, 24 or 32 bytes long.
    ///
    /// Returns [`Error::NotSupported`] if the instructions cannot be
    /// confirmed available.
    pub fn try_new(key: &[u8]) -> Result<Self, Error> {
        if !has_zkn() {
            return Err(Error::NotSupported);
        }
        // SAFETY: the instructions were just confirmed present.
        unsafe { Self::new_unchecked(key) }
    }

    /// Expands `key` without checking for the instructions.
    ///
    /// # Safety
    /// The caller must have confirmed that Zkne and Zknd are
    /// available.
    pub(crate) unsafe fn new_unchecked(key: &[u8]) -> Result<Self, Error> {
        let size = KeySize::for_key(key)?;
        let rounds = size.rounds();

        let mut enc = [0u64; MAX_HALVES];
        match size {
            KeySize::Aes128 => expand128(key.as_ptr(), enc.as_mut_ptr()),
            KeySize::Aes192 => expand192(key.as_ptr(), enc.as_mut_ptr()),
            KeySize::Aes256 => expand256(key.as_ptr(), enc.as_mut_ptr()),
        }

        let mut dec = [0u64; MAX_HALVES];
        dec[0] = enc[2 * rounds];
        dec[1] = enc[2 * rounds + 1];
        for r in 1..rounds {
            let src = 2 * (rounds - r);
            dec[2 * r] = inv_mix_columns(enc[src]);
            dec[2 * r + 1] = inv_mix_columns(enc[src + 1]);
        }
        dec[2 * rounds] = enc[0];
        dec[2 * rounds + 1] = enc[1];

        Ok(Aes { enc, dec, size })
    }

    /// Number of rounds: 10, 12 or 14 depending on key size.
    pub fn rounds(&self) -> usize {
        self.size.rounds()
    }

    /// Encrypts one block in place.
    #[inline]
    pub fn encrypt_block(&self, block: &mut [u8; BLOCK_SIZE]) {
        // SAFETY: the struct only exists if try_new confirmed support.
        unsafe {
            encrypt(self.enc.as_ptr(), self.rounds(), block.as_mut_ptr(), 1)
        }
    }

    /// Decrypts one block in place.
    #[inline]
    pub fn decrypt_block(&self, block: &mut [u8; BLOCK_SIZE]) {
        // SAFETY: the struct only exists if try_new confirmed support.
        unsafe {
            decrypt(self.dec.as_ptr(), self.rounds(), block.as_mut_ptr(), 1)
        }
    }

    /// Encrypts every block of `data` in place, independently (ECB).
    ///
    /// `data.len()` must be a multiple of 16; nothing is changed
    /// otherwise.
    pub fn encrypt_blocks(&self, data: &mut [u8]) -> Result<(), Error> {
        if !data.len().is_multiple_of(BLOCK_SIZE) {
            return Err(Error::NotBlockAligned(data.len()));
        }
        let blocks = data.len() / BLOCK_SIZE;
        if blocks > 0 {
            // SAFETY: the struct only exists if try_new confirmed
            // support; the length is a whole number of blocks.
            unsafe {
                encrypt(
                    self.enc.as_ptr(),
                    self.rounds(),
                    data.as_mut_ptr(),
                    blocks,
                )
            }
        }
        Ok(())
    }

    /// Decrypts every block of `data` in place, independently (ECB).
    ///
    /// `data.len()` must be a multiple of 16; nothing is changed
    /// otherwise.
    pub fn decrypt_blocks(&self, data: &mut [u8]) -> Result<(), Error> {
        if !data.len().is_multiple_of(BLOCK_SIZE) {
            return Err(Error::NotBlockAligned(data.len()));
        }
        let blocks = data.len() / BLOCK_SIZE;
        if blocks > 0 {
            // SAFETY: as in encrypt_blocks.
            unsafe {
                decrypt(
                    self.dec.as_ptr(),
                    self.rounds(),
                    data.as_mut_ptr(),
                    blocks,
                )
            }
        }
        Ok(())
    }
}

impl BlockCipher for Aes {
    const BLOCK_SIZE: usize = BLOCK_SIZE;

    fn try_new(key: &[u8]) -> Result<Self, Error> {
        Aes::try_new(key)
    }

    fn encrypt_block(&self, block: &mut [u8]) -> Result<(), Error> {
        Aes::encrypt_block(self, as_block(block)?);
        Ok(())
    }

    fn decrypt_block(&self, block: &mut [u8]) -> Result<(), Error> {
        Aes::decrypt_block(self, as_block(block)?);
        Ok(())
    }

    fn encrypt_blocks(&self, data: &mut [u8]) -> Result<(), Error> {
        Aes::encrypt_blocks(self, data)
    }

    fn decrypt_blocks(&self, data: &mut [u8]) -> Result<(), Error> {
        Aes::decrypt_blocks(self, data)
    }
}

// The key schedules use the dedicated instructions: `aes64ks1i`
// does SubWord, RotWord and the round constant on the high word of
// its input (round number 0xA means SubWord only, for the AES-256
// middle step), and `aes64ks2` xors the running words in. Each step
// stores the next 16, 24 or 32 bytes of schedule; the buffer is 240
// bytes, so the few bytes past the last round key written by the
// uniform AES-192 steps are harmless. The `.option arch` directives
// only tell the assembler the instructions are allowed.

/// AES-128 key schedule: ten steps of one round key.
///
/// # Safety
/// Requires Zkne; `key` must point at the key bytes and `out` at
/// 240 writable bytes.
unsafe fn expand128(key: *const u8, out: *mut u64) {
    core::arch::asm!(
        ".option push",
        ".option arch, +zkne",
        "ld      {t0}, 0({key})",
        "ld      {t1}, 8({key})",
        "sd      {t0}, 0({out})",
        "sd      {t1}, 8({out})",
        "aes64ks1i {t2}, {t1}, 0",
        "aes64ks2 {t0}, {t2}, {t0}",
        "aes64ks2 {t1}, {t0}, {t1}",
        "sd      {t0}, 16({out})",
        "sd      {t1}, 24({out})",
        "aes64ks1i {t2}, {t1}, 1",
        "aes64ks2 {t0}, {t2}, {t0}",
        "aes64ks2 {t1}, {t0}, {t1}",
        "sd      {t0}, 32({out})",
        "sd      {t1}, 40({out})",
        "aes64ks1i {t2}, {t1}, 2",
        "aes64ks2 {t0}, {t2}, {t0}",
        "aes64ks2 {t1}, {t0}, {t1}",
        "sd      {t0}, 48({out})",
        "sd      {t1}, 56({out})",
        "aes64ks1i {t2}, {t1}, 3",
        "aes64ks2 {t0}, {t2}, {t0}",
        "aes64ks2 {t1}, {t0}, {t1}",
        "sd      {t0}, 64({out})",
        "sd      {t1}, 72({out})",
        "aes64ks1i {t2}, {t1}, 4",
        "aes64ks2 {t0}, {t2}, {t0}",
        "aes64ks2 {t1}, {t0}, {t1}",
        "sd      {t0}, 80({out})",
        "sd      {t1}, 88({out})",
        "aes64ks1i {t2}, {t1}, 5",
        "aes64ks2 {t0}, {t2}, {t0}",
        "aes64ks2 {t1}, {t0}, {t1}",
        "sd      {t0}, 96({out})",
        "sd      {t1}, 104({out})",
        "aes64ks1i {t2}, {t1}, 6",
        "aes64ks2 {t0}, {t2}, {t0}",
        "aes64ks2 {t1}, {t0}, {t1}",
        "sd      {t0}, 112({out})",
        "sd      {t1}, 120({out})",
        "aes64ks1i {t2}, {t1}, 7",
        "aes64ks2 {t0}, {t2}, {t0}",
        "aes64ks2 {t1}, {t0}, {t1}",
        "sd      {t0}, 128({out})",
        "sd      {t1}, 136({out})",
        "aes64ks1i {t2}, {t1}, 8",
        "aes64ks2 {t0}, {t2}, {t0}",
        "aes64ks2 {t1}, {t0}, {t1}",
        "sd      {t0}, 144({out})",
        "sd      {t1}, 152({out})",
        "aes64ks1i {t2}, {t1}, 9",
        "aes64ks2 {t0}, {t2}, {t0}",
        "aes64ks2 {t1}, {t0}, {t1}",
        "sd      {t0}, 160({out})",
        "sd      {t1}, 168({out})",
        ".option pop",
        key = in(reg) key,
        out = in(reg) out,
        t0 = out(reg) _,
        t1 = out(reg) _,
        t2 = out(reg) _,
        options(nostack),
    );
}

/// AES-192 key schedule: eight steps of one and a half round keys.
///
/// # Safety
/// Requires Zkne; `key` must point at the key bytes and `out` at
/// 240 writable bytes.
unsafe fn expand192(key: *const u8, out: *mut u64) {
    core::arch::asm!(
        ".option push",
        ".option arch, +zkne",
        "ld      {t0}, 0({key})",
        "ld      {t1}, 8({key})",
        "ld      {t2}, 16({key})",
        "sd      {t0}, 0({out})",
        "sd      {t1}, 8({out})",
        "sd      {t2}, 16({out})",
        "aes64ks1i {t3}, {t2}, 0",
        "aes64ks2 {t0}, {t3}, {t0}",
        "aes64ks2 {t1}, {t0}, {t1}",
        "aes64ks2 {t2}, {t1}, {t2}",
        "sd      {t0}, 24({out})",
        "sd      {t1}, 32({out})",
        "sd      {t2}, 40({out})",
        "aes64ks1i {t3}, {t2}, 1",
        "aes64ks2 {t0}, {t3}, {t0}",
        "aes64ks2 {t1}, {t0}, {t1}",
        "aes64ks2 {t2}, {t1}, {t2}",
        "sd      {t0}, 48({out})",
        "sd      {t1}, 56({out})",
        "sd      {t2}, 64({out})",
        "aes64ks1i {t3}, {t2}, 2",
        "aes64ks2 {t0}, {t3}, {t0}",
        "aes64ks2 {t1}, {t0}, {t1}",
        "aes64ks2 {t2}, {t1}, {t2}",
        "sd      {t0}, 72({out})",
        "sd      {t1}, 80({out})",
        "sd      {t2}, 88({out})",
        "aes64ks1i {t3}, {t2}, 3",
        "aes64ks2 {t0}, {t3}, {t0}",
        "aes64ks2 {t1}, {t0}, {t1}",
        "aes64ks2 {t2}, {t1}, {t2}",
        "sd      {t0}, 96({out})",
        "sd      {t1}, 104({out})",
        "sd      {t2}, 112({out})",
        "aes64ks1i {t3}, {t2}, 4",
        "aes64ks2 {t0}, {t3}, {t0}",
        "aes64ks2 {t1}, {t0}, {t1}",
        "aes64ks2 {t2}, {t1}, {t2}",
        "sd      {t0}, 120({out})",
        "sd      {t1}, 128({out})",
        "sd      {t2}, 136({out})",
        "aes64ks1i {t3}, {t2}, 5",
        "aes64ks2 {t0}, {t3}, {t0}",
        "aes64ks2 {t1}, {t0}, {t1}",
        "aes64ks2 {t2}, {t1}, {t2}",
        "sd      {t0}, 144({out})",
        "sd      {t1}, 152({out})",
        "sd      {t2}, 160({out})",
        "aes64ks1i {t3}, {t2}, 6",
        "aes64ks2 {t0}, {t3}, {t0}",
        "aes64ks2 {t1}, {t0}, {t1}",
        "aes64ks2 {t2}, {t1}, {t2}",
        "sd      {t0}, 168({out})",
        "sd      {t1}, 176({out})",
        "sd      {t2}, 184({out})",
        "aes64ks1i {t3}, {t2}, 7",
        "aes64ks2 {t0}, {t3}, {t0}",
        "aes64ks2 {t1}, {t0}, {t1}",
        "sd      {t0}, 192({out})",
        "sd      {t1}, 200({out})",
        ".option pop",
        key = in(reg) key,
        out = in(reg) out,
        t0 = out(reg) _,
        t1 = out(reg) _,
        t2 = out(reg) _,
        t3 = out(reg) _,
        options(nostack),
    );
}

/// AES-256 key schedule: seven steps of two round keys.
///
/// # Safety
/// Requires Zkne; `key` must point at the key bytes and `out` at
/// 240 writable bytes.
unsafe fn expand256(key: *const u8, out: *mut u64) {
    core::arch::asm!(
        ".option push",
        ".option arch, +zkne",
        "ld      {t0}, 0({key})",
        "ld      {t1}, 8({key})",
        "ld      {t2}, 16({key})",
        "ld      {t3}, 24({key})",
        "sd      {t0}, 0({out})",
        "sd      {t1}, 8({out})",
        "sd      {t2}, 16({out})",
        "sd      {t3}, 24({out})",
        "aes64ks1i {t4}, {t3}, 0",
        "aes64ks2 {t0}, {t4}, {t0}",
        "aes64ks2 {t1}, {t0}, {t1}",
        "sd      {t0}, 32({out})",
        "sd      {t1}, 40({out})",
        "aes64ks1i {t4}, {t1}, 0xA",
        "aes64ks2 {t2}, {t4}, {t2}",
        "aes64ks2 {t3}, {t2}, {t3}",
        "sd      {t2}, 48({out})",
        "sd      {t3}, 56({out})",
        "aes64ks1i {t4}, {t3}, 1",
        "aes64ks2 {t0}, {t4}, {t0}",
        "aes64ks2 {t1}, {t0}, {t1}",
        "sd      {t0}, 64({out})",
        "sd      {t1}, 72({out})",
        "aes64ks1i {t4}, {t1}, 0xA",
        "aes64ks2 {t2}, {t4}, {t2}",
        "aes64ks2 {t3}, {t2}, {t3}",
        "sd      {t2}, 80({out})",
        "sd      {t3}, 88({out})",
        "aes64ks1i {t4}, {t3}, 2",
        "aes64ks2 {t0}, {t4}, {t0}",
        "aes64ks2 {t1}, {t0}, {t1}",
        "sd      {t0}, 96({out})",
        "sd      {t1}, 104({out})",
        "aes64ks1i {t4}, {t1}, 0xA",
        "aes64ks2 {t2}, {t4}, {t2}",
        "aes64ks2 {t3}, {t2}, {t3}",
        "sd      {t2}, 112({out})",
        "sd      {t3}, 120({out})",
        "aes64ks1i {t4}, {t3}, 3",
        "aes64ks2 {t0}, {t4}, {t0}",
        "aes64ks2 {t1}, {t0}, {t1}",
        "sd      {t0}, 128({out})",
        "sd      {t1}, 136({out})",
        "aes64ks1i {t4}, {t1}, 0xA",
        "aes64ks2 {t2}, {t4}, {t2}",
        "aes64ks2 {t3}, {t2}, {t3}",
        "sd      {t2}, 144({out})",
        "sd      {t3}, 152({out})",
        "aes64ks1i {t4}, {t3}, 4",
        "aes64ks2 {t0}, {t4}, {t0}",
        "aes64ks2 {t1}, {t0}, {t1}",
        "sd      {t0}, 160({out})",
        "sd      {t1}, 168({out})",
        "aes64ks1i {t4}, {t1}, 0xA",
        "aes64ks2 {t2}, {t4}, {t2}",
        "aes64ks2 {t3}, {t2}, {t3}",
        "sd      {t2}, 176({out})",
        "sd      {t3}, 184({out})",
        "aes64ks1i {t4}, {t3}, 5",
        "aes64ks2 {t0}, {t4}, {t0}",
        "aes64ks2 {t1}, {t0}, {t1}",
        "sd      {t0}, 192({out})",
        "sd      {t1}, 200({out})",
        "aes64ks1i {t4}, {t1}, 0xA",
        "aes64ks2 {t2}, {t4}, {t2}",
        "aes64ks2 {t3}, {t2}, {t3}",
        "sd      {t2}, 208({out})",
        "sd      {t3}, 216({out})",
        "aes64ks1i {t4}, {t3}, 6",
        "aes64ks2 {t0}, {t4}, {t0}",
        "aes64ks2 {t1}, {t0}, {t1}",
        "sd      {t0}, 224({out})",
        "sd      {t1}, 232({out})",
        ".option pop",
        key = in(reg) key,
        out = in(reg) out,
        t0 = out(reg) _,
        t1 = out(reg) _,
        t2 = out(reg) _,
        t3 = out(reg) _,
        t4 = out(reg) _,
        options(nostack),
    );
}

/// InvMixColumns on the two columns in one 64-bit half of a round
/// key, for the equivalent inverse cipher.
///
/// # Safety
/// Requires Zknd.
unsafe fn inv_mix_columns(half: u64) -> u64 {
    let out: u64;
    core::arch::asm!(
        ".option push",
        ".option arch, +zknd",
        "aes64im {out}, {half}",
        ".option pop",
        half = in(reg) half,
        out = lateout(reg) out,
        options(pure, nomem, nostack, preserves_flags),
    );
    out
}

// The block loops below are hand-written so the instruction order can
// be tuned. One block per iteration: its halves live
// in a register pair, the middle rounds loop over the key pointer so
// one body serves all key sizes. `aes64esm t, lo, hi` makes the new
// low half, `aes64esm hi, hi, lo` the new high half in place, then
// the key halves are xored in.

/// Encrypts `blocks` blocks at `data` with `rounds` rounds.
///
/// # Safety
/// Requires Zkne; `rk` must point at `rounds + 1` round keys
/// (two halves each), `data` at `blocks * 16` writable bytes, and
/// `blocks >= 1`.
unsafe fn encrypt(rk: *const u64, rounds: usize, data: *mut u8, blocks: usize) {
    core::arch::asm!(
        ".option push",
        ".option arch, +zkne",
        "3:",
        "ld      {l}, 0({data})",
        "ld      {h}, 8({data})",
        "ld      {kl}, 0({rk})",
        "ld      {kh}, 8({rk})",
        "xor     {l}, {l}, {kl}",
        "xor     {h}, {h}, {kh}",
        "addi    {k}, {rk}, 16",
        "mv      {n}, {nr}",
        "2:",
        "ld      {kl}, 0({k})",
        "ld      {kh}, 8({k})",
        "aes64esm {t}, {l}, {h}",
        "aes64esm {h}, {h}, {l}",
        "xor     {l}, {t}, {kl}",
        "xor     {h}, {h}, {kh}",
        "addi    {k}, {k}, 16",
        "addi    {n}, {n}, -1",
        "bnez    {n}, 2b",
        "ld      {kl}, 0({k})",
        "ld      {kh}, 8({k})",
        "aes64es {t}, {l}, {h}",
        "aes64es {h}, {h}, {l}",
        "xor     {l}, {t}, {kl}",
        "xor     {h}, {h}, {kh}",
        "sd      {l}, 0({data})",
        "sd      {h}, 8({data})",
        "addi    {data}, {data}, 16",
        "addi    {blocks}, {blocks}, -1",
        "bnez    {blocks}, 3b",
        ".option pop",
        rk = in(reg) rk,
        nr = in(reg) rounds - 1,
        data = inout(reg) data => _,
        blocks = inout(reg) blocks => _,
        k = out(reg) _,
        n = out(reg) _,
        kl = out(reg) _,
        kh = out(reg) _,
        l = out(reg) _,
        h = out(reg) _,
        t = out(reg) _,
        options(nostack),
    );
}

/// Decrypts `blocks` blocks at `data` with `rounds` rounds, using the
/// inverse-cipher round keys.
///
/// # Safety
/// Requires Zknd; `rk` must point at `rounds + 1` round keys
/// (two halves each), `data` at `blocks * 16` writable bytes, and
/// `blocks >= 1`.
unsafe fn decrypt(rk: *const u64, rounds: usize, data: *mut u8, blocks: usize) {
    core::arch::asm!(
        ".option push",
        ".option arch, +zknd",
        "3:",
        "ld      {l}, 0({data})",
        "ld      {h}, 8({data})",
        "ld      {kl}, 0({rk})",
        "ld      {kh}, 8({rk})",
        "xor     {l}, {l}, {kl}",
        "xor     {h}, {h}, {kh}",
        "addi    {k}, {rk}, 16",
        "mv      {n}, {nr}",
        "2:",
        "ld      {kl}, 0({k})",
        "ld      {kh}, 8({k})",
        "aes64dsm {t}, {l}, {h}",
        "aes64dsm {h}, {h}, {l}",
        "xor     {l}, {t}, {kl}",
        "xor     {h}, {h}, {kh}",
        "addi    {k}, {k}, 16",
        "addi    {n}, {n}, -1",
        "bnez    {n}, 2b",
        "ld      {kl}, 0({k})",
        "ld      {kh}, 8({k})",
        "aes64ds {t}, {l}, {h}",
        "aes64ds {h}, {h}, {l}",
        "xor     {l}, {t}, {kl}",
        "xor     {h}, {h}, {kh}",
        "sd      {l}, 0({data})",
        "sd      {h}, 8({data})",
        "addi    {data}, {data}, 16",
        "addi    {blocks}, {blocks}, -1",
        "bnez    {blocks}, 3b",
        ".option pop",
        rk = in(reg) rk,
        nr = in(reg) rounds - 1,
        data = inout(reg) data => _,
        blocks = inout(reg) blocks => _,
        k = out(reg) _,
        n = out(reg) _,
        kl = out(reg) _,
        kh = out(reg) _,
        l = out(reg) _,
        h = out(reg) _,
        t = out(reg) _,
        options(nostack),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::symmetric::aes::portable;

    /// Returns the cipher, or `None` (skipping the test) without
    /// Zkn.
    fn aes(key: &[u8]) -> Option<Aes> {
        match Aes::try_new(key) {
            Ok(a) => Some(a),
            Err(Error::NotSupported) => None,
            Err(e) => panic!("{e}"),
        }
    }

    fn unhex(s: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, pair) in s.as_bytes().chunks_exact(2).enumerate() {
            let hex = core::str::from_utf8(pair).unwrap();
            out[i] = u8::from_str_radix(hex, 16).unwrap();
        }
        out
    }

    fn check(key: &str, plain: &str, cipher: &str) {
        let key = &unhex(key)[..key.len() / 2];
        let plain: [u8; 16] = unhex(plain)[..16].try_into().unwrap();
        let cipher: [u8; 16] = unhex(cipher)[..16].try_into().unwrap();
        let Some(aes) = aes(key) else { return };

        let mut block = plain;
        aes.encrypt_block(&mut block);
        assert_eq!(block, cipher, "encrypt");
        aes.decrypt_block(&mut block);
        assert_eq!(block, plain, "decrypt");
    }

    // FIPS 197 Appendix C.
    #[test]
    fn fips197_aes128() {
        check(
            "000102030405060708090a0b0c0d0e0f",
            "00112233445566778899aabbccddeeff",
            "69c4e0d86a7b0430d8cdb78070b4c55a",
        );
    }

    #[test]
    fn fips197_aes192() {
        check(
            "000102030405060708090a0b0c0d0e0f1011121314151617",
            "00112233445566778899aabbccddeeff",
            "dda97ca4864cdfe06eaf70a0ec0d7191",
        );
    }

    #[test]
    fn fips197_aes256() {
        check(
            "000102030405060708090a0b0c0d0e0f\
             101112131415161718191a1b1c1d1e1f",
            "00112233445566778899aabbccddeeff",
            "8ea2b7ca516745bfeafc49904b496089",
        );
    }

    #[test]
    fn matches_portable() {
        const MAX: usize = 9;
        for klen in [16, 24, 32] {
            let mut key = [0u8; 32];
            for (i, k) in key.iter_mut().enumerate() {
                *k = (i * 37 + klen) as u8;
            }
            let Some(hw) = aes(&key[..klen]) else { return };
            let sw = portable::Aes::try_new(&key[..klen]).unwrap();
            for nblocks in [0, 1, 3, 4, 5, 8, 9] {
                let mut data = [0u8; MAX * BLOCK_SIZE];
                for (i, b) in data.iter_mut().enumerate() {
                    *b = (i * 13 + klen) as u8;
                }
                let data = &mut data[..nblocks * BLOCK_SIZE];
                let mut expected = [0u8; MAX * BLOCK_SIZE];
                let expected = &mut expected[..data.len()];
                expected.copy_from_slice(data);
                let mut orig = [0u8; MAX * BLOCK_SIZE];
                orig[..data.len()].copy_from_slice(data);

                sw.encrypt_blocks(expected).unwrap();
                hw.encrypt_blocks(data).unwrap();
                assert_eq!(data, expected, "encrypt {klen} {nblocks}");
                hw.decrypt_blocks(data).unwrap();
                assert_eq!(data, &orig[..data.len()], "decrypt {klen}");
            }
        }
    }

    #[test]
    fn rejects_bad_key_lengths() {
        if aes(&[0; 16]).is_none() {
            return;
        }
        for n in [0, 1, 15, 17, 23, 25, 31, 33, 64] {
            assert_eq!(
                Aes::try_new(&[0; 64][..n]).unwrap_err(),
                Error::InvalidKeyLength(n)
            );
        }
    }

    #[test]
    fn blocks_reject_partial_block() {
        let Some(aes) = aes(&[0; 16]) else { return };
        for n in [1, 15, 17, 31, 33] {
            let mut data = [0x33u8; 33];
            let data = &mut data[..n];
            assert_eq!(
                aes.encrypt_blocks(data).unwrap_err(),
                Error::NotBlockAligned(n)
            );
            assert_eq!(
                aes.decrypt_blocks(data).unwrap_err(),
                Error::NotBlockAligned(n)
            );
            assert!(data.iter().all(|&b| b == 0x33), "data untouched");
        }
    }

    #[test]
    fn round_counts() {
        let Some(a) = aes(&[0; 16]) else { return };
        assert_eq!(a.rounds(), 10);
        assert_eq!(aes(&[0; 24]).unwrap().rounds(), 12);
        assert_eq!(aes(&[0; 32]).unwrap().rounds(), 14);
    }
}
