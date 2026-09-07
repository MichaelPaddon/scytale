//! AES using the RISC-V vector cryptography extension (Zvkned), with
//! the key schedule and round loops in hand-written assembly.
//!
//! Each 128-bit element group of a vector register holds one block,
//! and one `vaesem.vs` instruction runs a round on every group in a
//! register group. With `LMUL=8` that is eight blocks per instruction
//! on a 128-bit machine and proportionally more on wider ones, so the
//! loop processes whatever the hardware fits in one register group
//! per iteration; the 15 round keys sit in `v16..v30`.
//!
//! The S-box lives in hardware, so this implementation does not leak
//! key material through cache timing.
//!
//! # Availability
//!
//! [`Aes::try_new`] accepts when the crate was compiled with the `v`
//! and `zvkned` target features, or, on Linux, when `riscv_hwprobe`
//! reports them; vector registers must be at least 128 bits wide.
//! Otherwise it returns [`Error::NotSupported`].
//!
//! # Example
//!
//! ```
//! use scytale::cipher::aes::riscv64::zvkned::Aes;
//! use scytale::Error;
//!
//! # fn main() -> Result<(), Error> {
//! match Aes::try_new(&[0u8; 16]) {
//!     Ok(aes) => {
//!         let mut data = [[0u8; 16]; 3];
//!         aes.encrypt_blocks(&mut data);
//!         aes.decrypt_blocks(&mut data);
//!         assert_eq!(data, [[0u8; 16]; 3]);
//!     }
//!     Err(Error::NotSupported) => {} // no Zvkned on this machine
//!     Err(e) => return Err(e),
//! }
//! # Ok(())
//! # }
//! ```

use core::fmt;

use super::{has_zvbb, has_zvkned};
use crate::cipher::aes::{BLOCK_SIZE, KeySize, MAX_WORDS, expand_words};
use crate::cipher::{BlockCipher, add_low32, counter_blocks_via_ecb};
use crate::{BlockType, Error, KeyType};
use zeroize::ZeroizeOnDrop;

/// An AES cipher with an expanded key, using the Zvkned instructions.
///
/// Supports 128, 192 and 256 bit keys. Key expansion happens once in
/// [`Aes::try_new`]; the key is wiped on drop. The vector inverse
/// cipher takes the round keys as they are, so one schedule serves
/// both directions.
#[derive(Clone, ZeroizeOnDrop)]
pub struct Aes<const K: usize> {
    keys: [u32; MAX_WORDS],
    #[zeroize(skip)]
    size: KeySize,
    /// Whether `vrev8.v` is here, asked once at key expansion so that
    /// the counter loop costs nothing to choose.
    #[zeroize(skip)]
    zvbb: bool,
}

impl<const K: usize> fmt::Debug for Aes<K> {
    /// Deliberately omits the key material.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Aes")
            .field("rounds", &self.rounds())
            .finish()
    }
}

impl<const K: usize> Aes<K> {
    /// Expands `key`, which must be 16, 24 or 32 bytes long.
    ///
    /// Returns [`Error::NotSupported`] if the instructions cannot be
    /// confirmed available.
    pub fn try_new(key: &[u8; K]) -> Result<Self, Error> {
        const {
            assert!(
                K == 16 || K == 24 || K == 32,
                "AES keys are 16, 24 or 32 bytes"
            )
        };
        if !has_zvkned() {
            return Err(Error::NotSupported);
        }
        // SAFETY: the instructions were just confirmed present.
        unsafe { Self::new_unchecked(key) }
    }

    /// Expands `key` without checking for the instructions.
    ///
    /// # Safety
    /// The caller must have confirmed that the vector extension and
    /// Zvkned are available with `VLEN >= 128`.
    pub(crate) unsafe fn new_unchecked(key: &[u8; K]) -> Result<Self, Error> {
        unsafe {
            let size = KeySize::for_key(key)?;
            let mut keys = [0u32; MAX_WORDS];
            match size {
                KeySize::Aes128 => expand128(key.as_ptr(), keys.as_mut_ptr()),
                KeySize::Aes256 => expand256(key.as_ptr(), keys.as_mut_ptr()),
                // No vector instruction covers AES-192; use the shared
                // schedule with a vector SubWord.
                KeySize::Aes192 => {
                    keys = expand_words(key, size, |w| sub_word(w))
                }
            }
            Ok(Aes {
                keys,
                size,
                zvbb: has_zvbb(),
            })
        }
    }

    /// Number of rounds: 10, 12 or 14 depending on key size.
    pub fn rounds(&self) -> usize {
        self.size.rounds()
    }

    /// Encrypts one block in place.
    #[inline]
    pub fn encrypt_block(&self, block: &mut [u8; BLOCK_SIZE]) {
        // SAFETY: the struct only exists if try_new confirmed support.
        unsafe { self.encrypt(block.as_mut_ptr(), 1) }
    }

    /// Decrypts one block in place.
    #[inline]
    pub fn decrypt_block(&self, block: &mut [u8; BLOCK_SIZE]) {
        // SAFETY: the struct only exists if try_new confirmed support.
        unsafe { self.decrypt(block.as_mut_ptr(), 1) }
    }

    /// Encrypts every block in place, independently (ECB).
    pub fn encrypt_blocks(&self, blocks: &mut [[u8; BLOCK_SIZE]]) {
        let data = blocks.as_flattened_mut();
        if !data.is_empty() {
            // SAFETY: the struct only exists if try_new confirmed
            // support; the length is a whole number of blocks.
            unsafe { self.encrypt(data.as_mut_ptr(), data.len() / BLOCK_SIZE) }
        }
    }

    /// Decrypts every block in place, independently (ECB).
    pub fn decrypt_blocks(&self, blocks: &mut [[u8; BLOCK_SIZE]]) {
        let data = blocks.as_flattened_mut();
        if !data.is_empty() {
            // SAFETY: as in encrypt_blocks.
            unsafe { self.decrypt(data.as_mut_ptr(), data.len() / BLOCK_SIZE) }
        }
    }

    /// Counter mode's inner loop; see
    /// [`BlockCipher::xor_counter_blocks`].
    ///
    /// The counters are made in registers and encrypted where they
    /// lie, then XORed over the data on the way to a single store, so
    /// a block is read once and written once, which is what plain ECB
    /// costs. Without Zvbb there is no vector byte reverse to put the
    /// counter field the right way round, and the shared loop runs
    /// instead.
    pub fn xor_counter_blocks(
        &self,
        counter: &mut [u8; BLOCK_SIZE],
        data: &mut [u8],
    ) {
        debug_assert_eq!(data.len() % BLOCK_SIZE, 0);
        if data.is_empty() {
            return;
        }
        if !self.zvbb {
            return counter_blocks_via_ecb(self, counter, data);
        }
        // The block as four big-endian words: the first three are
        // fixed, the last is the counter. Read this way they need no
        // reversing on the way in, only on the way out.
        let word = |i: usize| {
            u32::from_be_bytes([
                counter[i],
                counter[i + 1],
                counter[i + 2],
                counter[i + 3],
            ])
        };
        let blocks = data.len() / BLOCK_SIZE;
        let rk = self.keys.as_ptr();
        // SAFETY: the struct only exists if try_new confirmed the
        // vector AES instructions, and `zvbb` says `vrev8.v` is here;
        // `data` holds `blocks` whole blocks and `blocks >= 1`.
        unsafe {
            let run = match self.size {
                KeySize::Aes128 => counter10,
                KeySize::Aes192 => counter12,
                KeySize::Aes256 => counter14,
            };
            run(
                rk,
                word(0),
                word(4),
                word(8),
                word(12),
                data.as_mut_ptr(),
                blocks,
            );
        }
        add_low32(counter, blocks as u32);
    }

    /// # Safety
    /// Requires Zvkned; `data` must hold `blocks` writable blocks,
    /// `blocks >= 1`.
    #[inline]
    unsafe fn encrypt(&self, data: *mut u8, blocks: usize) {
        unsafe {
            let rk = self.keys.as_ptr();
            match self.size {
                KeySize::Aes128 => encrypt10(rk, data, blocks),
                KeySize::Aes192 => encrypt12(rk, data, blocks),
                KeySize::Aes256 => encrypt14(rk, data, blocks),
            }
        }
    }

    /// # Safety
    /// As [`Aes::encrypt`].
    #[inline]
    unsafe fn decrypt(&self, data: *mut u8, blocks: usize) {
        unsafe {
            let rk = self.keys.as_ptr();
            match self.size {
                KeySize::Aes128 => decrypt10(rk, data, blocks),
                KeySize::Aes192 => decrypt12(rk, data, blocks),
                KeySize::Aes256 => decrypt14(rk, data, blocks),
            }
        }
    }
}

impl<const K: usize> BlockType for Aes<K> {
    type Block = [u8; BLOCK_SIZE];

    fn zero_block() -> Self::Block {
        [0; BLOCK_SIZE]
    }
}

impl<const K: usize> KeyType for Aes<K> {
    type Key = [u8; K];

    fn zero_key() -> Self::Key {
        [0; K]
    }
}

impl<const K: usize> BlockCipher for Aes<K> {
    fn try_new(key: &Self::Key) -> Result<Self, Error> {
        Aes::try_new(key)
    }

    fn encrypt_block(&self, block: &mut Self::Block) {
        Aes::encrypt_block(self, block)
    }

    fn decrypt_block(&self, block: &mut Self::Block) {
        Aes::decrypt_block(self, block)
    }

    fn encrypt_blocks(&self, blocks: &mut [Self::Block]) {
        Aes::encrypt_blocks(self, blocks)
    }

    fn decrypt_blocks(&self, blocks: &mut [Self::Block]) {
        Aes::decrypt_blocks(self, blocks)
    }

    fn xor_counter_blocks(&self, counter: &mut Self::Block, data: &mut [u8]) {
        Aes::xor_counter_blocks(self, counter, data)
    }
}

// The key schedules use the dedicated instructions:
// `vaeskf1.vi` derives each AES-128 round key from the previous one,
// and `vaeskf2.vi` each AES-256 round key from the previous two.
// Round keys are written straight into the word array.

/// AES-128 key schedule.
///
/// # Safety
/// Requires the vector extension and Zvkned; `key` must point at 16
/// key bytes and `out` at 44 writable words.
unsafe fn expand128(key: *const u8, out: *mut u32) {
    unsafe {
        core::arch::asm!(
            ".option push",
            ".option arch, +v, +zvkned",
            "vsetivli zero, 4, e32, m1, tu, mu",
            "vle32.v v10, ({key})",
            "vaeskf1.vi v11, v10, 1",
            "vaeskf1.vi v12, v11, 2",
            "vaeskf1.vi v13, v12, 3",
            "vaeskf1.vi v14, v13, 4",
            "vaeskf1.vi v15, v14, 5",
            "vaeskf1.vi v16, v15, 6",
            "vaeskf1.vi v17, v16, 7",
            "vaeskf1.vi v18, v17, 8",
            "vaeskf1.vi v19, v18, 9",
            "vaeskf1.vi v20, v19, 10",
            "vse32.v v10, ({out})",
            "addi {out}, {out}, 16",
            "vse32.v v11, ({out})",
            "addi {out}, {out}, 16",
            "vse32.v v12, ({out})",
            "addi {out}, {out}, 16",
            "vse32.v v13, ({out})",
            "addi {out}, {out}, 16",
            "vse32.v v14, ({out})",
            "addi {out}, {out}, 16",
            "vse32.v v15, ({out})",
            "addi {out}, {out}, 16",
            "vse32.v v16, ({out})",
            "addi {out}, {out}, 16",
            "vse32.v v17, ({out})",
            "addi {out}, {out}, 16",
            "vse32.v v18, ({out})",
            "addi {out}, {out}, 16",
            "vse32.v v19, ({out})",
            "addi {out}, {out}, 16",
            "vse32.v v20, ({out})",
            ".option pop",
            key = in(reg) key,
            out = inout(reg) out => _,
            out("v10") _,
            out("v11") _,
            out("v12") _,
            out("v13") _,
            out("v14") _,
            out("v15") _,
            out("v16") _,
            out("v17") _,
            out("v18") _,
            out("v19") _,
            out("v20") _,
            options(nostack),
        );
    }
}

/// AES-256 key schedule.
///
/// # Safety
/// Requires the vector extension and Zvkned; `key` must point at 32
/// key bytes and `out` at 60 writable words.
unsafe fn expand256(key: *const u8, out: *mut u32) {
    unsafe {
        core::arch::asm!(
            ".option push",
            ".option arch, +v, +zvkned",
            "vsetivli zero, 4, e32, m1, tu, mu",
            "vle32.v v10, ({key})",
            "addi {key}, {key}, 16",
            "vle32.v v11, ({key})",
            "vmv.v.v v12, v10",
            "vaeskf2.vi v12, v11, 2",
            "vmv.v.v v13, v11",
            "vaeskf2.vi v13, v12, 3",
            "vmv.v.v v14, v12",
            "vaeskf2.vi v14, v13, 4",
            "vmv.v.v v15, v13",
            "vaeskf2.vi v15, v14, 5",
            "vmv.v.v v16, v14",
            "vaeskf2.vi v16, v15, 6",
            "vmv.v.v v17, v15",
            "vaeskf2.vi v17, v16, 7",
            "vmv.v.v v18, v16",
            "vaeskf2.vi v18, v17, 8",
            "vmv.v.v v19, v17",
            "vaeskf2.vi v19, v18, 9",
            "vmv.v.v v20, v18",
            "vaeskf2.vi v20, v19, 10",
            "vmv.v.v v21, v19",
            "vaeskf2.vi v21, v20, 11",
            "vmv.v.v v22, v20",
            "vaeskf2.vi v22, v21, 12",
            "vmv.v.v v23, v21",
            "vaeskf2.vi v23, v22, 13",
            "vmv.v.v v24, v22",
            "vaeskf2.vi v24, v23, 14",
            "vse32.v v10, ({out})",
            "addi {out}, {out}, 16",
            "vse32.v v11, ({out})",
            "addi {out}, {out}, 16",
            "vse32.v v12, ({out})",
            "addi {out}, {out}, 16",
            "vse32.v v13, ({out})",
            "addi {out}, {out}, 16",
            "vse32.v v14, ({out})",
            "addi {out}, {out}, 16",
            "vse32.v v15, ({out})",
            "addi {out}, {out}, 16",
            "vse32.v v16, ({out})",
            "addi {out}, {out}, 16",
            "vse32.v v17, ({out})",
            "addi {out}, {out}, 16",
            "vse32.v v18, ({out})",
            "addi {out}, {out}, 16",
            "vse32.v v19, ({out})",
            "addi {out}, {out}, 16",
            "vse32.v v20, ({out})",
            "addi {out}, {out}, 16",
            "vse32.v v21, ({out})",
            "addi {out}, {out}, 16",
            "vse32.v v22, ({out})",
            "addi {out}, {out}, 16",
            "vse32.v v23, ({out})",
            "addi {out}, {out}, 16",
            "vse32.v v24, ({out})",
            ".option pop",
            key = inout(reg) key => _,
            out = inout(reg) out => _,
            out("v10") _,
            out("v11") _,
            out("v12") _,
            out("v13") _,
            out("v14") _,
            out("v15") _,
            out("v16") _,
            out("v17") _,
            out("v18") _,
            out("v19") _,
            out("v20") _,
            out("v21") _,
            out("v22") _,
            out("v23") _,
            out("v24") _,
            options(nostack),
        );
    }
}

/// `SubWord` via a final AES round with a zero key on a vector holding
/// the word in every column: ShiftRows then only moves equal bytes
/// around, so every column ends up as `SubWord(w)`.
///
/// # Safety
/// Requires the vector extension and Zvkned.
unsafe fn sub_word(w: u32) -> u32 {
    unsafe {
        let out: u64;
        core::arch::asm!(
            ".option push",
            ".option arch, +v, +zvkned",
            "vsetivli zero, 4, e32, m1, ta, ma",
            "vmv.v.x v8, {w}",
            "vmv.v.i v9, 0",
            "vaesef.vv v8, v9",
            "vmv.x.s {out}, v8",
            ".option pop",
            w = in(reg) w,
            out = lateout(reg) out,
            out("v8") _, out("v9") _,
            options(nomem, nostack),
        );
        out as u32
    }
}

// The round loops below are hand-written so the instruction order can
// be tuned. Vector register names cannot be chosen at run time, so
// there is one body per key size, generated by `vaes_body!`. Each
// loads the round keys into v16.. (one 128-bit group each), then
// loops: set vl for up to a whole LMUL=8 register group of blocks,
// load them into v8..v15, run the rounds with the `.vs` forms (one
// key group applied to every block group), store, advance. `avl` is
// counted in 32-bit elements, four per block, so every `vl` is a
// whole number of blocks. The `.option arch` directive only tells the
// assembler the instructions are allowed.

/// Defines `fn $name(rk, data, blocks)` running the rounds given as
/// (instruction, key register) pairs.
macro_rules! vaes_body {
    ($name:ident, $first:literal, [$($mid:literal),*], $last:literal,
     $midop:literal, $lastop:literal) => {
        /// # Safety
        /// Requires the vector extension and Zvkned with VLEN >= 128;
        /// `rk` must point at 15 round keys and `data` at `blocks`
        /// writable blocks, `blocks >= 1`.
        unsafe fn $name(rk: *const u32, data: *mut u8, blocks: usize) {
            unsafe {
                core::arch::asm!(
                    ".option push",
                    ".option arch, +v, +zvkned",
                    "vsetivli zero, 4, e32, m1, ta, ma",
                    "vle32.v v16, ({rk})",
                    "addi {rk}, {rk}, 16",
                    "vle32.v v17, ({rk})",
                    "addi {rk}, {rk}, 16",
                    "vle32.v v18, ({rk})",
                    "addi {rk}, {rk}, 16",
                    "vle32.v v19, ({rk})",
                    "addi {rk}, {rk}, 16",
                    "vle32.v v20, ({rk})",
                    "addi {rk}, {rk}, 16",
                    "vle32.v v21, ({rk})",
                    "addi {rk}, {rk}, 16",
                    "vle32.v v22, ({rk})",
                    "addi {rk}, {rk}, 16",
                    "vle32.v v23, ({rk})",
                    "addi {rk}, {rk}, 16",
                    "vle32.v v24, ({rk})",
                    "addi {rk}, {rk}, 16",
                    "vle32.v v25, ({rk})",
                    "addi {rk}, {rk}, 16",
                    "vle32.v v26, ({rk})",
                    "addi {rk}, {rk}, 16",
                    "vle32.v v27, ({rk})",
                    "addi {rk}, {rk}, 16",
                    "vle32.v v28, ({rk})",
                    "addi {rk}, {rk}, 16",
                    "vle32.v v29, ({rk})",
                    "addi {rk}, {rk}, 16",
                    "vle32.v v30, ({rk})",
                    "2:",
                    "vsetvli {vl}, {avl}, e32, m8, ta, ma",
                    "vle32.v v8, ({data})",
                    concat!("vaesz.vs v8, ", $first),
                    $(concat!($midop, " v8, ", $mid),)*
                    concat!($lastop, " v8, ", $last),
                    "vse32.v v8, ({data})",
                    "slli {t}, {vl}, 2",
                    "add {data}, {data}, {t}",
                    "sub {avl}, {avl}, {vl}",
                    "bnez {avl}, 2b",
                    ".option pop",
                    rk = inout(reg) rk => _,
                    data = inout(reg) data => _,
                    avl = inout(reg) 4 * blocks => _,
                    vl = out(reg) _,
                    t = out(reg) _,
                    out("v8") _, out("v9") _, out("v10") _, out("v11") _,
                    out("v12") _, out("v13") _, out("v14") _, out("v15") _,
                    out("v16") _, out("v17") _, out("v18") _, out("v19") _,
                    out("v20") _, out("v21") _, out("v22") _, out("v23") _,
                    out("v24") _, out("v25") _, out("v26") _, out("v27") _,
                    out("v28") _, out("v29") _, out("v30") _,
                    options(nostack),
                );
            }
        }
    };
}

/// Defines `fn $name(rk, c0, c1, c2, n, data, blocks)`: counter mode
/// over `blocks` blocks, with the rounds given as key registers.
///
/// The first three words of the block are fixed and the fourth is the
/// counter, all read big-endian, so the vector holds them as plain
/// numbers and one `vrev8.v` puts a whole pass into block order. The
/// counters and the per-pass step are built once; the loop then adds
/// the step to the last word of each block and does nothing else.
///
/// Only that word is added to, so a carry out of it would be lost;
/// the caller splits its run at that boundary.
macro_rules! counter_body {
    ($name:ident, $first:literal, [$($mid:literal),*], $last:literal) => {
        /// # Safety
        /// Requires the vector extension, Zvkned and Zvbb with
        /// VLEN >= 128; `rk` must point at 15 round keys and `data`
        /// at `blocks` writable blocks, `blocks >= 1`.
        #[allow(clippy::too_many_arguments)]
        unsafe fn $name(
            rk: *const u32,
            c0: u32,
            c1: u32,
            c2: u32,
            n: u32,
            data: *mut u8,
            blocks: usize,
        ) {
            unsafe {
                core::arch::asm!(
                    ".option push",
                    ".option arch, +v, +zvkned, +zvbb",
                    "vsetivli zero, 4, e32, m1, ta, ma",
                    "vle32.v v16, ({rk})",
                    "addi {rk}, {rk}, 16",
                    "vle32.v v17, ({rk})",
                    "addi {rk}, {rk}, 16",
                    "vle32.v v18, ({rk})",
                    "addi {rk}, {rk}, 16",
                    "vle32.v v19, ({rk})",
                    "addi {rk}, {rk}, 16",
                    "vle32.v v20, ({rk})",
                    "addi {rk}, {rk}, 16",
                    "vle32.v v21, ({rk})",
                    "addi {rk}, {rk}, 16",
                    "vle32.v v22, ({rk})",
                    "addi {rk}, {rk}, 16",
                    "vle32.v v23, ({rk})",
                    "addi {rk}, {rk}, 16",
                    "vle32.v v24, ({rk})",
                    "addi {rk}, {rk}, 16",
                    "vle32.v v25, ({rk})",
                    "addi {rk}, {rk}, 16",
                    "vle32.v v26, ({rk})",
                    "addi {rk}, {rk}, 16",
                    "vle32.v v27, ({rk})",
                    "addi {rk}, {rk}, 16",
                    "vle32.v v28, ({rk})",
                    "addi {rk}, {rk}, 16",
                    "vle32.v v29, ({rk})",
                    "addi {rk}, {rk}, 16",
                    "vle32.v v30, ({rk})",
                    // The counters, and the step from one pass to the
                    // next, built once. Element `i` is word `i & 3` of
                    // block `i >> 2`.
                    "vsetvli {vl}, {avl}, e32, m4, ta, ma",
                    "vid.v v8",
                    "vand.vi v12, v8, 3",
                    "vsrl.vi v8, v8, 2",
                    "vadd.vx v8, v8, {n}",
                    "vmseq.vi v0, v12, 0",
                    "vmerge.vxm v8, v8, {c0}, v0",
                    "vmseq.vi v0, v12, 1",
                    "vmerge.vxm v8, v8, {c1}, v0",
                    "vmseq.vi v0, v12, 2",
                    "vmerge.vxm v8, v8, {c2}, v0",
                    "srli {t}, {vl}, 2",
                    "vmv.v.i v4, 0",
                    "vmseq.vi v0, v12, 3",
                    "vmerge.vxm v4, v4, {t}, v0",
                    "2:",
                    "vsetvli {vl}, {avl}, e32, m4, ta, ma",
                    "vmv.v.v v12, v8",
                    "vrev8.v v12, v12",
                    concat!("vaesz.vs v12, ", $first),
                    $(concat!("vaesem.vs v12, ", $mid),)*
                    concat!("vaesef.vs v12, ", $last),
                    // The keystream never reaches memory: it is XORed
                    // over the data on the way to the one store.
                    "vle32.v v0, ({data})",
                    "vxor.vv v12, v12, v0",
                    "vse32.v v12, ({data})",
                    "slli {t}, {vl}, 2",
                    "add {data}, {data}, {t}",
                    "vadd.vv v8, v8, v4",
                    "sub {avl}, {avl}, {vl}",
                    "bnez {avl}, 2b",
                    ".option pop",
                    rk = inout(reg) rk => _,
                    c0 = in(reg) c0,
                    c1 = in(reg) c1,
                    c2 = in(reg) c2,
                    n = in(reg) n,
                    data = inout(reg) data => _,
                    avl = inout(reg) 4 * blocks => _,
                    vl = out(reg) _,
                    t = out(reg) _,
                    out("v0") _, out("v1") _, out("v2") _, out("v3") _,
                    out("v4") _, out("v5") _, out("v6") _, out("v7") _,
                    out("v8") _, out("v9") _, out("v10") _, out("v11") _,
                    out("v12") _, out("v13") _, out("v14") _, out("v15") _,
                    out("v16") _, out("v17") _, out("v18") _, out("v19") _,
                    out("v20") _, out("v21") _, out("v22") _, out("v23") _,
                    out("v24") _, out("v25") _, out("v26") _, out("v27") _,
                    out("v28") _, out("v29") _, out("v30") _,
                    options(nostack),
                );
            }
        }
    };
}

counter_body!(
    counter10,
    "v16",
    [
        "v17", "v18", "v19", "v20", "v21", "v22", "v23", "v24", "v25"
    ],
    "v26"
);
counter_body!(
    counter12,
    "v16",
    [
        "v17", "v18", "v19", "v20", "v21", "v22", "v23", "v24", "v25", "v26",
        "v27"
    ],
    "v28"
);
counter_body!(
    counter14,
    "v16",
    [
        "v17", "v18", "v19", "v20", "v21", "v22", "v23", "v24", "v25", "v26",
        "v27", "v28", "v29"
    ],
    "v30"
);

// Encryption: key 0, middle rounds with keys 1..R-1, final with R.
vaes_body!(
    encrypt10,
    "v16",
    [
        "v17", "v18", "v19", "v20", "v21", "v22", "v23", "v24", "v25"
    ],
    "v26",
    "vaesem.vs",
    "vaesef.vs"
);
vaes_body!(
    encrypt12,
    "v16",
    [
        "v17", "v18", "v19", "v20", "v21", "v22", "v23", "v24", "v25", "v26",
        "v27"
    ],
    "v28",
    "vaesem.vs",
    "vaesef.vs"
);
vaes_body!(
    encrypt14,
    "v16",
    [
        "v17", "v18", "v19", "v20", "v21", "v22", "v23", "v24", "v25", "v26",
        "v27", "v28", "v29"
    ],
    "v30",
    "vaesem.vs",
    "vaesef.vs"
);

// Decryption runs the same keys backwards: `vaesdm` adds the key
// before InvMixColumns, so the keys need no transformation.
vaes_body!(
    decrypt10,
    "v26",
    [
        "v25", "v24", "v23", "v22", "v21", "v20", "v19", "v18", "v17"
    ],
    "v16",
    "vaesdm.vs",
    "vaesdf.vs"
);
vaes_body!(
    decrypt12,
    "v28",
    [
        "v27", "v26", "v25", "v24", "v23", "v22", "v21", "v20", "v19", "v18",
        "v17"
    ],
    "v16",
    "vaesdm.vs",
    "vaesdf.vs"
);
vaes_body!(
    decrypt14,
    "v30",
    [
        "v29", "v28", "v27", "v26", "v25", "v24", "v23", "v22", "v21", "v20",
        "v19", "v18", "v17"
    ],
    "v16",
    "vaesdm.vs",
    "vaesdf.vs"
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cipher::aes::portable;

    /// Returns the cipher, or `None` (skipping the test) without
    /// Zvkned.
    fn aes<const K: usize>(key: &[u8; K]) -> Option<Aes<K>> {
        match Aes::try_new(key) {
            Ok(a) => Some(a),
            Err(Error::NotSupported) => None,
            Err(e) => panic!("{e}"),
        }
    }

    /// The counter loop against a block at a time, at every length
    /// across a pass and past it.
    ///
    /// Round-tripping would not catch a wrong keystream, since the
    /// same wrong keystream undoes itself.
    #[test]
    fn counter_blocks_match_a_block_at_a_time() {
        let Some(aes) = aes(&[0x5au8; 16]) else {
            return;
        };
        const N: usize = 37 * BLOCK_SIZE;
        let start = [0x77u8; BLOCK_SIZE];

        let mut want = [0u8; N];
        let mut counter = start;
        for chunk in want.chunks_mut(BLOCK_SIZE) {
            let mut block = counter;
            aes.encrypt_block(&mut block);
            chunk.copy_from_slice(&block);
            add_low32(&mut counter, 1);
        }

        for blocks in 0..=N / BLOCK_SIZE {
            let n = blocks * BLOCK_SIZE;
            let mut got = [0u8; N];
            let mut counter = start;
            aes.xor_counter_blocks(&mut counter, &mut got[..n]);
            assert_eq!(got[..n], want[..n], "{blocks} blocks");
            // And the counter is left on the block after the last.
            let mut want_counter = start;
            add_low32(&mut want_counter, blocks as u32);
            assert_eq!(counter, want_counter, "{blocks} blocks, counter");
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

    fn check<const K: usize>(key: &str, plain: &str, cipher: &str) {
        let key: [u8; K] = unhex(key)[..K].try_into().unwrap();
        let plain: [u8; 16] = unhex(plain)[..16].try_into().unwrap();
        let cipher: [u8; 16] = unhex(cipher)[..16].try_into().unwrap();
        let Some(aes) = aes(&key) else { return };

        let mut block = plain;
        aes.encrypt_block(&mut block);
        assert_eq!(block, cipher, "encrypt");
        aes.decrypt_block(&mut block);
        assert_eq!(block, plain, "decrypt");
    }

    // FIPS 197 Appendix C.
    #[test]
    fn fips197_aes128() {
        check::<16>(
            "000102030405060708090a0b0c0d0e0f",
            "00112233445566778899aabbccddeeff",
            "69c4e0d86a7b0430d8cdb78070b4c55a",
        );
    }

    #[test]
    fn fips197_aes192() {
        check::<24>(
            "000102030405060708090a0b0c0d0e0f1011121314151617",
            "00112233445566778899aabbccddeeff",
            "dda97ca4864cdfe06eaf70a0ec0d7191",
        );
    }

    #[test]
    fn fips197_aes256() {
        check::<32>(
            "000102030405060708090a0b0c0d0e0f\
             101112131415161718191a1b1c1d1e1f",
            "00112233445566778899aabbccddeeff",
            "8ea2b7ca516745bfeafc49904b496089",
        );
    }

    #[test]
    fn matches_ttable() {
        matches_ttable_for::<16>();
        matches_ttable_for::<24>();
        matches_ttable_for::<32>();
    }

    fn matches_ttable_for<const K: usize>() {
        const MAX: usize = 40;
        let klen = K;
        {
            let mut key = [0u8; K];
            for (i, k) in key.iter_mut().enumerate() {
                *k = (i * 37 + klen) as u8;
            }
            let Some(hw) = aes(&key) else { return };
            let sw = portable::ttable::Aes::try_new(&key).unwrap();
            for nblocks in [0, 1, 7, 8, 9, 16, 17, 24, 25, 33, 39] {
                let mut data = [[0u8; BLOCK_SIZE]; MAX];
                for (i, b) in data.as_flattened_mut().iter_mut().enumerate() {
                    *b = (i * 13 + klen) as u8;
                }
                let data = &mut data[..nblocks];
                let mut expected = [[0u8; BLOCK_SIZE]; MAX];
                let expected = &mut expected[..data.len()];
                expected.copy_from_slice(data);
                let mut orig = [[0u8; BLOCK_SIZE]; MAX];
                orig[..data.len()].copy_from_slice(data);

                sw.encrypt_blocks(expected);
                hw.encrypt_blocks(data);
                assert_eq!(data, expected, "encrypt {klen} {nblocks}");
                hw.decrypt_blocks(data);
                assert_eq!(data, &orig[..data.len()], "decrypt {klen}");
            }
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
