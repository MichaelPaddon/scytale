//! AES using the AES-NI instructions on 128-bit registers, with the
//! block loops in hand-written assembly.
//!
//! The loops run eight blocks through each round together: the
//! instruction is pipelined, so eight independent blocks keep it busy
//! where one block would wait on its own result. This is the
//! interleave Intel recommends for ECB-style processing. A tail of
//! fewer blocks goes through one pass of exactly its width.
//!
//! The S-box lives in hardware, so unlike the table-driven portable
//! implementation this one does not leak key material through cache
//! timing.
//!
//! # Availability
//!
//! [`Aes::supported`] says whether this processor has AES-NI.
//! [`Aes::new`] panics without it, so the dispatching cipher asks
//! first; nothing outside this crate can name the type.
//!

use core::fmt;

use super::{RoundKeys, expand, has_aesni};
use crate::cipher::aes::BLOCK_SIZE;
use crate::cipher::{BlockCipher, ByteOrder, add_counter};
use crate::{BlockType, Key, KeyType};
use zeroize::ZeroizeOnDrop;

/// An AES cipher with an expanded key, using AES-NI.
///
/// Supports 128, 192 and 256 bit keys. Key expansion happens once in
/// [`Aes::new`]; the key is wiped on drop.
#[derive(Clone, ZeroizeOnDrop)]
pub struct Aes<const K: usize> {
    keys: RoundKeys,
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
    /// Whether this processor can run this implementation.
    pub(crate) fn supported() -> bool {
        has_aesni()
    }

    /// Expands `key`.
    ///
    /// # Panics
    /// If the processor lacks AES-NI. The type is private and
    /// is named only after the probe has confirmed them, so the
    /// panic is unreachable from outside this crate.
    pub(crate) fn new(key: &[u8; K]) -> Self {
        const {
            assert!(
                K == 16 || K == 24 || K == 32,
                "AES keys are 16, 24 or 32 bytes"
            )
        };
        assert!(Self::supported(), "AES-NI not available");
        // SAFETY: just confirmed present.
        unsafe { Self::new_unchecked(key) }
    }

    /// Expands `key` without checking for AES-NI.
    ///
    /// # Safety
    /// The caller must have confirmed that AES-NI is available.
    pub(crate) unsafe fn new_unchecked(key: &[u8; K]) -> Self {
        unsafe {
            let size = super::KeySize::for_key(key);
            let keys = expand(key, size);
            Aes { keys }
        }
    }

    /// Number of rounds: 10, 12 or 14 depending on key size.
    pub fn rounds(&self) -> usize {
        self.keys.size.rounds()
    }

    /// Encrypts every block in place, independently (ECB).
    pub fn encrypt_blocks(&self, blocks: &mut [[u8; BLOCK_SIZE]]) {
        // SAFETY: the struct only exists if try_new confirmed AES-NI.
        unsafe { encrypt_blocks(&self.keys, blocks.as_flattened_mut()) }
    }

    /// Decrypts every block in place, independently (ECB).
    pub fn decrypt_blocks(&self, blocks: &mut [[u8; BLOCK_SIZE]]) {
        // SAFETY: the struct only exists if try_new confirmed AES-NI.
        unsafe { decrypt_blocks(&self.keys, blocks.as_flattened_mut()) }
    }
}

impl<const K: usize> super::Keyed for Aes<K> {
    /// Always: this implementation exists only where they do.
    fn schedule(&self) -> Option<super::Schedule<'_>> {
        Some(super::Schedule::new(&self.keys))
    }
}

impl<const K: usize> BlockType for Aes<K> {
    type Block = [u8; BLOCK_SIZE];

    fn zero_block() -> Self::Block {
        [0; BLOCK_SIZE]
    }
}

impl<const K: usize> KeyType for Aes<K> {
    type Key = Key<[u8; K]>;

    fn zero_key() -> Self::Key {
        Key::zeroed()
    }
}

impl<const K: usize> Aes<K> {
    /// Counter mode's inner loop; see
    /// [`BlockCipher::xor_counter_blocks`].
    ///
    /// The counters are made in registers and encrypted where they
    /// lie, then XORed over the data on the way to a single store, so
    /// a block is read once and written once, which is what plain ECB
    /// costs. Whole groups go first, then one pass of exactly the
    /// blocks left over.
    ///
    /// `pshufb` comes with SSSE3 rather than AES-NI; `has_aesni`
    /// asks for both, so this type does not exist without it.
    pub fn xor_counter_blocks(
        &self,
        counter: &mut [u8; BLOCK_SIZE],
        order: ByteOrder,
        data: &mut [u8],
    ) {
        xor_counter_blocks_of(
            super::Schedule::new(&self.keys),
            counter,
            order,
            data,
        )
    }
}

/// Counter mode's inner loop given only the expanded key.
///
/// The same work as [`Aes::xor_counter_blocks`], for code that holds
/// a key schedule rather than a cipher: the mode that runs this and
/// GHASH together has one of those and no cipher to ask.
pub(crate) fn xor_counter_blocks_of(
    schedule: super::Schedule<'_>,
    counter: &mut [u8; BLOCK_SIZE],
    order: ByteOrder,
    data: &mut [u8],
) {
    debug_assert_eq!(data.len() % BLOCK_SIZE, 0);
    let shuffle = shuffle_for(order);
    let rk = schedule.keys();
    let rounds = schedule.rounds();
    let mut data = data;

    let groups = data.len() / (GROUP * BLOCK_SIZE);
    if groups > 0 {
        let (whole, rest) = data.split_at_mut(groups * GROUP * BLOCK_SIZE);
        // SAFETY: a schedule exists only where AES-NI does; `whole`
        // is `groups` whole groups, at least one. The loop leaves
        // `counter` on the block after the last.
        unsafe {
            counter_groups(
                rk,
                rounds,
                counter.as_mut_ptr(),
                whole.as_mut_ptr(),
                groups,
                shuffle,
            );
        }
        data = rest;
    }

    // At most seven blocks are left, each width with a body of
    // its own so that a short message costs one pass, not a group.
    if !data.is_empty() {
        let blocks = data.len() / BLOCK_SIZE;
        // SAFETY: as above, and `blocks` is 1 to 7, which indexes
        // the table, with `data` exactly that many blocks.
        unsafe {
            TAILS[blocks - 1](
                rk,
                rounds,
                counter.as_ptr(),
                data.as_mut_ptr(),
                shuffle,
            );
        }
        add_counter(counter, order, blocks as u32);
    }
}

/// Blocks the counter loop puts through the cipher at once.
pub(super) const GROUP: usize = 8;

/// Constants the counter loop reads, at the width it loads them.
#[repr(align(16))]
struct Mask([u8; BLOCK_SIZE]);

#[repr(align(16))]
struct Words<const N: usize>([u32; N]);

/// Reverses the bytes of a register. The counter is the last four
/// bytes of a block, most significant first; reversed, it is the low
/// doubleword, least significant first, where a doubleword add can
/// reach it.
static BSWAP: Mask =
    Mask([15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0]);

/// Leaves a register alone. A counter in the first four bytes, least
/// significant first, is already the low doubleword, so the same loop
/// serves it with nothing to reverse.
static KEEP: Mask =
    Mask([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);

/// The shuffle that puts a block's counter field in the low
/// doubleword, and afterwards puts it back.
fn shuffle_for(order: ByteOrder) -> *const u8 {
    match order {
        ByteOrder::Big => BSWAP.0.as_ptr(),
        ByteOrder::Little => KEEP.0.as_ptr(),
    }
}

/// What each register adds to the base counter to make its block,
/// and after those, in the ninth place, what the base itself moves on
/// by once a group is made: one group's worth.
static OFFSETS: Words<{ 4 * (GROUP + 1) }> = {
    let mut w = [0u32; 4 * (GROUP + 1)];
    let mut i = 0;
    while i <= GROUP {
        w[4 * i] = i as u32;
        i += 1;
    }
    Words(w)
};

impl<const K: usize> BlockCipher for Aes<K> {
    fn new(key: &Self::Key) -> Self {
        Aes::new(key.array())
    }

    fn encrypt(&self, blocks: &mut [Self::Block]) {
        Aes::encrypt_blocks(self, blocks)
    }

    fn decrypt(&self, blocks: &mut [Self::Block]) {
        Aes::decrypt_blocks(self, blocks)
    }
}

/// Encrypts a whole number of blocks.
///
/// # Safety
/// Requires AES-NI; `data.len()` must be a multiple of 16.
pub(super) unsafe fn encrypt_blocks(keys: &RoundKeys, data: &mut [u8]) {
    unsafe {
        run(
            keys.enc.as_ptr(),
            keys.size.rounds(),
            data,
            encrypt8,
            [
                encrypt1, encrypt2, encrypt3, encrypt4, encrypt5, encrypt6,
                encrypt7,
            ],
        )
    }
}

/// Decrypts a whole number of blocks.
///
/// # Safety
/// Requires AES-NI; `data.len()` must be a multiple of 16.
pub(super) unsafe fn decrypt_blocks(keys: &RoundKeys, data: &mut [u8]) {
    unsafe {
        run(
            keys.dec.as_ptr(),
            keys.size.rounds(),
            data,
            decrypt8,
            [
                decrypt1, decrypt2, decrypt3, decrypt4, decrypt5, decrypt6,
                decrypt7,
            ],
        )
    }
}

/// A body that processes `n` blocks at `data`.
type Body = unsafe fn(*const u32, usize, *mut u8);

/// Whole groups of eight through `groups`, then the 1 to 7 leftover
/// blocks through the body of exactly that width, so the tail is one
/// interleaved pass rather than a sequence of single blocks.
///
/// # Safety
/// Requires AES-NI; `data.len()` must be a multiple of 16.
unsafe fn run(
    rk: *const u32,
    rounds: usize,
    data: &mut [u8],
    groups: unsafe fn(*const u32, usize, *mut u8, usize),
    tails: [Body; 7],
) {
    unsafe {
        let blocks = data.len() / BLOCK_SIZE;
        let full = blocks / 8;
        let mut p = data.as_mut_ptr();
        if full > 0 {
            groups(rk, rounds, p, full);
            p = p.add(full * 8 * BLOCK_SIZE);
        }
        if let Some(tail) = (blocks % 8).checked_sub(1) {
            tails[tail](rk, rounds, p);
        }
    }
}

// The bodies below are hand-written so the instruction order can be
// tuned. Blocks live in xmm0..xmm7; round keys stream through xmm8
// from memory (always via `movdqu`: the key array is not 16-byte
// aligned, which legacy SSE memory operands require). The middle
// rounds loop over the key pointer, so one body serves all key sizes.

/// Defines a body that runs the listed registers, loaded from the
/// listed byte offsets, through the cipher once.
macro_rules! body {
    ($name:ident, $mid:literal, $last:literal,
     [$(($r:literal, $off:literal)),+]) => {
        /// # Safety
        /// Requires AES-NI; `rk` must point at `rounds + 1` round keys
        /// and `data` at the blocks this body handles.
        unsafe fn $name(rk: *const u32, rounds: usize, data: *mut u8) {
            unsafe {
                core::arch::asm!(
                    "movdqu xmm8, [{rk}]",
                    $(concat!("movdqu ", $r, ", [{data} + ", $off, "]"),)+
                    $(concat!("pxor ", $r, ", xmm8"),)+
                    "lea {k}, [{rk} + 16]",
                    "mov {n}, {nr}",
                    "2:",
                    "movdqu xmm8, [{k}]",
                    $(concat!($mid, " ", $r, ", xmm8"),)+
                    "add {k}, 16",
                    "dec {n}",
                    "jnz 2b",
                    "movdqu xmm8, [{k}]",
                    $(concat!($last, " ", $r, ", xmm8"),)+
                    $(concat!("movdqu [{data} + ", $off, "], ", $r),)+
                    rk = in(reg) rk,
                    nr = in(reg) rounds - 1,
                    data = in(reg) data,
                    k = out(reg) _,
                    n = out(reg) _,
                    out("xmm0") _, out("xmm1") _, out("xmm2") _, out("xmm3") _,
                    out("xmm4") _, out("xmm5") _, out("xmm6") _, out("xmm7") _,
                    out("xmm8") _,
                    options(nostack),
                );
            }
        }
    };
}

/// Defines the loop over whole groups of eight blocks.
macro_rules! groups {
    ($name:ident, $mid:literal, $last:literal) => {
        /// # Safety
        /// Requires AES-NI; `rk` must point at `rounds + 1` round keys
        /// and `data` at `groups * 128` writable bytes, `groups >= 1`.
        unsafe fn $name(
            rk: *const u32,
            rounds: usize,
            data: *mut u8,
            groups: usize,
        ) {
            unsafe {
                core::arch::asm!(
                    "3:",
                    "movdqu xmm8, [{rk}]",
                    "movdqu xmm0, [{data}]",
                    "movdqu xmm1, [{data} + 16]",
                    "movdqu xmm2, [{data} + 32]",
                    "movdqu xmm3, [{data} + 48]",
                    "movdqu xmm4, [{data} + 64]",
                    "movdqu xmm5, [{data} + 80]",
                    "movdqu xmm6, [{data} + 96]",
                    "movdqu xmm7, [{data} + 112]",
                    "pxor xmm0, xmm8",
                    "pxor xmm1, xmm8",
                    "pxor xmm2, xmm8",
                    "pxor xmm3, xmm8",
                    "pxor xmm4, xmm8",
                    "pxor xmm5, xmm8",
                    "pxor xmm6, xmm8",
                    "pxor xmm7, xmm8",
                    "lea {k}, [{rk} + 16]",
                    "mov {n}, {nr}",
                    "2:",
                    "movdqu xmm8, [{k}]",
                    concat!($mid, " xmm0, xmm8"),
                    concat!($mid, " xmm1, xmm8"),
                    concat!($mid, " xmm2, xmm8"),
                    concat!($mid, " xmm3, xmm8"),
                    concat!($mid, " xmm4, xmm8"),
                    concat!($mid, " xmm5, xmm8"),
                    concat!($mid, " xmm6, xmm8"),
                    concat!($mid, " xmm7, xmm8"),
                    "add {k}, 16",
                    "dec {n}",
                    "jnz 2b",
                    "movdqu xmm8, [{k}]",
                    concat!($last, " xmm0, xmm8"),
                    concat!($last, " xmm1, xmm8"),
                    concat!($last, " xmm2, xmm8"),
                    concat!($last, " xmm3, xmm8"),
                    concat!($last, " xmm4, xmm8"),
                    concat!($last, " xmm5, xmm8"),
                    concat!($last, " xmm6, xmm8"),
                    concat!($last, " xmm7, xmm8"),
                    "movdqu [{data}], xmm0",
                    "movdqu [{data} + 16], xmm1",
                    "movdqu [{data} + 32], xmm2",
                    "movdqu [{data} + 48], xmm3",
                    "movdqu [{data} + 64], xmm4",
                    "movdqu [{data} + 80], xmm5",
                    "movdqu [{data} + 96], xmm6",
                    "movdqu [{data} + 112], xmm7",
                    "add {data}, 128",
                    "dec {groups}",
                    "jnz 3b",
                    rk = in(reg) rk,
                    nr = in(reg) rounds - 1,
                    data = inout(reg) data => _,
                    groups = inout(reg) groups => _,
                    k = out(reg) _,
                    n = out(reg) _,
                    out("xmm0") _, out("xmm1") _, out("xmm2") _, out("xmm3") _,
                    out("xmm4") _, out("xmm5") _, out("xmm6") _, out("xmm7") _,
                    out("xmm8") _,
                    options(nostack),
                );
            }
        }
    };
}

/// Runs whole groups of counter blocks through the cipher and XORs
/// them over `data`, leaving `counter` on the block after the last.
///
/// Only the low doubleword is added to, so a carry out of the counter
/// field would be lost; the caller splits its run at that boundary.
///
/// # Safety
/// Requires AES-NI and `pshufb`, which `has_aesni` asks for
/// together; `rk` must point at `rounds + 1` round keys, `counter` at
/// a block, and `data` at `groups * 128` writable bytes, with
/// `groups >= 1`.
unsafe fn counter_groups(
    rk: *const u32,
    rounds: usize,
    counter: *mut u8,
    data: *mut u8,
    groups: usize,
    shuffle: *const u8,
) {
    unsafe {
        core::arch::asm!(
            "movdqa xmm10, [{shuffle}]",
            // The base counter, byte-reversed so the field adds.
            "movdqu xmm9, [{counter}]",
            "pshufb xmm9, xmm10",
            "3:",
            // Eight counters from the one base, then the base moved
            // on while they are turned back into blocks.
            "movdqa xmm0, xmm9",
            "movdqa xmm1, xmm9",
            "movdqa xmm2, xmm9",
            "movdqa xmm3, xmm9",
            "movdqa xmm4, xmm9",
            "movdqa xmm5, xmm9",
            "movdqa xmm6, xmm9",
            "movdqa xmm7, xmm9",
            "paddd xmm0, [{offs}]",
            "paddd xmm1, [{offs} + 16]",
            "paddd xmm2, [{offs} + 32]",
            "paddd xmm3, [{offs} + 48]",
            "paddd xmm4, [{offs} + 64]",
            "paddd xmm5, [{offs} + 80]",
            "paddd xmm6, [{offs} + 96]",
            "paddd xmm7, [{offs} + 112]",
            "paddd xmm9, [{offs} + 128]",
            "pshufb xmm0, xmm10",
            "pshufb xmm1, xmm10",
            "pshufb xmm2, xmm10",
            "pshufb xmm3, xmm10",
            "pshufb xmm4, xmm10",
            "pshufb xmm5, xmm10",
            "pshufb xmm6, xmm10",
            "pshufb xmm7, xmm10",
            "movdqu xmm8, [{rk}]",
            "pxor xmm0, xmm8",
            "pxor xmm1, xmm8",
            "pxor xmm2, xmm8",
            "pxor xmm3, xmm8",
            "pxor xmm4, xmm8",
            "pxor xmm5, xmm8",
            "pxor xmm6, xmm8",
            "pxor xmm7, xmm8",
            "lea {k}, [{rk} + 16]",
            "mov {n}, {nr}",
            "2:",
            "movdqu xmm8, [{k}]",
            "aesenc xmm0, xmm8",
            "aesenc xmm1, xmm8",
            "aesenc xmm2, xmm8",
            "aesenc xmm3, xmm8",
            "aesenc xmm4, xmm8",
            "aesenc xmm5, xmm8",
            "aesenc xmm6, xmm8",
            "aesenc xmm7, xmm8",
            "add {k}, 16",
            "dec {n}",
            "jnz 2b",
            "movdqu xmm8, [{k}]",
            "aesenclast xmm0, xmm8",
            "aesenclast xmm1, xmm8",
            "aesenclast xmm2, xmm8",
            "aesenclast xmm3, xmm8",
            "aesenclast xmm4, xmm8",
            "aesenclast xmm5, xmm8",
            "aesenclast xmm6, xmm8",
            "aesenclast xmm7, xmm8",
            // The keystream never reaches memory: it is XORed over
            // the data on the way to the one store. The load is
            // separate because a plain SSE operand must be aligned
            // and the message need not be.
            "movdqu xmm12, [{data}]",
            "pxor xmm0, xmm12",
            "movdqu [{data}], xmm0",
            "movdqu xmm12, [{data} + 16]",
            "pxor xmm1, xmm12",
            "movdqu [{data} + 16], xmm1",
            "movdqu xmm12, [{data} + 32]",
            "pxor xmm2, xmm12",
            "movdqu [{data} + 32], xmm2",
            "movdqu xmm12, [{data} + 48]",
            "pxor xmm3, xmm12",
            "movdqu [{data} + 48], xmm3",
            "movdqu xmm12, [{data} + 64]",
            "pxor xmm4, xmm12",
            "movdqu [{data} + 64], xmm4",
            "movdqu xmm12, [{data} + 80]",
            "pxor xmm5, xmm12",
            "movdqu [{data} + 80], xmm5",
            "movdqu xmm12, [{data} + 96]",
            "pxor xmm6, xmm12",
            "movdqu [{data} + 96], xmm6",
            "movdqu xmm12, [{data} + 112]",
            "pxor xmm7, xmm12",
            "movdqu [{data} + 112], xmm7",
            "add {data}, 128",
            "dec {groups}",
            "jnz 3b",
            // Hand the counter back in block order.
            "pshufb xmm9, xmm10",
            "movdqu [{counter}], xmm9",
            rk = in(reg) rk,
            nr = in(reg) rounds - 1,
            counter = in(reg) counter,
            data = inout(reg) data => _,
            groups = inout(reg) groups => _,
            offs = in(reg) OFFSETS.0.as_ptr(),
            shuffle = in(reg) shuffle,
            k = out(reg) _,
            n = out(reg) _,
            out("xmm0") _, out("xmm1") _, out("xmm2") _, out("xmm3") _,
            out("xmm4") _, out("xmm5") _, out("xmm6") _, out("xmm7") _,
            out("xmm8") _, out("xmm9") _, out("xmm10") _, out("xmm12") _,
            options(nostack),
        );
    }
}

/// Defines a counter body for a fixed number of blocks: it makes its
/// counters from `counter`, encrypts them and XORs them over `data`.
/// Advancing `counter` is left to the caller, which knows the width.
macro_rules! counter_body {
    ($name:ident, [$(($r:literal, $off:literal)),+]) => {
        /// # Safety
        /// Requires AES-NI and `pshufb`; `rk` must point at
        /// `rounds + 1` round keys, `counter` at a block, and `data`
        /// at the blocks this body handles.
        unsafe fn $name(
            rk: *const u32,
            rounds: usize,
            counter: *const u8,
            data: *mut u8,
            shuffle: *const u8,
        ) {
            unsafe {
                core::arch::asm!(
                    "movdqa xmm10, [{shuffle}]",
                    "movdqu xmm9, [{counter}]",
                    "pshufb xmm9, xmm10",
                    $(concat!("movdqa ", $r, ", xmm9"),)+
                    $(concat!(
                        "paddd ", $r, ", [{offs} + ", $off, "]"),)+
                    $(concat!("pshufb ", $r, ", xmm10"),)+
                    "movdqu xmm8, [{rk}]",
                    $(concat!("pxor ", $r, ", xmm8"),)+
                    "lea {k}, [{rk} + 16]",
                    "mov {n}, {nr}",
                    "2:",
                    "movdqu xmm8, [{k}]",
                    $(concat!("aesenc ", $r, ", xmm8"),)+
                    "add {k}, 16",
                    "dec {n}",
                    "jnz 2b",
                    "movdqu xmm8, [{k}]",
                    $(concat!("aesenclast ", $r, ", xmm8"),)+
                    $(concat!(
                        "movdqu xmm12, [{data} + ", $off, "]\n",
                        "pxor ", $r, ", xmm12\n",
                        "movdqu [{data} + ", $off, "], ", $r),)+
                    rk = in(reg) rk,
                    nr = in(reg) rounds - 1,
                    counter = in(reg) counter,
                    data = in(reg) data,
                    offs = in(reg) OFFSETS.0.as_ptr(),
                    shuffle = in(reg) shuffle,
                    k = out(reg) _,
                    n = out(reg) _,
                    out("xmm0") _, out("xmm1") _, out("xmm2") _, out("xmm3") _,
                    out("xmm4") _, out("xmm5") _, out("xmm6") _, out("xmm8") _,
                    out("xmm9") _, out("xmm10") _, out("xmm12") _,
                    options(nostack),
                );
            }
        }
    };
}

counter_body!(counter1, [("xmm0", "0")]);
counter_body!(counter2, [("xmm0", "0"), ("xmm1", "16")]);
counter_body!(counter3, [("xmm0", "0"), ("xmm1", "16"), ("xmm2", "32")]);
counter_body!(
    counter4,
    [
        ("xmm0", "0"),
        ("xmm1", "16"),
        ("xmm2", "32"),
        ("xmm3", "48")
    ]
);
counter_body!(
    counter5,
    [
        ("xmm0", "0"),
        ("xmm1", "16"),
        ("xmm2", "32"),
        ("xmm3", "48"),
        ("xmm4", "64")
    ]
);
counter_body!(
    counter6,
    [
        ("xmm0", "0"),
        ("xmm1", "16"),
        ("xmm2", "32"),
        ("xmm3", "48"),
        ("xmm4", "64"),
        ("xmm5", "80")
    ]
);
counter_body!(
    counter7,
    [
        ("xmm0", "0"),
        ("xmm1", "16"),
        ("xmm2", "32"),
        ("xmm3", "48"),
        ("xmm4", "64"),
        ("xmm5", "80"),
        ("xmm6", "96")
    ]
);

/// A counter body: the round keys, the round count, the counter
/// block, the data, and the shuffle that puts the counter field
/// where an add can reach it.
type CounterBody = unsafe fn(*const u32, usize, *const u8, *mut u8, *const u8);

/// The bodies by block count, so that a tail of `n` blocks is one
/// call.
static TAILS: [CounterBody; 7] = [
    counter1, counter2, counter3, counter4, counter5, counter6, counter7,
];

groups!(encrypt8, "aesenc", "aesenclast");
groups!(decrypt8, "aesdec", "aesdeclast");

body!(encrypt1, "aesenc", "aesenclast", [("xmm0", "0")]);
body!(
    encrypt2,
    "aesenc",
    "aesenclast",
    [("xmm0", "0"), ("xmm1", "16")]
);
body!(
    encrypt3,
    "aesenc",
    "aesenclast",
    [("xmm0", "0"), ("xmm1", "16"), ("xmm2", "32")]
);
body!(
    encrypt4,
    "aesenc",
    "aesenclast",
    [
        ("xmm0", "0"),
        ("xmm1", "16"),
        ("xmm2", "32"),
        ("xmm3", "48")
    ]
);
body!(
    encrypt5,
    "aesenc",
    "aesenclast",
    [
        ("xmm0", "0"),
        ("xmm1", "16"),
        ("xmm2", "32"),
        ("xmm3", "48"),
        ("xmm4", "64")
    ]
);
body!(
    encrypt6,
    "aesenc",
    "aesenclast",
    [
        ("xmm0", "0"),
        ("xmm1", "16"),
        ("xmm2", "32"),
        ("xmm3", "48"),
        ("xmm4", "64"),
        ("xmm5", "80")
    ]
);
body!(
    encrypt7,
    "aesenc",
    "aesenclast",
    [
        ("xmm0", "0"),
        ("xmm1", "16"),
        ("xmm2", "32"),
        ("xmm3", "48"),
        ("xmm4", "64"),
        ("xmm5", "80"),
        ("xmm6", "96")
    ]
);

body!(decrypt1, "aesdec", "aesdeclast", [("xmm0", "0")]);
body!(
    decrypt2,
    "aesdec",
    "aesdeclast",
    [("xmm0", "0"), ("xmm1", "16")]
);
body!(
    decrypt3,
    "aesdec",
    "aesdeclast",
    [("xmm0", "0"), ("xmm1", "16"), ("xmm2", "32")]
);
body!(
    decrypt4,
    "aesdec",
    "aesdeclast",
    [
        ("xmm0", "0"),
        ("xmm1", "16"),
        ("xmm2", "32"),
        ("xmm3", "48")
    ]
);
body!(
    decrypt5,
    "aesdec",
    "aesdeclast",
    [
        ("xmm0", "0"),
        ("xmm1", "16"),
        ("xmm2", "32"),
        ("xmm3", "48"),
        ("xmm4", "64")
    ]
);
body!(
    decrypt6,
    "aesdec",
    "aesdeclast",
    [
        ("xmm0", "0"),
        ("xmm1", "16"),
        ("xmm2", "32"),
        ("xmm3", "48"),
        ("xmm4", "64"),
        ("xmm5", "80")
    ]
);
body!(
    decrypt7,
    "aesdec",
    "aesdeclast",
    [
        ("xmm0", "0"),
        ("xmm1", "16"),
        ("xmm2", "32"),
        ("xmm3", "48"),
        ("xmm4", "64"),
        ("xmm5", "80"),
        ("xmm6", "96")
    ]
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cipher::aes::portable;

    /// Returns the cipher, or `None` (skipping the test) without AES-NI.
    fn aes<const K: usize>(key: &[u8; K]) -> Option<Aes<K>> {
        Aes::<K>::supported().then(|| Aes::new(key))
    }

    /// The counter loop against a block at a time, at every length
    /// across a group, its tail widths and the block after it.
    ///
    /// Round-tripping would not catch a wrong keystream, since the
    /// same wrong keystream undoes itself.
    #[test]
    fn counter_blocks_match_a_block_at_a_time() {
        let Some(aes) = aes(&[0x5au8; 16]) else {
            return;
        };
        // Both conventions: GCM's last four bytes and GCM-SIV's
        // first four, which is the same loop with nothing to
        // reverse.
        for order in [ByteOrder::Big, ByteOrder::Little] {
            counter_blocks_match(&aes, order);
        }
    }

    fn counter_blocks_match<const K: usize>(aes: &Aes<K>, order: ByteOrder) {
        const N: usize = (2 * GROUP + 5) * BLOCK_SIZE;
        let start = [0x77u8; BLOCK_SIZE];

        let mut want = [0u8; N];
        let mut counter = start;
        for chunk in want.chunks_mut(BLOCK_SIZE) {
            let mut block = counter;
            aes.encrypt_blocks(core::slice::from_mut(&mut block));
            chunk.copy_from_slice(&block);
            add_counter(&mut counter, order, 1);
        }

        for blocks in 0..=N / BLOCK_SIZE {
            let n = blocks * BLOCK_SIZE;
            let mut got = [0u8; N];
            let mut counter = start;
            aes.xor_counter_blocks(&mut counter, order, &mut got[..n]);
            assert_eq!(got[..n], want[..n], "{blocks} blocks");
            // And the counter is left on the block after the last.
            let mut want_counter = start;
            add_counter(&mut want_counter, order, blocks as u32);
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
        aes.encrypt_blocks(core::slice::from_mut(&mut block));
        assert_eq!(block, cipher, "encrypt");
        aes.decrypt_blocks(core::slice::from_mut(&mut block));
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
        let klen = K;
        {
            let mut key = [0u8; K];
            for (i, k) in key.iter_mut().enumerate() {
                *k = (i * 37 + klen) as u8;
            }
            let Some(hw) = aes(&key) else { return };
            let sw = portable::ttable::Aes::new(&key);
            // Every tail width, with and without full groups before it.
            for nblocks in 0..26 {
                let mut data = [[0u8; BLOCK_SIZE]; 25];
                for (i, b) in data.as_flattened_mut().iter_mut().enumerate() {
                    *b = (i * 13 + klen) as u8;
                }
                let data = &mut data[..nblocks];
                let mut expected = [[0u8; BLOCK_SIZE]; 25];
                let expected = &mut expected[..data.len()];
                expected.copy_from_slice(data);
                let mut orig = [[0u8; BLOCK_SIZE]; 25];
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
