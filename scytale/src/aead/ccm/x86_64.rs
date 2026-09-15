//! CCM as one loop, for processors with the AES instructions.
//!
//! The two halves of CCM run the cipher at different rates: the
//! counter mode keystream could take every block at once, while the
//! CBC-MAC chains, each block waiting on the one before it. Called in
//! turn, the MAC sets the pace of the whole and the keystream is then
//! a second pass on top. Written as one loop, each iteration issues
//! one keystream block beside one MAC block, and neither depends on
//! the other's result within the iteration beyond the plaintext
//! itself, so the processor runs them together and the keystream
//! costs little more than the ports it occupies.
//!
//! When decrypting, the plaintext the MAC takes is the ciphertext
//! with this iteration's keystream on it, so the MAC block waits for
//! that keystream block as well as for its own chain. The two are
//! the same length of work, started together, so the wait is for the
//! longer of the two and not for their sum.
//!
//! # The chain between blocks
//!
//! Each iteration finishes the previous MAC block's last round and
//! starts the next. AESENCLAST ends by XORing in its round key, and
//! what happens to the chain next is the plaintext block and the first
//! round key; the three are folded into one key made off the chain's
//! path, so the chain waits for the rounds and nothing else. That
//! folded key carries the last round key a second time, cancelling
//! the one the round put in. The chain a call starts from has had its
//! last round already, so it is brought in with that key XORed back
//! on and then through AESDECLAST under a zero key, which undoes the
//! byte substitution and the row shift and nothing more: the loop's
//! first AESENCLAST then gives exactly the chain it was given.
//!
//! # Availability
//!
//! [`Engine::of`] asks for AES-NI and AVX: the loop is written in the
//! VEX encoding, for its three-operand forms.

#![allow(unsafe_code)]

use crate::cipher::BlockCipher;
use crate::cipher::aes::x86_64::{Keys, has_aesni, keys};
use crate::implementation::Implementation;
use crate::probe::Probe;

/// The block the loop works in.
const BLOCK: usize = 16;

/// The interleaved loop, and how to reach the key it runs under.
pub(crate) struct Engine<C> {
    keys: Keys<C>,
}

/// By hand rather than derived: nothing here is a cipher, only the
/// way to reach one's round keys, so this clones whatever `C` is.
impl<C> Clone for Engine<C> {
    fn clone(&self) -> Self {
        Engine { keys: self.keys }
    }
}

impl<C: BlockCipher> Engine<C> {
    /// The engine `implementation` names, or `None` where the
    /// processor lacks the instructions or `C` is not a cipher this is
    /// written for. Both of the AES implementations run this loop: a
    /// chain has nothing for wider registers to do.
    pub(crate) fn of(implementation: Implementation) -> Option<Self> {
        match implementation {
            Implementation::Vaes | Implementation::Aesni if supported() => {
                Some(Engine { keys: keys::<C>()? })
            }
            _ => None,
        }
    }

    /// Runs CCM over `data`, a whole number of blocks: the keystream
    /// from `counter`, and the MAC from `chain` over the plaintext.
    /// `encrypt` says which side of the keystream the plaintext is on.
    /// Leaves `counter` at the block after the last and `chain` at
    /// the MAC so far.
    ///
    /// Returns whether it ran, which it does wherever the engine was
    /// built for this cipher and the counter's low 32 bits do not wrap
    /// inside the run, which would take 64 gigabytes.
    pub(crate) fn run(
        &self,
        cipher: &C,
        chain: &mut [u8; BLOCK],
        counter: &mut [u8; BLOCK],
        data: &mut [u8],
        encrypt: bool,
    ) -> bool {
        debug_assert_eq!(data.len() % BLOCK, 0);
        let blocks = data.len() / BLOCK;
        let Some(schedule) = (self.keys)(cipher) else {
            return false;
        };
        let low = u32::from_be_bytes([
            counter[12],
            counter[13],
            counter[14],
            counter[15],
        ]);
        if blocks == 0 || (u32::MAX - low) as usize + 1 < blocks {
            return false;
        }
        let run = if encrypt { seal } else { open };
        // SAFETY: the instructions were confirmed when the engine was
        // built, the schedule holds `rounds + 1` round keys, `data` is
        // `blocks` whole blocks with at least one, and the counter's
        // low word does not wrap within them.
        unsafe {
            run(
                schedule.keys(),
                schedule.rounds(),
                chain.as_mut_ptr(),
                counter.as_ptr(),
                data.as_mut_ptr(),
                blocks,
                low,
            );
        }
        *counter = u128::from_be_bytes(*counter)
            .wrapping_add(blocks as u128)
            .to_be_bytes();
        true
    }
}

/// Whether the processor has AES-NI and SSSE3, as the cipher asks,
/// and AVX with the operating system saving its state (CPUID leaf 1,
/// ECX bits 27 and 28, then XCR0 bits 1 and 2).
fn supported() -> bool {
    has_aesni() && PROBED.yes(ask_avx)
}

/// Asked once; see [`crate::probe`].
static PROBED: Probe = Probe::new();

fn ask_avx() -> bool {
    use core::arch::x86_64::{__cpuid, _xgetbv};
    let wanted = (1 << 27) | (1 << 28);
    if __cpuid(1).ecx & wanted != wanted {
        return false;
    }
    // SAFETY: OSXSAVE was just confirmed, so XGETBV is available.
    let xcr0 = unsafe { _xgetbv(0) };
    xcr0 & 0b110 == 0b110
}

/// The loop, written once for both directions. `$plain` names the
/// register the plaintext block is in once the keystream has been
/// applied: the input when sealing, the output when opening.
macro_rules! ccm_loop {
    ($name:ident, $plain:literal, $doc:literal) => {
        #[doc = $doc]
        ///
        /// # Safety
        /// Requires AES-NI and AVX; `rk` must point at `rounds + 1`
        /// round keys, `chain` and `counter` at a block each, and
        /// `data` at `blocks` blocks, with `blocks >= 1` and `low`, the
        /// counter's last four bytes read big-endian, not wrapping
        /// within them.
        unsafe fn $name(
            rk: *const u32,
            rounds: usize,
            chain: *mut u8,
            counter: *const u8,
            data: *mut u8,
            blocks: usize,
            low: u32,
        ) {
            unsafe {
                core::arch::asm!(
                    "vmovdqu xmm2, [{rk}]",
                    "vpxor xmm8, xmm2, [{last}]",
                    "vmovdqu xmm7, [{counter}]",
                    "vpxor xmm6, xmm6, xmm6",
                    "vmovdqu xmm0, [{chain}]",
                    "vpxor xmm0, xmm0, [{last}]",
                    "vaesdeclast xmm0, xmm0, xmm6",
                    "3:",
                    // The keystream block.
                    "mov {t:e}, {low:e}",
                    "bswap {t:e}",
                    "vpinsrd xmm1, xmm7, {t:e}, 3",
                    "inc {low:e}",
                    "vpxor xmm1, xmm1, xmm2",
                    "lea {k}, [{rk} + 16]",
                    "mov {n}, {nr}",
                    "2:",
                    "vaesenc xmm1, xmm1, [{k}]",
                    "add {k}, 16",
                    "dec {n}",
                    "jnz 2b",
                    "vaesenclast xmm1, xmm1, [{k}]",
                    "vmovdqu xmm3, [{data}]",
                    "vpxor xmm4, xmm3, xmm1",
                    "vmovdqu [{data}], xmm4",
                    // The previous MAC block's last round, with this
                    // plaintext block and the first round key folded
                    // into its key, then this block's rounds.
                    concat!("vpxor xmm5, xmm8, ", $plain),
                    "vaesenclast xmm0, xmm0, xmm5",
                    "lea {k}, [{rk} + 16]",
                    "mov {n}, {nr}",
                    "2:",
                    "vaesenc xmm0, xmm0, [{k}]",
                    "add {k}, 16",
                    "dec {n}",
                    "jnz 2b",
                    "add {data}, 16",
                    "dec {blocks}",
                    "jnz 3b",
                    "vaesenclast xmm0, xmm0, [{k}]",
                    "vmovdqu [{chain}], xmm0",
                    rk = in(reg) rk,
                    last = in(reg) rk.add(4 * rounds),
                    nr = in(reg) rounds - 1,
                    chain = in(reg) chain,
                    counter = in(reg) counter,
                    data = inout(reg) data => _,
                    blocks = inout(reg) blocks => _,
                    low = inout(reg) low => _,
                    t = out(reg) _,
                    k = out(reg) _,
                    n = out(reg) _,
                    out("xmm0") _, out("xmm1") _, out("xmm2") _,
                    out("xmm3") _, out("xmm4") _, out("xmm5") _,
                    out("xmm6") _, out("xmm7") _, out("xmm8") _,
                    options(nostack),
                );
            }
        }
    };
}

ccm_loop!(
    seal,
    "xmm3",
    "Encrypts a run of blocks and takes the MAC over what they were."
);
ccm_loop!(
    open,
    "xmm4",
    "Decrypts a run of blocks and takes the MAC over what they are."
);
