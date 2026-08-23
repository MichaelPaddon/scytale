//! Linux, through the `getrandom` system call made directly.
//!
//! Linux promises its system call numbers never change, so calling
//! one straight is safe here in a way it is nowhere else. It also
//! means this works with no C library at all, which a static binary
//! may well have.
//!
//! The call is made with no flags, so it waits if the kernel's
//! generator has not been seeded yet. That only happens very early
//! in boot, and waiting is the right answer: the alternative is
//! handing back bytes that are not yet unpredictable.

#![allow(unsafe_code)]

use crate::Error;

/// Whether there is a call to make here.
#[cfg(test)]
pub(crate) const AVAILABLE: bool = true;

/// The number this call goes by. Every architecture below takes it
/// from the generic table except x86-64, which has its own.
#[cfg(target_arch = "x86_64")]
const NUMBER: usize = 318;
#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
const NUMBER: usize = 278;

/// A signal arrived before the kernel had written anything.
const EINTR: isize = -4;

/// Kernels report failure as a small negative number; anything
/// outside this range is not an error code at all.
const FAILURES: core::ops::Range<isize> = -4095..0;

/// Fills `out` with random bytes from the kernel.
pub(crate) fn fill(out: &mut [u8]) -> Result<(), Error> {
    fill_from(getrandom, out)
}

/// Drives `source` until `out` is full.
///
/// Split from the call itself so it can be tested. A request of 256
/// bytes or fewer is never answered in part and never interrupted,
/// so on the sizes anything here actually asks for, this never goes
/// round twice. Handing it a stand-in is the only way to reach those
/// paths on purpose.
fn fill_from(
    mut source: impl FnMut(&mut [u8]) -> isize,
    out: &mut [u8],
) -> Result<(), Error> {
    let mut done = 0;
    while done < out.len() {
        let got = source(&mut out[done..]);
        if got > 0 {
            // The kernel cannot report more than it was offered.
            done += (got as usize).min(out.len() - done);
        } else if got == EINTR {
            // Nothing was written. Ask again from the same place.
            continue;
        } else if FAILURES.contains(&got) {
            return Err(Error::EntropyUnavailable(-got as i32));
        } else {
            // Zero written with bytes still wanted, or a return no
            // kernel makes. Neither should happen, and treating it
            // as progress would loop here forever.
            return Err(Error::EntropyUnavailable(0));
        }
    }
    Ok(())
}

/// One `getrandom` call, with no flags. Returns what the kernel
/// returned: the count written, or a negative error number.
#[cfg(target_arch = "x86_64")]
fn getrandom(out: &mut [u8]) -> isize {
    let ret: isize;
    // SAFETY: the kernel writes at most `len` bytes at `ptr`, and the
    // two describe a slice held exclusively for the call. That write
    // is why this must not claim `nomem`.
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") NUMBER => ret,
            in("rdi") out.as_mut_ptr(),
            in("rsi") out.len(),
            in("rdx") 0usize,
            // The instruction takes these two for itself.
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    ret
}

/// One `getrandom` call, with no flags. Returns what the kernel
/// returned: the count written, or a negative error number.
#[cfg(target_arch = "aarch64")]
fn getrandom(out: &mut [u8]) -> isize {
    let ret: isize;
    // SAFETY: as for x86-64 above.
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") NUMBER,
            inlateout("x0") out.as_mut_ptr() as usize => ret,
            in("x1") out.len(),
            in("x2") 0usize,
            options(nostack),
        );
    }
    ret
}

/// One `getrandom` call, with no flags. Returns what the kernel
/// returned: the count written, or a negative error number.
#[cfg(target_arch = "riscv64")]
fn getrandom(out: &mut [u8]) -> isize {
    let ret: isize;
    // SAFETY: as for x86-64 above.
    unsafe {
        core::arch::asm!(
            "ecall",
            in("a7") NUMBER,
            inlateout("a0") out.as_mut_ptr() as usize => ret,
            in("a1") out.len(),
            in("a2") 0usize,
            options(nostack),
        );
    }
    ret
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An empty request must not reach the kernel at all: a call
    /// asking for nothing returns nothing, which the loop would
    /// otherwise read as failure to make progress.
    #[test]
    fn an_empty_request_asks_for_nothing() {
        let mut asked = 0;
        fill_from(
            |_| {
                asked += 1;
                0
            },
            &mut [],
        )
        .expect("empty");
        assert_eq!(asked, 0);
    }

    /// A kernel answering a byte at a time must still fill the
    /// buffer, and must not write the same byte repeatedly.
    #[test]
    fn short_answers_still_fill_the_buffer() {
        let mut out = [0u8; 64];
        let mut next = 1u8;
        fill_from(
            |chunk| {
                chunk[0] = next;
                next = next.wrapping_add(1);
                1
            },
            &mut out,
        )
        .expect("short");
        let want: [u8; 64] = core::array::from_fn(|i| i as u8 + 1);
        assert_eq!(out, want);
    }

    /// An interrupted call wrote nothing, so the next one must start
    /// from the same place rather than skipping it.
    #[test]
    fn an_interrupted_call_is_retried() {
        let mut left = 2;
        let mut out = [0u8; 8];
        fill_from(
            |chunk| {
                if left > 0 {
                    left -= 1;
                    return EINTR;
                }
                chunk.fill(0xff);
                chunk.len() as isize
            },
            &mut out,
        )
        .expect("interrupted");
        assert_eq!(left, 0, "the failures were not all seen");
        assert_eq!(out, [0xff; 8]);
    }

    /// A kernel error is reported with its number, not swallowed.
    #[test]
    fn a_refusal_is_reported() {
        let mut out = [0u8; 8];
        assert_eq!(
            fill_from(|_| -38, &mut out).unwrap_err(),
            Error::EntropyUnavailable(38)
        );
    }

    /// The one return that could hang: no progress, no error. It has
    /// to end the loop rather than go round again.
    #[test]
    fn no_progress_is_an_error_rather_than_a_hang() {
        let mut out = [0u8; 8];
        assert_eq!(
            fill_from(|_| 0, &mut out).unwrap_err(),
            Error::EntropyUnavailable(0)
        );
        // Likewise a return no kernel would make.
        assert_eq!(
            fill_from(|_| isize::MIN, &mut out).unwrap_err(),
            Error::EntropyUnavailable(0)
        );
    }
}
