//! Linux's `getrandom` system call, made directly.
//!
//! There is no crate for this here: the library has one dependency
//! and no build script, so the call is written out, as the RISC-V
//! feature probe in the `arch` module already does.
//!
//! Each architecture supplies the same single function, so the code
//! that uses it needs no conditionals. Where there is no such call
//! to make, the stand-in reports the same thing the kernel would.

#![allow(unsafe_code)]

/// The number this call goes by. Every architecture below takes it
/// from the generic table except x86-64, which has its own.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const NUMBER: usize = 318;
#[cfg(all(
    target_os = "linux",
    any(target_arch = "aarch64", target_arch = "riscv64")
))]
const NUMBER: usize = 278;

/// Asks the kernel to fill `out`, waiting if its generator is not
/// ready yet. Returns what the kernel returned: the count written,
/// or a negative error number.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub(super) fn getrandom(out: &mut [u8]) -> isize {
    let ret: isize;
    // SAFETY: the kernel writes at most `len` bytes at `ptr`, and the
    // two describe a slice held exclusively for the call. The write
    // is why this must not claim `nomem`.
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") NUMBER => ret,
            in("rdi") out.as_mut_ptr(),
            in("rsi") out.len(),
            // No flags: waiting beats handing back bytes that are not
            // yet unpredictable.
            in("rdx") 0usize,
            // The instruction takes these two for itself.
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    ret
}

/// Asks the kernel to fill `out`, waiting if its generator is not
/// ready yet. Returns what the kernel returned: the count written,
/// or a negative error number.
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
pub(super) fn getrandom(out: &mut [u8]) -> isize {
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

/// Asks the kernel to fill `out`, waiting if its generator is not
/// ready yet. Returns what the kernel returned: the count written,
/// or a negative error number.
#[cfg(all(target_os = "linux", target_arch = "riscv64"))]
pub(super) fn getrandom(out: &mut [u8]) -> isize {
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

/// Where there is no such call, report what a kernel without one
/// would: the function is not implemented.
///
/// Unlike the other stand-ins in this library this one is really
/// reached, so it returns a value rather than giving up. Inventing
/// randomness from the clock or the process number would be worse
/// than refusing, because it would look as though it had worked.
#[cfg(not(all(
    target_os = "linux",
    any(
        target_arch = "aarch64",
        target_arch = "riscv64",
        target_arch = "x86_64"
    )
)))]
pub(super) fn getrandom(_out: &mut [u8]) -> isize {
    -38
}
