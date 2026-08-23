//! Asking each operating system for random bytes.
//!
//! Exactly one of the modules below is compiled, and each offers the
//! same `fill`, so the code above it needs no conditionals at all.
//!
//! # Why not one system call everywhere
//!
//! Linux promises its system call numbers never change, so the call
//! there is made directly. That keeps working with no C library at
//! all, which matters for a static binary.
//!
//! No other system makes that promise. Apple's numbers move between
//! releases and going straight to them breaks on upgrade; OpenBSD
//! renumbers on purpose; Windows has no stable system call interface
//! whatsoever. On all of those the stable thing to call is a C
//! function, so that is what gets called. Naming a function the
//! platform already provides costs no dependency: it is a symbol the
//! linker resolves against a library every binary there already
//! loads.

mod bare;

/// Linux, on the architectures whose system call numbers are written
/// out here. Others fall through to `none` until someone adds them.
#[cfg(all(
    target_os = "linux",
    any(
        target_arch = "aarch64",
        target_arch = "riscv64",
        target_arch = "x86_64"
    )
))]
#[path = "linux.rs"]
mod platform;

/// Everything with the `getentropy` function: Apple's systems, the
/// BSDs, and the Solaris family.
#[cfg(any(
    target_os = "dragonfly",
    target_os = "freebsd",
    target_os = "illumos",
    target_os = "ios",
    target_os = "macos",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "solaris"
))]
#[path = "getentropy.rs"]
mod platform;

#[cfg(target_os = "windows")]
#[path = "windows.rs"]
mod platform;

/// Anything left over: bare metal, where the processor is asked
/// directly because there is nobody else to ask.
///
/// Compiled everywhere, not only where it is used, so that its tests
/// run on an ordinary machine. Code that only ever builds for bare
/// metal is code nobody ever runs until it matters.
#[cfg(not(any(
    all(
        target_os = "linux",
        any(
            target_arch = "aarch64",
            target_arch = "riscv64",
            target_arch = "x86_64"
        )
    ),
    target_os = "dragonfly",
    target_os = "freebsd",
    target_os = "illumos",
    target_os = "ios",
    target_os = "macos",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "solaris",
    target_os = "windows"
)))]
use self::bare as platform;

pub(super) use platform::fill;

/// Only the tests need to know, so that the ones asking for real
/// randomness can stand aside where there is none to be had.
#[cfg(test)]
pub(super) use platform::AVAILABLE;
