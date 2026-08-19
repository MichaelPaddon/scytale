//! Core cycle counting through `perf_event_open`.
//!
//! Wall time is the wrong instrument for this comparison. The core clock
//! moves under `powersave` and turbo, so a stopwatch measures the governor
//! as much as the code; a cycle count does not move when the clock does.
//! Kernel and interrupt cycles are excluded, which removes the other
//! large source of run to run movement.
//!
//! The counter is read through `rdpmc` on the page the kernel maps for
//! that purpose, which costs tens of cycles rather than the microsecond a
//! `read` syscall would. That is what makes short measurement windows
//! affordable, and short windows are what keep a sample free of
//! interference.

#![cfg(target_os = "linux")]

use std::os::raw::c_int;
use std::sync::atomic::{Ordering, compiler_fence};

/// `PERF_TYPE_HARDWARE`.
const TYPE_HARDWARE: u32 = 0;
/// `PERF_COUNT_HW_CPU_CYCLES`.
const COUNT_HW_CPU_CYCLES: u64 = 0;
/// `exclude_kernel` and `exclude_hv`, bits 5 and 6 of the flag word.
const EXCLUDE_KERNEL_HV: u64 = (1 << 5) | (1 << 6);
/// `cap_user_rdpmc`, bit 2 of the capability word.
const CAP_USER_RDPMC: u64 = 1 << 2;

/// The subset of `perf_event_attr` this needs.
///
/// The kernel reads `size` and treats anything it does not know about as
/// zero, so a struct that stops at the fields in use is a valid one.
#[repr(C)]
#[derive(Default)]
struct EventAttr {
    kind: u32,
    size: u32,
    config: u64,
    sample_period: u64,
    sample_type: u64,
    read_format: u64,
    flags: u64,
    wakeup_events: u32,
    bp_type: u32,
    config1: u64,
    config2: u64,
}

/// The head of the page the kernel maps for a counter.
///
/// Only the fields up to `pmc_width` are named, which are the ones the
/// `rdpmc` protocol needs.
#[repr(C)]
struct MmapPage {
    version: u32,
    compat_version: u32,
    lock: u32,
    index: u32,
    offset: i64,
    time_enabled: u64,
    time_running: u64,
    capabilities: u64,
    pmc_width: u16,
    time_shift: u16,
    time_mult: u32,
    time_offset: u64,
}

/// A running count of core cycles for this thread.
pub struct Cycles {
    fd: c_int,
    page: *const MmapPage,
    page_len: usize,
}

impl Cycles {
    /// Open a cycle counter for the calling process.
    ///
    /// Returns `None` when the kernel refuses, which is the ordinary
    /// answer under a restrictive `perf_event_paranoid` or in a container
    /// without the capability. The caller is expected to fall back to a
    /// clock and say so.
    pub fn try_new() -> Option<Self> {
        // A hybrid CPU has one PMU per core type, and an event opened on
        // the wrong one is accepted and then never counts anything. Which
        // is which depends on the core this is pinned to, so each is
        // opened and then asked to prove it counts.
        for kind in pmu_types() {
            if let Some(counter) = Self::open(kind)
                && counter.counts()
            {
                return Some(counter);
            }
        }
        None
    }

    /// Open a cycle counter on one PMU.
    fn open(kind: u32) -> Option<Self> {
        let mut attr = EventAttr {
            kind,
            size: size_of::<EventAttr>() as u32,
            config: COUNT_HW_CPU_CYCLES,
            flags: EXCLUDE_KERNEL_HV,
            ..Default::default()
        };

        // SAFETY: attr is a correctly sized perf_event_attr; pid 0 and cpu
        // -1 ask for this process on whatever core it runs on.
        let fd = unsafe {
            libc::syscall(
                libc::SYS_perf_event_open,
                &raw mut attr,
                0,
                -1,
                -1,
                0,
            )
        };
        if fd < 0 {
            return None;
        }
        let fd = fd as c_int;

        // A single page maps the metadata the rdpmc protocol reads. No
        // ring buffer is asked for, because no samples are collected.
        let page_len = page_size();
        // SAFETY: fd is a live perf event and the length is one page,
        // which is the mapping the kernel provides for metadata alone.
        let page = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                page_len,
                libc::PROT_READ,
                libc::MAP_SHARED,
                fd,
                0,
            )
        };
        if page == libc::MAP_FAILED {
            // SAFETY: fd is open and owned here.
            unsafe { libc::close(fd) };
            return None;
        }

        Some(Self { fd, page: page.cast(), page_len })
    }

    /// Whether this counter actually advances while work is done.
    fn counts(&self) -> bool {
        let Some(before) = self.read() else {
            return false;
        };
        let mut x = 0u64;
        for i in 0..10_000u64 {
            x = x.wrapping_add(i).rotate_left(7);
        }
        std::hint::black_box(x);
        self.read().is_some_and(|after| after > before)
    }

    /// Whether counts come from `rdpmc` rather than the `read` syscall.
    pub fn is_direct(&self) -> bool {
        // SAFETY: the page is mapped for the lifetime of self.
        let page = unsafe { &*self.page };
        page.capabilities & CAP_USER_RDPMC != 0 && page.index != 0
    }

    /// The current count, or `None` if the counter could not be read.
    #[inline]
    pub fn read(&self) -> Option<u64> {
        // SAFETY: the page is mapped for the lifetime of self and is only
        // ever read.
        let page = unsafe { &*self.page };

        loop {
            // The kernel bumps lock around any update to index and
            // offset, so a value read between two equal, even lock
            // values was taken from a consistent page.
            let seq = volatile(&page.lock);
            compiler_fence(Ordering::SeqCst);

            let index = volatile(&page.index);
            let offset = volatile_i64(&page.offset);
            let width = volatile_u16(&page.pmc_width);
            let caps = volatile_u64(&page.capabilities);

            if caps & CAP_USER_RDPMC == 0 || index == 0 {
                return self.read_syscall();
            }

            // SAFETY: the kernel published this index for this thread.
            let raw = unsafe { rdpmc(index - 1) };
            // The counter is narrower than 64 bits and wraps, so the
            // reading is sign extended before the kernel's offset is
            // applied. Otherwise a wrap reads as an enormous jump.
            let shift = 64 - u32::from(width);
            let signed = ((raw << shift) as i64) >> shift;
            let count = offset.wrapping_add(signed) as u64;

            compiler_fence(Ordering::SeqCst);
            if volatile(&page.lock) == seq {
                return Some(count);
            }
        }
    }

    /// Read the counter the slow way, for kernels without `rdpmc`.
    fn read_syscall(&self) -> Option<u64> {
        let mut buf = [0u8; 8];
        // SAFETY: fd is a live perf event and buf is eight bytes, the
        // size of one counter value in the default read format.
        let n = unsafe {
            libc::read(self.fd, buf.as_mut_ptr().cast(), buf.len())
        };
        if n == buf.len() as isize {
            Some(u64::from_ne_bytes(buf))
        } else {
            None
        }
    }
}

impl Drop for Cycles {
    fn drop(&mut self) {
        // SAFETY: both were obtained in try_new and are owned here.
        unsafe {
            libc::munmap(self.page as *mut _, self.page_len);
            libc::close(self.fd);
        }
    }
}

/// Read one performance counter by its index.
///
/// # Safety
///
/// `index` must be one the kernel published for this thread.
#[inline]
unsafe fn rdpmc(index: u32) -> u64 {
    let low: u32;
    let high: u32;
    // SAFETY: rdpmc is enabled for user space by the kernel that
    // published the index. It writes only the two named registers.
    unsafe {
        std::arch::asm!(
            "rdpmc",
            in("ecx") index,
            out("eax") low,
            out("edx") high,
            options(nostack, nomem),
        );
    }
    (u64::from(high) << 32) | u64::from(low)
}

/// The PMU types to try, most likely first.
///
/// A hybrid Intel CPU exposes `cpu_core` and `cpu_atom` separately, and
/// the generic type reaches only one of them. Anything else has a single
/// PMU, where the generic type is the whole answer.
fn pmu_types() -> Vec<u32> {
    let mut types: Vec<u32> = ["cpu_core", "cpu_atom"]
        .iter()
        .filter_map(|name| {
            let path =
                format!("/sys/bus/event_source/devices/{name}/type");
            std::fs::read_to_string(path).ok()
        })
        .filter_map(|text| text.trim().parse().ok())
        .collect();
    types.push(TYPE_HARDWARE);
    types
}

fn page_size() -> usize {
    // SAFETY: sysconf with a valid name has no preconditions.
    let n = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if n > 0 { n as usize } else { 4096 }
}

// The kernel writes these fields from another context, so every read has
// to actually happen where it is written rather than be hoisted out of
// the sequence lock loop.
fn volatile(p: &u32) -> u32 {
    // SAFETY: p is a live reference into the mapped page.
    unsafe { std::ptr::read_volatile(p) }
}

fn volatile_u64(p: &u64) -> u64 {
    // SAFETY: as above.
    unsafe { std::ptr::read_volatile(p) }
}

fn volatile_i64(p: &i64) -> i64 {
    // SAFETY: as above.
    unsafe { std::ptr::read_volatile(p) }
}

fn volatile_u16(p: &u16) -> u16 {
    // SAFETY: as above.
    unsafe { std::ptr::read_volatile(p) }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The counter must move forwards, and by something like the work
    /// done rather than by an arbitrary amount.
    #[test]
    fn counts_cycles() {
        let Some(cycles) = Cycles::try_new() else {
            return;
        };
        let before = cycles.read().expect("counter reads");
        let mut x = 0u64;
        for i in 0..100_000u64 {
            x = x.wrapping_add(i).rotate_left(7);
        }
        std::hint::black_box(x);
        let after = cycles.read().expect("counter reads");

        let spent = after - before;
        assert!(spent > 10_000, "counted {spent} cycles for 100k rounds");
        assert!(spent < 100_000_000, "counted {spent} cycles, implausible");
    }

    /// Reading twice with nothing in between costs little. This is the
    /// overhead the harness subtracts, so it must be small and stable.
    #[test]
    fn read_overhead_is_small() {
        let Some(cycles) = Cycles::try_new() else {
            return;
        };
        if !cycles.is_direct() {
            return;
        }
        let mut best = u64::MAX;
        for _ in 0..1000 {
            let a = cycles.read().expect("counter reads");
            let b = cycles.read().expect("counter reads");
            best = best.min(b - a);
        }
        assert!(best < 1000, "a back to back read pair cost {best} cycles");
    }
}

