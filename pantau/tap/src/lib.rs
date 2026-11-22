// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: Apache-2.0

//! `#![no_std]` wait-free SPSC telemetry tap linked directly into framework processes
//! (`SurfaceFlinger`, `InputFlinger`, `libhwui`, `RenderEngine`, `framefx`).
//!
//! Design guarantees:
//! - Zero `std`, zero heap allocation, zero mutexes, zero syscalls on the hot path.
//! - When disarmed (`MODE_OFF == 0`), [`TapChannel::matches`] is a single relaxed atomic load.
//! - Multi-UID & `MODE_ALL` filtering without extra indirection on the common single-UID path.
//! - Epoch-guarded disarm ensures `munmap` can never race with an in-flight producer write.

#![cfg_attr(not(test), no_std)]

pub mod ffi;
pub mod wire;

use core::marker::PhantomData;
use core::mem::size_of;
use core::ptr::{self, NonNull};
use core::sync::atomic::{AtomicPtr, AtomicU32, Ordering};

use wire::{RingHeader, RingKind, RING_MAGIC, RING_VERSION};

/// Tap disabled (fast-path single load == 0).
pub const MODE_OFF: u32 = 0;
/// Capture every UID (system-wide transitions, SystemUI + Launcher + app).
pub const MODE_ALL: u32 = u32::MAX;
/// Match against the 4-slot inline UID table.
pub const MODE_MULTI: u32 = u32::MAX - 1;
/// Maximum UIDs in inline multi-UID mode.
pub const MAX_MULTI_UIDS: usize = 4;

/// Standalone panic handler used ONLY when linked into C++ binaries with `no_stdlibs: true`.
#[cfg(all(feature = "standalone", not(test)))]
#[panic_handler]
fn panic_abort(_info: &core::panic::PanicInfo<'_>) -> ! {
    extern "C" {
        fn abort() -> !;
    }
    // SAFETY: libc `abort()` terminates immediately with no unwinding.
    unsafe { abort() }
}

/// Initializes a freshly zeroed mapped region as an empty SPSC ring for element type `T`.
///
/// # Safety
/// `base` must be 64-byte aligned and writable for at least `wire::ring_byte_size::<T>(cap)` bytes.
pub unsafe fn init_ring<T>(base: *mut u8, byte_len: usize, kind: RingKind, cap: u32) -> bool {
    if base.is_null() || (base as usize) & 63 != 0 {
        return false;
    }
    let Some(needed) = wire::ring_byte_size::<T>(cap) else {
        return false;
    };
    if byte_len < needed {
        return false;
    }
    // SAFETY: alignment and byte_len checked above.
    let hdr = unsafe { &mut *(base as *mut RingHeader) };
    hdr.version = RING_VERSION;
    hdr.kind = kind as u16;
    hdr.cap = cap;
    hdr.mask = cap - 1;
    hdr.tail.store(0, Ordering::Relaxed);
    hdr.drops.store(0, Ordering::Relaxed);
    hdr.elem_size = size_of::<T>() as u32;
    hdr._pad0 = [0; 36];
    hdr.head.store(0, Ordering::Relaxed);
    hdr.flags.store(0, Ordering::Relaxed);
    hdr._pad1 = [0; 56];
    // Publish magic last with a release fence so concurrent mappers never see half-initialized state.
    core::sync::atomic::fence(Ordering::Release);
    hdr.magic = RING_MAGIC;
    true
}

/// Validates an existing mapped ring header before arming or consuming.
///
/// # Safety
/// `base` must be readable for at least `size_of::<RingHeader>()` bytes (and `byte_len` total).
pub unsafe fn validate_ring<T>(base: *const u8, byte_len: usize, expected_kind: RingKind) -> bool {
    if base.is_null() || (base as usize) & 63 != 0 || byte_len < size_of::<RingHeader>() {
        return false;
    }
    // SAFETY: bounds & alignment validated above.
    let hdr = unsafe { &*(base as *const RingHeader) };
    if hdr.magic != RING_MAGIC
        || hdr.version != RING_VERSION
        || hdr.kind != expected_kind as u16
        || hdr.elem_size != size_of::<T>() as u32
    {
        return false;
    }
    let cap = hdr.cap;
    if cap == 0 || (cap & (cap - 1)) != 0 || hdr.mask != cap - 1 {
        return false;
    }
    matches!(wire::ring_byte_size::<T>(cap), Some(needed) if byte_len >= needed)
}

/// Producer-side lock-free SPSC tap channel with epoch-guarded safe disarm.
#[repr(C, align(64))]
pub struct TapChannel<T: Copy> {
    /// Hot-path atomic filter (`0 = OFF`, `MODE_ALL`, `MODE_MULTI`, or exact single `uid`).
    pub mode: AtomicU32,
    /// Number of producers currently inside `push_slow` (prevents use-after-unmap on disarm).
    active_writers: AtomicU32,
    /// Optional 4-UID inline filter used only when `mode == MODE_MULTI`.
    multi_uids: [AtomicU32; MAX_MULTI_UIDS],
    /// Mapped ring base pointer (64-byte aligned `RingHeader` followed by `[T; cap]`).
    ring: AtomicPtr<u8>,
    _marker: PhantomData<T>,
}

impl<T: Copy> TapChannel<T> {
    pub const fn new() -> Self {
        Self {
            mode: AtomicU32::new(MODE_OFF),
            active_writers: AtomicU32::new(0),
            multi_uids: [
                AtomicU32::new(0),
                AtomicU32::new(0),
                AtomicU32::new(0),
                AtomicU32::new(0),
            ],
            ring: AtomicPtr::new(ptr::null_mut()),
            _marker: PhantomData,
        }
    }

    /// Single-atomic hot-path check. When disarmed, executes one relaxed load (`== 0`).
    #[inline(always)]
    pub fn matches(&self, uid: u32) -> bool {
        let m = self.mode.load(Ordering::Relaxed);
        if m == MODE_OFF {
            return false;
        }
        if m == uid || m == MODE_ALL {
            return true;
        }
        if m == MODE_MULTI {
            return self.matches_multi(uid);
        }
        false
    }

    #[cold]
    #[inline(never)]
    fn matches_multi(&self, uid: u32) -> bool {
        let mut i = 0;
        while i < MAX_MULTI_UIDS {
            let entry = self.multi_uids[i].load(Ordering::Relaxed);
            if entry != 0 && entry == uid {
                return true;
            }
            i += 1;
        }
        false
    }

    /// Arms the channel against an already-validated ring mapping.
    ///
    /// # Safety
    /// `ring_base` must point to a valid mapped ring of `expected_kind` initialized with
    /// [`init_ring`] and remain mapped until [`Self::disarm`] returns it.
    pub unsafe fn arm(
        &self,
        ring_base: *mut u8,
        byte_len: usize,
        expected_kind: RingKind,
        mode: u32,
        extra_uids: &[u32],
    ) -> bool {
        // SAFETY: caller guarantees `ring_base` is readable for `byte_len`.
        if !unsafe { validate_ring::<T>(ring_base, byte_len, expected_kind) } {
            return false;
        }
        if mode == MODE_OFF {
            return false;
        }
        // Always disarm cleanly before replacing a ring.
        self.mode.store(MODE_OFF, Ordering::Release);
        while self.active_writers.load(Ordering::Acquire) != 0 {
            core::hint::spin_loop();
        }
        if mode == MODE_MULTI {
            let mut i = 0;
            while i < MAX_MULTI_UIDS {
                let v = if i < extra_uids.len() { extra_uids[i] } else { 0 };
                self.multi_uids[i].store(v, Ordering::Relaxed);
                i += 1;
            }
        }
        self.ring.store(ring_base, Ordering::Release);
        self.mode.store(mode, Ordering::Release);
        true
    }

    /// Disarms the channel and waits for any in-flight writer to exit before returning the
    /// previously mapped pointer for `munmap`.
    pub fn disarm(&self) -> *mut u8 {
        self.mode.store(MODE_OFF, Ordering::Release);
        let old = self.ring.swap(ptr::null_mut(), Ordering::AcqRel);
        while self.active_writers.load(Ordering::Acquire) != 0 {
            core::hint::spin_loop();
        }
        old
    }

    /// Hot-path push: returns immediately on one relaxed load when disarmed or filtered out.
    #[inline(always)]
    pub fn push(&self, uid: u32, rec: &T) -> bool {
        if !self.matches(uid) {
            return false;
        }
        self.push_slow(rec)
    }

    /// Out-of-line wait-free SPSC write (kept out of producer I-cache when disarmed).
    #[cold]
    #[inline(never)]
    pub fn push_slow(&self, rec: &T) -> bool {
        // Pin epoch BEFORE loading ring pointer so `disarm()` cannot unmap underneath us.
        self.active_writers.fetch_add(1, Ordering::AcqRel);
        let base = self.ring.load(Ordering::Acquire);
        if base.is_null() {
            self.active_writers.fetch_sub(1, Ordering::Release);
            return false;
        }
        // SAFETY: `base` was validated on `arm()` and cannot be unmapped while `active_writers > 0`.
        let written = unsafe {
            let hdr = &*(base as *const RingHeader);
            let tail = hdr.tail.load(Ordering::Relaxed);
            let head = hdr.head.load(Ordering::Acquire);
            if tail.wrapping_sub(head) >= hdr.cap {
                hdr.drops.fetch_add(1, Ordering::Relaxed);
                false
            } else {
                let slot = (tail & hdr.mask) as usize;
                let slots_ptr = base.add(size_of::<RingHeader>()) as *mut T;
                ptr::write(slots_ptr.add(slot), *rec);
                hdr.tail.store(tail.wrapping_add(1), Ordering::Release);
                true
            }
        };
        self.active_writers.fetch_sub(1, Ordering::Release);
        written
    }
}

/// Consumer-side lock-free batch drainer used by `pantaud`.
pub struct RingConsumer<T: Copy> {
    base: NonNull<u8>,
    _marker: PhantomData<T>,
}

// SAFETY: SPSC consumer is owned by one thread (`pantaud`'s reactor thread).
unsafe impl<T: Copy> Send for RingConsumer<T> {}

impl<T: Copy> RingConsumer<T> {
    /// Attaches a consumer to an existing validated ring mapping.
    ///
    /// # Safety
    /// `base` must remain mapped for the lifetime of `RingConsumer`.
    pub unsafe fn attach(base: *mut u8, byte_len: usize, expected_kind: RingKind) -> Option<Self> {
        // SAFETY: caller guarantees readability for `byte_len`.
        if !unsafe { validate_ring::<T>(base, byte_len, expected_kind) } {
            return None;
        }
        NonNull::new(base).map(|nn| Self {
            base: nn,
            _marker: PhantomData,
        })
    }

    #[inline]
    fn header(&self) -> &RingHeader {
        // SAFETY: validated on attach.
        unsafe { &*(self.base.as_ptr() as *const RingHeader) }
    }

    /// Number of overflow drops observed by the producer since ring init.
    #[inline]
    pub fn drops(&self) -> u32 {
        self.header().drops.load(Ordering::Relaxed)
    }

    /// Drains up to `max_items` available records in one batch, updating `head` only once at end.
    pub fn drain_up_to<F: FnMut(&T)>(&mut self, max_items: usize, mut f: F) -> usize {
        let hdr = self.header();
        let head = hdr.head.load(Ordering::Relaxed);
        let tail = hdr.tail.load(Ordering::Acquire);
        let avail = tail.wrapping_sub(head) as usize;
        let cap = hdr.cap as usize;
        // Guard against corrupt shared memory reporting avail > cap.
        let count = avail.min(cap).min(max_items);
        if count == 0 {
            return 0;
        }
        let mask = hdr.mask as usize;
        // SAFETY: ring slots lie immediately after RingHeader for `cap` elements of `T`.
        let slots = unsafe { self.base.as_ptr().add(size_of::<RingHeader>()) as *const T };
        let mut i = 0;
        while i < count {
            let idx = (head as usize).wrapping_add(i) & mask;
            // SAFETY: producer published these slots with Release before advancing `tail`.
            let item = unsafe { &*slots.add(idx) };
            f(item);
            i += 1;
        }
        hdr.head
            .store(head.wrapping_add(count as u32), Ordering::Release);
        count
    }

    /// Drains all currently published records.
    #[inline]
    pub fn drain<F: FnMut(&T)>(&mut self, f: F) -> usize {
        self.drain_up_to(usize::MAX, f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wire::{FrameRec, InputRec, UiFrameRec};

    #[repr(align(64))]
    struct AlignedBuf<const N: usize>([u8; N]);

    #[test]
    fn ring_init_push_wrap_and_drop() {
        const CAP: u32 = 8;
        const BYTES: usize = 128 + 8 * 64;
        let mut mem = AlignedBuf([0u8; BYTES]);
        assert!(unsafe { init_ring::<FrameRec>(mem.0.as_mut_ptr(), BYTES, RingKind::Frame, CAP) });

        let ch = TapChannel::<FrameRec>::new();
        assert!(!ch.matches(10042));
        assert!(unsafe {
            ch.arm(
                mem.0.as_mut_ptr(),
                BYTES,
                RingKind::Frame,
                10042,
                &[],
            )
        });
        assert!(ch.matches(10042));
        assert!(!ch.matches(10043));

        // Fill all 8 slots + 3 overflows.
        for i in 0..11u32 {
            let mut rec = FrameRec::default();
            rec.present_ns = i as i64 * 8_333_000;
            rec.uid = 10042;
            let ok = ch.push(10042, &rec);
            assert_eq!(ok, i < CAP);
        }

        let mut cons =
            unsafe { RingConsumer::<FrameRec>::attach(mem.0.as_mut_ptr(), BYTES, RingKind::Frame) }
                .expect("attach");
        assert_eq!(cons.drops(), 3);

        let mut seen = [0i64; 8];
        let mut n = 0;
        let drained = cons.drain(|r| {
            seen[n] = r.present_ns;
            n += 1;
        });
        assert_eq!(drained, 8);
        for i in 0..8 {
            assert_eq!(seen[i], i as i64 * 8_333_000);
        }

        // Push across wrap boundary.
        for i in 100..105i64 {
            let mut rec = FrameRec::default();
            rec.present_ns = i;
            assert!(ch.push(10042, &rec));
        }
        let mut sum = 0i64;
        assert_eq!(cons.drain(|r| sum += r.present_ns), 5);
        assert_eq!(sum, 100 + 101 + 102 + 103 + 104);

        let old = ch.disarm();
        assert_eq!(old, mem.0.as_mut_ptr());
        assert!(!ch.matches(10042));
    }

    #[test]
    fn multi_uid_and_all_filter() {
        const BYTES: usize = 128 + 4 * 32;
        let mut mem = AlignedBuf([0u8; BYTES]);
        assert!(unsafe { init_ring::<InputRec>(mem.0.as_mut_ptr(), BYTES, RingKind::Input, 4) });
        let ch = TapChannel::<InputRec>::new();

        assert!(unsafe {
            ch.arm(
                mem.0.as_mut_ptr(),
                BYTES,
                RingKind::Input,
                MODE_MULTI,
                &[1000, 10128, 10250],
            )
        });
        assert!(ch.matches(1000));
        assert!(ch.matches(10128));
        assert!(ch.matches(10250));
        assert!(!ch.matches(10999));

        assert!(unsafe {
            ch.arm(mem.0.as_mut_ptr(), BYTES, RingKind::Input, MODE_ALL, &[])
        });
        assert!(ch.matches(10999));
        ch.disarm();
    }

    #[test]
    fn rejects_corrupt_or_truncated_ring() {
        let mut mem = AlignedBuf([0u8; 64]);
        assert!(!unsafe { init_ring::<UiFrameRec>(mem.0.as_mut_ptr(), 64, RingKind::UiFrame, 4) });
        assert!(!unsafe {
            validate_ring::<UiFrameRec>(mem.0.as_ptr(), 64, RingKind::UiFrame)
        });
        assert!(!unsafe {
            init_ring::<UiFrameRec>(mem.0.as_mut_ptr(), 64, RingKind::UiFrame, 3) // non-pow2
        });
    }

    #[test]
    fn concurrent_push_drain_and_disarm_stress() {
        extern crate std;
        use std::sync::Arc;
        use std::thread;

        const CAP: u32 = 256;
        const BYTES: usize = 128 + 256 * 64;
        let mut mem = std::boxed::Box::new(AlignedBuf([0u8; BYTES]));
        let ptr = mem.0.as_mut_ptr();
        assert!(unsafe { init_ring::<FrameRec>(ptr, BYTES, RingKind::Frame, CAP) });

        let ch = Arc::new(TapChannel::<FrameRec>::new());
        assert!(unsafe { ch.arm(ptr, BYTES, RingKind::Frame, MODE_ALL, &[]) });

        let ch_prod = Arc::clone(&ch);
        let prod = thread::spawn(move || {
            let mut pushed = 0usize;
            for i in 0..50_000i64 {
                let mut r = FrameRec::default();
                r.present_ns = i;
                if ch_prod.push(10042, &r) {
                    pushed += 1;
                }
            }
            pushed
        });

        let mut cons =
            unsafe { RingConsumer::<FrameRec>::attach(ptr, BYTES, RingKind::Frame) }.unwrap();
        let mut drained = 0usize;
        let mut last = -1i64;
        for _ in 0..5_000 {
            drained += cons.drain(|r| {
                assert!(r.present_ns > last, "out-of-order ring item");
                last = r.present_ns;
            });
            thread::yield_now();
        }
        let pushed = prod.join().unwrap();
        drained += cons.drain(|r| {
            assert!(r.present_ns > last);
            last = r.present_ns;
        });
        assert_eq!(drained, pushed);
        assert_eq!(ch.disarm(), ptr);
    }
}
