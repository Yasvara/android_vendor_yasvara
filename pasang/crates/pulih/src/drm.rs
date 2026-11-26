// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: Apache-2.0

//! Triple-buffered non-blocking atomic DRM/KMS backend for `Pulih`
//! (`SPEC-0051` §5.3).
//!
//! - On Android (`target_os = "android"`), links directly to `libpulih_drm_shim`
//!   (`QTI SDE` + generic atomic KMS, 3 dumb buffers, live 120/90/60 Hz switching).
//! - Falls back cleanly to a headless framebuffer if DRM fails to open or on
//!   desktop host tests — NEVER crashes recovery, keeping `adbd` root 100% live!

use pulih_gfx::Surface;
use std::ffi::c_void;

/// Number of dumb buffers in the triple-buffered swapchain.
pub const SWAPCHAIN_BUFFERS: usize = 3;

#[cfg(target_os = "android")]
#[repr(C)]
#[derive(Clone, Copy, Debug)]
struct PulihDrmInfo {
    handle: *mut c_void,
    fd: i32,
    width: u32,
    height: u32,
    stride_px: u32,
    refresh_hz: u32,
    num_lms: u32,
}

#[cfg(target_os = "android")]
extern "C" {
    fn pulih_drm_init(target_hz: u32, out: *mut PulihDrmInfo) -> i32;
    fn pulih_drm_backbuffer(handle: *mut c_void) -> *mut u32;
    fn pulih_drm_flip(handle: *mut c_void) -> i32;
    fn pulih_drm_set_refresh(handle: *mut c_void, target_hz: u32) -> i32;
    fn pulih_drm_blank(handle: *mut c_void, blank: i32) -> i32;
    fn pulih_drm_destroy(handle: *mut c_void);
    fn pulih_exec_fastbootd() -> i32;
}

/// Exec stock `/system/bin/fastbootd` (ultimate unbrick layer).
pub fn exec_fastbootd() -> i32 {
    #[cfg(target_os = "android")]
    unsafe {
        pulih_exec_fastbootd()
    }
    #[cfg(not(target_os = "android"))]
    {
        -1
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DrmBackendKind {
    QtiSdeAtomic,
    GenericKmsAtomic,
    HeadlessFallback,
}

/// Manages triple-buffered swapchain state, live refresh-rate switching, and
/// modeset discipline (`ALLOW_MODESET` once on init/refresh/unblank, 0 FPS idle).
pub struct DisplayEngine {
    pub kind: DrmBackendKind,
    pub width: u32,
    pub height: u32,
    pub stride_px: u32,
    pub refresh_hz: u32,
    pub modeset_done: bool,
    pub blanked: bool,
    pub current_buf: usize,
    pub flip_count: u64,
    pub surface: Surface,
    #[allow(dead_code)]
    drm_handle: *mut c_void,
}

impl DisplayEngine {
    /// Attempt hardware atomic DRM init on Android; fall back cleanly to headless
    /// `fallback_w × fallback_h` if DRM is absent so recovery never crashes.
    pub fn open_or_fallback(fallback_w: u32, fallback_h: u32, target_hz: u32) -> Self {
        #[cfg(target_os = "android")]
        {
            let mut info = PulihDrmInfo {
                handle: std::ptr::null_mut(),
                fd: -1,
                width: 0,
                height: 0,
                stride_px: 0,
                refresh_hz: 0,
                num_lms: 0,
            };
            let rc = unsafe { pulih_drm_init(target_hz, &mut info) };
            if rc == 0 && !info.handle.is_null() && info.width > 0 && info.height > 0 {
                return Self {
                    kind: if info.num_lms >= 1 {
                        DrmBackendKind::QtiSdeAtomic
                    } else {
                        DrmBackendKind::GenericKmsAtomic
                    },
                    width: info.width,
                    height: info.height,
                    stride_px: info.stride_px.max(info.width),
                    refresh_hz: info.refresh_hz.max(60),
                    modeset_done: false,
                    blanked: false,
                    current_buf: 0,
                    flip_count: 0,
                    surface: Surface::new(info.width, info.height),
                    drm_handle: info.handle,
                };
            }
        }
        let _ = target_hz;
        Self::new_headless(fallback_w, fallback_h, target_hz.max(60))
    }

    /// Initialize a headless/fallback display engine (always succeeds; zero crash risk).
    pub fn new_headless(width: u32, height: u32, refresh_hz: u32) -> Self {
        Self {
            kind: DrmBackendKind::HeadlessFallback,
            width,
            height,
            stride_px: width,
            refresh_hz,
            modeset_done: false,
            blanked: false,
            current_buf: 0,
            flip_count: 0,
            surface: Surface::new(width, height),
            drm_handle: std::ptr::null_mut(),
        }
    }

    /// Returns whether the next atomic commit requires `DRM_MODE_ATOMIC_ALLOW_MODESET`.
    pub fn next_commit_needs_modeset(&self) -> bool {
        !self.modeset_done
    }

    /// Switch live panel refresh rate (e.g. `120 Hz` <-> `60 Hz` for Powersave).
    pub fn set_refresh_hz(&mut self, hz: u32) {
        if hz == self.refresh_hz {
            return;
        }
        #[cfg(target_os = "android")]
        if !self.drm_handle.is_null() {
            let actual = unsafe { pulih_drm_set_refresh(self.drm_handle, hz) };
            if actual > 0 {
                self.refresh_hz = actual as u32;
                self.modeset_done = false;
                return;
            }
        }
        self.refresh_hz = hz;
        self.modeset_done = false;
    }

    /// Copy dirty frame into the mapped DRM dumb buffer and submit a non-blocking
    /// atomic page flip. Does nothing when `surface.dirty` is empty (0 FPS idle!).
    pub fn present(&mut self) -> usize {
        if self.surface.dirty.is_empty() || self.blanked {
            return self.current_buf;
        }

        #[cfg(target_os = "android")]
        if !self.drm_handle.is_null() {
            unsafe {
                let dst = pulih_drm_backbuffer(self.drm_handle);
                if !dst.is_null() {
                    let w = self.width as usize;
                    let h = self.height as usize;
                    let dst_stride = self.stride_px as usize;
                    let src_stride = self.surface.stride_px as usize;
                    if dst_stride == src_stride {
                        std::ptr::copy_nonoverlapping(
                            self.surface.pixels.as_ptr(),
                            dst,
                            w * h,
                        );
                    } else {
                        for y in 0..h {
                            std::ptr::copy_nonoverlapping(
                                self.surface.pixels.as_ptr().add(y * src_stride),
                                dst.add(y * dst_stride),
                                w,
                            );
                        }
                    }
                    let _ = pulih_drm_flip(self.drm_handle);
                }
            }
        }

        self.modeset_done = true;
        let presented = self.current_buf;
        self.current_buf = (self.current_buf + 1) % SWAPCHAIN_BUFFERS;
        self.flip_count += 1;
        self.surface.clear_dirty();
        presented
    }

    /// Blank / unblank OLED screen (`ACTIVE=0/1`).
    pub fn set_blank(&mut self, blank: bool) {
        if self.blanked == blank {
            return;
        }
        #[cfg(target_os = "android")]
        if !self.drm_handle.is_null() {
            let _ = unsafe { pulih_drm_blank(self.drm_handle, if blank { 1 } else { 0 }) };
        }
        self.blanked = blank;
        if !blank {
            self.modeset_done = false;
        }
    }

    pub fn blank(&mut self) {
        self.set_blank(true);
    }
}

impl Drop for DisplayEngine {
    fn drop(&mut self) {
        #[cfg(target_os = "android")]
        if !self.drm_handle.is_null() {
            unsafe { pulih_drm_destroy(self.drm_handle) };
            self.drm_handle = std::ptr::null_mut();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pulih_gfx::Color;

    #[test]
    fn modeset_only_once_zero_flips_when_idle_and_refresh_switch() {
        let mut disp = DisplayEngine::new_headless(1280, 2772, 120);
        assert!(disp.next_commit_needs_modeset());

        // First frame needs modeset and increments flip_count
        disp.surface.clear(Color::BLACK);
        assert_eq!(disp.present(), 0);
        assert!(!disp.next_commit_needs_modeset());
        assert_eq!(disp.flip_count, 1);

        // Idle frame (no dirty rect): MUST NOT flip (0 FPS idle!)
        assert_eq!(disp.present(), 1);
        assert_eq!(disp.flip_count, 1);

        // Refresh rate switch (120 -> 60 Hz for Powersave) requests one modeset
        disp.set_refresh_hz(60);
        assert_eq!(disp.refresh_hz, 60);
        assert!(disp.next_commit_needs_modeset());

        // Second dirty frame advances ring buffer 1 -> 2 -> 0
        disp.surface.clear(Color::WHITE);
        assert_eq!(disp.present(), 1);
        disp.surface.clear(Color::BLACK);
        assert_eq!(disp.present(), 2);
        disp.surface.clear(Color::WHITE);
        assert_eq!(disp.present(), 0);
        assert_eq!(disp.flip_count, 4);

        // Blank suppresses flips; unblank requests single modeset again
        disp.set_blank(true);
        disp.surface.clear(Color::BLACK);
        assert_eq!(disp.present(), 1);
        assert_eq!(disp.flip_count, 4);
        disp.set_blank(false);
        assert!(disp.next_commit_needs_modeset());
    }
}
