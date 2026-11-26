// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: Apache-2.0

//! Linux `/dev/input/event*` `O_NONBLOCK` + `poll(2)` evdev reader with
//! per-device `EVIOCGABS` calibration (via Android's real `<linux/input.h>` in
//! `libpulih_drm_shim`) and automatic 1-second hotplug rescan for late-arriving
//! `NVTCapacitiveTouchScreen` (`touch_report_debug`).

use crate::input::{InputEvent, InputState};
#[cfg(target_os = "android")]
use std::ffi::c_void;
use std::time::{Duration, Instant};

#[cfg(target_os = "android")]
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct PulihRawEvent {
    type_: u16,
    code: u16,
    value: i32,
    min_x: i32,
    max_x: i32,
    min_y: i32,
    max_y: i32,
    has_abs: u8,
}

#[cfg(target_os = "android")]
extern "C" {
    fn pulih_input_open() -> *mut c_void;
    fn pulih_input_rescan(handle: *mut c_void) -> i32;
    fn pulih_input_count(handle: *mut c_void, out_x: *mut i32, out_y: *mut i32) -> i32;
    fn pulih_input_poll(
        handle: *mut c_void,
        timeout_ms: i32,
        out_buf: *mut PulihRawEvent,
        max_events: i32,
    ) -> i32;
    fn pulih_input_close(handle: *mut c_void);
}

pub struct EvdevPoller {
    #[cfg(target_os = "android")]
    handle: *mut c_void,
    last_scan: Instant,
    pub state: InputState,
    pub last_touch: Option<(i32, i32)>,
}

impl EvdevPoller {
    pub fn open_all(screen_w: i32, screen_h: i32) -> Self {
        #[cfg(target_os = "android")]
        let handle = unsafe { pulih_input_open() };
        Self {
            #[cfg(target_os = "android")]
            handle,
            last_scan: Instant::now(),
            state: InputState::new(screen_w, screen_h, screen_w - 1, screen_h - 1),
            last_touch: None,
        }
    }

    pub fn rescan_if_needed(&mut self) {
        if self.last_scan.elapsed() >= Duration::from_secs(1) {
            self.last_scan = Instant::now();
            #[cfg(target_os = "android")]
            if !self.handle.is_null() {
                unsafe { pulih_input_rescan(self.handle) };
            }
        }
    }

    /// Returns `(device_count, touch_max_x, touch_max_y)` for live diagnostics.
    pub fn diagnostics(&self) -> (usize, i32, i32) {
        #[cfg(target_os = "android")]
        if !self.handle.is_null() {
            let mut mx = 0i32;
            let mut my = 0i32;
            let cnt = unsafe { pulih_input_count(self.handle, &mut mx, &mut my) };
            return (cnt.max(0) as usize, mx, my);
        }
        (0, 0, 0)
    }

    pub fn poll_events(&mut self, timeout_ms: i32) -> Vec<InputEvent> {
        self.rescan_if_needed();
        #[cfg(target_os = "android")]
        {
            if self.handle.is_null() {
                std::thread::sleep(Duration::from_millis(timeout_ms.clamp(10, 250) as u64));
                return Vec::new();
            }
            let mut raw = [PulihRawEvent::default(); 64];
            let n = unsafe { pulih_input_poll(self.handle, timeout_ms, raw.as_mut_ptr(), 64) };
            let mut out = Vec::new();
            for ev in raw.iter().take(n.max(0) as usize) {
                // Apply the EXACT per-fd EVIOCGABS range of the device that generated this event!
                if ev.has_abs != 0 && ev.max_x > ev.min_x && ev.max_y > ev.min_y {
                    self.state
                        .update_abs_range(ev.min_x, ev.max_x, ev.min_y, ev.max_y);
                }
                if let Some(mapped) = self.state.feed(ev.type_, ev.code, ev.value) {
                    match mapped {
                        InputEvent::TouchDown { x, y }
                        | InputEvent::TouchMove { x, y }
                        | InputEvent::TouchUp { x, y } => {
                            self.last_touch = Some((x, y));
                        }
                        _ => {}
                    }
                    out.push(mapped);
                }
            }
            out
        }
        #[cfg(not(target_os = "android"))]
        {
            if timeout_ms > 0 {
                std::thread::sleep(Duration::from_millis(timeout_ms.min(250) as u64));
            }
            Vec::new()
        }
    }
}

#[cfg(target_os = "android")]
impl Drop for EvdevPoller {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            unsafe { pulih_input_close(self.handle) };
            self.handle = std::ptr::null_mut();
        }
    }
}
