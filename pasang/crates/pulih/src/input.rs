// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: Apache-2.0

//! Linux `evdev` Multi-Touch Protocol B + Protocol A + Single-Touch + physical
//! Volume/Power key fallback + gesture recognizer + tactile haptics (`SPEC-0051` §5.4).
//!
//! Properly commits touch coordinates at `EV_SYN` (`SYN_REPORT`) so Protocol B
//! drivers (like `onyx`'s `NVTCapacitiveTouchScreen` which emits `ABS_MT_TRACKING_ID`
//! BEFORE `ABS_MT_POSITION_X/Y`) always report exact `(x, y)` on `TouchDown` & `TouchUp`.

pub const EV_SYN: u16 = 0x00;
pub const EV_KEY: u16 = 0x01;
pub const EV_ABS: u16 = 0x03;

pub const SYN_REPORT: u16 = 0x00;

pub const KEY_VOLUMEDOWN: u16 = 114;
pub const KEY_VOLUMEUP: u16 = 115;
pub const KEY_POWER: u16 = 116;
pub const BTN_TOUCH: u16 = 0x14a; // 330

pub const ABS_X: u16 = 0x00;
pub const ABS_Y: u16 = 0x01;
pub const ABS_MT_SLOT: u16 = 0x2f;
pub const ABS_MT_POSITION_X: u16 = 0x35;
pub const ABS_MT_POSITION_Y: u16 = 0x36;
pub const ABS_MT_TRACKING_ID: u16 = 0x39;

/// High-level UI input event emitted to `Pulih`'s main event loop.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InputEvent {
    TouchDown { x: i32, y: i32 },
    TouchMove { x: i32, y: i32 },
    TouchUp { x: i32, y: i32 },
    SwipeBack,
    PullDownQuickSettings,
    KeyFocusPrev, // Physical Volume Up -> Scroll Up / Brightness +
    KeyFocusNext, // Physical Volume Down -> Scroll Down / Brightness -
    KeySelect,    // Enter / Keyboard Select (never triggered by Power button!)
    PowerToggle,  // Physical Power button -> Screen Sleep / Wake toggle!
    ScreenshotCombo,
}

/// Maps raw `evdev` touch ranges (`EVIOCGABS`) to screen coordinates and
/// decodes Protocol A/B multi-touch gestures + physical button fallback.
#[derive(Clone, Debug)]
pub struct InputState {
    pub screen_w: i32,
    pub screen_h: i32,
    pub abs_min_x: i32,
    pub abs_max_x: i32,
    pub abs_min_y: i32,
    pub abs_max_y: i32,
    slot: i32,
    raw_x: i32,
    raw_y: i32,
    pos_dirty: bool,
    touching: bool,
    pending_down: bool,
    pending_up: bool,
    start_x: i32,
    start_y: i32,
    vol_down_held: bool,
    power_held: bool,
}

impl InputState {
    pub fn new(screen_w: i32, screen_h: i32, abs_max_x: i32, abs_max_y: i32) -> Self {
        Self::with_range(screen_w, screen_h, 0, abs_max_x, 0, abs_max_y)
    }

    pub fn with_range(
        screen_w: i32,
        screen_h: i32,
        abs_min_x: i32,
        abs_max_x: i32,
        abs_min_y: i32,
        abs_max_y: i32,
    ) -> Self {
        Self {
            screen_w: screen_w.max(1),
            screen_h: screen_h.max(1),
            abs_min_x,
            abs_max_x: abs_max_x.max(abs_min_x + 1),
            abs_min_y,
            abs_max_y: abs_max_y.max(abs_min_y + 1),
            slot: 0,
            raw_x: 0,
            raw_y: 0,
            pos_dirty: false,
            touching: false,
            pending_down: false,
            pending_up: false,
            start_x: 0,
            start_y: 0,
            vol_down_held: false,
            power_held: false,
        }
    }

    pub fn update_abs_range(&mut self, min_x: i32, max_x: i32, min_y: i32, max_y: i32) {
        if max_x > min_x {
            self.abs_min_x = min_x;
            self.abs_max_x = max_x;
        }
        if max_y > min_y {
            self.abs_min_y = min_y;
            self.abs_max_y = max_y;
        }
    }

    #[inline]
    pub fn map_x(&self, raw: i32) -> i32 {
        let span = (self.abs_max_x - self.abs_min_x).max(1) as i64;
        let rel = (raw - self.abs_min_x) as i64;
        ((rel * (self.screen_w - 1) as i64) / span).clamp(0, (self.screen_w - 1) as i64) as i32
    }

    #[inline]
    pub fn map_y(&self, raw: i32) -> i32 {
        let span = (self.abs_max_y - self.abs_min_y).max(1) as i64;
        let rel = (raw - self.abs_min_y) as i64;
        ((rel * (self.screen_h - 1) as i64) / span).clamp(0, (self.screen_h - 1) as i64) as i32
    }

    /// Feed a single Linux `input_event` `(type_, code, value)`.
    /// Touch transitions are committed cleanly on `EV_SYN / SYN_REPORT` so X and Y
    /// are guaranteed up to date regardless of Protocol A or Protocol B ordering!
    pub fn feed(&mut self, type_: u16, code: u16, value: i32) -> Option<InputEvent> {
        match type_ {
            EV_KEY => match code {
                BTN_TOUCH => {
                    if value != 0 {
                        if !self.touching {
                            self.pending_down = true;
                        }
                    } else if self.touching || self.pending_down {
                        self.pending_up = true;
                    }
                    None
                }
                KEY_VOLUMEUP if value == 1 => Some(InputEvent::KeyFocusPrev),
                KEY_VOLUMEDOWN => {
                    self.vol_down_held = value != 0;
                    if self.vol_down_held && self.power_held {
                        return Some(InputEvent::ScreenshotCombo);
                    }
                    if value == 1 {
                        Some(InputEvent::KeyFocusNext)
                    } else {
                        None
                    }
                }
                KEY_POWER => {
                    self.power_held = value != 0;
                    if self.vol_down_held && self.power_held {
                        return Some(InputEvent::ScreenshotCombo);
                    }
                    if value == 1 {
                        Some(InputEvent::PowerToggle)
                    } else {
                        None
                    }
                }
                _ => None,
            },
            EV_ABS => match code {
                ABS_MT_SLOT => {
                    self.slot = value;
                    None
                }
                ABS_MT_POSITION_X | ABS_X if self.slot == 0 => {
                    self.raw_x = value;
                    self.pos_dirty = true;
                    None
                }
                ABS_MT_POSITION_Y | ABS_Y if self.slot == 0 => {
                    self.raw_y = value;
                    self.pos_dirty = true;
                    None
                }
                ABS_MT_TRACKING_ID if self.slot == 0 => {
                    if value >= 0 {
                        self.pending_down = true;
                        self.pending_up = false;
                    } else {
                        self.pending_up = true;
                    }
                    None
                }
                _ => None,
            },
            EV_SYN if code == SYN_REPORT => {
                let sx = self.map_x(self.raw_x);
                let sy = self.map_y(self.raw_y);
                let moved = self.pos_dirty;
                self.pos_dirty = false;

                if self.pending_down && self.pending_up {
                    // Ultra-fast single-frame tap
                    self.pending_down = false;
                    self.pending_up = false;
                    self.touching = false;
                    self.start_x = sx;
                    self.start_y = sy;
                    return Some(InputEvent::TouchUp { x: sx, y: sy });
                }
                if self.pending_down {
                    self.pending_down = false;
                    self.touching = true;
                    self.start_x = sx;
                    self.start_y = sy;
                    return Some(InputEvent::TouchDown { x: sx, y: sy });
                }
                if self.pending_up {
                    self.pending_up = false;
                    if self.touching {
                        self.touching = false;
                        if self.start_x < self.screen_w / 10 && (sx - self.start_x) > self.screen_w / 5 {
                            return Some(InputEvent::SwipeBack);
                        }
                        if self.start_y < self.screen_h / 12 && (sy - self.start_y) > self.screen_h / 10 {
                            return Some(InputEvent::PullDownQuickSettings);
                        }
                        return Some(InputEvent::TouchUp { x: sx, y: sy });
                    }
                    return None;
                }
                if self.touching && moved {
                    return Some(InputEvent::TouchMove { x: sx, y: sy });
                }
                None
            }
            _ => None,
        }
    }
}

#[cfg(target_os = "android")]
extern "C" {
    fn pulih_haptic_click(duration_ms: u32) -> i32;
}

/// Trigger a crisp tactile haptic click via real Linux `EV_FF` (`si_haptic` on
/// POCO F7 / Qualcomm QTI haptics), falling back to `/sys/class/leds/vibrator`.
/// Returns `0` on `EV_FF` success or negative errno / fallback code.
pub fn trigger_haptic_with_status(duration_ms: u32) -> i32 {
    let ms = duration_ms.clamp(8, 200);
    #[cfg(target_os = "android")]
    {
        let rc = unsafe { pulih_haptic_click(ms) };
        if rc == 0 {
            return 0;
        }
    }
    let _ = std::fs::write("/sys/class/leds/vibrator/duration", ms.to_string());
    if std::fs::write("/sys/class/leds/vibrator/activate", "1").is_ok() {
        0
    } else {
        -19 // ENODEV
    }
}

/// Fire-and-forget UI click vibration (`8..=60 ms`).
pub fn trigger_haptic_click(duration_ms: u32) {
    let _ = trigger_haptic_with_status(duration_ms.clamp(8, 60));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_b_tracking_id_before_xy_commits_exact_coords_at_syn() {
        let mut inp = InputState::new(1280, 2772, 1279, 2771);
        // Real Linux MT Protocol B order: TRACKING_ID first, THEN X, Y, SYN_REPORT!
        assert_eq!(inp.feed(EV_ABS, ABS_MT_TRACKING_ID, 7), None);
        assert_eq!(inp.feed(EV_ABS, ABS_MT_POSITION_X, 640), None);
        assert_eq!(inp.feed(EV_ABS, ABS_MT_POSITION_Y, 2600), None);
        assert_eq!(
            inp.feed(EV_SYN, SYN_REPORT, 0),
            Some(InputEvent::TouchDown { x: 640, y: 2600 })
        );
        // Lift finger
        assert_eq!(inp.feed(EV_ABS, ABS_MT_TRACKING_ID, -1), None);
        assert_eq!(
            inp.feed(EV_SYN, SYN_REPORT, 0),
            Some(InputEvent::TouchUp { x: 640, y: 2600 })
        );
    }

    #[test]
    fn protocol_a_btn_touch_and_gestures_and_power_sleep_toggle_work() {
        let mut inp = InputState::new(1280, 2772, 1279, 2771);
        // Physical button behavior: Vol Up/Down scroll, VolDown+Power screenshots, Power alone toggles sleep!
        assert_eq!(inp.feed(EV_KEY, KEY_VOLUMEUP, 1), Some(InputEvent::KeyFocusPrev));
        assert_eq!(inp.feed(EV_KEY, KEY_VOLUMEDOWN, 1), Some(InputEvent::KeyFocusNext));
        assert_eq!(inp.feed(EV_KEY, KEY_POWER, 1), Some(InputEvent::ScreenshotCombo));
        inp.feed(EV_KEY, KEY_VOLUMEDOWN, 0);
        inp.feed(EV_KEY, KEY_POWER, 0);
        assert_eq!(inp.feed(EV_KEY, KEY_POWER, 1), Some(InputEvent::PowerToggle));

        // Left-edge swipe back via BTN_TOUCH (Protocol A)
        inp.feed(EV_KEY, BTN_TOUCH, 1);
        inp.feed(EV_ABS, ABS_MT_POSITION_X, 20);
        inp.feed(EV_ABS, ABS_MT_POSITION_Y, 1200);
        assert_eq!(
            inp.feed(EV_SYN, SYN_REPORT, 0),
            Some(InputEvent::TouchDown { x: 20, y: 1200 })
        );
        inp.feed(EV_ABS, ABS_MT_POSITION_X, 420);
        assert_eq!(
            inp.feed(EV_SYN, SYN_REPORT, 0),
            Some(InputEvent::TouchMove { x: 420, y: 1200 })
        );
        inp.feed(EV_KEY, BTN_TOUCH, 0);
        assert_eq!(inp.feed(EV_SYN, SYN_REPORT, 0), Some(InputEvent::SwipeBack));
    }
}
