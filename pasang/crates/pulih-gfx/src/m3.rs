// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: Apache-2.0

//! Pure-Rust Material 3 Expressive (`Material You`) Interactive Components:
//! - [`M3BottomSheet`]: Spring-driven modal bottom sheet with Material 3 drag handle,
//!   1:1 finger drag tracking, rubber-band over-pull resistance, velocity/threshold
//!   auto-dismiss (drag down to close like Android 16/17!), and animated scrim backdrop.
//! - [`M3TopSheet`]: Mirror top pull-down sheet for Quick Settings (drag up to close!).
//! - [`M3ScrollPhysics`]: Pixel-smooth 120 Hz inertial scrolling (`OverScroller` fling
//!   momentum + exponential deceleration + elastic edge overscroll rebound).

use crate::monet::Palette;
use crate::raster::fill_rounded_rect;
use crate::spring::{Spring, SpringConfig};
use crate::{Rect, Surface};

const SHEET_SPRING: SpringConfig = SpringConfig {
    stiffness: 520.0,
    damping: 40.0,
    epsilon: 0.5,
};

const OVERSCROLL_SPRING: SpringConfig = SpringConfig {
    stiffness: 340.0,
    damping: 36.0,
    epsilon: 0.5,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SheetEvent {
    None,
    Consumed,
    RequestClose,
    Dismissed,
}

/// Material 3 Expressive Modal Bottom Sheet controller with real spring physics
/// and 1:1 Android drag-down-to-dismiss gesture.
#[derive(Clone, Debug)]
pub struct M3BottomSheet {
    pub active: bool,
    pub dismissing: bool,
    pub sheet_height: f32,
    pub spring: Spring,
    pub dragging: bool,
    armed: bool,
    drag_start_y: i32,
    last_y: i32,
    last_time_ms: u64,
    pub velocity_px_s: f32,
}

impl Default for M3BottomSheet {
    fn default() -> Self {
        Self::new()
    }
}

impl M3BottomSheet {
    pub const fn new() -> Self {
        Self {
            active: false,
            dismissing: false,
            sheet_height: 820.0,
            spring: Spring::new(820.0, SHEET_SPRING),
            dragging: false,
            armed: false,
            drag_start_y: 0,
            last_y: 0,
            last_time_ms: 0,
            velocity_px_s: 0.0,
        }
    }

    /// Open the sheet smoothly from offscreen bottom (`offset = height -> 0`).
    pub fn open(&mut self, sheet_height: f32) {
        let h = sheet_height.max(160.0);
        self.sheet_height = h;
        if !self.active || self.dismissing {
            self.spring.snap(h);
        }
        self.active = true;
        self.dismissing = false;
        self.dragging = false;
        self.armed = false;
        self.velocity_px_s = 0.0;
        self.spring.set_target(0.0);
    }

    /// Animate the sheet smoothly offscreen downward (`offset -> height`).
    pub fn close(&mut self) {
        if !self.active {
            return;
        }
        self.dismissing = true;
        self.dragging = false;
        self.armed = false;
        self.spring.set_target(self.sheet_height);
    }

    /// Immediate reset without animation.
    pub fn reset(&mut self) {
        self.active = false;
        self.dismissing = false;
        self.dragging = false;
        self.armed = false;
        self.velocity_px_s = 0.0;
        self.spring.snap(self.sheet_height);
    }

    /// Current vertical pixel translation (`0` = fully open, `sheet_height` = closed).
    #[inline]
    pub fn offset_px(&self) -> i32 {
        self.spring.value.round() as i32
    }

    /// Current open progress in `0.0..=1.0` (used to drive translucent scrim fade).
    #[inline]
    pub fn open_progress(&self) -> f32 {
        if !self.active || self.sheet_height <= 1.0 {
            return 0.0;
        }
        (1.0 - self.spring.value / self.sheet_height).clamp(0.0, 1.0)
    }

    /// Scrim darken alpha (`0..=155`) synced to sheet open progress.
    #[inline]
    pub fn scrim_alpha(&self) -> u8 {
        (self.open_progress() * 150.0).round().clamp(0.0, 155.0) as u8
    }

    #[inline]
    pub fn is_animating(&self) -> bool {
        self.active && (self.dragging || !self.spring.is_settled())
    }

    /// Feed `TouchDown`. Tapping outside `sheet_rect` closes the sheet smoothly;
    /// touching inside arms 1:1 drag-to-dismiss tracking.
    pub fn on_touch_down(&mut self, sheet_rect: Rect, x: i32, y: i32, now_ms: u64) -> SheetEvent {
        if !self.active || self.dismissing {
            return SheetEvent::None;
        }
        if !sheet_rect.contains(x, y) {
            self.close();
            return SheetEvent::RequestClose;
        }
        self.armed = true;
        self.dragging = y <= sheet_rect.y + 84; // Immediate drag on M3 drag handle zone!
        self.drag_start_y = y;
        self.last_y = y;
        self.last_time_ms = now_ms;
        self.velocity_px_s = 0.0;
        if self.dragging {
            SheetEvent::Consumed
        } else {
            SheetEvent::None
        }
    }

    /// Feed `TouchMove`. Tracks finger 1:1 downward (and soft rubber-band upward).
    pub fn on_touch_move(&mut self, y: i32, now_ms: u64) -> SheetEvent {
        if !self.active || !self.armed {
            return SheetEvent::None;
        }
        let total_dy = y - self.drag_start_y;
        if !self.dragging && total_dy > 14 {
            self.dragging = true;
            self.last_y = y;
            self.last_time_ms = now_ms;
            return SheetEvent::Consumed;
        }
        if !self.dragging {
            return SheetEvent::None;
        }
        let dy = (y - self.last_y) as f32;
        let dt_ms = now_ms.saturating_sub(self.last_time_ms).max(4) as f32;
        let inst_v = (dy / dt_ms) * 1000.0;
        self.velocity_px_s = self.velocity_px_s * 0.45 + inst_v * 0.55;
        self.last_y = y;
        self.last_time_ms = now_ms;

        // 1:1 downward pull; soft 0.18x Android rubber-band if pulled upward past 0
        let next = if self.spring.value + dy < 0.0 {
            (self.spring.value + dy * 0.18).max(-48.0)
        } else {
            (self.spring.value + dy).min(self.sheet_height)
        };
        self.spring.value = next;
        self.spring.target = next;
        self.spring.velocity = 0.0;
        SheetEvent::Consumed
    }

    /// Feed `TouchUp`. Auto-closes if pulled > 25% or flicked downward fast,
    /// otherwise springs crisply back open!
    pub fn on_touch_up(&mut self) -> SheetEvent {
        let was_dragging = self.dragging;
        self.armed = false;
        self.dragging = false;
        if !self.active || !was_dragging {
            return SheetEvent::None;
        }
        if self.spring.value > self.sheet_height * 0.25 || self.velocity_px_s > 550.0 {
            self.dismissing = true;
            self.spring.velocity = self.velocity_px_s.max(350.0);
            self.spring.set_target(self.sheet_height);
            SheetEvent::RequestClose
        } else {
            self.dismissing = false;
            self.spring.velocity = self.velocity_px_s.clamp(-1200.0, 1200.0);
            self.spring.set_target(0.0);
            SheetEvent::Consumed
        }
    }

    /// Advance spring physics by `dt_s` seconds. Returns `SheetEvent::Dismissed`
    /// once a closing animation has finished sliding off-screen.
    pub fn step(&mut self, dt_s: f32) -> SheetEvent {
        if !self.active || self.dragging {
            return SheetEvent::None;
        }
        let moving = self.spring.step(dt_s);
        if self.dismissing && (!moving || self.spring.value >= self.sheet_height - 1.5) {
            self.reset();
            return SheetEvent::Dismissed;
        }
        SheetEvent::None
    }
}

/// Mirror Material 3 Top Pull-Down Sheet (for Quick Settings shade: slides down from top,
/// drag upward past 25% or flick up to auto-close smoothly!).
#[derive(Clone, Debug)]
pub struct M3TopSheet {
    pub active: bool,
    pub dismissing: bool,
    pub sheet_height: f32,
    pub spring: Spring, // 0.0 = open, -sheet_height = closed off-top
    pub dragging: bool,
    armed: bool,
    drag_start_y: i32,
    last_y: i32,
    last_time_ms: u64,
    pub velocity_px_s: f32,
}

impl Default for M3TopSheet {
    fn default() -> Self {
        Self::new()
    }
}

impl M3TopSheet {
    pub const fn new() -> Self {
        Self {
            active: false,
            dismissing: false,
            sheet_height: 860.0,
            spring: Spring::new(-860.0, SHEET_SPRING),
            dragging: false,
            armed: false,
            drag_start_y: 0,
            last_y: 0,
            last_time_ms: 0,
            velocity_px_s: 0.0,
        }
    }

    pub fn open(&mut self, sheet_height: f32) {
        let h = sheet_height.max(200.0);
        self.sheet_height = h;
        if !self.active || self.dismissing {
            self.spring.snap(-h);
        }
        self.active = true;
        self.dismissing = false;
        self.dragging = false;
        self.armed = false;
        self.velocity_px_s = 0.0;
        self.spring.set_target(0.0);
    }

    pub fn close(&mut self) {
        if !self.active {
            return;
        }
        self.dismissing = true;
        self.dragging = false;
        self.armed = false;
        self.spring.set_target(-self.sheet_height);
    }

    pub fn reset(&mut self) {
        self.active = false;
        self.dismissing = false;
        self.dragging = false;
        self.armed = false;
        self.velocity_px_s = 0.0;
        self.spring.snap(-self.sheet_height);
    }

    #[inline]
    pub fn offset_px(&self) -> i32 {
        self.spring.value.round() as i32
    }

    #[inline]
    pub fn open_progress(&self) -> f32 {
        if !self.active || self.sheet_height <= 1.0 {
            return 0.0;
        }
        (1.0 + self.spring.value / self.sheet_height).clamp(0.0, 1.0)
    }

    #[inline]
    pub fn scrim_alpha(&self) -> u8 {
        (self.open_progress() * 150.0).round().clamp(0.0, 155.0) as u8
    }

    #[inline]
    pub fn is_animating(&self) -> bool {
        self.active && (self.dragging || !self.spring.is_settled())
    }

    pub fn on_touch_down(&mut self, sheet_rect: Rect, x: i32, y: i32, now_ms: u64) -> SheetEvent {
        if !self.active || self.dismissing {
            return SheetEvent::None;
        }
        if !sheet_rect.contains(x, y) {
            self.close();
            return SheetEvent::RequestClose;
        }
        self.armed = true;
        self.dragging = y >= sheet_rect.bottom() - 84; // Bottom drag handle pill!
        self.drag_start_y = y;
        self.last_y = y;
        self.last_time_ms = now_ms;
        self.velocity_px_s = 0.0;
        if self.dragging {
            SheetEvent::Consumed
        } else {
            SheetEvent::None
        }
    }

    pub fn on_touch_move(&mut self, y: i32, now_ms: u64) -> SheetEvent {
        if !self.active || !self.armed {
            return SheetEvent::None;
        }
        let total_dy = y - self.drag_start_y;
        if !self.dragging && total_dy < -14 {
            self.dragging = true;
            self.last_y = y;
            self.last_time_ms = now_ms;
            return SheetEvent::Consumed;
        }
        if !self.dragging {
            return SheetEvent::None;
        }
        let dy = (y - self.last_y) as f32;
        let dt_ms = now_ms.saturating_sub(self.last_time_ms).max(4) as f32;
        let inst_v = (dy / dt_ms) * 1000.0;
        self.velocity_px_s = self.velocity_px_s * 0.45 + inst_v * 0.55;
        self.last_y = y;
        self.last_time_ms = now_ms;

        let next = if self.spring.value + dy > 0.0 {
            (self.spring.value + dy * 0.18).min(48.0)
        } else {
            (self.spring.value + dy).max(-self.sheet_height)
        };
        self.spring.value = next;
        self.spring.target = next;
        self.spring.velocity = 0.0;
        SheetEvent::Consumed
    }

    pub fn on_touch_up(&mut self) -> SheetEvent {
        let was_dragging = self.dragging;
        self.armed = false;
        self.dragging = false;
        if !self.active || !was_dragging {
            return SheetEvent::None;
        }
        if self.spring.value < -self.sheet_height * 0.25 || self.velocity_px_s < -550.0 {
            self.dismissing = true;
            self.spring.velocity = self.velocity_px_s.min(-350.0);
            self.spring.set_target(-self.sheet_height);
            SheetEvent::RequestClose
        } else {
            self.dismissing = false;
            self.spring.velocity = self.velocity_px_s.clamp(-1200.0, 1200.0);
            self.spring.set_target(0.0);
            SheetEvent::Consumed
        }
    }

    pub fn step(&mut self, dt_s: f32) -> SheetEvent {
        if !self.active || self.dragging {
            return SheetEvent::None;
        }
        let moving = self.spring.step(dt_s);
        if self.dismissing && (!moving || self.spring.value <= -self.sheet_height + 1.5) {
            self.reset();
            return SheetEvent::Dismissed;
        }
        SheetEvent::None
    }
}

/// Draw standard Material 3 Expressive Bottom Sheet surface + top centered Drag Handle Pill.
pub fn draw_m3_bottom_sheet_chrome(surface: &mut Surface, rect: Rect, pal: &Palette) {
    fill_rounded_rect(surface, rect, 44.0, pal.surface_container_highest);
    let handle_w = 108;
    let handle_h = 10;
    let handle = Rect::new(
        rect.x + (rect.w - handle_w) / 2,
        rect.y + 18,
        handle_w,
        handle_h,
    );
    fill_rounded_rect(surface, handle, 5.0, pal.outline);
}

/// Draw standard Material 3 Top Quick Settings Sheet surface + bottom centered Drag Handle Pill.
pub fn draw_m3_top_sheet_chrome(surface: &mut Surface, rect: Rect, pal: &Palette) {
    fill_rounded_rect(surface, rect, 44.0, pal.surface_container_highest);
    let handle_w = 108;
    let handle_h = 10;
    let handle = Rect::new(
        rect.x + (rect.w - handle_w) / 2,
        rect.bottom() - 24,
        handle_w,
        handle_h,
    );
    fill_rounded_rect(surface, handle, 5.0, pal.outline);
}

/// Pixel-smooth 120 Hz inertial scroll physics (`OverScroller` fling + elastic edge rebound).
#[derive(Clone, Debug)]
pub struct M3ScrollPhysics {
    pub offset_px: f32,
    pub max_scroll_px: f32,
    pub velocity_px_s: f32,
    pub dragging: bool,
    pub moved_beyond_slop: bool,
    start_y: i32,
    last_y: i32,
    last_time_ms: u64,
    rebound: Spring,
}

impl Default for M3ScrollPhysics {
    fn default() -> Self {
        Self::new()
    }
}

impl M3ScrollPhysics {
    pub const fn new() -> Self {
        Self {
            offset_px: 0.0,
            max_scroll_px: 0.0,
            velocity_px_s: 0.0,
            dragging: false,
            moved_beyond_slop: false,
            start_y: 0,
            last_y: 0,
            last_time_ms: 0,
            rebound: Spring::new(0.0, OVERSCROLL_SPRING),
        }
    }

    pub fn set_bounds(&mut self, max_scroll_px: f32) {
        self.max_scroll_px = max_scroll_px.max(0.0);
        if !self.dragging && self.velocity_px_s.abs() < 1.0 {
            self.offset_px = self.offset_px.clamp(0.0, self.max_scroll_px);
        }
    }

    pub fn reset(&mut self) {
        self.offset_px = 0.0;
        self.velocity_px_s = 0.0;
        self.dragging = false;
        self.moved_beyond_slop = false;
    }

    /// Programmatic smooth scroll by `delta_px` (e.g. Volume buttons or Page Up/Down).
    pub fn scroll_by(&mut self, delta_px: f32) {
        self.velocity_px_s = 0.0;
        self.offset_px = (self.offset_px + delta_px).clamp(0.0, self.max_scroll_px);
    }

    #[inline]
    pub fn scroll_px(&self) -> i32 {
        self.offset_px.round() as i32
    }

    #[inline]
    pub fn is_animating(&self) -> bool {
        if self.dragging {
            return true;
        }
        self.velocity_px_s.abs() > 12.0
            || self.offset_px < -0.5
            || self.offset_px > self.max_scroll_px + 0.5
    }

    pub fn on_touch_down(&mut self, y: i32, now_ms: u64) {
        self.dragging = true;
        self.moved_beyond_slop = false;
        self.velocity_px_s = 0.0;
        self.start_y = y;
        self.last_y = y;
        self.last_time_ms = now_ms;
    }

    /// Returns `true` if the gesture crossed touch slop and scrolled the list.
    pub fn on_touch_move(&mut self, y: i32, now_ms: u64) -> bool {
        if !self.dragging {
            return false;
        }
        if !self.moved_beyond_slop && (y - self.start_y).abs() >= 12 {
            self.moved_beyond_slop = true;
            self.last_y = y;
            self.last_time_ms = now_ms;
            return true;
        }
        if !self.moved_beyond_slop {
            return false;
        }
        let dy = (self.last_y - y) as f32; // Dragging finger UP increases scroll offset!
        let dt_ms = now_ms.saturating_sub(self.last_time_ms).max(4) as f32;
        let inst_v = (dy / dt_ms) * 1000.0;
        self.velocity_px_s = self.velocity_px_s * 0.4 + inst_v * 0.6;
        self.last_y = y;
        self.last_time_ms = now_ms;

        let next = self.offset_px + dy;
        if next < 0.0 || next > self.max_scroll_px {
            // Soft elastic overscroll resistance (Android stretch feel)
            self.offset_px += dy * 0.25;
            self.offset_px = self.offset_px.clamp(-120.0, self.max_scroll_px + 120.0);
        } else {
            self.offset_px = next;
        }
        true
    }

    /// Returns `true` if this touch sequence was a scroll (caller should NOT fire tap click).
    pub fn on_touch_up(&mut self) -> bool {
        let was_scroll = self.moved_beyond_slop;
        self.dragging = false;
        self.moved_beyond_slop = false;
        if was_scroll {
            self.velocity_px_s = self.velocity_px_s.clamp(-6500.0, 6500.0);
            if self.offset_px < 0.0 || self.offset_px > self.max_scroll_px {
                self.velocity_px_s *= 0.25;
                self.rebound.value = self.offset_px;
                self.rebound.velocity = self.velocity_px_s;
                self.rebound.target = self.offset_px.clamp(0.0, self.max_scroll_px);
            }
        } else {
            self.velocity_px_s = 0.0;
        }
        was_scroll
    }

    /// Step momentum fling + elastic edge rebound at 120 Hz. Returns `true` if still moving.
    pub fn step(&mut self, dt_s: f32) -> bool {
        if self.dragging {
            return true;
        }
        let dt = dt_s.clamp(0.001, 0.05);
        if self.offset_px < -0.5 || self.offset_px > self.max_scroll_px + 0.5 {
            self.rebound.value = self.offset_px;
            self.rebound.target = self.offset_px.clamp(0.0, self.max_scroll_px);
            let moving = self.rebound.step(dt);
            self.offset_px = self.rebound.value;
            self.velocity_px_s = if moving { self.rebound.velocity } else { 0.0 };
            return moving;
        }

        if self.velocity_px_s.abs() <= 12.0 {
            self.velocity_px_s = 0.0;
            self.offset_px = self.offset_px.clamp(0.0, self.max_scroll_px);
            return false;
        }

        self.offset_px += self.velocity_px_s * dt;
        // Crisp natural Android fling friction (~0.65s glide)
        let decay = 0.025_f32.powf(dt);
        self.velocity_px_s *= decay;

        if self.offset_px < 0.0 {
            self.offset_px = self.offset_px.max(-64.0);
            self.velocity_px_s *= 0.2;
            self.rebound.value = self.offset_px;
            self.rebound.velocity = self.velocity_px_s;
            self.rebound.target = 0.0;
        } else if self.offset_px > self.max_scroll_px {
            self.offset_px = self.offset_px.min(self.max_scroll_px + 64.0);
            self.velocity_px_s *= 0.2;
            self.rebound.value = self.offset_px;
            self.rebound.velocity = self.velocity_px_s;
            self.rebound.target = self.max_scroll_px;
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bottom_sheet_springs_open_drags_and_auto_dismisses() {
        let mut sheet = M3BottomSheet::new();
        sheet.open(800.0);
        assert!(sheet.active);
        assert_eq!(sheet.offset_px(), 800);

        // Animate to open
        for _ in 0..180 {
            sheet.step(1.0 / 120.0);
        }
        assert_eq!(sheet.offset_px(), 0);
        assert!(!sheet.is_animating());

        // 1. Slow gentle pull down (< 25% and slow speed) snaps back open cleanly!
        let r = Rect::new(36, 1900, 1208, 800);
        sheet.on_touch_down(r, 640, 1940, 100);
        sheet.on_touch_move(2020, 450); // 80px in 350ms (~228 px/s, gentle drag)
        assert!(sheet.offset_px() >= 75);
        assert_eq!(sheet.on_touch_up(), SheetEvent::Consumed);
        assert!(!sheet.dismissing);
        for _ in 0..180 {
            sheet.step(1.0 / 120.0);
        }
        assert_eq!(sheet.offset_px(), 0);

        // 2. Fast downward flick auto-closes smoothly!
        sheet.on_touch_down(r, 640, 1940, 600);
        sheet.on_touch_move(2040, 640); // 100px in 40ms (~2500 px/s flick!)
        assert_eq!(sheet.on_touch_up(), SheetEvent::RequestClose);
        assert!(sheet.dismissing);
        let mut dismissed = false;
        for _ in 0..240 {
            if sheet.step(1.0 / 120.0) == SheetEvent::Dismissed {
                dismissed = true;
                break;
            }
        }
        assert!(dismissed);
        assert!(!sheet.active);

        // 3. Slow pull down past 25% (> 200px) also auto-closes smoothly!
        sheet.open(800.0);
        for _ in 0..180 {
            sheet.step(1.0 / 120.0);
        }
        sheet.on_touch_down(r, 640, 1940, 1000);
        sheet.on_touch_move(2260, 2200); // 320px slowly over 1.2s
        assert_eq!(sheet.on_touch_up(), SheetEvent::RequestClose);
        assert!(sheet.dismissing);
    }

    #[test]
    fn top_sheet_and_inertial_scroll_work_smoothly() {
        let mut qs = M3TopSheet::new();
        qs.open(820.0);
        for _ in 0..180 {
            qs.step(1.0 / 120.0);
        }
        assert_eq!(qs.offset_px(), 0);

        // Drag upward past 25% -> auto-closes!
        let r = Rect::new(32, 200, 1216, 820);
        qs.on_touch_down(r, 640, 990, 100);
        qs.on_touch_move(680, 220);
        assert_eq!(qs.on_touch_up(), SheetEvent::RequestClose);
        let mut closed = false;
        for _ in 0..240 {
            if qs.step(1.0 / 120.0) == SheetEvent::Dismissed {
                closed = true;
                break;
            }
        }
        assert!(closed);

        // Inertial pixel scroll flings smoothly and settles
        let mut sc = M3ScrollPhysics::new();
        sc.set_bounds(2000.0);
        sc.on_touch_down(1500, 0);
        sc.on_touch_move(1460, 10);
        sc.on_touch_move(1260, 26);
        assert!(sc.on_touch_up());
        let after_drag = sc.offset_px;
        assert!(after_drag > 150.0);
        let mut frames = 0;
        while sc.step(1.0 / 120.0) && frames < 300 {
            frames += 1;
        }
        assert!(sc.offset_px > after_drag, "fling must glide past lift point");
        assert!(!sc.is_animating());
    }
}
