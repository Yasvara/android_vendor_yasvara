// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: Apache-2.0

//! Pure-Rust daemon lifecycle state machine (`Off`, `Session`, `Pinned`, `Suspended`, `Diagnostic`).
//!
//! Follows Rust owns all transitions and TTL leases; the C++ shim acts on the
//! returned [`LifeActions`] POD.

use crate::schema::{mask, AfterGamePolicy, HudProfile};

/// Maximum permitted diagnostic/capture lease (1 hour).
pub const MAX_TTL_SEC: u32 = 3600;
/// Default watch/capture TTL when caller passes 0.
pub const DEFAULT_TTL_SEC: u32 = 30;

#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum LifeState {
    Off = 0,
    Session = 1,
    Pinned = 2,
    Suspended = 3,
    Diagnostic = 4,
}

/// Flat action plan returned to the C++ / epoll shim after each event.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct LifeActions {
    pub state: u8,
    pub timer_ms: u32,       // 0 = disarm timerfd
    pub hud_visible: bool,
    pub allow_exit: bool,    // true when Off & no active clients → lazy service may exit
    pub disarm_taps: bool,
    pub active_consumers: u64,
    pub focused_task_id: i32,
    pub focused_uid: u32,
}

#[derive(Copy, Clone, Debug)]
pub struct LifeMachine {
    state: LifeState,
    before_suspend: LifeState,
    hud_profile: HudProfile,
    panel_consumers: u64,
    capture_consumers: u64,
    capture_deadline_ns: u64, // 0 = no active capture lease
    pin_deadline_ns: u64,     // 0 = indefinite pin
    in_game: bool,
    screen_on: bool,
    focused_task_id: i32,
    focused_uid: u32,
}

impl Default for LifeMachine {
    fn default() -> Self {
        Self::new()
    }
}

impl LifeMachine {
    pub fn new() -> Self {
        Self {
            state: LifeState::Off,
            before_suspend: LifeState::Off,
            hud_profile: HudProfile::default(),
            panel_consumers: 0,
            capture_consumers: 0,
            capture_deadline_ns: 0,
            pin_deadline_ns: 0,
            in_game: false,
            screen_on: true,
            focused_task_id: -1,
            focused_uid: 0,
        }
    }

    #[inline]
    pub fn state(&self) -> LifeState {
        self.state
    }

    #[inline]
    pub fn profile(&self) -> &HudProfile {
        &self.hud_profile
    }

    pub fn set_profile(&mut self, p: HudProfile, now_ns: u64) -> LifeActions {
        self.hud_profile = p;
        if self.state == LifeState::Pinned && !self.hud_profile.any_enabled() {
            self.pin_deadline_ns = 0;
            self.recompute(now_ns, false)
        } else {
            self.recompute(now_ns, false)
        }
    }

    pub fn set_panel_consumers(&mut self, m: u64, now_ns: u64) -> LifeActions {
        self.panel_consumers = m;
        self.recompute(now_ns, false)
    }

    /// Game session start (`uid >= 0, is_game == true`) or focus update (`is_game == false`).
    pub fn on_session(&mut self, task_id: i32, uid: i32, is_game: bool, now_ns: u64) -> LifeActions {
        if uid < 0 {
            // Game session ended.
            self.in_game = false;
            if self.hud_profile.any_enabled() {
                match self.hud_profile.policy {
                    AfterGamePolicy::Close => {
                        self.pin_deadline_ns = 0;
                    }
                    AfterGamePolicy::Keep => {
                        self.pin_deadline_ns = 0;
                        self.state = LifeState::Pinned;
                    }
                    AfterGamePolicy::KeepTimer => {
                        let dur_ns = (self.hud_profile.keep_sec as u64) * 1_000_000_000;
                        self.pin_deadline_ns = now_ns.saturating_add(dur_ns);
                        self.state = LifeState::Pinned;
                    }
                }
            }
            return self.recompute(now_ns, false);
        }

        self.focused_task_id = task_id;
        self.focused_uid = uid as u32;
        if is_game {
            self.in_game = true;
            self.pin_deadline_ns = 0;
        }
        self.recompute(now_ns, false)
    }

    pub fn on_screen(&mut self, on: bool, now_ns: u64) -> LifeActions {
        self.screen_on = on;
        if !on {
            if self.state == LifeState::Pinned && self.hud_profile.close_on_screen_off {
                self.pin_deadline_ns = 0;
                self.state = LifeState::Off;
                return self.recompute(now_ns, false);
            }
            if self.state != LifeState::Off && self.state != LifeState::Suspended {
                self.before_suspend = self.state;
                self.state = LifeState::Suspended;
            }
            return self.build_actions(false);
        }
        // Screen turned on.
        if self.state == LifeState::Suspended {
            self.state = self.before_suspend;
        }
        self.recompute(now_ns, false)
    }

    /// Explicit QS tile / `cmd pantau hud` pin/unpin toggle.
    pub fn on_hud_pin(&mut self, pin: bool, now_ns: u64) -> LifeActions {
        if pin {
            if !self.hud_profile.any_enabled() {
                self.hud_profile.enabled_mask = 1 << (crate::schema::WidgetId::Classic as u8);
            }
            self.pin_deadline_ns = 0;
            if !self.in_game {
                self.state = LifeState::Pinned;
            }
        } else if self.state == LifeState::Pinned {
            self.pin_deadline_ns = 0;
            self.state = LifeState::Off;
        }
        self.recompute(now_ns, false)
    }

    /// Moves a widget for the current orientation (edit-mode drag proxy or `cmd pantau hud move`).
    pub fn move_widget(&mut self, idx: usize, is_land: bool, x: i32, y: i32) {
        if idx >= crate::schema::WIDGET_COUNT {
            return;
        }
        let cx = x.clamp(i16::MIN as i32, i16::MAX as i32) as i16;
        let cy = y.clamp(i16::MIN as i32, i16::MAX as i32) as i16;
        if idx == crate::schema::WidgetId::Mini as usize {
            self.hud_profile.mini_anchor = crate::schema::mini_anchor::FREE;
        }
        if is_land {
            self.hud_profile.pos[idx].x_land = cx;
            self.hud_profile.pos[idx].y_land = cy;
        } else {
            self.hud_profile.pos[idx].x_port = cx;
            self.hud_profile.pos[idx].y_port = cy;
        }
    }

    /// Starts a TTL-leased diagnostic or Jejak capture.
    pub fn start_capture(&mut self, extra_consumers: u64, ttl_sec: u32, now_ns: u64) -> LifeActions {
        let clamped = if ttl_sec == 0 {
            DEFAULT_TTL_SEC
        } else {
            ttl_sec.min(MAX_TTL_SEC)
        };
        self.capture_consumers = mask::JEJAK_T1 | extra_consumers;
        self.capture_deadline_ns = now_ns.saturating_add((clamped as u64) * 1_000_000_000);
        self.recompute(now_ns, false)
    }

    /// Stops active capture (or called on `linkToDeath` / TTL expiry).
    pub fn stop_capture(&mut self, now_ns: u64) -> LifeActions {
        self.capture_consumers = 0;
        self.capture_deadline_ns = 0;
        self.recompute(now_ns, true)
    }

    /// Periodic tick check for TTL and pin countdown expiry.
    pub fn on_tick(&mut self, now_ns: u64) -> LifeActions {
        let mut disarmed = false;
        if self.capture_deadline_ns != 0 && now_ns >= self.capture_deadline_ns {
            self.capture_consumers = 0;
            self.capture_deadline_ns = 0;
            disarmed = true;
        }
        if self.state == LifeState::Pinned
            && self.pin_deadline_ns != 0
            && now_ns >= self.pin_deadline_ns
        {
            self.pin_deadline_ns = 0;
            self.state = LifeState::Off;
        }
        self.recompute(now_ns, disarmed)
    }

    fn recompute(&mut self, now_ns: u64, disarm_taps: bool) -> LifeActions {
        if !self.screen_on && self.capture_deadline_ns == 0 {
            if self.state != LifeState::Off && self.state != LifeState::Suspended {
                self.before_suspend = self.state;
                self.state = LifeState::Suspended;
            }
            return self.build_actions(disarm_taps);
        }

        let capture_live = self.capture_deadline_ns != 0 && now_ns < self.capture_deadline_ns;
        let pin_live = self.state == LifeState::Pinned
            && self.hud_profile.any_enabled()
            && (self.pin_deadline_ns == 0 || now_ns < self.pin_deadline_ns);

        self.state = if self.in_game {
            LifeState::Session
        } else if pin_live {
            LifeState::Pinned
        } else if capture_live || self.panel_consumers != 0 {
            LifeState::Diagnostic
        } else {
            LifeState::Off
        };

        self.build_actions(disarm_taps)
    }

    fn build_actions(&self, disarm_taps: bool) -> LifeActions {
        let hud_visible = matches!(self.state, LifeState::Session | LifeState::Pinned)
            && self.hud_profile.any_enabled();
        let hud_consumers = if hud_visible {
            self.hud_profile.required_consumers()
        } else {
            0
        };
        let active_consumers = match self.state {
            LifeState::Off | LifeState::Suspended => 0,
            // Strictly demand-driven: sample only what active HUD widgets, an open Pentas panel,
            // or a TTL capture lease actually observe. When HUD is off and Sidebar is closed
            // during a game, active_consumers == 0 -> timerfd disarmed -> 0% CPU overhead!
            LifeState::Session | LifeState::Pinned => {
                hud_consumers | self.panel_consumers | self.capture_consumers
            }
            LifeState::Diagnostic => self.panel_consumers | self.capture_consumers,
        };
        let timer_ms = if active_consumers != 0 { 1000 } else { 0 };
        LifeActions {
            state: self.state as u8,
            timer_ms,
            hud_visible,
            allow_exit: self.state == LifeState::Off || (active_consumers == 0 && !hud_visible),
            disarm_taps,
            active_consumers,
            focused_task_id: self.focused_task_id,
            focused_uid: self.focused_uid,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::WidgetId;

    #[test]
    fn after_game_policies_and_suspend() {
        let mut lm = LifeMachine::new();
        let mut p = HudProfile::default();
        p.enabled_mask = 1 << (WidgetId::Classic as u8);
        p.policy = AfterGamePolicy::KeepTimer;
        p.keep_sec = 60;
        lm.set_profile(p, 0);

        let a = lm.on_session(7, 10042, true, 1_000_000_000);
        assert_eq!(a.state, LifeState::Session as u8);
        assert!(a.hud_visible);
        assert!(!a.allow_exit);

        // Leave game → Pinned for 60s.
        let a = lm.on_session(7, -1, false, 10_000_000_000);
        assert_eq!(a.state, LifeState::Pinned as u8);
        assert!(a.hud_visible);

        // Screen off with close_on_screen_off=true → Off!
        let a = lm.on_screen(false, 20_000_000_000);
        assert_eq!(a.state, LifeState::Off as u8);
        assert_eq!(a.timer_ms, 0);
        assert!(a.allow_exit);
    }

    #[test]
    fn diagnostic_ttl_auto_disarms() {
        let mut lm = LifeMachine::new();
        let a = lm.start_capture(0, 15, 1_000_000_000);
        assert_eq!(a.state, LifeState::Diagnostic as u8);
        assert!(!a.hud_visible);
        assert_eq!(a.timer_ms, 1000);

        let a = lm.on_tick(16_000_000_000);
        assert_eq!(a.state, LifeState::Off as u8);
        assert!(a.disarm_taps);
        assert!(a.allow_exit);
    }

    #[test]
    fn game_session_with_no_hud_or_panel_is_zero_overhead() {
        let mut lm = LifeMachine::new();
        let a = lm.on_session(12, 10055, true, 1_000_000_000);
        assert_eq!(a.state, LifeState::Session as u8);
        assert!(!a.hud_visible);
        assert_eq!(a.active_consumers, 0);
        assert_eq!(a.timer_ms, 0);
        assert!(a.allow_exit);

        let a = lm.set_panel_consumers(mask::PANEL_HOME, 2_000_000_000);
        assert_eq!(a.timer_ms, 1000);
        assert!(!a.allow_exit);

        let a = lm.set_panel_consumers(0, 3_000_000_000);
        assert_eq!(a.timer_ms, 0);
        assert_eq!(a.active_consumers, 0);
        assert!(a.allow_exit);
    }
}
