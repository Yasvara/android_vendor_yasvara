// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: Apache-2.0

//! Pantau & Jejak core engine.
//!
//! Zero external crates (`core` + `std` + local `pantau_tap` only). All policy, parsing, state
//! transitions, shared-memory snapshot publishing, HUD rasterization, Jejak encoding, and JSON
//! formatting live here; the C++ `pantaud` daemon is a thin Binder + SurfaceControl shim.

pub mod abi;
pub mod ffi;
pub mod hud;
pub mod jejak;
pub mod json;
pub mod life;
pub mod parse;
pub mod sampler;
pub mod schema;
pub mod sys;

use core::mem::size_of;

use abi::{Snapshot, SnapshotCopy};
use hud::layout::{HudCompositor, HudWidgetPlan};
use life::{LifeActions, LifeMachine};
use sampler::{Sampler, Scratch};
use schema::HudProfile;
use sys::{boottime_ns, close_fd, create_sealed_memfd, munmap_region, tune_daemon_thread, RawFd};

/// Event kinds pushed from `PentasService` via `IPantau::event(kind, a, b)`.
#[repr(u32)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum EventKind {
    ThermalStatus = 1,   // a = status, b = headroom_permille
    DisplayMode = 2,     // a = refresh_hz, b = render_hz
    BatteryChanged = 3,  // a = capacity_pct, b = (charging << 16) | (deci_c & 0xffff)
    WifiLink = 4,        // a = rssi_dbm, b = (link_mbps << 16) | tx_retries_s
    CellLink = 5,        // a = level, b = link_type
    NetUidBytes = 6,     // a = rx_bps, b = tx_bps
    ScreenState = 7,     // a = 1 (on) / 0 (off)
    HudPin = 8,          // a = 1 (pin) / 0 (unpin)
}

/// Complete daemon runtime owned behind an opaque pointer by `pantaud`.
pub struct Engine {
    life: LifeMachine,
    sampler: Sampler,
    hud: HudCompositor,
    scratch: Box<Scratch>,
    work_snap: Box<SnapshotCopy>,
    shm_fd: RawFd,
    shm_ptr: *mut Snapshot,
    last_actions: LifeActions,
    is_landscape: bool,
    json_buf: Box<[u8; 8192]>,
}

impl Engine {
    /// Creates the engine, discovers hardware topology once, seals the shared-memory snapshot,
    /// and optionally pins the daemon thread to the efficiency CPU cluster (`policy0`).
    pub fn new(tune_thread: bool) -> Option<Self> {
        let sampler = Sampler::discover();
        if tune_thread {
            tune_daemon_thread(sampler.little_cpu_mask(), 50_000_000);
        }
        let (shm_fd, raw_ptr) = create_sealed_memfd(b"pantau_snap\0", size_of::<Snapshot>())?;
        let shm_ptr = raw_ptr as *mut Snapshot;
        // SAFETY: `shm_ptr` is a freshly created `size_of::<Snapshot>()` page-aligned mapping.
        unsafe {
            (*shm_ptr).init_in_place();
        }
        Some(Self {
            life: LifeMachine::new(),
            sampler,
            hud: HudCompositor::new(),
            scratch: Box::new(Scratch::default()),
            work_snap: Box::new(SnapshotCopy::default()),
            shm_fd,
            shm_ptr,
            last_actions: LifeActions::default(),
            is_landscape: false,
            json_buf: Box::new([0u8; 8192]),
        })
    }

    #[inline]
    pub fn snapshot_fd(&self) -> RawFd {
        self.shm_fd
    }

    #[inline]
    pub fn snapshot_copy(&self) -> &SnapshotCopy {
        &self.work_snap
    }

    #[inline]
    pub fn actions(&self) -> LifeActions {
        self.last_actions
    }

    pub fn configure(&mut self, profile_bytes: &[u8]) -> LifeActions {
        let p = HudProfile::parse(profile_bytes);
        if p == *self.life.profile() && self.work_snap.tick_boottime_ns != 0 {
            return self.last_actions;
        }
        let now = boottime_ns();
        self.last_actions = self.life.set_profile(p, now);
        if self.last_actions.active_consumers != 0 && self.work_snap.tick_boottime_ns == 0 {
            self.tick_at(now);
        }
        self.last_actions
    }

    /// Guarantees the shared-memory Snapshot has at least one live sample before a client maps it.
    pub fn ensure_fresh_snapshot(&mut self) {
        let now = boottime_ns();
        let stale = self.work_snap.tick_boottime_ns == 0
            || now.saturating_sub(self.work_snap.tick_boottime_ns) > 1_500_000_000;
        if stale {
            let m = self.last_actions.active_consumers | schema::mask::PANEL_HOME;
            self.sampler.tick(m, self.last_actions.focused_uid, now, &mut self.scratch, &mut self.work_snap);
            let hud = &self.hud;
            self.work_snap.procs.apply_labels(|u| hud.uid_label(u));
            self.publish();
        }
    }

    /// Returns true if `uid` is present in the active process table and triggered a display update.
    pub fn put_uid_meta(&mut self, uid: u32, label: &[u8], rgba: &[u8]) -> bool {
        self.hud.put_uid_meta(uid, label, rgba);
        let n = (self.work_snap.procs.count as usize).min(abi::MAX_PROCS);
        let visible_hit = self.work_snap.procs.rows[..n].iter().any(|r| r.uid == uid);
        if visible_hit && !label.is_empty() {
            let hud = &self.hud;
            self.work_snap.procs.apply_labels(|u| hud.uid_label(u));
            self.publish();
        }
        visible_hit
    }

    /// Returns true if any network metadata field changed.
    #[allow(clippy::too_many_arguments)]
    pub fn push_net_meta(
        &mut self,
        link_mask: u8,
        wifi_standard: u8,
        wifi_freq_mhz: u16,
        wifi_link_mbps: u16,
        wifi_rssi_dbm: i16,
        cell_gen: u8,
        cell_level: u8,
        cell_rsrp_dbm: i16,
    ) -> bool {
        let n = &mut self.work_snap.net;
        let changed = n.link_type != link_mask
            || n.wifi_standard != wifi_standard
            || n.wifi_freq_mhz != wifi_freq_mhz
            || n.wifi_link_mbps != wifi_link_mbps
            || n.wifi_rssi_dbm != wifi_rssi_dbm
            || n.cell_gen != cell_gen
            || n.cell_level != cell_level
            || n.cell_rsrp_dbm != cell_rsrp_dbm;
        if !changed {
            return false;
        }
        n.link_type = link_mask;
        n.wifi_standard = wifi_standard;
        n.wifi_freq_mhz = wifi_freq_mhz;
        n.wifi_link_mbps = wifi_link_mbps;
        n.wifi_rssi_dbm = wifi_rssi_dbm;
        n.cell_gen = cell_gen;
        n.cell_level = cell_level;
        n.cell_rsrp_dbm = cell_rsrp_dbm;
        self.publish();
        true
    }

    pub fn on_session(&mut self, task_id: i32, uid: i32, is_game: bool) -> LifeActions {
        let now = boottime_ns();
        let prev_uid = self.work_snap.fps.focused_uid;
        let prev_task = self.last_actions.focused_task_id;
        let prev_active = self.last_actions.active_consumers;
        if uid >= 0 && is_game && (uid as u32) != prev_uid {
            self.sampler.reset_session_energy();
            self.work_snap.fps.current_x100 = 0;
            self.work_snap.hist.fps_head = 0;
            self.work_snap.hist.fps_len = 0;
        }
        self.last_actions = self.life.on_session(task_id, uid, is_game, now);
        self.work_snap.fps.task_id = self.last_actions.focused_task_id;
        self.work_snap.fps.focused_uid = self.last_actions.focused_uid;
        let newly_active = (self.last_actions.active_consumers & !prev_active) != 0
            || self.work_snap.tick_boottime_ns == 0
            || task_id != prev_task;
        if self.last_actions.active_consumers != 0 && newly_active {
            self.tick_at(now);
        }
        self.last_actions
    }

    pub fn set_panel_consumers(&mut self, consumers: u64) -> LifeActions {
        let now = boottime_ns();
        let prev_active = self.last_actions.active_consumers;
        self.last_actions = self.life.set_panel_consumers(consumers, now);
        let newly_requested = (self.last_actions.active_consumers & !prev_active) != 0;
        if self.last_actions.active_consumers != 0
            && (newly_requested || self.work_snap.tick_boottime_ns == 0)
        {
            self.tick_at(now);
        }
        self.last_actions
    }

    pub fn on_fps(&mut self, fps_x100: u16) {
        self.work_snap.fps.current_x100 = fps_x100;
        self.work_snap.hist.push_fps(fps_x100);
        self.publish();
    }

    pub fn display_changed(&mut self, rotation: u8, width_px: u32, height_px: u32, refresh_hz: u16) {
        self.is_landscape = (rotation == 1 || rotation == 3) || (width_px > height_px);
        self.hud.set_display(rotation, width_px, height_px);
        if refresh_hz > 0 {
            if self.work_snap.display.refresh_hz != 0 && self.work_snap.display.refresh_hz != refresh_hz {
                self.work_snap.display.mode_switches =
                    self.work_snap.display.mode_switches.saturating_add(1);
            }
            self.work_snap.display.refresh_hz = refresh_hz;
            self.publish();
        }
    }

    pub fn set_monet(&mut self, argb: &[u32; 4]) {
        self.hud.set_monet_argb(argb);
    }

    pub fn move_widget(&mut self, widget_idx: usize, x: i32, y: i32) {
        self.life.move_widget(widget_idx, self.is_landscape, x, y);
    }

    pub fn hud_plan(&mut self, widget_idx: usize) -> HudWidgetPlan {
        self.hud.plan_widget(
            widget_idx,
            self.last_actions.hud_visible,
            self.life.profile(),
            &self.work_snap,
        )
    }

    pub fn hud_render(
        &mut self,
        widget_idx: usize,
        dst: &mut [u8],
        stride_px: usize,
        slot_idx: usize,
    ) -> u32 {
        let us = self.hud.render_widget(widget_idx, dst, stride_px, slot_idx);
        // Stored for the next tick's single publish() — avoids N redundant 4 KB memfd copies/tick.
        self.work_snap.self_draw_us = us;
        us
    }

    pub fn on_event(&mut self, kind: u32, a: i64, b: i64) -> LifeActions {
        let now = boottime_ns();
        match kind {
            1 => {
                self.work_snap.thermal.hal_status = a.clamp(0, 255) as u8;
                self.work_snap.thermal.hal_headroom_permille = b.clamp(0, 2000) as u16;
            }
            2 => {
                let hz = a.clamp(0, u16::MAX as i64) as u16;
                if self.work_snap.display.refresh_hz != 0 && self.work_snap.display.refresh_hz != hz
                {
                    self.work_snap.display.mode_switches =
                        self.work_snap.display.mode_switches.saturating_add(1);
                }
                self.work_snap.display.refresh_hz = hz;
                self.work_snap.display.render_hz = b.clamp(0, u16::MAX as i64) as u16;
            }
            3 => {
                self.work_snap.power.capacity_pct = a.clamp(0, 100) as u8;
                self.work_snap.power.charging = ((b >> 16) != 0) as u8;
                self.work_snap.thermal.bat_deci_c = (b & 0xffff) as i16;
            }
            4 => {
                self.work_snap.net.wifi_rssi_dbm = a.clamp(i16::MIN as i64, i16::MAX as i64) as i16;
                self.work_snap.net.wifi_link_mbps = ((b >> 16) & 0xffff) as u16;
                self.work_snap.net.wifi_tx_retries_s = (b & 0xffff) as u16;
                self.work_snap.net.link_type = 1;
            }
            5 => {
                self.work_snap.net.cell_level = a.clamp(0, 255) as u8;
                self.work_snap.net.link_type = b.clamp(0, 255) as u8;
            }
            6 => {
                self.work_snap.net.rx_bps = a.clamp(0, u32::MAX as i64) as u32;
                self.work_snap.net.tx_bps = b.clamp(0, u32::MAX as i64) as u32;
            }
            7 => {
                self.last_actions = self.life.on_screen(a != 0, now);
            }
            8 => {
                self.last_actions = self.life.on_hud_pin(a != 0, now);
            }
            _ => {}
        }
        self.work_snap.life_state = self.last_actions.state;
        self.publish();
        self.last_actions
    }

    /// Periodic 1 Hz tick (0 heap allocations).
    pub fn tick(&mut self) -> LifeActions {
        self.tick_at(boottime_ns())
    }

    pub fn tick_at(&mut self, now_ns: u64) -> LifeActions {
        self.last_actions = self.life.on_tick(now_ns);
        self.work_snap.life_state = self.last_actions.state;
        if self.last_actions.active_consumers != 0 {
            self.sampler.tick(
                self.last_actions.active_consumers,
                self.last_actions.focused_uid,
                now_ns,
                &mut self.scratch,
                &mut self.work_snap,
            );
            let hud = &self.hud;
            self.work_snap.procs.apply_labels(|u| hud.uid_label(u));
            self.publish();
        }
        self.last_actions
    }

    /// Handles `cmd pantau <cmd>` JSON queries into the internal scratch buffer (0 alloc).
    pub fn query_json(&mut self, cmd: &[u8]) -> &[u8] {
        let n = match cmd {
            b"status" => json::emit_status(&mut self.json_buf[..], &self.last_actions, &self.work_snap),
            b"snap" => {
                // Force one fresh sample if idle/stale so `cmd pantau snap` never returns zeros.
                self.ensure_fresh_snapshot();
                json::emit_snapshot(&mut self.json_buf[..], &self.work_snap)
            }
            _ => {
                let err = b"{\"v\":1,\"error\":\"unknown_cmd\"}\n";
                self.json_buf[..err.len()].copy_from_slice(err);
                err.len()
            }
        };
        &self.json_buf[..n]
    }

    #[inline]
    fn publish(&mut self) {
        // SAFETY: `self.shm_ptr` stays mapped for the lifetime of `Engine`.
        unsafe {
            (*self.shm_ptr).publish_from(&self.work_snap);
        }
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        // SAFETY: `shm_ptr` was mapped with `size_of::<Snapshot>()` in `Engine::new`.
        unsafe {
            munmap_region(self.shm_ptr as *mut u8, size_of::<Snapshot>());
        }
        close_fd(self.shm_fd);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn engine_memfd_tick_and_json_queries() {
        let mut eng = Engine::new(false).expect("Engine::new");
        assert!(eng.snapshot_fd() >= 0);

        let a = eng.on_session(42, 10042, true);
        assert_eq!(a.state, life::LifeState::Session as u8);
        assert_eq!(a.timer_ms, 0);
        assert!(a.allow_exit);

        let a = eng.set_panel_consumers(schema::mask::PANEL_HOME);
        assert_eq!(a.timer_ms, 1000);
        assert!(!a.allow_exit);

        eng.on_fps(11985);
        eng.tick();

        let status = core::str::from_utf8(eng.query_json(b"status")).unwrap();
        assert!(status.contains("\"state\":\"session\""));
        assert!(status.contains("\"focused_task_id\":42"));

        let snap = core::str::from_utf8(eng.query_json(b"snap")).unwrap();
        assert!(snap.contains("\"current_x100\":11985"));
    }
}
