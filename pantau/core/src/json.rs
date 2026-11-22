// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: Apache-2.0

//! Zero-allocation streaming JSON writer (`"v": 1`) for `cmd pantau` and AI automation.
//!
//! Writes directly into a reusable `&mut [u8]` or pre-reserved `Vec<u8>` scratch buffer with zero
//! `serde` dependencies and zero `core::fmt` overhead.

use crate::abi::SnapshotCopy;
use crate::life::LifeActions;

pub struct JsonBuf<'a> {
    buf: &'a mut [u8],
    pos: usize,
    truncated: bool,
}

impl<'a> JsonBuf<'a> {
    pub fn new(buf: &'a mut [u8]) -> Self {
        Self {
            buf,
            pos: 0,
            truncated: false,
        }
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.pos
    }

    #[inline]
    pub fn is_truncated(&self) -> bool {
        self.truncated
    }

    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.pos]
    }

    #[inline]
    pub fn raw(&mut self, s: &[u8]) {
        if self.pos + s.len() <= self.buf.len() {
            self.buf[self.pos..self.pos + s.len()].copy_from_slice(s);
            self.pos += s.len();
        } else {
            self.truncated = true;
        }
    }

    #[inline]
    pub fn byte(&mut self, b: u8) {
        if self.pos < self.buf.len() {
            self.buf[self.pos] = b;
            self.pos += 1;
        } else {
            self.truncated = true;
        }
    }

    pub fn u64(&mut self, mut v: u64) {
        if v == 0 {
            self.byte(b'0');
            return;
        }
        let mut tmp = [0u8; 20];
        let mut n = 0;
        while v > 0 {
            tmp[n] = b'0' + (v % 10) as u8;
            v /= 10;
            n += 1;
        }
        while n > 0 {
            n -= 1;
            self.byte(tmp[n]);
        }
    }

    pub fn i64(&mut self, v: i64) {
        if v < 0 {
            self.byte(b'-');
            self.u64(v.unsigned_abs());
        } else {
            self.u64(v as u64);
        }
    }

    /// Writes fixed-point tenths (`455` → `45.5`).
    pub fn fixed1(&mut self, v: i64) {
        if v < 0 {
            self.byte(b'-');
        }
        let mag = v.unsigned_abs();
        self.u64(mag / 10);
        self.byte(b'.');
        self.byte(b'0' + (mag % 10) as u8);
    }

    /// Writes fixed-point hundredths (`748` → `7.48`).
    pub fn fixed2(&mut self, v: u64) {
        self.u64(v / 100);
        self.byte(b'.');
        let frac = v % 100;
        self.byte(b'0' + (frac / 10) as u8);
        self.byte(b'0' + (frac % 10) as u8);
    }

    pub fn bool(&mut self, v: bool) {
        self.raw(if v { b"true" } else { b"false" });
    }

    /// Writes a JSON-escaped quoted string from arbitrary bytes (ASCII-safe, never allocates).
    pub fn str_bytes(&mut self, s: &[u8]) {
        self.byte(b'"');
        for &b in s {
            match b {
                b'"' => self.raw(b"\\\""),
                b'\\' => self.raw(b"\\\\"),
                b'\n' => self.raw(b"\\n"),
                b'\r' => self.raw(b"\\r"),
                b'\t' => self.raw(b"\\t"),
                0x20..=0x7e => self.byte(b),
                _ => {
                    const HEX: &[u8; 16] = b"0123456789abcdef";
                    self.raw(b"\\u00");
                    self.byte(HEX[(b >> 4) as usize]);
                    self.byte(HEX[(b & 0xf) as usize]);
                }
            }
        }
        self.byte(b'"');
    }

    #[inline]
    pub fn kv_u64(&mut self, comma: bool, k: &[u8], v: u64) {
        if comma { self.byte(b','); }
        self.byte(b'"');
        self.raw(k);
        self.raw(b"\":");
        self.u64(v);
    }

    #[inline]
    pub fn kv_i64(&mut self, comma: bool, k: &[u8], v: i64) {
        if comma { self.byte(b','); }
        self.byte(b'"');
        self.raw(k);
        self.raw(b"\":");
        self.i64(v);
    }

    #[inline]
    pub fn kv_bool(&mut self, comma: bool, k: &[u8], v: bool) {
        if comma { self.byte(b','); }
        self.byte(b'"');
        self.raw(k);
        self.raw(b"\":");
        self.bool(v);
    }

    #[inline]
    pub fn kv_str(&mut self, comma: bool, k: &[u8], v: &[u8]) {
        if comma { self.byte(b','); }
        self.byte(b'"');
        self.raw(k);
        self.raw(b"\":");
        self.str_bytes(v);
    }
}

pub fn state_name(s: u8) -> &'static [u8] {
    match s {
        0 => b"off",
        1 => b"session",
        2 => b"pinned",
        3 => b"suspended",
        4 => b"diagnostic",
        _ => b"unknown",
    }
}

/// Emits `cmd pantau status --json` payload into `dst` (0 heap allocations).
pub fn emit_status(dst: &mut [u8], actions: &LifeActions, snap: &SnapshotCopy) -> usize {
    let mut j = JsonBuf::new(dst);
    j.byte(b'{');
    j.kv_u64(false, b"v", 1);
    j.kv_str(true, b"state", state_name(actions.state));
    j.kv_bool(true, b"hud_visible", actions.hud_visible);
    j.kv_u64(true, b"timer_ms", actions.timer_ms as u64);
    j.kv_u64(true, b"consumers_mask", actions.active_consumers);
    j.kv_i64(true, b"focused_task_id", actions.focused_task_id as i64);
    j.kv_u64(true, b"focused_uid", actions.focused_uid as u64);
    j.raw(b",\"self\":{");
    j.kv_u64(false, b"tick_us", snap.self_tick_us as u64);
    j.kv_u64(true, b"draw_us", snap.self_draw_us as u64);
    j.kv_u64(true, b"drops", snap.self_drops as u64);
    j.kv_u64(true, b"rss_kb", snap.self_rss_kb as u64);
    j.kv_str(
        true,
        b"hud_hwc",
        if snap.hud_hwc_client != 0 { b"client" } else { b"device" },
    );
    j.raw(b"}}\n");
    j.len()
}

/// Emits `cmd pantau snap --json` payload into `dst` (0 heap allocations).
pub fn emit_snapshot(dst: &mut [u8], snap: &SnapshotCopy) -> usize {
    let mut j = JsonBuf::new(dst);
    j.byte(b'{');
    j.kv_u64(false, b"v", 1);
    j.kv_u64(true, b"tick_boottime_ns", snap.tick_boottime_ns);
    j.kv_u64(true, b"valid_mask", snap.valid_mask);
    j.kv_str(true, b"state", state_name(snap.life_state));

    // CPU
    j.raw(b",\"cpu\":{");
    j.kv_u64(false, b"total_permille", snap.cpu.total_permille as u64);
    j.kv_u64(true, b"max_khz", snap.cpu.max_freq_khz as u64);
    j.kv_bool(true, b"capped", snap.cpu.ceiling_capped != 0);
    j.kv_u64(true, b"ctxt_s", snap.cpu.ctxt_per_sec as u64);
    j.kv_u64(true, b"irq_s", snap.cpu.irq_per_sec as u64);
    j.raw(b",\"clusters\":[");
    for i in 0..(snap.num_clusters as usize).min(snap.cpu.clusters.len()) {
        let c = &snap.cpu.clusters[i];
        if i > 0 { j.byte(b','); }
        j.byte(b'{');
        j.kv_u64(false, b"mask", c.cpu_mask as u64);
        j.kv_u64(true, b"cur_khz", c.cur_khz as u64);
        j.kv_u64(true, b"cap_khz", c.scaling_max_khz as u64);
        j.kv_u64(true, b"hw_max_khz", c.hw_max_khz as u64);
        j.kv_u64(true, b"util_permille", c.util_permille as u64);
        j.byte(b'}');
    }
    j.raw(b"]}");

    // GPU
    j.raw(b",\"gpu\":{");
    j.kv_u64(false, b"busy_permille", snap.gpu.busy_permille as u64);
    j.kv_u64(true, b"cur_mhz", snap.gpu.cur_mhz as u64);
    j.kv_u64(true, b"avg_mhz", snap.gpu.avg_mhz as u64);
    j.kv_u64(true, b"cap_mhz", snap.gpu.cap_mhz as u64);
    j.kv_u64(true, b"hw_max_mhz", snap.gpu.hw_max_mhz as u64);
    j.kv_bool(true, b"capped", snap.gpu.ceiling_capped != 0);
    j.kv_u64(true, b"thermal_pwrlevel", snap.gpu.thermal_pwrlevel as u64);
    j.byte(b'}');

    // Thermal (deci-C)
    j.raw(b",\"thermal\":{");
    j.kv_i64(false, b"cpu_c10", snap.thermal.cpu_deci_c as i64);
    j.kv_i64(true, b"gpu_c10", snap.thermal.gpu_deci_c as i64);
    j.kv_i64(true, b"ddr_c10", snap.thermal.ddr_deci_c as i64);
    j.kv_i64(true, b"skin_c10", snap.thermal.skin_deci_c as i64);
    j.kv_i64(true, b"bat_c10", snap.thermal.bat_deci_c as i64);
    j.kv_u64(true, b"cpu_heat_permille", snap.thermal.cpu_heat_permille as u64);
    j.kv_u64(true, b"gpu_heat_permille", snap.thermal.gpu_heat_permille as u64);
    j.kv_bool(true, b"headroom_reduced", snap.thermal.headroom_reduced != 0);
    j.byte(b'}');

    // Memory
    j.raw(b",\"mem\":{");
    j.kv_u64(false, b"total_kb", snap.mem.total_kb as u64);
    j.kv_u64(true, b"avail_kb", snap.mem.avail_kb as u64);
    j.kv_u64(true, b"used_kb", snap.mem.used_kb as u64);
    j.kv_u64(true, b"swap_total_kb", snap.mem.swap_total_kb as u64);
    j.kv_u64(true, b"swap_used_kb", snap.mem.swap_used_kb as u64);
    j.kv_u64(true, b"zram_ratio_permille", snap.mem.zram_ratio_permille as u64);
    j.kv_u64(true, b"game_mem_kb", snap.mem.game_mem_kb as u64);
    j.byte(b'}');

    // Power
    j.raw(b",\"power\":{");
    j.kv_u64(false, b"power_mw", snap.power.power_mw as u64);
    j.kv_i64(true, b"current_ua", snap.power.current_ua as i64);
    j.kv_u64(true, b"voltage_uv", snap.power.voltage_uv as u64);
    j.kv_u64(true, b"capacity_pct", snap.power.capacity_pct as u64);
    j.kv_bool(true, b"charging", snap.power.charging != 0);
    j.kv_u64(true, b"session_uah", snap.power.session_uah as u64);
    j.kv_u64(true, b"mj_per_frame_x10", snap.power.mj_per_frame_x10 as u64);
    j.byte(b'}');

    // Network (unified Wi-Fi + Mobile Data + passive TCP RTT)
    j.raw(b",\"net\":{");
    j.kv_u64(false, b"rx_bps", snap.net.rx_bps as u64);
    j.kv_u64(true, b"tx_bps", snap.net.tx_bps as u64);
    j.kv_u64(true, b"wifi_rx_bps", snap.net.wifi_rx_bps as u64);
    j.kv_u64(true, b"cell_rx_bps", snap.net.cell_rx_bps as u64);
    j.kv_u64(true, b"wifi_session_kb", snap.net.wifi_session_kb as u64);
    j.kv_u64(true, b"cell_session_kb", snap.net.cell_session_kb as u64);
    j.kv_u64(true, b"rtt_us", snap.net.tcp_rtt_us as u64);
    j.kv_u64(true, b"rttvar_us", snap.net.tcp_rttvar_us as u64);
    j.kv_u64(true, b"retrans_s", snap.net.tcp_retrans_s as u64);
    j.kv_i64(true, b"wifi_rssi_dbm", snap.net.wifi_rssi_dbm as i64);
    j.kv_i64(true, b"cell_rsrp_dbm", snap.net.cell_rsrp_dbm as i64);
    j.kv_u64(true, b"wifi_std", snap.net.wifi_standard as u64);
    j.kv_u64(true, b"cell_gen", snap.net.cell_gen as u64);
    j.kv_u64(true, b"link_mask", snap.net.link_type as u64);
    j.byte(b'}');

    // FPS & Display
    j.raw(b",\"fps\":{");
    j.kv_u64(false, b"current_x100", snap.fps.current_x100 as u64);
    j.kv_i64(true, b"task_id", snap.fps.task_id as i64);
    j.kv_u64(true, b"refresh_hz", snap.display.refresh_hz as u64);
    j.kv_u64(true, b"render_hz", snap.display.render_hz as u64);
    j.byte(b'}');

    // PSI
    j.raw(b",\"psi\":{");
    j.kv_u64(false, b"cpu_some_x100", snap.psi.cpu_some_avg10 as u64);
    j.kv_u64(true, b"mem_full_x100", snap.psi.mem_full_avg10 as u64);
    j.kv_u64(true, b"io_full_x100", snap.psi.io_full_avg10 as u64);
    j.byte(b'}');

    // Top procs (if populated)
    j.raw(b",\"procs\":[");
    for i in 0..(snap.procs.count as usize).min(snap.procs.rows.len()) {
        let r = &snap.procs.rows[i];
        if i > 0 { j.byte(b','); }
        j.byte(b'{');
        j.kv_u64(false, b"uid", r.uid as u64);
        j.kv_u64(true, b"cpu_permille", r.cpu_permille as u64);
        j.kv_u64(true, b"mem_kb", r.mem_kb as u64);
        j.kv_bool(true, b"system", r.is_system != 0);
        j.kv_str(true, b"name", snap.procs.name_of(r));
        j.byte(b'}');
    }
    j.raw(b"]");

    // Self overhead
    j.raw(b",\"self\":{");
    j.kv_u64(false, b"tick_us", snap.self_tick_us as u64);
    j.kv_u64(true, b"draw_us", snap.self_draw_us as u64);
    j.kv_u64(true, b"rss_kb", snap.self_rss_kb as u64);
    j.raw(b"}}\n");
    j.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emits_valid_compact_json_zero_alloc() {
        let mut buf = [0u8; 4096];
        let mut s = SnapshotCopy::default();
        s.tick_boottime_ns = 999;
        s.cpu.total_permille = 415;
        s.thermal.cpu_deci_c = 455;
        s.procs.push(10042, 0, 180, 200_000, false, b"uid_10042");

        let n = emit_snapshot(&mut buf, &s);
        let text = core::str::from_utf8(&buf[..n]).unwrap();
        assert!(text.starts_with("{\"v\":1,\"tick_boottime_ns\":999"));
        assert!(text.contains("\"cpu_c10\":455"));
        assert!(text.contains("\"name\":\"uid_10042\""));
        assert!(text.ends_with("}\n"));
    }
}
