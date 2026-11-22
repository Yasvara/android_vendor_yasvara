// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: Apache-2.0

//! Persistent-FD, demand-driven telemetry sampler (zero heap allocation after `init`).
//!
//! Hardware topology (CPU policies, thermal zones & trip points, Adreno kgsl, fuel gauge, zram,
//! PSI) is discovered once at startup. Every tick reads only nodes whose consumer bit is active
//! and whose cadence period is due, via `pread(fd, &mut scratch, 0)`.

pub mod cgroup;
pub mod net;

use std::fs;

use crate::abi::{ClusterSnap, SnapshotCopy, MAX_CLUSTERS, MAX_CORES};
use crate::parse::{
    gpu_avg_mhz_from_trans, normalize_temp_deci_c, parse_cpu_mask, parse_gpu_busy_permille,
    parse_i64, parse_meminfo, parse_proc_stat, parse_psi, parse_trans_stat, parse_u64,
    parse_vm_rss_kb, parse_zram_mm_stat, raw_gpu_freq_to_mhz, GpuTransRaw, MemInfoRaw,
    ProcStatRaw, PsiRaw, ZramStatRaw,
};
use crate::schema::mask;
use crate::sys::{close_fd, open_ro, open_ro_cstr, pread_zero, thread_cpu_ns, RawFd};

use cgroup::CgroupScanner;
use net::NetSampler;

const MAX_THERM_ZONES: usize = 16;

#[derive(Copy, Clone)]
struct ClusterFds {
    cpu_mask: u32,
    cur_fd: RawFd,
    max_fd: RawFd,
    hw_max_khz: u32,
}

impl Default for ClusterFds {
    fn default() -> Self {
        Self {
            cpu_mask: 0,
            cur_fd: -1,
            max_fd: -1,
            hw_max_khz: 0,
        }
    }
}

/// Reusable scratch arena pre-allocated once at daemon init (0 heap allocations on tick).
pub struct Scratch {
    pub io_buf: [u8; 8192],
    pub proc_stat: ProcStatRaw,
    pub meminfo: MemInfoRaw,
    pub trans_cur: GpuTransRaw,
    pub zram: ZramStatRaw,
    pub psi: PsiRaw,
}

impl Default for Scratch {
    fn default() -> Self {
        Self {
            io_buf: [0u8; 8192],
            proc_stat: ProcStatRaw::default(),
            meminfo: MemInfoRaw::default(),
            trans_cur: GpuTransRaw::default(),
            zram: ZramStatRaw::default(),
            psi: PsiRaw::default(),
        }
    }
}

pub struct Sampler {
    // Persistent FDs
    fd_proc_stat: RawFd,
    fd_meminfo: RawFd,
    fd_self_status: RawFd,
    fd_zram_mm: RawFd,
    fd_psi_cpu: RawFd,
    fd_psi_mem: RawFd,
    fd_psi_io: RawFd,

    // Per-core cur freq fds
    core_cur_fds: [RawFd; MAX_CORES],
    num_cores: usize,

    // CPU clusters
    clusters: [ClusterFds; MAX_CLUSTERS],
    num_clusters: usize,
    little_cpu_mask: u64,

    // Thermal zone fds (grouped by domain; hottest index refreshed every 10 ticks)
    cpu_temp_fds: [RawFd; MAX_THERM_ZONES],
    cpu_temp_count: usize,
    hottest_cpu_idx: usize,
    gpu_temp_fds: [RawFd; MAX_THERM_ZONES],
    gpu_temp_count: usize,
    hottest_gpu_idx: usize,
    fd_ddr_temp: RawFd,
    fd_skin_temp: RawFd,
    cpu_trip_deci_c: i16,
    gpu_trip_deci_c: i16,

    // GPU (Adreno kgsl)
    fd_gpu_trans: RawFd,
    fd_gpu_busy_pct: RawFd,
    fd_gpu_clk: RawFd,
    fd_gpu_max: RawFd,
    fd_gpu_therm_lvl: RawFd,
    gpu_hw_max_mhz: u16,

    // Battery / power (read on slow cadence — fuel gauge I2C/GLINK costs ~0.7-1 ms/read!)
    fd_bat_temp: RawFd,
    fd_bat_cap: RawFd,
    fd_bat_cur_ua: RawFd,
    fd_bat_vol_uv: RawFd,
    fd_bat_charge_uah: RawFd,
    session_start_uah: Option<u64>,

    // Delta state
    stat_primed: bool,
    prev_stat: ProcStatRaw,
    prev_stat_ns: u64,
    prev_trans: GpuTransRaw,
    trans_primed: bool,
    prev_psi_cpu_us: u64,
    prev_psi_mem_us: u64,
    prev_psi_io_us: u64,

    // Adaptive cgroup scanner & unified network sampler
    cgroups: CgroupScanner,
    net: NetSampler,

    // Tick counter for per-node cadence gating
    tick_idx: u32,
}

impl Default for Sampler {
    fn default() -> Self {
        Self::discover()
    }
}

impl Sampler {
    /// Discovers platform topology and opens all persistent read-only fds once.
    pub fn discover() -> Self {
        let mut s = Self {
            fd_proc_stat: open_ro_cstr(b"/proc/stat\0"),
            fd_meminfo: open_ro_cstr(b"/proc/meminfo\0"),
            fd_self_status: open_ro_cstr(b"/proc/self/status\0"),
            fd_zram_mm: open_ro_cstr(b"/sys/block/zram0/mm_stat\0"),
            fd_psi_cpu: open_ro_cstr(b"/proc/pressure/cpu\0"),
            fd_psi_mem: open_ro_cstr(b"/proc/pressure/memory\0"),
            fd_psi_io: open_ro_cstr(b"/proc/pressure/io\0"),
            core_cur_fds: [-1; MAX_CORES],
            num_cores: 0,
            clusters: [ClusterFds::default(); MAX_CLUSTERS],
            num_clusters: 0,
            little_cpu_mask: 0,
            cpu_temp_fds: [-1; MAX_THERM_ZONES],
            cpu_temp_count: 0,
            hottest_cpu_idx: 0,
            gpu_temp_fds: [-1; MAX_THERM_ZONES],
            gpu_temp_count: 0,
            hottest_gpu_idx: 0,
            fd_ddr_temp: -1,
            fd_skin_temp: -1,
            cpu_trip_deci_c: 950,
            gpu_trip_deci_c: 950,
            fd_gpu_trans: open_ro_cstr(b"/sys/class/kgsl/kgsl-3d0/devfreq/trans_stat\0"),
            fd_gpu_busy_pct: open_ro_cstr(b"/sys/class/kgsl/kgsl-3d0/gpu_busy_percentage\0"),
            fd_gpu_clk: open_ro_cstr(b"/sys/class/kgsl/kgsl-3d0/gpuclk\0"),
            fd_gpu_max: open_ro_cstr(b"/sys/class/kgsl/kgsl-3d0/devfreq/max_freq\0"),
            fd_gpu_therm_lvl: open_ro_cstr(b"/sys/class/kgsl/kgsl-3d0/thermal_pwrlevel\0"),
            gpu_hw_max_mhz: 0,
            fd_bat_temp: open_ro_cstr(b"/sys/class/power_supply/battery/temp\0"),
            fd_bat_cap: open_ro_cstr(b"/sys/class/power_supply/battery/capacity\0"),
            fd_bat_cur_ua: open_ro_cstr(b"/sys/class/power_supply/battery/current_now\0"),
            fd_bat_vol_uv: open_ro_cstr(b"/sys/class/power_supply/battery/voltage_now\0"),
            fd_bat_charge_uah: open_ro_cstr(b"/sys/class/power_supply/battery/charge_counter\0"),
            session_start_uah: None,
            stat_primed: false,
            prev_stat: ProcStatRaw::default(),
            prev_stat_ns: 0,
            prev_trans: GpuTransRaw::default(),
            trans_primed: false,
            prev_psi_cpu_us: 0,
            prev_psi_mem_us: 0,
            prev_psi_io_us: 0,
            cgroups: CgroupScanner::new(),
            net: NetSampler::new(),
            tick_idx: 0,
        };
        let mut scratch = Scratch::default();
        s.discover_cpu(&mut scratch);
        s.discover_thermal(&mut scratch);
        s.discover_gpu(&mut scratch);
        // Prime `/proc/stat` and `trans_stat` immediately so tick #1 already emits real deltas!
        if let Some(raw) = pread_zero(s.fd_proc_stat, &mut scratch.io_buf) {
            if parse_proc_stat(raw, &mut s.prev_stat) {
                s.stat_primed = true;
                s.num_cores = s.num_cores.max(s.prev_stat.num_cores);
            }
        }
        if let Some(raw) = pread_zero(s.fd_gpu_trans, &mut scratch.io_buf) {
            if parse_trans_stat(raw, &mut s.prev_trans) {
                s.trans_primed = true;
            }
        }
        s
    }

    /// Efficiency cluster bitmask (`policy0`, lowest `hw_max_khz`) for pinning `pantaud`.
    #[inline]
    pub fn little_cpu_mask(&self) -> u64 {
        self.little_cpu_mask
    }

    pub fn reset_session_energy(&mut self) {
        self.session_start_uah = None;
        self.net.reset_session();
    }

    /// Runs one demand-driven sampling tick into `snap` with **0 heap allocations**.
    pub fn tick(
        &mut self,
        consumers: u64,
        focused_uid: u32,
        now_ns: u64,
        scratch: &mut Scratch,
        snap: &mut SnapshotCopy,
    ) {
        let cpu_t0 = thread_cpu_ns();
        let tick = self.tick_idx;
        self.tick_idx = tick.wrapping_add(1);

        snap.tick_boottime_ns = now_ns;
        snap.valid_mask = consumers;
        snap.num_cores = self.num_cores as u8;
        snap.num_clusters = self.num_clusters as u8;

        // Staggered demand-driven cadence + instant fill when any domain has not yet populated:
        //   Every tick (1 Hz): /proc/stat + cluster cur_freq + kgsl trans_stat + gpu_busy + /proc/net/dev
        //   Even ticks (0.5 Hz): cluster scaling_max + gpu cap/therm_lvl + hottest thermal + power
        //   Odd ticks  (0.5 Hz): /proc/meminfo + cgroup procs / foreground threads (when visible)
        //   Every 10 ticks (0.1 Hz): full thermal-zone hottest sweep + zram + charge_counter + RSS
        if consumers & mask::CPU != 0 {
            self.sample_cpu(tick, now_ns, scratch, snap);
        }
        if consumers & mask::GPU != 0 {
            self.sample_gpu(tick, scratch, snap);
        }
        if (consumers & mask::THERMAL != 0)
            && (tick == 0 || tick % 2 == 0 || snap.thermal.cpu_deci_c == 0)
        {
            self.sample_thermal(tick, scratch, snap);
        }
        if (consumers & mask::MEM != 0) && (tick == 0 || tick % 2 == 1 || snap.mem.total_kb == 0) {
            self.sample_mem(tick, focused_uid, scratch, snap);
        }
        // Fuel-gauge nodes (`current_now`, `voltage_now`) cost ~1.5 ms combined on onyx:
        // sample at 0.5 Hz (every 2 ticks) when visible, or immediately on first open.
        if (consumers & mask::POWER != 0)
            && (tick == 0 || tick % 2 == 0 || snap.power.voltage_uv == 0)
        {
            self.sample_power(tick, scratch, snap);
        }
        if consumers & mask::NET != 0 {
            self.net.sample(tick, focused_uid, now_ns, &mut scratch.io_buf, snap);
        }
        if consumers & mask::PSI != 0 {
            self.sample_psi(scratch, snap);
        }
        if consumers & mask::THREADS != 0 {
            if tick == 0 || tick % 2 == 1 || snap.procs.count == 0 {
                self.cgroups.sample_threads(focused_uid, now_ns, &mut scratch.io_buf, &mut snap.procs);
            }
        } else if (consumers & mask::PROCS != 0)
            && (tick == 0 || tick % 2 == 1 || snap.procs.count == 0)
        {
            self.cgroups.sample(now_ns, self.num_cores.max(1), &mut scratch.io_buf, &mut snap.procs, true);
        }

        // Rolling metric histories (used for instant first-frame graphs in Pentas panel).
        if consumers & (mask::CPU | mask::GPU | mask::THERMAL) != 0 {
            snap.hist.push_metrics(
                (snap.cpu.total_permille / 10).min(100) as u8,
                (snap.gpu.busy_permille / 10).min(100) as u8,
                snap.thermal.cpu_deci_c,
            );
        }

        // Self-monitoring (staggered on tick % 10 == 7 for RSS, every tick for CPU µs).
        if tick == 0 || tick % 10 == 7 {
            if let Some(raw) = pread_zero(self.fd_self_status, &mut scratch.io_buf) {
                snap.self_rss_kb = parse_vm_rss_kb(raw);
            }
        }
        let cpu_t1 = thread_cpu_ns();
        snap.self_tick_us = (cpu_t1.saturating_sub(cpu_t0) / 1_000).min(u32::MAX as u64) as u32;
    }

    fn sample_cpu(&mut self, tick: u32, now_ns: u64, scratch: &mut Scratch, snap: &mut SnapshotCopy) {
        if let Some(raw) = pread_zero(self.fd_proc_stat, &mut scratch.io_buf) {
            if parse_proc_stat(raw, &mut scratch.proc_stat) {
                let cur = scratch.proc_stat;
                let dt_ms = if self.prev_stat_ns > 0 {
                    now_ns.saturating_sub(self.prev_stat_ns) / 1_000_000
                } else {
                    1000
                }
                .max(1);

                if self.stat_primed {
                    let dt = cur.agg_total.saturating_sub(self.prev_stat.agg_total);
                    let di = cur.agg_idle.saturating_sub(self.prev_stat.agg_idle);
                    snap.cpu.total_permille = if dt > 0 {
                        (dt.saturating_sub(di).saturating_mul(1000) / dt).min(1000) as u16
                    } else {
                        0
                    };
                    let nc = cur.num_cores.min(MAX_CORES);
                    for i in 0..nc {
                        let cdt = cur.core_total[i].saturating_sub(self.prev_stat.core_total[i]);
                        let cdi = cur.core_idle[i].saturating_sub(self.prev_stat.core_idle[i]);
                        snap.cpu.core_util_permille[i] = if cdt > 0 {
                            (cdt.saturating_sub(cdi).saturating_mul(1000) / cdt).min(1000) as u16
                        } else {
                            0
                        };
                    }
                    let d_ctxt = cur.ctxt.saturating_sub(self.prev_stat.ctxt);
                    let d_intr = cur.intr_total.saturating_sub(self.prev_stat.intr_total);
                    snap.cpu.ctxt_per_sec = ((d_ctxt * 1000) / dt_ms).min(u32::MAX as u64) as u32;
                    snap.cpu.irq_per_sec = ((d_intr * 1000) / dt_ms).min(u32::MAX as u64) as u32;
                }
                self.prev_stat = cur;
                self.prev_stat_ns = now_ns;
                self.stat_primed = true;
            }
        }

        // Per-cluster clocks (1 read/cluster at 1 Hz); thermal ceiling (`scaling_max_freq`) at 0.5 Hz.
        let read_caps = tick == 0 || tick % 2 == 0;
        let mut max_khz = 0u32;
        let mut any_cap = false;
        for ci in 0..self.num_clusters {
            let cl = self.clusters[ci];
            let cur_khz = pread_zero(cl.cur_fd, &mut scratch.io_buf)
                .and_then(parse_u64)
                .unwrap_or(0) as u32;
            let smax_khz = if read_caps {
                pread_zero(cl.max_fd, &mut scratch.io_buf)
                    .and_then(parse_u64)
                    .map(|v| v as u32)
                    .unwrap_or(cl.hw_max_khz)
            } else {
                let prev = snap.cpu.clusters[ci].scaling_max_khz;
                if prev > 0 { prev } else { cl.hw_max_khz }
            };
            let capped = smax_khz > 0 && smax_khz + 1_000 < cl.hw_max_khz;
            if capped {
                any_cap = true;
            }
            if cur_khz > max_khz {
                max_khz = cur_khz;
            }

            let mut u_sum = 0u32;
            let mut u_cnt = 0u32;
            for core in 0..self.num_cores.min(MAX_CORES) {
                if (cl.cpu_mask & (1u32 << core)) != 0 {
                    snap.cpu.core_freq_khz[core] = cur_khz;
                    u_sum += snap.cpu.core_util_permille[core] as u32;
                    u_cnt += 1;
                }
            }
            snap.cpu.clusters[ci] = ClusterSnap {
                cpu_mask: cl.cpu_mask,
                cur_khz,
                scaling_max_khz: smax_khz,
                hw_max_khz: cl.hw_max_khz,
                util_permille: if u_cnt > 0 { (u_sum / u_cnt) as u16 } else { 0 },
                capped: capped as u8,
                _pad: 0,
            };
        }
        snap.cpu.max_freq_khz = max_khz;
        snap.cpu.ceiling_capped = any_cap as u8;
    }

    fn sample_gpu(&mut self, tick: u32, scratch: &mut Scratch, snap: &mut SnapshotCopy) {
        // Weighted average + active clock from monotonic `devfreq/trans_stat` (1 read replaces 2!).
        let mut got_cur = false;
        if let Some(raw) = pread_zero(self.fd_gpu_trans, &mut scratch.io_buf) {
            if parse_trans_stat(raw, &mut scratch.trans_cur) {
                if self.trans_primed {
                    snap.gpu.avg_mhz = gpu_avg_mhz_from_trans(&self.prev_trans, &scratch.trans_cur);
                }
                let aidx = scratch.trans_cur.active_idx as usize;
                if aidx < scratch.trans_cur.count {
                    snap.gpu.cur_mhz = raw_gpu_freq_to_mhz(scratch.trans_cur.freq_hz[aidx]);
                    got_cur = true;
                }
                self.prev_trans = scratch.trans_cur;
                self.trans_primed = true;
            }
        }
        if !got_cur {
            if let Some(raw) = pread_zero(self.fd_gpu_clk, &mut scratch.io_buf) {
                if let Some(hz) = parse_u64(raw) {
                    if hz > 0 {
                        snap.gpu.cur_mhz = raw_gpu_freq_to_mhz(hz);
                    }
                }
            }
        }
        if let Some(raw) = pread_zero(self.fd_gpu_busy_pct, &mut scratch.io_buf) {
            if let Some(pm) = parse_gpu_busy_permille(raw) {
                snap.gpu.busy_permille = pm;
            }
        }
        // Thermal cap & pwrlevel change on slow thermal steps (0.5 Hz).
        if tick == 0 || tick % 2 == 0 {
            let cap_mhz = pread_zero(self.fd_gpu_max, &mut scratch.io_buf)
                .and_then(parse_u64)
                .map(raw_gpu_freq_to_mhz)
                .unwrap_or(0);
            snap.gpu.cap_mhz = cap_mhz;
            snap.gpu.hw_max_mhz = self.gpu_hw_max_mhz;
            snap.gpu.ceiling_capped =
                (cap_mhz > 0 && self.gpu_hw_max_mhz > 0 && cap_mhz + 1 < self.gpu_hw_max_mhz) as u8;

            if let Some(raw) = pread_zero(self.fd_gpu_therm_lvl, &mut scratch.io_buf) {
                if let Some(lvl) = parse_u64(raw) {
                    snap.gpu.thermal_pwrlevel = lvl.min(255) as u8;
                }
            }
        }
    }

    fn sample_thermal(&mut self, tick: u32, scratch: &mut Scratch, snap: &mut SnapshotCopy) {
        // Hot-zone tracking: sweep all 22+ die sensors only every 10 ticks (0.1 Hz) to identify
        // which sensor is hottest; on intermediate 0.5 Hz ticks read ONLY the tracked hottest zone
        // (18x fewer TSENS driver calls with identical peak temperature accuracy!).
        let full_sweep = tick % 10 == 0;
        let cpu_max = if full_sweep {
            let mut best = 0i16;
            let mut best_idx = 0usize;
            for i in 0..self.cpu_temp_count {
                if let Some(raw) = pread_zero(self.cpu_temp_fds[i], &mut scratch.io_buf) {
                    if let Some(v) = parse_i64(raw) {
                        let t = normalize_temp_deci_c(v, false);
                        if t > best {
                            best = t;
                            best_idx = i;
                        }
                    }
                }
            }
            self.hottest_cpu_idx = best_idx;
            best
        } else if self.cpu_temp_count > 0 {
            let fd = self.cpu_temp_fds[self.hottest_cpu_idx.min(self.cpu_temp_count - 1)];
            pread_zero(fd, &mut scratch.io_buf)
                .and_then(parse_i64)
                .map(|v| normalize_temp_deci_c(v, false))
                .unwrap_or(snap.thermal.cpu_deci_c)
        } else {
            0
        };

        let gpu_max = if full_sweep {
            let mut best = 0i16;
            let mut best_idx = 0usize;
            for i in 0..self.gpu_temp_count {
                if let Some(raw) = pread_zero(self.gpu_temp_fds[i], &mut scratch.io_buf) {
                    if let Some(v) = parse_i64(raw) {
                        let t = normalize_temp_deci_c(v, false);
                        if t > best {
                            best = t;
                            best_idx = i;
                        }
                    }
                }
            }
            self.hottest_gpu_idx = best_idx;
            best
        } else if self.gpu_temp_count > 0 {
            let fd = self.gpu_temp_fds[self.hottest_gpu_idx.min(self.gpu_temp_count - 1)];
            pread_zero(fd, &mut scratch.io_buf)
                .and_then(parse_i64)
                .map(|v| normalize_temp_deci_c(v, false))
                .unwrap_or(snap.thermal.gpu_deci_c)
        } else {
            0
        };

        let ddr = if full_sweep {
            pread_zero(self.fd_ddr_temp, &mut scratch.io_buf)
                .and_then(parse_i64)
                .map(|v| normalize_temp_deci_c(v, false))
                .unwrap_or(snap.thermal.ddr_deci_c)
        } else {
            snap.thermal.ddr_deci_c
        };
        // Skin (`quiet_therm`) is a slow PMIC ADC (~2.3 ms SPMI sleep): sample at 0.1 Hz staggered.
        let skin = if tick == 0 || tick % 10 == 4 {
            pread_zero(self.fd_skin_temp, &mut scratch.io_buf)
                .and_then(parse_i64)
                .map(|v| normalize_temp_deci_c(v, false))
                .unwrap_or(snap.thermal.skin_deci_c)
        } else {
            snap.thermal.skin_deci_c
        };
        // Battery temp arrives event-driven via ACTION_BATTERY_CHANGED; poll only at 0.1 Hz fallback.
        let bat = if tick == 0 || tick % 10 == 6 {
            pread_zero(self.fd_bat_temp, &mut scratch.io_buf)
                .and_then(parse_i64)
                .map(|v| normalize_temp_deci_c(v, true))
                .unwrap_or(snap.thermal.bat_deci_c)
        } else {
            snap.thermal.bat_deci_c
        };

        snap.thermal.cpu_deci_c = cpu_max;
        snap.thermal.gpu_deci_c = gpu_max;
        snap.thermal.ddr_deci_c = ddr;
        snap.thermal.skin_deci_c = skin;
        snap.thermal.bat_deci_c = bat;
        snap.thermal.cpu_trip_deci_c = self.cpu_trip_deci_c;
        snap.thermal.gpu_trip_deci_c = self.gpu_trip_deci_c;
        snap.thermal.cpu_heat_permille = if self.cpu_trip_deci_c > 0 && cpu_max > 0 {
            ((cpu_max as u32 * 1000) / self.cpu_trip_deci_c as u32).min(2000) as u16
        } else {
            0
        };
        snap.thermal.gpu_heat_permille = if self.gpu_trip_deci_c > 0 && gpu_max > 0 {
            ((gpu_max as u32 * 1000) / self.gpu_trip_deci_c as u32).min(2000) as u16
        } else {
            0
        };
        snap.thermal.headroom_reduced =
            (snap.cpu.ceiling_capped != 0 || snap.gpu.ceiling_capped != 0) as u8;
    }

    fn sample_mem(
        &mut self,
        tick: u32,
        focused_uid: u32,
        scratch: &mut Scratch,
        snap: &mut SnapshotCopy,
    ) {
        if let Some(raw) = pread_zero(self.fd_meminfo, &mut scratch.io_buf) {
            if parse_meminfo(raw, &mut scratch.meminfo) {
                let m = scratch.meminfo;
                let used = m.total_kb.saturating_sub(m.avail_kb);
                snap.mem.total_kb = m.total_kb;
                snap.mem.avail_kb = m.avail_kb;
                snap.mem.used_kb = used;
                snap.mem.swap_total_kb = m.swap_total_kb;
                snap.mem.swap_used_kb = m.swap_total_kb.saturating_sub(m.swap_free_kb);
                snap.mem.used_permille = if m.total_kb > 0 {
                    ((used as u64 * 1000) / m.total_kb as u64).min(1000) as u16
                } else {
                    0
                };
            }
        }
        // Zram ratio changes slowly: read at 0.2 Hz.
        if tick % 5 == 0 {
            if let Some(raw) = pread_zero(self.fd_zram_mm, &mut scratch.io_buf) {
                if parse_zram_mm_stat(raw, &mut scratch.zram) {
                    snap.mem.zram_orig_kb = (scratch.zram.orig_bytes / 1024) as u32;
                    snap.mem.zram_compr_kb = (scratch.zram.compr_bytes / 1024) as u32;
                    snap.mem.zram_ratio_permille = if scratch.zram.orig_bytes > 0 {
                        ((scratch.zram.compr_bytes * 1000) / scratch.zram.orig_bytes).min(1000)
                            as u16
                    } else {
                        0
                    };
                }
            }
        }
        if focused_uid > 0 && tick % 2 == 0 {
            let (gmem, gswap) = self.cgroups.read_uid_memory(focused_uid, &mut scratch.io_buf);
            if gmem > 0 {
                snap.mem.game_mem_kb = gmem;
                snap.mem.game_swap_kb = gswap;
            }
        }
    }

    fn sample_power(&mut self, tick: u32, scratch: &mut Scratch, snap: &mut SnapshotCopy) {
        let cur_ua = pread_zero(self.fd_bat_cur_ua, &mut scratch.io_buf)
            .and_then(parse_i64)
            .unwrap_or(0);
        let vol_uv = pread_zero(self.fd_bat_vol_uv, &mut scratch.io_buf)
            .and_then(parse_u64)
            .unwrap_or(0);
        let cap = pread_zero(self.fd_bat_cap, &mut scratch.io_buf)
            .and_then(parse_u64)
            .unwrap_or(0);

        snap.power.current_ua = cur_ua.clamp(i32::MIN as i64, i32::MAX as i64) as i32;
        snap.power.voltage_uv = vol_uv.min(u32::MAX as u64) as u32;
        // mW = |uA| * uV / 10^9
        let mw = (cur_ua.unsigned_abs() as u128 * vol_uv as u128) / 1_000_000_000u128;
        snap.power.power_mw = mw.min(u32::MAX as u128) as u32;
        snap.power.capacity_pct = cap.min(100) as u8;
        snap.power.charging = (cur_ua < 0) as u8;

        // Session energy via `charge_counter` at 0.1 Hz (every 10 ticks).
        if tick % 10 == 0 {
            if let Some(raw) = pread_zero(self.fd_bat_charge_uah, &mut scratch.io_buf) {
                if let Some(uah) = parse_u64(raw) {
                    let start = *self.session_start_uah.get_or_insert(uah);
                    snap.power.session_uah = start.saturating_sub(uah).min(u32::MAX as u64) as u32;
                }
            }
        }
        // mJ/frame * 10 = (mW * 1000) / fps_x100  (since mW = mJ/s)
        if snap.fps.current_x100 >= 100 {
            snap.power.mj_per_frame_x10 =
                ((snap.power.power_mw as u64 * 1000) / snap.fps.current_x100 as u64)
                    .min(u32::MAX as u64) as u32;
        }
    }

    fn sample_psi(&mut self, scratch: &mut Scratch, snap: &mut SnapshotCopy) {
        if let Some(raw) = pread_zero(self.fd_psi_cpu, &mut scratch.io_buf) {
            if parse_psi(raw, &mut scratch.psi) {
                snap.psi.cpu_some_avg10 = scratch.psi.some_avg10_x100;
                if self.prev_psi_cpu_us > 0 {
                    snap.psi.cpu_some_delta_us = scratch
                        .psi
                        .some_total_us
                        .saturating_sub(self.prev_psi_cpu_us)
                        .min(u32::MAX as u64) as u32;
                }
                self.prev_psi_cpu_us = scratch.psi.some_total_us;
            }
        }
        if let Some(raw) = pread_zero(self.fd_psi_mem, &mut scratch.io_buf) {
            if parse_psi(raw, &mut scratch.psi) {
                snap.psi.mem_some_avg10 = scratch.psi.some_avg10_x100;
                snap.psi.mem_full_avg10 = scratch.psi.full_avg10_x100;
                if self.prev_psi_mem_us > 0 {
                    snap.psi.mem_full_delta_us = scratch
                        .psi
                        .full_total_us
                        .saturating_sub(self.prev_psi_mem_us)
                        .min(u32::MAX as u64) as u32;
                }
                self.prev_psi_mem_us = scratch.psi.full_total_us;
            }
        }
        if let Some(raw) = pread_zero(self.fd_psi_io, &mut scratch.io_buf) {
            if parse_psi(raw, &mut scratch.psi) {
                snap.psi.io_some_avg10 = scratch.psi.some_avg10_x100;
                snap.psi.io_full_avg10 = scratch.psi.full_avg10_x100;
                if self.prev_psi_io_us > 0 {
                    snap.psi.io_full_delta_us = scratch
                        .psi
                        .full_total_us
                        .saturating_sub(self.prev_psi_io_us)
                        .min(u32::MAX as u64) as u32;
                }
                self.prev_psi_io_us = scratch.psi.full_total_us;
            }
        }
    }

    fn discover_cpu(&mut self, scratch: &mut Scratch) {
        let mut policies: Vec<(u32, String)> = Vec::new();
        if let Ok(rd) = fs::read_dir("/sys/devices/system/cpu/cpufreq") {
            for ent in rd.flatten() {
                if let Some(name) = ent.file_name().to_str() {
                    if let Some(num) = name.strip_prefix("policy").and_then(|s| s.parse::<u32>().ok()) {
                        policies.push((num, format!("/sys/devices/system/cpu/cpufreq/{name}")));
                    }
                }
            }
        }
        policies.sort_by_key(|(idx, _)| *idx);

        let mut lowest_hw_max = u32::MAX;
        for (_, dir) in policies.into_iter().take(MAX_CLUSTERS) {
            let aff_fd = open_ro(format!("{dir}/affected_cpus").as_bytes());
            let cpu_mask = pread_zero(aff_fd, &mut scratch.io_buf)
                .map(parse_cpu_mask)
                .unwrap_or(0);
            close_fd(aff_fd);

            let hw_fd = open_ro(format!("{dir}/cpuinfo_max_freq").as_bytes());
            let hw_max = pread_zero(hw_fd, &mut scratch.io_buf)
                .and_then(parse_u64)
                .unwrap_or(0) as u32;
            close_fd(hw_fd);

            let cur_fd = open_ro(format!("{dir}/scaling_cur_freq").as_bytes());
            let max_fd = open_ro(format!("{dir}/scaling_max_freq").as_bytes());

            if hw_max > 0 && hw_max < lowest_hw_max && cpu_mask != 0 {
                lowest_hw_max = hw_max;
                self.little_cpu_mask = cpu_mask as u64;
            }

            let highest_core = 32u32.saturating_sub(cpu_mask.leading_zeros()) as usize;
            if highest_core > self.num_cores {
                self.num_cores = highest_core.min(MAX_CORES);
            }

            self.clusters[self.num_clusters] = ClusterFds {
                cpu_mask,
                cur_fd,
                max_fd,
                hw_max_khz: hw_max,
            };
            self.num_clusters += 1;
        }
    }

    fn discover_thermal(&mut self, scratch: &mut Scratch) {
        let Ok(rd) = fs::read_dir("/sys/class/thermal") else {
            return;
        };
        let mut cpu_trip = 0i16;
        let mut gpu_trip = 0i16;
        for ent in rd.flatten() {
            let Some(name) = ent.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            if !name.starts_with("thermal_zone") {
                continue;
            }
            let base = format!("/sys/class/thermal/{name}");
            let tfd = open_ro(format!("{base}/type").as_bytes());
            let kind = pread_zero(tfd, &mut scratch.io_buf)
                .and_then(|b| core::str::from_utf8(b).ok())
                .map(|s| s.trim().to_ascii_lowercase())
                .unwrap_or_default();
            close_fd(tfd);
            if kind.is_empty() {
                continue;
            }

            let temp_path = format!("{base}/temp");
            // Prefer fast on-die TSENS sensors (`cpu-*`/`cpuss-*`) and skip slow ~2.3 ms PMIC ADC
            // board thermistors (`*_therm`, `bcl`) that always read cooler than die sensors anyway.
            if (kind.contains("cpu") || kind.contains("core") || kind.contains("cluster"))
                && !kind.contains("bcl")
                && !kind.ends_with("_therm")
            {
                if self.cpu_temp_count < MAX_THERM_ZONES {
                    let fd = open_ro(temp_path.as_bytes());
                    if fd >= 0 {
                        self.cpu_temp_fds[self.cpu_temp_count] = fd;
                        self.cpu_temp_count += 1;
                        cpu_trip = cpu_trip.max(read_zone_trip(&base, scratch));
                    }
                }
            } else if kind.contains("gpu") || kind.contains("kgsl") || kind.contains("adreno") {
                if self.gpu_temp_count < MAX_THERM_ZONES {
                    let fd = open_ro(temp_path.as_bytes());
                    if fd >= 0 {
                        self.gpu_temp_fds[self.gpu_temp_count] = fd;
                        self.gpu_temp_count += 1;
                        gpu_trip = gpu_trip.max(read_zone_trip(&base, scratch));
                    }
                }
            } else if self.fd_ddr_temp < 0 && (kind.contains("ddr") || kind.contains("dram")) {
                self.fd_ddr_temp = open_ro(temp_path.as_bytes());
            } else if self.fd_skin_temp < 0
                && (kind.contains("skin") || kind.contains("quiet-therm") || kind.contains("quiet_therm"))
            {
                self.fd_skin_temp = open_ro(temp_path.as_bytes());
            }
        }
        if cpu_trip > 300 {
            self.cpu_trip_deci_c = cpu_trip;
        }
        if gpu_trip > 300 {
            self.gpu_trip_deci_c = gpu_trip;
        }
    }

    fn discover_gpu(&mut self, scratch: &mut Scratch) {
        let fd = open_ro_cstr(b"/sys/class/kgsl/kgsl-3d0/gpu_available_frequencies\0");
        if let Some(raw) = pread_zero(fd, &mut scratch.io_buf) {
            let mut i = 0;
            let mut best = 0u64;
            while let Some(v) = crate::parse::scan_u64(raw, &mut i) {
                if v > best {
                    best = v;
                }
            }
            self.gpu_hw_max_mhz = raw_gpu_freq_to_mhz(best);
        }
        close_fd(fd);
    }
}

fn read_zone_trip(zone_base: &str, scratch: &mut Scratch) -> i16 {
    let mut best = 0i16;
    for n in 0..4 {
        let fd = open_ro(format!("{zone_base}/trip_point_{n}_temp").as_bytes());
        if let Some(raw) = pread_zero(fd, &mut scratch.io_buf) {
            if let Some(v) = parse_i64(raw) {
                let d = normalize_temp_deci_c(v, false);
                if d > best && d < 1250 {
                    best = d;
                }
            }
        }
        close_fd(fd);
    }
    best
}

impl Drop for Sampler {
    fn drop(&mut self) {
        close_fd(self.fd_proc_stat);
        close_fd(self.fd_meminfo);
        close_fd(self.fd_self_status);
        close_fd(self.fd_zram_mm);
        close_fd(self.fd_psi_cpu);
        close_fd(self.fd_psi_mem);
        close_fd(self.fd_psi_io);
        for fd in self.core_cur_fds {
            close_fd(fd);
        }
        for i in 0..self.num_clusters {
            close_fd(self.clusters[i].cur_fd);
            close_fd(self.clusters[i].max_fd);
        }
        for i in 0..self.cpu_temp_count {
            close_fd(self.cpu_temp_fds[i]);
        }
        for i in 0..self.gpu_temp_count {
            close_fd(self.gpu_temp_fds[i]);
        }
        close_fd(self.fd_ddr_temp);
        close_fd(self.fd_skin_temp);
        close_fd(self.fd_gpu_trans);
        close_fd(self.fd_gpu_busy_pct);
        close_fd(self.fd_gpu_clk);
        close_fd(self.fd_gpu_max);
        close_fd(self.fd_gpu_therm_lvl);
        close_fd(self.fd_bat_temp);
        close_fd(self.fd_bat_cap);
        close_fd(self.fd_bat_cur_ua);
        close_fd(self.fd_bat_vol_uv);
        close_fd(self.fd_bat_charge_uah);
    }
}
