// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: Apache-2.0

//! Shared-memory snapshot layout (`memfd`, read-only to Pentas & CLI) with lock-free seqlock.
//!
//! All field offsets are exported via [`LAYOUT_FIELDS`] so `pantau_layout_gen` generates both
//! `pantau_abi.h` (`static_assert`) and `PantauLayout.kt` (`ByteBuffer` + seqlock).

use core::mem::{align_of, offset_of, size_of};
use core::ptr;
use core::sync::atomic::{fence, AtomicU32, Ordering};

pub const SNAP_MAGIC: u32 = 0x3154_4E50; // "PNT1"
pub const SNAP_VERSION: u16 = 2;

pub const MAX_CORES: usize = 16;
pub const MAX_CLUSTERS: usize = 6;
pub const FPS_HIST_LEN: usize = 120;
pub const METRIC_HIST_LEN: usize = 60;
pub const MAX_PROCS: usize = 16;
pub const PROC_NAME_BYTES: usize = 512;

/// Bit flags for [`NetSnap::link_type`].
pub const LINK_WIFI: u8 = 1 << 0;
pub const LINK_CELL: u8 = 1 << 1;
pub const LINK_ETH: u8 = 1 << 2;
pub const LINK_VPN: u8 = 1 << 3;

/// Cache line 0 (64 bytes): identity, seqlock counter, timestamp & self-overhead.
#[repr(C, align(64))]
#[derive(Debug)]
pub struct SnapHeader {
    pub magic: u32,
    pub version: u16,
    pub header_size: u16,
    pub total_size: u32,
    /// Seqlock generation: odd = write in progress, even = stable snapshot.
    pub seq: AtomicU32,
    pub tick_boottime_ns: u64,
    pub valid_mask: u64,
    pub self_tick_us: u32,
    pub self_draw_us: u32,
    pub self_drops: u32,
    pub self_rss_kb: u32,
    pub life_state: u8,
    pub hud_hwc_client: u8,
    pub num_cores: u8,
    pub num_clusters: u8,
    pub _pad: [u8; 12],
}

impl Default for SnapHeader {
    fn default() -> Self {
        Self {
            magic: SNAP_MAGIC,
            version: SNAP_VERSION,
            header_size: size_of::<SnapHeader>() as u16,
            total_size: size_of::<Snapshot>() as u32,
            seq: AtomicU32::new(0),
            tick_boottime_ns: 0,
            valid_mask: 0,
            self_tick_us: 0,
            self_draw_us: 0,
            self_drops: 0,
            self_rss_kb: 0,
            life_state: 0,
            hud_hwc_client: 0,
            num_cores: 0,
            num_clusters: 0,
            _pad: [0; 12],
        }
    }
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct ClusterSnap {
    pub cpu_mask: u32,
    pub cur_khz: u32,
    pub scaling_max_khz: u32,
    pub hw_max_khz: u32,
    pub util_permille: u16,
    pub capped: u8,
    pub _pad: u8,
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct CpuSnap {
    pub total_permille: u16,
    pub ceiling_capped: u8,
    pub _pad0: u8,
    pub max_freq_khz: u32,
    pub ctxt_per_sec: u32,
    pub irq_per_sec: u32,
    pub core_util_permille: [u16; MAX_CORES],
    pub core_freq_khz: [u32; MAX_CORES],
    pub clusters: [ClusterSnap; MAX_CLUSTERS],
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct GpuSnap {
    pub busy_permille: u16,
    pub cur_mhz: u16,
    pub avg_mhz: u16,
    pub cap_mhz: u16,
    pub hw_max_mhz: u16,
    pub ceiling_capped: u8,
    pub thermal_pwrlevel: u8,
    pub game_gpumem_kb: u32,
    pub global_gpumem_kb: u32,
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct ThermalSnap {
    // All temperatures in deci-°C (e.g. 455 == 45.5 °C).
    pub cpu_deci_c: i16,
    pub gpu_deci_c: i16,
    pub ddr_deci_c: i16,
    pub skin_deci_c: i16,
    pub bat_deci_c: i16,
    pub cpu_trip_deci_c: i16,
    pub gpu_trip_deci_c: i16,
    pub cpu_heat_permille: u16,
    pub gpu_heat_permille: u16,
    pub hal_headroom_permille: u16,
    pub hal_status: u8,
    pub headroom_reduced: u8,
    pub _pad: [u8; 2],
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct MemSnap {
    pub total_kb: u32,
    pub avail_kb: u32,
    pub used_kb: u32,
    pub swap_total_kb: u32,
    pub swap_used_kb: u32,
    pub zram_orig_kb: u32,
    pub zram_compr_kb: u32,
    pub game_mem_kb: u32,
    pub game_swap_kb: u32,
    pub used_permille: u16,
    pub zram_ratio_permille: u16,
    pub pgmajfault_s: u32,
    pub allocstall_s: u32,
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct PowerSnap {
    pub power_mw: u32,
    pub current_ua: i32,
    pub voltage_uv: u32,
    pub session_uah: u32,
    pub mj_per_frame_x10: u32,
    pub capacity_pct: u8,
    pub charging: u8,
    pub _pad: [u8; 2],
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct DisplaySnap {
    pub refresh_hz: u16,
    pub render_hz: u16,
    pub mode_switches: u16,
    pub hwc_client_permille: u16,
}

/// Unified Wi-Fi + Mobile Data + passive kernel TCP RTT/jitter snapshot.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct NetSnap {
    pub rx_bps: u32,
    pub tx_bps: u32,
    pub wifi_rx_bps: u32,
    pub wifi_tx_bps: u32,
    pub cell_rx_bps: u32,
    pub cell_tx_bps: u32,
    pub wifi_session_kb: u32,
    pub cell_session_kb: u32,
    pub tcp_rtt_us: u32,
    pub tcp_rttvar_us: u32,
    pub tcp_retrans_s: u16,
    pub wifi_link_mbps: u16,
    pub wifi_freq_mhz: u16,
    pub wifi_rssi_dbm: i16,
    pub cell_rsrp_dbm: i16,
    pub wifi_tx_retries_s: u16,
    pub cell_level: u8,    // 0..=4
    pub cell_gen: u8,      // 0=none, 2=2G, 3=3G, 4=4G, 5=5G, 6=5G+
    pub wifi_standard: u8, // 0=unknown, 4=Wi-Fi 4, 5=Wi-Fi 5, 6=Wi-Fi 6, 7=Wi-Fi 7
    pub link_type: u8,     // bitmask: LINK_WIFI | LINK_CELL | LINK_ETH | LINK_VPN
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct FpsSnap {
    pub current_x100: u16,
    pub avg_x100: u16,
    pub low1_x100: u16,
    pub _pad: u16,
    pub task_id: i32,
    pub focused_uid: u32,
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct PsiSnap {
    // avg10 encoded as hundredths of percent (e.g. 748 == 7.48%).
    pub cpu_some_avg10: u16,
    pub mem_some_avg10: u16,
    pub mem_full_avg10: u16,
    pub io_some_avg10: u16,
    pub io_full_avg10: u16,
    pub mem_stall_events: u16,
    pub io_stall_events: u16,
    pub _pad: u16,
    pub cpu_some_delta_us: u32,
    pub mem_full_delta_us: u32,
    pub io_full_delta_us: u32,
}

#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct HistoryRings {
    pub fps_head: u16,
    pub fps_len: u16,
    pub metric_head: u16,
    pub metric_len: u16,
    pub net_head: u16,
    pub net_len: u16,
    pub fps_x100: [u16; FPS_HIST_LEN],
    pub gpu_pct: [u8; METRIC_HIST_LEN],
    pub cpu_pct: [u8; METRIC_HIST_LEN],
    pub cpu_deci_c: [i16; METRIC_HIST_LEN],
    /// Unified 60-sample network history (KB/s per transport + passive RTT ms).
    pub net_wifi_rx_kbps: [u32; METRIC_HIST_LEN],
    pub net_cell_rx_kbps: [u32; METRIC_HIST_LEN],
    pub net_tx_kbps: [u32; METRIC_HIST_LEN],
    pub net_rtt_ms: [u16; METRIC_HIST_LEN],
}

impl Default for HistoryRings {
    fn default() -> Self {
        Self {
            fps_head: 0,
            fps_len: 0,
            metric_head: 0,
            metric_len: 0,
            net_head: 0,
            net_len: 0,
            fps_x100: [0; FPS_HIST_LEN],
            gpu_pct: [0; METRIC_HIST_LEN],
            cpu_pct: [0; METRIC_HIST_LEN],
            cpu_deci_c: [0; METRIC_HIST_LEN],
            net_wifi_rx_kbps: [0; METRIC_HIST_LEN],
            net_cell_rx_kbps: [0; METRIC_HIST_LEN],
            net_tx_kbps: [0; METRIC_HIST_LEN],
            net_rtt_ms: [0; METRIC_HIST_LEN],
        }
    }
}

impl HistoryRings {
    #[inline]
    pub fn push_fps(&mut self, fps_x100: u16) {
        let idx = self.fps_head as usize;
        self.fps_x100[idx] = fps_x100;
        self.fps_head = ((idx + 1) % FPS_HIST_LEN) as u16;
        if (self.fps_len as usize) < FPS_HIST_LEN {
            self.fps_len += 1;
        }
    }

    #[inline]
    pub fn push_metrics(&mut self, cpu_pct: u8, gpu_pct: u8, cpu_deci_c: i16) {
        let idx = self.metric_head as usize;
        self.cpu_pct[idx] = cpu_pct;
        self.gpu_pct[idx] = gpu_pct;
        self.cpu_deci_c[idx] = cpu_deci_c;
        self.metric_head = ((idx + 1) % METRIC_HIST_LEN) as u16;
        if (self.metric_len as usize) < METRIC_HIST_LEN {
            self.metric_len += 1;
        }
    }

    #[inline]
    pub fn push_net(&mut self, wifi_rx_kbps: u32, cell_rx_kbps: u32, tx_kbps: u32, rtt_ms: u16) {
        let idx = self.net_head as usize;
        self.net_wifi_rx_kbps[idx] = wifi_rx_kbps;
        self.net_cell_rx_kbps[idx] = cell_rx_kbps;
        self.net_tx_kbps[idx] = tx_kbps;
        self.net_rtt_ms[idx] = rtt_ms;
        self.net_head = ((idx + 1) % METRIC_HIST_LEN) as u16;
        if (self.net_len as usize) < METRIC_HIST_LEN {
            self.net_len += 1;
        }
    }
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct ProcRow {
    pub uid: u32,
    pub pid: u32,
    pub cpu_permille: u16,
    pub name_off: u16,
    pub name_len: u8,
    pub is_system: u8, // 0=app, 1=system daemon/kernel, 2=thread
    pub _pad: u16,
    pub mem_kb: u32,
}

#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ProcTable {
    pub count: u16,
    pub name_bytes: u16,
    pub rows: [ProcRow; MAX_PROCS],
    pub names: [u8; PROC_NAME_BYTES],
}

impl Default for ProcTable {
    fn default() -> Self {
        Self {
            count: 0,
            name_bytes: 0,
            rows: [ProcRow::default(); MAX_PROCS],
            names: [0; PROC_NAME_BYTES],
        }
    }
}

impl ProcTable {
    pub fn clear(&mut self) {
        self.count = 0;
        self.name_bytes = 0;
    }

    /// Appends a row and its UTF-8/ASCII name into the inline table without allocating.
    pub fn push(&mut self, uid: u32, pid: u32, cpu_permille: u16, mem_kb: u32, is_system: bool, name: &[u8]) -> bool {
        self.push_kind(uid, pid, cpu_permille, mem_kb, if is_system { 1 } else { 0 }, name)
    }

    pub fn push_kind(&mut self, uid: u32, pid: u32, cpu_permille: u16, mem_kb: u32, kind: u8, name: &[u8]) -> bool {
        let idx = self.count as usize;
        if idx >= MAX_PROCS {
            return false;
        }
        let off = self.name_bytes as usize;
        let max_len = (PROC_NAME_BYTES.saturating_sub(off)).min(31);
        let len = name.len().min(max_len);
        self.names[off..off + len].copy_from_slice(&name[..len]);
        self.rows[idx] = ProcRow {
            uid,
            pid,
            cpu_permille,
            name_off: off as u16,
            name_len: len as u8,
            is_system: kind,
            _pad: 0,
            mem_kb,
        };
        self.count += 1;
        self.name_bytes = (off + len) as u16;
        true
    }

    #[inline]
    pub fn name_of(&self, row: &ProcRow) -> &[u8] {
        let start = (row.name_off as usize).min(PROC_NAME_BYTES);
        let end = start.saturating_add(row.name_len as usize).min(PROC_NAME_BYTES);
        &self.names[start..end]
    }

    /// Rewrites inline names in-place for any non-thread row whose UID resolves via `lookup`
    /// (zero heap allocations; keeps `Snapshot` & `cmd pantau snap` free of `uid_XXXXX` fallbacks).
    pub fn apply_labels<'a, F>(&mut self, mut lookup: F)
    where
        F: FnMut(u32) -> Option<&'a [u8]>,
    {
        let n = (self.count as usize).min(MAX_PROCS);
        if n == 0 {
            return;
        }
        let mut old_names = [0u8; PROC_NAME_BYTES];
        old_names.copy_from_slice(&self.names);
        let mut off = 0usize;
        for i in 0..n {
            let r = &mut self.rows[i];
            let s = (r.name_off as usize).min(PROC_NAME_BYTES);
            let e = s.saturating_add(r.name_len as usize).min(PROC_NAME_BYTES);
            let orig = &old_names[s..e];
            let src: &[u8] = if r.is_system != 2 {
                match lookup(r.uid) {
                    Some(lbl) if !lbl.is_empty() => lbl,
                    _ => orig,
                }
            } else {
                orig
            };
            let max_len = PROC_NAME_BYTES.saturating_sub(off).min(31);
            let len = src.len().min(max_len);
            self.names[off..off + len].copy_from_slice(&src[..len]);
            r.name_off = off as u16;
            r.name_len = len as u8;
            off += len;
        }
        self.name_bytes = off as u16;
    }
}

/// Complete shared-memory snapshot mapped read-only by Pentas and CLI clients.
#[repr(C, align(64))]
#[derive(Debug, Default)]
pub struct Snapshot {
    pub hdr: SnapHeader,
    pub cpu: CpuSnap,
    pub gpu: GpuSnap,
    pub thermal: ThermalSnap,
    pub mem: MemSnap,
    pub power: PowerSnap,
    pub display: DisplaySnap,
    pub net: NetSnap,
    pub fps: FpsSnap,
    pub psi: PsiSnap,
    pub hist: HistoryRings,
    pub procs: ProcTable,
}

/// Plain-old-data copy of [`Snapshot`] without the atomic header word (for seqlock reads).
#[repr(C, align(64))]
#[derive(Copy, Clone, Debug)]
pub struct SnapshotCopy {
    pub tick_boottime_ns: u64,
    pub valid_mask: u64,
    pub self_tick_us: u32,
    pub self_draw_us: u32,
    pub self_drops: u32,
    pub self_rss_kb: u32,
    pub life_state: u8,
    pub hud_hwc_client: u8,
    pub num_cores: u8,
    pub num_clusters: u8,
    pub cpu: CpuSnap,
    pub gpu: GpuSnap,
    pub thermal: ThermalSnap,
    pub mem: MemSnap,
    pub power: PowerSnap,
    pub display: DisplaySnap,
    pub net: NetSnap,
    pub fps: FpsSnap,
    pub psi: PsiSnap,
    pub hist: HistoryRings,
    pub procs: ProcTable,
}

impl Default for SnapshotCopy {
    fn default() -> Self {
        Self {
            tick_boottime_ns: 0,
            valid_mask: 0,
            self_tick_us: 0,
            self_draw_us: 0,
            self_drops: 0,
            self_rss_kb: 0,
            life_state: 0,
            hud_hwc_client: 0,
            num_cores: 0,
            num_clusters: 0,
            cpu: CpuSnap::default(),
            gpu: GpuSnap::default(),
            thermal: ThermalSnap::default(),
            mem: MemSnap::default(),
            power: PowerSnap::default(),
            display: DisplaySnap::default(),
            net: NetSnap::default(),
            fps: FpsSnap::default(),
            psi: PsiSnap::default(),
            hist: HistoryRings::default(),
            procs: ProcTable::default(),
        }
    }
}

impl Snapshot {
    /// Initializes header metadata on a freshly mapped `memfd` region.
    pub fn init_in_place(&mut self) {
        *self = Self::default();
        fence(Ordering::Release);
    }

    /// Wait-free seqlock publish: copies `src` into shared memory using odd→even generation.
    pub fn publish_from(&mut self, src: &SnapshotCopy) {
        let s0 = self.hdr.seq.load(Ordering::Relaxed);
        self.hdr.seq.store(s0.wrapping_add(1) | 1, Ordering::Release);
        fence(Ordering::Release);

        self.hdr.tick_boottime_ns = src.tick_boottime_ns;
        self.hdr.valid_mask = src.valid_mask;
        self.hdr.self_tick_us = src.self_tick_us;
        self.hdr.self_draw_us = src.self_draw_us;
        self.hdr.self_drops = src.self_drops;
        self.hdr.self_rss_kb = src.self_rss_kb;
        self.hdr.life_state = src.life_state;
        self.hdr.hud_hwc_client = src.hud_hwc_client;
        self.hdr.num_cores = src.num_cores;
        self.hdr.num_clusters = src.num_clusters;
        self.cpu = src.cpu;
        self.gpu = src.gpu;
        self.thermal = src.thermal;
        self.mem = src.mem;
        self.power = src.power;
        self.display = src.display;
        self.net = src.net;
        self.fps = src.fps;
        self.psi = src.psi;
        self.hist = src.hist;
        self.procs = src.procs;

        fence(Ordering::Release);
        self.hdr.seq.store((s0.wrapping_add(1) | 1).wrapping_add(1), Ordering::Release);
    }

    /// Lock-free seqlock read into `dst`. Retries up to 8 times if concurrent write occurred.
    pub fn read_consistent(&self, dst: &mut SnapshotCopy) -> bool {
        if self.hdr.magic != SNAP_MAGIC || self.hdr.version != SNAP_VERSION {
            return false;
        }
        for _ in 0..8 {
            let s1 = self.hdr.seq.load(Ordering::Acquire);
            if s1 & 1 != 0 {
                core::hint::spin_loop();
                continue;
            }
            // SAFETY: `self` is a valid aligned `Snapshot`; torn reads are rejected by `s1 != s2`.
            unsafe {
                dst.tick_boottime_ns = ptr::read_volatile(&self.hdr.tick_boottime_ns);
                dst.valid_mask = ptr::read_volatile(&self.hdr.valid_mask);
                dst.self_tick_us = ptr::read_volatile(&self.hdr.self_tick_us);
                dst.self_draw_us = ptr::read_volatile(&self.hdr.self_draw_us);
                dst.self_drops = ptr::read_volatile(&self.hdr.self_drops);
                dst.self_rss_kb = ptr::read_volatile(&self.hdr.self_rss_kb);
                dst.life_state = ptr::read_volatile(&self.hdr.life_state);
                dst.hud_hwc_client = ptr::read_volatile(&self.hdr.hud_hwc_client);
                dst.num_cores = ptr::read_volatile(&self.hdr.num_cores);
                dst.num_clusters = ptr::read_volatile(&self.hdr.num_clusters);
                dst.cpu = ptr::read_volatile(&self.cpu);
                dst.gpu = ptr::read_volatile(&self.gpu);
                dst.thermal = ptr::read_volatile(&self.thermal);
                dst.mem = ptr::read_volatile(&self.mem);
                dst.power = ptr::read_volatile(&self.power);
                dst.display = ptr::read_volatile(&self.display);
                dst.net = ptr::read_volatile(&self.net);
                dst.fps = ptr::read_volatile(&self.fps);
                dst.psi = ptr::read_volatile(&self.psi);
                dst.hist = ptr::read_volatile(&self.hist);
                dst.procs = ptr::read_volatile(&self.procs);
            }
            fence(Ordering::Acquire);
            let s2 = self.hdr.seq.load(Ordering::Acquire);
            if s1 == s2 {
                return true;
            }
        }
        false
    }
}

/// Exported offset table consumed by `tools/layout_gen.rs` to generate C++ & Kotlin bindings.
pub const LAYOUT_FIELDS: &[(&str, usize)] = &[
    ("SNAP_SIZE", size_of::<Snapshot>()),
    ("SNAP_ALIGN", align_of::<Snapshot>()),
    ("MAX_CORES", MAX_CORES),
    ("MAX_CLUSTERS", MAX_CLUSTERS),
    ("FPS_HIST_LEN", FPS_HIST_LEN),
    ("METRIC_HIST_LEN", METRIC_HIST_LEN),
    ("MAX_PROCS", MAX_PROCS),
    ("PROC_NAME_BYTES", PROC_NAME_BYTES),
    ("HDR_MAGIC", offset_of!(Snapshot, hdr) + offset_of!(SnapHeader, magic)),
    ("HDR_VERSION", offset_of!(Snapshot, hdr) + offset_of!(SnapHeader, version)),
    ("HDR_SEQ", offset_of!(Snapshot, hdr) + offset_of!(SnapHeader, seq)),
    ("HDR_TICK_NS", offset_of!(Snapshot, hdr) + offset_of!(SnapHeader, tick_boottime_ns)),
    ("HDR_VALID_MASK", offset_of!(Snapshot, hdr) + offset_of!(SnapHeader, valid_mask)),
    ("HDR_SELF_TICK_US", offset_of!(Snapshot, hdr) + offset_of!(SnapHeader, self_tick_us)),
    ("HDR_SELF_DRAW_US", offset_of!(Snapshot, hdr) + offset_of!(SnapHeader, self_draw_us)),
    ("HDR_NUM_CORES", offset_of!(Snapshot, hdr) + offset_of!(SnapHeader, num_cores)),
    ("HDR_NUM_CLUSTERS", offset_of!(Snapshot, hdr) + offset_of!(SnapHeader, num_clusters)),
    ("OFF_CPU", offset_of!(Snapshot, cpu)),
    ("OFF_CPU_TOTAL", offset_of!(Snapshot, cpu) + offset_of!(CpuSnap, total_permille)),
    ("OFF_CPU_CEILING", offset_of!(Snapshot, cpu) + offset_of!(CpuSnap, ceiling_capped)),
    ("OFF_CPU_MAX_KHZ", offset_of!(Snapshot, cpu) + offset_of!(CpuSnap, max_freq_khz)),
    ("OFF_CPU_CORE_UTIL", offset_of!(Snapshot, cpu) + offset_of!(CpuSnap, core_util_permille)),
    ("OFF_CPU_CORE_KHZ", offset_of!(Snapshot, cpu) + offset_of!(CpuSnap, core_freq_khz)),
    ("OFF_CPU_CLUSTERS", offset_of!(Snapshot, cpu) + offset_of!(CpuSnap, clusters)),
    ("SIZE_CLUSTER_SNAP", size_of::<ClusterSnap>()),
    ("OFF_GPU", offset_of!(Snapshot, gpu)),
    ("OFF_GPU_BUSY", offset_of!(Snapshot, gpu) + offset_of!(GpuSnap, busy_permille)),
    ("OFF_GPU_CUR_MHZ", offset_of!(Snapshot, gpu) + offset_of!(GpuSnap, cur_mhz)),
    ("OFF_GPU_AVG_MHZ", offset_of!(Snapshot, gpu) + offset_of!(GpuSnap, avg_mhz)),
    ("OFF_GPU_CAP_MHZ", offset_of!(Snapshot, gpu) + offset_of!(GpuSnap, cap_mhz)),
    ("OFF_GPU_HW_MAX_MHZ", offset_of!(Snapshot, gpu) + offset_of!(GpuSnap, hw_max_mhz)),
    ("OFF_GPU_CEILING", offset_of!(Snapshot, gpu) + offset_of!(GpuSnap, ceiling_capped)),
    ("OFF_THERMAL", offset_of!(Snapshot, thermal)),
    ("OFF_THERM_CPU", offset_of!(Snapshot, thermal) + offset_of!(ThermalSnap, cpu_deci_c)),
    ("OFF_THERM_GPU", offset_of!(Snapshot, thermal) + offset_of!(ThermalSnap, gpu_deci_c)),
    ("OFF_THERM_DDR", offset_of!(Snapshot, thermal) + offset_of!(ThermalSnap, ddr_deci_c)),
    ("OFF_THERM_SKIN", offset_of!(Snapshot, thermal) + offset_of!(ThermalSnap, skin_deci_c)),
    ("OFF_THERM_BAT", offset_of!(Snapshot, thermal) + offset_of!(ThermalSnap, bat_deci_c)),
    ("OFF_THERM_CPU_HEAT", offset_of!(Snapshot, thermal) + offset_of!(ThermalSnap, cpu_heat_permille)),
    ("OFF_THERM_GPU_HEAT", offset_of!(Snapshot, thermal) + offset_of!(ThermalSnap, gpu_heat_permille)),
    ("OFF_THERM_REDUCED", offset_of!(Snapshot, thermal) + offset_of!(ThermalSnap, headroom_reduced)),
    ("OFF_MEM", offset_of!(Snapshot, mem)),
    ("OFF_MEM_TOTAL_KB", offset_of!(Snapshot, mem) + offset_of!(MemSnap, total_kb)),
    ("OFF_MEM_AVAIL_KB", offset_of!(Snapshot, mem) + offset_of!(MemSnap, avail_kb)),
    ("OFF_MEM_USED_KB", offset_of!(Snapshot, mem) + offset_of!(MemSnap, used_kb)),
    ("OFF_MEM_SWAP_TOT_KB", offset_of!(Snapshot, mem) + offset_of!(MemSnap, swap_total_kb)),
    ("OFF_MEM_SWAP_USED_KB", offset_of!(Snapshot, mem) + offset_of!(MemSnap, swap_used_kb)),
    ("OFF_MEM_USED_PM", offset_of!(Snapshot, mem) + offset_of!(MemSnap, used_permille)),
    ("OFF_POWER", offset_of!(Snapshot, power)),
    ("OFF_PWR_MW", offset_of!(Snapshot, power) + offset_of!(PowerSnap, power_mw)),
    ("OFF_PWR_UA", offset_of!(Snapshot, power) + offset_of!(PowerSnap, current_ua)),
    ("OFF_PWR_UV", offset_of!(Snapshot, power) + offset_of!(PowerSnap, voltage_uv)),
    ("OFF_PWR_CAP", offset_of!(Snapshot, power) + offset_of!(PowerSnap, capacity_pct)),
    ("OFF_PWR_CHG", offset_of!(Snapshot, power) + offset_of!(PowerSnap, charging)),
    ("OFF_DISPLAY", offset_of!(Snapshot, display)),
    ("OFF_DISP_HZ", offset_of!(Snapshot, display) + offset_of!(DisplaySnap, refresh_hz)),
    ("OFF_NET", offset_of!(Snapshot, net)),
    ("OFF_NET_RX_BPS", offset_of!(Snapshot, net) + offset_of!(NetSnap, rx_bps)),
    ("OFF_NET_TX_BPS", offset_of!(Snapshot, net) + offset_of!(NetSnap, tx_bps)),
    ("OFF_NET_WIFI_RX_BPS", offset_of!(Snapshot, net) + offset_of!(NetSnap, wifi_rx_bps)),
    ("OFF_NET_WIFI_TX_BPS", offset_of!(Snapshot, net) + offset_of!(NetSnap, wifi_tx_bps)),
    ("OFF_NET_CELL_RX_BPS", offset_of!(Snapshot, net) + offset_of!(NetSnap, cell_rx_bps)),
    ("OFF_NET_CELL_TX_BPS", offset_of!(Snapshot, net) + offset_of!(NetSnap, cell_tx_bps)),
    ("OFF_NET_WIFI_SESS_KB", offset_of!(Snapshot, net) + offset_of!(NetSnap, wifi_session_kb)),
    ("OFF_NET_CELL_SESS_KB", offset_of!(Snapshot, net) + offset_of!(NetSnap, cell_session_kb)),
    ("OFF_NET_RTT_US", offset_of!(Snapshot, net) + offset_of!(NetSnap, tcp_rtt_us)),
    ("OFF_NET_RTTVAR_US", offset_of!(Snapshot, net) + offset_of!(NetSnap, tcp_rttvar_us)),
    ("OFF_NET_RETRANS_S", offset_of!(Snapshot, net) + offset_of!(NetSnap, tcp_retrans_s)),
    ("OFF_NET_WIFI_MBPS", offset_of!(Snapshot, net) + offset_of!(NetSnap, wifi_link_mbps)),
    ("OFF_NET_WIFI_FREQ", offset_of!(Snapshot, net) + offset_of!(NetSnap, wifi_freq_mhz)),
    ("OFF_NET_WIFI_RSSI", offset_of!(Snapshot, net) + offset_of!(NetSnap, wifi_rssi_dbm)),
    ("OFF_NET_CELL_RSRP", offset_of!(Snapshot, net) + offset_of!(NetSnap, cell_rsrp_dbm)),
    ("OFF_NET_CELL_LVL", offset_of!(Snapshot, net) + offset_of!(NetSnap, cell_level)),
    ("OFF_NET_CELL_GEN", offset_of!(Snapshot, net) + offset_of!(NetSnap, cell_gen)),
    ("OFF_NET_WIFI_STD", offset_of!(Snapshot, net) + offset_of!(NetSnap, wifi_standard)),
    ("OFF_NET_LINK_TYPE", offset_of!(Snapshot, net) + offset_of!(NetSnap, link_type)),
    ("OFF_FPS", offset_of!(Snapshot, fps)),
    ("OFF_FPS_CUR_X100", offset_of!(Snapshot, fps) + offset_of!(FpsSnap, current_x100)),
    ("OFF_PSI", offset_of!(Snapshot, psi)),
    ("OFF_HIST", offset_of!(Snapshot, hist)),
    ("OFF_HIST_FPS_HEAD", offset_of!(Snapshot, hist) + offset_of!(HistoryRings, fps_head)),
    ("OFF_HIST_FPS_LEN", offset_of!(Snapshot, hist) + offset_of!(HistoryRings, fps_len)),
    ("OFF_HIST_METRIC_HEAD", offset_of!(Snapshot, hist) + offset_of!(HistoryRings, metric_head)),
    ("OFF_HIST_METRIC_LEN", offset_of!(Snapshot, hist) + offset_of!(HistoryRings, metric_len)),
    ("OFF_HIST_NET_HEAD", offset_of!(Snapshot, hist) + offset_of!(HistoryRings, net_head)),
    ("OFF_HIST_NET_LEN", offset_of!(Snapshot, hist) + offset_of!(HistoryRings, net_len)),
    ("OFF_HIST_FPS", offset_of!(Snapshot, hist) + offset_of!(HistoryRings, fps_x100)),
    ("OFF_HIST_GPU_PCT", offset_of!(Snapshot, hist) + offset_of!(HistoryRings, gpu_pct)),
    ("OFF_HIST_CPU_PCT", offset_of!(Snapshot, hist) + offset_of!(HistoryRings, cpu_pct)),
    ("OFF_HIST_NET_WIFI_RX", offset_of!(Snapshot, hist) + offset_of!(HistoryRings, net_wifi_rx_kbps)),
    ("OFF_HIST_NET_CELL_RX", offset_of!(Snapshot, hist) + offset_of!(HistoryRings, net_cell_rx_kbps)),
    ("OFF_HIST_NET_TX", offset_of!(Snapshot, hist) + offset_of!(HistoryRings, net_tx_kbps)),
    ("OFF_HIST_NET_RTT", offset_of!(Snapshot, hist) + offset_of!(HistoryRings, net_rtt_ms)),
    ("OFF_PROCS", offset_of!(Snapshot, procs)),
    ("OFF_PROCS_COUNT", offset_of!(Snapshot, procs) + offset_of!(ProcTable, count)),
    ("OFF_PROCS_ROWS", offset_of!(Snapshot, procs) + offset_of!(ProcTable, rows)),
    ("OFF_PROCS_NAMES", offset_of!(Snapshot, procs) + offset_of!(ProcTable, names)),
    ("SIZE_PROC_ROW", size_of::<ProcRow>()),
];

const _: () = assert!(size_of::<SnapHeader>() == 64);
const _: () = assert!(align_of::<Snapshot>() == 64);
const _: () = assert!(size_of::<Snapshot>() <= 8192); // Fits cleanly in 2 4K pages!

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seqlock_publish_and_read() {
        let mut shm = Snapshot::default();
        shm.init_in_place();

        let mut src = SnapshotCopy::default();
        src.tick_boottime_ns = 123_456_789;
        src.cpu.total_permille = 543;
        src.gpu.avg_mhz = 763;
        src.thermal.cpu_deci_c = 455;
        src.net.wifi_rx_bps = 4_200_000;
        src.net.cell_rx_bps = 1_100_000;
        src.net.link_type = LINK_WIFI | LINK_CELL;
        src.hist.push_net(4100, 1074, 580, 18);
        src.procs.push(10042, 4321, 312, 512_000, false, b"com.mobile.legends");

        shm.publish_from(&src);
        assert_eq!(shm.hdr.seq.load(Ordering::Acquire), 2);

        let mut out = SnapshotCopy::default();
        assert!(shm.read_consistent(&mut out));
        assert_eq!(out.tick_boottime_ns, 123_456_789);
        assert_eq!(out.cpu.total_permille, 543);
        assert_eq!(out.gpu.avg_mhz, 763);
        assert_eq!(out.net.wifi_rx_bps, 4_200_000);
        assert_eq!(out.hist.net_len, 1);
        assert_eq!(out.hist.net_wifi_rx_kbps[0], 4100);
        assert_eq!(out.procs.count, 1);
        assert_eq!(out.procs.name_of(&out.procs.rows[0]), b"com.mobile.legends");
    }
}
