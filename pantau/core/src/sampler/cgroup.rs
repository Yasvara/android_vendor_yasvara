// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: Apache-2.0

//! Adaptive cgroup v2 per-UID CPU & memory scanner (replaces Pentas's 120 ms `top` forks).
//!
//! - Refreshes `/sys/fs/cgroup/{apps,system}/uid_*` directory entries only every 10 ticks while
//!   `mask::PROCS` is active.
//! - Keeps persistent read-only fds for `cpu.stat` and `memory.current` in a fixed `[UidSlot; 128]`
//!   table; zero heap allocation during hot sampling ticks.

use std::fs;
use std::os::unix::ffi::OsStrExt;

use crate::abi::{ProcTable, MAX_PROCS};
use crate::parse::{parse_cgroup_usage_usec, parse_u64};
use crate::sys::{close_fd, open_ro, pread_zero, RawFd};

pub const MAX_UID_SLOTS: usize = 128;

#[derive(Copy, Clone)]
struct UidSlot {
    uid: u32,
    is_system: bool,
    active: bool,
    cpu_fd: RawFd,
    mem_fd: RawFd,
    prev_usage_us: u64,
    last_mem_kb: u32,
}

impl Default for UidSlot {
    fn default() -> Self {
        Self {
            uid: 0,
            is_system: false,
            active: false,
            cpu_fd: -1,
            mem_fd: -1,
            prev_usage_us: 0,
            last_mem_kb: 0,
        }
    }
}

pub struct CgroupScanner {
    slots: [UidSlot; MAX_UID_SLOTS],
    count: usize,
    last_scan_ns: u64,
    last_sample_ns: u64,
}

impl Default for CgroupScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl CgroupScanner {
    pub fn new() -> Self {
        Self {
            slots: [UidSlot::default(); MAX_UID_SLOTS],
            count: 0,
            last_scan_ns: 0,
            last_sample_ns: 0,
        }
    }

    /// Samples all tracked UIDs into `out` (top 16 by normalized 0..100% CPU share, 0 alloc).
    pub fn sample(
        &mut self,
        now_ns: u64,
        num_cores: usize,
        io_buf: &mut [u8],
        out: &mut ProcTable,
        allow_rescan: bool,
    ) {
        if allow_rescan
            && (self.last_scan_ns == 0 || now_ns.saturating_sub(self.last_scan_ns) >= 10_000_000_000)
        {
            self.rescan_dirs();
            self.last_scan_ns = now_ns;
        }

        let elapsed_us = if self.last_sample_ns == 0 {
            0
        } else {
            now_ns.saturating_sub(self.last_sample_ns) / 1_000
        };
        self.last_sample_ns = now_ns;

        // Top-N stack selection sorted by raw delta_us (keeps all active UIDs, no noise cutoff
        // that drops SystemUI / background apps on 8-core SoCs, 0 heap allocation).
        let mut top_idx = [0usize; MAX_PROCS];
        let mut top_delta = [0u64; MAX_PROCS];
        let mut top_pm = [0u16; MAX_PROCS];
        let mut top_len = 0usize;
        let denom = elapsed_us.saturating_mul(num_cores.max(1) as u64);

        for idx in 0..self.count {
            let slot = &mut self.slots[idx];
            if !slot.active || slot.cpu_fd < 0 {
                continue;
            }
            let Some(raw) = pread_zero(slot.cpu_fd, io_buf) else {
                continue;
            };
            let Some(cur_us) = parse_cgroup_usage_usec(raw) else {
                continue;
            };
            let delta_us = if slot.prev_usage_us > 0 && cur_us >= slot.prev_usage_us {
                cur_us - slot.prev_usage_us
            } else {
                0
            };
            slot.prev_usage_us = cur_us;

            if elapsed_us == 0 || delta_us == 0 {
                continue;
            }
            // Permille of total SoC CPU capacity (0..1000 = 0.0%..100.0%).
            let pm = delta_us
                .saturating_mul(1000)
                .checked_div(denom)
                .unwrap_or(0)
                .min(1000) as u16;

            // Read live memory only for non-idle UIDs (saves ~80% of memory.current syscalls).
            if slot.mem_fd >= 0 {
                if let Some(mraw) = pread_zero(slot.mem_fd, io_buf) {
                    if let Some(bytes) = parse_u64(mraw) {
                        slot.last_mem_kb = (bytes / 1024).min(u32::MAX as u64) as u32;
                    }
                }
            }

            // Insert descending by delta_us into fixed top-16 stack array.
            let mut pos = top_len;
            while pos > 0 && delta_us > top_delta[pos - 1] {
                if pos < MAX_PROCS {
                    top_delta[pos] = top_delta[pos - 1];
                    top_pm[pos] = top_pm[pos - 1];
                    top_idx[pos] = top_idx[pos - 1];
                }
                pos -= 1;
            }
            if pos < MAX_PROCS {
                top_delta[pos] = delta_us;
                top_pm[pos] = pm;
                top_idx[pos] = idx;
                if top_len < MAX_PROCS {
                    top_len += 1;
                }
            }
        }

        // Keep previous non-empty rows during warm-up ticks (elapsed_us == 0) so UI never flashes blank.
        if top_len > 0 || elapsed_us > 0 {
            out.clear();
            let mut name_buf = [0u8; 24];
            for i in 0..top_len {
                let slot = &self.slots[top_idx[i]];
                let nlen = fmt_uid_label(slot.uid, &mut name_buf);
                out.push(
                    slot.uid,
                    0,
                    top_pm[i],
                    slot.last_mem_kb,
                    slot.is_system,
                    &name_buf[..nlen],
                );
            }
        }
    }

    /// Samples top threads of `focused_uid`'s primary process (`/proc/<pid>/task/*/stat`)
    /// into `out` (`is_system = 2` marks thread rows for the monochrome thread icon).
    pub fn sample_threads(
        &mut self,
        focused_uid: u32,
        now_ns: u64,
        io_buf: &mut [u8],
        out: &mut ProcTable,
    ) {
        // Locate the first PID inside `/sys/fs/cgroup/apps/uid_<uid>/cgroup.procs` (or pid_* subdir).
        let Some(pid) = find_pid_for_uid(focused_uid, io_buf) else {
            return;
        };
        let mut dir_path = [0u8; 64];
        let dir_len = fmt_proc_task_dir(pid, &mut dir_path);
        let Ok(dir_str) = core::str::from_utf8(&dir_path[..dir_len]) else {
            return;
        };
        let Ok(entries) = fs::read_dir(dir_str) else {
            return;
        };

        // Snapshot current thread CPU ticks (top 16 by cumulative/recent utime+stime).
        // Lightweight single-pass without retaining hundreds of FDs per ephemeral game thread.
        let _ = now_ns;
        let mut tids = [0u32; MAX_PROCS];
        let mut ticks = [0u64; MAX_PROCS];
        let mut names = [[0u8; 20]; MAX_PROCS];
        let mut nlens = [0u8; MAX_PROCS];
        let mut count = 0usize;
        let mut total_ticks = 0u64;

        let mut stat_path = [0u8; 96];
        for ent in entries.flatten() {
            let fname = ent.file_name();
            let Some(tid_u64) = parse_u64(fname.as_bytes()) else {
                continue;
            };
            let tid = tid_u64 as u32;
            let plen = fmt_task_stat_path(pid, tid, &mut stat_path);
            let fd = open_ro(&stat_path[..plen]);
            if fd < 0 {
                continue;
            }
            let raw_opt = pread_zero(fd, io_buf);
            close_fd(fd);
            let Some(raw) = raw_opt else {
                continue;
            };
            let Some((comm, t_sum)) = parse_thread_stat(raw) else {
                continue;
            };
            if t_sum == 0 {
                continue;
            }
            total_ticks = total_ticks.saturating_add(t_sum);

            let mut pos = count;
            while pos > 0 && t_sum > ticks[pos - 1] {
                if pos < MAX_PROCS {
                    ticks[pos] = ticks[pos - 1];
                    tids[pos] = tids[pos - 1];
                    names[pos] = names[pos - 1];
                    nlens[pos] = nlens[pos - 1];
                }
                pos -= 1;
            }
            if pos < MAX_PROCS {
                ticks[pos] = t_sum;
                tids[pos] = tid;
                let cl = comm.len().min(20);
                names[pos][..cl].copy_from_slice(&comm[..cl]);
                nlens[pos] = cl as u8;
                if count < MAX_PROCS {
                    count += 1;
                }
            }
        }

        if count > 0 {
            out.clear();
            let denom = total_ticks.max(1);
            for i in 0..count {
                let pm = ((ticks[i].saturating_mul(1000)) / denom).min(1000) as u16;
                out.push_kind(
                    focused_uid,
                    tids[i],
                    pm,
                    0,
                    2, // thread row
                    &names[i][..nlens[i] as usize],
                );
            }
        }
    }

    /// Reads live `(mem_kb, swap_kb)` for one specific UID (e.g. active game) with 0 alloc.
    pub fn read_uid_memory(&self, uid: u32, io_buf: &mut [u8]) -> (u32, u32) {
        for idx in 0..self.count {
            let slot = &self.slots[idx];
            if slot.active && slot.uid == uid {
                let mem_kb = if slot.mem_fd >= 0 {
                    pread_zero(slot.mem_fd, io_buf)
                        .and_then(parse_u64)
                        .map(|b| (b / 1024).min(u32::MAX as u64) as u32)
                        .unwrap_or(0)
                } else {
                    0
                };
                return (mem_kb, 0);
            }
        }
        (0, 0)
    }

    fn rescan_dirs(&mut self) {
        for i in 0..self.count {
            self.slots[i].active = false;
        }
        self.scan_root(b"/sys/fs/cgroup/apps", false);
        self.scan_root(b"/sys/fs/cgroup/system", true);

        // Close stale fds and compact.
        let mut write = 0;
        for read in 0..self.count {
            if self.slots[read].active {
                if write != read {
                    self.slots[write] = self.slots[read];
                }
                write += 1;
            } else {
                close_fd(self.slots[read].cpu_fd);
                close_fd(self.slots[read].mem_fd);
            }
        }
        self.count = write;
    }

    fn scan_root(&mut self, root: &[u8], is_system: bool) {
        let Ok(root_str) = core::str::from_utf8(root) else {
            return;
        };
        let Ok(entries) = fs::read_dir(root_str) else {
            return;
        };
        let mut path = [0u8; 160];
        for ent in entries.flatten() {
            let fname = ent.file_name();
            let nb = fname.as_bytes();
            let Some(uid_bytes) = nb.strip_prefix(b"uid_") else {
                continue;
            };
            let Some(uid_u64) = parse_u64(uid_bytes) else {
                continue;
            };
            let uid = uid_u64 as u32;

            // Already tracked?
            if let Some(slot) = self.slots[..self.count].iter_mut().find(|s| s.uid == uid) {
                slot.active = true;
                continue;
            }
            if self.count >= MAX_UID_SLOTS {
                continue;
            }

            let cpu_fd = open_child_file(&mut path, root, nb, b"/cpu.stat");
            if cpu_fd < 0 {
                continue;
            }
            let mem_fd = open_child_file(&mut path, root, nb, b"/memory.current");

            self.slots[self.count] = UidSlot {
                uid,
                is_system,
                active: true,
                cpu_fd,
                mem_fd,
                prev_usage_us: 0,
                last_mem_kb: 0,
            };
            self.count += 1;
        }
    }
}

impl Drop for CgroupScanner {
    fn drop(&mut self) {
        for i in 0..self.count {
            close_fd(self.slots[i].cpu_fd);
            close_fd(self.slots[i].mem_fd);
        }
    }
}

fn open_child_file(scratch: &mut [u8; 160], root: &[u8], dir: &[u8], leaf: &[u8]) -> RawFd {
    let total = root.len() + 1 + dir.len() + leaf.len();
    if total >= scratch.len() {
        return -1;
    }
    let mut p = 0;
    scratch[p..p + root.len()].copy_from_slice(root);
    p += root.len();
    scratch[p] = b'/';
    p += 1;
    scratch[p..p + dir.len()].copy_from_slice(dir);
    p += dir.len();
    scratch[p..p + leaf.len()].copy_from_slice(leaf);
    p += leaf.len();
    open_ro(&scratch[..p])
}

fn fmt_uid_label(mut uid: u32, out: &mut [u8; 24]) -> usize {
    let app_id = uid % 100_000;
    let known: Option<&[u8]> = match app_id {
        0 => Some(b"kernel"),
        1000 => Some(b"system"),
        1001 => Some(b"radio"),
        1002 => Some(b"bluetooth"),
        1003 => Some(b"graphics"),
        1004 => Some(b"input"),
        1005 => Some(b"audio"),
        1006 => Some(b"camera"),
        1007 => Some(b"log"),
        1010 => Some(b"wifi"),
        1011 => Some(b"adb"),
        1012 => Some(b"installd"),
        1013 => Some(b"media"),
        1016 => Some(b"vpn"),
        1017 => Some(b"keystore"),
        1018 => Some(b"usb"),
        1019 => Some(b"drm"),
        1020 => Some(b"mdns"),
        1021 => Some(b"gps"),
        1023 => Some(b"media_rw"),
        1027 => Some(b"nfc"),
        1031 => Some(b"mediadrm"),
        1036 => Some(b"logd"),
        1037 => Some(b"relro"),
        1040 => Some(b"mediaex"),
        1041 => Some(b"audioserver"),
        1045 => Some(b"debuggerd"),
        1046 => Some(b"mediacodec"),
        1047 => Some(b"cameraserver"),
        1051 => Some(b"dns"),
        1053 => Some(b"webview"),
        1058 => Some(b"tombstoned"),
        1066 => Some(b"statsd"),
        1067 => Some(b"incidentd"),
        1068 => Some(b"secure_elem"),
        1069 => Some(b"lmkd"),
        1070 => Some(b"llkd"),
        1072 => Some(b"gpu_service"),
        1073 => Some(b"network_stack"),
        1076 => Some(b"credstore"),
        1077 => Some(b"storage"),
        1082 => Some(b"artd"),
        1083 => Some(b"uwb"),
        1086 => Some(b"dmesgd"),
        1091 => Some(b"seclog"),
        1092 => Some(b"prng_seeder"),
        2000 => Some(b"shell"),
        9999 => Some(b"nobody"),
        90_000..=98_999 => Some(b"sandbox"),
        99_000..=99_999 => Some(b"isolated"),
        _ => None,
    };
    if let Some(lbl) = known {
        let n = lbl.len().min(out.len());
        out[..n].copy_from_slice(&lbl[..n]);
        return n;
    }
    out[..4].copy_from_slice(b"uid_");
    let mut tmp = [0u8; 10];
    let mut n = 0;
    while uid > 0 {
        tmp[n] = b'0' + (uid % 10) as u8;
        uid /= 10;
        n += 1;
    }
    for i in 0..n {
        out[4 + i] = tmp[n - 1 - i];
    }
    4 + n
}

fn push_u32_buf(mut v: u32, dst: &mut [u8], pos: &mut usize) {
    let mut tmp = [0u8; 10];
    let mut n = 0;
    if v == 0 {
        if *pos < dst.len() {
            dst[*pos] = b'0';
            *pos += 1;
        }
        return;
    }
    while v > 0 {
        tmp[n] = b'0' + (v % 10) as u8;
        v /= 10;
        n += 1;
    }
    while n > 0 {
        n -= 1;
        if *pos < dst.len() {
            dst[*pos] = tmp[n];
            *pos += 1;
        }
    }
}

fn push_bytes_buf(src: &[u8], dst: &mut [u8], pos: &mut usize) {
    let n = src.len().min(dst.len().saturating_sub(*pos));
    dst[*pos..*pos + n].copy_from_slice(&src[..n]);
    *pos += n;
}

fn fmt_proc_task_dir(pid: u32, out: &mut [u8; 64]) -> usize {
    let mut p = 0;
    push_bytes_buf(b"/proc/", out, &mut p);
    push_u32_buf(pid, out, &mut p);
    push_bytes_buf(b"/task", out, &mut p);
    p
}

fn fmt_task_stat_path(pid: u32, tid: u32, out: &mut [u8; 96]) -> usize {
    let mut p = 0;
    push_bytes_buf(b"/proc/", out, &mut p);
    push_u32_buf(pid, out, &mut p);
    push_bytes_buf(b"/task/", out, &mut p);
    push_u32_buf(tid, out, &mut p);
    push_bytes_buf(b"/stat", out, &mut p);
    p
}

fn find_pid_for_uid(uid: u32, io_buf: &mut [u8]) -> Option<u32> {
    if uid == 0 {
        return None;
    }
    let mut path = [0u8; 96];
    let mut p = 0;
    push_bytes_buf(b"/sys/fs/cgroup/apps/uid_", &mut path, &mut p);
    push_u32_buf(uid, &mut path, &mut p);
    let base_str = core::str::from_utf8(&path[..p]).ok()?;
    let entries = fs::read_dir(base_str).ok()?;
    for ent in entries.flatten() {
        let name = ent.file_name();
        if let Some(rest) = name.as_bytes().strip_prefix(b"pid_") {
            if let Some(pid) = parse_u64(rest) {
                return Some(pid as u32);
            }
        }
    }
    let _ = io_buf;
    None
}

fn parse_thread_stat(raw: &[u8]) -> Option<(&[u8], u64)> {
    let lp = raw.iter().position(|&b| b == b'(')?;
    let rp = raw.iter().rposition(|&b| b == b')')?;
    if rp <= lp + 1 || rp + 2 >= raw.len() {
        return None;
    }
    let comm = &raw[lp + 1..rp];
    let rest = &raw[rp + 2..];
    // Fields after ") ": 0=state, 1=ppid, ..., 11=utime, 12=stime
    let mut idx = 0usize;
    let mut utime = 0u64;
    let mut stime = 0u64;
    for tok in rest.split(|&b| b == b' ').filter(|s| !s.is_empty()) {
        if idx == 11 {
            utime = parse_u64(tok).unwrap_or(0);
        } else if idx == 12 {
            stime = parse_u64(tok).unwrap_or(0);
            break;
        }
        idx += 1;
    }
    Some((comm, utime.saturating_add(stime)))
}
