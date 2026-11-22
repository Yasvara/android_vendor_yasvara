// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: Apache-2.0

//! Single-pass zero-allocation ASCII byte parsers for Linux `/proc` and `/sys` nodes.
//!
//! No UTF-8 validation, no `Regex`, no `split_whitespace`, no heap allocation.
//! Golden tests cover exact dumps captured from live `onyx` (`6.6.152`).

use crate::abi::MAX_CORES;

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct ProcStatRaw {
    pub agg_total: u64,
    pub agg_idle: u64,
    pub core_total: [u64; MAX_CORES],
    pub core_idle: [u64; MAX_CORES],
    pub num_cores: usize,
    pub intr_total: u64,
    pub ctxt: u64,
}

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct MemInfoRaw {
    pub total_kb: u32,
    pub avail_kb: u32,
    pub swap_total_kb: u32,
    pub swap_free_kb: u32,
}

pub const MAX_GPU_FREQS: usize = 24;

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct GpuTransRaw {
    pub count: usize,
    pub active_idx: u8,
    pub freq_hz: [u64; MAX_GPU_FREQS],
    pub time_ms: [u64; MAX_GPU_FREQS],
}

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct ZramStatRaw {
    pub orig_bytes: u64,
    pub compr_bytes: u64,
    pub mem_used_bytes: u64,
}

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct PsiRaw {
    pub some_avg10_x100: u16,
    pub full_avg10_x100: u16,
    pub some_total_us: u64,
    pub full_total_us: u64,
}

/// Parses an unsigned decimal integer starting at `i`, advancing `i` past the digits.
#[inline(always)]
pub fn scan_u64(b: &[u8], i: &mut usize) -> Option<u64> {
    let n = b.len();
    while *i < n && (b[*i] == b' ' || b[*i] == b'\t') {
        *i += 1;
    }
    let start = *i;
    let mut v = 0u64;
    while *i < n {
        let d = b[*i].wrapping_sub(b'0');
        if d > 9 {
            break;
        }
        v = v.wrapping_mul(10).wrapping_add(d as u64);
        *i += 1;
    }
    if *i == start { None } else { Some(v) }
}

/// Parses an optionally signed decimal integer from trimmed ASCII bytes.
#[inline(always)]
pub fn parse_i64(b: &[u8]) -> Option<i64> {
    let mut i = 0;
    while i < b.len() && (b[i] == b' ' || b[i] == b'\t' || b[i] == b'\n' || b[i] == b'\r') {
        i += 1;
    }
    if i >= b.len() {
        return None;
    }
    let neg = if b[i] == b'-' {
        i += 1;
        true
    } else {
        if b[i] == b'+' {
            i += 1;
        }
        false
    };
    let mag = scan_u64(b, &mut i)? as i64;
    Some(if neg { mag.wrapping_neg() } else { mag })
}

#[inline(always)]
pub fn parse_u64(b: &[u8]) -> Option<u64> {
    let mut i = 0;
    while i < b.len() && (b[i] == b' ' || b[i] == b'\t' || b[i] == b'\n' || b[i] == b'\r') {
        i += 1;
    }
    scan_u64(b, &mut i)
}

#[inline(always)]
fn skip_line(b: &[u8], i: &mut usize) {
    while *i < b.len() {
        let c = b[*i];
        *i += 1;
        if c == b'\n' {
            break;
        }
    }
}

/// Single-pass `/proc/stat` parser.
///
/// Extracts aggregate CPU, per-core ticks, total `intr` (skipping the ~1.5 KB per-IRQ tail in one
/// newline scan), and `ctxt`. Early-exits right after `ctxt`.
pub fn parse_proc_stat(b: &[u8], out: &mut ProcStatRaw) -> bool {
    *out = ProcStatRaw::default();
    let mut have_agg = false;
    let mut i = 0;
    let n = b.len();

    while i < n {
        let line_start = i;
        if line_start + 4 <= n && &b[line_start..line_start + 3] == b"cpu" {
            let c3 = b[line_start + 3];
            let core_idx: Option<usize> = if c3 == b' ' {
                i = line_start + 4;
                None
            } else if c3.is_ascii_digit() {
                i = line_start + 3;
                match scan_u64(b, &mut i) {
                    Some(idx) if (idx as usize) < MAX_CORES => Some(idx as usize),
                    _ => {
                        skip_line(b, &mut i);
                        continue;
                    }
                }
            } else {
                skip_line(b, &mut i);
                continue;
            };

            let mut total = 0u64;
            let mut idle = 0u64;
            let mut cols = 0usize;
            while cols < 10 {
                if let Some(v) = scan_u64(b, &mut i) {
                    total = total.wrapping_add(v);
                    if cols == 3 || cols == 4 {
                        idle = idle.wrapping_add(v);
                    }
                    cols += 1;
                } else {
                    break;
                }
            }
            if cols >= 7 {
                if let Some(idx) = core_idx {
                    out.core_total[idx] = total;
                    out.core_idle[idx] = idle;
                    if idx + 1 > out.num_cores {
                        out.num_cores = idx + 1;
                    }
                } else {
                    out.agg_total = total;
                    out.agg_idle = idle;
                    have_agg = true;
                }
            }
            skip_line(b, &mut i);
            continue;
        }

        if line_start + 5 <= n && &b[line_start..line_start + 5] == b"intr " {
            i = line_start + 5;
            if let Some(v) = scan_u64(b, &mut i) {
                out.intr_total = v;
            }
            // Skip hundreds of individual IRQ counters in one pass.
            skip_line(b, &mut i);
            continue;
        }

        if line_start + 5 <= n && &b[line_start..line_start + 5] == b"ctxt " {
            i = line_start + 5;
            if let Some(v) = scan_u64(b, &mut i) {
                out.ctxt = v;
            }
            break; // Nothing we need appears after `ctxt` in `/proc/stat`.
        }

        skip_line(b, &mut i);
    }

    have_agg
}

/// Fast prefix-matching `/proc/meminfo` parser; stops as soon as all 4 target fields are found.
pub fn parse_meminfo(b: &[u8], out: &mut MemInfoRaw) -> bool {
    *out = MemInfoRaw::default();
    let mut found = 0u8;
    let mut i = 0;
    let n = b.len();

    while i < n && found != 0x0f {
        let rem = &b[i..];
        if rem.starts_with(b"MemTotal:") {
            i += 9;
            if let Some(v) = scan_u64(b, &mut i) {
                out.total_kb = v.min(u32::MAX as u64) as u32;
                found |= 1 << 0;
            }
        } else if rem.starts_with(b"MemAvailable:") {
            i += 13;
            if let Some(v) = scan_u64(b, &mut i) {
                out.avail_kb = v.min(u32::MAX as u64) as u32;
                found |= 1 << 1;
            }
        } else if rem.starts_with(b"SwapTotal:") {
            i += 10;
            if let Some(v) = scan_u64(b, &mut i) {
                out.swap_total_kb = v.min(u32::MAX as u64) as u32;
                found |= 1 << 2;
            }
        } else if rem.starts_with(b"SwapFree:") {
            i += 9;
            if let Some(v) = scan_u64(b, &mut i) {
                out.swap_free_kb = v.min(u32::MAX as u64) as u32;
                found |= 1 << 3;
            }
        }
        skip_line(b, &mut i);
    }

    (found & 0x03) == 0x03
}

/// Parses kgsl `devfreq/trans_stat` (monotonic cumulative time_ms per frequency).
///
/// Handles the optional leading `* ` active-frequency marker emitted by Adreno devfreq.
pub fn parse_trans_stat(b: &[u8], out: &mut GpuTransRaw) -> bool {
    *out = GpuTransRaw::default();
    let mut i = 0;
    let n = b.len();

    while i < n && out.count < MAX_GPU_FREQS {
        let line_start = i;
        let mut line_end = i;
        while line_end < n && b[line_end] != b'\n' {
            line_end += 1;
        }
        let line = &b[line_start..line_end];
        i = if line_end < n { line_end + 1 } else { n };

        // Data rows look like: " 1162000000:   0 3 ... 1310" or "* 515000000: ... 3162210".
        let Some(colon) = line.iter().position(|&c| c == b':') else {
            continue;
        };
        let lhs = &line[..colon];
        let mut p = 0;
        let mut is_active = false;
        while p < lhs.len() && (lhs[p] == b' ' || lhs[p] == b'\t') {
            p += 1;
        }
        if p < lhs.len() && lhs[p] == b'*' {
            is_active = true;
            p += 1;
        }
        let Some(freq) = scan_u64(lhs, &mut p) else {
            continue; // Header rows ("From  :", "      :", "Total transition :").
        };
        // Reject "Total transition : 202" or malformed rows where lhs has trailing text.
        while p < lhs.len() && (lhs[p] == b' ' || lhs[p] == b'\t') {
            p += 1;
        }
        if p != lhs.len() || freq < 1_000_000 {
            continue;
        }

        // Last integer on the right of ':' is cumulative `time(ms)`.
        let rhs = &line[colon + 1..];
        let mut end = rhs.len();
        while end > 0 && (rhs[end - 1] == b' ' || rhs[end - 1] == b'\t' || rhs[end - 1] == b'\r') {
            end -= 1;
        }
        let mut start = end;
        while start > 0 && rhs[start - 1].is_ascii_digit() {
            start -= 1;
        }
        if start == end {
            continue;
        }
        let mut q = start;
        let Some(time_ms) = scan_u64(&rhs[..end], &mut q) else {
            continue;
        };

        let idx = out.count;
        out.freq_hz[idx] = freq;
        out.time_ms[idx] = time_ms;
        if is_active {
            out.active_idx = idx as u8;
        }
        out.count += 1;
    }

    out.count > 0
}

/// Computes time-weighted average GPU MHz between two `trans_stat` snapshots.
/// Returns `0` if elapsed residency across all states is zero (GPU idle/suspended).
pub fn gpu_avg_mhz_from_trans(prev: &GpuTransRaw, cur: &GpuTransRaw) -> u16 {
    let n = prev.count.min(cur.count);
    let mut weighted_mhz_ms = 0u128;
    let mut total_ms = 0u64;
    for i in 0..n {
        if prev.freq_hz[i] != cur.freq_hz[i] {
            continue;
        }
        let dt = cur.time_ms[i].saturating_sub(prev.time_ms[i]);
        if dt > 0 {
            let mhz = cur.freq_hz[i] / 1_000_000;
            weighted_mhz_ms += (mhz as u128) * (dt as u128);
            total_ms = total_ms.saturating_add(dt);
        }
    }
    if total_ms == 0 {
        0
    } else {
        (weighted_mhz_ms / (total_ms as u128)).min(u16::MAX as u128) as u16
    }
}

/// Parses either kgsl `gpu_busy_percentage` (`"47 %"`) or `gpubusy` (`"busy total"`) into permille (`0..=1000`).
pub fn parse_gpu_busy_permille(b: &[u8]) -> Option<u16> {
    if b.contains(&b'%') {
        let mut i = 0;
        let pct = scan_u64(b, &mut i)?;
        return Some((pct.min(100) * 10) as u16);
    }
    let mut i = 0;
    let busy = scan_u64(b, &mut i)?;
    if let Some(total) = scan_u64(b, &mut i) {
        if total == 0 {
            return Some(0);
        }
        let pm = busy.saturating_mul(1000) / total;
        Some(pm.min(1000) as u16)
    } else {
        Some((busy.min(100) * 10) as u16)
    }
}

/// Parses `/sys/block/zram0/mm_stat` first three integers: orig, compr, mem_used_total.
pub fn parse_zram_mm_stat(b: &[u8], out: &mut ZramStatRaw) -> bool {
    let mut i = 0;
    let Some(orig) = scan_u64(b, &mut i) else { return false };
    let Some(compr) = scan_u64(b, &mut i) else { return false };
    let Some(used) = scan_u64(b, &mut i) else { return false };
    out.orig_bytes = orig;
    out.compr_bytes = compr;
    out.mem_used_bytes = used;
    true
}

/// Parses `/proc/pressure/{cpu,memory,io}` into fixed-point `avg10 * 100` and `total_us`.
pub fn parse_psi(b: &[u8], out: &mut PsiRaw) -> bool {
    *out = PsiRaw::default();
    let mut ok = false;
    let mut i = 0;
    let n = b.len();

    while i < n {
        let rem = &b[i..];
        let is_some = rem.starts_with(b"some ");
        let is_full = !is_some && rem.starts_with(b"full ");
        if is_some || is_full {
            let line_start = i;
            let mut line_end = i;
            while line_end < n && b[line_end] != b'\n' {
                line_end += 1;
            }
            let line = &b[line_start..line_end];
            if let Some(avg10) = extract_psi_fixed2(line, b"avg10=") {
                if is_some {
                    out.some_avg10_x100 = avg10;
                } else {
                    out.full_avg10_x100 = avg10;
                }
                ok = true;
            }
            if let Some(tot) = extract_psi_u64(line, b"total=") {
                if is_some {
                    out.some_total_us = tot;
                } else {
                    out.full_total_us = tot;
                }
            }
            i = if line_end < n { line_end + 1 } else { n };
        } else {
            skip_line(b, &mut i);
        }
    }
    ok
}

fn find_subslice(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > hay.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

fn extract_psi_fixed2(line: &[u8], key: &[u8]) -> Option<u16> {
    let pos = find_subslice(line, key)? + key.len();
    let mut p = pos;
    let whole = scan_u64(line, &mut p)?;
    let frac = if p < line.len() && line[p] == b'.' {
        p += 1;
        let d1 = if p < line.len() && line[p].is_ascii_digit() {
            let d = (line[p] - b'0') as u64;
            p += 1;
            d
        } else {
            0
        };
        let d2 = if p < line.len() && line[p].is_ascii_digit() {
            (line[p] - b'0') as u64
        } else {
            0
        };
        d1 * 10 + d2
    } else {
        0
    };
    Some((whole.saturating_mul(100).saturating_add(frac)).min(10_000) as u16)
}

fn extract_psi_u64(line: &[u8], key: &[u8]) -> Option<u64> {
    let mut p = find_subslice(line, key)? + key.len();
    scan_u64(line, &mut p)
}

/// Parses cgroup v2 `cpu.stat` first line: `usage_usec 236191`.
pub fn parse_cgroup_usage_usec(b: &[u8]) -> Option<u64> {
    let pos = find_subslice(b, b"usage_usec ")? + 11;
    let mut i = pos;
    scan_u64(b, &mut i)
}

/// Normalizes a thermal sysfs integer to deci-°C (e.g. `45500` m°C → `455`, `382` d°C → `382`).
#[inline]
pub fn normalize_temp_deci_c(raw: i64, is_battery_deci: bool) -> i16 {
    if raw == 0 {
        return 0;
    }
    let deci = if is_battery_deci {
        raw
    } else if raw.abs() >= 1000 {
        raw / 100
    } else if raw.abs() >= 150 {
        raw
    } else {
        raw * 10
    };
    deci.clamp(-400, 1500) as i16
}

/// Parses a CPU list like `"0 1"` or `"2-4"` into a `u32` bitmask.
pub fn parse_cpu_mask(b: &[u8]) -> u32 {
    let mut mask = 0u32;
    let mut i = 0;
    let n = b.len();
    while i < n {
        while i < n && !b[i].is_ascii_digit() {
            i += 1;
        }
        let Some(a) = scan_u64(b, &mut i) else { break };
        if i < n && b[i] == b'-' {
            i += 1;
            if let Some(end) = scan_u64(b, &mut i) {
                let mut c = a;
                while c <= end && c < 32 {
                    mask |= 1u32 << c;
                    c += 1;
                }
            }
        } else if a < 32 {
            mask |= 1u32 << a;
        }
    }
    mask
}

/// Normalizes Hz / kHz / MHz raw GPU frequency into MHz.
#[inline]
pub fn raw_gpu_freq_to_mhz(raw: u64) -> u16 {
    let mhz = if raw > 1_000_000 {
        raw / 1_000_000
    } else if raw > 10_000 {
        raw / 1_000
    } else {
        raw
    };
    mhz.min(u16::MAX as u64) as u16
}

/// Parses `VmRSS:` (kB) from `/proc/self/status`.
pub fn parse_vm_rss_kb(b: &[u8]) -> u32 {
    let Some(pos) = find_subslice(b, b"VmRSS:") else {
        return 0;
    };
    let mut i = pos + 6;
    scan_u64(b, &mut i).unwrap_or(0).min(u32::MAX as u64) as u32
}

#[cfg(test)]
pub mod fixtures {
    /// Exact dumps captured from `onyx` (`cf49eff5`, Linux 6.6.152) on 2026-11-19.
    pub const ONYX_PROC_STAT: &[u8] = b"\
cpu  245277 14111 130489 2200138 1721 0 1911 90 0 0\n\
cpu0 26511 2472 32837 253010 181 0 1759 42 0 0\n\
cpu1 24780 2775 27548 267643 164 0 63 20 0 0\n\
cpu2 42505 1523 9122 272151 204 0 21 11 0 0\n\
cpu3 43734 1523 9040 271404 183 0 16 2 0 0\n\
cpu4 44171 1464 9318 270879 199 0 13 2 0 0\n\
cpu5 26926 1393 20180 275902 130 0 12 4 0 0\n\
cpu6 27071 1448 19521 276445 153 0 16 3 0 0\n\
cpu7 9575 1509 2918 312700 504 0 7 2 0 0\n\
intr 26331913 0 14356684 574487 0 0 0 4847901 0 0 0 0\n\
ctxt 39445279\n\
btime 1795070943\n";

    pub const ONYX_MEMINFO: &[u8] = b"\
MemTotal:       11533688 kB\n\
MemFree:         1267780 kB\n\
MemAvailable:    4203040 kB\n\
Buffers:           10284 kB\n\
Cached:          4036840 kB\n\
SwapTotal:       6291452 kB\n\
SwapFree:        2160620 kB\n";

    pub const ONYX_TRANS_STAT: &[u8] = b"\
     From  :   To\n\
           :116200000011500000001090000000 965000000 915000000 873000000 763000000 685000000 515000000 300000000 150000000   time(ms)\n\
 1162000000:         0         3         0         0         0         0         0         0         0         0         0      1310\n\
 1150000000:         3         0         5         0         0         0         0         0         0         0         0      1353\n\
 1090000000:         0         5         0         6         0         0         0         0         0         0         0      2173\n\
  965000000:         0         0         6         0         8         0         0         0         0         0         0      2170\n\
  915000000:         0         0         0         8         0        10         0         0         0         0         0      3343\n\
  873000000:         0         0         0         0        10         0        11         0         2         0         0     16173\n\
  763000000:         0         0         0         0         0        13         0        30         0         0         0     15753\n\
  685000000:         0         0         0         0         0         0        32         0        24         0         0     73036\n\
* 515000000:         0         0         0         0         0         0         0        26         0         0         0   3162210\n\
  300000000:         0         0         0         0         0         0         0         0         0         0         0         0\n\
  150000000:         0         0         0         0         0         0         0         0         0         0         0         0\n\
Total transition : 202\n";

    pub const ONYX_ZRAM: &[u8] =
        b"4227706880 1451463299 1525477376        0 1534267392    39039    27071    45749    67652\n";

    pub const ONYX_PSI_IO: &[u8] = b"\
some avg10=0.36 avg60=0.12 avg300=0.08 total=8421026\n\
full avg10=0.18 avg60=0.06 avg300=0.06 total=5051824\n";

    pub const ONYX_CGROUP_CPU: &[u8] = b"\
usage_usec 236191\n\
user_usec 113242\n\
system_usec 122948\n";
}

#[cfg(test)]
mod tests {
    use super::fixtures::*;
    use super::*;

    #[test]
    fn golden_onyx_proc_stat() {
        let mut s = ProcStatRaw::default();
        assert!(parse_proc_stat(ONYX_PROC_STAT, &mut s));
        assert_eq!(s.num_cores, 8);
        assert_eq!(s.agg_total, 245277 + 14111 + 130489 + 2200138 + 1721 + 1911 + 90);
        assert_eq!(s.agg_idle, 2200138 + 1721);
        assert_eq!(s.intr_total, 26331913);
        assert_eq!(s.ctxt, 39445279);
    }

    #[test]
    fn golden_onyx_meminfo_and_zram() {
        let mut m = MemInfoRaw::default();
        assert!(parse_meminfo(ONYX_MEMINFO, &mut m));
        assert_eq!(m.total_kb, 11533688);
        assert_eq!(m.avail_kb, 4203040);
        assert_eq!(m.swap_total_kb, 6291452);
        assert_eq!(m.swap_free_kb, 2160620);

        let mut z = ZramStatRaw::default();
        assert!(parse_zram_mm_stat(ONYX_ZRAM, &mut z));
        assert_eq!(z.orig_bytes, 4227706880);
        assert_eq!(z.compr_bytes, 1451463299);
    }

    #[test]
    fn golden_onyx_trans_stat_and_weighted_avg() {
        let mut t1 = GpuTransRaw::default();
        assert!(parse_trans_stat(ONYX_TRANS_STAT, &mut t1));
        assert_eq!(t1.count, 11);
        assert_eq!(t1.active_idx, 8); // * 515000000
        assert_eq!(t1.freq_hz[0], 1_162_000_000);
        assert_eq!(t1.time_ms[0], 1310);
        assert_eq!(t1.freq_hz[8], 515_000_000);
        assert_eq!(t1.time_ms[8], 3_162_210);

        let mut t2 = t1;
        t2.time_ms[0] += 500; // 500 ms at 1162 MHz
        t2.time_ms[8] += 500; // 500 ms at 515 MHz
        let avg = gpu_avg_mhz_from_trans(&t1, &t2);
        assert_eq!(avg, (1162 + 515) / 2);
    }

    #[test]
    fn golden_onyx_psi_gpu_busy_cgroup_and_truncated() {
        let mut psi = PsiRaw::default();
        assert!(parse_psi(ONYX_PSI_IO, &mut psi));
        assert_eq!(psi.some_avg10_x100, 36);
        assert_eq!(psi.full_avg10_x100, 18);
        assert_eq!(psi.some_total_us, 8421026);
        assert_eq!(psi.full_total_us, 5051824);

        assert_eq!(parse_gpu_busy_permille(b"47 %\n"), Some(470));
        assert_eq!(parse_gpu_busy_permille(b"0 %\n"), Some(0));
        assert_eq!(parse_gpu_busy_permille(b"500 1000\n"), Some(500));
        assert_eq!(parse_gpu_busy_permille(b"0 0\n"), Some(0));
        assert_eq!(parse_cgroup_usage_usec(ONYX_CGROUP_CPU), Some(236191));
        assert_eq!(parse_cpu_mask(b"2 3 4\n"), 0b11100);
        assert_eq!(parse_cpu_mask(b"0-1\n"), 0b11);
        assert_eq!(normalize_temp_deci_c(45500, false), 455);
        assert_eq!(normalize_temp_deci_c(382, true), 382);

        // Truncated/corrupt inputs never panic.
        let mut s = ProcStatRaw::default();
        assert!(!parse_proc_stat(b"cpu\n", &mut s));
        let mut m = MemInfoRaw::default();
        assert!(!parse_meminfo(b"MemTotal:", &mut m));
        let mut t = GpuTransRaw::default();
        assert!(!parse_trans_stat(b"garbage: no numbers\n", &mut t));
    }
}
