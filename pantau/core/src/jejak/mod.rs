// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: Apache-2.0

//! Jejak low-level primitives: hardware CRC32C, ZigZag Delta-of-Delta varint codec,
//! O(1)-memory log-linear latency histogram, and stack-only top-20 worst-frame min-heap.

/// Castagnoli CRC32C checksum. Uses ARMv8/v9 hardware `crc32cd`/`crc32cb` instructions on `onyx`.
#[inline]
pub fn crc32c(seed: u32, data: &[u8]) -> u32 {
    #[cfg(target_arch = "aarch64")]
    {
        if std::arch::is_aarch64_feature_detected!("crc") {
            // SAFETY: CPU feature `crc` verified via runtime detection.
            return unsafe { crc32c_aarch64(seed, data) };
        }
    }
    crc32c_scalar(seed, data)
}

#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "crc")]
unsafe fn crc32c_aarch64(seed: u32, data: &[u8]) -> u32 {
    use core::arch::aarch64::{__crc32cb, __crc32cd};
    let mut crc = !seed;
    let mut i = 0;
    let n = data.len();
    while i + 8 <= n {
        let word = u64::from_le_bytes([
            data[i],
            data[i + 1],
            data[i + 2],
            data[i + 3],
            data[i + 4],
            data[i + 5],
            data[i + 6],
            data[i + 7],
        ]);
        crc = __crc32cd(crc, word);
        i += 8;
    }
    while i < n {
        crc = __crc32cb(crc, data[i]);
        i += 1;
    }
    !crc
}

/// Bit-exact Castagnoli CRC32C (polynomial `0x82F63B78`) scalar fallback.
pub fn crc32c_scalar(seed: u32, data: &[u8]) -> u32 {
    const TABLE: [u32; 256] = {
        let mut t = [0u32; 256];
        let mut i = 0usize;
        while i < 256 {
            let mut c = i as u32;
            let mut k = 0;
            while k < 8 {
                c = if c & 1 != 0 {
                    0x82F6_3B78 ^ (c >> 1)
                } else {
                    c >> 1
                };
                k += 1;
            }
            t[i] = c;
            i += 1;
        }
        t
    };
    let mut crc = !seed;
    for &b in data {
        crc = TABLE[((crc as u8) ^ b) as usize] ^ (crc >> 8);
    }
    !crc
}

#[inline(always)]
pub const fn zigzag_encode(v: i64) -> u64 {
    ((v << 1) ^ (v >> 63)) as u64
}

#[inline(always)]
pub const fn zigzag_decode(v: u64) -> i64 {
    ((v >> 1) as i64) ^ (-((v & 1) as i64))
}

/// Encodes an unsigned varint into `out`, returning bytes written (`0` if `out` too small).
#[inline(always)]
pub fn encode_varint(mut v: u64, out: &mut [u8]) -> usize {
    let mut i = 0;
    while v >= 0x80 {
        if i >= out.len() {
            return 0;
        }
        out[i] = (v as u8) | 0x80;
        v >>= 7;
        i += 1;
    }
    if i >= out.len() {
        return 0;
    }
    out[i] = v as u8;
    i + 1
}

/// Decodes a varint from `src`, returning `(value, bytes_consumed)`.
#[inline(always)]
pub fn decode_varint(src: &[u8]) -> Option<(u64, usize)> {
    let mut v = 0u64;
    let mut shift = 0u32;
    for (i, &b) in src.iter().enumerate() {
        if shift >= 64 {
            return None;
        }
        v |= ((b & 0x7f) as u64) << shift;
        if b & 0x80 == 0 {
            return Some((v, i + 1));
        }
        shift += 7;
    }
    None
}

/// Encodes a monotonic timestamp series using Delta-of-Delta + ZigZag LEB128 (~1 B/frame at 120 fps).
pub fn encode_dod_i64(values: &[i64], out: &mut [u8]) -> Option<usize> {
    let mut pos = 0;
    let mut prev = 0i64;
    let mut prev_delta = 0i64;
    for (idx, &v) in values.iter().enumerate() {
        let encoded = if idx == 0 {
            prev = v;
            zigzag_encode(v)
        } else {
            let delta = v.wrapping_sub(prev);
            let dod = delta.wrapping_sub(prev_delta);
            prev = v;
            prev_delta = delta;
            zigzag_encode(dod)
        };
        let n = encode_varint(encoded, &mut out[pos..]);
        if n == 0 {
            return None;
        }
        pos += n;
    }
    Some(pos)
}

/// Decodes `count` Delta-of-Delta encoded `i64` values into `dst`.
pub fn decode_dod_i64(src: &[u8], dst: &mut [i64]) -> Option<usize> {
    let mut pos = 0;
    let mut prev = 0i64;
    let mut prev_delta = 0i64;
    for (idx, slot) in dst.iter_mut().enumerate() {
        let (zz, used) = decode_varint(&src[pos..])?;
        pos += used;
        let val = zigzag_decode(zz);
        if idx == 0 {
            *slot = val;
            prev = val;
        } else {
            let delta = prev_delta.wrapping_add(val);
            let cur = prev.wrapping_add(delta);
            *slot = cur;
            prev = cur;
            prev_delta = delta;
        }
    }
    Some(pos)
}

/// Compact O(1)-memory latency histogram (512 buckets = 2 KB stack) covering 0 µs .. 5 s.
///
/// - Buckets `0..256`: 100 µs linear steps (`0.0 .. 25.6 ms` — crisp 0.1 ms precision across 60/90/120 Hz!)
/// - Buckets `256..384`: 1 ms linear steps (`25.6 .. 153.6 ms`)
/// - Buckets `384..512`: 40 ms linear steps (`153.6 ms .. 5.27 s`, saturating for Daveys)
#[derive(Clone, Debug)]
pub struct LatencyHist {
    buckets: [u32; 512],
    pub count: u64,
    pub sum_us: u64,
    pub min_us: u32,
    pub max_us: u32,
}

impl Default for LatencyHist {
    fn default() -> Self {
        Self::new()
    }
}

impl LatencyHist {
    pub const fn new() -> Self {
        Self {
            buckets: [0; 512],
            count: 0,
            sum_us: 0,
            min_us: u32::MAX,
            max_us: 0,
        }
    }

    #[inline(always)]
    fn bucket_of(us: u32) -> usize {
        if us < 25_600 {
            (us / 100) as usize
        } else if us < 153_600 {
            256 + ((us - 25_600) / 1_000) as usize
        } else {
            (384 + ((us - 153_600) / 40_000) as usize).min(511)
        }
    }

    #[inline(always)]
    fn bucket_upper_us(idx: usize) -> u32 {
        if idx < 256 {
            ((idx + 1) * 100) as u32
        } else if idx < 384 {
            25_600 + ((idx - 256 + 1) * 1_000) as u32
        } else {
            153_600 + ((idx - 384 + 1) * 40_000) as u32
        }
    }

    #[inline(always)]
    pub fn record_us(&mut self, us: u32) {
        self.buckets[Self::bucket_of(us)] += 1;
        self.count += 1;
        self.sum_us += us as u64;
        if us < self.min_us {
            self.min_us = us;
        }
        if us > self.max_us {
            self.max_us = us;
        }
    }

    /// Returns the percentile value in µs (`permille`: `500` = P50, `990` = P99, `999` = P99.9).
    pub fn percentile_us(&self, permille: u32) -> u32 {
        if self.count == 0 {
            return 0;
        }
        let target = ((self.count as u128 * permille as u128 + 999) / 1000).max(1) as u64;
        let mut acc = 0u64;
        for (i, &c) in self.buckets.iter().enumerate() {
            acc += c as u64;
            if acc >= target {
                return Self::bucket_upper_us(i).min(self.max_us);
            }
        }
        self.max_us
    }

    /// True 1% or 0.1% low FPS (`fps * 100`) derived from worst-tail average frame interval.
    pub fn low_fps_x100(&self, worst_permille: u32) -> u16 {
        if self.count == 0 {
            return 0;
        }
        let need = ((self.count as u128 * worst_permille as u128 + 999) / 1000).max(1) as u64;
        let mut rem = need;
        let mut tail_us = 0u128;
        for i in (0..512).rev() {
            let c = self.buckets[i] as u64;
            if c == 0 {
                continue;
            }
            let take = c.min(rem);
            tail_us += take as u128 * Self::bucket_upper_us(i) as u128;
            rem -= take;
            if rem == 0 {
                break;
            }
        }
        let avg_us = (tail_us / need as u128).max(1);
        // fps * 100 = 100_000_000 / avg_us
        (100_000_000u128 / avg_us).min(u16::MAX as u128) as u16
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc32c_known_vector_and_hw_parity() {
        // Standard RFC 3720 / iSCSI check value for "123456789" is 0xE3069283.
        assert_eq!(crc32c_scalar(0, b"123456789"), 0xE306_9283);
        assert_eq!(crc32c(0, b"123456789"), 0xE306_9283);
    }

    #[test]
    fn dod_varint_compresses_120fps_to_near_one_byte_per_frame() {
        let mut ts = [0i64; 120];
        let mut cur = 1_000_000_000i64;
        for i in 0..120 {
            ts[i] = cur;
            cur += 8_333 + ((i as i64 % 5) - 2) * 3; // tiny ±6 us jitter
        }
        let mut enc = [0u8; 512];
        let used = encode_dod_i64(&ts, &mut enc).unwrap();
        // 120 timestamps (~960 B raw) compress to < 140 bytes!
        assert!(used < 140, "expected compact encoding, got {used} B");

        let mut dec = [0i64; 120];
        let consumed = decode_dod_i64(&enc[..used], &mut dec).unwrap();
        assert_eq!(consumed, used);
        assert_eq!(ts, dec);
    }

    #[test]
    fn latency_hist_percentiles_and_lows() {
        let mut h = LatencyHist::new();
        for _ in 0..990 {
            h.record_us(8_333); // 120 fps
        }
        for _ in 0..10 {
            h.record_us(33_333); // 1% slow frames (~30 fps)
        }
        assert!((8_300..=8_500).contains(&h.percentile_us(500)));
        assert!((33_000..=34_000).contains(&h.percentile_us(995)));
        let low1 = h.low_fps_x100(10); // worst 1%
        assert!((2900..=3100).contains(&low1), "got low1={low1}");
    }
}
