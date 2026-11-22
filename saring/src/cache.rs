// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: Apache-2.0

//! 16-shard DNS wire-packet cache with RFC 8767 Serve-Stale.
//!
//! Entries stay lazily allocated (0 B while unused, ≤ 1.2 MB at 4096 entries). Lookups never
//! allocate, rewrite the 2-byte transaction ID into the caller's slice and return expired entries
//! immediately while signalling a single background refresh.

use crate::dns::{RCODE_NOERROR, RCODE_SERVFAIL};
use std::sync::Mutex;

const SHARDS: usize = 16;
const SLOTS_PER_SHARD: usize = 256; // 16 * 256 = 4096 entries (~2048 dual-stack hosts)
const INLINE_CAP: usize = 256;

pub const MIN_POS_TTL_SECS: u32 = 300;
pub const MAX_POS_TTL_SECS: u32 = 86_400;
pub const MIN_NEG_TTL_SECS: u32 = 10;
pub const MAX_NEG_TTL_SECS: u32 = 60;
pub const STALE_WINDOW_SECS: i64 = 86_400;
const REFRESH_COOLDOWN_SECS: i64 = 15;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lookup {
    Fresh { len: usize, rcode: u8 },
    Stale { len: usize, rcode: u8, refresh: bool },
    Miss,
}

enum Wire {
    Inline { buf: [u8; INLINE_CAP], len: u16 },
    Heap(Box<[u8]>),
}

impl Wire {
    fn from_slice(src: &[u8]) -> Self {
        if src.len() <= INLINE_CAP {
            let mut buf = [0u8; INLINE_CAP];
            buf[..src.len()].copy_from_slice(src);
            Self::Inline { buf, len: src.len() as u16 }
        } else {
            Self::Heap(src.to_vec().into_boxed_slice())
        }
    }

    #[inline]
    fn as_slice(&self) -> &[u8] {
        match self {
            Self::Inline { buf, len } => &buf[..*len as usize],
            Self::Heap(b) => b,
        }
    }
}

struct Entry {
    key: u64,
    netid: u32,
    rcode: u8,
    fresh_until: i64,
    stale_until: i64,
    refresh_at: i64,
    last_used: u64,
    wire: Wire,
}

#[derive(Default)]
struct Shard {
    tick: u64,
    entries: Vec<Entry>,
}

pub struct DnsCache {
    shards: [Mutex<Shard>; SHARDS],
}

impl Default for DnsCache {
    fn default() -> Self {
        Self::new()
    }
}

impl DnsCache {
    pub fn new() -> Self {
        Self { shards: std::array::from_fn(|_| Mutex::new(Shard::default())) }
    }

    #[inline]
    fn shard_of(key: u64) -> usize {
        ((key >> 32) as usize) & (SHARDS - 1)
    }

    /// Probes the cache and, on hit, writes the answer with `qid` into `out`.
    pub fn lookup(&self, netid: u32, key: u64, qid: u16, now_sec: i64, out: &mut [u8]) -> Lookup {
        let Ok(mut shard) = self.shards[Self::shard_of(key)].lock() else {
            return Lookup::Miss;
        };
        let Some(pos) = shard.entries.iter().position(|e| e.key == key && e.netid == netid) else {
            return Lookup::Miss;
        };

        if now_sec >= shard.entries[pos].stale_until {
            shard.entries.swap_remove(pos);
            return Lookup::Miss;
        }

        let pkt = shard.entries[pos].wire.as_slice();
        if pkt.len() < 12 || pkt.len() > out.len() {
            return Lookup::Miss;
        }
        let len = pkt.len();
        out[..len].copy_from_slice(pkt);
        out[0..2].copy_from_slice(&qid.to_be_bytes());

        shard.tick = shard.tick.wrapping_add(1);
        let tick = shard.tick;
        let entry = &mut shard.entries[pos];
        entry.last_used = tick;
        let rcode = entry.rcode;

        if now_sec < entry.fresh_until {
            Lookup::Fresh { len, rcode }
        } else {
            let refresh = now_sec >= entry.refresh_at;
            if refresh {
                entry.refresh_at = now_sec + REFRESH_COOLDOWN_SECS;
            }
            Lookup::Stale { len, rcode, refresh }
        }
    }

    /// Stores a verified answer packet, clamping positive TTLs to `[300 s, 86400 s]` and negative
    /// TTLs to `[10 s, 60 s]`. Never caches `SERVFAIL`.
    pub fn insert(
        &self,
        netid: u32,
        key: u64,
        packet: &[u8],
        rcode: u8,
        ancount: u16,
        raw_ttl: u32,
        now_sec: i64,
    ) {
        if packet.len() < 12 || rcode == RCODE_SERVFAIL {
            return;
        }
        let positive = rcode == RCODE_NOERROR && ancount > 0;
        let ttl = if positive {
            raw_ttl.clamp(MIN_POS_TTL_SECS, MAX_POS_TTL_SECS)
        } else {
            raw_ttl.clamp(MIN_NEG_TTL_SECS, MAX_NEG_TTL_SECS)
        };
        let fresh_until = now_sec.saturating_add(i64::from(ttl));
        let stale_until = if positive {
            fresh_until.saturating_add(STALE_WINDOW_SECS)
        } else {
            fresh_until
        };

        let Ok(mut shard) = self.shards[Self::shard_of(key)].lock() else {
            return;
        };
        shard.tick = shard.tick.wrapping_add(1);
        let tick = shard.tick;

        if let Some(existing) = shard.entries.iter_mut().find(|e| e.key == key && e.netid == netid)
        {
            existing.rcode = rcode;
            existing.fresh_until = fresh_until;
            existing.stale_until = stale_until;
            existing.refresh_at = 0;
            existing.last_used = tick;
            existing.wire = Wire::from_slice(packet);
            return;
        }

        let new_entry = Entry {
            key,
            netid,
            rcode,
            fresh_until,
            stale_until,
            refresh_at: 0,
            last_used: tick,
            wire: Wire::from_slice(packet),
        };

        if shard.entries.len() < SLOTS_PER_SHARD {
            shard.entries.push(new_entry);
            return;
        }

        // Evict an expired entry first, else the least-recently-used slot.
        let victim = shard
            .entries
            .iter()
            .position(|e| now_sec >= e.stale_until)
            .unwrap_or_else(|| {
                shard
                    .entries
                    .iter()
                    .enumerate()
                    .min_by_key(|(_, e)| e.last_used)
                    .map_or(0, |(i, _)| i)
            });
        shard.entries[victim] = new_entry;
    }

    pub fn flush_net(&self, netid: u32) {
        for s in &self.shards {
            if let Ok(mut shard) = s.lock() {
                shard.entries.retain(|e| e.netid != netid);
            }
        }
    }

    pub fn clear(&self) {
        for s in &self.shards {
            if let Ok(mut shard) = s.lock() {
                shard.entries.clear();
            }
        }
    }

    pub fn len(&self) -> usize {
        self.shards.iter().filter_map(|s| s.lock().ok()).map(|s| s.entries.len()).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_pkt(qid: u16) -> Vec<u8> {
        let mut p = vec![0u8; 48];
        p[0..2].copy_from_slice(&qid.to_be_bytes());
        p[2] = 0x81;
        p[3] = 0x80;
        p[5] = 1;
        p[7] = 1;
        p
    }

    #[test]
    fn clamps_ttl_serves_stale_and_rewrites_qid() {
        let cache = DnsCache::new();
        let pkt = dummy_pkt(0x1111);
        // Short 10s CDN TTL gets clamped up to 300s.
        cache.insert(100, 0xABCD_0001_0000_0000, &pkt, 0, 1, 10, 1000);

        let mut out = [0u8; 512];
        // Still fresh at +299s (would have expired at +10s in stock AOSP).
        assert_eq!(
            cache.lookup(100, 0xABCD_0001_0000_0000, 0x2222, 1299, &mut out),
            Lookup::Fresh { len: 48, rcode: 0 }
        );
        assert_eq!(&out[0..2], &0x2222u16.to_be_bytes());

        // At +301s: Serve-Stale returns immediately and asks for one background refresh.
        assert_eq!(
            cache.lookup(100, 0xABCD_0001_0000_0000, 0x3333, 1301, &mut out),
            Lookup::Stale { len: 48, rcode: 0, refresh: true }
        );
        assert_eq!(&out[0..2], &0x3333u16.to_be_bytes());

        // Second concurrent stale hit within cooldown does not duplicate refresh.
        assert_eq!(
            cache.lookup(100, 0xABCD_0001_0000_0000, 0x4444, 1302, &mut out),
            Lookup::Stale { len: 48, rcode: 0, refresh: false }
        );

        // Beyond 24h stale window -> Miss.
        assert_eq!(
            cache.lookup(100, 0xABCD_0001_0000_0000, 0x5555, 1300 + STALE_WINDOW_SECS + 1, &mut out),
            Lookup::Miss
        );
    }

    #[test]
    fn negative_ttl_capped_and_servfail_ignored() {
        let cache = DnsCache::new();
        let pkt = dummy_pkt(0xAAAA);
        cache.insert(100, 1, &pkt, RCODE_SERVFAIL, 0, 300, 1000);
        assert!(cache.is_empty());

        // NXDOMAIN with 3600s SOA gets capped at 60s and has no stale window.
        cache.insert(100, 2, &pkt, 3, 0, 3600, 1000);
        let mut out = [0u8; 512];
        assert_eq!(cache.lookup(100, 2, 0xBBBB, 1059, &mut out), Lookup::Fresh { len: 48, rcode: 3 });
        assert_eq!(cache.lookup(100, 2, 0xCCCC, 1060, &mut out), Lookup::Miss);
    }
}
