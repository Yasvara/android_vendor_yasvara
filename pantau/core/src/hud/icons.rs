// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: Apache-2.0

//! Fixed-capacity 64-slot LRU cache for app icons (`28×28` RGBA8888) and friendly labels
//! pushed lazily (once per UID) from `PentasService`.
//!
//! Zero heap allocations on steady ticks; O(64) scan takes ~40 ns on aarch64.

pub const ICON_DIM: usize = 28;
pub const ICON_BYTES: usize = ICON_DIM * ICON_DIM * 4; // 3136 bytes
pub const ICON_SLOTS: usize = 64;
pub const LABEL_SLOTS: usize = 256;
pub const LABEL_CAP: usize = 28;

#[derive(Copy, Clone)]
struct LabelSlot {
    uid: u32,
    used_tick: u32,
    label: [u8; LABEL_CAP],
    label_len: u8,
}

impl Default for LabelSlot {
    fn default() -> Self {
        Self {
            uid: 0,
            used_tick: 0,
            label: [0; LABEL_CAP],
            label_len: 0,
        }
    }
}

#[derive(Clone)]
struct IconSlot {
    uid: u32,
    used_tick: u32,
    rgba: [u8; ICON_BYTES],
}

impl Default for IconSlot {
    fn default() -> Self {
        Self {
            uid: 0,
            used_tick: 0,
            rgba: [0; ICON_BYTES],
        }
    }
}

pub struct IconCache {
    labels: Box<[LabelSlot; LABEL_SLOTS]>,
    icons: Box<[IconSlot; ICON_SLOTS]>,
    clock: u32,
    generation: u32,
}

impl Default for IconCache {
    fn default() -> Self {
        Self::new()
    }
}

impl IconCache {
    pub fn new() -> Self {
        // Allocated once on heap at daemon init (~210 KB total), never reallocated afterwards.
        let mut lv = Vec::with_capacity(LABEL_SLOTS);
        for _ in 0..LABEL_SLOTS {
            lv.push(LabelSlot::default());
        }
        let labels: Box<[LabelSlot; LABEL_SLOTS]> = lv.into_boxed_slice().try_into().ok().unwrap();

        let mut iv = Vec::with_capacity(ICON_SLOTS);
        for _ in 0..ICON_SLOTS {
            iv.push(IconSlot::default());
        }
        let icons: Box<[IconSlot; ICON_SLOTS]> = iv.into_boxed_slice().try_into().ok().unwrap();
        Self {
            labels,
            icons,
            clock: 1,
            generation: 1,
        }
    }

    #[inline]
    pub fn generation(&self) -> u32 {
        self.generation
    }

    /// Inserts or updates `(label, optional 28×28 RGBA)` for `uid` (0 heap allocations!).
    /// Label-only updates (`rgba.is_empty()`) preserve any previously cached 28×28 RGBA icon.
    pub fn put(&mut self, uid: u32, label: &[u8], rgba: &[u8]) {
        if uid == 0 {
            return;
        }
        self.clock = self.clock.wrapping_add(1).max(1);
        let mut changed = false;

        if !label.is_empty() {
            let mut target = None;
            let mut lru_idx = 0usize;
            let mut lru_tick = u32::MAX;
            for (i, s) in self.labels.iter().enumerate() {
                if s.uid == uid {
                    target = Some(i);
                    break;
                }
                if s.uid == 0 && target.is_none() {
                    target = Some(i);
                }
                if s.used_tick < lru_tick {
                    lru_tick = s.used_tick;
                    lru_idx = i;
                }
            }
            let idx = target.unwrap_or(lru_idx);
            let slot = &mut self.labels[idx];
            let n = label.len().min(LABEL_CAP);
            if slot.uid != uid || slot.label_len as usize != n || slot.label[..n] != label[..n] {
                slot.uid = uid;
                slot.label[..n].copy_from_slice(&label[..n]);
                slot.label_len = n as u8;
                changed = true;
            }
            slot.used_tick = self.clock;
        }

        if rgba.len() == ICON_BYTES {
            let mut target = None;
            let mut lru_idx = 0usize;
            let mut lru_tick = u32::MAX;
            for (i, s) in self.icons.iter().enumerate() {
                if s.uid == uid {
                    target = Some(i);
                    break;
                }
                if s.uid == 0 && target.is_none() {
                    target = Some(i);
                }
                if s.used_tick < lru_tick {
                    lru_tick = s.used_tick;
                    lru_idx = i;
                }
            }
            let idx = target.unwrap_or(lru_idx);
            let slot = &mut self.icons[idx];
            slot.uid = uid;
            slot.used_tick = self.clock;
            slot.rgba.copy_from_slice(rgba);
            changed = true;
        }

        if changed {
            self.generation = self.generation.wrapping_add(1).max(1);
        }
    }

    /// Looks up cached friendly label for `uid` (falling back to `appId = uid % 100_000`).
    #[inline]
    pub fn label_of(&self, uid: u32) -> Option<&[u8]> {
        if uid == 0 {
            return None;
        }
        let app_id = uid % 100_000;
        let mut fallback: Option<&[u8]> = None;
        for s in self.labels.iter() {
            if s.uid == uid {
                return Some(&s.label[..s.label_len as usize]);
            }
            if app_id != uid && s.uid == app_id && fallback.is_none() {
                fallback = Some(&s.label[..s.label_len as usize]);
            }
        }
        fallback
    }

    #[inline]
    fn icon_of(&self, uid: u32) -> Option<&[u8]> {
        if uid == 0 {
            return None;
        }
        let app_id = uid % 100_000;
        let mut fallback: Option<&[u8]> = None;
        for s in self.icons.iter() {
            if s.uid == uid {
                return Some(&s.rgba[..]);
            }
            if app_id != uid && s.uid == app_id && fallback.is_none() {
                fallback = Some(&s.rgba[..]);
            }
        }
        fallback
    }

    /// Looks up `(friendly_label, optional_rgba_28x28)` for `uid` without allocating.
    #[inline]
    pub fn get(&self, uid: u32) -> Option<(&[u8], Option<&[u8]>)> {
        let lbl = self.label_of(uid);
        let img = self.icon_of(uid);
        match (lbl, img) {
            (Some(l), i) => Some((l, i)),
            (None, Some(i)) => Some((&[], Some(i))),
            (None, None) => None,
        }
    }
}

/// Zero-alloc smart process/daemon name shortener (prevents 2-line wraps on long Android HALs
/// like `vendor.qti.hardware.display.composer-service` or `kworker/u16:1-ufs_clkscaling_0`).
pub fn shorten_proc_name<'a>(raw: &'a [u8], out: &'a mut [u8; 32]) -> &'a [u8] {
    // Strip path prefix if present (e.g. `/vendor/bin/hw/foo` -> `foo`).
    let s = if let Some(pos) = raw.iter().rposition(|&b| b == b'/') {
        if raw.starts_with(b"kworker/") || raw.starts_with(b"irq/") {
            raw
        } else {
            &raw[pos + 1..]
        }
    } else {
        raw
    };

    // Shorten `vendor.qti.hardware.display.composer-service` -> `composer-service`.
    let trimmed = if s.starts_with(b"vendor.") || s.starts_with(b"android.hardware.") {
        if let Some(dot) = s.iter().rposition(|&b| b == b'.') {
            if dot + 1 < s.len() {
                &s[dot + 1..]
            } else {
                s
            }
        } else {
            s
        }
    } else if let Some(rest) = s.strip_prefix(b"kworker/") {
        // `kworker/u16:1-ufs_clkscaling_0` -> `kworker/ufs_clkscaling_0`
        if let Some(dash) = rest.iter().position(|&b| b == b'-') {
            if dash + 1 < rest.len() {
                let mut p = 0usize;
                let pref = b"kworker/";
                out[..pref.len()].copy_from_slice(pref);
                p += pref.len();
                let tail = &rest[dash + 1..];
                let n = tail.len().min(out.len() - p);
                out[p..p + n].copy_from_slice(&tail[..n]);
                return &out[..p + n];
            }
        }
        s
    } else {
        s
    };

    let n = trimmed.len().min(out.len());
    out[..n].copy_from_slice(&trimmed[..n]);
    &out[..n]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn icon_cache_put_get_and_shortener() {
        let mut cache = IconCache::new();
        let px = [0x80u8; ICON_BYTES];
        cache.put(10242, b"Mobile Legends", &px);
        let (lbl, img) = cache.get(10242).expect("hit");
        assert_eq!(lbl, b"Mobile Legends");
        assert_eq!(img.unwrap().len(), ICON_BYTES);
        assert!(cache.get(99999).is_none());

        let mut buf = [0u8; 32];
        assert_eq!(
            shorten_proc_name(b"vendor.qti.hardware.display.composer-service", &mut buf),
            b"composer-service"
        );
        assert_eq!(
            shorten_proc_name(b"kworker/u16:1-ufs_clkscaling_0", &mut buf),
            b"kworker/ufs_clkscaling_0"
        );
    }
}
