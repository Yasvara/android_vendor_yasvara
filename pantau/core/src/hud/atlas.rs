// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: Apache-2.0

//! Zero-copy `mmap` reader for prebaked Google Sans Flex glyph & monochrome icon atlas
//! (`/system_ext/etc/pantau/atlas.bin`, magic `"PNA1"` v2).
//!
//! Validates magic, version, table size, and every glyph bitmap range ONCE on open so
//! runtime blitting never panics, never allocates, and runs O(1) lookup for ASCII, symbols,
//! and prebaked monochrome Material You icons (kernel chip, system daemon, thread split).

use core::mem::size_of;
use core::ptr;
use std::fs::File;
use std::os::unix::io::AsRawFd;

use crate::sys::{munmap_region, MAP_SHARED, PROT_READ};

pub const ATLAS_MAGIC: u32 = 0x3141_4E50; // "PNA1"
pub const ATLAS_VERSION: u16 = 2;
pub const STYLE_COUNT: usize = 4;
pub const ASCII_START: u32 = 32;
pub const ASCII_COUNT: usize = 95;
pub const GLYPHS_PER_STYLE: usize = 106;

/// Style IDs matching `tools/atlas_bake.cpp`.
pub const STYLE_LABEL: u8 = 0; // 26px
pub const STYLE_VALUE: u8 = 1; // 30px
pub const STYLE_BIG: u8 = 2;   // 54px
pub const STYLE_MICRO: u8 = 3; // 20px (top-docked y=0 Mini bar)

/// Compact glyph indices for extra symbols & monochrome icons past ASCII `32..=126`.
pub const SYM_DEGREE: u16 = 95;       // °
pub const SYM_MIDDOT: u16 = 96;       // ·
pub const SYM_EMDASH: u16 = 97;       // —
pub const SYM_DOWN: u16 = 98;         // ↓
pub const SYM_UP: u16 = 99;           // ↑
pub const SYM_MULT: u16 = 100;        // ×
pub const SYM_ELLIPSIS: u16 = 101;    // …
pub const SYM_PLUSMINUS: u16 = 102;   // ±
pub const SYM_ICON_KERNEL: u16 = 103; // 24x24 CPU chip (STYLE_LABEL)
pub const SYM_ICON_DAEMON: u16 = 104; // 24x24 terminal `>_` (STYLE_LABEL)
pub const SYM_ICON_THREAD: u16 = 105; // 24x24 thread fork (STYLE_LABEL)

#[repr(C, packed)]
#[derive(Copy, Clone, Debug)]
struct RawHeader {
    magic: u32,
    version: u16,
    style_count: u16,
    glyphs_per_style: u32,
    glyph_count: u32,
    bitmap_offset: u32,
    bitmap_size: u32,
    line_heights: [u16; STYLE_COUNT],
    ascents: [u16; STYLE_COUNT],
}

#[repr(C, packed)]
#[derive(Copy, Clone, Debug, Default)]
pub struct GlyphInfo {
    pub codepoint: u32,
    pub bitmap_off: u32,
    pub w: u16,
    pub h: u16,
    pub bearing_x: i16,
    pub bearing_y: i16,
    pub advance_x: u16,
    pub style: u8,
    pub _pad: u8,
}

const _: () = assert!(size_of::<RawHeader>() == 40);
const _: () = assert!(size_of::<GlyphInfo>() == 20);

/// Validated zero-copy view over an in-memory or `mmap`'d `atlas.bin`.
pub struct AtlasView<'a> {
    bytes: &'a [u8],
    glyphs_per_style: usize,
    bitmap_offset: usize,
    line_heights: [u16; STYLE_COUNT],
    ascents: [u16; STYLE_COUNT],
}

impl<'a> AtlasView<'a> {
    /// Validates the entire atlas buffer once; damaged or truncated files cleanly return `None`.
    pub fn open(bytes: &'a [u8]) -> Option<Self> {
        if bytes.len() < size_of::<RawHeader>() {
            return None;
        }
        // SAFETY: length verified; `read_unaligned` handles packed alignment.
        let hdr = unsafe { ptr::read_unaligned(bytes.as_ptr() as *const RawHeader) };
        let magic = hdr.magic;
        let version = hdr.version;
        let style_count = hdr.style_count as usize;
        let gps = hdr.glyphs_per_style as usize;
        let gcount = hdr.glyph_count as usize;
        let bm_off = hdr.bitmap_offset as usize;
        let bm_size = hdr.bitmap_size as usize;

        if magic != ATLAS_MAGIC
            || version != ATLAS_VERSION
            || style_count != STYLE_COUNT
            || gps != GLYPHS_PER_STYLE
            || gcount != STYLE_COUNT * GLYPHS_PER_STYLE
        {
            return None;
        }
        let table_end = size_of::<RawHeader>().checked_add(gcount.checked_mul(size_of::<GlyphInfo>())?)?;
        if bm_off < table_end || bm_off.checked_add(bm_size)? > bytes.len() {
            return None;
        }

        // Validate every glyph's bitmap span up front so blitting needs zero bounds checks.
        for idx in 0..gcount {
            let off = size_of::<RawHeader>() + idx * size_of::<GlyphInfo>();
            // SAFETY: `off + size_of::<GlyphInfo>() <= table_end <= bytes.len()`.
            let g = unsafe { ptr::read_unaligned(bytes.as_ptr().add(off) as *const GlyphInfo) };
            let span = (g.w as usize).checked_mul(g.h as usize)?;
            let end = (g.bitmap_off as usize).checked_add(span)?;
            if end > bm_size {
                return None;
            }
        }

        Some(Self {
            bytes,
            glyphs_per_style: gps,
            bitmap_offset: bm_off,
            line_heights: hdr.line_heights,
            ascents: hdr.ascents,
        })
    }

    #[inline(always)]
    pub fn line_height(&self, style: u8) -> u16 {
        self.line_heights[(style as usize).min(STYLE_COUNT - 1)]
    }

    #[inline(always)]
    pub fn ascent(&self, style: u8) -> u16 {
        self.ascents[(style as usize).min(STYLE_COUNT - 1)]
    }

    /// Maps an ASCII byte (`32..=126`) to its O(1) glyph slot index.
    #[inline(always)]
    pub const fn ascii_glyph_id(b: u8) -> u16 {
        if b >= 32 && b <= 126 {
            (b - 32) as u16
        } else {
            0 // space
        }
    }

    /// O(1) lookup by `(style, glyph_id)` returning `(GlyphInfo, alpha8_slice)`.
    #[inline(always)]
    pub fn glyph(&self, style: u8, glyph_id: u16) -> Option<(GlyphInfo, &'a [u8])> {
        let s = style as usize;
        let id = glyph_id as usize;
        if s >= STYLE_COUNT || id >= self.glyphs_per_style {
            return None;
        }
        let idx = s * self.glyphs_per_style + id;
        let off = size_of::<RawHeader>() + idx * size_of::<GlyphInfo>();
        // SAFETY: validated in `AtlasView::open`.
        let g = unsafe { ptr::read_unaligned(self.bytes.as_ptr().add(off) as *const GlyphInfo) };
        let bstart = self.bitmap_offset + g.bitmap_off as usize;
        let blen = (g.w as usize) * (g.h as usize);
        Some((g, &self.bytes[bstart..bstart + blen]))
    }

    /// Computes horizontal pixel advance of an ASCII slice in a given style.
    #[inline]
    pub fn measure_ascii(&self, style: u8, s: &[u8]) -> i32 {
        let mut w = 0i32;
        for &b in s {
            if let Some((g, _)) = self.glyph(style, Self::ascii_glyph_id(b)) {
                w += g.advance_x as i32;
            }
        }
        w
    }

    /// Computes horizontal pixel advance of a glyph-ID slice.
    #[inline]
    pub fn measure_ids(&self, style: u8, ids: &[u16]) -> i32 {
        let mut w = 0i32;
        for &id in ids {
            if let Some((g, _)) = self.glyph(style, id) {
                w += g.advance_x as i32;
            }
        }
        w
    }
}

/// Owned `PROT_READ, MAP_SHARED` mapping of `/system_ext/etc/pantau/atlas.bin`.
pub struct MappedAtlas {
    ptr: *mut u8,
    len: usize,
}

// SAFETY: immutable read-only file mapping.
unsafe impl Send for MappedAtlas {}
unsafe impl Sync for MappedAtlas {}

impl MappedAtlas {
    pub fn open_file(path: &str) -> Option<Self> {
        extern "C" {
            fn mmap(
                addr: *mut core::ffi::c_void,
                length: usize,
                prot: core::ffi::c_int,
                flags: core::ffi::c_int,
                fd: core::ffi::c_int,
                offset: i64,
            ) -> *mut core::ffi::c_void;
        }
        let file = File::open(path).ok()?;
        let len = file.metadata().ok()?.len() as usize;
        if len < size_of::<RawHeader>() || len > 4 * 1024 * 1024 {
            return None;
        }
        // SAFETY: valid file fd and checked length.
        let p = unsafe { mmap(ptr::null_mut(), len, PROT_READ, MAP_SHARED, file.as_raw_fd(), 0) };
        if p.is_null() || p == (!0usize as *mut core::ffi::c_void) {
            return None;
        }
        let mapped = Self { ptr: p as *mut u8, len };
        if mapped.view().is_none() {
            return None;
        }
        Some(mapped)
    }

    /// Loads the default platform atlas path (`/system_ext/etc/pantau/atlas.bin`).
    pub fn open_default() -> Option<Self> {
        if let Ok(env_path) = std::env::var("PANTAU_ATLAS_PATH") {
            if let Some(m) = Self::open_file(&env_path) {
                return Some(m);
            }
        }
        Self::open_file("/system_ext/etc/pantau/atlas.bin")
            .or_else(|| Self::open_file("/system/etc/pantau/atlas.bin"))
    }

    #[inline]
    pub fn view(&self) -> Option<AtlasView<'_>> {
        // SAFETY: `self.ptr` stays mapped for `self`'s lifetime.
        let slice = unsafe { core::slice::from_raw_parts(self.ptr, self.len) };
        AtlasView::open(slice)
    }
}

impl Drop for MappedAtlas {
    fn drop(&mut self) {
        // SAFETY: mapped with `self.len` in `open_file`.
        unsafe { munmap_region(self.ptr, self.len) };
    }
}

/// Builds a compact synthetic atlas in RAM (used by host tests & benchmarks without external files).
pub fn build_synthetic_atlas() -> Vec<u8> {
    let px: [u16; STYLE_COUNT] = [26, 30, 54, 20];
    let gcount = STYLE_COUNT * GLYPHS_PER_STYLE;
    let mut metrics = vec![GlyphInfo::default(); gcount];
    let mut bitmaps = Vec::<u8>::with_capacity(16 * 1024);

    for (s, &sz) in px.iter().enumerate() {
        let gw = (sz / 2).max(8);
        let gh = ((sz * 3) / 4).max(10);
        for id in 0..GLYPHS_PER_STYLE {
            let idx = s * GLYPHS_PER_STYLE + id;
            let is_icon = id >= (SYM_ICON_KERNEL as usize);
            let m = &mut metrics[idx];
            m.codepoint = if id < ASCII_COUNT {
                ASCII_START + id as u32
            } else {
                0x2000 + id as u32
            };
            m.style = s as u8;
            if is_icon {
                if s == 0 {
                    m.w = 24;
                    m.h = 24;
                    m.bearing_x = 0;
                    m.bearing_y = 21;
                    m.advance_x = 28;
                    m.bitmap_off = bitmaps.len() as u32;
                    let fill = (160 + (id as u8 & 3) * 24).min(255);
                    bitmaps.resize(bitmaps.len() + 24 * 24, fill);
                }
                continue;
            }
            m.advance_x = gw + 2;
            if id == 0 {
                // Space: empty bitmap.
                continue;
            }
            m.w = gw;
            m.h = gh;
            m.bearing_x = 1;
            m.bearing_y = gh as i16;
            m.bitmap_off = bitmaps.len() as u32;
            // Vary the interior alpha pattern by glyph id so different characters produce
            // distinct rendered pixels in unit tests.
            let seed = ((id as u32).wrapping_mul(37) & 0x7f) as u8 + 96;
            for r in 0..gh {
                for c in 0..gw {
                    let edge = r == 0 || r + 1 == gh || c == 0 || c + 1 == gw;
                    let pat = ((r as usize + c as usize + id) % 3 == 0) as u8;
                    let a = if edge { 220 } else if pat != 0 { seed } else { 140 };
                    bitmaps.push(a);
                }
            }
        }
    }

    let bm_off = size_of::<RawHeader>() + metrics.len() * size_of::<GlyphInfo>();
    let hdr = RawHeader {
        magic: ATLAS_MAGIC,
        version: ATLAS_VERSION,
        style_count: STYLE_COUNT as u16,
        glyphs_per_style: GLYPHS_PER_STYLE as u32,
        glyph_count: gcount as u32,
        bitmap_offset: bm_off as u32,
        bitmap_size: bitmaps.len() as u32,
        line_heights: [30, 34, 60, 24],
        ascents: [24, 28, 48, 18],
    };

    let mut out = Vec::with_capacity(bm_off + bitmaps.len());
    // SAFETY: `RawHeader` and `GlyphInfo` are packed POD structs.
    unsafe {
        out.extend_from_slice(core::slice::from_raw_parts(
            (&hdr as *const RawHeader) as *const u8,
            size_of::<RawHeader>(),
        ));
        out.extend_from_slice(core::slice::from_raw_parts(
            metrics.as_ptr() as *const u8,
            metrics.len() * size_of::<GlyphInfo>(),
        ));
    }
    out.extend_from_slice(&bitmaps);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn atlas_validates_and_rejects_corruption() {
        let mut raw = build_synthetic_atlas();
        let view = AtlasView::open(&raw).expect("valid synthetic atlas");
        assert_eq!(view.line_height(STYLE_BIG), 60);
        assert_eq!(view.line_height(STYLE_MICRO), 24);
        let (g, bm) = view.glyph(STYLE_VALUE, AtlasView::ascii_glyph_id(b'9')).unwrap();
        assert_eq!(bm.len(), (g.w as usize) * (g.h as usize));
        assert!(view.measure_ascii(STYLE_MICRO, b"120") > 0);
        let (ik, ibm) = view.glyph(STYLE_LABEL, SYM_ICON_KERNEL).unwrap();
        assert_eq!((ik.w, ik.h, ibm.len()), (24, 24, 24 * 24));

        // Corrupt magic → must cleanly reject.
        raw[0] ^= 0xff;
        assert!(AtlasView::open(&raw).is_none());
    }
}
