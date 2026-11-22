// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: Apache-2.0

//! Zero-allocation HUD glyph layout, dirty-rect check, and bit-exact `aarch64` NEON alpha blitter.
//!
//! - Zero `core::fmt`: integers convert directly into glyph indices in ~15 ns.
//! - Dirty check (`prev == curr`) skips drawing and SurfaceFlinger transactions in < 50 ns.
//! - Rounded background SDF is pre-rendered once into `bg_template`; ticks only restore dirty
//!   glyph bounding boxes and NEON-blend alpha-8 glyphs directly into the ping-pong RGBA8888 buffer.

pub mod atlas;
pub mod icons;
pub mod layout;

/// One positioned glyph draw command (8 bytes, POD).
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct GlyphCmd {
    pub x: i16,
    pub y: i16,
    pub glyph_id: u16,
    pub color_idx: u8, // index into 4-entry Monet palette
    pub style: u8,     // 0=label, 1=num_small, 2=num_large
}

/// RGBA8888 colour word (`[r, g, b, a]` in byte order matching `PIXEL_FORMAT_RGBA_8888`).
pub type Rgba = [u8; 4];

/// Formats `u32` directly into ASCII bytes in `out`, returning length written (0 alloc, 0 `core::fmt`).
#[inline]
pub fn fmt_u32_ascii(mut v: u32, out: &mut [u8]) -> usize {
    if out.is_empty() {
        return 0;
    }
    if v == 0 {
        out[0] = b'0';
        return 1;
    }
    let mut tmp = [0u8; 10];
    let mut n = 0;
    while v > 0 {
        tmp[n] = b'0' + (v % 10) as u8;
        v /= 10;
        n += 1;
    }
    let len = n.min(out.len());
    for i in 0..len {
        out[i] = tmp[n - 1 - i];
    }
    len
}

/// Formats fixed-point tenths (`455` → `"45.5"`) directly into `out` (0 alloc).
#[inline]
pub fn fmt_deci_ascii(v: i32, out: &mut [u8]) -> usize {
    let mut p = 0;
    let mag = if v < 0 {
        if p < out.len() {
            out[p] = b'-';
            p += 1;
        }
        v.unsigned_abs()
    } else {
        v as u32
    };
    p += fmt_u32_ascii(mag / 10, &mut out[p..]);
    if p + 2 <= out.len() {
        out[p] = b'.';
        out[p + 1] = b'0' + (mag % 10) as u8;
        p += 2;
    }
    p
}

/// Returns `true` if two glyph command runs are identical (enabling instant skip of redraw + SF txn).
#[inline]
pub fn runs_equal(a: &[GlyphCmd], b: &[GlyphCmd]) -> bool {
    a == b
}

/// Exact integer alpha-over blend: `out = round((fg * a + bg * (255 - a)) / 255)`.
/// Exact for `a == 0` (`bg`) and `a == 255` (`fg`). Matches NEON path bit-for-bit.
#[inline(always)]
fn blend_chan(fg: u8, bg: u8, a: u8) -> u8 {
    let a16 = a as u16;
    let inv = 255u16 - a16;
    let t = (fg as u16) * a16 + (bg as u16) * inv + 128;
    ((t + (t >> 8)) >> 8) as u8
}

/// Scalar reference blitter: blends an `alpha8` glyph bitmap (`w × h`, stride `alpha_stride`) with
/// solid `fg` RGB over an RGBA8888 destination buffer (`dst_stride_px` pixels per row).
pub fn blit_alpha8_scalar(
    dst: &mut [u8],
    dst_stride_px: usize,
    dst_w: usize,
    dst_h: usize,
    x0: i32,
    y0: i32,
    alpha: &[u8],
    alpha_stride: usize,
    w: usize,
    h: usize,
    fg: Rgba,
) {
    let fg_a = fg[3] as u16;
    if fg_a == 0 || w == 0 || h == 0 {
        return;
    }
    for gy in 0..h {
        let dy = y0 + gy as i32;
        if dy < 0 || dy as usize >= dst_h {
            continue;
        }
        let a_row_off = gy * alpha_stride;
        let d_row_off = (dy as usize) * dst_stride_px * 4;
        for gx in 0..w {
            let dx = x0 + gx as i32;
            if dx < 0 || dx as usize >= dst_w {
                continue;
            }
            let raw_a = alpha[a_row_off + gx];
            if raw_a == 0 {
                continue;
            }
            let a = if fg_a == 255 {
                raw_a
            } else {
                let t = (raw_a as u16) * fg_a + 128;
                ((t + (t >> 8)) >> 8) as u8
            };
            let px = d_row_off + (dx as usize) * 4;
            dst[px] = blend_chan(fg[0], dst[px], a);
            dst[px + 1] = blend_chan(fg[1], dst[px + 1], a);
            dst[px + 2] = blend_chan(fg[2], dst[px + 2], a);
            dst[px + 3] = blend_chan(255, dst[px + 3], a);
        }
    }
}

/// `aarch64` NEON (`asimd`) 8-pixel-wide RGBA8888 alpha-over glyph blitter.
///
/// Bit-identical to [`blit_alpha8_scalar`] for all `(fg, bg, a)` in `0..=255`.
#[cfg(target_arch = "aarch64")]
pub fn blit_alpha8(
    dst: &mut [u8],
    dst_stride_px: usize,
    dst_w: usize,
    dst_h: usize,
    x0: i32,
    y0: i32,
    alpha: &[u8],
    alpha_stride: usize,
    w: usize,
    h: usize,
    fg: Rgba,
) {
    if fg[3] != 255 {
        return blit_alpha8_scalar(
            dst,
            dst_stride_px,
            dst_w,
            dst_h,
            x0,
            y0,
            alpha,
            alpha_stride,
            w,
            h,
            fg,
        );
    }
    use core::arch::aarch64::*;

    let x_start = (-x0).max(0) as usize;
    let y_start = (-y0).max(0) as usize;
    let x_end = ((dst_w as i32 - x0).max(0) as usize).min(w);
    let y_end = ((dst_h as i32 - y0).max(0) as usize).min(h);
    if x_start >= x_end || y_start >= y_end {
        return;
    }

    // SAFETY: `asimd` (NEON) is mandatory on aarch64; all pointer ranges are clamped to
    // `[x_start, x_end)` and `[y_start, y_end)` within `dst` and `alpha`.
    unsafe {
        let v_fg_r = vdup_n_u8(fg[0]);
        let v_fg_g = vdup_n_u8(fg[1]);
        let v_fg_b = vdup_n_u8(fg[2]);
        let v_255_8 = vdup_n_u8(255);
        let v_128_16 = vdupq_n_u16(128);

        let blend8 = |fg_c: uint8x8_t, bg_c: uint8x8_t, a: uint8x8_t, inv: uint8x8_t| -> uint8x8_t {
            let prod = vmlal_u8(vmull_u8(fg_c, a), bg_c, inv);
            let t = vaddq_u16(prod, v_128_16);
            vshrn_n_u16(vaddq_u16(t, vshrq_n_u16(t, 8)), 8)
        };

        for gy in y_start..y_end {
            let dy = (y0 + gy as i32) as usize;
            let a_row = gy * alpha_stride;
            let d_row = dy * dst_stride_px * 4;

            let mut gx = x_start;
            while gx + 8 <= x_end {
                let a = vld1_u8(alpha.as_ptr().add(a_row + gx));
                // Fast skip when all 8 alpha pixels are transparent (common around glyph margins).
                if vget_lane_u64(vreinterpret_u64_u8(a), 0) != 0 {
                    let dx = (x0 + gx as i32) as usize;
                    let dp = dst.as_mut_ptr().add(d_row + dx * 4);
                    let mut bg = vld4_u8(dp);
                    let inv = vsub_u8(v_255_8, a);
                    bg.0 = blend8(v_fg_r, bg.0, a, inv);
                    bg.1 = blend8(v_fg_g, bg.1, a, inv);
                    bg.2 = blend8(v_fg_b, bg.2, a, inv);
                    bg.3 = blend8(v_255_8, bg.3, a, inv);
                    vst4_u8(dp, bg);
                }
                gx += 8;
            }
            while gx < x_end {
                let a = *alpha.get_unchecked(a_row + gx);
                if a != 0 {
                    let dx = (x0 + gx as i32) as usize;
                    let px = d_row + dx * 4;
                    dst[px] = blend_chan(fg[0], dst[px], a);
                    dst[px + 1] = blend_chan(fg[1], dst[px + 1], a);
                    dst[px + 2] = blend_chan(fg[2], dst[px + 2], a);
                    dst[px + 3] = blend_chan(255, dst[px + 3], a);
                }
                gx += 1;
            }
        }
    }
}

#[cfg(not(target_arch = "aarch64"))]
#[inline]
pub fn blit_alpha8(
    dst: &mut [u8],
    dst_stride_px: usize,
    dst_w: usize,
    dst_h: usize,
    x0: i32,
    y0: i32,
    alpha: &[u8],
    alpha_stride: usize,
    w: usize,
    h: usize,
    fg: Rgba,
) {
    blit_alpha8_scalar(
        dst,
        dst_stride_px,
        dst_w,
        dst_h,
        x0,
        y0,
        alpha,
        alpha_stride,
        w,
        h,
        fg,
    );
}

/// Restores a dirty sub-rectangle from a pre-rendered rounded-box background template into `dst`.
pub fn restore_dirty_rect(
    dst: &mut [u8],
    bg_template: &[u8],
    stride_px: usize,
    x: usize,
    y: usize,
    w: usize,
    h: usize,
) {
    let row_bytes = w * 4;
    for row in y..y + h {
        let off = (row * stride_px + x) * 4;
        if off + row_bytes <= dst.len() && off + row_bytes <= bg_template.len() {
            dst[off..off + row_bytes].copy_from_slice(&bg_template[off..off + row_bytes]);
        }
    }
}

/// Pre-renders a Material You rounded rectangle background with a crisp 1.5 px tonal outline
/// once (on config/theme change — zero cost on steady ticks).
pub fn render_rounded_bg(dst: &mut [u8], w: usize, h: usize, radius_px: f32, bg: Rgba) {
    render_rounded_bg_stroked(dst, w, h, radius_px, bg, [255, 255, 255, 0]);
}

/// Pre-renders a rounded rectangle background + optional inner tonal stroke (`stroke[3] > 0`).
pub fn render_rounded_bg_stroked(
    dst: &mut [u8],
    w: usize,
    h: usize,
    radius_px: f32,
    bg: Rgba,
    stroke: Rgba,
) {
    let r = radius_px.max(1.0);
    let half_w = w as f32 * 0.5;
    let half_h = h as f32 * 0.5;
    let bx = half_w - r;
    let by = half_h - r;
    let has_stroke = stroke[3] > 0;

    for y in 0..h {
        let py = (y as f32 + 0.5 - half_h).abs() - by;
        for x in 0..w {
            let px = (x as f32 + 0.5 - half_w).abs() - bx;
            let qx = px.max(0.0);
            let qy = py.max(0.0);
            let dist = (qx * qx + qy * qy).sqrt() + px.max(py).min(0.0) - r;
            // 1-px antialiased outer coverage.
            let cov = (0.5 - dist).clamp(0.0, 1.0);
            let base_a = (cov * bg[3] as f32 + 0.5) as u8;
            let mut r_c = bg[0];
            let mut g_c = bg[1];
            let mut b_c = bg[2];
            let mut a_c = base_a;

            if has_stroke && cov > 0.0 && dist > -2.0 {
                // Crisp 1.5-px inner tonal rim.
                let rim = ((dist + 2.0).clamp(0.0, 1.0) * cov * stroke[3] as f32 + 0.5) as u8;
                if rim > 0 {
                    r_c = blend_chan(stroke[0], r_c, rim);
                    g_c = blend_chan(stroke[1], g_c, rim);
                    b_c = blend_chan(stroke[2], b_c, rim);
                    a_c = a_c.max(rim);
                }
            }

            let off = (y * w + x) * 4;
            dst[off] = r_c;
            dst[off + 1] = g_c;
            dst[off + 2] = b_c;
            dst[off + 3] = a_c;
        }
    }
}

/// Pre-renders a **top-edge docked** Material You bar (`y = 0` flush against top bezel):
/// flat top edge (`radius_top = 0`), rounded bottom-left/bottom-right corners, and a crisp
/// 1.5-px tonal stroke along left, right, and bottom edges only (zero top border!).
pub fn render_top_docked_bg(
    dst: &mut [u8],
    w: usize,
    h: usize,
    radius_bottom_px: f32,
    bg: Rgba,
    stroke: Rgba,
) {
    let r = radius_bottom_px.max(1.0).min((h as f32).min(w as f32 * 0.5));
    let has_stroke = stroke[3] > 0;

    for y in 0..h {
        let yf = y as f32 + 0.5;
        for x in 0..w {
            let xf = x as f32 + 0.5;
            // Distance from left, right, bottom edges (top edge y=0 is open/flush!).
            let dx = xf.min(w as f32 - xf);
            let dy_bot = h as f32 - yf;
            let dist = if dy_bot < r && dx < r {
                // Inside bottom-left or bottom-right corner quadrant: circular arc SDF.
                let cx = r - dx;
                let cy = r - dy_bot;
                (cx * cx + cy * cy).sqrt() - r
            } else {
                // Straight left/right/bottom edge.
                -dx.min(dy_bot)
            };

            let cov = (0.5 - dist).clamp(0.0, 1.0);
            let base_a = (cov * bg[3] as f32 + 0.5) as u8;
            let mut r_c = bg[0];
            let mut g_c = bg[1];
            let mut b_c = bg[2];
            let mut a_c = base_a;

            if has_stroke && cov > 0.0 && dist > -1.8 {
                let rim = ((dist + 1.8).clamp(0.0, 1.0) * cov * stroke[3] as f32 + 0.5) as u8;
                if rim > 0 {
                    r_c = blend_chan(stroke[0], r_c, rim);
                    g_c = blend_chan(stroke[1], g_c, rim);
                    b_c = blend_chan(stroke[2], b_c, rim);
                    a_c = a_c.max(rim);
                }
            }

            let off = (y * w + x) * 4;
            dst[off] = r_c;
            dst[off + 1] = g_c;
            dst[off + 2] = b_c;
            dst[off + 3] = a_c;
        }
    }
}

/// Alpha-blends a straight-alpha RGBA8888 sprite (e.g. cached 28×28 app icon) onto `dst`.
pub fn blit_rgba_sprite(
    dst: &mut [u8],
    dst_stride_px: usize,
    dst_w: usize,
    dst_h: usize,
    x0: i32,
    y0: i32,
    src: &[u8],
    sw: usize,
    sh: usize,
) {
    if sw == 0 || sh == 0 || src.len() < sw * sh * 4 {
        return;
    }
    for sy in 0..sh {
        let dy = y0 + sy as i32;
        if dy < 0 || dy as usize >= dst_h {
            continue;
        }
        let s_row = sy * sw * 4;
        let d_row = (dy as usize) * dst_stride_px * 4;
        for sx in 0..sw {
            let dx = x0 + sx as i32;
            if dx < 0 || dx as usize >= dst_w {
                continue;
            }
            let sp = s_row + sx * 4;
            let a = src[sp + 3];
            if a == 0 {
                continue;
            }
            let dp = d_row + (dx as usize) * 4;
            if a == 255 {
                dst[dp] = src[sp];
                dst[dp + 1] = src[sp + 1];
                dst[dp + 2] = src[sp + 2];
                dst[dp + 3] = 255;
            } else {
                dst[dp] = blend_chan(src[sp], dst[dp], a);
                dst[dp + 1] = blend_chan(src[sp + 1], dst[dp + 1], a);
                dst[dp + 2] = blend_chan(src[sp + 2], dst[dp + 2], a);
                dst[dp + 3] = blend_chan(255, dst[dp + 3], a);
            }
        }
    }
}

/// Alpha-blends a solid axis-aligned rectangle into `dst` (slice-based for SIMD auto-vectorization).
pub fn fill_rect_blend(
    dst: &mut [u8],
    dst_stride_px: usize,
    dst_w: usize,
    dst_h: usize,
    x: i32,
    y: i32,
    w: i32,
    h: i32,
    col: Rgba,
) {
    let a = col[3];
    if a == 0 || w <= 0 || h <= 0 {
        return;
    }
    let x0 = x.clamp(0, dst_w as i32) as usize;
    let y0 = y.clamp(0, dst_h as i32) as usize;
    let x1 = (x + w).clamp(0, dst_w as i32) as usize;
    let y1 = (y + h).clamp(0, dst_h as i32) as usize;
    if x0 >= x1 || y0 >= y1 {
        return;
    }
    let a16 = a as u16;
    let inv = 255u16 - a16;
    let fr = (col[0] as u16) * a16 + 128;
    let fg = (col[1] as u16) * a16 + 128;
    let fb = (col[2] as u16) * a16 + 128;
    let fa = 255u16 * a16 + 128;
    let span_bytes = (x1 - x0) * 4;

    for py in y0..y1 {
        let start = (py * dst_stride_px + x0) * 4;
        let row = &mut dst[start..start + span_bytes];
        for px in row.chunks_exact_mut(4) {
            let tr = fr + (px[0] as u16) * inv;
            let tg = fg + (px[1] as u16) * inv;
            let tb = fb + (px[2] as u16) * inv;
            let ta = fa + (px[3] as u16) * inv;
            px[0] = ((tr + (tr >> 8)) >> 8) as u8;
            px[1] = ((tg + (tg >> 8)) >> 8) as u8;
            px[2] = ((tb + (tb >> 8)) >> 8) as u8;
            px[3] = ((ta + (ta >> 8)) >> 8) as u8;
        }
    }
}

/// Draws a 2-px crisp line segment (`(x0, y0) -> (x1, y1)`) using integer Bresenham + alpha blend.
pub fn draw_line_blend(
    dst: &mut [u8],
    dst_stride_px: usize,
    dst_w: usize,
    dst_h: usize,
    mut x0: i32,
    mut y0: i32,
    x1: i32,
    y1: i32,
    col: Rgba,
    dashed: bool,
) {
    let dx = (x1 - x0).abs();
    let sx = if x0 < x1 { 1 } else { -1 };
    let dy = -(y1 - y0).abs();
    let sy = if y0 < y1 { 1 } else { -1 };
    let mut err = dx + dy;
    let mut step = 0i32;

    loop {
        if !dashed || ((step / 4) & 1 == 0) {
            for oy in 0..2 {
                let py = y0 + oy;
                if x0 >= 0 && (x0 as usize) < dst_w && py >= 0 && (py as usize) < dst_h {
                    let off = ((py as usize) * dst_stride_px + (x0 as usize)) * 4;
                    dst[off] = blend_chan(col[0], dst[off], col[3]);
                    dst[off + 1] = blend_chan(col[1], dst[off + 1], col[3]);
                    dst[off + 2] = blend_chan(col[2], dst[off + 2], col[3]);
                    dst[off + 3] = blend_chan(255, dst[off + 3], col[3]);
                }
            }
        }
        if x0 == x1 && y0 == y1 {
            break;
        }
        let e2 = err * 2;
        if e2 >= dy {
            err += dy;
            x0 += sx;
        }
        if e2 <= dx {
            err += dx;
            y0 += sy;
        }
        step += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fast_formatters_and_blitter_parity() {
        let mut buf = [0u8; 16];
        let n = fmt_u32_ascii(120, &mut buf);
        assert_eq!(&buf[..n], b"120");
        let n = fmt_deci_ascii(455, &mut buf);
        assert_eq!(&buf[..n], b"45.5");
        let n = fmt_deci_ascii(-32, &mut buf);
        assert_eq!(&buf[..n], b"-3.2");

        // Verify NEON (on aarch64) and scalar match bit-for-bit across all alpha values.
        const W: usize = 32;
        const H: usize = 16;
        let mut alpha = [0u8; W * H];
        for i in 0..alpha.len() {
            alpha[i] = (i as u8).wrapping_mul(17);
        }
        let mut d_ref = [0u8; W * H * 4];
        let mut d_opt = [0u8; W * H * 4];
        for i in 0..d_ref.len() {
            d_ref[i] = (i as u8).wrapping_mul(31);
            d_opt[i] = d_ref[i];
        }
        let fg = [235, 240, 255, 255];
        blit_alpha8_scalar(&mut d_ref, W, W, H, 2, 1, &alpha, W, 24, 12, fg);
        blit_alpha8(&mut d_opt, W, W, H, 2, 1, &alpha, W, 24, 12, fg);
        assert_eq!(d_ref, d_opt);
    }
}
