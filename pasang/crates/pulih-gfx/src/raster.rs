// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: Apache-2.0

//! Fast CPU 2D SDF rasterizer for `Pulih` 120 Hz Material You UI.
//!
//! Uses span-accelerated solid fills for interior regions and analytic SDF
//! coverage only on rounded-corner edge bands so a full `1280×2772` screen
//! renders well inside the 2.5 ms frame budget.

use crate::{Color, Rect, Surface};

/// Flat single-color Google Material Symbols Rounded geometric icons (zero emojis).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Icon {
    Home,
    Folder,
    Storage,
    Build,
    Flash,
    Wifi,
    Usb,
    Battery,
    Shield,
    Terminal,
    Globe,
    Backup,
    Wipe,
    SwapSlot,
    Power,
    ChevronRight,
    Check,
    Warning,
}

/// Fast solid rectangle fill with full clipping and opaque fast-path.
pub fn fill_rect(surface: &mut Surface, rect: Rect, color: Color) {
    let r = rect.intersect(surface.bounds());
    if r.is_empty() || color.a == 0 {
        return;
    }
    surface.mark_dirty(r);
    if color.a == 255 {
        let px = color.to_xbgr8888();
        let stride = surface.stride_px as usize;
        for y in r.y..r.bottom() {
            let start = y as usize * stride + r.x as usize;
            let end = start + r.w as usize;
            surface.pixels[start..end].fill(px);
        }
    } else {
        for y in r.y..r.bottom() {
            for x in r.x..r.right() {
                surface.blend_pixel(x, y, color, 255);
            }
        }
    }
}

/// Analytic anti-aliased rounded rectangle using interior fast-fill + corner SDF.
pub fn fill_rounded_rect(surface: &mut Surface, rect: Rect, radius: f32, color: Color) {
    let clipped = rect.intersect(surface.bounds());
    if clipped.is_empty() || color.a == 0 {
        return;
    }
    let max_r = (rect.w.min(rect.h) as f32) * 0.5;
    let rad = radius.clamp(0.0, max_r);
    if rad <= 0.5 {
        fill_rect(surface, rect, color);
        return;
    }

    surface.mark_dirty(clipped);
    let ir = rad.ceil() as i32;

    // Fast path: solid horizontal middle band (no corner SDF math needed!).
    let mid_top = (rect.y + ir).max(clipped.y);
    let mid_bot = (rect.bottom() - ir).min(clipped.bottom());
    if mid_bot > mid_top {
        fill_rect(
            surface,
            Rect::new(clipped.x, mid_top, clipped.w, mid_bot - mid_top),
            color,
        );
    }

    // Fast path: solid center strip in top and bottom corner bands.
    let mid_left = (rect.x + ir).max(clipped.x);
    let mid_right = (rect.right() - ir).min(clipped.right());
    if mid_right > mid_left {
        if mid_top > clipped.y {
            fill_rect(
                surface,
                Rect::new(mid_left, clipped.y, mid_right - mid_left, mid_top - clipped.y),
                color,
            );
        }
        if clipped.bottom() > mid_bot {
            fill_rect(
                surface,
                Rect::new(
                    mid_left,
                    mid_bot,
                    mid_right - mid_left,
                    clipped.bottom() - mid_bot,
                ),
                color,
            );
        }
    }

    // Analytic SDF on the 4 corner boxes only.
    let cx_l = rect.x as f32 + rad;
    let cx_r = rect.right() as f32 - rad;
    let cy_t = rect.y as f32 + rad;
    let cy_b = rect.bottom() as f32 - rad;

    let corners = [
        (Rect::new(rect.x, rect.y, ir, ir), cx_l, cy_t),
        (Rect::new(rect.right() - ir, rect.y, ir, ir), cx_r, cy_t),
        (Rect::new(rect.x, rect.bottom() - ir, ir, ir), cx_l, cy_b),
        (
            Rect::new(rect.right() - ir, rect.bottom() - ir, ir, ir),
            cx_r,
            cy_b,
        ),
    ];

    for (box_r, cx, cy) in corners {
        let cb = box_r.intersect(clipped);
        if cb.is_empty() {
            continue;
        }
        for y in cb.y..cb.bottom() {
            let dy = (y as f32 + 0.5) - cy;
            let dy2 = dy * dy;
            for x in cb.x..cb.right() {
                let dx = (x as f32 + 0.5) - cx;
                let dist = (dx * dx + dy2).sqrt() - rad;
                let cov = (0.5 - dist).clamp(0.0, 1.0);
                if cov > 0.0 {
                    surface.blend_pixel(x, y, color, (cov * 255.0).round() as u8);
                }
            }
        }
    }
}

/// Anti-aliased filled circle.
pub fn fill_circle(surface: &mut Surface, cx: f32, cy: f32, radius: f32, color: Color) {
    if radius <= 0.0 || color.a == 0 {
        return;
    }
    let box_r = Rect::new(
        (cx - radius - 1.0).floor() as i32,
        (cy - radius - 1.0).floor() as i32,
        (radius * 2.0 + 3.0).ceil() as i32,
        (radius * 2.0 + 3.0).ceil() as i32,
    )
    .intersect(surface.bounds());
    if box_r.is_empty() {
        return;
    }
    surface.mark_dirty(box_r);
    for y in box_r.y..box_r.bottom() {
        let dy = (y as f32 + 0.5) - cy;
        let dy2 = dy * dy;
        for x in box_r.x..box_r.right() {
            let dx = (x as f32 + 0.5) - cx;
            let dist = (dx * dx + dy2).sqrt() - radius;
            let cov = (0.5 - dist).clamp(0.0, 1.0);
            if cov > 0.0 {
                surface.blend_pixel(x, y, color, (cov * 255.0).round() as u8);
            }
        }
    }
}

/// Anti-aliased rounded line segment (capsule SDF) used for flat vector icons and YasvaraMark.
pub fn draw_capsule(
    surface: &mut Surface,
    x0: f32,
    y0: f32,
    x1: f32,
    y1: f32,
    half_width: f32,
    color: Color,
) {
    let pad = half_width + 1.5;
    let min_x = x0.min(x1) - pad;
    let max_x = x0.max(x1) + pad;
    let min_y = y0.min(y1) - pad;
    let max_y = y0.max(y1) + pad;
    let r = Rect::new(
        min_x.floor() as i32,
        min_y.floor() as i32,
        (max_x - min_x).ceil() as i32 + 1,
        (max_y - min_y).ceil() as i32 + 1,
    )
    .intersect(surface.bounds());
    if r.is_empty() {
        return;
    }
    surface.mark_dirty(r);
    let vx = x1 - x0;
    let vy = y1 - y0;
    let len2 = (vx * vx + vy * vy).max(1e-6);
    for y in r.y..r.bottom() {
        let py = y as f32 + 0.5;
        for x in r.x..r.right() {
            let px = x as f32 + 0.5;
            let t = (((px - x0) * vx + (py - y0) * vy) / len2).clamp(0.0, 1.0);
            let dx = px - (x0 + vx * t);
            let dy = py - (y0 + vy * t);
            let dist = (dx * dx + dy * dy).sqrt() - half_width;
            let cov = (0.5 - dist).clamp(0.0, 1.0);
            if cov > 0.0 {
                surface.blend_pixel(x, y, color, (cov * 255.0).round() as u8);
            }
        }
    }
}

/// Draw the Yasvara Y-wave monogram (`SPEC-0004`).
pub fn draw_yasvara_mark(surface: &mut Surface, cx: f32, cy: f32, size: f32, color: Color) {
    let s = size * 0.5;
    let w = (size * 0.09).max(2.0);
    // Left arm into center wave
    draw_capsule(surface, cx - s * 0.68, cy - s * 0.65, cx, cy + s * 0.05, w, color);
    // Right arm into center wave
    draw_capsule(surface, cx + s * 0.68, cy - s * 0.65, cx, cy + s * 0.05, w, color);
    // Stem descending cleanly
    draw_capsule(surface, cx, cy + s * 0.05, cx, cy + s * 0.72, w, color);
    // Subtle accent dot at top crest
    fill_circle(surface, cx, cy - s * 0.58, w * 0.95, color);
}

/// M3 Expressive wavy progress indicator (`progress` in `0.0..=1.0`, `phase` in radians).
pub fn draw_wavy_progress(
    surface: &mut Surface,
    rect: Rect,
    progress: f32,
    phase: f32,
    active: Color,
    track: Color,
) {
    let p = progress.clamp(0.0, 1.0);
    let cy = rect.y as f32 + rect.h as f32 * 0.5;
    let stroke = (rect.h as f32 * 0.22).clamp(2.5, 6.0);
    let active_w = (rect.w as f32 * p).round() as i32;

    // Inactive straight track
    if active_w < rect.w {
        let track_r = Rect::new(
            rect.x + active_w + 4,
            (cy - stroke).round() as i32,
            (rect.w - active_w - 4).max(0),
            (stroke * 2.0).round() as i32,
        );
        fill_rounded_rect(surface, track_r, stroke, track);
    }

    // Active M3 wavy stroke
    if active_w > 4 {
        let amp = (rect.h as f32 * 0.28).clamp(2.0, 7.0);
        let freq = 0.095;
        let step = 4;
        let mut x = rect.x;
        let end_x = rect.x + active_w;
        while x < end_x {
            let nx = (x + step).min(end_x);
            let y0 = cy + ((x - rect.x) as f32 * freq + phase).sin() * amp;
            let y1 = cy + ((nx - rect.x) as f32 * freq + phase).sin() * amp;
            draw_capsule(surface, x as f32, y0, nx as f32, y1, stroke, active);
            x = nx;
        }
    }
}

/// Draw flat single-color Material Symbols Rounded geometric icon centered at `(cx, cy)`.
pub fn draw_icon(surface: &mut Surface, icon: Icon, cx: f32, cy: f32, size: f32, color: Color) {
    let r = size * 0.42;
    let sw = (size * 0.085).clamp(1.5, 4.0);
    match icon {
        Icon::Home => {
            draw_capsule(surface, cx - r, cy, cx, cy - r * 0.85, sw, color);
            draw_capsule(surface, cx, cy - r * 0.85, cx + r, cy, sw, color);
            draw_capsule(surface, cx - r * 0.7, cy, cx - r * 0.7, cy + r * 0.85, sw, color);
            draw_capsule(surface, cx + r * 0.7, cy, cx + r * 0.7, cy + r * 0.85, sw, color);
            draw_capsule(surface, cx - r * 0.7, cy + r * 0.85, cx + r * 0.7, cy + r * 0.85, sw, color);
        }
        Icon::Folder => {
            draw_capsule(surface, cx - r, cy - r * 0.6, cx - r * 0.1, cy - r * 0.6, sw, color);
            draw_capsule(surface, cx - r * 0.1, cy - r * 0.6, cx + r * 0.15, cy - r * 0.35, sw, color);
            draw_capsule(surface, cx + r * 0.15, cy - r * 0.35, cx + r, cy - r * 0.35, sw, color);
            draw_capsule(surface, cx - r, cy - r * 0.6, cx - r, cy + r * 0.7, sw, color);
            draw_capsule(surface, cx + r, cy - r * 0.35, cx + r, cy + r * 0.7, sw, color);
            draw_capsule(surface, cx - r, cy + r * 0.7, cx + r, cy + r * 0.7, sw, color);
        }
        Icon::Storage => {
            draw_capsule(surface, cx - r, cy - r * 0.55, cx + r, cy - r * 0.55, sw, color);
            draw_capsule(surface, cx - r, cy, cx + r, cy, sw, color);
            draw_capsule(surface, cx - r, cy + r * 0.55, cx + r, cy + r * 0.55, sw, color);
        }
        Icon::Build | Icon::Terminal => {
            draw_capsule(surface, cx - r * 0.8, cy - r * 0.45, cx - r * 0.15, cy, sw, color);
            draw_capsule(surface, cx - r * 0.8, cy + r * 0.45, cx - r * 0.15, cy, sw, color);
            draw_capsule(surface, cx + r * 0.05, cy + r * 0.45, cx + r * 0.85, cy + r * 0.45, sw, color);
        }
        Icon::Flash => {
            draw_capsule(surface, cx + r * 0.15, cy - r, cx - r * 0.45, cy + r * 0.05, sw, color);
            draw_capsule(surface, cx - r * 0.45, cy + r * 0.05, cx + r * 0.45, cy - r * 0.05, sw, color);
            draw_capsule(surface, cx + r * 0.45, cy - r * 0.05, cx - r * 0.15, cy + r, sw, color);
        }
        Icon::Wifi => {
            fill_circle(surface, cx, cy + r * 0.55, sw * 1.1, color);
            draw_capsule(surface, cx - r * 0.45, cy + r * 0.05, cx, cy - r * 0.15, sw * 0.85, color);
            draw_capsule(surface, cx, cy - r * 0.15, cx + r * 0.45, cy + r * 0.05, sw * 0.85, color);
            draw_capsule(surface, cx - r * 0.85, cy - r * 0.35, cx, cy - r * 0.72, sw * 0.85, color);
            draw_capsule(surface, cx, cy - r * 0.72, cx + r * 0.85, cy - r * 0.35, sw * 0.85, color);
        }
        Icon::Usb | Icon::SwapSlot => {
            draw_capsule(surface, cx - r * 0.7, cy - r * 0.35, cx + r * 0.7, cy - r * 0.35, sw, color);
            draw_capsule(surface, cx + r * 0.3, cy - r * 0.75, cx + r * 0.7, cy - r * 0.35, sw, color);
            draw_capsule(surface, cx - r * 0.7, cy + r * 0.35, cx + r * 0.7, cy + r * 0.35, sw, color);
            draw_capsule(surface, cx - r * 0.3, cy + r * 0.75, cx - r * 0.7, cy + r * 0.35, sw, color);
        }
        Icon::Battery => {
            draw_capsule(surface, cx - r * 0.5, cy - r * 0.8, cx + r * 0.5, cy - r * 0.8, sw, color);
            draw_capsule(surface, cx - r * 0.5, cy - r * 0.8, cx - r * 0.5, cy + r * 0.85, sw, color);
            draw_capsule(surface, cx + r * 0.5, cy - r * 0.8, cx + r * 0.5, cy + r * 0.85, sw, color);
            draw_capsule(surface, cx - r * 0.5, cy + r * 0.85, cx + r * 0.5, cy + r * 0.85, sw, color);
        }
        Icon::Shield => {
            draw_capsule(surface, cx, cy - r, cx + r * 0.75, cy - r * 0.55, sw, color);
            draw_capsule(surface, cx, cy - r, cx - r * 0.75, cy - r * 0.55, sw, color);
            draw_capsule(surface, cx - r * 0.75, cy - r * 0.55, cx, cy + r, sw, color);
            draw_capsule(surface, cx + r * 0.75, cy - r * 0.55, cx, cy + r, sw, color);
        }
        Icon::Globe => {
            draw_capsule(surface, cx - r, cy, cx + r, cy, sw * 0.8, color);
            draw_capsule(surface, cx, cy - r, cx, cy + r, sw * 0.8, color);
            draw_capsule(surface, cx - r * 0.7, cy - r * 0.7, cx + r * 0.7, cy - r * 0.7, sw * 0.8, color);
            draw_capsule(surface, cx - r * 0.7, cy + r * 0.7, cx + r * 0.7, cy + r * 0.7, sw * 0.8, color);
        }
        Icon::Backup => {
            draw_capsule(surface, cx, cy - r * 0.8, cx, cy + r * 0.4, sw, color);
            draw_capsule(surface, cx - r * 0.45, cy, cx, cy + r * 0.45, sw, color);
            draw_capsule(surface, cx + r * 0.45, cy, cx, cy + r * 0.45, sw, color);
            draw_capsule(surface, cx - r * 0.8, cy + r * 0.8, cx + r * 0.8, cy + r * 0.8, sw, color);
        }
        Icon::Wipe => {
            draw_capsule(surface, cx - r * 0.65, cy - r * 0.65, cx + r * 0.65, cy + r * 0.65, sw, color);
            draw_capsule(surface, cx + r * 0.65, cy - r * 0.65, cx - r * 0.65, cy + r * 0.65, sw, color);
        }
        Icon::Power => {
            draw_capsule(surface, cx, cy - r * 0.9, cx, cy, sw, color);
            draw_capsule(surface, cx - r * 0.7, cy - r * 0.2, cx - r * 0.5, cy + r * 0.65, sw, color);
            draw_capsule(surface, cx - r * 0.5, cy + r * 0.65, cx + r * 0.5, cy + r * 0.65, sw, color);
            draw_capsule(surface, cx + r * 0.5, cy + r * 0.65, cx + r * 0.7, cy - r * 0.2, sw, color);
        }
        Icon::ChevronRight => {
            draw_capsule(surface, cx - r * 0.3, cy - r * 0.6, cx + r * 0.4, cy, sw, color);
            draw_capsule(surface, cx + r * 0.4, cy, cx - r * 0.3, cy + r * 0.6, sw, color);
        }
        Icon::Check => {
            draw_capsule(surface, cx - r * 0.7, cy + r * 0.05, cx - r * 0.15, cy + r * 0.6, sw, color);
            draw_capsule(surface, cx - r * 0.15, cy + r * 0.6, cx + r * 0.75, cy - r * 0.55, sw, color);
        }
        Icon::Warning => {
            draw_capsule(surface, cx, cy - r * 0.85, cx - r * 0.85, cy + r * 0.75, sw, color);
            draw_capsule(surface, cx, cy - r * 0.85, cx + r * 0.85, cy + r * 0.75, sw, color);
            draw_capsule(surface, cx - r * 0.85, cy + r * 0.75, cx + r * 0.85, cy + r * 0.75, sw, color);
            draw_capsule(surface, cx, cy - r * 0.2, cx, cy + r * 0.25, sw * 0.9, color);
            fill_circle(surface, cx, cy + r * 0.5, sw * 0.9, color);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rasterizer_never_panics_on_oob_or_negative_coords() {
        let mut s = Surface::new(64, 64);
        fill_rect(&mut s, Rect::new(-50, -50, 200, 200), Color::rgb(10, 20, 30));
        fill_rounded_rect(&mut s, Rect::new(-10, 50, 120, 40), 25.0, Color::rgb(40, 80, 120));
        fill_circle(&mut s, -5.0, 68.0, 30.0, Color::rgba(255, 0, 0, 128));
        draw_yasvara_mark(&mut s, 32.0, 32.0, 40.0, Color::WHITE);
        draw_wavy_progress(&mut s, Rect::new(4, 24, 56, 12), 0.65, 1.2, Color::WHITE, Color::BLACK);
        assert_eq!(s.pixels.len(), 64 * 64);
    }
}
