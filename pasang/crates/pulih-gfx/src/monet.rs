// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: Apache-2.0

//! Pure-Rust Material You (M3 Expressive) dynamic tonal palette generator.
//!
//! Derives a complete M3 Dark color scheme from a 32-bit ARGB seed color
//! (matching Android's `recovery_theme.bin` seed written by Laras) using
//! perceptual OKLCH tone/chroma mapping so contrast ratios stay legible
//! across every hue, plus an optional OLED True Black surface mode.

use crate::Color;

/// Built-in Yasvara recovery theme presets.
pub const PRESET_SEEDS: &[(&str, u32)] = &[
    ("Yasvara Indigo", 0xFF6750A4),
    ("Ocean Teal", 0xFF006A6A),
    ("Emerald", 0xFF1B6D3D),
    ("Amber Gold", 0xFF8B5000),
    ("Crimson", 0xFF984061),
    ("Slate Blue", 0xFF3E5F90),
];

/// Complete Material 3 Dark palette for Pulih Recovery.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Palette {
    pub seed_argb: u32,
    pub oled_black: bool,
    pub surface: Color,
    pub surface_container_lowest: Color,
    pub surface_container_low: Color,
    pub surface_container: Color,
    pub surface_container_high: Color,
    pub surface_container_highest: Color,
    pub on_surface: Color,
    pub on_surface_variant: Color,
    pub primary: Color,
    pub on_primary: Color,
    pub primary_container: Color,
    pub on_primary_container: Color,
    pub secondary: Color,
    pub secondary_container: Color,
    pub on_secondary_container: Color,
    pub tertiary: Color,
    pub tertiary_container: Color,
    pub on_tertiary_container: Color,
    pub error: Color,
    pub on_error: Color,
    pub error_container: Color,
    pub on_error_container: Color,
    pub warning: Color,
    pub warning_container: Color,
    pub success: Color,
    pub success_container: Color,
    pub outline: Color,
    pub outline_variant: Color,
}

impl Palette {
    /// Generate a Material 3 Dark palette from an ARGB seed color.
    pub fn from_seed(seed_argb: u32, oled_black: bool) -> Self {
        let seed = Color::from_argb(seed_argb);
        let (_, c_seed, hue) = rgb_to_oklch(seed.r, seed.g, seed.b);
        let primary_c = c_seed.clamp(0.08, 0.17);
        let secondary_c = (primary_c * 0.45).clamp(0.03, 0.08);
        let tertiary_hue = (hue + 60.0) % 360.0;
        let tertiary_c = (primary_c * 0.65).clamp(0.06, 0.13);
        let neutral_c = (primary_c * 0.12).clamp(0.008, 0.022);

        let surface = if oled_black {
            Color::BLACK
        } else {
            oklch_to_rgb(0.16, neutral_c, hue)
        };
        let surface_container_lowest = if oled_black {
            Color::BLACK
        } else {
            oklch_to_rgb(0.12, neutral_c, hue)
        };
        let surface_container_low = if oled_black {
            oklch_to_rgb(0.14, neutral_c, hue)
        } else {
            oklch_to_rgb(0.19, neutral_c, hue)
        };
        let surface_container = if oled_black {
            oklch_to_rgb(0.17, neutral_c, hue)
        } else {
            oklch_to_rgb(0.22, neutral_c, hue)
        };
        let surface_container_high = oklch_to_rgb(0.26, neutral_c * 1.2, hue);
        let surface_container_highest = oklch_to_rgb(0.31, neutral_c * 1.3, hue);

        Self {
            seed_argb,
            oled_black,
            surface,
            surface_container_lowest,
            surface_container_low,
            surface_container,
            surface_container_high,
            surface_container_highest,
            on_surface: oklch_to_rgb(0.92, neutral_c * 0.5, hue),
            on_surface_variant: oklch_to_rgb(0.76, neutral_c * 1.1, hue),
            primary: oklch_to_rgb(0.82, primary_c, hue),
            on_primary: oklch_to_rgb(0.24, primary_c * 0.9, hue),
            primary_container: oklch_to_rgb(0.36, primary_c * 0.95, hue),
            on_primary_container: oklch_to_rgb(0.93, primary_c * 0.55, hue),
            secondary: oklch_to_rgb(0.80, secondary_c, hue),
            secondary_container: oklch_to_rgb(0.33, secondary_c * 1.1, hue),
            on_secondary_container: oklch_to_rgb(0.92, secondary_c * 0.7, hue),
            tertiary: oklch_to_rgb(0.82, tertiary_c, tertiary_hue),
            tertiary_container: oklch_to_rgb(0.35, tertiary_c * 0.9, tertiary_hue),
            on_tertiary_container: oklch_to_rgb(0.94, tertiary_c * 0.5, tertiary_hue),
            error: oklch_to_rgb(0.80, 0.14, 24.0),
            on_error: oklch_to_rgb(0.22, 0.11, 24.0),
            error_container: oklch_to_rgb(0.34, 0.13, 24.0),
            on_error_container: oklch_to_rgb(0.94, 0.06, 24.0),
            warning: oklch_to_rgb(0.84, 0.14, 78.0),
            warning_container: oklch_to_rgb(0.35, 0.10, 78.0),
            success: oklch_to_rgb(0.82, 0.14, 148.0),
            success_container: oklch_to_rgb(0.33, 0.10, 148.0),
            outline: oklch_to_rgb(0.62, neutral_c * 1.3, hue),
            outline_variant: oklch_to_rgb(0.36, neutral_c * 1.2, hue),
        }
    }

    pub fn default_yasvara() -> Self {
        Self::from_seed(PRESET_SEEDS[0].1, false)
    }
}

/// WCAG relative luminance `[0.0, 1.0]` for contrast verification tests.
pub fn relative_luminance(c: Color) -> f32 {
    let r = srgb_to_linear(c.r as f32 / 255.0);
    let g = srgb_to_linear(c.g as f32 / 255.0);
    let b = srgb_to_linear(c.b as f32 / 255.0);
    0.2126 * r + 0.7152 * g + 0.0722 * b
}

/// WCAG contrast ratio `[1.0, 21.0]`.
pub fn contrast_ratio(a: Color, b: Color) -> f32 {
    let la = relative_luminance(a);
    let lb = relative_luminance(b);
    let (hi, lo) = if la >= lb { (la, lb) } else { (lb, la) };
    (hi + 0.05) / (lo + 0.05)
}

#[inline]
fn srgb_to_linear(v: f32) -> f32 {
    if v <= 0.04045 {
        v / 12.92
    } else {
        ((v + 0.055) / 1.055).powf(2.4)
    }
}

#[inline]
fn linear_to_srgb(v: f32) -> f32 {
    let v = v.clamp(0.0, 1.0);
    if v <= 0.0031308 {
        12.92 * v
    } else {
        1.055 * v.powf(1.0 / 2.4) - 0.055
    }
}

fn rgb_to_oklch(r: u8, g: u8, b: u8) -> (f32, f32, f32) {
    let lr = srgb_to_linear(r as f32 / 255.0);
    let lg = srgb_to_linear(g as f32 / 255.0);
    let lb = srgb_to_linear(b as f32 / 255.0);

    let l = (0.4122214708 * lr + 0.5363325363 * lg + 0.0514459929 * lb).cbrt();
    let m = (0.2119034982 * lr + 0.6806995451 * lg + 0.1073969566 * lb).cbrt();
    let s = (0.0883024619 * lr + 0.2817188376 * lg + 0.6299787005 * lb).cbrt();

    let okl = 0.2104542553 * l + 0.7936177850 * m - 0.0040720468 * s;
    let oka = 1.9779984951 * l - 2.4285922050 * m + 0.4505937099 * s;
    let okb = 0.0259040371 * l + 0.7827717662 * m - 0.8086757660 * s;

    let c = (oka * oka + okb * okb).sqrt();
    let mut h = okb.atan2(oka).to_degrees();
    if h < 0.0 {
        h += 360.0;
    }
    (okl, c, h)
}

fn oklch_to_rgb(l: f32, c: f32, hue_deg: f32) -> Color {
    let rad = hue_deg.to_radians();
    let a = c * rad.cos();
    let b = c * rad.sin();

    let l_ = l + 0.3963377774 * a + 0.2158037573 * b;
    let m_ = l - 0.1055613458 * a - 0.0638541728 * b;
    let s_ = l - 0.0894841775 * a - 1.2914855480 * b;

    let l3 = l_ * l_ * l_;
    let m3 = m_ * m_ * m_;
    let s3 = s_ * s_ * s_;

    let lr = 4.0767416621 * l3 - 3.3077115913 * m3 + 0.2309699292 * s3;
    let lg = -1.2684380046 * l3 + 2.6097574011 * m3 - 0.3413193965 * s3;
    let lb = -0.0041960863 * l3 - 0.7034186147 * m3 + 1.7076147010 * s3;

    Color::rgb(
        (linear_to_srgb(lr) * 255.0).round() as u8,
        (linear_to_srgb(lg) * 255.0).round() as u8,
        (linear_to_srgb(lb) * 255.0).round() as u8,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_presets_meet_wcag_aa_contrast() {
        for &(name, seed) in PRESET_SEEDS {
            for oled in [false, true] {
                let p = Palette::from_seed(seed, oled);
                assert!(
                    contrast_ratio(p.on_surface, p.surface) >= 7.0,
                    "{name} (oled={oled}) on_surface contrast too low"
                );
                assert!(
                    contrast_ratio(p.on_primary, p.primary) >= 4.5,
                    "{name} (oled={oled}) on_primary contrast too low"
                );
                assert!(
                    contrast_ratio(p.on_primary_container, p.primary_container) >= 4.5,
                    "{name} (oled={oled}) on_primary_container contrast too low"
                );
                assert!(
                    contrast_ratio(p.on_error, p.error) >= 4.5,
                    "{name} (oled={oled}) on_error contrast too low"
                );
                if oled {
                    assert_eq!(p.surface, Color::BLACK);
                }
            }
        }
    }
}
