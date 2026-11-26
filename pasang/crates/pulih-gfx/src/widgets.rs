// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: Apache-2.0

//! Material You (M3 Expressive) UI widgets and safety controls for `Pulih`:
//! - Top Status Capsule (48 dp punch-hole clearance)
//! - 4-Tab Floating Bottom Navigation Pill
//! - Bento Action Cards with spring press scale
//! - Swipe-to-Confirm destructive action guard
//! - M3 QWERTY touch keyboard layout + hit-testing

use crate::font::{draw_text, draw_text_centered};
use crate::i18n::{t, Locale, StrKey};
use crate::monet::Palette;
use crate::raster::{draw_icon, draw_wavy_progress, draw_yasvara_mark, fill_circle, fill_rounded_rect, Icon};
use crate::{Rect, Surface};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tab {
    Home = 0,
    Files = 1,
    Partitions = 2,
    Tools = 3,
}

/// Live telemetry shown in the persistent top status capsule and Home quick controls.
#[derive(Clone, Debug)]
pub struct StatusSnapshot {
    pub clock: String,
    pub active_slot: char, // 'A' or 'B'
    pub adb_root: bool,
    pub wifi_on: bool,
    pub otg_mounted: bool,
    pub battery_pct: u8,
    pub charge_watts: f32,
    pub super_free_gib: f32,
    pub bootloop_canary: bool,
    pub device_label: String,
    pub build_label: String,
    pub backlight_pct: u8,
    pub gpu_active: bool,
}

impl Default for StatusSnapshot {
    fn default() -> Self {
        Self {
            clock: "09:15".to_string(),
            active_slot: 'A',
            adb_root: true,
            wifi_on: false,
            otg_mounted: false,
            battery_pct: 84,
            charge_watts: 32.5,
            super_free_gib: 6.03,
            bootloop_canary: false,
            device_label: "POCO F7 (onyx)".to_string(),
            build_label: "Yasvara 1.0 - Android 17".to_string(),
            backlight_pct: 60,
            gpu_active: false,
        }
    }
}

/// Tactile Swipe-to-Confirm state machine guarding every destructive operation
/// (Wipe, Format, Resize Super, Raw Flash, Change FS).
#[derive(Clone, Debug)]
pub struct SwipeConfirm {
    pub label: String,
    pub progress: f32, // 0.0..=1.0
    pub dragging: bool,
    pub confirmed: bool,
}

impl SwipeConfirm {
    pub fn new(label: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            progress: 0.0,
            dragging: false,
            confirmed: false,
        }
    }

    pub fn on_touch_down(&mut self, rect: Rect, x: i32, y: i32) -> bool {
        let knob_r = rect.h / 2;
        let knob_cx = rect.x + knob_r + ((rect.w - rect.h) as f32 * self.progress) as i32;
        let dx = x - knob_cx;
        let dy = y - (rect.y + knob_r);
        if dx * dx + dy * dy <= (knob_r + 16) * (knob_r + 16) {
            self.dragging = true;
            return true;
        }
        false
    }

    pub fn on_touch_move(&mut self, rect: Rect, x: i32) {
        if !self.dragging || self.confirmed {
            return;
        }
        let travel = (rect.w - rect.h).max(1) as f32;
        let raw = (x - (rect.x + rect.h / 2)) as f32 / travel;
        self.progress = raw.clamp(0.0, 1.0);
        if self.progress >= 0.92 {
            self.progress = 1.0;
            self.confirmed = true;
            self.dragging = false;
        }
    }

    pub fn on_touch_up(&mut self) {
        self.dragging = false;
        if !self.confirmed {
            self.progress = 0.0;
        }
    }

    pub fn draw(&self, surface: &mut Surface, rect: Rect, pal: &Palette, locale: Locale) {
        let r = rect.h as f32 * 0.5;
        let bg = if self.confirmed {
            pal.error
        } else {
            pal.error_container
        };
        fill_rounded_rect(surface, rect, r, bg);
        let text = if self.confirmed {
            t(locale, StrKey::Confirmed)
        } else {
            &self.label
        };
        let fg = if self.confirmed {
            pal.on_error
        } else {
            pal.on_error_container
        };
        draw_text_centered(
            surface,
            rect.x + rect.w / 2 + rect.h / 4,
            rect.y + rect.h / 2,
            text,
            3,
            fg,
        );
        let knob_r = r - 6.0;
        let knob_cx = rect.x as f32 + r + (rect.w - rect.h) as f32 * self.progress;
        let knob_cy = rect.y as f32 + r;
        fill_circle(surface, knob_cx, knob_cy, knob_r, pal.error);
        draw_icon(
            surface,
            if self.confirmed { Icon::Check } else { Icon::ChevronRight },
            knob_cx,
            knob_cy,
            knob_r * 1.1,
            pal.on_error,
        );
    }
}

/// Draw the persistent Top Status Capsule with 48 dp (~144 px on 504 DPI) punch-hole clearance.
pub fn draw_status_capsule(
    surface: &mut Surface,
    pal: &Palette,
    status: &StatusSnapshot,
    locale: Locale,
) -> Rect {
    let w = surface.width as i32;
    let pad = (w / 32).max(20);
    let top_y = (surface.height as i32 / 24).max(48); // punch-hole clearance
    let cap_h = 84;
    let rect = Rect::new(pad, top_y, w - pad * 2, cap_h);
    fill_rounded_rect(surface, rect, cap_h as f32 * 0.5, pal.surface_container_high);

    let cy = rect.y + rect.h / 2;
    let mut x = rect.x + 28;
    draw_text(surface, x, cy - 10, &status.clock, 3, pal.on_surface);
    x += 120;

    // Active Slot Pill
    let slot_r = Rect::new(x, rect.y + 16, 132, 52);
    fill_rounded_rect(surface, slot_r, 26.0, pal.primary_container);
    let slot_txt = if status.active_slot == 'A' {
        t(locale, StrKey::SlotA)
    } else {
        t(locale, StrKey::SlotB)
    };
    draw_text_centered(
        surface,
        slot_r.x + slot_r.w / 2,
        cy,
        slot_txt,
        3,
        pal.on_primary_container,
    );
    x += 148;

    // ADB Root Badge
    if status.adb_root {
        let adb_r = Rect::new(x, rect.y + 16, 176, 52);
        fill_rounded_rect(surface, adb_r, 26.0, pal.tertiary_container);
        draw_text_centered(
            surface,
            adb_r.x + adb_r.w / 2,
            cy,
            t(locale, StrKey::AdbRootOn),
            3,
            pal.on_tertiary_container,
        );
        x += 192;
    }

    // Wi-Fi 7 Status Pill in Top Capsule
    let wifi_r = Rect::new(x, rect.y + 16, 172, 52);
    fill_rounded_rect(
        surface,
        wifi_r,
        26.0,
        if status.wifi_on { pal.primary } else { pal.surface_container },
    );
    draw_text_centered(
        surface,
        wifi_r.x + wifi_r.w / 2,
        cy,
        if status.wifi_on {
            t(locale, StrKey::WifiOn)
        } else {
            t(locale, StrKey::WifiOff)
        },
        2,
        if status.wifi_on { pal.on_primary } else { pal.on_surface_variant },
    );

    // Right side: Live Charging Pill
    let bat_txt = if status.charge_watts >= 1.0 {
        format!("{:.0}W {}%", status.charge_watts, status.battery_pct)
    } else {
        format!("{}%", status.battery_pct)
    };
    let bat_w = 210;
    let bat_r = Rect::new(rect.right() - bat_w - 18, rect.y + 16, bat_w, 52);
    fill_rounded_rect(surface, bat_r, 26.0, pal.secondary_container);
    draw_text_centered(
        surface,
        bat_r.x + bat_r.w / 2,
        cy,
        &bat_txt,
        3,
        pal.on_secondary_container,
    );

    rect
}

/// Draw the 4-Tab Floating Bottom Navigation Pill and return the 4 hit rects.
pub fn draw_bottom_nav(
    surface: &mut Surface,
    pal: &Palette,
    active: Tab,
    locale: Locale,
) -> [Rect; 4] {
    let w = surface.width as i32;
    let h = surface.height as i32;
    let pad = (w / 18).max(32);
    let nav_h = 124;
    let nav_r = Rect::new(pad, h - nav_h - 48, w - pad * 2, nav_h);
    fill_rounded_rect(surface, nav_r, nav_h as f32 * 0.5, pal.surface_container_high);

    let items = [
        (Tab::Home, Icon::Home, StrKey::TabHome),
        (Tab::Files, Icon::Folder, StrKey::TabFiles),
        (Tab::Partitions, Icon::Storage, StrKey::TabPartitions),
        (Tab::Tools, Icon::Build, StrKey::TabTools),
    ];

    let slot_w = nav_r.w / 4;
    let mut rects = [Rect::default(); 4];
    for (i, (tab, icon, label_key)) in items.iter().enumerate() {
        let r = Rect::new(nav_r.x + i as i32 * slot_w, nav_r.y, slot_w, nav_r.h);
        rects[i] = r;
        let is_active = *tab == active;
        if is_active {
            let pill = Rect::new(r.x + 16, r.y + 14, r.w - 32, r.h - 28);
            fill_rounded_rect(surface, pill, pill.h as f32 * 0.5, pal.primary_container);
        }
        let fg = if is_active {
            pal.on_primary_container
        } else {
            pal.on_surface_variant
        };
        let cx = r.x + r.w / 2;
        draw_icon(surface, *icon, cx as f32, (r.y + 44) as f32, 38.0, fg);
        draw_text_centered(surface, cx, r.y + 92, t(locale, *label_key), 2, fg);
    }
    rects
}

/// Render a tactile Material You (M3 Expressive) draggable horizontal slider
/// (e.g., live OLED Brightness `5%..=100%`) and return its interactive hit rect.
pub fn draw_m3_slider(
    surface: &mut Surface,
    rect: Rect,
    pal: &Palette,
    label: &str,
    value_pct: u8,
) -> Rect {
    let pct = value_pct.clamp(5, 100);
    let r = rect.h as f32 * 0.5;
    // Inactive track
    fill_rounded_rect(surface, rect, r, pal.surface_container_highest);

    // Active filled bar (minimum width = rect.h so pill corners stay clean)
    let min_fill = rect.h.min(rect.w);
    let fill_w = min_fill + (((rect.w - min_fill) as i32 * (pct as i32 - 5)) / 95).max(0);
    let fill_rect = Rect::new(rect.x, rect.y, fill_w.min(rect.w), rect.h);
    fill_rounded_rect(surface, fill_rect, r, pal.primary);

    // Tactile vertical handle pill inside active bar edge
    let thumb_x = (fill_rect.right() - 26).max(rect.x + 16);
    let thumb = Rect::new(thumb_x, rect.y + 14, 14, (rect.h - 28).max(12));
    fill_rounded_rect(surface, thumb, 7.0, pal.on_primary);

    // Label on left (high contrast over primary fill) & percentage badge on right
    let cy = rect.y + rect.h / 2;
    draw_text(surface, rect.x + 32, cy - 10, label, 3, pal.on_primary);
    let pct_str = format!("{pct}%");
    let right_fg = if pct >= 84 {
        pal.on_primary
    } else {
        pal.on_surface
    };
    draw_text(surface, rect.right() - 108, cy - 10, &pct_str, 3, right_fg);
    rect
}

/// Hit-test regions produced by `render_home_screen` so every card, pill,
/// slider, status capsule, and bottom navigation item responds immediately to touch.
#[derive(Clone, Copy, Debug, Default)]
pub struct HomeLayout {
    pub status_capsule: Rect,
    pub nav: [Rect; 4],
    pub bento: [Rect; 4],
    pub quick: [Rect; 4],
    pub brightness_slider: Rect,
    pub feature_pills: [Rect; 4],
}

/// Render the complete Pulih Home Bento Dashboard frame.
pub fn render_home_screen(
    surface: &mut Surface,
    pal: &Palette,
    status: &StatusSnapshot,
    locale: Locale,
    wavy_phase: f32,
    flash_progress: Option<f32>,
) -> HomeLayout {
    surface.clear(pal.surface);
    let top = draw_status_capsule(surface, pal, status, locale);

    let w = surface.width as i32;
    let pad = (w / 32).max(20);
    let mut y = top.bottom() + 28;

    // Hero Card (YasvaraMark + Device + Build + Super Free)
    let hero = Rect::new(pad, y, w - pad * 2, 260);
    fill_rounded_rect(surface, hero, 44.0, pal.surface_container);
    draw_yasvara_mark(
        surface,
        (hero.x + 92) as f32,
        (hero.y + 115) as f32,
        96.0,
        pal.primary,
    );
    draw_text(
        surface,
        hero.x + 170,
        hero.y + 54,
        t(locale, StrKey::AppName),
        6,
        pal.on_surface,
    );
    draw_text(
        surface,
        hero.x + 170,
        hero.y + 118,
        &status.device_label,
        3,
        pal.on_surface_variant,
    );
    let meta_line = format!(
        "{}  |  {:.2} GiB {}",
        status.build_label,
        status.super_free_gib,
        t(locale, StrKey::SuperFree)
    );
    draw_text(surface, hero.x + 170, hero.y + 162, &meta_line, 2, pal.primary);
    y = hero.bottom() + 24;

    // Quiet-by-default Bootloop Canary Alert Strip
    if status.bootloop_canary {
        let alert = Rect::new(pad, y, w - pad * 2, 92);
        fill_rounded_rect(surface, alert, 28.0, pal.error_container);
        draw_icon(
            surface,
            Icon::Warning,
            (alert.x + 48) as f32,
            (alert.y + 46) as f32,
            38.0,
            pal.on_error_container,
        );
        draw_text(
            surface,
            alert.x + 92,
            alert.y + 34,
            t(locale, StrKey::BootloopDetected),
            3,
            pal.on_error_container,
        );
        y = alert.bottom() + 24;
    }

    // Active OTA / Flash Wavy Progress Card (when flashing)
    if let Some(prog) = flash_progress {
        let pcard = Rect::new(pad, y, w - pad * 2, 130);
        fill_rounded_rect(surface, pcard, 32.0, pal.surface_container_high);
        let pct_txt = format!("Pasang CoW OTA  {:.0}%", prog * 100.0);
        draw_text(surface, pcard.x + 32, pcard.y + 28, &pct_txt, 3, pal.on_surface);
        draw_wavy_progress(
            surface,
            Rect::new(pcard.x + 32, pcard.y + 76, pcard.w - 64, 28),
            prog,
            wavy_phase,
            pal.primary,
            pal.outline_variant,
        );
        y = pcard.bottom() + 24;
    }

    // 2x2 Bento Grid
    let gap = 24;
    let card_w = (w - pad * 2 - gap) / 2;
    let card_h = 240;
    let bento = [
        (Icon::Flash, StrKey::InstallFlash, pal.primary_container, pal.on_primary_container),
        (Icon::Folder, StrKey::FileManager, pal.surface_container, pal.on_surface),
        (Icon::Storage, StrKey::PartitionsMount, pal.surface_container, pal.on_surface),
        (Icon::Shield, StrKey::RootModules, pal.surface_container, pal.on_surface),
    ];
    let mut bento_rects = [Rect::default(); 4];
    for (idx, &(icon, label, bg, fg)) in bento.iter().enumerate() {
        let col = (idx % 2) as i32;
        let row = (idx / 2) as i32;
        let r = Rect::new(pad + col * (card_w + gap), y + row * (card_h + gap), card_w, card_h);
        bento_rects[idx] = r;
        fill_rounded_rect(surface, r, 40.0, bg);
        draw_icon(surface, icon, (r.x + 64) as f32, (r.y + 72) as f32, 56.0, fg);
        draw_text(surface, r.x + 36, r.y + 158, t(locale, label), 3, fg);
    }
    y += (card_h + gap) * 2 + 12;

    // Quick Action Pills Row
    let pills = [
        (Icon::Backup, StrKey::Backup),
        (Icon::Wipe, StrKey::Wipe),
        (Icon::SwapSlot, StrKey::SwitchSlot),
        (Icon::Power, StrKey::Reboot),
    ];
    let pill_gap = 16;
    let pill_w = (w - pad * 2 - pill_gap * 3) / 4;
    let pill_h = 110;
    let mut quick_rects = [Rect::default(); 4];
    for (i, &(icon, label)) in pills.iter().enumerate() {
        let r = Rect::new(pad + i as i32 * (pill_w + pill_gap), y, pill_w, pill_h);
        quick_rects[i] = r;
        fill_rounded_rect(surface, r, 32.0, pal.secondary_container);
        draw_icon(
            surface,
            icon,
            (r.x + r.w / 2) as f32,
            (r.y + 38) as f32,
            34.0,
            pal.on_secondary_container,
        );
        draw_text_centered(
            surface,
            r.x + r.w / 2,
            r.y + 82,
            t(locale, label),
            2,
            pal.on_secondary_container,
        );
    }
    y += pill_h + 24;

    // Quick Controls Card: Draggable Brightness Slider + Wi-Fi 7 / Jelajah Web / Adreno GPU / Sleep
    let ctrl_card = Rect::new(pad, y, w - pad * 2, 272);
    fill_rounded_rect(surface, ctrl_card, 40.0, pal.surface_container);
    draw_text(
        surface,
        ctrl_card.x + 32,
        ctrl_card.y + 24,
        "Quick Controls (Drag Slider / Tap Status Bar)",
        2,
        pal.on_surface_variant,
    );
    let slider_r = draw_m3_slider(
        surface,
        Rect::new(ctrl_card.x + 28, ctrl_card.y + 62, ctrl_card.w - 56, 82),
        pal,
        "Brightness",
        status.backlight_pct,
    );

    let feat_y = slider_r.bottom() + 20;
    let feat_gap = 14;
    let feat_w = (ctrl_card.w - 56 - feat_gap * 3) / 4;
    let feat_h = 84;
    let feats = [
        (
            if status.wifi_on { "Wi-Fi: ON" } else { "Wi-Fi 7" },
            if status.wifi_on { pal.primary } else { pal.surface_container_high },
            if status.wifi_on { pal.on_primary } else { pal.on_surface },
        ),
        (
            "Browser",
            pal.secondary_container,
            pal.on_secondary_container,
        ),
        (
            if status.gpu_active { "GPU: ON" } else { "GPU/DOOM" },
            if status.gpu_active { pal.tertiary_container } else { pal.surface_container_high },
            if status.gpu_active { pal.on_tertiary_container } else { pal.on_surface },
        ),
        (
            "Sleep",
            pal.surface_container_high,
            pal.on_surface,
        ),
    ];
    let mut feature_pills = [Rect::default(); 4];
    for (i, &(lbl, bg, fg)) in feats.iter().enumerate() {
        let r = Rect::new(ctrl_card.x + 28 + i as i32 * (feat_w + feat_gap), feat_y, feat_w, feat_h);
        feature_pills[i] = r;
        fill_rounded_rect(surface, r, 26.0, bg);
        draw_text_centered(surface, r.x + r.w / 2, r.y + feat_h / 2, lbl, 2, fg);
    }

    let nav = draw_bottom_nav(surface, pal, Tab::Home, locale);
    HomeLayout {
        status_capsule: top,
        nav,
        bento: bento_rects,
        quick: quick_rects,
        brightness_slider: slider_r,
        feature_pills,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn swipe_confirm_requires_full_slide() {
        let rect = Rect::new(40, 2000, 1200, 120);
        let mut sc = SwipeConfirm::new("Swipe to wipe /data");
        // Random tap in the middle must NOT arm swipe
        assert!(!sc.on_touch_down(rect, 600, 2060));
        // Touch knob on left edge
        assert!(sc.on_touch_down(rect, 100, 2060));
        // Halfway slide and release resets to 0
        sc.on_touch_move(rect, 600);
        assert!(!sc.confirmed);
        sc.on_touch_up();
        assert_eq!(sc.progress, 0.0);
        assert!(!sc.confirmed);
        // Full slide confirms
        assert!(sc.on_touch_down(rect, 100, 2060));
        sc.on_touch_move(rect, 1180);
        assert!(sc.confirmed);
    }

    #[test]
    fn home_screen_renders_cleanly_at_onyx_resolution() {
        let mut surf = Surface::new(1280, 2772);
        let pal = Palette::default_yasvara();
        let status = StatusSnapshot {
            bootloop_canary: true,
            ..Default::default()
        };
        let layout = render_home_screen(&mut surf, &pal, &status, Locale::EnUs, 0.5, Some(0.62));
        assert_eq!(layout.nav.len(), 4);
        assert_eq!(layout.bento.len(), 4);
        assert_eq!(layout.quick.len(), 4);
        assert!(!surf.dirty.is_empty());
    }

    #[test]
    fn qwerty_keyboard_renders_and_hit_tests_keys() {
        let mut surf = Surface::new(1280, 2772);
        let pal = Palette::default_yasvara();
        let kb = draw_qwerty_keyboard(&mut surf, &pal, false, false);
        assert!(kb.len() >= 40);
        assert!(kb.iter().any(|(_, k)| *k == KeyAction::Char('a')));
        assert!(kb.iter().any(|(_, k)| *k == KeyAction::Char('m')));
        assert!(kb.iter().any(|(_, k)| *k == KeyAction::Shift));
        assert!(kb.iter().any(|(_, k)| *k == KeyAction::Symbols));
        assert!(kb.iter().any(|(_, k)| *k == KeyAction::Backspace));
        assert!(kb.iter().any(|(_, k)| *k == KeyAction::Enter));

        // Symbols page (`?123`) has `:`, `/`, `-`, `_`, `|`
        let sym = draw_qwerty_keyboard(&mut surf, &pal, false, true);
        assert!(sym.iter().any(|(_, k)| *k == KeyAction::Char(':')));
        assert!(sym.iter().any(|(_, k)| *k == KeyAction::Char('/')));
        assert!(sym.iter().any(|(_, k)| *k == KeyAction::Char('|')));
        assert!(sym.iter().any(|(_, k)| *k == KeyAction::Symbols));
    }
}

/// Key action emitted by Pulih's built-in 1:1 Android Gboard M3 Touch Keyboard.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyAction {
    Char(char),
    Backspace,
    Shift,
    Symbols,
    Space,
    Enter,
    Cancel,
}

/// Render a 1:1 Android Gboard Material You touch keyboard at the bottom of `surface`
/// and return all `(Rect, KeyAction)` hit regions.
pub fn draw_qwerty_keyboard(
    surface: &mut Surface,
    pal: &Palette,
    uppercase: bool,
    symbols: bool,
) -> Vec<(Rect, KeyAction)> {
    draw_qwerty_keyboard_offset(surface, pal, uppercase, symbols, 0)
}

/// Render 1:1 Android Gboard shifted vertically by `y_offset` pixels for M3 spring animations.
pub fn draw_qwerty_keyboard_offset(
    surface: &mut Surface,
    pal: &Palette,
    uppercase: bool,
    symbols: bool,
    y_offset: i32,
) -> Vec<(Rect, KeyAction)> {
    let w = surface.width as i32;
    let h = surface.height as i32;
    let row_h = 114;
    let row_gap = 16;
    let pad = 12;
    let gap = 10;
    let bottom_inset = 72; // Gesture bar clearance matching Android Gboard
    let kb_h = 24 + 5 * row_h + 4 * row_gap + bottom_inset;
    let kb_top = h - kb_h + y_offset;

    let bg = Rect::new(0, kb_top, w, kb_h);
    fill_rounded_rect(surface, bg, 32.0, pal.surface_container_low);

    let mut out = Vec::with_capacity(52);
    let kw10 = (w - pad * 2 - gap * 9) / 10;

    let draw_char_key = |surface: &mut Surface,
                         out: &mut Vec<(Rect, KeyAction)>,
                         r: Rect,
                         ch: char,
                         key_bg: crate::Color,
                         key_fg: crate::Color| {
        fill_rounded_rect(surface, r, 18.0, key_bg);
        let mut s = [0u8; 4];
        let label = ch.encode_utf8(&mut s);
        draw_text_centered(surface, r.x + r.w / 2, r.y + r.h / 2, label, 4, key_fg);
        out.push((r, KeyAction::Char(ch)));
    };

    // Row 0: Number row (10 keys, identical across Letters & Symbols)
    let y0 = kb_top + 20;
    for (i, ch) in "1234567890".chars().enumerate() {
        let x = pad + i as i32 * (kw10 + gap);
        draw_char_key(
            surface,
            &mut out,
            Rect::new(x, y0, kw10, row_h),
            ch,
            pal.surface_container_high,
            pal.on_surface,
        );
    }

    if !symbols {
        // Row 1: q w e r t y u i o p (10 keys)
        let r1 = if uppercase { "QWERTYUIOP" } else { "qwertyuiop" };
        let y1 = y0 + row_h + row_gap;
        for (i, ch) in r1.chars().enumerate() {
            let x = pad + i as i32 * (kw10 + gap);
            draw_char_key(
                surface,
                &mut out,
                Rect::new(x, y1, kw10, row_h),
                ch,
                pal.surface_container_highest,
                pal.on_surface,
            );
        }

        // Row 2: a s d f g h j k l (9 keys, staggered inward by half-key like Gboard!)
        let r2 = if uppercase { "ASDFGHJKL" } else { "asdfghjkl" };
        let y2 = y1 + row_h + row_gap;
        let row2_total = 9 * kw10 + 8 * gap;
        let row2_start = (w - row2_total) / 2;
        for (i, ch) in r2.chars().enumerate() {
            let x = row2_start + i as i32 * (kw10 + gap);
            draw_char_key(
                surface,
                &mut out,
                Rect::new(x, y2, kw10, row_h),
                ch,
                pal.surface_container_highest,
                pal.on_surface,
            );
        }

        // Row 3: [SHIFT] z x c v b n m [DEL] (exact Gboard 1.5x side modifiers!)
        let r3 = if uppercase { "ZXCVBNM" } else { "zxcvbnm" };
        let y3 = y2 + row_h + row_gap;
        let letters_w = 7 * kw10 + 6 * gap;
        let side_w = ((w - pad * 2 - letters_w - gap * 2) / 2).max(120);

        // Left Shift pill
        let shift_r = Rect::new(pad, y3, side_w, row_h);
        let shift_bg = if uppercase {
            pal.primary
        } else {
            pal.secondary_container
        };
        let shift_fg = if uppercase {
            pal.on_primary
        } else {
            pal.on_secondary_container
        };
        fill_rounded_rect(surface, shift_r, 22.0, shift_bg);
        draw_text_centered(
            surface,
            shift_r.x + shift_r.w / 2,
            shift_r.y + shift_r.h / 2,
            if uppercase { "CAPS" } else { "SHFT" },
            3,
            shift_fg,
        );
        out.push((shift_r, KeyAction::Shift));

        // 7 center letter keys
        let c_start = shift_r.right() + gap;
        for (i, ch) in r3.chars().enumerate() {
            let x = c_start + i as i32 * (kw10 + gap);
            draw_char_key(
                surface,
                &mut out,
                Rect::new(x, y3, kw10, row_h),
                ch,
                pal.surface_container_highest,
                pal.on_surface,
            );
        }

        // Right Backspace pill
        let del_x = c_start + letters_w + gap;
        let del_r = Rect::new(del_x, y3, w - pad - del_x, row_h);
        fill_rounded_rect(surface, del_r, 22.0, pal.secondary_container);
        draw_text_centered(
            surface,
            del_r.x + del_r.w / 2,
            del_r.y + del_r.h / 2,
            "DEL",
            3,
            pal.on_secondary_container,
        );
        out.push((del_r, KeyAction::Backspace));
    } else {
        // Symbols Page (`?123`): 1:1 Gboard symbol layout tailored for Linux/URL/Files
        let y1 = y0 + row_h + row_gap;
        for (i, ch) in "@#$_&-+()/".chars().enumerate() {
            let x = pad + i as i32 * (kw10 + gap);
            draw_char_key(
                surface,
                &mut out,
                Rect::new(x, y1, kw10, row_h),
                ch,
                pal.surface_container_highest,
                pal.on_surface,
            );
        }

        let y2 = y1 + row_h + row_gap;
        for (i, ch) in "*\"':;!?~|\\".chars().enumerate() {
            let x = pad + i as i32 * (kw10 + gap);
            draw_char_key(
                surface,
                &mut out,
                Rect::new(x, y2, kw10, row_h),
                ch,
                pal.surface_container_highest,
                pal.on_surface,
            );
        }

        // Row 3: [ABC] , = [ ] { } < > [DEL]
        let y3 = y2 + row_h + row_gap;
        let sym3 = ",=[]{}<>";
        let sym_w = 8 * kw10 + 7 * gap;
        let side_w = ((w - pad * 2 - sym_w - gap * 2) / 2).max(100);
        let abc_r = Rect::new(pad, y3, side_w, row_h);
        fill_rounded_rect(surface, abc_r, 22.0, pal.secondary_container);
        draw_text_centered(
            surface,
            abc_r.x + abc_r.w / 2,
            abc_r.y + abc_r.h / 2,
            "ABC",
            3,
            pal.on_secondary_container,
        );
        out.push((abc_r, KeyAction::Symbols));

        let c_start = abc_r.right() + gap;
        for (i, ch) in sym3.chars().enumerate() {
            let x = c_start + i as i32 * (kw10 + gap);
            draw_char_key(
                surface,
                &mut out,
                Rect::new(x, y3, kw10, row_h),
                ch,
                pal.surface_container_highest,
                pal.on_surface,
            );
        }

        let del_x = c_start + sym_w + gap;
        let del_r = Rect::new(del_x, y3, w - pad - del_x, row_h);
        fill_rounded_rect(surface, del_r, 22.0, pal.secondary_container);
        draw_text_centered(
            surface,
            del_r.x + del_r.w / 2,
            del_r.y + del_r.h / 2,
            "DEL",
            3,
            pal.on_secondary_container,
        );
        out.push((del_r, KeyAction::Backspace));
    }

    // Row 4 (Exact Android Gboard bottom row): [?123 / ABC]  [/]  [     space     ]  [.]  [OK]
    let y4 = y0 + 4 * (row_h + row_gap);
    let sym_w = 176;
    let slash_w = 114;
    let dot_w = 114;
    let enter_w = 196;
    let space_w = (w - pad * 2 - sym_w - slash_w - dot_w - enter_w - gap * 4).max(200);

    let mut cx = pad;
    let sym_r = Rect::new(cx, y4, sym_w, row_h);
    fill_rounded_rect(surface, sym_r, row_h as f32 * 0.5, pal.secondary_container);
    draw_text_centered(
        surface,
        sym_r.x + sym_r.w / 2,
        sym_r.y + sym_r.h / 2,
        if symbols { "ABC" } else { "?123" },
        3,
        pal.on_secondary_container,
    );
    out.push((sym_r, KeyAction::Symbols));
    cx += sym_w + gap;

    let left_punct = if symbols { ',' } else { '/' };
    draw_char_key(
        surface,
        &mut out,
        Rect::new(cx, y4, slash_w, row_h),
        left_punct,
        pal.surface_container_high,
        pal.on_surface,
    );
    cx += slash_w + gap;

    let space_r = Rect::new(cx, y4, space_w, row_h);
    fill_rounded_rect(surface, space_r, 22.0, pal.surface_container_highest);
    draw_text_centered(
        surface,
        space_r.x + space_r.w / 2,
        space_r.y + space_r.h / 2,
        "English (US)",
        2,
        pal.on_surface_variant,
    );
    out.push((space_r, KeyAction::Space));
    cx += space_w + gap;

    draw_char_key(
        surface,
        &mut out,
        Rect::new(cx, y4, dot_w, row_h),
        '.',
        pal.surface_container_high,
        pal.on_surface,
    );
    cx += dot_w + gap;

    let enter_r = Rect::new(cx, y4, w - pad - cx, row_h);
    fill_rounded_rect(surface, enter_r, row_h as f32 * 0.5, pal.primary);
    draw_text_centered(
        surface,
        enter_r.x + enter_r.w / 2,
        enter_r.y + enter_r.h / 2,
        "GO",
        3,
        pal.on_primary,
    );
    out.push((enter_r, KeyAction::Enter));

    out
}
