// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: Apache-2.0

//! Pure-Rust 5-widget Material You HUD compositor, dirty-rect tracker, and ping-pong renderer.
//!
//! Widgets:
//! - `0 · Classic`: big FPS + CPU / GPU / RAM / NET / PWR card
//! - `1 · Mini`: ultra-compact **top-edge docked (`y = 0`)** customizable bar (`STYLE_MICRO` 20px)
//! - `2 · Processes`: Scene-inspired Material You list with real cached 28×28 app icons, prebaked
//!   monochrome kernel/HAL/thread icons, `Apps`/`All`/`Threads` modes, smart 1-line shortening,
//!   and 3px CPU micro-bars
//! - `3 · Temp`: compact CPU / GPU / BAT temperature pill
//! - `4 · Network`: unified **1-graph** Wi-Fi + Mobile Data + Upload chart + passive kernel RTT/jitter
//!
//! Zero `core::fmt`, zero heap allocations on steady ticks!

use crate::abi::{
    SnapshotCopy, LINK_CELL, LINK_ETH, LINK_VPN, LINK_WIFI, METRIC_HIST_LEN,
};
use crate::hud::atlas::{
    AtlasView, MappedAtlas, STYLE_BIG, STYLE_LABEL, STYLE_MICRO, STYLE_VALUE, SYM_DEGREE, SYM_DOWN,
    SYM_ELLIPSIS, SYM_EMDASH, SYM_ICON_DAEMON, SYM_ICON_KERNEL, SYM_ICON_THREAD, SYM_MIDDOT,
    SYM_PLUSMINUS, SYM_UP,
};
use crate::hud::icons::{shorten_proc_name, IconCache, ICON_DIM};
use crate::hud::{
    blit_alpha8, blit_rgba_sprite, draw_line_blend, fill_rect_blend, fmt_deci_ascii, fmt_u32_ascii,
    render_rounded_bg_stroked, render_top_docked_bg, restore_dirty_rect, runs_equal, GlyphCmd,
    Rgba,
};
use crate::schema::{field, mini_anchor, HudProfile, WidgetId, WIDGET_COUNT};
use crate::sys::thread_cpu_ns;

pub const MAX_CMDS: usize = 256;
pub const MAX_RECTS: usize = 24;
pub const MAX_ICONS: usize = 8;
const NET_GRAPH_SAMPLES: usize = 48;

const HOT_SOC_DECI_C: i16 = 700; // 70.0 °C
const HOT_BAT_DECI_C: i16 = 420; // 42.0 °C

/// Monet palette indices embedded in [`GlyphCmd::color_idx`].
const COL_PRIMARY: u8 = 0;    // Material You primary (blue/accent)
const COL_ON_SURFACE: u8 = 1; // Primary text
const COL_VARIANT: u8 = 2;    // Secondary / label text
const COL_ERROR: u8 = 3;      // Hot / high load warning
const COL_TERTIARY: u8 = 4;   // Mobile Data mint-green accent
const COL_AMBER: u8 = 5;      // Upload (Tx) amber accent

/// Per-widget action plan handed across FFI to `daemon/hud.cpp`.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct HudWidgetPlan {
    pub enabled: bool,
    pub needs_resize: bool,
    pub needs_redraw: bool,
    pub skip_screenshot: bool,
    pub w: u32,
    pub h: u32,
    pub x: i32,
    pub y: i32,
}

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
struct RectCmd {
    x: i16,
    y: i16,
    w: u16,
    h: u16,
    rgba: Rgba,
}

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
struct IconCmd {
    x: i16,
    y: i16,
    uid: u32,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
struct NetGraphState {
    active: bool,
    x: i16,
    y: i16,
    w: u16,
    h: u16,
    count: u16,
    max_kbps: u32,
    wifi_rx: [u32; NET_GRAPH_SAMPLES],
    cell_rx: [u32; NET_GRAPH_SAMPLES],
    tx: [u32; NET_GRAPH_SAMPLES],
}

impl Default for NetGraphState {
    fn default() -> Self {
        Self {
            active: false,
            x: 0,
            y: 0,
            w: 0,
            h: 0,
            count: 0,
            max_kbps: 0,
            wifi_rx: [0; NET_GRAPH_SAMPLES],
            cell_rx: [0; NET_GRAPH_SAMPLES],
            tx: [0; NET_GRAPH_SAMPLES],
        }
    }
}

#[derive(Copy, Clone, Debug, Default)]
struct BBox {
    x0: u16,
    y0: u16,
    x1: u16,
    y1: u16,
}

impl BBox {
    #[inline]
    fn empty() -> Self {
        Self { x0: u16::MAX, y0: u16::MAX, x1: 0, y1: 0 }
    }
    #[inline]
    fn is_empty(&self) -> bool {
        self.x0 >= self.x1 || self.y0 >= self.y1
    }
    #[inline]
    fn include(&mut self, x0: i32, y0: i32, x1: i32, y1: i32, max_w: u16, max_h: u16) {
        let cx0 = x0.clamp(0, max_w as i32) as u16;
        let cy0 = y0.clamp(0, max_h as i32) as u16;
        let cx1 = x1.clamp(0, max_w as i32) as u16;
        let cy1 = y1.clamp(0, max_h as i32) as u16;
        if cx0 < cx1 && cy0 < cy1 {
            self.x0 = self.x0.min(cx0);
            self.y0 = self.y0.min(cy0);
            self.x1 = self.x1.max(cx1);
            self.y1 = self.y1.max(cy1);
        }
    }
    #[inline]
    fn union(&self, other: &Self) -> Self {
        if self.is_empty() {
            return *other;
        }
        if other.is_empty() {
            return *self;
        }
        Self {
            x0: self.x0.min(other.x0),
            y0: self.y0.min(other.y0),
            x1: self.x1.max(other.x1),
            y1: self.y1.max(other.y1),
        }
    }
}

struct WidgetSlot {
    w: u32,
    h: u32,
    bg_template: Vec<u8>,
    bg_version: u32,
    slot_bg_version: [u32; 2],
    slot_bbox: [BBox; 2],
    prev_cmds: [GlyphCmd; MAX_CMDS],
    prev_len: usize,
    curr_cmds: [GlyphCmd; MAX_CMDS],
    curr_len: usize,
    prev_rects: [RectCmd; MAX_RECTS],
    prev_rect_len: usize,
    curr_rects: [RectCmd; MAX_RECTS],
    curr_rect_len: usize,
    prev_icons: [IconCmd; MAX_ICONS],
    prev_icon_len: usize,
    curr_icons: [IconCmd; MAX_ICONS],
    curr_icon_len: usize,
    prev_icon_gen: u32,
    prev_graph: NetGraphState,
    curr_graph: NetGraphState,
    curr_bbox: BBox,
    last_plan: HudWidgetPlan,
}

impl Default for WidgetSlot {
    fn default() -> Self {
        Self {
            w: 0,
            h: 0,
            bg_template: Vec::new(),
            bg_version: 0,
            slot_bg_version: [0; 2],
            slot_bbox: [BBox::empty(), BBox::empty()],
            prev_cmds: [GlyphCmd::default(); MAX_CMDS],
            prev_len: 0,
            curr_cmds: [GlyphCmd::default(); MAX_CMDS],
            curr_len: 0,
            prev_rects: [RectCmd::default(); MAX_RECTS],
            prev_rect_len: 0,
            curr_rects: [RectCmd::default(); MAX_RECTS],
            curr_rect_len: 0,
            prev_icons: [IconCmd::default(); MAX_ICONS],
            prev_icon_len: 0,
            curr_icons: [IconCmd::default(); MAX_ICONS],
            curr_icon_len: 0,
            prev_icon_gen: 0,
            prev_graph: NetGraphState::default(),
            curr_graph: NetGraphState::default(),
            curr_bbox: BBox::empty(),
            last_plan: HudWidgetPlan::default(),
        }
    }
}

/// Complete Monet-themed 5-widget native HUD compositor.
pub struct HudCompositor {
    mapped_atlas: Option<MappedAtlas>,
    fallback_atlas: Vec<u8>,
    icons: IconCache,
    surface_rgb: [u8; 3],
    palette: [Rgba; 6], // [primary, on_surface, variant, error, tertiary_mint, amber_tx]
    theme_gen: u32,
    rotation: u8, // 0=portrait, 1=landscape (90/270)
    disp_w: u32,
    disp_h: u32,
    widgets: [WidgetSlot; WIDGET_COUNT],
}

impl Default for HudCompositor {
    fn default() -> Self {
        Self::new()
    }
}

impl HudCompositor {
    pub fn new() -> Self {
        let mapped = MappedAtlas::open_default();
        let fallback = if mapped.is_none() {
            crate::hud::atlas::build_synthetic_atlas()
        } else {
            Vec::new()
        };
        Self {
            mapped_atlas: mapped,
            fallback_atlas: fallback,
            icons: IconCache::new(),
            // Material 3 dark defaults until PentasService pushes Monet dynamic colours.
            surface_rgb: [16, 18, 23],
            palette: [
                [168, 199, 250, 255], // 0: primary (Wi-Fi / accent)
                [227, 226, 230, 255], // 1: onSurface
                [196, 198, 208, 255], // 2: onSurfaceVariant
                [242, 184, 181, 255], // 3: error
                [110, 231, 183, 255], // 4: tertiary mint (Mobile Data 5G/4G)
                [251, 191, 36, 255],  // 5: amber (Upload Tx)
            ],
            theme_gen: 1,
            rotation: 0,
            disp_w: 1280,
            disp_h: 2772,
            widgets: [
                WidgetSlot::default(),
                WidgetSlot::default(),
                WidgetSlot::default(),
                WidgetSlot::default(),
                WidgetSlot::default(),
            ],
        }
    }

    #[inline]
    fn atlas(&self) -> Option<AtlasView<'_>> {
        if let Some(m) = &self.mapped_atlas {
            m.view()
        } else {
            AtlasView::open(&self.fallback_atlas)
        }
    }

    /// Updates cached app label and 28×28 RGBA icon for `uid` (pushed lazily from `PentasService`).
    pub fn put_uid_meta(&mut self, uid: u32, label: &[u8], rgba: &[u8]) {
        self.icons.put(uid, label, rgba);
    }

    #[inline]
    pub fn uid_label(&self, uid: u32) -> Option<&[u8]> {
        self.icons.label_of(uid)
    }

    /// Updates Monet dynamic dark colours (`[surface, primary, onSurface, onSurfaceVariant]` ARGB).
    pub fn set_monet_argb(&mut self, argb: &[u32; 4]) {
        let unpack = |c: u32| -> Rgba {
            [((c >> 16) & 0xff) as u8, ((c >> 8) & 0xff) as u8, (c & 0xff) as u8, 255]
        };
        let surf = unpack(argb[0]);
        let next_rgb = [surf[0], surf[1], surf[2]];
        let next_pal = [
            unpack(argb[1]),
            unpack(argb[2]),
            unpack(argb[3]),
            [242, 184, 181, 255],
            [110, 231, 183, 255],
            [251, 191, 36, 255],
        ];
        if next_rgb != self.surface_rgb || next_pal != self.palette {
            self.surface_rgb = next_rgb;
            self.palette = next_pal;
            self.theme_gen = self.theme_gen.wrapping_add(1).max(1);
        }
    }

    pub fn set_display(&mut self, rotation: u8, width_px: u32, height_px: u32) {
        self.rotation = rotation & 3;
        if width_px > 0 && height_px > 0 {
            self.disp_w = width_px;
            self.disp_h = height_px;
        }
    }

    /// Recomputes layout & dirty status for widget `idx` (0 heap allocations on steady ticks!).
    pub fn plan_widget(
        &mut self,
        idx: usize,
        hud_visible: bool,
        profile: &HudProfile,
        snap: &SnapshotCopy,
    ) -> HudWidgetPlan {
        if idx >= WIDGET_COUNT {
            return HudWidgetPlan::default();
        }
        let wid = match idx {
            0 => WidgetId::Classic,
            1 => WidgetId::Mini,
            2 => WidgetId::Processes,
            3 => WidgetId::Temp,
            _ => WidgetId::Network,
        };
        if !hud_visible || !profile.widget_enabled(wid) {
            let plan = HudWidgetPlan::default();
            let slot = &mut self.widgets[idx];
            slot.last_plan = plan;
            slot.slot_bg_version = [0, 0];
            slot.slot_bbox = [BBox::empty(), BBox::empty()];
            slot.prev_len = 0;
            slot.prev_rect_len = 0;
            slot.prev_icon_len = 0;
            slot.prev_graph.active = false;
            return plan;
        }

        let mut cmds = [GlyphCmd::default(); MAX_CMDS];
        let mut rects = [RectCmd::default(); MAX_RECTS];
        let mut rlen = 0usize;
        let mut icons = [IconCmd::default(); MAX_ICONS];
        let mut ilen = 0usize;
        let mut graph = NetGraphState::default();

        let (w, h, len, mut bbox) = {
            let Some(atlas) = self.atlas() else {
                return HudWidgetPlan::default();
            };
            match wid {
                WidgetId::Classic => layout_classic(&atlas, profile, snap, &mut cmds),
                WidgetId::Mini => layout_mini(&atlas, profile, snap, &mut cmds),
                WidgetId::Processes => layout_processes(
                    &atlas,
                    profile,
                    snap,
                    &self.icons,
                    &self.palette,
                    &mut cmds,
                    &mut rects,
                    &mut rlen,
                    &mut icons,
                    &mut ilen,
                ),
                WidgetId::Temp => layout_temp(&atlas, profile, snap, &mut cmds),
                WidgetId::Network => layout_network(&atlas, snap, &mut cmds, &mut graph),
            }
        };

        for r in &rects[..rlen] {
            bbox.include(
                r.x as i32,
                r.y as i32,
                r.x as i32 + r.w as i32,
                r.y as i32 + r.h as i32,
                w as u16,
                h as u16,
            );
        }
        for ic in &icons[..ilen] {
            bbox.include(
                ic.x as i32,
                ic.y as i32,
                ic.x as i32 + ICON_DIM as i32,
                ic.y as i32 + ICON_DIM as i32,
                w as u16,
                h as u16,
            );
        }
        if graph.active {
            bbox.include(
                graph.x as i32,
                graph.y as i32,
                graph.x as i32 + graph.w as i32,
                graph.y as i32 + graph.h as i32,
                w as u16,
                h as u16,
            );
        }

        let is_top_docked = wid == WidgetId::Mini && profile.mini_anchor != mini_anchor::FREE;
        let slot = &mut self.widgets[idx];
        let needs_resize = slot.w != w || slot.h != h;
        let bg_key = self
            .theme_gen
            .wrapping_mul(513)
            .wrapping_add(profile.opacity_u8 as u32 * 2 + is_top_docked as u32);
        let bg_stale = needs_resize || slot.bg_version != bg_key;

        if bg_stale {
            let bytes_needed = (w as usize) * (h as usize) * 4;
            slot.bg_template.resize(bytes_needed, 0);
            let p_col = self.palette[COL_PRIMARY as usize];
            if is_top_docked {
                // Flush top-edge docked bar: pure bezel-black at y=0, flat top edge, rounded bottom.
                let dock_alpha = profile.opacity_u8.max(244);
                render_top_docked_bg(
                    &mut slot.bg_template,
                    w as usize,
                    h as usize,
                    14.0,
                    [0, 0, 0, dock_alpha],
                    [p_col[0], p_col[1], p_col[2], 64],
                );
            } else {
                let radius = if matches!(wid, WidgetId::Mini | WidgetId::Temp) { 26.0 } else { 34.0 };
                render_rounded_bg_stroked(
                    &mut slot.bg_template,
                    w as usize,
                    h as usize,
                    radius,
                    [self.surface_rgb[0], self.surface_rgb[1], self.surface_rgb[2], profile.opacity_u8],
                    [p_col[0], p_col[1], p_col[2], 56],
                );
                if wid == WidgetId::Network && graph.active {
                    // Bake chart inset background & 2 hairline grid lines ONCE into bg_template!
                    let gx = graph.x as i32;
                    let gy = graph.y as i32;
                    let gw = graph.w as i32;
                    let gh = graph.h as i32;
                    fill_rect_blend(&mut slot.bg_template, w as usize, w as usize, h as usize, gx, gy, gw, gh, [255, 255, 255, 14]);
                    fill_rect_blend(&mut slot.bg_template, w as usize, w as usize, h as usize, gx, gy + gh / 3, gw, 1, [255, 255, 255, 22]);
                    fill_rect_blend(&mut slot.bg_template, w as usize, w as usize, h as usize, gx, gy + (gh * 2) / 3, gw, 1, [255, 255, 255, 22]);
                }
            }
            slot.w = w;
            slot.h = h;
            slot.bg_version = bg_key;
            slot.slot_bg_version = [0, 0];
            slot.slot_bbox = [BBox::empty(), BBox::empty()];
            slot.prev_len = 0;
            slot.prev_rect_len = 0;
            slot.prev_icon_len = 0;
            slot.prev_graph.active = false;
        }

        let icon_gen = self.icons.generation();
        let changed = bg_stale
            || !runs_equal(&cmds[..len], &slot.prev_cmds[..slot.prev_len])
            || rects[..rlen] != slot.prev_rects[..slot.prev_rect_len]
            || icons[..ilen] != slot.prev_icons[..slot.prev_icon_len]
            || (ilen > 0 && slot.prev_icon_gen != icon_gen)
            || graph != slot.prev_graph;

        slot.curr_cmds[..len].copy_from_slice(&cmds[..len]);
        slot.curr_len = len;
        slot.curr_rects[..rlen].copy_from_slice(&rects[..rlen]);
        slot.curr_rect_len = rlen;
        slot.curr_icons[..ilen].copy_from_slice(&icons[..ilen]);
        slot.curr_icon_len = ilen;
        slot.curr_graph = graph;
        slot.curr_bbox = bbox;

        let max_x = self.disp_w.saturating_sub(w) as i32;
        let max_y = self.disp_h.saturating_sub(h) as i32;
        let (x, y) = if is_top_docked {
            // Flush y = 0 against top screen bezel (NOT floating!).
            let tx = match profile.mini_anchor {
                mini_anchor::TOP_LEFT => 16.min(max_x.max(0)),
                mini_anchor::TOP_RIGHT => max_x.saturating_sub(16).max(0),
                _ => (max_x / 2).max(0),
            };
            (tx, 0)
        } else {
            let is_land = (self.rotation == 1 || self.rotation == 3) || (self.disp_w > self.disp_h);
            let p = profile.pos[idx];
            let (raw_x, raw_y) = if is_land {
                (p.x_land as i32, p.y_land as i32)
            } else {
                (p.x_port as i32, p.y_port as i32)
            };
            (raw_x.clamp(0, max_x.max(0)), raw_y.clamp(0, max_y.max(0)))
        };

        let plan = HudWidgetPlan {
            enabled: true,
            needs_resize,
            needs_redraw: changed,
            skip_screenshot: !profile.show_in_capture,
            w,
            h,
            x,
            y,
        };
        slot.last_plan = plan;
        plan
    }

    /// Renders widget `idx` into locked ping-pong `GraphicBuffer` `dst`
    /// (`slot_idx_flags`: bit 0 = slot `{0, 1}`, bit 8 (`0x100`) = freshly allocated buffer).
    /// Returns CPU render duration in microseconds (0 heap allocations!).
    pub fn render_widget(
        &mut self,
        idx: usize,
        dst: &mut [u8],
        stride_px: usize,
        slot_idx_flags: usize,
    ) -> u32 {
        let force_full = (slot_idx_flags & 0x100) != 0;
        let slot_idx = slot_idx_flags & 1;
        if idx >= WIDGET_COUNT {
            return 0;
        }
        let t0 = thread_cpu_ns();
        let w = self.widgets[idx].w as usize;
        let h = self.widgets[idx].h as usize;
        if w == 0 || h == 0 || stride_px < w || dst.len() < h * stride_px * 4 {
            return 0;
        }

        // 1) Restore full template (first draw/fresh GraphicBuffer/resize/theme) or dirty union bbox.
        let need_full = force_full
            || self.widgets[idx].slot_bg_version[slot_idx] != self.widgets[idx].bg_version;
        if need_full {
            let row_bytes = w * 4;
            let bg = &self.widgets[idx].bg_template;
            for row in 0..h {
                let soff = row * row_bytes;
                let doff = row * stride_px * 4;
                dst[doff..doff + row_bytes].copy_from_slice(&bg[soff..soff + row_bytes]);
            }
            self.widgets[idx].slot_bg_version[slot_idx] = self.widgets[idx].bg_version;
        } else {
            let dirty = self.widgets[idx].slot_bbox[slot_idx].union(&self.widgets[idx].curr_bbox);
            if !dirty.is_empty() {
                let dx = dirty.x0 as usize;
                let dy = dirty.y0 as usize;
                let dw = (dirty.x1 - dirty.x0) as usize;
                let dh = (dirty.y1 - dirty.y0) as usize;
                let bg = &self.widgets[idx].bg_template;
                for row in dy..dy + dh {
                    let soff = (row * w + dx) * 4;
                    let doff = (row * stride_px + dx) * 4;
                    let rb = dw * 4;
                    dst[doff..doff + rb].copy_from_slice(&bg[soff..soff + rb]);
                }
            }
        }

        // 2) Draw auxiliary rectangles (micro-bars, hairline dividers, transport dots).
        let rlen = self.widgets[idx].curr_rect_len;
        for i in 0..rlen {
            let r = self.widgets[idx].curr_rects[i];
            fill_rect_blend(
                dst,
                stride_px,
                w,
                h,
                r.x as i32,
                r.y as i32,
                r.w as i32,
                r.h as i32,
                r.rgba,
            );
        }

        // 3) Draw Unified Network 1-Grafik (stacked Wi-Fi + Mobile Data area + dashed Tx line).
        if self.widgets[idx].curr_graph.active {
            render_unified_net_graph(
                dst,
                stride_px,
                w,
                h,
                &self.widgets[idx].curr_graph,
                &self.palette,
            );
        }

        // 4) Draw cached 28×28 RGBA app icons (Processes widget).
        let ilen = self.widgets[idx].curr_icon_len;
        for i in 0..ilen {
            let ic = self.widgets[idx].curr_icons[i];
            if let Some((_, Some(rgba))) = self.icons.get(ic.uid) {
                blit_rgba_sprite(
                    dst,
                    stride_px,
                    w,
                    h,
                    ic.x as i32,
                    ic.y as i32,
                    rgba,
                    ICON_DIM,
                    ICON_DIM,
                );
            }
        }

        // 5) Blit every glyph command via ARMv9 NEON (or scalar on host).
        let cmds_len = self.widgets[idx].curr_len;
        let palette = self.palette;
        if let Some(atlas) = self.atlas() {
            for i in 0..cmds_len {
                let c = self.widgets[idx].curr_cmds[i];
                if let Some((g, bm)) = atlas.glyph(c.style, c.glyph_id) {
                    if g.w > 0 && g.h > 0 {
                        let gx = c.x as i32 + g.bearing_x as i32;
                        let gy = c.y as i32 - g.bearing_y as i32;
                        let fg = palette[(c.color_idx as usize).min(palette.len() - 1)];
                        blit_alpha8(
                            dst,
                            stride_px,
                            w,
                            h,
                            gx,
                            gy,
                            bm,
                            g.w as usize,
                            g.w as usize,
                            g.h as usize,
                            fg,
                        );
                    }
                }
            }
        }

        let icon_gen = self.icons.generation();
        let wslot = &mut self.widgets[idx];
        wslot.slot_bbox[slot_idx] = wslot.curr_bbox;
        wslot.prev_cmds[..cmds_len].copy_from_slice(&wslot.curr_cmds[..cmds_len]);
        wslot.prev_len = cmds_len;
        wslot.prev_rects[..rlen].copy_from_slice(&wslot.curr_rects[..rlen]);
        wslot.prev_rect_len = rlen;
        wslot.prev_icons[..ilen].copy_from_slice(&wslot.curr_icons[..ilen]);
        wslot.prev_icon_len = ilen;
        wslot.prev_icon_gen = icon_gen;
        wslot.prev_graph = wslot.curr_graph;

        let _ = restore_dirty_rect;

        let t1 = thread_cpu_ns();
        (t1.saturating_sub(t0) / 1_000).min(u32::MAX as u64) as u32
    }
}

// ── Unified 1-Grafik Network Renderer (0 alloc) ─────────────────────────────

fn render_unified_net_graph(
    dst: &mut [u8],
    stride_px: usize,
    dst_w: usize,
    dst_h: usize,
    g: &NetGraphState,
    palette: &[Rgba; 6],
) {
    let gx = g.x as i32;
    let gy = g.y as i32;
    let gw = g.w as i32;
    let gh = g.h as i32;
    if gw < 8 || gh < 8 {
        return;
    }

    let n = (g.count as usize).min(NET_GRAPH_SAMPLES);
    if n < 2 {
        return;
    }

    let max_v = g.max_kbps.max(64) as i64;
    let usable_h = (gh - 6).max(4) as i64;
    let bot_y = gy + gh - 2;

    let wifi_col = palette[COL_PRIMARY as usize];
    let cell_col = palette[COL_TERTIARY as usize];
    let tx_col = palette[COL_AMBER as usize];
    let wifi_fill = [wifi_col[0], wifi_col[1], wifi_col[2], 74];
    let cell_fill = [cell_col[0], cell_col[1], cell_col[2], 74];

    let y_of = |v: u32| -> i32 {
        let clamped = (v as i64).min(max_v);
        bot_y - ((clamped * usable_h) / max_v) as i32
    };
    let x_of = |i: usize| -> i32 {
        gx + ((i as i64 * (gw - 1) as i64) / (NET_GRAPH_SAMPLES - 1) as i64) as i32
    };

    // Align newest sample to the right edge of the graph.
    let start_slot = NET_GRAPH_SAMPLES - n;

    // 1) Non-overlapping vertical stacked area fills.
    for i in 0..n {
        let x0 = x_of(start_slot + i);
        let x1 = if i + 1 < n { x_of(start_slot + i + 1) } else { gx + gw };
        let col_w = (x1 - x0).max(1);
        let wv = g.wifi_rx[i];
        let cv = g.cell_rx[i];
        let y_w = y_of(wv);
        let y_wc = y_of(wv.saturating_add(cv));
        if wv > 0 && bot_y > y_w {
            fill_rect_blend(dst, stride_px, dst_w, dst_h, x0, y_w, col_w, bot_y - y_w, wifi_fill);
        }
        if cv > 0 && y_w > y_wc {
            fill_rect_blend(dst, stride_px, dst_w, dst_h, x0, y_wc, col_w, y_w - y_wc, cell_fill);
        }
    }

    // 2) Crisp 2-px polylines: Wi-Fi (blue), Mobile Data (mint), dashed Upload (amber).
    for i in 1..n {
        let x0 = x_of(start_slot + i - 1);
        let x1 = x_of(start_slot + i);

        if g.wifi_rx[i - 1] > 0 || g.wifi_rx[i] > 0 {
            draw_line_blend(
                dst,
                stride_px,
                dst_w,
                dst_h,
                x0,
                y_of(g.wifi_rx[i - 1]),
                x1,
                y_of(g.wifi_rx[i]),
                wifi_col,
                false,
            );
        }
        if g.cell_rx[i - 1] > 0 || g.cell_rx[i] > 0 {
            draw_line_blend(
                dst,
                stride_px,
                dst_w,
                dst_h,
                x0,
                y_of(g.wifi_rx[i - 1].saturating_add(g.cell_rx[i - 1])),
                x1,
                y_of(g.wifi_rx[i].saturating_add(g.cell_rx[i])),
                cell_col,
                false,
            );
        }
        if g.tx[i - 1] > 0 || g.tx[i] > 0 {
            draw_line_blend(
                dst,
                stride_px,
                dst_w,
                dst_h,
                x0,
                y_of(g.tx[i - 1]),
                x1,
                y_of(g.tx[i]),
                tx_col,
                true,
            );
        }
    }
}

// ── Zero-alloc Glyph Run Builder ────────────────────────────────────────────

struct RunBuilder<'a> {
    atlas: &'a AtlasView<'a>,
    cmds: &'a mut [GlyphCmd; MAX_CMDS],
    len: usize,
    bbox: BBox,
    max_w: u16,
    max_h: u16,
}

impl<'a> RunBuilder<'a> {
    fn new(atlas: &'a AtlasView<'a>, cmds: &'a mut [GlyphCmd; MAX_CMDS], max_w: u32, max_h: u32) -> Self {
        Self {
            atlas,
            cmds,
            len: 0,
            bbox: BBox::empty(),
            max_w: max_w.min(u16::MAX as u32) as u16,
            max_h: max_h.min(u16::MAX as u32) as u16,
        }
    }

    #[inline]
    fn push_id(&mut self, x: &mut i32, baseline_y: i32, style: u8, id: u16, col: u8) {
        let Some((g, _)) = self.atlas.glyph(style, id) else {
            return;
        };
        if g.w > 0 && g.h > 0 && self.len < MAX_CMDS {
            let gx = *x + g.bearing_x as i32;
            let gy = baseline_y - g.bearing_y as i32;
            self.cmds[self.len] = GlyphCmd {
                x: (*x).clamp(i16::MIN as i32, i16::MAX as i32) as i16,
                y: baseline_y.clamp(i16::MIN as i32, i16::MAX as i32) as i16,
                glyph_id: id,
                color_idx: col,
                style,
            };
            self.len += 1;
            self.bbox.include(gx, gy, gx + g.w as i32, gy + g.h as i32, self.max_w, self.max_h);
        }
        *x += g.advance_x as i32;
    }

    #[inline]
    fn push_ascii(&mut self, x: &mut i32, baseline_y: i32, style: u8, s: &[u8], col: u8) {
        for &b in s {
            self.push_id(x, baseline_y, style, AtlasView::ascii_glyph_id(b), col);
        }
    }

    /// Pushes ASCII clipped cleanly to `max_x` with a trailing `…` ellipsis if truncated.
    fn push_ascii_clipped(
        &mut self,
        x: &mut i32,
        max_x: i32,
        baseline_y: i32,
        style: u8,
        s: &[u8],
        col: u8,
    ) {
        let ell_w = self
            .atlas
            .glyph(style, SYM_ELLIPSIS)
            .map(|(g, _)| g.advance_x as i32)
            .unwrap_or(14);
        let full_w = self.atlas.measure_ascii(style, s);
        if *x + full_w <= max_x {
            self.push_ascii(x, baseline_y, style, s, col);
            return;
        }
        let limit = (max_x - ell_w).max(*x);
        for &b in s {
            let id = AtlasView::ascii_glyph_id(b);
            let adv = self.atlas.glyph(style, id).map(|(g, _)| g.advance_x as i32).unwrap_or(0);
            if *x + adv > limit {
                break;
            }
            self.push_id(x, baseline_y, style, id, col);
        }
        self.push_id(x, baseline_y, style, SYM_ELLIPSIS, col);
    }

    #[inline]
    fn push_u32(&mut self, x: &mut i32, baseline_y: i32, style: u8, v: u32, col: u8) {
        let mut buf = [0u8; 12];
        let n = fmt_u32_ascii(v, &mut buf);
        self.push_ascii(x, baseline_y, style, &buf[..n], col);
    }

    fn push_right_aligned_ids(
        &mut self,
        right_x: i32,
        baseline_y: i32,
        style: u8,
        items: &[(u16, u8)],
    ) {
        let mut total_w = 0i32;
        for &(id, _) in items {
            if let Some((g, _)) = self.atlas.glyph(style, id) {
                total_w += g.advance_x as i32;
            }
        }
        let mut x = right_x - total_w;
        for &(id, col) in items {
            self.push_id(&mut x, baseline_y, style, id, col);
        }
    }
}

/// Small stack buffer to compose a right-aligned or centered mixed-color cell without allocating.
struct CellBuf {
    items: [(u16, u8); 72],
    len: usize,
}

impl CellBuf {
    fn new() -> Self {
        Self { items: [(0, 0); 72], len: 0 }
    }
    #[inline]
    fn id(&mut self, id: u16, col: u8) {
        if self.len < self.items.len() {
            self.items[self.len] = (id, col);
            self.len += 1;
        }
    }
    #[inline]
    fn ascii(&mut self, s: &[u8], col: u8) {
        for &b in s {
            self.id(AtlasView::ascii_glyph_id(b), col);
        }
    }
    #[inline]
    fn u32(&mut self, v: u32, col: u8) {
        let mut b = [0u8; 12];
        let n = fmt_u32_ascii(v, &mut b);
        self.ascii(&b[..n], col);
    }
    #[inline]
    fn deci(&mut self, v: i32, col: u8) {
        let mut b = [0u8; 16];
        let n = fmt_deci_ascii(v, &mut b);
        self.ascii(&b[..n], col);
    }
    #[inline]
    fn slice(&self) -> &[(u16, u8)] {
        &self.items[..self.len]
    }
}

fn push_speed(cell: &mut CellBuf, bps: u32, col: u8) {
    let kbps = bps / 1024;
    if kbps >= 1024 {
        let deci_mb = ((kbps as u64 * 10) / 1024) as i32;
        cell.deci(deci_mb, col);
        cell.ascii(b"M", col);
    } else {
        cell.u32(kbps, col);
        cell.ascii(b"K", col);
    }
}

fn push_size_mb(cell: &mut CellBuf, kb: u32, col: u8) {
    if kb >= 1_048_576 {
        let dgb = ((kb as u64 * 10) / 1_048_576) as i32;
        cell.deci(dgb, col);
        cell.ascii(b"G", col);
    } else {
        cell.u32(kb / 1024, col);
        cell.ascii(b"M", col);
    }
}

// ── Widget 0: Classic ───────────────────────────────────────────────────────

fn layout_classic(
    atlas: &AtlasView<'_>,
    profile: &HudProfile,
    s: &SnapshotCopy,
    cmds: &mut [GlyphCmd; MAX_CMDS],
) -> (u32, u32, usize, BBox) {
    let f = profile.fields[WidgetId::Classic as usize];
    let has_fps = f & field::FPS != 0;
    let has_cpu = f & field::CPU != 0;
    let has_gpu = f & field::GPU != 0;
    let has_ram = f & field::RAM != 0;
    let has_net = f & field::NET != 0;
    let has_pwr = f & field::POWER != 0;
    let show_temp = f & field::TEMP != 0;

    let pad_x = 26i32;
    let pad_y = 20i32;
    let w = 368u32;
    let row_h = (atlas.line_height(STYLE_VALUE) as i32).max(30) + 6;
    let big_h = (atlas.line_height(STYLE_BIG) as i32).max(48) + 8;

    let mut rows = 0i32;
    if has_cpu { rows += 1; }
    if has_gpu { rows += 1; }
    if has_ram { rows += 1; }
    if has_net { rows += 1; }
    if has_pwr { rows += 1; }

    let h = ((pad_y * 2) + if has_fps { big_h } else { 0 } + rows * row_h).max(76) as u32;
    let mut rb = RunBuilder::new(atlas, cmds, w, h);
    let mut y = pad_y;
    let right_x = w as i32 - pad_x;

    if has_fps {
        let base = y + atlas.ascent(STYLE_BIG) as i32;
        let mut x = pad_x;
        let fps_int = (s.fps.current_x100 as u32 + 50) / 100;
        rb.push_u32(&mut x, base, STYLE_BIG, fps_int, COL_PRIMARY);
        rb.push_ascii(&mut x, base, STYLE_LABEL, b" fps", COL_VARIANT);
        y += big_h;
    }

    let val_asc = atlas.ascent(STYLE_VALUE) as i32;
    if has_cpu {
        let base = y + val_asc;
        let mut lx = pad_x;
        rb.push_ascii(&mut lx, base, STYLE_LABEL, b"CPU", COL_VARIANT);
        let mut c = CellBuf::new();
        c.u32((s.cpu.total_permille as u32 + 5) / 10, COL_ON_SURFACE);
        c.ascii(b"% ", COL_ON_SURFACE);
        c.id(SYM_MIDDOT, COL_VARIANT);
        c.ascii(b" ", COL_ON_SURFACE);
        c.deci((s.cpu.max_freq_khz / 100_000) as i32, COL_ON_SURFACE);
        c.ascii(b"G", COL_ON_SURFACE);
        if show_temp {
            let tcol = if s.thermal.cpu_deci_c >= HOT_SOC_DECI_C { COL_ERROR } else { COL_ON_SURFACE };
            c.ascii(b" ", COL_ON_SURFACE);
            c.id(SYM_MIDDOT, COL_VARIANT);
            c.ascii(b" ", COL_ON_SURFACE);
            c.u32(((s.thermal.cpu_deci_c.max(0) as u32) + 5) / 10, tcol);
            c.id(SYM_DEGREE, tcol);
        }
        rb.push_right_aligned_ids(right_x, base, STYLE_VALUE, c.slice());
        y += row_h;
    }

    if has_gpu {
        let base = y + val_asc;
        let mut lx = pad_x;
        rb.push_ascii(&mut lx, base, STYLE_LABEL, b"GPU", COL_VARIANT);
        let mut c = CellBuf::new();
        c.u32((s.gpu.busy_permille as u32 + 5) / 10, COL_ON_SURFACE);
        c.ascii(b"% ", COL_ON_SURFACE);
        c.id(SYM_MIDDOT, COL_VARIANT);
        c.ascii(b" ", COL_ON_SURFACE);
        let mhz = if s.gpu.avg_mhz > 0 { s.gpu.avg_mhz } else { s.gpu.cur_mhz };
        c.u32(mhz as u32, COL_ON_SURFACE);
        c.ascii(b"M", COL_ON_SURFACE);
        if show_temp {
            let tcol = if s.thermal.gpu_deci_c >= HOT_SOC_DECI_C { COL_ERROR } else { COL_ON_SURFACE };
            c.ascii(b" ", COL_ON_SURFACE);
            c.id(SYM_MIDDOT, COL_VARIANT);
            c.ascii(b" ", COL_ON_SURFACE);
            c.u32(((s.thermal.gpu_deci_c.max(0) as u32) + 5) / 10, tcol);
            c.id(SYM_DEGREE, tcol);
        }
        rb.push_right_aligned_ids(right_x, base, STYLE_VALUE, c.slice());
        y += row_h;
    }

    if has_ram {
        let base = y + val_asc;
        let mut lx = pad_x;
        rb.push_ascii(&mut lx, base, STYLE_LABEL, b"RAM", COL_VARIANT);
        let mut c = CellBuf::new();
        let used_dgb = ((s.mem.used_kb as u64 * 10) / 1_048_576) as i32;
        let tot_gb = ((s.mem.total_kb as u64 + 1_048_575) / 1_048_576) as u32;
        c.deci(used_dgb, COL_ON_SURFACE);
        c.ascii(b" / ", COL_VARIANT);
        c.u32(tot_gb, COL_ON_SURFACE);
        c.ascii(b"G", COL_VARIANT);
        rb.push_right_aligned_ids(right_x, base, STYLE_VALUE, c.slice());
        y += row_h;
    }

    if has_net {
        let base = y + val_asc;
        let mut lx = pad_x;
        rb.push_ascii(&mut lx, base, STYLE_LABEL, b"NET", COL_VARIANT);
        let mut c = CellBuf::new();
        c.id(SYM_DOWN, COL_PRIMARY);
        push_speed(&mut c, s.net.rx_bps, COL_ON_SURFACE);
        c.ascii(b" ", COL_ON_SURFACE);
        c.id(SYM_UP, COL_AMBER);
        push_speed(&mut c, s.net.tx_bps, COL_ON_SURFACE);
        rb.push_right_aligned_ids(right_x, base, STYLE_VALUE, c.slice());
        y += row_h;
    }

    if has_pwr {
        let base = y + val_asc;
        let mut lx = pad_x;
        rb.push_ascii(&mut lx, base, STYLE_LABEL, b"PWR", COL_VARIANT);
        let mut c = CellBuf::new();
        let deci_w = ((s.power.power_mw + 50) / 100) as i32;
        c.deci(deci_w, COL_ON_SURFACE);
        c.ascii(b"W", COL_VARIANT);
        rb.push_right_aligned_ids(right_x, base, STYLE_VALUE, c.slice());
    }

    (w, h, rb.len, rb.bbox)
}

// ── Widget 1: Ultra-Compact Top-Docked Mini Bar (y = 0, customizable) ───────

fn layout_mini(
    atlas: &AtlasView<'_>,
    profile: &HudProfile,
    s: &SnapshotCopy,
    cmds: &mut [GlyphCmd; MAX_CMDS],
) -> (u32, u32, usize, BBox) {
    let f = profile.fields[WidgetId::Mini as usize];
    let pad_x = 16i32;
    // Ultra-sleek 34 px bezel-hugging bar: fits comfortably above punch-hole camera (y=45) in
    // portrait and sits razor-thin flush at y=0 in landscape.
    let h = 34u32;
    let base = 23i32;

    let mut cell = CellBuf::new();
    let mut first = true;
    let push_sep = |c: &mut CellBuf, first: &mut bool| {
        if !*first {
            c.ascii(b" ", COL_VARIANT);
            c.id(SYM_MIDDOT, COL_VARIANT);
            c.ascii(b" ", COL_VARIANT);
        }
        *first = false;
    };

    if f & field::FPS != 0 {
        push_sep(&mut cell, &mut first);
        cell.u32((s.fps.current_x100 as u32 + 50) / 100, COL_PRIMARY);
    }
    if f & field::CPU != 0 {
        push_sep(&mut cell, &mut first);
        cell.ascii(b"C", COL_VARIANT);
        cell.u32((s.cpu.total_permille as u32 + 5) / 10, COL_ON_SURFACE);
        cell.ascii(b"%", COL_ON_SURFACE);
    }
    if f & field::GPU != 0 {
        push_sep(&mut cell, &mut first);
        cell.ascii(b"G", COL_VARIANT);
        cell.u32((s.gpu.busy_permille as u32 + 5) / 10, COL_ON_SURFACE);
        cell.ascii(b"%", COL_ON_SURFACE);
    }
    if f & field::TEMP != 0 {
        push_sep(&mut cell, &mut first);
        let tcol = if s.thermal.cpu_deci_c >= HOT_SOC_DECI_C { COL_ERROR } else { COL_ON_SURFACE };
        cell.u32(((s.thermal.cpu_deci_c.max(0) as u32) + 5) / 10, tcol);
        cell.id(SYM_DEGREE, tcol);
    }
    if f & field::POWER != 0 {
        push_sep(&mut cell, &mut first);
        cell.deci(((s.power.power_mw + 50) / 100) as i32, COL_PRIMARY);
        cell.ascii(b"W", COL_VARIANT);
    }
    if f & field::RAM != 0 {
        push_sep(&mut cell, &mut first);
        let used_dgb = ((s.mem.used_kb as u64 * 10) / 1_048_576) as i32;
        cell.ascii(b"R", COL_VARIANT);
        cell.deci(used_dgb, COL_ON_SURFACE);
        cell.ascii(b"G", COL_VARIANT);
    }
    if f & field::NET != 0 {
        push_sep(&mut cell, &mut first);
        let ncol = if (s.net.link_type & LINK_CELL) != 0 && (s.net.link_type & LINK_WIFI) == 0 {
            COL_TERTIARY
        } else {
            COL_PRIMARY
        };
        cell.id(SYM_DOWN, ncol);
        push_speed(&mut cell, s.net.rx_bps, COL_ON_SURFACE);
    }
    if f & field::BATTERY != 0 {
        push_sep(&mut cell, &mut first);
        cell.u32(s.power.capacity_pct as u32, COL_TERTIARY);
        cell.ascii(b"%", COL_VARIANT);
    }

    // Measure exact pixel run width and bucket to 24 px so GraphicBuffer rarely reallocates
    // while keeping text perfectly centered with crisp symmetric margins.
    let mut content_w = 0i32;
    for &(id, _) in cell.slice() {
        if let Some((g, _)) = atlas.glyph(STYLE_MICRO, id) {
            content_w += g.advance_x as i32;
        }
    }
    let raw_w = (content_w + pad_x * 2).max(96) as u32;
    let w = (((raw_w + 23) / 24) * 24).clamp(120, 760);

    let mut rb = RunBuilder::new(atlas, cmds, w, h);
    let mut x = ((w as i32 - content_w) / 2).max(pad_x / 2);
    for &(id, col) in cell.slice() {
        rb.push_id(&mut x, base, STYLE_MICRO, id, col);
    }

    (w, h, rb.len, rb.bbox)
}

// ── Widget 2: Scene-Style Material You Processes / Threads Monitor ──────────

#[allow(clippy::too_many_arguments)]
fn layout_processes(
    atlas: &AtlasView<'_>,
    profile: &HudProfile,
    s: &SnapshotCopy,
    icon_cache: &IconCache,
    palette: &[Rgba; 6],
    cmds: &mut [GlyphCmd; MAX_CMDS],
    rects: &mut [RectCmd; MAX_RECTS],
    rlen: &mut usize,
    icons: &mut [IconCmd; MAX_ICONS],
    ilen: &mut usize,
) -> (u32, u32, usize, BBox) {
    let f = profile.fields[WidgetId::Processes as usize];
    let show_threads = f & field::THREADS != 0;
    let show_sys = f & field::SYSTEM_PROCS != 0;

    let pad_x = 22i32;
    let pad_y = 18i32;
    let w = 440u32;
    let hdr_h = 36i32;
    let row_h = 44i32;
    let max_rows = 6usize;

    let mut picked = [0usize; 6];
    let mut n = 0usize;
    let count = (s.procs.count as usize).min(s.procs.rows.len());
    for i in 0..count {
        if n >= max_rows {
            break;
        }
        let r = &s.procs.rows[i];
        if show_threads || show_sys || r.is_system == 0 {
            picked[n] = i;
            n += 1;
        }
    }

    // Stable 6-row card height (346 px) avoids DMA-BUF realloc churn as active process count
    // fluctuates and keeps the drag hitbox aligned pixel-for-pixel.
    let h = (pad_y * 2 + hdr_h + 10 + (max_rows as i32) * row_h) as u32;
    let mut rb = RunBuilder::new(atlas, cmds, w, h);
    let right_x = w as i32 - pad_x;

    // Header: "Processes · All/Apps/Threads" + right-aligned "CPU xx%"
    let hdr_base = pad_y + atlas.ascent(STYLE_LABEL) as i32;
    let mut hx = pad_x;
    rb.push_ascii(
        &mut hx,
        hdr_base,
        STYLE_LABEL,
        if show_threads { b"Threads " } else { b"Processes " },
        COL_ON_SURFACE,
    );
    rb.push_id(&mut hx, hdr_base, STYLE_LABEL, SYM_MIDDOT, COL_VARIANT);
    rb.push_ascii(
        &mut hx,
        hdr_base,
        STYLE_LABEL,
        if show_threads {
            b" Top"
        } else if show_sys {
            b" All"
        } else {
            b" Apps"
        },
        COL_PRIMARY,
    );

    let mut hc = CellBuf::new();
    hc.ascii(b"CPU ", COL_VARIANT);
    hc.u32((s.cpu.total_permille as u32 + 5) / 10, COL_ON_SURFACE);
    hc.ascii(b"%", COL_VARIANT);
    rb.push_right_aligned_ids(right_x, hdr_base, STYLE_MICRO, hc.slice());

    // Subtle 1-px header divider.
    if *rlen < MAX_RECTS {
        rects[*rlen] = RectCmd {
            x: pad_x as i16,
            y: (pad_y + hdr_h) as i16,
            w: (w as i32 - pad_x * 2) as u16,
            h: 2,
            rgba: [255, 255, 255, 24],
        };
        *rlen += 1;
    }

    let mut y = pad_y + hdr_h + 10;
    let asc = atlas.ascent(STYLE_LABEL) as i32;
    let p_col = palette[COL_PRIMARY as usize];
    let e_col = palette[COL_ERROR as usize];

    if n == 0 {
        let mut x = pad_x;
        rb.push_id(&mut x, y + asc, STYLE_LABEL, SYM_EMDASH, COL_VARIANT);
    } else {
        let text_x = pad_x + ICON_DIM as i32 + 12;
        let pct_reserve = 92;
        let name_max_x = right_x - pct_reserve;
        let bar_w = (right_x - text_x).max(40);

        for &idx in &picked[..n] {
            let r = &s.procs.rows[idx];
            let base = y + asc;
            let raw_name = s.procs.name_of(r);

            // 1) Icon: cached real 28×28 RGBA app icon OR prebaked Material You monochrome vector icon!
            let cached = if r.is_system != 2 { icon_cache.get(r.uid) } else { None };
            let mut drew_rgba = false;
            if let Some((_, Some(_))) = cached {
                if *ilen < MAX_ICONS {
                    icons[*ilen] = IconCmd {
                        x: pad_x as i16,
                        y: (y + 3) as i16,
                        uid: r.uid,
                    };
                    *ilen += 1;
                    drew_rgba = true;
                }
            }
            if !drew_rgba {
                let icon_sym = if r.is_system == 2 {
                    SYM_ICON_THREAD
                } else if raw_name == b"kernel"
                    || raw_name.starts_with(b"kworker")
                    || raw_name.starts_with(b"irq/")
                    || raw_name.starts_with(b"kswapd")
                {
                    SYM_ICON_KERNEL
                } else {
                    SYM_ICON_DAEMON
                };
                let icon_col = if r.is_system == 2 || icon_sym == SYM_ICON_KERNEL {
                    COL_PRIMARY
                } else {
                    COL_VARIANT
                };
                let mut ix = pad_x + 2;
                rb.push_id(&mut ix, y + 25, STYLE_LABEL, icon_sym, icon_col);
            }

            // 2) Friendly cached app label OR smart 1-line shortened process name + `…`!
            let mut short_buf = [0u8; 32];
            let display_name = match cached {
                Some((lbl, _)) if !lbl.is_empty() => lbl,
                _ => shorten_proc_name(raw_name, &mut short_buf),
            };
            let mut nx = text_x;
            rb.push_ascii_clipped(&mut nx, name_max_x, base, STYLE_LABEL, display_name, COL_ON_SURFACE);

            // 3) Right-aligned CPU % (`xx.x%`)
            let is_hot = r.cpu_permille >= 500;
            let pct_col = if is_hot { COL_ERROR } else { COL_ON_SURFACE };
            let mut c = CellBuf::new();
            c.deci(r.cpu_permille as i32, pct_col);
            c.ascii(b"%", COL_VARIANT);
            rb.push_right_aligned_ids(right_x, base, STYLE_LABEL, c.slice());

            // 4) 3-px utilization micro-bar (track + proportional fill)
            let bar_y = y + row_h - 8;
            if *rlen + 2 <= MAX_RECTS {
                rects[*rlen] = RectCmd {
                    x: text_x as i16,
                    y: bar_y as i16,
                    w: bar_w as u16,
                    h: 3,
                    rgba: [255, 255, 255, 22],
                };
                *rlen += 1;
                let fill_w = (((r.cpu_permille.min(1000) as i32) * bar_w) / 1000).max(4);
                let fc = if is_hot { e_col } else { p_col };
                rects[*rlen] = RectCmd {
                    x: text_x as i16,
                    y: bar_y as i16,
                    w: fill_w as u16,
                    h: 3,
                    rgba: [fc[0], fc[1], fc[2], 140],
                };
                *rlen += 1;
            }

            y += row_h;
        }
    }

    (w, h, rb.len, rb.bbox)
}

// ── Widget 3: Temperature ───────────────────────────────────────────────────

fn layout_temp(
    atlas: &AtlasView<'_>,
    profile: &HudProfile,
    s: &SnapshotCopy,
    cmds: &mut [GlyphCmd; MAX_CMDS],
) -> (u32, u32, usize, BBox) {
    let f = profile.fields[WidgetId::Temp as usize];
    let pad_x = 22i32;
    let gap = 18i32;
    let h = ((atlas.line_height(STYLE_VALUE) as i32) + 24).max(56) as u32;
    let base = (h as i32 - atlas.line_height(STYLE_VALUE) as i32) / 2 + atlas.ascent(STYLE_VALUE) as i32;

    let mut cells = 0u32;
    if f & field::CPU != 0 { cells += 1; }
    if f & field::GPU != 0 { cells += 1; }
    if f & field::BATTERY != 0 { cells += 1; }
    let w = (pad_x as u32 * 2 + cells.max(1) * 144).min(520);

    let mut rb = RunBuilder::new(atlas, cmds, w, h);
    let mut x = pad_x;

    let mut emit_temp = |lbl: &[u8], deci_c: i16, hot: i16| {
        let tcol = if deci_c >= hot { COL_ERROR } else { COL_ON_SURFACE };
        rb.push_ascii(&mut x, base, STYLE_LABEL, lbl, COL_VARIANT);
        rb.push_u32(&mut x, base, STYLE_VALUE, ((deci_c.max(0) as u32) + 5) / 10, tcol);
        rb.push_id(&mut x, base, STYLE_VALUE, SYM_DEGREE, tcol);
        x += gap;
    };

    if f & field::CPU != 0 {
        emit_temp(b"CPU ", s.thermal.cpu_deci_c, HOT_SOC_DECI_C);
    }
    if f & field::GPU != 0 {
        emit_temp(b"GPU ", s.thermal.gpu_deci_c, HOT_SOC_DECI_C);
    }
    if f & field::BATTERY != 0 {
        emit_temp(b"BAT ", s.thermal.bat_deci_c, HOT_BAT_DECI_C);
    }

    (w, h, rb.len, rb.bbox)
}

// ── Widget 4: Unified Network Monitor (1-Grafik Wi-Fi + Mobile Data + RTT) ──

fn layout_network(
    atlas: &AtlasView<'_>,
    s: &SnapshotCopy,
    cmds: &mut [GlyphCmd; MAX_CMDS],
    graph: &mut NetGraphState,
) -> (u32, u32, usize, BBox) {
    let pad_x = 22i32;
    let pad_y = 18i32;
    let w = 440u32;
    let graph_h = 104u16;
    let hdr_h = 34i32;
    let foot_h = 34i32;
    let h = (pad_y * 2 + hdr_h + 10 + graph_h as i32 + 12 + foot_h) as u32;

    let mut rb = RunBuilder::new(atlas, cmds, w, h);
    let right_x = w as i32 - pad_x;

    // 1) Header: transport label + signal dBm (left) | passive RTT ± jitter (right)
    let hdr_base = pad_y + atlas.ascent(STYLE_LABEL) as i32;
    let mut lx = pad_x;
    let lt = s.net.link_type;
    let has_wifi = (lt & LINK_WIFI) != 0;
    let has_cell = (lt & LINK_CELL) != 0;
    let has_vpn = (lt & LINK_VPN) != 0;

    if has_wifi && has_cell {
        rb.push_ascii(&mut lx, hdr_base, STYLE_LABEL, b"Wi-Fi+Cell", COL_PRIMARY);
    } else if has_wifi {
        let lbl: &[u8] = match s.net.wifi_standard {
            7 => b"Wi-Fi 7",
            6 => b"Wi-Fi 6",
            5 => b"Wi-Fi 5",
            _ => b"Wi-Fi",
        };
        rb.push_ascii(&mut lx, hdr_base, STYLE_LABEL, lbl, COL_PRIMARY);
        if s.net.wifi_rssi_dbm < 0 {
            rb.push_ascii(&mut lx, hdr_base, STYLE_MICRO, b" ", COL_VARIANT);
            rb.push_ascii(&mut lx, hdr_base, STYLE_MICRO, b"-", COL_VARIANT);
            rb.push_u32(&mut lx, hdr_base, STYLE_MICRO, s.net.wifi_rssi_dbm.unsigned_abs() as u32, COL_VARIANT);
            rb.push_ascii(&mut lx, hdr_base, STYLE_MICRO, b"dBm", COL_VARIANT);
        }
    } else if has_cell {
        let lbl: &[u8] = match s.net.cell_gen {
            6 => b"5G+",
            5 => b"5G NR",
            4 => b"4G LTE",
            3 => b"3G",
            _ => b"Mobile",
        };
        rb.push_ascii(&mut lx, hdr_base, STYLE_LABEL, lbl, COL_TERTIARY);
        if s.net.cell_rsrp_dbm < 0 {
            rb.push_ascii(&mut lx, hdr_base, STYLE_MICRO, b" -", COL_VARIANT);
            rb.push_u32(&mut lx, hdr_base, STYLE_MICRO, s.net.cell_rsrp_dbm.unsigned_abs() as u32, COL_VARIANT);
            rb.push_ascii(&mut lx, hdr_base, STYLE_MICRO, b"dBm", COL_VARIANT);
        }
    } else if (lt & LINK_ETH) != 0 {
        rb.push_ascii(&mut lx, hdr_base, STYLE_LABEL, b"Ethernet", COL_PRIMARY);
    } else {
        rb.push_ascii(&mut lx, hdr_base, STYLE_LABEL, b"Network", COL_VARIANT);
    }
    if has_vpn {
        rb.push_ascii(&mut lx, hdr_base, STYLE_MICRO, b" VPN", COL_AMBER);
    }

    // Right: passive RTT & jitter
    let mut rc = CellBuf::new();
    let rtt_ms = s.net.tcp_rtt_us / 1000;
    let jit_ms = s.net.tcp_rttvar_us / 1000;
    if rtt_ms > 0 {
        let rcol = if rtt_ms >= 120 { COL_ERROR } else { COL_PRIMARY };
        rc.u32(rtt_ms, rcol);
        rc.ascii(b"ms ", COL_VARIANT);
        rc.id(SYM_PLUSMINUS, COL_VARIANT);
        rc.u32(jit_ms, COL_VARIANT);
    } else {
        rc.id(SYM_EMDASH, COL_VARIANT);
        rc.ascii(b" ms", COL_VARIANT);
    }
    rb.push_right_aligned_ids(right_x, hdr_base, STYLE_MICRO, rc.slice());

    // 2) Populate 48-sample Unified Network Graph (oldest -> newest)
    let gy = pad_y + hdr_h + 10;
    let gw = (w as i32 - pad_x * 2) as u16;
    let len = (s.hist.net_len as usize).min(NET_GRAPH_SAMPLES).min(METRIC_HIST_LEN);
    let head = s.hist.net_head as usize;
    let mut peak = 64u32;

    graph.active = true;
    graph.x = pad_x as i16;
    graph.y = gy as i16;
    graph.w = gw;
    graph.h = graph_h;
    graph.count = len as u16;

    for i in 0..len {
        let ring_idx = (head + METRIC_HIST_LEN - len + i) % METRIC_HIST_LEN;
        let wr = s.hist.net_wifi_rx_kbps[ring_idx];
        let cr = s.hist.net_cell_rx_kbps[ring_idx];
        let tx = s.hist.net_tx_kbps[ring_idx];
        graph.wifi_rx[i] = wr;
        graph.cell_rx[i] = cr;
        graph.tx[i] = tx;
        peak = peak.max(wr.saturating_add(cr)).max(tx);
    }
    graph.max_kbps = peak;

    // Peak label inside top-left of graph
    let mut px = pad_x + 8;
    let py = gy + atlas.ascent(STYLE_MICRO) as i32 + 4;
    let mut pc = CellBuf::new();
    push_speed(&mut pc, peak.saturating_mul(1024), COL_VARIANT);
    for &(id, col) in pc.slice() {
        rb.push_id(&mut px, py, STYLE_MICRO, id, col);
    }

    // 3) Footer: live ↓/↑ speeds (left) | session W / M breakdown (right)
    let foot_base = gy + graph_h as i32 + 12 + atlas.ascent(STYLE_LABEL) as i32;
    let mut fx = pad_x;
    rb.push_id(&mut fx, foot_base, STYLE_LABEL, SYM_DOWN, COL_PRIMARY);
    let mut dl = CellBuf::new();
    push_speed(&mut dl, s.net.rx_bps, COL_ON_SURFACE);
    for &(id, col) in dl.slice() {
        rb.push_id(&mut fx, foot_base, STYLE_LABEL, id, col);
    }
    fx += 14;
    rb.push_id(&mut fx, foot_base, STYLE_LABEL, SYM_UP, COL_AMBER);
    let mut ul = CellBuf::new();
    push_speed(&mut ul, s.net.tx_bps, COL_ON_SURFACE);
    for &(id, col) in ul.slice() {
        rb.push_id(&mut fx, foot_base, STYLE_LABEL, id, col);
    }

    let mut sc = CellBuf::new();
    sc.ascii(b"W ", COL_PRIMARY);
    push_size_mb(&mut sc, s.net.wifi_session_kb, COL_VARIANT);
    sc.ascii(b" ", COL_VARIANT);
    sc.id(SYM_MIDDOT, COL_VARIANT);
    sc.ascii(b" M ", COL_TERTIARY);
    push_size_mb(&mut sc, s.net.cell_session_kb, COL_VARIANT);
    rb.push_right_aligned_ids(right_x, foot_base, STYLE_MICRO, sc.slice());

    (w, h, rb.len, rb.bbox)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dirty_check_skips_unchanged_and_renders_ping_pong_cleanly() {
        let mut comp = HudCompositor::new();
        let mut prof = HudProfile::default();
        prof.enabled_mask = (1 << WidgetId::Classic as u8)
            | (1 << WidgetId::Mini as u8)
            | (1 << WidgetId::Processes as u8)
            | (1 << WidgetId::Network as u8);

        let mut snap = SnapshotCopy::default();
        snap.fps.current_x100 = 12000;
        snap.cpu.total_permille = 420;
        snap.cpu.max_freq_khz = 2_800_000;
        snap.gpu.busy_permille = 680;
        snap.gpu.avg_mhz = 763;
        snap.thermal.cpu_deci_c = 450;
        snap.thermal.gpu_deci_c = 410;
        snap.mem.used_kb = 6_291_456;
        snap.mem.total_kb = 12_582_912;
        snap.net.link_type = LINK_WIFI | LINK_CELL | LINK_VPN;
        snap.net.wifi_rx_bps = 4_200_000;
        snap.net.cell_rx_bps = 1_100_000;
        snap.net.rx_bps = 5_300_000;
        snap.net.tx_bps = 620_000;
        snap.net.tcp_rtt_us = 18_000;
        snap.net.tcp_rttvar_us = 2_000;
        for i in 0..24 {
            snap.hist.push_net(2000 + i * 80, if i > 12 { 900 + i * 40 } else { 0 }, 400, 18);
        }
        snap.procs.push(10100, 1234, 642, 420_000, false, b"com.mobile.legends");
        comp.put_uid_meta(10100, b"Mobile Legends", &[0xcc; ICON_DIM * ICON_DIM * 4]);

        // Classic ping-pong dirty check
        let p0 = comp.plan_widget(WidgetId::Classic as usize, true, &prof, &snap);
        assert!(p0.enabled && p0.needs_redraw);
        let stride = p0.w as usize + 16;
        let mut buf0 = vec![0u8; stride * (p0.h as usize) * 4];
        let mut buf1 = vec![0u8; stride * (p0.h as usize) * 4];
        comp.render_widget(WidgetId::Classic as usize, &mut buf0, stride, 0);
        let p1 = comp.plan_widget(WidgetId::Classic as usize, true, &prof, &snap);
        assert!(!p1.needs_redraw);

        snap.fps.current_x100 = 9000;
        let p2 = comp.plan_widget(WidgetId::Classic as usize, true, &prof, &snap);
        assert!(p2.needs_redraw);
        comp.render_widget(WidgetId::Classic as usize, &mut buf1, stride, 1);
        assert_ne!(buf0, buf1);

        // Mini must be flush top-docked at y = 0!
        let pm = comp.plan_widget(WidgetId::Mini as usize, true, &prof, &snap);
        assert!(pm.enabled && pm.y == 0 && pm.h <= 44);
        let mut mbuf = vec![0u8; (pm.w as usize) * (pm.h as usize) * 4];
        comp.render_widget(WidgetId::Mini as usize, &mut mbuf, pm.w as usize, 0);

        // Processes with cached icon + micro-bar
        let pp = comp.plan_widget(WidgetId::Processes as usize, true, &prof, &snap);
        assert!(pp.enabled && pp.needs_redraw);
        let mut pbuf = vec![0u8; (pp.w as usize) * (pp.h as usize) * 4];
        comp.render_widget(WidgetId::Processes as usize, &mut pbuf, pp.w as usize, 0);

        // Unified Network 1-Grafik
        let pn = comp.plan_widget(WidgetId::Network as usize, true, &prof, &snap);
        assert!(pn.enabled && pn.needs_redraw);
        let mut nbuf = vec![0u8; (pn.w as usize) * (pn.h as usize) * 4];
        comp.render_widget(WidgetId::Network as usize, &mut nbuf, pn.w as usize, 0);
        assert!(nbuf.iter().any(|&b| b != 0));
    }
}
