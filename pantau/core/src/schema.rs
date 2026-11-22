// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: Apache-2.0

//! Single source of truth for consumer masks, sampling cadences and the `pentas_hud` profile.

/// Bitmask of active metric domains requested by HUD widgets, open panel cards or Jejak.
pub mod mask {
    pub const NONE: u64 = 0;
    pub const CPU: u64 = 1 << 0;
    pub const GPU: u64 = 1 << 1;
    pub const THERMAL: u64 = 1 << 2;
    pub const MEM: u64 = 1 << 3;
    pub const POWER: u64 = 1 << 4;
    pub const DISPLAY: u64 = 1 << 5;
    pub const NET: u64 = 1 << 6;
    pub const FPS: u64 = 1 << 7;
    pub const PSI: u64 = 1 << 8;
    pub const PROCS: u64 = 1 << 9;
    pub const SCHED: u64 = 1 << 10;
    pub const IO: u64 = 1 << 11;
    pub const GPUMEM: u64 = 1 << 12;
    pub const THREADS: u64 = 1 << 13;

    /// Lightweight baseline when Pentas panel home tiles are open.
    pub const PANEL_HOME: u64 = CPU | GPU | THERMAL | MEM | POWER | DISPLAY | FPS | NET | PROCS;
    /// Full set needed while Jejak Tier 1 is recording.
    pub const JEJAK_T1: u64 =
        CPU | GPU | THERMAL | MEM | POWER | DISPLAY | NET | FPS | PSI | SCHED | IO | GPUMEM;
}

/// After-game HUD lifecycle policy persisted inside `Settings.Secure pentas_hud`.
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum AfterGamePolicy {
    /// Close HUD when leaving game, remember exact layout for next session.
    Close = 0,
    /// Keep HUD pinned after game until toggled off (QS tile) or screen off (if configured).
    Keep = 1,
    /// Keep HUD pinned for `sec` seconds after game exit, then return to `Off`.
    KeepTimer = 2,
}

#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum WidgetId {
    Classic = 0,
    Mini = 1,
    Processes = 2,
    Temp = 3,
    Network = 4,
}

pub const WIDGET_COUNT: usize = 5;

/// Top-edge docking mode for [`WidgetId::Mini`].
pub mod mini_anchor {
    pub const TOP_CENTER: u8 = 0; // y = 0, centered (default: flush against top bezel!)
    pub const TOP_LEFT: u8 = 1;   // y = 0, left-aligned
    pub const TOP_RIGHT: u8 = 2;  // y = 0, right-aligned
    pub const FREE: u8 = 3;       // user-dragged free position
}

/// Field enable bits per widget.
pub mod field {
    pub const FPS: u16 = 1 << 0;
    pub const CPU: u16 = 1 << 1;
    pub const GPU: u16 = 1 << 2;
    pub const RAM: u16 = 1 << 3;
    pub const TEMP: u16 = 1 << 4;
    pub const NET: u16 = 1 << 5;
    pub const BATTERY: u16 = 1 << 6;
    pub const SYSTEM_PROCS: u16 = 1 << 7;
    pub const POWER: u16 = 1 << 8;
    pub const THREADS: u16 = 1 << 9;
}

/// Saved position for portrait (0) and landscape (1) rotations.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct WidgetPos {
    pub x_port: i16,
    pub y_port: i16,
    pub x_land: i16,
    pub y_land: i16,
}

/// Complete persisted HUD configuration (`Settings.Secure pentas_hud`).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct HudProfile {
    pub enabled_mask: u8, // bit i = WidgetId i (0..=4)
    pub fields: [u16; WIDGET_COUNT],
    pub pos: [WidgetPos; WIDGET_COUNT],
    pub opacity_u8: u8, // 77..=255 (30%..100%)
    pub mini_anchor: u8,
    pub policy: AfterGamePolicy,
    pub keep_sec: u32,
    pub show_in_capture: bool,
    pub close_on_screen_off: bool,
}

impl Default for HudProfile {
    fn default() -> Self {
        Self {
            enabled_mask: 0,
            fields: [
                // Classic
                field::FPS | field::CPU | field::GPU | field::RAM | field::TEMP | field::NET,
                // Mini (y=0 top-docked bar, user-customizable across all fields!)
                field::FPS | field::CPU | field::GPU | field::TEMP,
                // Processes (0 = Apps only, SYSTEM_PROCS = All, THREADS = foreground threads)
                field::SYSTEM_PROCS,
                // Temp
                field::CPU | field::GPU | field::BATTERY,
                // Network (unified Wi-Fi + Mobile Data graph + passive RTT)
                field::NET,
            ],
            // Non-overlapping default layout anchors.
            pos: [
                WidgetPos { x_port: 24, y_port: 108, x_land: 24, y_land: 48 },
                WidgetPos { x_port: 0, y_port: 0, x_land: 0, y_land: 0 },
                WidgetPos { x_port: 420, y_port: 108, x_land: 420, y_land: 48 },
                WidgetPos { x_port: 900, y_port: 108, x_land: 2000, y_land: 48 },
                WidgetPos { x_port: 24, y_port: 440, x_land: 24, y_land: 260 },
            ],
            opacity_u8: 224, // ~88%
            mini_anchor: mini_anchor::TOP_CENTER,
            policy: AfterGamePolicy::Close,
            keep_sec: 300,
            show_in_capture: true,
            close_on_screen_off: true,
        }
    }
}

impl HudProfile {
    #[inline]
    pub fn any_enabled(&self) -> bool {
        self.enabled_mask != 0
    }

    #[inline]
    pub fn widget_enabled(&self, w: WidgetId) -> bool {
        (self.enabled_mask & (1u8 << (w as u8))) != 0
    }

    /// Computes the minimal [`mask`] bitset required to render all currently enabled HUD widgets.
    pub fn required_consumers(&self) -> u64 {
        let mut m = mask::NONE;
        if self.widget_enabled(WidgetId::Classic) {
            let f = self.fields[WidgetId::Classic as usize];
            if f & field::FPS != 0 { m |= mask::FPS; }
            if f & field::CPU != 0 { m |= mask::CPU; }
            if f & field::GPU != 0 { m |= mask::GPU; }
            if f & field::RAM != 0 { m |= mask::MEM; }
            if f & field::TEMP != 0 { m |= mask::THERMAL; }
            if f & field::NET != 0 { m |= mask::NET; }
            if f & field::POWER != 0 { m |= mask::POWER; }
        }
        if self.widget_enabled(WidgetId::Mini) {
            let f = self.fields[WidgetId::Mini as usize];
            if f & field::FPS != 0 { m |= mask::FPS; }
            if f & field::CPU != 0 { m |= mask::CPU; }
            if f & field::GPU != 0 { m |= mask::GPU; }
            if f & field::RAM != 0 { m |= mask::MEM; }
            if f & field::TEMP != 0 { m |= mask::THERMAL; }
            if f & field::NET != 0 { m |= mask::NET; }
            if f & (field::POWER | field::BATTERY) != 0 { m |= mask::POWER; }
        }
        if self.widget_enabled(WidgetId::Processes) {
            let f = self.fields[WidgetId::Processes as usize];
            m |= mask::CPU;
            if f & field::THREADS != 0 {
                m |= mask::THREADS;
            } else {
                m |= mask::PROCS;
            }
        }
        if self.widget_enabled(WidgetId::Temp) {
            let f = self.fields[WidgetId::Temp as usize];
            if f & (field::CPU | field::GPU | field::BATTERY) != 0 {
                m |= mask::THERMAL;
            }
            if f & field::BATTERY != 0 {
                m |= mask::POWER;
            }
        }
        if self.widget_enabled(WidgetId::Network) {
            m |= mask::NET;
        }
        m
    }

    /// Parses compact key=value profile string (`v=1;en=1;op=224;ma=0;pol=keep:300;f0=63;p0=...`).
    /// Never fails or allocates; malformed keys fall back to defaults.
    pub fn parse(raw: &[u8]) -> Self {
        let mut out = Self::default();
        if raw.is_empty() {
            return out;
        }
        for part in raw.split(|&b| b == b';' || b == b'\n') {
            let Some(eq) = part.iter().position(|&b| b == b'=') else {
                continue;
            };
            let k = &part[..eq];
            let v = &part[eq + 1..];
            match k {
                b"en" => {
                    if let Some(n) = parse_u32_ascii(v) {
                        out.enabled_mask = (n & 0x1f) as u8;
                    }
                }
                b"op" => {
                    if let Some(n) = parse_u32_ascii(v) {
                        out.opacity_u8 = n.clamp(77, 255) as u8;
                    }
                }
                b"ma" => {
                    if let Some(n) = parse_u32_ascii(v) {
                        out.mini_anchor = (n as u8).min(mini_anchor::FREE);
                    }
                }
                b"cap" => out.show_in_capture = v == b"1",
                b"soff" => out.close_on_screen_off = v == b"1",
                b"pol" => {
                    if v == b"close" {
                        out.policy = AfterGamePolicy::Close;
                    } else if v == b"keep" {
                        out.policy = AfterGamePolicy::Keep;
                    } else if let Some(rest) = v.strip_prefix(b"keep:") {
                        if let Some(sec) = parse_u32_ascii(rest) {
                            out.policy = AfterGamePolicy::KeepTimer;
                            out.keep_sec = sec.clamp(10, 86_400);
                        }
                    }
                }
                b"f0" | b"f1" | b"f2" | b"f3" | b"f4" => {
                    let idx = (k[1] - b'0') as usize;
                    if let Some(n) = parse_u32_ascii(v) {
                        out.fields[idx] = n as u16;
                    }
                }
                b"p0" | b"p1" | b"p2" | b"p3" | b"p4" => {
                    let idx = (k[1] - b'0') as usize;
                    let mut nums = [0i16; 4];
                    let mut count = 0;
                    for tok in v.split(|&b| b == b',') {
                        if count >= 4 {
                            break;
                        }
                        if let Some(n) = parse_i32_ascii(tok) {
                            nums[count] = n.clamp(i16::MIN as i32, i16::MAX as i32) as i16;
                            count += 1;
                        }
                    }
                    if count == 4 {
                        out.pos[idx] = WidgetPos {
                            x_port: nums[0],
                            y_port: nums[1],
                            x_land: nums[2],
                            y_land: nums[3],
                        };
                    }
                }
                _ => {}
            }
        }
        out
    }

    /// Serializes into caller's stack buffer with zero heap allocation. Returns bytes written.
    pub fn format_into(&self, dst: &mut [u8]) -> usize {
        let mut w = BufWriter::new(dst);
        w.bytes(b"v=1;en=");
        w.u32(self.enabled_mask as u32);
        w.bytes(b";op=");
        w.u32(self.opacity_u8 as u32);
        w.bytes(b";ma=");
        w.u32(self.mini_anchor as u32);
        w.bytes(b";cap=");
        w.byte(if self.show_in_capture { b'1' } else { b'0' });
        w.bytes(b";soff=");
        w.byte(if self.close_on_screen_off { b'1' } else { b'0' });
        w.bytes(b";pol=");
        match self.policy {
            AfterGamePolicy::Close => w.bytes(b"close"),
            AfterGamePolicy::Keep => w.bytes(b"keep"),
            AfterGamePolicy::KeepTimer => {
                w.bytes(b"keep:");
                w.u32(self.keep_sec);
            }
        }
        for i in 0..WIDGET_COUNT {
            w.bytes(b";f");
            w.byte(b'0' + i as u8);
            w.byte(b'=');
            w.u32(self.fields[i] as u32);
            let p = self.pos[i];
            w.bytes(b";p");
            w.byte(b'0' + i as u8);
            w.byte(b'=');
            w.i32(p.x_port as i32);
            w.byte(b',');
            w.i32(p.y_port as i32);
            w.byte(b',');
            w.i32(p.x_land as i32);
            w.byte(b',');
            w.i32(p.y_land as i32);
        }
        w.pos
    }
}

fn parse_u32_ascii(b: &[u8]) -> Option<u32> {
    if b.is_empty() {
        return None;
    }
    let mut acc = 0u32;
    for &c in b {
        if !c.is_ascii_digit() {
            return None;
        }
        acc = acc.checked_mul(10)?.checked_add((c - b'0') as u32)?;
    }
    Some(acc)
}

fn parse_i32_ascii(b: &[u8]) -> Option<i32> {
    if let Some(rest) = b.strip_prefix(b"-") {
        let mag = parse_u32_ascii(rest)?;
        i32::try_from(mag).ok().map(|x| -x)
    } else {
        parse_u32_ascii(b).and_then(|x| i32::try_from(x).ok())
    }
}

struct BufWriter<'a> {
    dst: &'a mut [u8],
    pos: usize,
}

impl<'a> BufWriter<'a> {
    fn new(dst: &'a mut [u8]) -> Self {
        Self { dst, pos: 0 }
    }
    fn byte(&mut self, b: u8) {
        if self.pos < self.dst.len() {
            self.dst[self.pos] = b;
            self.pos += 1;
        }
    }
    fn bytes(&mut self, s: &[u8]) {
        let n = s.len().min(self.dst.len().saturating_sub(self.pos));
        self.dst[self.pos..self.pos + n].copy_from_slice(&s[..n]);
        self.pos += n;
    }
    fn u32(&mut self, mut v: u32) {
        if v == 0 {
            self.byte(b'0');
            return;
        }
        let mut tmp = [0u8; 10];
        let mut n = 0;
        while v > 0 {
            tmp[n] = b'0' + (v % 10) as u8;
            v /= 10;
            n += 1;
        }
        while n > 0 {
            n -= 1;
            self.byte(tmp[n]);
        }
    }
    fn i32(&mut self, v: i32) {
        if v < 0 {
            self.byte(b'-');
            self.u32(v.unsigned_abs());
        } else {
            self.u32(v as u32);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hud_profile_round_trip_and_consumers() {
        let mut p = HudProfile::default();
        p.enabled_mask = (1 << WidgetId::Mini as u8) | (1 << WidgetId::Network as u8);
        p.mini_anchor = mini_anchor::TOP_LEFT;
        p.fields[WidgetId::Mini as usize] = field::FPS | field::CPU | field::GPU | field::POWER | field::NET;
        p.opacity_u8 = 190;
        p.policy = AfterGamePolicy::KeepTimer;
        p.keep_sec = 600;
        p.show_in_capture = true;
        p.pos[WidgetId::Network as usize] = WidgetPos { x_port: 12, y_port: 340, x_land: 56, y_land: 78 };

        let mut buf = [0u8; 320];
        let n = p.format_into(&mut buf);
        let parsed = HudProfile::parse(&buf[..n]);
        assert_eq!(parsed, p);

        let m = parsed.required_consumers();
        assert_eq!(m, mask::FPS | mask::CPU | mask::GPU | mask::POWER | mask::NET);
    }

    #[test]
    fn hud_profile_handles_corrupt_input() {
        let p = HudProfile::parse(b"en=999;op=5;ma=99;pol=keep:1;f0=abc;p0=1,2;garbage");
        assert_eq!(p.enabled_mask, 999u32 as u8 & 0x1f);
        assert_eq!(p.opacity_u8, 77); // clamped to min 30%
        assert_eq!(p.mini_anchor, mini_anchor::FREE); // clamped
        assert_eq!(p.keep_sec, 10);   // clamped to min 10s
    }
}
