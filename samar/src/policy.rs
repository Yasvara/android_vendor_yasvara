// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: Apache-2.0

//! Who sees which location: the global profile, per-app profiles, privacy layers, saved places,
//! and their persisted text form.

use crate::geo;
use crate::motion::{Fix, Source, Speed, Walker};
use crate::sky::{SatView, Sky};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt::Write as _;

/// Wi-Fi scan results, connected BSSID and cell identity.
pub const LAYER_RADIO: u32 = 1 << 0;
/// Bluetooth LE scan results.
pub const LAYER_BLE: u32 = 1 << 1;
/// Location in photo metadata.
pub const LAYER_MEDIA: u32 = 1 << 2;
/// Local network discovery (mDNS, SSDP, neighbour tables).
pub const LAYER_LAN: u32 = 1 << 3;
pub const LAYER_ALL: u32 = LAYER_RADIO | LAYER_BLE | LAYER_MEDIA | LAYER_LAN;

/// First uid of regular apps; lower appIds are platform components and always see the truth.
pub const FIRST_APPLICATION_UID: u32 = 10_000;
const MAX_USED_SATELLITES: usize = 28;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Mode {
    /// Use the global profile.
    Follow = 0,
    /// Always the real location.
    Real = 1,
    /// The app's own pin and joystick.
    Own = 2,
}

impl Mode {
    pub fn from_u8(v: u8) -> Mode {
        match v {
            1 => Mode::Real,
            2 => Mode::Own,
            _ => Mode::Follow,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Target<'a> {
    Real,
    Global,
    App(&'a str),
}

#[derive(Clone, Debug)]
struct Profile {
    walker: Walker,
    sky: Sky,
    has_place: bool,
    fixes: [Option<Fix>; 3],
    sats: Option<Vec<SatView>>,
}

impl Profile {
    fn new(lat: f64, lng: f64, altitude: f64, seed: u64) -> Profile {
        Profile {
            walker: Walker::new(lat, lng, altitude, seed),
            sky: Sky::new(seed),
            has_place: false,
            fixes: [None; 3],
            sats: None,
        }
    }

    fn step(&mut self, now_ns: i64) {
        self.walker.step(now_ns);
        self.fixes = [None; 3];
        self.sats = None;
    }

    /// One fix per source per step, so every client sees the same point.
    fn fix(&mut self, source: Source) -> Fix {
        let slot = source as usize;
        if let Some(f) = self.fixes[slot] {
            return f;
        }
        let f = self.walker.fix(source);
        self.fixes[slot] = Some(f);
        f
    }

    fn sats(&mut self, now_ns: i64) -> &[SatView] {
        if self.sats.is_none() {
            self.sats = Some(self.sky.view(now_ns, MAX_USED_SATELLITES));
        }
        self.sats.as_deref().unwrap_or(&[])
    }
}

#[derive(Clone, Debug)]
struct App {
    mode: Mode,
    profile: Profile,
    layer_mask: u32,
    layer_value: u32,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Place {
    pub name: String,
    pub lat: f64,
    pub lng: f64,
}

/// Live position of a profile, for the UI.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Position {
    pub lat: f64,
    pub lng: f64,
    pub altitude: f64,
    pub speed: f64,
    pub heading: f64,
    pub speed_preset: Speed,
    pub has_place: bool,
}

#[derive(Clone, Debug)]
pub struct Policy {
    global_on: bool,
    global: Profile,
    global_layers: u32,
    apps: BTreeMap<String, App>,
    bound: HashMap<u32, String>,
    exempt: HashSet<u32>,
    places: Vec<Place>,
    seed: u64,
}

impl Policy {
    pub fn new(seed: u64) -> Policy {
        Policy {
            global_on: false,
            global: Profile::new(0.0, 0.0, 0.0, seed),
            global_layers: 0,
            apps: BTreeMap::new(),
            bound: HashMap::new(),
            exempt: HashSet::new(),
            places: Vec::new(),
            seed,
        }
    }

    fn is_exempt(&self, app_id: u32) -> bool {
        app_id < FIRST_APPLICATION_UID || self.exempt.contains(&app_id)
    }

    /// Resolution order: emergency or exempt, then the app's own profile, then global, then real.
    pub fn resolve(&self, app_id: u32, emergency: bool) -> Target<'_> {
        if emergency || self.is_exempt(app_id) {
            return Target::Real;
        }
        if let Some(pkg) = self.bound.get(&app_id) {
            if let Some(app) = self.apps.get(pkg) {
                match app.mode {
                    Mode::Real => return Target::Real,
                    Mode::Own if app.profile.has_place => return Target::App(pkg.as_str()),
                    Mode::Own => return Target::Real,
                    Mode::Follow => {}
                }
            }
        }
        if self.global_on && self.global.has_place {
            Target::Global
        } else {
            Target::Real
        }
    }

    pub fn overrides(&self, app_id: u32, emergency: bool) -> bool {
        self.resolve(app_id, emergency) != Target::Real
    }

    fn profile_for(&mut self, app_id: u32, emergency: bool) -> Option<&mut Profile> {
        let pkg = match self.resolve(app_id, emergency) {
            Target::Real => return None,
            Target::Global => None,
            Target::App(pkg) => Some(pkg.to_owned()),
        };
        match pkg {
            None => Some(&mut self.global),
            Some(pkg) => self.apps.get_mut(&pkg).map(|a| &mut a.profile),
        }
    }

    pub fn fix(&mut self, app_id: u32, emergency: bool, source: Source) -> Option<Fix> {
        self.profile_for(app_id, emergency).map(|p| p.fix(source))
    }

    pub fn sky(&mut self, app_id: u32, emergency: bool, now_ns: i64) -> Option<Vec<SatView>> {
        self.profile_for(app_id, emergency).map(|p| p.sats(now_ns).to_vec())
    }

    /// Privacy layers in force for an app; independent of the location override.
    pub fn layers(&self, app_id: u32) -> u32 {
        if self.is_exempt(app_id) {
            return 0;
        }
        let base = self.global_layers;
        match self.bound.get(&app_id).and_then(|p| self.apps.get(p)) {
            Some(app) => (base & !app.layer_mask) | (app.layer_value & app.layer_mask),
            None => base,
        }
    }

    pub fn step(&mut self, now_ns: i64) {
        self.global.step(now_ns);
        for app in self.apps.values_mut() {
            if app.mode == Mode::Own {
                app.profile.step(now_ns);
            }
        }
    }

    /// Whether any client can currently receive a simulated location.
    pub fn active(&self) -> bool {
        (self.global_on && self.global.has_place)
            || self.apps.values().any(|a| a.mode == Mode::Own && a.profile.has_place)
    }

    pub fn layers_active(&self) -> bool {
        self.global_layers != 0 || self.apps.values().any(|a| a.layer_value & a.layer_mask != 0)
    }

    pub fn global_on(&self) -> bool {
        self.global_on
    }

    pub fn set_global_on(&mut self, on: bool) {
        self.global_on = on;
    }

    fn target_profile(&mut self, target: &str) -> &mut Profile {
        if target.is_empty() {
            return &mut self.global;
        }
        if !self.apps.contains_key(target) {
            let seed = self.seed ^ hash(target);
            let g = &self.global.walker;
            let mut profile = Profile::new(g.lat, g.lng, g.altitude, seed);
            profile.has_place = self.global.has_place;
            self.apps.insert(
                target.to_owned(),
                App { mode: Mode::Follow, profile, layer_mask: 0, layer_value: 0 },
            );
        }
        &mut self.apps.get_mut(target).expect("inserted").profile
    }

    /// Pins a target ("" is global) to a point. Returns the implied jump speed in m/s.
    pub fn place(&mut self, target: &str, lat: f64, lng: f64, now_ns: i64) -> Option<f64> {
        if !geo::valid(lat, lng) {
            return None;
        }
        let p = self.target_profile(target);
        p.has_place = true;
        p.fixes = [None; 3];
        Some(p.walker.place(lat, lng, now_ns))
    }

    pub fn set_altitude(&mut self, target: &str, altitude: f64) {
        if altitude.is_finite() {
            self.target_profile(target).walker.altitude = altitude.clamp(-500.0, 9000.0);
        }
    }

    pub fn set_joystick(&mut self, target: &str, x: f64, y: f64) {
        self.target_profile(target).walker.set_joystick(x, y);
    }

    pub fn set_speed(&mut self, target: &str, preset: Speed) {
        self.target_profile(target).walker.speed_preset = preset;
    }

    pub fn position(&self, target: &str) -> Option<Position> {
        let p = if target.is_empty() { &self.global } else { &self.apps.get(target)?.profile };
        let w = &p.walker;
        Some(Position {
            lat: w.lat,
            lng: w.lng,
            altitude: w.altitude,
            speed: w.speed(),
            heading: w.heading(),
            speed_preset: w.speed_preset,
            has_place: p.has_place,
        })
    }

    pub fn moving(&self) -> bool {
        (self.global_on && self.global.walker.is_moving())
            || self.apps.values().any(|a| a.mode == Mode::Own && a.profile.walker.is_moving())
    }

    pub fn mode(&self, pkg: &str) -> Mode {
        self.apps.get(pkg).map(|a| a.mode).unwrap_or(Mode::Follow)
    }

    pub fn set_mode(&mut self, pkg: &str, mode: Mode) {
        if pkg.is_empty() {
            return;
        }
        self.target_profile(pkg);
        if let Some(app) = self.apps.get_mut(pkg) {
            app.mode = mode;
        }
        self.prune(pkg);
    }

    /// For "" sets the global layers (`mask` ignored); for a package, overrides the bits in `mask`.
    pub fn set_layers(&mut self, target: &str, mask: u32, value: u32) {
        if target.is_empty() {
            self.global_layers = value & LAYER_ALL;
            return;
        }
        self.target_profile(target);
        if let Some(app) = self.apps.get_mut(target) {
            app.layer_mask = mask & LAYER_ALL;
            app.layer_value = value & mask & LAYER_ALL;
        }
        self.prune(target);
    }

    pub fn layer_override(&self, target: &str) -> (u32, u32) {
        if target.is_empty() {
            return (LAYER_ALL, self.global_layers);
        }
        self.apps.get(target).map(|a| (a.layer_mask, a.layer_value)).unwrap_or((0, 0))
    }

    /// Drops an app entry that no longer differs from the defaults.
    fn prune(&mut self, pkg: &str) {
        if let Some(app) = self.apps.get(pkg) {
            if app.mode == Mode::Follow && app.layer_mask == 0 {
                self.apps.remove(pkg);
            }
        }
    }

    /// Packages that carry their own mode or layer settings.
    pub fn configured_apps(&self) -> Vec<(String, Mode, u32, u32)> {
        self.apps.iter().map(|(k, a)| (k.clone(), a.mode, a.layer_mask, a.layer_value)).collect()
    }

    pub fn bind(&mut self, pkg: &str, app_id: u32) {
        self.bound.retain(|_, p| p != pkg);
        self.bound.insert(app_id, pkg.to_owned());
    }

    pub fn unbind(&mut self, pkg: &str) {
        self.bound.retain(|_, p| p != pkg);
    }

    pub fn set_exempt(&mut self, app_id: u32, exempt: bool) {
        if exempt {
            self.exempt.insert(app_id);
        } else {
            self.exempt.remove(&app_id);
        }
    }

    pub fn places(&self) -> &[Place] {
        &self.places
    }

    pub fn add_place(&mut self, name: &str, lat: f64, lng: f64) -> bool {
        let name: String = name.chars().filter(|c| !c.is_control()).collect::<String>().trim().to_owned();
        if name.is_empty() || !geo::valid(lat, lng) {
            return false;
        }
        self.places.retain(|p| p.name != name);
        self.places.push(Place { name, lat, lng });
        true
    }

    pub fn remove_place(&mut self, index: usize) -> bool {
        if index < self.places.len() {
            self.places.remove(index);
            true
        } else {
            false
        }
    }

    /// Persisted form. Joystick state and live motion are not kept.
    pub fn encode(&self) -> String {
        let mut s = String::from("samar 1\n");
        let g = &self.global.walker;
        let _ = writeln!(
            s,
            "global {} {} {:.7} {:.7} {:.1} {} {}",
            self.global_on as u8,
            self.global.has_place as u8,
            g.lat,
            g.lng,
            g.altitude,
            g.speed_preset as u8,
            self.global_layers
        );
        for (pkg, a) in &self.apps {
            let w = &a.profile.walker;
            let _ = writeln!(
                s,
                "app {} {} {} {:.7} {:.7} {:.1} {} {} {}",
                pkg,
                a.mode as u8,
                a.profile.has_place as u8,
                w.lat,
                w.lng,
                w.altitude,
                w.speed_preset as u8,
                a.layer_mask,
                a.layer_value
            );
        }
        for p in &self.places {
            let _ = writeln!(s, "place {:.7} {:.7} {}", p.lat, p.lng, p.name);
        }
        s
    }

    /// Restores settings onto this policy; bindings and exemptions are kept. Unknown or malformed
    /// lines are skipped so a damaged file degrades instead of failing.
    pub fn decode(&mut self, text: &str) -> bool {
        let mut lines = text.lines();
        if lines.next().map(str::trim) != Some("samar 1") {
            return false;
        }
        let mut fresh = Policy::new(self.seed);
        fresh.bound = std::mem::take(&mut self.bound);
        fresh.exempt = std::mem::take(&mut self.exempt);
        for line in lines {
            let f: Vec<&str> = line.split(' ').collect();
            match f.first().copied() {
                Some("global") if f.len() >= 8 => {
                    let (Some(lat), Some(lng), Some(alt)) = (num(f[3]), num(f[4]), num(f[5])) else { continue };
                    fresh.global_on = f[1] == "1";
                    if f[2] == "1" && geo::valid(lat, lng) {
                        fresh.global.walker.place(lat, lng, 0);
                        fresh.global.has_place = true;
                    }
                    fresh.global.walker.altitude = alt;
                    fresh.global.walker.speed_preset = Speed::from_u8(f[6].parse().unwrap_or(0));
                    fresh.global_layers = f[7].parse::<u32>().unwrap_or(0) & LAYER_ALL;
                }
                Some("app") if f.len() >= 10 && !f[1].is_empty() => {
                    let (Some(lat), Some(lng), Some(alt)) = (num(f[4]), num(f[5]), num(f[6])) else { continue };
                    let mut profile = Profile::new(lat, lng, alt, self.seed ^ hash(f[1]));
                    profile.has_place = f[3] == "1" && geo::valid(lat, lng);
                    profile.walker.speed_preset = Speed::from_u8(f[7].parse().unwrap_or(0));
                    let mask = f[8].parse::<u32>().unwrap_or(0) & LAYER_ALL;
                    let value = f[9].parse::<u32>().unwrap_or(0) & mask;
                    fresh.apps.insert(
                        f[1].to_owned(),
                        App { mode: Mode::from_u8(f[2].parse().unwrap_or(0)), profile, layer_mask: mask, layer_value: value },
                    );
                }
                Some("place") if f.len() >= 4 => {
                    if let (Some(lat), Some(lng)) = (num(f[1]), num(f[2])) {
                        fresh.add_place(&f[3..].join(" "), lat, lng);
                    }
                }
                _ => {}
            }
        }
        *self = fresh;
        true
    }

    pub fn dump(&self) -> String {
        let mut s = String::new();
        let g = &self.global.walker;
        let _ = writeln!(
            s,
            "global: on={} place={} {:.6},{:.6} alt={:.1} speed={:?} moving={} layers={:#x}",
            self.global_on,
            self.global.has_place,
            g.lat,
            g.lng,
            g.altitude,
            g.speed_preset,
            g.is_moving(),
            self.global_layers
        );
        for (pkg, a) in &self.apps {
            let w = &a.profile.walker;
            let _ = writeln!(
                s,
                "app {pkg}: mode={:?} place={} {:.6},{:.6} layers mask={:#x} value={:#x}",
                a.mode, a.profile.has_place, w.lat, w.lng, a.layer_mask, a.layer_value
            );
        }
        let _ = writeln!(s, "bound={} exempt={} places={}", self.bound.len(), self.exempt.len(), self.places.len());
        s
    }
}

fn num(s: &str) -> Option<f64> {
    s.parse::<f64>().ok().filter(|v| v.is_finite())
}

/// FNV-1a, for per-app seeds.
fn hash(s: &str) -> u64 {
    s.bytes().fold(0xcbf2_9ce4_8422_2325, |h, b| (h ^ b as u64).wrapping_mul(0x0100_0000_01b3))
}

#[cfg(test)]
mod tests {
    use super::*;

    const APP: u32 = 10_123;
    const OTHER: u32 = 10_200;

    fn policy() -> Policy {
        let mut p = Policy::new(1);
        p.bind("com.example.ride", APP);
        p.bind("com.example.chat", OTHER);
        p
    }

    #[test]
    fn real_until_global_has_a_place() {
        let mut p = policy();
        p.set_global_on(true);
        assert_eq!(p.resolve(APP, false), Target::Real);
        p.place("", -7.25, 112.75, 0).unwrap();
        assert_eq!(p.resolve(APP, false), Target::Global);
        assert!(p.active());
    }

    #[test]
    fn resolution_order() {
        let mut p = policy();
        p.place("", -7.25, 112.75, 0);
        p.set_global_on(true);
        p.place("com.example.ride", -6.2, 106.8, 0);
        p.set_mode("com.example.ride", Mode::Own);
        assert_eq!(p.resolve(APP, false), Target::App("com.example.ride"));
        assert_eq!(p.resolve(OTHER, false), Target::Global);
        assert_eq!(p.resolve(APP, true), Target::Real, "emergency wins");
        assert_eq!(p.resolve(1000, false), Target::Real, "platform uid");
        p.set_exempt(OTHER, true);
        assert_eq!(p.resolve(OTHER, false), Target::Real);
        p.set_mode("com.example.ride", Mode::Real);
        p.set_global_on(true);
        assert_eq!(p.resolve(APP, false), Target::Real);
        p.set_global_on(false);
        assert_eq!(p.resolve(10_999, false), Target::Real, "unbound app follows global (off)");
    }

    #[test]
    fn own_profile_starts_at_global_and_moves_alone() {
        let mut p = policy();
        p.place("", -7.25, 112.75, 0);
        p.set_global_on(true);
        p.set_mode("com.example.ride", Mode::Own);
        assert_eq!(p.resolve(APP, false), Target::App("com.example.ride"));
        p.set_joystick("com.example.ride", 0.0, 1.0);
        for i in 0..30 {
            p.step(i * 1_000_000_000);
        }
        let own = p.position("com.example.ride").unwrap();
        let global = p.position("").unwrap();
        assert!(geo::distance(own.lat, own.lng, global.lat, global.lng) > 20.0);
        assert!(p.moving());
    }

    #[test]
    fn same_fix_for_every_client_in_a_step() {
        let mut p = policy();
        p.place("", 1.0, 2.0, 0);
        p.set_global_on(true);
        p.step(1_000_000_000);
        let a = p.fix(APP, false, Source::Gnss).unwrap();
        let b = p.fix(OTHER, false, Source::Gnss).unwrap();
        assert_eq!(a, b);
        assert!(p.fix(1000, false, Source::Gnss).is_none());
        p.step(2_000_000_000);
        assert_ne!(p.fix(APP, false, Source::Gnss).unwrap(), a);
        assert!(p.sky(APP, false, 2_000_000_000).unwrap().len() >= 8);
    }

    #[test]
    fn layers_merge_global_and_app() {
        let mut p = policy();
        p.set_layers("", 0, LAYER_RADIO | LAYER_MEDIA);
        assert_eq!(p.layers(APP), LAYER_RADIO | LAYER_MEDIA);
        p.set_layers("com.example.ride", LAYER_RADIO | LAYER_BLE, LAYER_BLE);
        assert_eq!(p.layers(APP), LAYER_BLE | LAYER_MEDIA);
        assert_eq!(p.layers(OTHER), LAYER_RADIO | LAYER_MEDIA);
        assert_eq!(p.layers(1000), 0);
        assert!(p.layers_active());
    }

    #[test]
    fn default_entries_are_pruned() {
        let mut p = policy();
        p.set_mode("com.example.ride", Mode::Own);
        p.set_mode("com.example.ride", Mode::Follow);
        assert!(p.configured_apps().is_empty());
    }

    #[test]
    fn encode_decode_round_trip() {
        let mut p = policy();
        p.place("", -7.2575, 112.7521, 0);
        p.set_altitude("", 12.0);
        p.set_global_on(true);
        p.set_speed("", Speed::Bike);
        p.set_layers("", 0, LAYER_RADIO);
        p.place("com.example.ride", -6.2, 106.8, 0);
        p.set_mode("com.example.ride", Mode::Own);
        p.set_layers("com.example.chat", LAYER_MEDIA, LAYER_MEDIA);
        p.add_place("Rumah teman", -7.3, 112.7);
        let text = p.encode();
        let mut q = Policy::new(1);
        q.bind("com.example.ride", APP);
        assert!(q.decode(&text));
        assert_eq!(q.encode(), text);
        assert_eq!(q.resolve(APP, false), Target::App("com.example.ride"), "bindings survive decode");
        assert_eq!(q.places()[0].name, "Rumah teman");
        assert!(!q.decode("garbage"));
    }

    #[test]
    fn decode_skips_bad_lines() {
        let mut q = Policy::new(1);
        assert!(q.decode("samar 1\nglobal 1 1 nan 1 0 0 0\napp x 2 1 1 1\nplace 1 1 Ok\nwhat\n"));
        assert!(!q.active());
        assert_eq!(q.places().len(), 1);
    }

    #[test]
    fn rejects_invalid_points() {
        let mut p = policy();
        assert!(p.place("", 95.0, 0.0, 0).is_none());
        assert!(!p.add_place("x", 0.0, 200.0));
        assert!(!p.add_place("  ", 0.0, 0.0));
    }
}
