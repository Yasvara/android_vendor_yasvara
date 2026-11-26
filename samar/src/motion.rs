// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: Apache-2.0

//! A simulated receiver position: a pinned point that the joystick can move, with the noise,
//! accuracy and dynamics of a real phone fix.

use crate::geo;
use crate::rng::Rng;

/// Joystick speed presets, metres per second at full deflection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Speed {
    Walk = 0,
    Run = 1,
    Bike = 2,
    Car = 3,
}

impl Speed {
    pub fn from_u8(v: u8) -> Speed {
        match v {
            1 => Speed::Run,
            2 => Speed::Bike,
            3 => Speed::Car,
            _ => Speed::Walk,
        }
    }

    pub fn mps(self) -> f64 {
        match self {
            Speed::Walk => 1.4,
            Speed::Run => 3.0,
            Speed::Bike => 6.0,
            Speed::Car => 14.0,
        }
    }

    /// Acceleration limit, m/s².
    fn accel(self) -> f64 {
        match self {
            Speed::Walk | Speed::Run => 1.5,
            Speed::Bike => 1.2,
            Speed::Car => 2.5,
        }
    }
}

/// Which provider a fix is shaped for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Source {
    Gnss = 0,
    Network = 1,
    Fused = 2,
}

impl Source {
    pub fn from_u8(v: u8) -> Source {
        match v {
            1 => Source::Network,
            2 => Source::Fused,
            _ => Source::Gnss,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Fix {
    pub lat: f64,
    pub lng: f64,
    pub altitude: Option<f64>,
    pub accuracy: f32,
    pub vertical_accuracy: Option<f32>,
    pub speed: Option<f32>,
    pub speed_accuracy: Option<f32>,
    pub bearing: Option<f32>,
    pub bearing_accuracy: Option<f32>,
}

/// Position noise is an Ornstein-Uhlenbeck process: correlated drift around the true point,
/// which is how a real receiver's error behaves between fixes.
const JITTER_TAU_S: f64 = 8.0;
const JITTER_SIGMA_M: f64 = 1.6;

#[derive(Clone, Debug)]
pub struct Walker {
    pub lat: f64,
    pub lng: f64,
    pub altitude: f64,
    pub speed_preset: Speed,
    joy_x: f64,
    joy_y: f64,
    speed: f64,
    heading: f64,
    jitter_n: f64,
    jitter_e: f64,
    jitter_up: f64,
    net_n: f64,
    net_e: f64,
    net_extra_acc: f64,
    speed_noise: f64,
    bearing_noise: f64,
    accuracy: f64,
    last_ns: Option<i64>,
    rng: Rng,
}

impl Walker {
    pub fn new(lat: f64, lng: f64, altitude: f64, seed: u64) -> Walker {
        let mut rng = Rng::new(seed);
        let accuracy = rng.range(3.5, 5.5);
        Walker {
            lat,
            lng,
            altitude,
            speed_preset: Speed::Walk,
            joy_x: 0.0,
            joy_y: 0.0,
            speed: 0.0,
            heading: rng.range(0.0, 360.0),
            jitter_n: 0.0,
            jitter_e: 0.0,
            jitter_up: 0.0,
            net_n: 0.0,
            net_e: 0.0,
            net_extra_acc: 6.0,
            speed_noise: 0.0,
            bearing_noise: 0.0,
            accuracy,
            last_ns: None,
            rng,
        }
    }

    /// Moves the pin. Returns the speed in m/s this jump implies since the last step, or 0 when
    /// there is no previous step.
    pub fn place(&mut self, lat: f64, lng: f64, now_ns: i64) -> f64 {
        let implied = match self.last_ns {
            Some(last) if now_ns > last => {
                geo::distance(self.lat, self.lng, lat, lng) / ((now_ns - last) as f64 / 1e9).max(1.0)
            }
            _ => 0.0,
        };
        self.lat = lat;
        self.lng = lng;
        self.speed = 0.0;
        self.jitter_n = 0.0;
        self.jitter_e = 0.0;
        implied
    }

    /// Joystick deflection; x east, y north, each in [-1, 1].
    pub fn set_joystick(&mut self, x: f64, y: f64) {
        let (x, y) = (x.clamp(-1.0, 1.0), y.clamp(-1.0, 1.0));
        let m = (x * x + y * y).sqrt();
        let scale = if m > 1.0 { 1.0 / m } else { 1.0 };
        self.joy_x = x * scale;
        self.joy_y = y * scale;
    }

    pub fn joystick(&self) -> (f64, f64) {
        (self.joy_x, self.joy_y)
    }

    pub fn is_moving(&self) -> bool {
        self.speed > 0.05 || self.joy_x != 0.0 || self.joy_y != 0.0
    }

    pub fn speed(&self) -> f64 {
        self.speed
    }

    pub fn heading(&self) -> f64 {
        self.heading
    }

    /// Advances the simulation to `now_ns` (CLOCK_BOOTTIME).
    pub fn step(&mut self, now_ns: i64) {
        let dt = match self.last_ns {
            Some(last) => ((now_ns - last) as f64 / 1e9).clamp(0.0, 5.0),
            None => 0.0,
        };
        self.last_ns = Some(now_ns);
        if dt <= 0.0 {
            return;
        }
        let deflection = (self.joy_x * self.joy_x + self.joy_y * self.joy_y).sqrt();
        let target = self.speed_preset.mps() * deflection;
        let dv = (target - self.speed).clamp(-self.speed_preset.accel() * dt, self.speed_preset.accel() * dt);
        self.speed = (self.speed + dv).max(0.0);
        if deflection > 0.0 {
            let wanted = self.joy_x.atan2(self.joy_y).to_degrees().rem_euclid(360.0);
            // Turn rate limit keeps the track smooth when the stick swings.
            let diff = ((wanted - self.heading + 540.0) % 360.0) - 180.0;
            let max_turn = 120.0 * dt;
            self.heading = (self.heading + diff.clamp(-max_turn, max_turn)).rem_euclid(360.0);
        }
        if self.speed > 0.0 {
            let (lat, lng) = geo::destination(self.lat, self.lng, self.heading, self.speed * dt);
            self.lat = lat;
            self.lng = lng;
        }
        let decay = (-dt / JITTER_TAU_S).exp();
        let spread = JITTER_SIGMA_M * (1.0 - decay * decay).sqrt();
        self.jitter_n = self.jitter_n * decay + spread * self.rng.gauss();
        self.jitter_e = self.jitter_e * decay + spread * self.rng.gauss();
        self.jitter_up = self.jitter_up * decay + 1.5 * spread * self.rng.gauss();
        // Network fixes wander more slowly and further: a cell/Wi-Fi solution changes in jumps.
        let net_decay = (-dt / 30.0).exp();
        let net_spread = 6.0 * (1.0 - net_decay * net_decay).sqrt();
        self.net_n = self.net_n * net_decay + net_spread * self.rng.gauss();
        self.net_e = self.net_e * net_decay + net_spread * self.rng.gauss();
        self.net_extra_acc = (self.net_extra_acc * net_decay + (1.0 - net_decay) * self.rng.range(0.0, 12.0)).clamp(0.0, 12.0);
        self.speed_noise = self.rng.gauss() * 0.15;
        self.bearing_noise = self.rng.gauss() * 2.0;
        let target_acc = 4.0 + 1.2 * self.rng.gauss().abs();
        self.accuracy = (self.accuracy + (target_acc - self.accuracy) * (dt / 10.0).min(1.0)).clamp(3.0, 8.0);
    }

    /// The fix a provider of `source` would report at the current step. Every client and every
    /// call within a step sees the same values, as with one real receiver.
    pub fn fix(&self, source: Source) -> Fix {
        let (lat, lng) = geo::offset(self.lat, self.lng, self.jitter_n, self.jitter_e);
        let moving = self.speed > 0.3;
        match source {
            Source::Network => {
                let (lat, lng) = geo::offset(lat, lng, self.net_n, self.net_e);
                Fix {
                    lat,
                    lng,
                    altitude: None,
                    accuracy: (self.accuracy * 4.0 + self.net_extra_acc) as f32,
                    ..Fix::default()
                }
            }
            Source::Gnss | Source::Fused => {
                let speed_noise = if moving { self.speed_noise } else { 0.0 };
                let speed = (self.speed + speed_noise).max(0.0);
                Fix {
                    lat,
                    lng,
                    altitude: Some(self.altitude + self.jitter_up),
                    accuracy: self.accuracy as f32,
                    vertical_accuracy: Some((self.accuracy * 1.6) as f32),
                    speed: Some(if moving { speed as f32 } else { 0.0 }),
                    speed_accuracy: Some(if moving { 0.5 } else { 0.3 }),
                    bearing: moving.then(|| (self.heading + self.bearing_noise).rem_euclid(360.0) as f32),
                    bearing_accuracy: moving.then_some(8.0),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const S: i64 = 1_000_000_000;

    #[test]
    fn same_step_same_fix() {
        let mut w = Walker::new(-7.25, 112.75, 5.0, 3);
        w.step(0);
        w.step(S);
        assert_eq!(w.fix(Source::Gnss), w.fix(Source::Fused));
        assert_eq!(w.fix(Source::Network), w.fix(Source::Network));
        let a = w.fix(Source::Gnss);
        w.step(2 * S);
        assert_ne!(a, w.fix(Source::Gnss));
    }

    #[test]
    fn stays_near_pin_when_idle() {
        let mut w = Walker::new(-7.25, 112.75, 5.0, 1);
        let mut worst: f64 = 0.0;
        for i in 0..3600 {
            w.step(i * S);
            let f = w.fix(Source::Gnss);
            worst = worst.max(geo::distance(-7.25, 112.75, f.lat, f.lng));
            assert!((3.0..=8.0).contains(&f.accuracy));
            assert_eq!(f.speed, Some(0.0));
            assert!(f.bearing.is_none());
        }
        assert!(worst < 12.0, "drifted {worst} m");
        assert!(worst > 0.5, "no noise at all");
    }

    #[test]
    fn walks_north_at_preset_speed() {
        let mut w = Walker::new(0.0, 0.0, 0.0, 2);
        w.set_joystick(0.0, 1.0);
        w.heading = 0.0;
        for i in 0..=100 {
            w.step(i * S);
        }
        let moved = geo::distance(0.0, 0.0, w.lat, w.lng);
        // 100 s at 1.4 m/s minus the ~1 s ramp.
        assert!((moved - 139.3).abs() < 2.0, "moved {moved}");
        assert!(w.lat > 0.0);
        let f = w.fix(Source::Gnss);
        assert!((f.speed.unwrap() - 1.4).abs() < 0.6);
        let b = f.bearing.unwrap();
        assert!(b < 10.0 || b > 350.0, "bearing {b}");
    }

    #[test]
    fn stops_with_deceleration() {
        let mut w = Walker::new(0.0, 0.0, 0.0, 3);
        w.speed_preset = Speed::Car;
        w.set_joystick(1.0, 0.0);
        for i in 0..20 {
            w.step(i * S);
        }
        assert!((w.speed() - 14.0).abs() < 1e-9);
        w.set_joystick(0.0, 0.0);
        w.step(20 * S);
        assert!(w.speed() > 10.0, "no instant stop");
        for i in 21..40 {
            w.step(i * S);
        }
        assert_eq!(w.speed(), 0.0);
    }

    #[test]
    fn place_reports_implied_speed() {
        let mut w = Walker::new(-7.25, 112.75, 0.0, 4);
        w.step(0);
        let v = w.place(-6.2, 106.8, 10 * S);
        assert!(v > 60_000.0, "{v}");
        assert_eq!(w.lat, -6.2);
    }

    #[test]
    fn network_fix_is_coarser() {
        let mut w = Walker::new(1.0, 1.0, 0.0, 5);
        w.step(0);
        w.step(S);
        let f = w.fix(Source::Network);
        assert!(f.accuracy >= 12.0);
        assert!(f.altitude.is_none() && f.speed.is_none());
    }

    #[test]
    fn joystick_is_clamped_to_unit_circle() {
        let mut w = Walker::new(0.0, 0.0, 0.0, 6);
        w.set_joystick(1.0, 1.0);
        let (x, y) = w.joystick();
        assert!(((x * x + y * y).sqrt() - 1.0).abs() < 1e-9);
    }
}
