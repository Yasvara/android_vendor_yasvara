// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: Apache-2.0

//! A plausible satellite view to accompany simulated fixes: multi-constellation, slowly
//! drifting geometry, signal strength that follows elevation.

use crate::rng::Rng;

pub const GPS: u8 = 1;
pub const GLONASS: u8 = 3;
pub const QZSS: u8 = 4;
pub const BEIDOU: u8 = 5;
pub const GALILEO: u8 = 6;

const L1_HZ: f32 = 1_575_420_000.0;
const L5_HZ: f32 = 1_176_450_000.0;
const B1I_HZ: f32 = 1_561_098_000.0;
/// GLONASS FDMA: each satellite transmits on 1602 MHz + k * 562.5 kHz.
const G1_BASE_HZ: f64 = 1_602_000_000.0;
const G1_STEP_HZ: f64 = 562_500.0;
/// Frequency channel by orbital slot; antipodal pairs share one.
const GLONASS_FCN: [i8; 24] = [
    1, -4, 5, 6, 1, -4, 5, 6, -2, -7, 0, -1, -2, -7, 0, -1, 4, -3, 3, 2, 4, -3, 3, 2,
];
const MASK_DEG: f64 = 7.0;
const HORIZON_DIP_DEG: f64 = 30.0;

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct SatView {
    pub constellation: u8,
    pub svid: u16,
    pub cn0: f32,
    pub elevation: f32,
    pub azimuth: f32,
    pub carrier_hz: f32,
    pub used_in_fix: bool,
}

#[derive(Clone, Debug)]
struct Orbit {
    constellation: u8,
    svid: u16,
    carrier_hz: f32,
    az0: f64,
    el_peak: f64,
    phase: f64,
    /// Radians of pass phase per second; 0 for a geostationary satellite.
    rate: f64,
    az_rate: f64,
    cn0_bias: f64,
}

#[derive(Clone, Debug)]
pub struct Sky {
    orbits: Vec<Orbit>,
    rng: Rng,
}

impl Sky {
    /// A full constellation set, as a multi-band receiver near the equator in Asia tracks it.
    pub fn new(seed: u64) -> Sky {
        let mut rng = Rng::new(seed ^ 0x5A7E_11);
        let mut orbits = Vec::new();
        let medium = |rng: &mut Rng, constellation: u8, svid: u16, carrier_hz: f32| Orbit {
            constellation,
            svid,
            carrier_hz,
            az0: rng.range(0.0, 360.0),
            el_peak: rng.range(30.0, 88.0),
            phase: rng.range(-core::f64::consts::PI, core::f64::consts::PI),
            rate: rng.range(1.0, 1.6) * core::f64::consts::PI / (5.5 * 3600.0),
            az_rate: rng.range(-0.004, 0.004),
            cn0_bias: rng.range(-3.0, 3.0),
        };
        let parked = |rng: &mut Rng, constellation: u8, svid: u16, carrier_hz: f32, el: (f64, f64)| Orbit {
            constellation,
            svid,
            carrier_hz,
            az0: rng.range(0.0, 360.0),
            el_peak: rng.range(el.0, el.1),
            phase: 0.0,
            rate: 0.0,
            az_rate: rng.range(-0.0005, 0.0005),
            cn0_bias: rng.range(-2.0, 2.0),
        };
        for svid in 1..=31 {
            orbits.push(medium(&mut rng, GPS, svid, L1_HZ));
        }
        for svid in 1..=24u16 {
            let hz = G1_BASE_HZ + GLONASS_FCN[svid as usize - 1] as f64 * G1_STEP_HZ;
            orbits.push(medium(&mut rng, GLONASS, svid, hz as f32));
        }
        for svid in [1, 2, 3, 4, 5, 7, 8, 9, 10, 11, 12, 13, 15, 19, 21, 24, 25, 26, 27, 30, 31, 33, 34, 36] {
            orbits.push(medium(&mut rng, GALILEO, svid, L1_HZ));
        }
        // BeiDou GEO and IGSO satellites sit over Asia and stay up all day.
        for svid in [1, 2, 3, 4, 5, 59, 60] {
            orbits.push(parked(&mut rng, BEIDOU, svid, B1I_HZ, (25.0, 80.0)));
        }
        for svid in [6, 7, 8, 9, 10, 13, 16, 38, 39, 40] {
            orbits.push(parked(&mut rng, BEIDOU, svid, B1I_HZ, (15.0, 75.0)));
        }
        for svid in (19..=37).chain(41..=46) {
            orbits.push(medium(&mut rng, BEIDOU, svid, B1I_HZ));
        }
        for svid in [193, 194, 195, 199] {
            orbits.push(parked(&mut rng, QZSS, svid, L1_HZ, (10.0, 60.0)));
        }
        // Second band: L5 on newer GPS blocks and QZSS, E5a on Galileo, B1C/B2a on BeiDou-3.
        let mut extra = Vec::new();
        for o in &orbits {
            let (chance, hz, loss) = match o.constellation {
                GPS => (0.35, L5_HZ, 2.0),
                GALILEO => (0.3, L5_HZ, 2.5),
                QZSS => (1.0, L5_HZ, 2.0),
                BEIDOU if o.svid >= 19 && o.rate != 0.0 => (0.2, if rng.range(0.0, 1.0) < 0.5 { L5_HZ } else { L1_HZ }, 3.0),
                _ => continue,
            };
            if rng.range(0.0, 1.0) < chance {
                extra.push(Orbit { carrier_hz: hz, cn0_bias: o.cn0_bias - loss, ..o.clone() });
            }
        }
        orbits.extend(extra);
        Sky { orbits, rng }
    }

    /// Satellites above the mask at `now_ns`; at most `max_used` are flagged as in the fix.
    pub fn view(&mut self, now_ns: i64, max_used: usize) -> Vec<SatView> {
        let t = now_ns as f64 / 1e9;
        let mut out: Vec<SatView> = Vec::with_capacity(self.orbits.len());
        for o in &self.orbits {
            let p = o.phase + o.rate * t;
            // Each pass rises and sets on a cosine; wrap so the sky never empties.
            let wrapped = ((p + core::f64::consts::PI) % (2.0 * core::f64::consts::PI)) - core::f64::consts::PI;
            // The horizon cuts each pass below its midpoint, so a medium orbit is up about a third
            // of the time; a parked satellite holds its elevation.
            let el = if o.rate == 0.0 {
                o.el_peak
            } else {
                (o.el_peak + HORIZON_DIP_DEG) * wrapped.cos() - HORIZON_DIP_DEG
            };
            if el < MASK_DEG {
                continue;
            }
            let az = (o.az0 + o.az_rate * t * 57.3 + wrapped * 40.0).rem_euclid(360.0);
            let cn0 = (20.0 + 0.26 * el + o.cn0_bias + self.rng.gauss() * 0.8).clamp(12.0, 48.0);
            out.push(SatView {
                constellation: o.constellation,
                svid: o.svid,
                cn0: cn0 as f32,
                elevation: el as f32,
                azimuth: az as f32,
                carrier_hz: o.carrier_hz,
                used_in_fix: false,
            });
        }
        let mut order: Vec<usize> = (0..out.len()).collect();
        order.sort_by(|&a, &b| out[b].cn0.total_cmp(&out[a].cn0));
        for &i in order.iter().take(max_used) {
            if out[i].cn0 >= 22.0 {
                out[i].used_in_fix = true;
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sky_is_plausible_all_day() {
        for seed in 0..32 {
            let mut sky = Sky::new(seed);
            check_day(&mut sky);
        }
    }

    fn check_day(sky: &mut Sky) {
        for minute in (0..(24 * 60)).step_by(3) {
            let v = sky.view(minute * 60 * 1_000_000_000, 28);
            let used = v.iter().filter(|s| s.used_in_fix).count();
            assert!((45..=100).contains(&v.len()), "{} visible at minute {minute}", v.len());
            assert!((14..=28).contains(&used), "{used} used at minute {minute}");
            for s in &v {
                assert!((MASK_DEG as f32..=90.0).contains(&s.elevation));
                if s.constellation == GLONASS {
                    assert!((1_598e6..1_606e6).contains(&s.carrier_hz));
                }
                assert!((0.0..360.0).contains(&s.azimuth));
                assert!(s.svid >= 1);
            }
        }
    }

    #[test]
    fn geometry_drifts_slowly() {
        let mut sky = Sky::new(3);
        let a = sky.view(0, 14);
        let b = sky.view(1_000_000_000, 14);
        for s in &a {
            if let Some(t) = b.iter().find(|t| t.svid == s.svid && t.constellation == s.constellation && t.carrier_hz == s.carrier_hz) {
                assert!((s.elevation - t.elevation).abs() < 0.1);
            }
        }
    }
}
