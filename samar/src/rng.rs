// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: Apache-2.0

//! Small deterministic generator for fix noise and sky layout.

#[derive(Clone, Debug)]
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1)
    }

    /// xorshift64*.
    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    /// Uniform in [0, 1).
    pub fn unit(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64
    }

    pub fn range(&mut self, lo: f64, hi: f64) -> f64 {
        lo + (hi - lo) * self.unit()
    }

    /// Standard normal (Box-Muller).
    pub fn gauss(&mut self) -> f64 {
        let u = self.unit().max(1e-12);
        let v = self.unit();
        (-2.0 * u.ln()).sqrt() * (2.0 * core::f64::consts::PI * v).cos()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unit_stays_in_range_and_is_deterministic() {
        let mut a = Rng::new(7);
        let mut b = Rng::new(7);
        for _ in 0..10_000 {
            let x = a.unit();
            assert!((0.0..1.0).contains(&x));
            assert_eq!(x.to_bits(), b.unit().to_bits());
        }
    }

    #[test]
    fn gauss_has_unit_variance() {
        let mut r = Rng::new(42);
        let n = 200_000;
        let (mut s, mut s2) = (0.0, 0.0);
        for _ in 0..n {
            let g = r.gauss();
            s += g;
            s2 += g * g;
        }
        let mean = s / n as f64;
        let var = s2 / n as f64 - mean * mean;
        assert!(mean.abs() < 0.01, "mean {mean}");
        assert!((var - 1.0).abs() < 0.02, "var {var}");
    }
}
