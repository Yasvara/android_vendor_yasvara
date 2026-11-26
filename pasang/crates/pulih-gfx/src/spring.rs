// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: Apache-2.0

//! Critically-damped M3 Expressive spring physics with exact settle detection
//! so `Pulih` drops cleanly to 0 FPS / 0% CPU once motion completes.

#[derive(Clone, Copy, Debug)]
pub struct SpringConfig {
    pub stiffness: f32,
    pub damping: f32,
    pub epsilon: f32,
}

impl SpringConfig {
    /// M3 Expressive fast-spatial (card press, pill indicator, checkbox).
    pub const EXPRESSIVE_FAST: Self = Self {
        stiffness: 1400.0,
        damping: 68.0,
        epsilon: 0.001,
    };

    /// M3 Expressive standard-spatial (bottom sheet rise, tab transitions).
    pub const EXPRESSIVE_SPATIAL: Self = Self {
        stiffness: 520.0,
        damping: 42.0,
        epsilon: 0.001,
    };

    /// Gentle deceleration for scroll overscroll rebound.
    pub const SCROLL_REBOUND: Self = Self {
        stiffness: 320.0,
        damping: 36.0,
        epsilon: 0.05,
    };
}

#[derive(Clone, Copy, Debug)]
pub struct Spring {
    pub value: f32,
    pub velocity: f32,
    pub target: f32,
    pub config: SpringConfig,
}

impl Spring {
    pub const fn new(initial: f32, config: SpringConfig) -> Self {
        Self {
            value: initial,
            velocity: 0.0,
            target: initial,
            config,
        }
    }

    pub fn set_target(&mut self, target: f32) {
        self.target = target;
    }

    pub fn snap(&mut self, v: f32) {
        self.value = v;
        self.target = v;
        self.velocity = 0.0;
    }

    #[inline]
    pub fn is_settled(&self) -> bool {
        (self.value - self.target).abs() <= self.config.epsilon
            && self.velocity.abs() <= self.config.epsilon * 10.0
    }

    /// Advance spring by `dt` seconds (clamped to `<= 0.05s` to stay unconditionally stable).
    /// Returns `true` if still moving (needs another frame).
    pub fn step(&mut self, dt: f32) -> bool {
        if self.is_settled() {
            self.value = self.target;
            self.velocity = 0.0;
            return false;
        }
        let dt = dt.clamp(0.0005, 0.05);
        // Sub-step at <= 4 ms for rock-solid numerical stability at any refresh rate (60..120Hz).
        let substeps = ((dt / 0.004).ceil() as u32).max(1);
        let h = dt / substeps as f32;
        for _ in 0..substeps {
            let force = (self.target - self.value) * self.config.stiffness
                - self.velocity * self.config.damping;
            self.velocity += force * h;
            self.value += self.velocity * h;
        }
        if self.is_settled() {
            self.value = self.target;
            self.velocity = 0.0;
            false
        } else {
            true
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spring_converges_and_settles_to_zero_fps() {
        let mut s = Spring::new(0.0, SpringConfig::EXPRESSIVE_FAST);
        s.set_target(1.0);
        let mut frames = 0;
        while s.step(1.0 / 120.0) {
            frames += 1;
            assert!(frames < 240, "spring failed to settle within 2 seconds");
        }
        assert!(s.is_settled());
        assert_eq!(s.value, 1.0);
        assert_eq!(s.velocity, 0.0);
        // Subsequent steps immediately report false (0 FPS idle).
        assert!(!s.step(1.0 / 120.0));
    }
}
