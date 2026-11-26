// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: Apache-2.0

//! `pulih-sim` — Host desktop renderer & 120 Hz frame-time benchmark for `pulih-gfx`.
//!
//! Renders full `1280×2772` `onyx` frames offline, benchmarks ms/frame against
//! the `SPEC-0051` §7 hard budget, and optionally dumps a `.ppm` preview.

use pulih_gfx::i18n::Locale;
use pulih_gfx::monet::Palette;
use pulih_gfx::widgets::{render_home_screen, StatusSnapshot};
use pulih_gfx::Surface;
use std::env;
use std::fs;
use std::time::Instant;

fn main() {
    let args: Vec<String> = env::args().collect();
    let out_path = args.get(1).map(|s| s.as_str());
    let frames: usize = args
        .get(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or(10);

    let mut surf = Surface::new(1280, 2772);
    let pal = Palette::default_yasvara();
    let status = StatusSnapshot::default();

    let t0 = Instant::now();
    for i in 0..frames {
        let phase = i as f32 * 0.25;
        let prog = (i as f32 / frames.max(1) as f32).clamp(0.0, 1.0);
        render_home_screen(&mut surf, &pal, &status, Locale::EnUs, phase, Some(prog));
    }
    let elapsed = t0.elapsed();
    let ms_per_frame = elapsed.as_secs_f64() * 1000.0 / frames as f64;
    println!(
        "pulih-sim: {}x{} x {} frames in {:.2} ms ({:.2} ms/frame, budget <= 8.33 ms @ 120 Hz)",
        surf.width,
        surf.height,
        frames,
        elapsed.as_secs_f64() * 1000.0,
        ms_per_frame
    );

    if let Some(path) = out_path {
        fs::write(path, surf.to_ppm()).expect("write ppm");
        println!("pulih-sim: wrote preview to {path}");
    }
}
