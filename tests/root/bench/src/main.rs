// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: Apache-2.0

//! Spawn-cost benchmark for SPEC-0006 §10: `bench N -- CMD A… -- CMD B…` runs the two commands
//! interleaved N times each (so drift in clocks, thermals and the scheduler hits both alike)
//! and prints p50/p90/p99/mean per command and the p50/mean overhead of the second over the
//! first.

use std::process::{Command, Stdio};
use std::time::Instant;

fn run(argv: &[String]) -> f64 {
    let t = Instant::now();
    let _ = Command::new(&argv[0])
        .args(&argv[1..])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    t.elapsed().as_secs_f64() * 1000.0
}

fn pct(v: &[f64], p: f64) -> f64 {
    v[(((v.len() - 1) as f64) * p).round() as usize]
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let n: usize = args.first().and_then(|s| s.parse().ok()).unwrap_or(200);
    let mut cmds: Vec<Vec<String>> = Vec::new();
    for a in args.iter().skip(1) {
        if a == "--" {
            cmds.push(Vec::new());
        } else if let Some(c) = cmds.last_mut() {
            c.push(a.clone());
        }
    }
    if cmds.len() != 2 || cmds.iter().any(|c| c.is_empty()) {
        eprintln!("usage: bench N -- CMD [ARG…] -- CMD [ARG…]");
        std::process::exit(2);
    }
    for c in &cmds {
        for _ in 0..10 {
            run(c); // warm the page cache and the governor
        }
    }
    let mut samples = [Vec::with_capacity(n), Vec::with_capacity(n)];
    for _ in 0..n {
        for (i, c) in cmds.iter().enumerate() {
            samples[i].push(run(c));
        }
    }
    let mut stats = [(0.0, 0.0); 2];
    for (i, s) in samples.iter_mut().enumerate() {
        s.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let mean = s.iter().sum::<f64>() / s.len() as f64;
        stats[i] = (pct(s, 0.5), mean);
        println!(
            "{:<28} p50 {:6.2}  p90 {:6.2}  p99 {:6.2}  mean {:6.2} ms",
            cmds[i].join(" "),
            pct(s, 0.5),
            pct(s, 0.9),
            pct(s, 0.99),
            mean
        );
    }
    println!("overhead: p50 {:+.2} ms, mean {:+.2} ms", stats[1].0 - stats[0].0, stats[1].1 - stats[0].1);
}
