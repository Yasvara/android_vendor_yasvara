// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: Apache-2.0

//! `pantau_bench` — Speed & zero-allocation verification gate.
//!
//! Installs a custom counting `#[global_allocator]` so every hot path is verified for BOTH
//! latency budget AND **0 heap allocations**. Exits non-zero if any gate fails.
//!
//! Usage:
//!   pantau_bench            # synthetic hot-path gate (host & onyx)
//!   pantau_bench --live     # also benchmarks real `/proc` & `/sys` sampler ticks on device

use std::alloc::{GlobalAlloc, Layout, System};
use std::env;
use std::hint::black_box;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use pantau::abi::{Snapshot, SnapshotCopy};
use pantau::hud::layout::HudCompositor;
use pantau::hud::{blit_alpha8, fmt_deci_ascii, fmt_u32_ascii, render_rounded_bg, restore_dirty_rect};
use pantau::jejak::{crc32c, encode_dod_i64, LatencyHist};
use pantau::json::emit_snapshot;
use pantau::parse::{
    gpu_avg_mhz_from_trans, parse_cgroup_usage_usec, parse_gpu_busy_permille, parse_meminfo,
    parse_proc_stat, parse_psi, parse_trans_stat, parse_zram_mm_stat, GpuTransRaw, MemInfoRaw,
    ProcStatRaw, PsiRaw, ZramStatRaw,
};
use pantau::sampler::{Sampler, Scratch};
use pantau::schema::{mask, HudProfile, WidgetId};
use pantau::sys::boottime_ns;
use pantau_tap::wire::{FrameRec, RingKind};
use pantau_tap::{init_ring, RingConsumer, TapChannel, MODE_ALL};

struct CountingAlloc;
static ALLOC_COUNT: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for CountingAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOC_COUNT.fetch_add(1, Ordering::Relaxed);
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        ALLOC_COUNT.fetch_add(1, Ordering::Relaxed);
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static GLOBAL: CountingAlloc = CountingAlloc;

#[repr(align(64))]
struct AlignedRing([u8; 128 + 256 * 64]);

const FIX_PROC_STAT: &[u8] = b"\
cpu  245277 14111 130489 2200138 1721 0 1911 90 0 0\n\
cpu0 26511 2472 32837 253010 181 0 1759 42 0 0\n\
cpu1 24780 2775 27548 267643 164 0 63 20 0 0\n\
cpu2 42505 1523 9122 272151 204 0 21 11 0 0\n\
cpu3 43734 1523 9040 271404 183 0 16 2 0 0\n\
cpu4 44171 1464 9318 270879 199 0 13 2 0 0\n\
cpu5 26926 1393 20180 275902 130 0 12 4 0 0\n\
cpu6 27071 1448 19521 276445 153 0 16 3 0 0\n\
cpu7 9575 1509 2918 312700 504 0 7 2 0 0\n\
intr 26331913 0 14356684 574487 0 0 0 4847901 0 0 0 0 3927650 0 0 0 0 7 0 28 165832\n\
ctxt 39445279\n";

const FIX_MEMINFO: &[u8] = b"\
MemTotal:       11533688 kB\n\
MemFree:         1267780 kB\n\
MemAvailable:    4203040 kB\n\
Buffers:           10284 kB\n\
Cached:          4036840 kB\n\
SwapTotal:       6291452 kB\n\
SwapFree:        2160620 kB\n";

const FIX_TRANS_STAT: &[u8] = b"\
     From  :   To\n\
 1162000000:   0 3 0 0 0 0 0 0 0 0 0   1310\n\
 1150000000:   3 0 5 0 0 0 0 0 0 0 0   1353\n\
 1090000000:   0 5 0 6 0 0 0 0 0 0 0   2173\n\
  965000000:   0 0 6 0 8 0 0 0 0 0 0   2170\n\
  915000000:   0 0 0 8 0 10 0 0 0 0 0  3343\n\
  873000000:   0 0 0 0 10 0 11 0 2 0 0 16173\n\
  763000000:   0 0 0 0 0 13 0 30 0 0 0 15753\n\
  685000000:   0 0 0 0 0 0 32 0 24 0 0 73036\n\
* 515000000:   0 0 0 0 0 0 0 26 0 0 0 3162210\n";

const FIX_ZRAM: &[u8] = b"4227706880 1451463299 1525477376 0 1534267392 39039\n";
const FIX_PSI: &[u8] = b"some avg10=7.48 avg60=3.33 avg300=2.96 total=189308163\nfull avg10=0.18 avg60=0.06 avg300=0.06 total=5051824\n";
const FIX_CGROUP: &[u8] = b"usage_usec 236191\nuser_usec 113242\nsystem_usec 122948\n";

fn run_gate<F: FnMut()>(name: &str, iters: u64, budget_ns: u64, must_zero_alloc: bool, mut f: F) -> bool {
    // Warmup
    for _ in 0..iters.min(200) {
        f();
    }
    let a0 = ALLOC_COUNT.load(Ordering::Relaxed);
    let t0 = Instant::now();
    for _ in 0..iters {
        f();
    }
    let dt = t0.elapsed();
    let allocs = ALLOC_COUNT.load(Ordering::Relaxed) - a0;
    let per_ns = (dt.as_nanos() as u64) / iters.max(1);
    let ok = per_ns <= budget_ns && (!must_zero_alloc || allocs == 0);
    println!(
        "[{}] {:<28} {:>8} ns/op  (budget <= {:>7} ns)  allocs={}",
        if ok { "PASS" } else { "FAIL" },
        name,
        per_ns,
        budget_ns,
        allocs
    );
    ok
}

fn main() {
    let live = env::args().any(|a| a == "--live");
    let mut all_ok = true;

    // 1. Tap disarmed fast path (1 relaxed atomic load).
    let ch_off = TapChannel::<FrameRec>::new();
    let sample_rec = FrameRec::default();
    all_ok &= run_gate("tap_off_fast_path", 1_000_000, 10, true, || {
        black_box(ch_off.push(black_box(10042), black_box(&sample_rec)));
    });

    // 2. Tap armed push + 120-frame batch drain + DoD varint + CRC32C.
    let mut ring_mem = Box::new(AlignedRing([0u8; 128 + 256 * 64]));
    assert!(unsafe {
        init_ring::<FrameRec>(ring_mem.0.as_mut_ptr(), ring_mem.0.len(), RingKind::Frame, 256)
    });
    let ch_on = TapChannel::<FrameRec>::new();
    assert!(unsafe {
        ch_on.arm(
            ring_mem.0.as_mut_ptr(),
            ring_mem.0.len(),
            RingKind::Frame,
            MODE_ALL,
            &[],
        )
    });
    let mut cons = unsafe {
        RingConsumer::<FrameRec>::attach(ring_mem.0.as_mut_ptr(), ring_mem.0.len(), RingKind::Frame)
    }
    .unwrap();
    let mut ts_batch = [0i64; 120];
    let mut enc_buf = [0u8; 512];
    let mut hist = LatencyHist::new();
    all_ok &= run_gate("tap_120_push_drain_dod_crc", 2_000, 25_000, true, || {
        for i in 0..120i64 {
            let mut r = sample_rec;
            r.present_ns = 1_000_000_000 + i * 8_333_000;
            ch_on.push(10042, &r);
        }
        let mut idx = 0;
        cons.drain(|r| {
            ts_batch[idx] = r.present_ns;
            hist.record_us(8_333);
            idx += 1;
        });
        let used = encode_dod_i64(&ts_batch[..idx], &mut enc_buf).unwrap_or(0);
        black_box(crc32c(0, &enc_buf[..used]));
    });
    ch_on.disarm();

    // 3. Full suite of single-pass onyx parsers.
    let mut ps = ProcStatRaw::default();
    let mut mi = MemInfoRaw::default();
    let mut tr = GpuTransRaw::default();
    let mut tr_prev = GpuTransRaw::default();
    parse_trans_stat(FIX_TRANS_STAT, &mut tr_prev);
    let mut zr = ZramStatRaw::default();
    let mut psi = PsiRaw::default();
    all_ok &= run_gate("parse_all_onyx_nodes", 10_000, 15_000, true, || {
        black_box(parse_proc_stat(black_box(FIX_PROC_STAT), &mut ps));
        black_box(parse_meminfo(black_box(FIX_MEMINFO), &mut mi));
        black_box(parse_trans_stat(black_box(FIX_TRANS_STAT), &mut tr));
        black_box(gpu_avg_mhz_from_trans(&tr_prev, &tr));
        black_box(parse_gpu_busy_permille(black_box(b"47 %\n")));
        black_box(parse_zram_mm_stat(black_box(FIX_ZRAM), &mut zr));
        black_box(parse_psi(black_box(FIX_PSI), &mut psi));
        black_box(parse_cgroup_usage_usec(black_box(FIX_CGROUP)));
    });

    // 4. Seqlock Snapshot publish + consistent read.
    let mut shm = Box::new(Snapshot::default());
    shm.init_in_place();
    let mut src = Box::new(SnapshotCopy::default());
    src.cpu.total_permille = 520;
    let mut dst = Box::new(SnapshotCopy::default());
    all_ok &= run_gate("seqlock_publish_and_read", 20_000, 5_000, true, || {
        src.tick_boottime_ns += 1;
        shm.publish_from(&src);
        black_box(shm.read_consistent(&mut dst));
    });

    // 5. HUD dirty-rect restore + 16-glyph NEON/scalar alpha8 blit + integer formatting.
    const HUD_W: usize = 400;
    const HUD_H: usize = 120;
    let mut bg = vec![0u8; HUD_W * HUD_H * 4];
    render_rounded_bg(&mut bg, HUD_W, HUD_H, 14.0, [20, 22, 28, 216]);
    let mut fb = bg.clone();
    let mut glyph = [0u8; 16 * 24];
    for i in 0..glyph.len() {
        glyph[i] = ((i * 19) & 0xff) as u8;
    }
    let mut fmt_buf = [0u8; 16];
    all_ok &= run_gate("hud_dirty_rect_16_glyphs", 2_000, 60_000, true, || {
        black_box(fmt_u32_ascii(120, &mut fmt_buf));
        black_box(fmt_deci_ascii(455, &mut fmt_buf));
        restore_dirty_rect(&mut fb, &bg, HUD_W, 12, 12, 260, 28);
        for g in 0..16 {
            blit_alpha8(
                &mut fb,
                HUD_W,
                HUD_W,
                HUD_H,
                12 + g * 16,
                12,
                &glyph,
                16,
                16,
                24,
                [235, 240, 255, 255],
            );
        }
    });

    // 6. Full Classic HUD compose + dirty-rect ping-pong NEON render & unchanged skip check.
    let mut hud = HudCompositor::new();
    let mut prof = HudProfile::default();
    prof.enabled_mask = 1 << (WidgetId::Classic as u8);
    let mut hsnap = Box::new(SnapshotCopy::default());
    hsnap.fps.current_x100 = 12000;
    hsnap.cpu.total_permille = 450;
    hsnap.cpu.max_freq_khz = 2_803_200;
    hsnap.thermal.cpu_deci_c = 455;
    hsnap.gpu.busy_permille = 680;
    hsnap.gpu.avg_mhz = 763;
    hsnap.thermal.gpu_deci_c = 410;
    hsnap.mem.total_kb = 12 * 1_048_576;
    hsnap.mem.used_kb = 6 * 1_048_576;
    let init_plan = hud.plan_widget(0, true, &prof, &hsnap);
    let mut pp0 = vec![0u8; (init_plan.w * init_plan.h * 4) as usize];
    let mut pp1 = vec![0u8; (init_plan.w * init_plan.h * 4) as usize];
    hud.render_widget(0, &mut pp0, init_plan.w as usize, 0);
    hud.render_widget(0, &mut pp1, init_plan.w as usize, 1);
    let mut pp_slot = 0usize;
    all_ok &= run_gate("hud_classic_full_redraw", 2_000, 60_000, true, || {
        hsnap.fps.current_x100 = if hsnap.fps.current_x100 == 12000 { 11900 } else { 12000 };
        let plan = hud.plan_widget(0, true, &prof, &hsnap);
        if plan.needs_redraw {
            let dst = if pp_slot == 0 { &mut pp0 } else { &mut pp1 };
            black_box(hud.render_widget(0, dst, plan.w as usize, pp_slot));
            pp_slot ^= 1;
        }
    });
    all_ok &= run_gate("hud_classic_unchanged_skip", 20_000, 5_000, true, || {
        let plan = hud.plan_widget(0, true, &prof, &hsnap);
        black_box(plan.needs_redraw);
    });

    // 6b. Top-docked y=0 Mini bar + Unified Network 1-Grafik zero-alloc gates.
    prof.enabled_mask |= (1 << WidgetId::Mini as u8) | (1 << WidgetId::Network as u8);
    hsnap.net.link_type = pantau::abi::LINK_WIFI | pantau::abi::LINK_CELL;
    hsnap.net.wifi_rx_bps = 4_200_000;
    hsnap.net.cell_rx_bps = 900_000;
    hsnap.net.rx_bps = 5_100_000;
    hsnap.net.tx_bps = 540_000;
    hsnap.net.tcp_rtt_us = 18_000;
    hsnap.net.tcp_rttvar_us = 2_000;
    for i in 0..48u32 {
        hsnap.hist.push_net(2000 + i * 50, if i > 24 { 800 + i * 20 } else { 0 }, 400, 18);
    }
    let mplan = hud.plan_widget(WidgetId::Mini as usize, true, &prof, &hsnap);
    let mut mbuf = vec![0u8; (mplan.w * mplan.h * 4) as usize];
    hud.render_widget(WidgetId::Mini as usize, &mut mbuf, mplan.w as usize, 0);
    all_ok &= run_gate("hud_mini_top_docked", 2_000, 40_000, true, || {
        hsnap.cpu.total_permille = if hsnap.cpu.total_permille == 450 { 460 } else { 450 };
        let p = hud.plan_widget(WidgetId::Mini as usize, true, &prof, &hsnap);
        if p.needs_redraw {
            black_box(hud.render_widget(WidgetId::Mini as usize, &mut mbuf, p.w as usize, 0));
        }
    });
    let nplan = hud.plan_widget(WidgetId::Network as usize, true, &prof, &hsnap);
    let mut nbuf = vec![0u8; (nplan.w * nplan.h * 4) as usize];
    hud.render_widget(WidgetId::Network as usize, &mut nbuf, nplan.w as usize, 0);
    all_ok &= run_gate("hud_network_1graph", 1_000, 120_000, true, || {
        hsnap.net.rx_bps = if hsnap.net.rx_bps == 5_100_000 { 5_200_000 } else { 5_100_000 };
        let p = hud.plan_widget(WidgetId::Network as usize, true, &prof, &hsnap);
        if p.needs_redraw {
            black_box(hud.render_widget(WidgetId::Network as usize, &mut nbuf, p.w as usize, 0));
        }
    });

    // 7. Streaming zero-alloc JSON snapshot emission.
    let mut json_buf = [0u8; 8192];
    all_ok &= run_gate("json_emit_snapshot", 10_000, 15_000, true, || {
        black_box(emit_snapshot(&mut json_buf, &src));
    });

    // 7. Optional live device sampler tick (`--live` on onyx, Classic HUD mask, <= 600 us wall / <= 400 us CPU).
    if live {
        let mut sampler = Sampler::discover();
        let mut scratch = Box::new(Scratch::default());
        let mut snap = Box::new(SnapshotCopy::default());
        let classic_mask = mask::CPU | mask::GPU | mask::THERMAL | mask::MEM | mask::FPS;
        // Prime first tick.
        sampler.tick(classic_mask, 0, boottime_ns(), &mut scratch, &mut snap);
        let mut cpu_sum_us = 0u64;
        let mut cpu_iters = 0u64;
        all_ok &= run_gate("live_classic_hud_tick", 200, 600_000, true, || {
            sampler.tick(classic_mask, 0, boottime_ns(), &mut scratch, &mut snap);
            cpu_sum_us += snap.self_tick_us as u64;
            cpu_iters += 1;
        });
        let avg_cpu_us = cpu_sum_us / cpu_iters.max(1);
        let cpu_ok = avg_cpu_us <= 400;
        all_ok &= cpu_ok;
        println!(
            "[{}] {:<28} {:>8} us/op  (budget <=     400 us)  rss={} KB  cpu={}c10  gpu={}c10  skin={}c10  little=0x{:x}",
            if cpu_ok { "PASS" } else { "FAIL" },
            "live_classic_hud_cpu_time",
            avg_cpu_us,
            snap.self_rss_kb,
            snap.thermal.cpu_deci_c,
            snap.thermal.gpu_deci_c,
            snap.thermal.skin_deci_c,
            sampler.little_cpu_mask()
        );
    }

    if !all_ok {
        eprintln!("pantau_bench: ONE OR MORE GATES FAILED");
        std::process::exit(1);
    }
    println!("pantau_bench: ALL GATES GREEN");
}
