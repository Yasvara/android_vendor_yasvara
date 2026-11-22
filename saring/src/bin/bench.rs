// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: Apache-2.0

//! Speed gate for the name table, DNS cache and URL cleaner, on the host and on the phone.
//!
//!   saring_bench compile <out.bin> <list>...     compile and time it
//!   saring_bench lookup <names.bin> [budget_ns]  time lookups; non-zero exit over budget
//!   saring_bench cache [budget_ns]               time Serve-Stale cache lookups
//!   saring_bench clean [budget_ns]               time URL redirect unwrap + tracking strip
//!   saring_bench resolve <host> [count]          time getaddrinfo through the resolver

use saring::cache::{DnsCache, Lookup};
use saring::clean::clean_url;
use saring::compile::compile;
use saring::dns::{parse_question, QCLASS_IN, QTYPE_A};
use saring::Names;
use std::ffi::{c_char, c_int, c_void, CString};
use std::hint::black_box;
use std::time::Instant;
use std::{env, fs, process, ptr};

extern "C" {
    fn getaddrinfo(
        node: *const c_char,
        service: *const c_char,
        hints: *const c_void,
        res: *mut *mut c_void,
    ) -> c_int;
    fn freeaddrinfo(res: *mut c_void);
}

const MISSES: [&[u8]; 8] = [
    b"www.google.com",
    b"api.mobilelegends.com",
    b"scontent-cgk1-1.cdninstagram.com",
    b"mmg.whatsapp.net",
    b"edge-chat.instagram.com",
    b"clients4.google.com",
    b"a1234.dscg.akamai.net",
    b"play.googleapis.com",
];

const HITS: [&[u8]; 4] = [
    b"googleads.g.doubleclick.net",
    b"app-measurement.com",
    b"graph.facebook.com.doubleclick.net",
    b"pagead2.googlesyndication.com",
];

fn time(names: &Names, set: &[&[u8]], rounds: usize) -> (f64, usize) {
    let mut hits = 0;
    let start = Instant::now();
    for _ in 0..rounds {
        for name in set {
            hits += usize::from(names.blocked(black_box(name)));
        }
    }
    (start.elapsed().as_nanos() as f64 / (rounds * set.len()) as f64, hits / rounds)
}

/// Lookups that each touch a different part of the table, as the first query after idle does.
fn time_cold(names: &Names, count: usize) -> f64 {
    let made: Vec<String> = (0..count)
        .map(|i| format!("h{}.s{}.example{}.net", i.wrapping_mul(2_654_435_761) % 99_991, i % 613, i % 7919))
        .collect();
    let start = Instant::now();
    let mut hits = 0;
    for name in &made {
        hits += usize::from(names.blocked(black_box(name.as_bytes())));
    }
    black_box(hits);
    start.elapsed().as_nanos() as f64 / count as f64
}

fn main() {
    let args: Vec<String> = env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("compile") if args.len() >= 4 => {
            let texts: Vec<String> = args[3..]
                .iter()
                .map(|p| String::from_utf8_lossy(&fs::read(p).expect("read list")).into_owned())
                .collect();
            let refs: Vec<&str> = texts.iter().map(String::as_str).collect();
            let bytes: usize = texts.iter().map(String::len).sum();
            let start = Instant::now();
            let (blob, stats) = compile(&refs, 0);
            let ms = start.elapsed().as_secs_f64() * 1e3;
            for (path, s) in args[3..].iter().zip(&stats) {
                println!("{path}: {s:?}");
            }
            let entries = Names::open(&blob).expect("own blob").len();
            println!(
                "{entries} entries, {} kB blob from {} kB text in {ms:.0} ms",
                blob.len() / 1024,
                bytes / 1024
            );
            fs::write(&args[2], blob).expect("write blob");
        }
        Some("lookup") if args.len() >= 3 => {
            let blob = fs::read(&args[2]).expect("read blob");
            let names = Names::open(&blob).expect("valid blob");
            let budget: f64 = args.get(3).and_then(|b| b.parse().ok()).unwrap_or(f64::MAX);
            time(&names, &MISSES, 20_000);
            let (miss, _) = time(&names, &MISSES, 400_000);
            let (hit, hits) = time(&names, &HITS, 400_000);
            let cold = time_cold(&names, 2_000_000);
            println!("{} entries", names.len());
            println!("pass   {miss:7.1} ns/lookup");
            println!("block  {hit:7.1} ns/lookup ({hits} of {} blocked)", HITS.len());
            println!("spread {cold:7.1} ns/lookup");
            if miss > budget || hit > budget || cold > budget {
                eprintln!("over the {budget} ns budget");
                process::exit(1);
            }
        }
        Some("cache") => {
            let budget: f64 = args.get(2).and_then(|b| b.parse().ok()).unwrap_or(2000.0);
            let cache = DnsCache::new();
            let mut query = vec![0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
            for label in ["danbooru", "donmai", "us"] {
                query.push(label.len() as u8);
                query.extend_from_slice(label.as_bytes());
            }
            query.push(0);
            query.extend_from_slice(&QTYPE_A.to_be_bytes());
            query.extend_from_slice(&QCLASS_IN.to_be_bytes());
            let mut ans = query.clone();
            ans[2] = 0x81;
            ans[3] = 0x80;
            ans[7] = 1;
            ans.extend_from_slice(&[0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 1, 44, 0, 4, 104, 26, 10, 39]);

            let q = parse_question(&query).expect("question");
            let key = q.cache_key(100);
            cache.insert(100, key, &ans, 0, 1, 300, 1000);

            let mut out = [0u8; 512];
            let rounds = 500_000usize;
            for _ in 0..10_000 {
                let _ = black_box(cache.lookup(100, key, 0x9999, 1050, &mut out));
            }
            let start = Instant::now();
            let mut hits = 0usize;
            for i in 0..rounds {
                if let Lookup::Fresh { len, .. } =
                    cache.lookup(100, key, black_box(i as u16), 1050, &mut out)
                {
                    hits += len;
                }
            }
            black_box(hits);
            let ns = start.elapsed().as_nanos() as f64 / rounds as f64;
            println!("cache hit  {ns:7.1} ns/lookup");
            if ns > budget {
                eprintln!("over the {budget} ns budget");
                process::exit(1);
            }
        }
        Some("clean") => {
            let budget: f64 = args.get(2).and_then(|b| b.parse().ok()).unwrap_or(1000.0);
            let dirty = b"https://www.google.com/url?q=https%3A%2F%2Fdanbooru.donmai.us%2Fposts%3Ftags%3Dcat%26utm_source%3Dgoogle%26ved%3D123&sa=U&ved=2ahUKEwj";
            let clean = b"https://www.google.com/search?q=danbooru&hl=id";
            let mut out = [0u8; 512];
            let rounds = 500_000usize;
            let start = Instant::now();
            let mut acc = 0usize;
            for _ in 0..rounds {
                acc += clean_url(black_box(dirty), &mut out).unwrap_or(0);
                acc += clean_url(black_box(clean), &mut out).unwrap_or(0);
            }
            black_box(acc);
            let ns = start.elapsed().as_nanos() as f64 / (rounds * 2) as f64;
            println!("clean url  {ns:7.1} ns/call");
            if ns > budget {
                eprintln!("over the {budget} ns budget");
                process::exit(1);
            }
        }
        Some("resolve") if args.len() >= 3 => {
            let host = CString::new(args[2].as_str()).expect("host");
            let count: usize = args.get(3).and_then(|c| c.parse().ok()).unwrap_or(200);
            let mut times = Vec::with_capacity(count);
            let mut rc = 0;
            for _ in 0..count {
                let mut res = ptr::null_mut();
                let start = Instant::now();
                // SAFETY: valid C string, null service and hints, res freed when set.
                rc = unsafe { getaddrinfo(host.as_ptr(), ptr::null(), ptr::null(), &mut res) };
                times.push(start.elapsed().as_micros() as u64);
                if rc == 0 {
                    // SAFETY: res came from getaddrinfo.
                    unsafe { freeaddrinfo(res) };
                }
            }
            times.sort_unstable();
            println!(
                "{} rc={rc} first-sorted: min {} us, median {} us, p95 {} us",
                args[2],
                times[0],
                times[count / 2],
                times[count * 95 / 100]
            );
        }
        _ => {
            eprintln!("usage: saring_bench compile|lookup|resolve ...");
            process::exit(2);
        }
    }
}
