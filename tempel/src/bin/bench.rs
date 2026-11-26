// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: Apache-2.0

//! Host latency & throughput benchmark for `libtempel`.

use std::hint::black_box;
use std::time::Instant;
use tempel::apdu::{encode_ndef_uri, process_t4t_ndef_into, T4tSelection, NDEF_APP_AID};
use tempel::nci::{encode_mfc_verify_keys_into, ListenAConfig, ListenBConfig, ListenFConfig, MFC_VERIFY_MAX_PAYLOAD};
use tempel::tag::{build_gen4_write_block, build_mfc_block0, export_mct, parse_mct};
use tempel::vault::{Profile, Vault};

fn bench<F: FnMut()>(name: &str, iters: u32, mut f: F) {
    // Warmup
    for _ in 0..1000 {
        f();
    }
    let start = Instant::now();
    for _ in 0..iters {
        f();
    }
    let elapsed = start.elapsed();
    let ns_per_op = elapsed.as_nanos() as f64 / iters as f64;
    println!("{name:<36} {iters:>8} iters  {ns_per_op:>9.1} ns/op");
}

fn main() {
    // 1. Type-4A NDEF APDU hot path (zero heap allocs)
    let ndef = encode_ndef_uri("https://yasvara.org/tempel");
    let mut sel_cmd = vec![0x00, 0xA4, 0x04, 0x00, 0x07];
    sel_cmd.extend_from_slice(&NDEF_APP_AID);
    let read_cmd = [0x00u8, 0xB0, 0x00, 0x02, ndef.len() as u8];
    let mut out = [0u8; 260];
    let mut sel = T4tSelection::NdefFile;

    bench("t4t_ndef_read_binary_zero_alloc", 500_000, || {
        sel = T4tSelection::NdefFile;
        black_box(process_t4t_ndef_into(&mut sel, &ndef, &read_cmd, &mut out));
    });

    // 2. NCI Listen-A / Listen-B / Listen-F + 2F 45 40-key batch encoding
    let mut nci_buf = [0u8; MFC_VERIFY_MAX_PAYLOAD];
    let keys40 = [[0xFFu8; 6]; 40];
    bench("nci_listen_a_b_f_encode", 200_000, || {
        let a = ListenAConfig::from_card(&[0xDE, 0xAD, 0xBE, 0xEF], [0x04, 0x00], 0x08, 0, &[]);
        black_box(&a);
        let b = ListenBConfig::new([0xCA, 0xFE, 0xBA, 0xBE], [1, 2, 3, 4], true, &[]).unwrap();
        let _ = black_box(b.encode_set_config_into(&mut nci_buf));
        let f = ListenFConfig::new([0x12, 0xFC], [1, 2, 3, 4, 5, 6, 7, 8], ListenFConfig::DEFAULT_PMM, 0).unwrap();
        let _ = black_box(f.encode_set_config_into(&mut nci_buf));
    });
    bench("nci_2f45_40key_batch_encode", 500_000, || {
        let _ = black_box(encode_mfc_verify_keys_into(&keys40, &mut nci_buf));
    });

    // 3. Vault binary encode + CRC32 decode (64 profiles)
    let mut vault = Vault::new();
    vault.upsert(Profile::payment(0, "GoPay QRIS", "com.gojek.gopay"));
    for i in 1..64u32 {
        vault.upsert(Profile::uid_a(
            0,
            &format!("Door #{i}"),
            &[0xAA, 0xBB, (i >> 8) as u8, i as u8],
            [0x04, 0x00],
            0x08,
        ));
    }
    let blob = vault.encode_binary();
    println!("Vault binary size (64 profiles): {} bytes", blob.len());
    bench("vault_64_encode_binary", 10_000, || {
        black_box(vault.encode_binary());
    });
    let mut dst = Vault::new();
    bench("vault_64_decode_crc32", 10_000, || {
        black_box(dst.decode_binary(&blob));
    });

    // 4. MIFARE 1K .mct parse + Gen4 validated write frame
    let mut blocks = vec![[0u8; 16]; 64];
    blocks[0] = build_mfc_block0(&[0xDE, 0xAD, 0xBE, 0xEF], 0x08, [0x04, 0x00], None).unwrap();
    let mct = export_mct(&blocks);
    bench("mct_1k_parse", 5_000, || {
        let _ = black_box(parse_mct(&mct));
    });
    let trailer = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x07, 0x80, 0x69, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
    bench("gen4_validated_write_frame", 500_000, || {
        let _ = black_box(build_gen4_write_block([0; 4], 3, &trailer, true));
    });
}
