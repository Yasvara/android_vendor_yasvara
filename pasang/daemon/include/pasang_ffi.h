/*
 * SPDX-FileCopyrightText: The Yasvara Project
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef int32_t (*pasang_rsa_verify_fn)(
    const uint8_t* digest_ptr, size_t digest_len,
    const uint8_t* sig_ptr, size_t sig_len,
    const uint8_t* otacerts_path, size_t otacerts_path_len);

typedef ssize_t (*pasang_decompress_fn)(
    const uint8_t* src, size_t src_len,
    uint8_t* dst, size_t dst_cap);

typedef void (*pasang_sha256_oneshot_fn)(const uint8_t* data, size_t len, uint8_t* out32);
typedef void (*pasang_sha256_init_fn)(void* ctx_buf);
typedef void (*pasang_sha256_update_fn)(void* ctx_buf, const uint8_t* data, size_t len);
typedef void (*pasang_sha256_final_fn)(void* ctx_buf, uint8_t* out32);

typedef struct PasangPlatformHooks {
    int32_t (*current_slot)(void);
    int32_t (*active_boot_slot)(void);
    int32_t (*is_slot_bootable)(uint32_t slot);
    int32_t (*is_slot_successful)(uint32_t slot);
    int32_t (*set_active_boot_slot)(uint32_t slot);
    int32_t (*mark_boot_successful)(void);
    int32_t (*snapshot_merge_status)(void);
    pasang_rsa_verify_fn rsa_verify;
    pasang_decompress_fn zstd_decompress;
    pasang_decompress_fn xz_decompress;
    pasang_decompress_fn bz2_decompress;
    pasang_sha256_oneshot_fn sha256_oneshot;
    pasang_sha256_init_fn sha256_init;
    pasang_sha256_update_fn sha256_update;
    pasang_sha256_final_fn sha256_final;
} PasangPlatformHooks;

void pasang_register_hooks(const PasangPlatformHooks* hooks);
void pasang_free_string(char* ptr);

bool pasang_is_busy(void);
char* pasang_status_json(void);
char* pasang_slot_info_json(void);
char* pasang_overlay_status_json(void);
char* pasang_clean_overlays_json(void);
char* pasang_plan_ota_json(const char* path, const char* opts_json);
int32_t pasang_start_ota(const char* path, const char* opts_json);
void pasang_cancel_ota(void);
int32_t pasang_write_recovery_theme(uint32_t seed_argb, bool oled_black, const char* locale);
int32_t pasang_run_cli(int32_t argc, const char* const* argv);

void pasang_init_platform_hooks(void);

#ifdef __cplusplus
}
#endif
