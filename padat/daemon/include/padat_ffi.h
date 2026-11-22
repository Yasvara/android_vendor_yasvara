/*
 * SPDX-FileCopyrightText: The Yasvara Project
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

void padat_free_string(char* ptr);

char* padat_status_json(void);
char* padat_get_policy_json(void);
int32_t padat_set_policy_json(const char* json);

void padat_set_paused(bool paused);
void padat_cancel_job(void);

char* padat_scan_package_json(const char* pkg, uint8_t algo, uint8_t level,
                              uint16_t cluster_kb, uint32_t scope_mask);

char* padat_compress_package_json(const char* pkg, uint8_t algo, uint8_t level,
                                  uint16_t cluster_kb, uint32_t scope_mask,
                                  bool allow_running);

char* padat_sync_package_json(const char* pkg, uint8_t algo, uint8_t level,
                              uint16_t cluster_kb, uint32_t scope_mask);

char* padat_decompress_package_json(const char* pkg, uint32_t scope_mask,
                                    bool allow_running);

char* padat_release_path_json(const char* path);
char* padat_all_stats_json(void);

uint64_t padat_cleanup_stale_temps(void);
int32_t padat_apply_dir_profile(const char* path, uint8_t algo, uint8_t level,
                                uint16_t cluster_kb);

#ifdef __cplusplus
}
#endif
