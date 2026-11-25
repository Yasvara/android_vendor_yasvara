/*
 * SPDX-FileCopyrightText: The Yasvara Project
 * SPDX-License-Identifier: Apache-2.0
 */
#define LOG_TAG "pasangd"

#include "pasang_ffi.h"

#include <cstdlib>
#include <cstring>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include <BootControlClient.h>
#include <android-base/logging.h>
#include <bzlib.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <ziparchive/zip_archive.h>
#include <zstd.h>

extern "C" {
#include <7zCrc.h>
#include <Xz.h>
#include <XzCrc64.h>
}

namespace {

using aidl::android::hardware::boot::MergeStatus;
using android::hal::BootControlClient;

std::mutex gBootCtlMu;
std::unique_ptr<BootControlClient> gBootCtl;

BootControlClient* getBootControl() {
    std::lock_guard<std::mutex> lock(gBootCtlMu);
    if (!gBootCtl) {
        gBootCtl = BootControlClient::WaitForService();
        if (!gBootCtl) {
            LOG(ERROR) << "BootControlClient::WaitForService() returned null";
        }
    }
    return gBootCtl.get();
}

int32_t hook_current_slot() {
    auto* bc = getBootControl();
    if (!bc) return -1;
    return static_cast<int32_t>(bc->GetCurrentSlot());
}

int32_t hook_active_boot_slot() {
    auto* bc = getBootControl();
    if (!bc) return -1;
    return static_cast<int32_t>(bc->GetActiveBootSlot());
}

int32_t hook_is_slot_bootable(uint32_t slot) {
    auto* bc = getBootControl();
    if (!bc) return -1;
    auto ret = bc->IsSlotBootable(static_cast<int32_t>(slot));
    return ret.value_or(false) ? 1 : 0;
}

int32_t hook_is_slot_successful(uint32_t slot) {
    auto* bc = getBootControl();
    if (!bc) return -1;
    auto ret = bc->IsSlotMarkedSuccessful(static_cast<int32_t>(slot));
    return ret.value_or(false) ? 1 : 0;
}

int32_t hook_set_active_boot_slot(uint32_t slot) {
    auto* bc = getBootControl();
    if (!bc) return -1;
    auto cr = bc->SetActiveBootSlot(static_cast<int32_t>(slot));
    if (!cr.IsOk() || !cr.success) {
        LOG(ERROR) << "SetActiveBootSlot(" << slot << ") failed: " << cr.errMsg;
        return -1;
    }
    return 0;
}

int32_t hook_mark_boot_successful() {
    auto* bc = getBootControl();
    if (!bc) return -1;
    auto cr = bc->MarkBootSuccessful();
    if (!cr.IsOk() || !cr.success) {
        LOG(ERROR) << "MarkBootSuccessful() failed: " << cr.errMsg;
        return -1;
    }
    return 0;
}

int32_t hook_snapshot_merge_status() {
    auto* bc = getBootControl();
    if (!bc) return 1;
    switch (bc->getSnapshotMergeStatus()) {
        case MergeStatus::NONE: return 0;
        case MergeStatus::UNKNOWN: return 1;
        case MergeStatus::SNAPSHOTTED: return 2;
        case MergeStatus::MERGING: return 3;
        case MergeStatus::CANCELLED: return 4;
        default: return 1;
    }
}

// -----------------------------------------------------------------------------
// Native Decompression Hooks (libzstd, liblzma/XZ, libbz)
// -----------------------------------------------------------------------------

ssize_t hook_zstd_decompress(const uint8_t* src, size_t src_len, uint8_t* dst, size_t dst_cap) {
    if (!src || !dst) return -22;
    size_t ret = ZSTD_decompress(dst, dst_cap, src, src_len);
    if (ZSTD_isError(ret)) {
        LOG(ERROR) << "ZSTD_decompress failed: " << ZSTD_getErrorName(ret);
        return -5;
    }
    return static_cast<ssize_t>(ret);
}

void* szAlloc(ISzAllocPtr, size_t size) { return std::malloc(size); }
void szFree(ISzAllocPtr, void* addr) { std::free(addr); }
ISzAlloc gXzAlloc = {szAlloc, szFree};

ssize_t hook_xz_decompress(const uint8_t* src, size_t src_len, uint8_t* dst, size_t dst_cap) {
    if (!src || !dst) return -22;
    static std::once_flag crc_once;
    std::call_once(crc_once, []() {
        CrcGenerateTable();
        Crc64GenerateTable();
    });

    CXzUnpacker state;
    XzUnpacker_Construct(&state, &gXzAlloc);
    XzUnpacker_Init(&state);

    SizeT dest_len = dst_cap;
    SizeT src_used = src_len;
    ECoderStatus status = CODER_STATUS_NOT_SPECIFIED;
    SRes res = XzUnpacker_CodeFull(&state, dst, &dest_len, src, &src_used, CODER_FINISH_END, &status);
    bool finished = XzUnpacker_IsStreamWasFinished(&state) != 0;
    XzUnpacker_Free(&state);

    if (res != SZ_OK || !finished) {
        LOG(ERROR) << "XzUnpacker_CodeFull failed res=" << res << " status=" << status;
        return -5;
    }
    return static_cast<ssize_t>(dest_len);
}

ssize_t hook_bz2_decompress(const uint8_t* src, size_t src_len, uint8_t* dst, size_t dst_cap) {
    if (!src || !dst) return -22;
    unsigned int out_len = static_cast<unsigned int>(dst_cap);
    int rc = BZ2_bzBuffToBuffDecompress(
        reinterpret_cast<char*>(dst), &out_len,
        const_cast<char*>(reinterpret_cast<const char*>(src)),
        static_cast<unsigned int>(src_len), 0, 0);
    if (rc != BZ_OK) {
        LOG(ERROR) << "BZ2_bzBuffToBuffDecompress failed rc=" << rc;
        return -5;
    }
    return static_cast<ssize_t>(out_len);
}

// -----------------------------------------------------------------------------
// BoringSSL RSA-2048/4096 Payload Metadata Verification against otacerts.zip
// -----------------------------------------------------------------------------

bool verifyWithCertPem(const uint8_t* pem, size_t pem_len,
                       const uint8_t* digest, size_t digest_len,
                       const uint8_t* sig, size_t sig_len) {
    bssl::UniquePtr<BIO> bio(BIO_new_mem_buf(pem, static_cast<int>(pem_len)));
    if (!bio) return false;
    bssl::UniquePtr<X509> cert(PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr));
    if (!cert) return false;
    bssl::UniquePtr<EVP_PKEY> pkey(X509_get_pubkey(cert.get()));
    if (!pkey) return false;

    // Try RSA PKCS#1 v1.5 (standard AOSP update_engine payload signature)
    bssl::UniquePtr<EVP_PKEY_CTX> ctx(EVP_PKEY_CTX_new(pkey.get(), nullptr));
    if (ctx && EVP_PKEY_verify_init(ctx.get()) == 1 &&
        EVP_PKEY_CTX_set_signature_md(ctx.get(), EVP_sha256()) == 1) {
        if (EVP_PKEY_id(pkey.get()) == EVP_PKEY_RSA) {
            EVP_PKEY_CTX_set_rsa_padding(ctx.get(), RSA_PKCS1_PADDING);
        }
        if (EVP_PKEY_verify(ctx.get(), sig, sig_len, digest, digest_len) == 1) {
            return true;
        }
    }

    // Try RSA-PSS fallback
    if (EVP_PKEY_id(pkey.get()) == EVP_PKEY_RSA) {
        bssl::UniquePtr<EVP_PKEY_CTX> pss(EVP_PKEY_CTX_new(pkey.get(), nullptr));
        if (pss && EVP_PKEY_verify_init(pss.get()) == 1 &&
            EVP_PKEY_CTX_set_signature_md(pss.get(), EVP_sha256()) == 1 &&
            EVP_PKEY_CTX_set_rsa_padding(pss.get(), RSA_PKCS1_PSS_PADDING) == 1 &&
            EVP_PKEY_verify(pss.get(), sig, sig_len, digest, digest_len) == 1) {
            return true;
        }
    }
    return false;
}

int32_t hook_rsa_verify(const uint8_t* digest, size_t digest_len,
                        const uint8_t* sig, size_t sig_len,
                        const uint8_t* otacerts_path, size_t otacerts_path_len) {
    if (!digest || !sig || !otacerts_path || digest_len != 32 || sig_len == 0) {
        return -22;
    }
    std::string zip_path(reinterpret_cast<const char*>(otacerts_path), otacerts_path_len);
    ZipArchiveHandle handle = nullptr;
    if (OpenArchive(zip_path.c_str(), &handle) != 0) {
        LOG(WARNING) << "Failed to open otacerts archive: " << zip_path;
        return -2;
    }

    void* cookie = nullptr;
    bool verified = false;
    if (StartIteration(handle, &cookie) == 0) {
        ZipEntry entry;
        std::string name;
        while (Next(cookie, &entry, &name) == 0) {
            const bool is_pem = name.size() >= 4 &&
                                name.compare(name.size() - 4, 4, ".pem") == 0;
            if (!is_pem) {
                continue;
            }
            if (entry.uncompressed_length == 0 || entry.uncompressed_length > 65536) {
                continue;
            }
            std::vector<uint8_t> pem(entry.uncompressed_length);
            if (ExtractToMemory(handle, &entry, pem.data(), pem.size()) == 0) {
                if (verifyWithCertPem(pem.data(), pem.size(), digest, digest_len, sig, sig_len)) {
                    verified = true;
                    break;
                }
            }
        }
        EndIteration(cookie);
    }
    CloseArchive(handle);
    return verified ? 1 : 0;
}

// -----------------------------------------------------------------------------
// BoringSSL Hardware-Accelerated SHA-256 (ARMv8 sha256-ce, ~2.2 GB/s per core)
// -----------------------------------------------------------------------------

static_assert(sizeof(SHA256_CTX) <= 256, "SHA256_CTX exceeds 256-byte opaque FFI buffer");

void hook_sha256_oneshot(const uint8_t* data, size_t len, uint8_t* out32) {
    SHA256(data, len, out32);
}

void hook_sha256_init(void* ctx_buf) {
    SHA256_Init(reinterpret_cast<SHA256_CTX*>(ctx_buf));
}

void hook_sha256_update(void* ctx_buf, const uint8_t* data, size_t len) {
    SHA256_Update(reinterpret_cast<SHA256_CTX*>(ctx_buf), data, len);
}

void hook_sha256_final(void* ctx_buf, uint8_t* out32) {
    SHA256_Final(out32, reinterpret_cast<SHA256_CTX*>(ctx_buf));
}

} // namespace

extern "C" void pasang_init_platform_hooks(void) {
    PasangPlatformHooks hooks{};
    hooks.current_slot = hook_current_slot;
    hooks.active_boot_slot = hook_active_boot_slot;
    hooks.is_slot_bootable = hook_is_slot_bootable;
    hooks.is_slot_successful = hook_is_slot_successful;
    hooks.set_active_boot_slot = hook_set_active_boot_slot;
    hooks.mark_boot_successful = hook_mark_boot_successful;
    hooks.snapshot_merge_status = hook_snapshot_merge_status;
    hooks.rsa_verify = hook_rsa_verify;
    hooks.zstd_decompress = hook_zstd_decompress;
    hooks.xz_decompress = hook_xz_decompress;
    hooks.bz2_decompress = hook_bz2_decompress;
    hooks.sha256_oneshot = hook_sha256_oneshot;
    hooks.sha256_init = hook_sha256_init;
    hooks.sha256_update = hook_sha256_update;
    hooks.sha256_final = hook_sha256_final;
    pasang_register_hooks(&hooks);
}
