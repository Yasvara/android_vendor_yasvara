#
# SPDX-FileCopyrightText: The Yasvara Project
# SPDX-License-Identifier: Apache-2.0
#
# Yasvara spoofing (PIF + TrickyStore + per-app profiles).
# The framework engine reads Settings.Secure keys written by Laras, so this
# file only ships defaults and the offline fallback PIF profile.
#

# Laras system app + system_server Rust JNI bridge for integrity SSOT.
PRODUCT_PACKAGES += \
    Laras \
    libyasvara_integrity_jni

# Offline fallback PIF profile, used when no profile was ever fetched/imported.
PRODUCT_COPY_FILES += \
    vendor/yasvara/spoof/pif_fallback.json:$(TARGET_COPY_OUT_PRODUCT)/etc/yasvara/pif_fallback.json

# Master-toggle defaults (Laras Secure values win when set).
# persist.sys.yasvara.stealth controls boot/adb/marker hiding independently of PIF.
PRODUCT_PRODUCT_PROPERTIES += \
    persist.sys.yasvara.stealth=1 \
    persist.sys.yasvara.pif=1 \
    persist.sys.yasvara.trickystore=1 \
    persist.sys.yasvara.photos_spoof=1 \
    persist.sys.yasvara.snap_spoof=1

