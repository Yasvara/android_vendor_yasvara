#
# SPDX-FileCopyrightText: The Yasvara Project
# SPDX-License-Identifier: Apache-2.0
#
# Yasvara spoofing (PIF + TrickyStore + per-app profiles).
# The framework engine reads Settings.Secure keys written by Laras, so this
# file only ships defaults and the offline fallback PIF profile.
#

# Laras system app (PIF / TrickyStore / per-app spoof UI).
PRODUCT_PACKAGES += \
    Laras

# Offline fallback PIF profile, used when no profile was ever fetched/imported.
PRODUCT_COPY_FILES += \
    vendor/yasvara/spoof/pif_fallback.json:$(TARGET_COPY_OUT_PRODUCT)/etc/yasvara/pif_fallback.json

# Master-toggle defaults (Laras Secure values win when set).
PRODUCT_PRODUCT_PROPERTIES += \
    persist.sys.yasvara.pif=1 \
    persist.sys.yasvara.trickystore=1 \
    persist.sys.yasvara.photos_spoof=1 \
    persist.sys.yasvara.snap_spoof=1

# Yasvara brand strings and icons for the Lineage apps.
$(call inherit-product, vendor/yasvara/overlay/overlay.mk)
