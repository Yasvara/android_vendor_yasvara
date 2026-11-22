#
# SPDX-FileCopyrightText: The Yasvara Project
# SPDX-License-Identifier: Apache-2.0
#
# Core Yasvara OS product configuration — standalone, zero LineageOS runtime overhead.

# Allow vendor/extra to override any property by setting it first
$(call inherit-product-if-exists, vendor/extra/product.mk)

# Exclude non-ROM / retired LineageOS trees from Soong scanning
PRODUCT_SOURCE_ROOT_DIRS += \
    -kernel/platform \
    -prebuilts/misc/protobuf_vendorcompat \
    -vendor/lineage \
    -lineage-sdk \
    -device/lineage \
    -packages/overlays/Lineage \
    -packages/apps/Aperture \
    -packages/apps/AudioFX \
    -packages/apps/Backgrounds \
    -packages/apps/Camelot \
    -packages/apps/Catapult \
    -packages/apps/Etar \
    -packages/apps/ExactCalculator \
    -packages/apps/FlipFlap \
    -packages/apps/Glimpse \
    -packages/apps/Jelly \
    -packages/apps/LineageCustomizer \
    -packages/apps/LineageParts \
    -packages/apps/Profiles \
    -packages/apps/Recorder \
    -packages/apps/Seedvault \
    -packages/apps/SetupWizard \
    -packages/apps/SimpleDeviceConfig \
    -packages/apps/SimpleSettingsConfig \
    -packages/apps/Twelve \
    -packages/apps/Updater

# Allow vendor prebuilt repos to exclude themselves from bp scanning
-include $(sort $(wildcard vendor/*/*/exclude-bp.mk))

PRODUCT_BRAND ?= Yasvara

ifeq ($(PRODUCT_GMS_CLIENTID_BASE),)
PRODUCT_PRODUCT_PROPERTIES += \
    ro.com.google.clientidbase=android-google
else
PRODUCT_PRODUCT_PROPERTIES += \
    ro.com.google.clientidbase=$(PRODUCT_GMS_CLIENTID_BASE)
endif

ifeq ($(TARGET_BUILD_VARIANT),eng)
PRODUCT_SYSTEM_EXT_PROPERTIES += ro.adb.secure=0
else
ifdef WITH_ADB_INSECURE
PRODUCT_SYSTEM_EXT_PROPERTIES += ro.adb.secure=0
else
PRODUCT_SYSTEM_EXT_PROPERTIES += ro.adb.secure=1
PRODUCT_NOT_DEBUGGABLE_IN_USERDEBUG := true
endif
PRODUCT_PRODUCT_PROPERTIES += persist.sys.strictmode.disable=true
endif

# OTA Backup Tool (addon.d support for MindTheGapps survival across OTA)
PRODUCT_COPY_FILES += \
    vendor/yasvara/prebuilt/common/bin/backuptool.sh:install/bin/backuptool.sh \
    vendor/yasvara/prebuilt/common/bin/backuptool.functions:install/bin/backuptool.functions

PRODUCT_PACKAGES += \
    50-yasvara.sh

PRODUCT_ARTIFACT_PATH_REQUIREMENT_ALLOWED_LIST += \
    system/addon.d/50-yasvara.sh

ifneq ($(strip $(AB_OTA_PARTITIONS) $(AB_OTA_POSTINSTALL_CONFIG)),)
PRODUCT_COPY_FILES += \
    vendor/yasvara/prebuilt/common/bin/backuptool_ab.sh:$(TARGET_COPY_OUT_SYSTEM)/bin/backuptool_ab.sh \
    vendor/yasvara/prebuilt/common/bin/backuptool_ab.functions:$(TARGET_COPY_OUT_SYSTEM)/bin/backuptool_ab.functions \
    vendor/yasvara/prebuilt/common/bin/backuptool_postinstall.sh:$(TARGET_COPY_OUT_SYSTEM)/bin/backuptool_postinstall.sh

PRODUCT_ARTIFACT_PATH_REQUIREMENT_ALLOWED_LIST += \
    system/bin/backuptool_ab.sh \
    system/bin/backuptool_ab.functions \
    system/bin/backuptool_postinstall.sh

ifneq ($(TARGET_BUILD_VARIANT),user)
PRODUCT_PRODUCT_PROPERTIES += \
    ro.ota.allow_downgrade=true
endif
endif

# Sysconfig & init
PRODUCT_COPY_FILES += \
    vendor/yasvara/prebuilt/common/etc/yasvara-sysconfig.xml:$(TARGET_COPY_OUT_PRODUCT)/etc/sysconfig/yasvara-sysconfig.xml \
    vendor/yasvara/prebuilt/common/etc/init/init.yasvara-system_ext.rc:$(TARGET_COPY_OUT_SYSTEM_EXT)/etc/init/init.yasvara-system_ext.rc

# Enable SIP+VoIP on all targets
PRODUCT_COPY_FILES += \
    frameworks/native/data/etc/android.software.sip.voip.xml:$(TARGET_COPY_OUT_PRODUCT)/etc/permissions/android.software.sip.voip.xml

# Enable wireless Xbox 360 controller support
PRODUCT_COPY_FILES += \
    frameworks/base/data/keyboards/Vendor_045e_Product_028e.kl:$(TARGET_COPY_OUT_PRODUCT)/usr/keylayout/Vendor_045e_Product_0719.kl

# Component overrides (disable GMS OTA nag UI)
PRODUCT_PACKAGES += \
    yasvara-component-overrides.xml

# Enforce privapp-permissions whitelist
PRODUCT_PRODUCT_PROPERTIES += \
    ro.control_privapp_permissions=enforce

# Do not include art debug targets
PRODUCT_ART_TARGET_INCLUDE_DEBUG_BUILD := false
PRODUCT_MINIMIZE_JAVA_DEBUG_INFO := true

# Whole-program R8 Java optimizations for SystemUI & system_server
SYSTEM_OPTIMIZE_JAVA ?= true
SYSTEMUI_OPTIMIZE_JAVA ?= true
FULL_SYSTEM_OPTIMIZE_JAVA ?= true

PRODUCT_RESTRICT_VENDOR_FILES := false

ifneq ($(TARGET_DISABLE_EPPE),true)
$(call enforce-product-packages-exist-internal,$(lastword $(_include_stack)),product_manifest.xml rild Calendar android.hidl.memory@1.0-impl.vendor vndk_apex_snapshot_package)
endif

# Yasvara dynamic-colour boot animation
PRODUCT_PACKAGES += \
    bootanimation.zip \
    bootanimation-dark.zip

# Hentak: game sound catalogs for 4D haptics
PRODUCT_PACKAGES += \
    hentak_scan

# Power-user CLI utilities (zero runtime RAM cost)
PRODUCT_PACKAGES += \
    bash \
    curl \
    getcap \
    htop \
    nano \
    nano_recovery \
    rsync \
    setcap \
    unrar \
    vim \
    zstd

PRODUCT_ARTIFACT_PATH_REQUIREMENT_ALLOWED_LIST += \
    system/bin/curl \
    system/bin/getcap \
    system/bin/setcap \
    system/%/libzstd.so

# fastbootd
ifneq ($(TARGET_DISABLE_FASTBOOTD),true)
PRODUCT_PACKAGES += \
    fastbootd
endif

# Filesystems tools
PRODUCT_PACKAGES += \
    fsck.ntfs \
    mkfs.ntfs \
    mount.ntfs

PRODUCT_ARTIFACT_PATH_REQUIREMENT_ALLOWED_LIST += \
    system/bin/fsck.ntfs \
    system/bin/mkfs.ntfs \
    system/bin/mount.ntfs \
    system/%/libfuse-lite.so \
    system/%/libntfs-3g.so

# FRP
PRODUCT_COPY_FILES += \
    vendor/yasvara/prebuilt/common/bin/wipe-frp.sh:$(TARGET_COPY_OUT_RECOVERY)/root/system/bin/wipe-frp

# Openssh
PRODUCT_PACKAGES += \
    scp \
    sftp \
    ssh \
    sshd \
    sshd_config \
    ssh-keygen \
    start-ssh

PRODUCT_COPY_FILES += \
    vendor/yasvara/prebuilt/common/etc/init/init.openssh.rc:$(TARGET_COPY_OUT_PRODUCT)/etc/init/init.openssh.rc

# OverlayFS debug helper
PRODUCT_PACKAGES_DEBUG += \
    disable-overlays \
    procmem

ifneq ($(TARGET_BUILD_VARIANT),user)
PRODUCT_ARTIFACT_PATH_REQUIREMENT_ALLOWED_LIST += \
    system/bin/procmem
endif

# ADB root support
PRODUCT_PACKAGES += \
    adb_root

# Storage manager
PRODUCT_PRODUCT_PROPERTIES += \
    ro.storage_manager.enabled=true

# SystemUI AOT speed compile
PRODUCT_DEXPREOPT_SPEED_APPS += \
    SystemUI

PRODUCT_PRODUCT_PROPERTIES += \
    dalvik.vm.systemuicompilerfilter=speed

ifeq ($(TARGET_BUILD_VARIANT),userdebug)
PRODUCT_PRODUCT_PROPERTIES += \
    debug.sf.enable_transaction_tracing=false
endif

# Audio files
$(call inherit-product, vendor/yasvara/audio/audio.mk)

# SetupWizard theming
PRODUCT_PRODUCT_PROPERTIES += \
    setupwizard.theme=glif_v4 \
    setupwizard.feature.day_night_mode_enabled=true

# Overlays
$(call inherit-product, vendor/yasvara/overlay/overlay.mk)

PRODUCT_PACKAGES += \
    DocumentsUIOverlay \
    NetworkStackOverlay \
    PermissionControllerOverlay

# Version & branding
include vendor/yasvara/config/version.mk

# Yasvara native subsystems
$(call inherit-product, vendor/yasvara/spoof/yasvara_spoof.mk)
$(call inherit-product, vendor/yasvara/kait/yasvara_kait.mk)
$(call inherit-product, vendor/yasvara/pantau/yasvara_pantau.mk)
$(call inherit-product, vendor/yasvara/padat/yasvara_padat.mk)
$(call inherit-product, vendor/yasvara/root/yasvara_root.mk)

-include vendor/lineage-priv/keys/keys.mk
-include vendor/yasvara-priv/keys/keys.mk
include vendor/yasvara/config/gms.mk
