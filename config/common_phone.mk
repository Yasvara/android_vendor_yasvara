#
# SPDX-FileCopyrightText: The Yasvara Project
# SPDX-License-Identifier: Apache-2.0
#
# Yasvara phone profile — lean, zero LineageOS bloat.

$(call inherit-product, vendor/yasvara/config/common.mk)
$(call inherit-product, vendor/yasvara/config/telephony.mk)

PRODUCT_SIZE := full

# One-handed mode
PRODUCT_PRODUCT_PROPERTIES += \
    ro.support_one_handed_mode?=true

# Audio packages
$(call inherit-product-if-exists, frameworks/base/data/sounds/AudioPackage14.mk)
include vendor/yasvara/config/aosp_audio.mk
include vendor/yasvara/config/yasvara_audio.mk

PRODUCT_PRODUCT_PROPERTIES += \
    ro.config.notification_sound=Argon.ogg \
    ro.config.alarm_alert=Hassium.ogg

# Core apps (no LineageParts, Profiles, Twelve, Camelot, Backgrounds, AudioFX, Etar, Jelly, etc.)
PRODUCT_PACKAGES += \
    AvatarPicker \
    LatinIME \
    Launcher3QuickStep \
    Launcher3Overlay

PRODUCT_DEXPREOPT_SPEED_APPS += \
    Launcher3QuickStep

# Offline charger art
PRODUCT_PACKAGES += \
    charger_res_images

ifneq ($(WITH_YASVARA_CHARGER),false)
PRODUCT_PACKAGES += \
    yasvara_charger_animation \
    yasvara_charger_animation_vendor
endif

# Credential storage
PRODUCT_PACKAGES += \
    android.software.credentials.prebuilt.xml

# Upstream LineageOS legal attribution (About phone -> Legal & credits)
PRODUCT_PRODUCT_PROPERTIES += \
    ro.lineagelegal.url=https://lineageos.org/legal

# Media
PRODUCT_PRODUCT_PROPERTIES += \
    media.recorder.show_manufacturer_and_model=true

# SystemUI plugins
PRODUCT_PACKAGES += \
    QuickAccessWallet

# TextClassifier
PRODUCT_PACKAGES += \
    libtextclassifier_annotator_en_model \
    libtextclassifier_annotator_universal_model \
    libtextclassifier_actions_suggestions_universal_model \
    libtextclassifier_lang_id_model

PRODUCT_ARTIFACT_PATH_REQUIREMENT_ALLOWED_LIST += \
    system/etc/textclassifier/actions_suggestions.universal.model \
    system/etc/textclassifier/lang_id.model \
    system/etc/textclassifier/textclassifier.en.model \
    system/etc/textclassifier/textclassifier.universal.model

# Themes & Google Sans Flex font
$(call inherit-product-if-exists, external/google-fonts/google-sans-flex/fonts.mk)

PRODUCT_PACKAGES += \
    YasvaraBlackTheme \
    ThemePicker \
    ThemesStub \
    fonts_customization.xml \
    FontGoogleSansFlexOverlay

# LatinIME dictionaries
PRODUCT_PACKAGE_OVERLAYS += vendor/yasvara/overlay/dictionaries
PRODUCT_ENFORCE_RRO_EXCLUDED_OVERLAYS += vendor/yasvara/overlay/dictionaries
