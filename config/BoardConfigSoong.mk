#
# SPDX-FileCopyrightText: The Yasvara Project
# SPDX-License-Identifier: Apache-2.0
#

PATH_OVERRIDE_SOONG := $(shell echo $(TOOLS_PATH_OVERRIDE))

EXPORT_TO_SOONG := \
    KERNEL_ARCH \
    KERNEL_BUILD_OUT_PREFIX \
    KERNEL_CROSS_COMPILE \
    KERNEL_MAKE_CMD \
    KERNEL_MAKE_FLAGS \
    KERNEL_PATH \
    PATH_OVERRIDE_SOONG \
    TARGET_KERNEL_CONFIG \
    TARGET_KERNEL_SOURCE \
    TARGET_KERNEL_PLATFORM_TARGET \
    TARGET_MAX_PAGE_SIZE_SUPPORTED \
    TARGET_PREBUILT_KERNEL_HEADERS

# Keep lineageVarsPlugin namespace for upstream hardware/lineage/compat compatibility
$(call add_soong_config_namespace,lineageVarsPlugin)
$(foreach v,$(EXPORT_TO_SOONG),$(eval $(call add_soong_config_var,lineageVarsPlugin,$(v))))

# Yasvara dynamic-colour boot animation (device may override TARGET_BOOTANIMATION)
ifneq ($(TARGET_BOOTANIMATION),)
$(call soong_config_set,yasvara_bootanimation,prebuilt_file,$(TARGET_BOOTANIMATION))
endif

# Charger density
yasvara_charger_density := mdpi
ifneq (,$(TARGET_SCREEN_DENSITY))
yasvara_charger_density := $(strip \
  $(or $(if $(filter $(shell echo $$(($(TARGET_SCREEN_DENSITY) >= 560))),1),xxxhdpi),\
       $(if $(filter $(shell echo $$(($(TARGET_SCREEN_DENSITY) >= 400))),1),xxhdpi),\
       $(if $(filter $(shell echo $$(($(TARGET_SCREEN_DENSITY) >= 280))),1),xhdpi),\
       $(if $(filter $(shell echo $$(($(TARGET_SCREEN_DENSITY) >= 200))),1),hdpi,mdpi)))
else ifneq (,$(filter mdpi hdpi xhdpi xxhdpi xxxhdpi,$(PRODUCT_AAPT_PREF_CONFIG)))
yasvara_charger_density := $(PRODUCT_AAPT_PREF_CONFIG)
endif
$(call soong_config_set,yasvara_charger,density,$(yasvara_charger_density))

# Libui
ifneq ($(TARGET_ADDITIONAL_GRALLOC_10_USAGE_BITS),)
    $(call soong_config_set,libui,additional_gralloc_10_usage_bits,$(TARGET_ADDITIONAL_GRALLOC_10_USAGE_BITS))
endif
