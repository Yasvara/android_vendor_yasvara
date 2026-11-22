#
# SPDX-FileCopyrightText: The Yasvara Project
# SPDX-License-Identifier: Apache-2.0
#
# Google Mobile Services: MindTheGapps core (vendor/gapps) + Pixel apps (vendor/yasvara-gms).

ifeq ($(WITH_GMS),true)
$(call inherit-product-if-exists, vendor/gapps/arm64/arm64-vendor.mk)
$(call inherit-product-if-exists, vendor/yasvara-gms/products/gms.mk)
endif
