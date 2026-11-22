#
# SPDX-FileCopyrightText: The Yasvara Project
# SPDX-License-Identifier: Apache-2.0
#
# Yasvara OTA update package

YASVARA_TARGET_PACKAGE := $(PRODUCT_OUT)/Yasvara-$(YASVARA_VERSION).zip

SHA256 := prebuilts/build-tools/path/$(HOST_PREBUILT_TAG)/sha256sum

$(YASVARA_TARGET_PACKAGE): $(INTERNAL_OTA_PACKAGE_TARGET)
	$(hide) ln -f $(INTERNAL_OTA_PACKAGE_TARGET) $(YASVARA_TARGET_PACKAGE)
	$(hide) $(SHA256) $(YASVARA_TARGET_PACKAGE) | sed "s|$(PRODUCT_OUT)/||" > $(YASVARA_TARGET_PACKAGE).sha256sum
	@echo "Package Complete: $(YASVARA_TARGET_PACKAGE)" >&2

.PHONY: bacon
bacon: $(YASVARA_TARGET_PACKAGE) $(DEFAULT_GOAL)
