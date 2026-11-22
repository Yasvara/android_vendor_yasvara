#
# SPDX-FileCopyrightText: The Yasvara Project
# SPDX-License-Identifier: Apache-2.0
#

# Recovery
BOARD_USES_FULL_RECOVERY_IMAGE ?= true

include vendor/yasvara/config/BoardConfigKernel.mk

ifeq ($(BOARD_USES_QCOM_HARDWARE),true)
    include hardware/qcom-caf/common/BoardConfigQcom.mk
    include vendor/yasvara/sepolicy/qcom/sepolicy.mk
endif

include vendor/yasvara/config/BoardConfigSoong.mk
include vendor/yasvara/build/core/config.mk

# Yasvara system_ext + common SELinux policy.
include vendor/yasvara/sepolicy/sepolicy.mk

ifeq ($(TARGET_USES_PREBUILT_VENDOR_SEPOLICY),true)
-include vendor/yasvara/config/BoardConfigReservedSize.mk
endif
