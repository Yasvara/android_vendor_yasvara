# SPDX-FileCopyrightText: The Yasvara Project
# SPDX-License-Identifier: Apache-2.0
#
# Device-independent Yasvara system_ext + common policy.
# Included from vendor/yasvara/config/BoardConfigYasvara.mk for every device.

SYSTEM_EXT_PUBLIC_SEPOLICY_DIRS += vendor/yasvara/sepolicy/public
SYSTEM_EXT_PRIVATE_SEPOLICY_DIRS += vendor/yasvara/sepolicy/private

include vendor/yasvara/sepolicy/common/sepolicy.mk
