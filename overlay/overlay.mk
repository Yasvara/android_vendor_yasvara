#
# SPDX-FileCopyrightText: The Yasvara Project
# SPDX-License-Identifier: Apache-2.0
#

PRODUCT_ENFORCE_RRO_EXCLUDED_OVERLAYS += vendor/yasvara/overlay/no-rro
PRODUCT_PACKAGE_OVERLAYS +=     vendor/yasvara/overlay/common     vendor/yasvara/overlay/no-rro
