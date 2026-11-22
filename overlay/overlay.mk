#
# SPDX-FileCopyrightText: The Yasvara Project
# SPDX-License-Identifier: Apache-2.0
#
# Yasvara brand strings and icons for the Lineage apps. Merged into the APKs
# at build time (kept out of RRO enforcement), so the built APKs carry no LineageOS branding;
# vendor/yasvara/tests/branding/visible_lineage.sh checks them.
#

PRODUCT_ENFORCE_RRO_EXCLUDED_OVERLAYS += vendor/yasvara/overlay/no-rro
PRODUCT_PACKAGE_OVERLAYS += vendor/yasvara/overlay/no-rro
