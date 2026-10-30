#
# SPDX-FileCopyrightText: The Yasvara Project
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Rootless, ROM-integrated Xposed (Vector / LSPlant). The runtime is only ever loaded into
# processes the user scoped; see vendor/yasvara/xposed and the `// Yasvara:` seams in
# frameworks/base.
#

PRODUCT_PACKAGES += \
    libyasvara_xposed \
    yasvara-xposed
