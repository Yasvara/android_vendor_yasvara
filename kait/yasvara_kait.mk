#
# SPDX-FileCopyrightText: The Yasvara Project
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Kait — ROM-native, rootless hooking framework (Rust core + ROM-ART seam).
# Loaded only into processes system_server flags with Zygote.YASVARA_KAIT.
#

PRODUCT_PACKAGES += \
    libyasvara_kait \
    yasvara-kait
