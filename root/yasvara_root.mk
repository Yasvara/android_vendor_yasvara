#
# SPDX-FileCopyrightText: The Yasvara Project
# SPDX-License-Identifier: Apache-2.0
#
# SPEC-0006 native root. Debuggable builds only: the root shell is AOSP's userdebug `su`
# domain, which does not exist (as a permissive domain) in `user` builds.
#

ifneq ($(TARGET_BUILD_VARIANT),user)
PRODUCT_PACKAGES += \
    yasvara_rootd \
    yasvara_su \
    yasvara_su_xbin_link
endif
