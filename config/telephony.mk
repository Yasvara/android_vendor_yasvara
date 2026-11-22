#
# SPDX-FileCopyrightText: The Yasvara Project
# SPDX-License-Identifier: Apache-2.0
#

ifeq ($(WITH_GMS),true)
WITH_GMS_COMMS_SUITE := true
endif

# World APN list
PRODUCT_PACKAGES += \
    apns-conf.xml

# Telephony packages
PRODUCT_PACKAGES += \
    Stk

# Default ringtone
PRODUCT_PRODUCT_PROPERTIES += \
    ro.config.ringtone=Orion.ogg

# Tethering without carrier provisioning check
PRODUCT_PRODUCT_PROPERTIES += \
    net.tethering.noprovisioning=true

# Disable mobile data by default until user enables
PRODUCT_PRODUCT_PROPERTIES += \
    ro.com.android.mobiledata=false
