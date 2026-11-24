/*
 * SPDX-FileCopyrightText: The Yasvara Project
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
package org.yasvara.ketik.hook;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import java.io.File;
import java.util.Collections;

public final class DexFingerprinterTest {

    @Test
    public void handlesEmptyAndInvalidDexGracefully() {
        DexFingerprinter.Resolved r = new DexFingerprinter.Resolved();
        DexFingerprinter.scanDex(null, r);
        DexFingerprinter.scanDex(new byte[16], r);
        DexFingerprinter.scanDex(new byte[256], r);
        assertFalse(r.hasGenAiRoute());
        assertFalse(r.hasFlagManager());
    }

    @Test
    public void resolvesBothGboardVersionsWhenPresent() throws Exception {
        final File apk1856 = new File(
                "/home/ireddragonicy/Data/projects/onyx/los_workspace/lab/gboard-flags/apk/"
                        + "18.5.6.993608717-beta-arm64-v8a/base.apk");
        if (apk1856.isFile()) {
            DexFingerprinter.Resolved r = DexFingerprinter.scanApks(
                    Collections.singletonList(apk1856));
            assertTrue("18.5.6 complete: " + r, r.isComplete());
            assertEquals("ahux", r.proofreadTagClass);
            assertEquals("b", r.handlerGetterMethod);
            assertEquals("a", r.refreshTagsMethod);
            assertEquals("agxa", r.readinessClass);
            assertEquals("e", r.isReadyMethod);
            assertEquals("adov", r.serverGenAiClass);
        }

        final File apk1880 = new File(
                "/home/ireddragonicy/Data/projects/onyx/los_workspace/lab/gboard-flags/apk/"
                        + "18.8.0.1022711984-beta-arm64-v8a/base.apk");
        if (apk1880.isFile()) {
            DexFingerprinter.Resolved r = DexFingerprinter.scanApks(
                    Collections.singletonList(apk1880));
            assertTrue("18.8.0 complete: " + r, r.isComplete());
            assertEquals("aicd", r.proofreadTagClass);
            assertEquals("b", r.handlerGetterMethod);
            assertEquals("a", r.refreshTagsMethod);
            assertEquals("aheb", r.readinessClass);
            assertEquals("f", r.isReadyMethod);
            assertEquals("adfy", r.flagManagerClass);
            assertEquals("j", r.createFlagMethod);
            assertEquals("adtl", r.serverGenAiClass);
        }
    }
}
