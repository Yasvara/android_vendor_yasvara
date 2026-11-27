/*
 * Copyright (C) 2026 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.android.rkpdapp.utils;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;

/**
 * Host checks for the unverified RKP boot-state claims.
 *
 * <p>Run from the AOSP source root ({@code src/}). Java sessions shadow
 * {@link android.os.SystemProperties} with the stub; the device build links the real
 * framework class instead. Also checks source-level contract drift: the wiring in
 * {@link UnverifiedDeviceInfo} must source Yapvara's claim hook, and the canonical
 * digest property must keep its publisher contract (lowercase hex, 64/128).
 */
public final class RkpClaimsHostTest {
    private static int passed;
    private static int failed;

    public static void main(String[] args) throws Exception {
        check("disabled when trickystore=0", map(PROP_TRICKY, "0"), Map.of());
        check("disabled when rkp_spoof=0", combined(
                PROP_TRICKY, "1",
                PROP_SPOOF, "0"), Map.of());
        check("disabled when rkp_spoof unset (opt-in default off)",
                combined(PROP_DIGEST, "ab".repeat(32)), Map.of());
        check("disabled when digest missing", combined(PROP_SPOOF, "1", PROP_DIGEST, ""), Map.of());
        check("disabled when digest 63 hex",
                combined(PROP_SPOOF, "1", PROP_DIGEST, "ab".repeat(31) + "a"), Map.of());
        check("disabled when digest 128+1 hex",
                combined(PROP_SPOOF, "1", PROP_DIGEST, "ab".repeat(64) + "a"), Map.of());
        check("disabled when digest non-hex",
                combined(PROP_SPOOF, "1", PROP_DIGEST, "g".repeat(64)), Map.of());
        check("disabled when digest uppercase",
                combined(PROP_SPOOF, "1", PROP_DIGEST, "AB".repeat(32)), Map.of());
        check("disabled when digest all-zero sha256",
                combined(PROP_SPOOF, "1", PROP_DIGEST, "00".repeat(32)), Map.of());
        check("disabled when digest all-zero sha512",
                combined(PROP_SPOOF, "1", PROP_DIGEST, "00".repeat(64)), Map.of());

        Map<String, String> expected64 = Map.of(
                "vb_state", "green",
                "bootloader_state", "locked",
                "vbmeta_digest", "ab".repeat(32));
        check("claims with canonical sha256 digest when rkp_spoof=1",
                combined(PROP_SPOOF, "1", PROP_DIGEST, "ab".repeat(32)), expected64);
        check("claims with canonical sha512 digest when rkp_spoof=1",
                combined(PROP_SPOOF, "1", PROP_DIGEST, "cd".repeat(64)),
                Map.of(
                        "vb_state", "green",
                        "bootloader_state", "locked",
                        "vbmeta_digest", "cd".repeat(64)));

        checkSourceWiring();

        System.out.printf("RkpClaims host: %d cases, %d checks, %d failures%n",
                CASES, passed, failed);
        if (failed > 0) System.exit(1);
    }

    private static final String PROP_TRICKY = "persist.sys.yasvara.trickystore";
    private static final String PROP_SPOOF = "persist.sys.yasvara.rkp_spoof";
    private static final String PROP_DIGEST = "ro.yasvara.boot.digest";
    private static int CASES;

    private static void check(String name, Map<String, String> props,
            Map<String, String> expected) {
        CASES++;
        android.os.SystemProperties.OVERRIDE.putAll(props);
        Map<String, String> actual = YasvaraRkpClaims.claims();
        android.os.SystemProperties.OVERRIDE.clear();
        if (!actual.equals(expected)) {
            failed++;
            System.out.println("FAIL " + name + " expected=" + expected + " actual=" + actual);
            return;
        }
        System.out.println("PASS " + name);
        passed++;
    }

    private static Map<String, String> map(String key, String value) {
        Map<String, String> props = new HashMap<>();
        props.put(key, value);
        return props;
    }

    private static Map<String, String> combined(String a, String av) {
        return map(a, av);
    }

    private static Map<String, String> combined(String a, String av, String b, String bv) {
        Map<String, String> props = new HashMap<>();
        props.put(a, av);
        props.put(b, bv);
        return props;
    }

    private static void checkSourceWiring() throws IOException {
        CASES++;
        String claims = Files.readString(Path.of(
                "packages/modules/RemoteKeyProvisioning/app/src/com/android/rkpdapp/utils/"
                        + "YasvaraRkpClaims.java"));
        String unverified = Files.readString(Path.of(
                "packages/modules/RemoteKeyProvisioning/app/src/com/android/rkpdapp/utils/"
                        + "UnverifiedDeviceInfo.java"));
        boolean wiring = unverified.contains("YasvaraRkpClaims.claims()")
                && claims.contains(PROP_DIGEST)
                && claims.contains(PROP_TRICKY)
                && claims.contains(PROP_SPOOF)
                && claims.contains("\"vb_state\"")
                && claims.contains("\"bootloader_state\"")
                && claims.contains("\"vbmeta_digest\"");
        if (!wiring) {
            failed++;
            System.out.println("FAIL source contract drift in claims wiring");
            return;
        }
        System.out.println("PASS source contract: UnverifiedDeviceInfo wires yasvara claims");
        passed++;
    }
}
