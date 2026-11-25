/*
 * SPDX-FileCopyrightText: The Yasvara Project
 * SPDX-License-Identifier: Apache-2.0
 */
import android.security.yasvara.YasvaraTabirPolicy;

import com.android.server.yasvara.visibility.AppVisibilityPolicy;

public final class AppVisibilityPolicyTest {
    private static int sPassed;
    private static int sFailed;

    private static void check(String name, boolean ok) {
        System.out.println((ok ? "PASS " : "FAIL ") + name);
        if (ok) {
            sPassed++;
        } else {
            sFailed++;
        }
    }

    public static void main(String[] args) {
        final int systemUid = 1000;
        final int sysUiAppId = 10050;
        final int larasAppId = 10088;
        final int launcher = 10121;
        final int targetRoot = 10182;
        final int targetXposed = 10183;
        final int normalUserApp = 10201;
        final int whitelistedPeer = 10205;
        final int globalObserver = 10300;
        final int blacklistObserver = 10310;
        final int whitelistObserver = 10320;
        final int sdkSandboxUid = 20100;

        // 1. Legacy M1/M2 Global Selected & All-Except compatibility.
        AppVisibilityPolicy selected =
                AppVisibilityPolicy.selected(
                        new int[] {targetRoot, 10001}, new int[] {globalObserver, 10002});
        check("selected: observer denied", selected.hides(globalObserver, targetRoot));
        check("selected: unlisted caller allowed", !selected.hides(launcher, targetRoot));
        check("selected: unhidden target visible", !selected.hides(globalObserver, normalUserApp));
        check("selected: self never hidden", !selected.hides(targetRoot, targetRoot));

        AppVisibilityPolicy all =
                AppVisibilityPolicy.allExcept(
                        new int[] {targetRoot}, new int[] {launcher, 10002});
        check("all: unknown caller denied", all.hides(globalObserver, targetRoot));
        check("all: allowed caller sees it", !all.hides(launcher, targetRoot));
        check("all: unhidden target visible", !all.hides(globalObserver, normalUserApp));

        AppVisibilityPolicy empty = AppVisibilityPolicy.allExcept(new int[0], new int[0]);
        check("empty: nothing hidden", !empty.hides(globalObserver, targetRoot));

        // 2. Shared uid:1000 ROM packages + Dedicated-UID Laras + Per-Observer Blacklist/Whitelist.
        String[] globalRomPkgs = new String[] {
                "lineageos.platform",
                "org.lineageos.lineageparts",
                "org.yasvara.laras"
        };
        String[] knownRomPkgs = new String[] {
                "lineageos.platform",
                "org.lineageos.aperture",
                "org.lineageos.lineageparts",
                "org.yasvara.laras"
        };

        YasvaraTabirPolicy fullPolicy = new YasvaraTabirPolicy.Builder()
                .setExemptCallers(new int[] {sysUiAppId, larasAppId, launcher})
                .setProtectedSystemAppIds(new int[] {sysUiAppId, launcher})
                .setKnownHideableRomPackages(knownRomPkgs)
                .setXposedModuleAppIds(new int[] {targetXposed})
                .setGlobalSelected(
                        new int[] {targetRoot, larasAppId},
                        globalRomPkgs,
                        new int[] {globalObserver})
                .setObserverOverrides(
                        new int[] {blacklistObserver, whitelistObserver, launcher},
                        new int[] {
                                YasvaraTabirPolicy.MODE_BLACKLIST,
                                YasvaraTabirPolicy.MODE_WHITELIST,
                                YasvaraTabirPolicy.MODE_WHITELIST
                        },
                        new int[][] {
                                new int[] {targetRoot, targetXposed, larasAppId},
                                new int[] {whitelistedPeer},
                                new int[0]
                        },
                        new String[][] {
                                new String[] {"org.lineageos.lineageparts", "org.yasvara.laras"},
                                new String[] {"org.lineageos.aperture"},
                                new String[0]
                        })
                .setDevHideMode(YasvaraTabirPolicy.DEV_HIDE_OBSERVERS)
                .build();

        AppVisibilityPolicy.install(fullPolicy);

        // 2a. Shared system UID 1000 safety: LineageParts hidden, "android" & Settings intact!
        check("uid1000: LineageParts hidden from global observer",
                AppVisibilityPolicy.shouldHide(
                        globalObserver, systemUid, "org.lineageos.lineageparts"));
        check("uid1000: lineageos.platform hidden from global observer",
                AppVisibilityPolicy.shouldHide(
                        globalObserver, systemUid, "lineageos.platform"));
        check("uid1000: core 'android' package NEVER hidden",
                !AppVisibilityPolicy.shouldHide(globalObserver, systemUid, "android"));
        check("uid1000: com.android.settings (uid 1000) NEVER hidden",
                !AppVisibilityPolicy.shouldHide(
                        globalObserver, systemUid, "com.android.settings"));
        check("uid1000: checkUidPermission(1000) NEVER blocked",
                !YasvaraTabirPolicy.shouldHideUid(globalObserver, systemUid));

        // 2b. Dedicated-UID Laras: hidden as target (package + UID), exempt as caller!
        check("laras: hidden by package from observer",
                AppVisibilityPolicy.shouldHide(globalObserver, larasAppId, "org.yasvara.laras"));
        check("laras: hidden by UID (checkUidPermission) from observer",
                YasvaraTabirPolicy.shouldHideUid(globalObserver, larasAppId));
        check("laras: exempt caller sees hidden root app",
                !AppVisibilityPolicy.shouldHide(larasAppId, targetRoot, "com.topjohnwu.magisk"));
        check("laras: exempt caller sees LineageParts",
                !AppVisibilityPolicy.shouldHide(
                        larasAppId, systemUid, "org.lineageos.lineageparts"));
        check("system caller (<10000): never filtered",
                !AppVisibilityPolicy.shouldHide(systemUid, targetRoot, "com.topjohnwu.magisk"));
        check("sdk sandbox (>19999): outside app UID range in Tabir",
                !AppVisibilityPolicy.shouldHide(sdkSandboxUid, targetRoot, "com.topjohnwu.magisk"));

        // 2c. Per-Observer Blacklist override (even when not in globalObservers!).
        check("blacklist override: hides custom Xposed module",
                AppVisibilityPolicy.shouldHide(blacklistObserver, targetXposed, "org.lsposed.mod"));
        check("blacklist override: hides UID on checkUidPermission",
                YasvaraTabirPolicy.shouldHideUid(blacklistObserver, targetXposed));
        check("blacklist override: normal user app stays visible",
                !AppVisibilityPolicy.shouldHide(
                        blacklistObserver, normalUserApp, "com.whatsapp"));

        // 2d. Per-Observer Whitelist override (HMA-OSS banking mode).
        check("whitelist override: hides unwhitelisted normal user app",
                AppVisibilityPolicy.shouldHide(
                        whitelistObserver, normalUserApp, "com.whatsapp"));
        check("whitelist override: hides unwhitelisted UID on checkUidPermission",
                YasvaraTabirPolicy.shouldHideUid(whitelistObserver, normalUserApp));
        check("whitelist override: allows whitelisted peer app",
                !AppVisibilityPolicy.shouldHide(
                        whitelistObserver, whitelistedPeer, "com.google.android.apps.authenticator2"));
        check("whitelist override: allows protected non-ROM system app (SystemUI)",
                !AppVisibilityPolicy.shouldHide(
                        whitelistObserver, sysUiAppId, "com.android.systemui"));
        check("whitelist override: allows protected non-ROM system UID",
                !YasvaraTabirPolicy.shouldHideUid(whitelistObserver, sysUiAppId));
        check("whitelist override: hides unwhitelisted ROM pkg (LineageParts)",
                AppVisibilityPolicy.shouldHide(
                        whitelistObserver, systemUid, "org.lineageos.lineageparts"));
        check("whitelist override: allows explicitly whitelisted ROM camera (Aperture)",
                !AppVisibilityPolicy.shouldHide(
                        whitelistObserver, 10099, "org.lineageos.aperture"));
        check("whitelist override: hides Laras dedicated UID when unwhitelisted",
                YasvaraTabirPolicy.shouldHideUid(whitelistObserver, larasAppId));
        check("exempt launcher: never filtered even if accidentally placed in overrides",
                !AppVisibilityPolicy.shouldHide(launcher, normalUserApp, "com.whatsapp"));

        // 2e. Xposed metadata strip fast-path gate (avoids unparceling Bundles on normal packages).
        check("stripXposed: true for non-exempt caller inspecting Xposed module",
                YasvaraTabirPolicy.shouldStripXposedMetaData(globalObserver, targetXposed));
        check("stripXposed: false for non-Xposed target package",
                !YasvaraTabirPolicy.shouldStripXposedMetaData(globalObserver, normalUserApp));
        check("stripXposed: false for exempt caller (Laras/Launcher)",
                !YasvaraTabirPolicy.shouldStripXposedMetaData(larasAppId, targetXposed));
        check("stripXposed: false for self query",
                !YasvaraTabirPolicy.shouldStripXposedMetaData(targetXposed, targetXposed));
        check("stripXposed: false for system caller",
                !YasvaraTabirPolicy.shouldStripXposedMetaData(systemUid, targetXposed));

        // 3. Developer Options & ADB Settings / Sticky USB Broadcast concealment.
        check("devKey: adb_enabled matched",
                YasvaraTabirPolicy.isDevConcealedGlobalKey("adb_enabled"));
        check("devKey: adb_wifi_enabled matched",
                YasvaraTabirPolicy.isDevConcealedGlobalKey("adb_wifi_enabled"));
        check("devKey: development_settings_enabled matched",
                YasvaraTabirPolicy.isDevConcealedGlobalKey("development_settings_enabled"));
        check("devKey: animator_duration_scale ignored",
                !YasvaraTabirPolicy.isDevConcealedGlobalKey("animator_duration_scale"));
        check("devKey: null ignored",
                !YasvaraTabirPolicy.isDevConcealedGlobalKey(null));

        check("devHide(OBSERVERS): concealed from globalObserver",
                YasvaraTabirPolicy.shouldConcealDevSettings(globalObserver));
        check("devHide(OBSERVERS): concealed from per-app whitelistObserver",
                YasvaraTabirPolicy.shouldConcealDevSettings(whitelistObserver));
        check("devHide(OBSERVERS): NOT concealed from normalUserApp",
                !YasvaraTabirPolicy.shouldConcealDevSettings(normalUserApp));
        check("devHide(OBSERVERS): NOT concealed from exempt Laras",
                !YasvaraTabirPolicy.shouldConcealDevSettings(larasAppId));

        YasvaraTabirPolicy devAllPolicy = new YasvaraTabirPolicy.Builder()
                .setExemptCallers(new int[] {sysUiAppId, larasAppId, launcher})
                .setDevHideMode(YasvaraTabirPolicy.DEV_HIDE_ALL_NON_SYSTEM)
                .build();
        AppVisibilityPolicy.install(devAllPolicy);
        check("devHide(ALL_NON_SYSTEM): concealed from normalUserApp even when hidden list empty",
                YasvaraTabirPolicy.shouldConcealDevSettings(normalUserApp));
        check("devHide(ALL_NON_SYSTEM): NOT concealed from exempt Launcher",
                !YasvaraTabirPolicy.shouldConcealDevSettings(launcher));
        check("devHide(ALL_NON_SYSTEM): NOT concealed from system UID 1000",
                !YasvaraTabirPolicy.shouldConcealDevSettings(systemUid));

        // 4. Performance benchmarks (must stay sub-50ns even with 300 global + 32 per-app rules).
        AppVisibilityPolicy.install(empty);
        double nsEmpty = costPackage();
        System.out.printf("cost empty: %.2f ns%n", nsEmpty);
        check("perf: empty fast-path < 5.0 ns", nsEmpty < 5.0);

        int[] many = new int[300];
        for (int i = 0; i < many.length; i++) many[i] = 10000 + i * 2;
        int[] ovCallers = new int[32];
        int[] ovModes = new int[32];
        int[][] ovApps = new int[32][];
        String[][] ovRoms = new String[32][];
        for (int i = 0; i < 32; i++) {
            ovCallers[i] = 10800 + i * 3;
            ovModes[i] = (i & 1) == 0
                    ? YasvaraTabirPolicy.MODE_BLACKLIST
                    : YasvaraTabirPolicy.MODE_WHITELIST;
            ovApps[i] = new int[] {10002, 10050, 10100, 10200, 10300};
            ovRoms[i] = new String[] {"org.lineageos.lineageparts", "org.yasvara.laras"};
        }
        YasvaraTabirPolicy heavy = new YasvaraTabirPolicy.Builder()
                .setGlobalAllExcept(many, globalRomPkgs, many)
                .setExemptCallers(new int[] {sysUiAppId, larasAppId, launcher})
                .setProtectedSystemAppIds(new int[] {sysUiAppId, launcher})
                .setKnownHideableRomPackages(knownRomPkgs)
                .setObserverOverrides(ovCallers, ovModes, ovApps, ovRoms)
                .setDevHideMode(YasvaraTabirPolicy.DEV_HIDE_ALL_NON_SYSTEM)
                .build();
        AppVisibilityPolicy.install(heavy);
        double nsHeavy = costPackage();
        System.out.printf("cost 300 global + 32 per-app overrides: %.2f ns%n", nsHeavy);
        check("perf: 300 global + 32 overrides < 50.0 ns", nsHeavy < 50.0);

        System.out.printf("Summary: %d passed, %d failed%n", sPassed, sFailed);
        if (sFailed > 0) System.exit(1);
    }

    private static double costPackage() {
        final int n = 20_000_000;
        int hits = 0;
        for (int pass = 0; pass < 2; pass++) {
            long start = System.nanoTime();
            for (int i = 0; i < n; i++) {
                if (AppVisibilityPolicy.shouldHide(
                        10000 + (i & 1023), 10000 + ((i >> 3) & 1023), "com.example.app")) {
                    hits++;
                }
            }
            if (pass == 1) {
                double ns = (System.nanoTime() - start) / (double) n;
                if (hits < 0) throw new AssertionError();
                return ns;
            }
        }
        return 0;
    }
}
