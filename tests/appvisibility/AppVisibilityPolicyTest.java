/*
 * SPDX-FileCopyrightText: The Yasvara Project
 * SPDX-License-Identifier: Apache-2.0
 */
import android.security.yasvara.YasvaraRiskCacheReset;
import android.security.yasvara.YasvaraTabirPolicy;

import com.android.server.yasvara.visibility.AppVisibilityPolicy;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Locale;

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
        check("devHide(ALL_NON_SYSTEM): concealed from isolated worker UID 90005",
                YasvaraTabirPolicy.shouldConcealDevSettings(90005));
        check("devHide(ALL_NON_SYSTEM): concealed from isolated app UID 99012",
                YasvaraTabirPolicy.shouldConcealDevSettings(99012));

        YasvaraTabirPolicy isolatedPolicy = new YasvaraTabirPolicy.Builder()
                .setExemptCallers(new int[] {sysUiAppId, larasAppId, launcher})
                .setXposedModuleAppIds(new int[] {targetXposed})
                .setGlobalAllExcept(new int[] {targetRoot}, globalRomPkgs, new int[] {launcher})
                .setDevHideMode(YasvaraTabirPolicy.DEV_HIDE_OBSERVERS)
                .build();
        AppVisibilityPolicy.install(isolatedPolicy);
        check("isolated: Xposed metadata stripped for isolated worker UID 99012",
                YasvaraTabirPolicy.shouldStripXposedMetaData(99012, targetXposed));
        check("isolated: global all-except hides root pkg from isolated worker UID 99012",
                AppVisibilityPolicy.shouldHide(99012, targetRoot, "com.topjohnwu.magisk"));
        check("isolated: devHide(OBSERVERS) + all-except conceals from isolated worker UID 99012",
                YasvaraTabirPolicy.shouldConcealDevSettings(99012));

        // 4. Real-World App Scenarios: Shopee/SeaBank + Duck Detector + Risk/DFP Filesystem Reset.
        testShopeeSeaBankRealWorldScenario();
        testDuckDetectorRealWorldScenario();
        testShopeeRiskCacheResetFilesystem();

        // 5. Performance benchmarks (must stay sub-50ns even with 300 global + 32 per-app rules).
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

    /**
     * Realistic simulation of Shopee Indonesia (com.shopee.id + isolated SeaBank worker u0_i12)
     * in Tabir Whitelist ("Perbankan Ketat") mode with 20+ realistic installed system, ROM,
     * MindTheGapps, root/detection, Xposed (user + system), and ordinary user packages.
     */
    private static void testShopeeSeaBankRealWorldScenario() {
        final int systemUid = 1000;
        final int sysUi = 10050;
        final int laras = 10088;
        final int launcher = 10121;
        final int webview = 10110;
        final int gms = 10115;
        final int vending = 10116;
        final int gboard = 10118;
        final int mtgOverlay = 10095;
        final int ketikHookSys = 10097;   // FLAG_SYSTEM Xposed module!
        final int kaitTestSys = 10098;    // FLAG_SYSTEM Xposed module!
        final int vtools = 10201;         // Scene (also Xposed module!)
        final int termux = 10202;
        final int keyAttestation = 10203;
        final int integrityCheck = 10204;
        final int duckDetector = 10205;
        final int ksuWebUi = 10206;
        final int alihBridge = 10210;     // User Xposed module
        final int zarchiver = 10302;
        final int qiblaku = 10303;
        final int shopee = 10342;
        final int shopeeWorkProfile = 110342; // Secondary user 10 (10*100000 + 10342)
        final int seabankPeer = 10343;
        final int shopeeIsolatedBank = 99012; // com.shopee.id:wvvvuvww_bank (u0_i12)
        final int shopeeAppZygote = 90005;

        String[] knownRomPkgs = new String[] {
                "com.mtg.overlay.setupwizard",
                "lineageos.platform",
                "org.lineageos.lineageparts",
                "org.yasvara.kaittest",
                "org.yasvara.ketik.hook",
                "org.yasvara.laras",
                "org.yasvara.overlay.googlewebview",
        };
        int[] xposedModules = new int[] {ketikHookSys, kaitTestSys, vtools, alihBridge};

        YasvaraTabirPolicy shopeePolicy = new YasvaraTabirPolicy.Builder()
                .setExemptCallers(new int[] {sysUi, laras, launcher})
                .setProtectedSystemAppIds(new int[] {sysUi, launcher, webview, gms, vending, gboard})
                .setKnownHideableRomPackages(knownRomPkgs)
                .setXposedModuleAppIds(xposedModules)
                .setGlobalSelected(
                        new int[] {vtools, termux, keyAttestation, integrityCheck, duckDetector,
                                ksuWebUi, alihBridge, ketikHookSys, kaitTestSys, laras, mtgOverlay},
                        knownRomPkgs,
                        new int[] {shopee})
                .setObserverOverrides(
                        new int[] {shopee},
                        new int[] {YasvaraTabirPolicy.MODE_WHITELIST},
                        new int[][] {new int[] {seabankPeer}},
                        new String[][] {new String[0]})
                .setDevHideMode(YasvaraTabirPolicy.DEV_HIDE_ALL_NON_SYSTEM)
                .build();

        AppVisibilityPolicy.install(shopeePolicy);

        // Both main Shopee UID and work-profile Shopee UID must have identical strict isolation.
        for (int caller : new int[] {shopee, shopeeWorkProfile}) {
            String tag = caller == shopee ? "shopee(u0)" : "shopee(u10)";
            check(tag + ": sees self", !AppVisibilityPolicy.shouldHide(caller, shopee, "com.shopee.id"));
            check(tag + ": sees whitelisted SeaBank peer",
                    !AppVisibilityPolicy.shouldHide(caller, seabankPeer, "id.co.bankbkemobile.digitalbank"));
            check(tag + ": sees core android/webview/gms/vending/gboard",
                    !AppVisibilityPolicy.shouldHide(caller, systemUid, "android")
                    && !AppVisibilityPolicy.shouldHide(caller, webview, "com.google.android.webview")
                    && !AppVisibilityPolicy.shouldHide(caller, gms, "com.google.android.gms")
                    && !AppVisibilityPolicy.shouldHide(caller, vending, "com.android.vending")
                    && !AppVisibilityPolicy.shouldHide(caller, gboard, "com.google.android.inputmethod.latin"));

            // Every dangerous / root / detection / Xposed / ROM / MTG / unwhitelisted 3rd-party app MUST be hidden.
            check(tag + ": hides Scene (com.omarea.vtools)",
                    AppVisibilityPolicy.shouldHide(caller, vtools, "com.omarea.vtools"));
            check(tag + ": hides Termux (com.termux)",
                    AppVisibilityPolicy.shouldHide(caller, termux, "com.termux"));
            check(tag + ": hides KeyAttestation",
                    AppVisibilityPolicy.shouldHide(caller, keyAttestation, "io.github.vvb2060.keyattestation"));
            check(tag + ": hides IntegrityCheck",
                    AppVisibilityPolicy.shouldHide(caller, integrityCheck, "gr.nikolasspyr.integritycheck"));
            check(tag + ": hides DuckDetector",
                    AppVisibilityPolicy.shouldHide(caller, duckDetector, "com.eltavine.duckdetector"));
            check(tag + ": hides KsuWebUI",
                    AppVisibilityPolicy.shouldHide(caller, ksuWebUi, "io.github.a13e300.ksuwebui"));
            check(tag + ": hides MindTheGapps overlay (com.mtg.*)",
                    AppVisibilityPolicy.shouldHide(caller, mtgOverlay, "com.mtg.overlay.setupwizard"));
            check(tag + ": hides ROM LineageParts (shared uid 1000) without blocking android",
                    AppVisibilityPolicy.shouldHide(caller, systemUid, "org.lineageos.lineageparts")
                    && !YasvaraTabirPolicy.shouldHideUid(caller, systemUid));
            check(tag + ": hides Laras (package + UID)",
                    AppVisibilityPolicy.shouldHide(caller, laras, "org.yasvara.laras")
                    && YasvaraTabirPolicy.shouldHideUid(caller, laras));
            check(tag + ": hides system Xposed modules (ketik.hook + kaittest)",
                    AppVisibilityPolicy.shouldHide(caller, ketikHookSys, "org.yasvara.ketik.hook")
                    && AppVisibilityPolicy.shouldHide(caller, kaitTestSys, "org.yasvara.kaittest"));
            check(tag + ": hides unwhitelisted 3rd-party apps (ZArchiver + Qiblaku)",
                    AppVisibilityPolicy.shouldHide(caller, zarchiver, "ru.zdevs.zarchiver")
                    && AppVisibilityPolicy.shouldHide(caller, qiblaku, "com.qiblaku.app"));
            check(tag + ": checkUidPermission hides vtools & zarchiver UIDs",
                    YasvaraTabirPolicy.shouldHideUid(caller, vtools)
                    && YasvaraTabirPolicy.shouldHideUid(caller, zarchiver));
            check(tag + ": ADB/DevOptions concealed",
                    YasvaraTabirPolicy.shouldConcealDevSettings(caller));
        }

        // Shopee isolated SeaBank subprocess (u0_i12 = 99012) & app_zygote (90005).
        for (int iso : new int[] {shopeeIsolatedBank, shopeeAppZygote}) {
            check("shopee isolated(" + iso + "): ADB/DevOptions concealed",
                    YasvaraTabirPolicy.shouldConcealDevSettings(iso));
            for (int mod : xposedModules) {
                check("shopee isolated(" + iso + "): Xposed metadata stripped for appId " + mod,
                        YasvaraTabirPolicy.shouldStripXposedMetaData(iso, mod));
            }
        }
    }

    /**
     * Realistic simulation of Duck Detector (com.eltavine.duckdetector) regression found on live
     * device: reproduces both the "not in observers" case (where Xposed metadata MUST STILL be
     * stripped for all 4 modules including system modules!) and the "enrolled observer" case
     * (where Dangerous Apps like Scene/Termux are also hidden).
     */
    private static void testDuckDetectorRealWorldScenario() {
        final int sysUi = 10050;
        final int laras = 10088;
        final int launcher = 10121;
        final int ketikHookSys = 10097;
        final int kaitTestSys = 10098;
        final int alihBridge = 10210;
        final int vtools = 10201;
        final int termux = 10202;
        final int duckDetector = 10205;
        final int shopee = 10342;
        final int normalApp = 10400;

        int[] allFourXposed = new int[] {ketikHookSys, kaitTestSys, alihBridge, vtools};
        String[] romPkgs = new String[] {
                "org.yasvara.ketik.hook", "org.yasvara.kaittest", "org.yasvara.laras",
        };

        // Case A: Duck Detector accidentally NOT in observers (matches live device misconfig).
        // Even then, Xposed meta-data MUST be stripped for all 4 modules (2 user + 2 system)!
        YasvaraTabirPolicy unlistedDuck = new YasvaraTabirPolicy.Builder()
                .setExemptCallers(new int[] {sysUi, laras, launcher})
                .setKnownHideableRomPackages(romPkgs)
                .setXposedModuleAppIds(allFourXposed)
                .setGlobalSelected(
                        new int[] {vtools, termux, alihBridge, ketikHookSys, kaitTestSys},
                        romPkgs,
                        new int[] {shopee})
                .build();
        AppVisibilityPolicy.install(unlistedDuck);

        for (int mod : allFourXposed) {
            check("duck(unlisted): strips Xposed meta-data for appId " + mod,
                    YasvaraTabirPolicy.shouldStripXposedMetaData(duckDetector, mod));
        }
        check("duck(unlisted): does not waste work stripping non-Xposed app",
                !YasvaraTabirPolicy.shouldStripXposedMetaData(duckDetector, normalApp));
        check("duck(unlisted): Laras/Kait manager still sees all 4 Xposed modules intact",
                !YasvaraTabirPolicy.shouldStripXposedMetaData(laras, ketikHookSys)
                && !YasvaraTabirPolicy.shouldStripXposedMetaData(laras, kaitTestSys)
                && !YasvaraTabirPolicy.shouldStripXposedMetaData(laras, alihBridge)
                && !YasvaraTabirPolicy.shouldStripXposedMetaData(laras, vtools));

        // Case B: Duck Detector properly enrolled as observer -> Dangerous Apps & Xposed all hidden!
        YasvaraTabirPolicy enrolledDuck = new YasvaraTabirPolicy.Builder()
                .setExemptCallers(new int[] {sysUi, laras, launcher})
                .setKnownHideableRomPackages(romPkgs)
                .setXposedModuleAppIds(allFourXposed)
                .setGlobalSelected(
                        new int[] {vtools, termux, alihBridge, ketikHookSys, kaitTestSys},
                        romPkgs,
                        new int[] {shopee, duckDetector})
                .build();
        AppVisibilityPolicy.install(enrolledDuck);

        check("duck(observer): hides Scene & Termux (Dangerous Apps = 0)",
                AppVisibilityPolicy.shouldHide(duckDetector, vtools, "com.omarea.vtools")
                && AppVisibilityPolicy.shouldHide(duckDetector, termux, "com.termux"));
        check("duck(observer): hides all 4 Xposed modules including system ketik.hook & kaittest",
                AppVisibilityPolicy.shouldHide(duckDetector, alihBridge, "org.yasvara.alih.bridge")
                && AppVisibilityPolicy.shouldHide(duckDetector, ketikHookSys, "org.yasvara.ketik.hook")
                && AppVisibilityPolicy.shouldHide(duckDetector, kaitTestSys, "org.yasvara.kaittest")
                && AppVisibilityPolicy.shouldHide(duckDetector, vtools, "com.omarea.vtools"));
    }

    /**
     * Executes the exact production {@link YasvaraRiskCacheReset} engine on a real simulated
     * Shopee/SeaBank filesystem tree (CE + DE + sibling app), proving stale key_dfp/risk stores
     * (including .xml.bak!) are purged while login/session/chat databases stay 100% intact,
     * zero "yasvara" filenames are created, symlinks cannot escape, and TTL/idempotency work.
     */
    private static void testShopeeRiskCacheResetFilesystem() {
        Path tmp = null;
        try {
            tmp = Files.createTempDirectory("tabir-shopee-dfp-test-");
            File ce = tmp.resolve("data_user_0/com.shopee.id").toFile();
            File de = tmp.resolve("data_user_de_0/com.shopee.id").toFile();
            File bca = tmp.resolve("data_user_0/com.bca.mobile").toFile();
            File outsideSecret = tmp.resolve("outside_precious.txt").toFile();
            writeText(outsideSecret, "MUST_NOT_BE_DELETED_VIA_SYMLINK");

            // Populate realistic Shopee + SeaBank CE storage (modeled on live device audit).
            File seabankMmkv = new File(ce, "files/mmkv/seabank_live_seabank_live_default_file");
            File seabankMmkvCrc = new File(ce, "files/mmkv/seabank_live_seabank_live_default_file.crc");
            File seabankDefaultMmkv = new File(ce, "files/mmkv/default_seabank_mmapid");
            File seabankDefaultMmkvCrc = new File(ce, "files/mmkv/default_seabank_mmapid.crc");
            File loginMmkv = new File(ce, "files/mmkv/shopee_user_session");
            File loginMmkvCrc = new File(ce, "files/mmkv/shopee_user_session.crc");
            File shpsCache = new File(ce, "files/shps_device_cache.dat");
            File mainShpsPrefs = new File(ce, "shared_prefs/SPHelper_sp_main.xml");
            File mainShpsPrefsBak = new File(ce, "shared_prefs/SPHelper_sp_main.xml.bak");
            File bankPrefs = new File(ce, "shared_prefs/SPHelper_sp_main_bank.xml");
            File bankPrefsBak = new File(ce, "shared_prefs/SPHelper_sp_main_bank.xml.bak");
            File trackerPrefs = new File(ce, "shared_prefs/Seabank_Tracker_SharedPreferences.xml");
            File tongdunPrefs = new File(ce, "shared_prefs/tongdun_dfp_cache.xml");
            File loginPrefs = new File(ce, "shared_prefs/shopee_login_prefs.xml");
            File eventDb = new File(ce, "databases/seabank_event.db");
            File eventDbWal = new File(ce, "databases/seabank_event.db-wal");
            File eventDbShm = new File(ce, "databases/seabank_event.db-shm");
            File chatDb = new File(ce, "databases/shopee_chat.db");
            File httpCache = new File(ce, "cache/http/response.bin");
            File jitCache = new File(ce, "code_cache/shader.bin");
            File deDfp = new File(de, "shared_prefs/device_fingerprint.xml");
            File bcaDfp = new File(bca, "shared_prefs/device_fp.xml");

            writeText(seabankMmkv, "key_dfp=poisoned_vtools_fingerprint_123");
            writeText(seabankMmkvCrc, "crc");
            writeText(seabankDefaultMmkv, "default_seabank_risk_cache");
            writeText(seabankDefaultMmkvCrc, "crc2");
            writeText(loginMmkv, "shopee_auth_token=KEEP_ME_LOGGED_IN");
            writeText(loginMmkvCrc, "crc_keep");
            writeText(shpsCache, "stale_shps_blob");
            writeText(mainShpsPrefs, "<map><string name=\"mini-uuid\">1791079758449</string></map>");
            writeText(mainShpsPrefsBak, "<map><string name=\"mini-uuid\">1791079758449_bak</string></map>");
            writeText(bankPrefs, "<map><string name=\"shps_dfp\">poisoned</string></map>");
            writeText(bankPrefsBak, "<map><string name=\"shps_dfp\">poisoned_bak</string></map>");
            writeText(trackerPrefs, "<map><string name=\"tracker\">old</string></map>");
            writeText(tongdunPrefs, "<map/>");
            writeText(loginPrefs, "<map><string name=\"cookie\">KEEP_SESSION</string></map>");
            writeText(eventDb, "sqlite_event");
            writeText(eventDbWal, "wal");
            writeText(eventDbShm, "shm");
            writeText(chatDb, "KEEP_CHAT_HISTORY");
            writeText(httpCache, "cached");
            writeText(jitCache, "shader");
            writeText(deDfp, "de_poisoned");
            writeText(bcaDfp, "bca_untouched");

            // Symlink escape guard inside risk directory.
            Path evilLink = ce.toPath().resolve("shared_prefs/risk_control_link.xml");
            Files.createSymbolicLink(evilLink, outsideSecret.toPath());

            // 1. Wire-format merge, TTL pruning, and validation.
            final long t0 = 1_760_000_000_000L;
            final long expired = t0 - YasvaraRiskCacheReset.ENTRY_TTL_MS - 10_000L;
            String raw = YasvaraRiskCacheReset.mergePackageEpoch(
                    "com.expired.app=" + expired + ",bad_entry,com.other=1759999999000",
                    "com.shopee.id", t0);
            check("riskReset: expired entry pruned & valid entries merged",
                    !raw.contains("com.expired.app")
                    && !raw.contains("bad_entry")
                    && "1759999999000".equals(YasvaraRiskCacheReset.parsePackageEpoch(raw, "com.other"))
                    && String.valueOf(t0).equals(YasvaraRiskCacheReset.parsePackageEpoch(raw, "com.shopee.id")));
            check("riskReset: whitespace-tolerant parsing & invalid package rejection",
                    "42".equals(YasvaraRiskCacheReset.parsePackageEpoch(" com.a = 1 , com.shopee.id = 42 ", "com.shopee.id"))
                    && YasvaraRiskCacheReset.parsePackageEpoch("com.shopee.id=not_digits", "com.shopee.id") == null
                    && !YasvaraRiskCacheReset.isValidPackageName("android")
                    && !YasvaraRiskCacheReset.isValidPackageName("com.a,com.b")
                    && !YasvaraRiskCacheReset.isValidPackageName("../etc"));

            // 1b. AndroidKeyStore stale attestation alias classification vs protected user/payment keys.
            String[] staleAliases = {
                "KeyAttestation_persistent",
                "KeyAttestation",
                "KeyAttestation_strongbox",
                "KeyAttestation_strongbox_persistent",
                "attest_key",
                "attest_key_v2",
                "bank_attest_key",
                "shps_key_attestation_v1",
            };
            for (String a : staleAliases) {
                check("riskReset(keystore): stale attestation alias matched: " + a,
                        YasvaraRiskCacheReset.isStaleAttestationAlias(a)
                        && !YasvaraRiskCacheReset.isProtectedKeyAlias(a));
            }
            String[] protectedAliases = {
                null,
                "",
                "sdb-id-sdk",
                "shopee_biometric_encryption_key",
                "BodyEncryptBean_Key",
                "touch_id_372464040",
                "com.shopee.bke.lib.biometric.utils.CipherHelper",
                "payment_pin_key",
                "wallet_attest_token",
                "user_session_key",
                "my_random_rsa_key",
            };
            for (String a : protectedAliases) {
                check("riskReset(keystore): user/payment/biometric alias preserved: " + a,
                        !YasvaraRiskCacheReset.isStaleAttestationAlias(a));
            }
            check("riskReset(keystore): real Shopee payment/biometric aliases are hard-protected",
                    YasvaraRiskCacheReset.isProtectedKeyAlias("sdb-id-sdk")
                    && YasvaraRiskCacheReset.isProtectedKeyAlias("shopee_biometric_encryption_key")
                    && YasvaraRiskCacheReset.isProtectedKeyAlias("BodyEncryptBean_Key")
                    && YasvaraRiskCacheReset.isProtectedKeyAlias("touch_id_372464040")
                    && YasvaraRiskCacheReset.isProtectedKeyAlias("com.shopee.bke.lib.biometric.utils.CipherHelper"));

            // 2. Execute real reset for com.shopee.id at epoch t0 with locked keystore callback.
            final int[] lockedCallbackCount = {0};
            boolean ran = YasvaraRiskCacheReset.applyIfNeeded(
                    ce, de, "com.shopee.id", raw, 4242, () -> lockedCallbackCount[0]++);
            check("riskReset(shopee): executed on new epoch and invoked locked callback once",
                    ran && lockedCallbackCount[0] == 1);

            // Risk/DFP/cache files MUST be gone (including SPHelper_sp_main.xml, default_seabank_mmapid, tracker & .bak!).
            check("riskReset(shopee): purged seabank_live_* & default_seabank_mmapid MMKV + crc",
                    !seabankMmkv.exists() && !seabankMmkvCrc.exists()
                    && !seabankDefaultMmkv.exists() && !seabankDefaultMmkvCrc.exists());
            check("riskReset(shopee): purged SPHelper_sp_main.xml, SPHelper_sp_main_bank.xml, .bak, and tracker",
                    !mainShpsPrefs.exists() && !mainShpsPrefsBak.exists()
                    && !bankPrefs.exists() && !bankPrefsBak.exists()
                    && !trackerPrefs.exists());
            check("riskReset(shopee): purged shps, tongdun, seabank_event.db*, cache, code_cache, DE dfp",
                    !shpsCache.exists() && !tongdunPrefs.exists()
                    && !eventDb.exists() && !eventDbWal.exists() && !eventDbShm.exists()
                    && !httpCache.exists() && !jitCache.exists() && !deDfp.exists());
            check("riskReset(shopee): symlink unlinked WITHOUT deleting outside target",
                    !Files.exists(evilLink) && outsideSecret.exists()
                    && "MUST_NOT_BE_DELETED_VIA_SYMLINK".equals(readText(outsideSecret)));

            // Login/session/chat data MUST be 100% preserved!
            check("riskReset(shopee): preserved login MMKV, login prefs, and chat DB",
                    "shopee_auth_token=KEEP_ME_LOGGED_IN".equals(readText(loginMmkv))
                    && loginMmkvCrc.exists()
                    && readText(loginPrefs).contains("KEEP_SESSION")
                    && "KEEP_CHAT_HISTORY".equals(readText(chatDb)));

            // Sibling app (com.bca.mobile) MUST NOT be affected!
            boolean bcaRan = YasvaraRiskCacheReset.applyIfNeeded(bca, null, "com.bca.mobile", raw, 4243);
            check("riskReset(isolation): com.bca.mobile untouched by com.shopee.id epoch",
                    !bcaRan && bcaDfp.exists());

            // 3. Idempotency: re-running with the SAME epoch must be a strict no-op (callback NOT called).
            writeText(seabankMmkv, "fresh_clean_key_dfp_after_reset");
            boolean ranAgain = YasvaraRiskCacheReset.applyIfNeeded(
                    ce, de, "com.shopee.id", raw, 4244, () -> lockedCallbackCount[0]++);
            check("riskReset(idempotent): same epoch is no-op and preserves fresh key_dfp",
                    !ranAgain && lockedCallbackCount[0] == 1
                    && "fresh_clean_key_dfp_after_reset".equals(readText(seabankMmkv)));

            // 4. Subsequent reset with newer epoch purges again and runs locked callback again.
            String raw2 = YasvaraRiskCacheReset.mergePackageEpoch(raw, "com.shopee.id", t0 + 5000L);
            boolean ranSecond = YasvaraRiskCacheReset.applyIfNeeded(
                    ce, de, "com.shopee.id", raw2, 4245, () -> lockedCallbackCount[0]++);
            check("riskReset(new epoch): newer epoch triggers fresh purge & callback",
                    ranSecond && lockedCallbackCount[0] == 2 && !seabankMmkv.exists() && loginMmkv.exists());

            // 5. Stealth audit: ZERO "yasvara" string anywhere in created filenames!
            boolean hasYasvaraFilename = Files.walk(ce.toPath())
                    .anyMatch(p -> p.getFileName().toString().toLowerCase(Locale.ROOT).contains("yasvara"));
            check("riskReset(stealth): zero 'yasvara' filenames inside app data dir", !hasYasvaraFilename);
        } catch (IOException e) {
            check("riskReset: unexpected IOException: " + e, false);
        } finally {
            if (tmp != null) {
                deleteTree(tmp.toFile());
            }
        }
    }

    private static void writeText(File f, String content) throws IOException {
        File p = f.getParentFile();
        if (p != null) p.mkdirs();
        Files.write(f.toPath(), content.getBytes(StandardCharsets.UTF_8));
    }

    private static String readText(File f) throws IOException {
        return new String(Files.readAllBytes(f.toPath()), StandardCharsets.UTF_8);
    }

    private static void deleteTree(File f) {
        if (f == null || !f.exists()) return;
        if (!Files.isSymbolicLink(f.toPath()) && f.isDirectory()) {
            File[] children = f.listFiles();
            if (children != null) {
                for (File c : children) deleteTree(c);
            }
        }
        f.delete();
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
