/*
 * SPDX-FileCopyrightText: The Yasvara Project
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
package org.yasvara.ketik.hook;

import android.app.Application;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.RestrictionsManager;
import android.content.pm.PackageInfo;
import android.os.Bundle;
import android.util.Log;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

/**
 * Dynamic Kait hook for stock Play-updated Gboard ({@code com.google.android.inputmethod.latin}).
 *
 * <p>Survives Gboard updates with zero hardcoded obfuscated class names:
 * <ol>
 *   <li>Resolves obfuscated targets via {@link DexFingerprinter} (cached per Gboard versionCode
 *       and APK mtime inside Gboard's {@code noBackupFilesDir}).</li>
 *   <li>Hooks {@code ProofreadModelTag.b()} so when {@code writing_tools=true} is active via
 *       Ketik ({@code MANAGED_CONFIG}) and neither OnDeviceGenAi nor HybridGenAi is attached,
 *       Gboard falls back to its built-in {@code ServerSideGenAi} handler instead of {@code NONE}
 *       (auto-probing the exact {@code SERVER} enum value without pinning constants).</li>
 *   <li>Hooks {@code FlagManager.j(Class, String, Object, boolean)} so any experimental flag
 *       compiled as an immutable constant ({@code adfk.n(name, false)}) that the user explicitly
 *       overrides through Ketik becomes mutable via {@code MANAGED_CONFIG}.</li>
 * </ol>
 *
 * <p>Fails closed per hook: if a future Gboard update removes an anchor, only that hook is skipped
 * and Gboard never crashes.
 */
public final class KetikHookEntry implements IXposedHookLoadPackage {
    private static final String TAG = "YasvaraKetikHook";
    private static final String GBOARD_PKG = "com.google.android.inputmethod.latin";
    private static final String CACHE_FILE = "yasvara_ketik_fp_v1.properties";
    private static final int CACHE_SCHEMA = 1;

    private static volatile Context sAppContext;
    private static volatile Set<String> sManagedKeys = Collections.emptySet();
    private static volatile boolean sWritingToolsManaged = false;

    // Resolved reflection handles for GenAI server-route hook.
    private static volatile Method sRefreshTagsMethod;
    private static volatile Method sIsReadyMethod;
    private static volatile Class<?> sReadinessClass;
    private static volatile Map<?, ?> sTagNameMap;
    private static volatile Field sEntryTagField;
    private static volatile Method sServerGenAiSingleton;
    private static volatile Field sServerGenAiDelegateField;

    // Auto-probed handler enum values (0 = not yet probed, -1 = probe failed).
    private static volatile int sServerHandlerId = 0;
    private static final ThreadLocal<Integer> sProbeOverride = new ThreadLocal<>();

    /**
     * Flags declared via {@code adfk.n(name, false)} (immutable {@code adfd}) that should always
     * be created as mutable {@code adfs} (default stays false) so toggling them live in Laras
     * takes effect immediately without restarting Gboard.
     */
    private static final Set<String> ALWAYS_MUTABLE_FLAGS = Collections.singleton(
            "enable_llm_based_grammar_checker");

    @Override
    public void handleLoadPackage(final XC_LoadPackage.LoadPackageParam lp) {
        if (!GBOARD_PKG.equals(lp.packageName)) return;
        Log.i(TAG, "Loaded into " + lp.packageName + " process=" + lp.processName);

        // Hook Application.attach so we get Context + RestrictionsManager before Gboard's own
        // Application.onCreate initializes FlagManager, ManagedConfigs, and ProofreadModelTag.
        XposedHelpers.findAndHookMethod(
                Application.class,
                "attach",
                Context.class,
                new XC_MethodHook() {
                    private boolean mInstalled;

                    @Override
                    protected void afterHookedMethod(MethodHookParam param) {
                        if (mInstalled) return;
                        mInstalled = true;
                        final Context ctx = (Context) param.thisObject;
                        sAppContext = ctx;
                        refreshRestrictions(ctx);
                        installHooks(ctx, lp);
                    }
                });

        // After Application.onCreate, register for live restriction changes and ensure tags are
        // synced if ManagedConfigs ran before our hook settled.
        XposedHelpers.findAndHookMethod(
                Application.class,
                "onCreate",
                new XC_MethodHook() {
                    private boolean mRegistered;

                    @Override
                    protected void afterHookedMethod(MethodHookParam param) {
                        if (mRegistered) return;
                        mRegistered = true;
                        final Context ctx = (Context) param.thisObject;
                        registerRestrictionsReceiver(ctx);
                        refreshRestrictions(ctx);
                        triggerTagRefresh();
                    }
                });
    }

    private static void installHooks(Context ctx, XC_LoadPackage.LoadPackageParam lp) {
        final long t0 = System.nanoTime();
        final DexFingerprinter.Resolved resolved = loadOrScanFingerprints(ctx, lp);
        final long elapsedMs = (System.nanoTime() - t0) / 1_000_000L;
        Log.i(TAG, "Fingerprints ready in " + elapsedMs + "ms: " + resolved);

        if (resolved.hasFlagManager()) {
            installFlagManagerHook(lp.classLoader, resolved);
        } else {
            Log.w(TAG, "FlagManager anchor not found; immutable flag unlock skipped");
        }

        if (resolved.hasGenAiRoute()) {
            installGenAiRouteHook(lp.classLoader, resolved);
        } else {
            Log.w(TAG, "GenAi handler anchor not found; Writing Tools route hook skipped");
        }
    }

    private static void installFlagManagerHook(
            ClassLoader cl, DexFingerprinter.Resolved r) {
        try {
            final Class<?> fmClass = cl.loadClass(r.flagManagerClass);
            final Method create = fmClass.getDeclaredMethod(
                    r.createFlagMethod, Class.class, String.class, Object.class, boolean.class);
            XposedBridge.hookMethod(create, new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) {
                    if (Boolean.TRUE.equals(param.args[3])) return;
                    final Object nameObj = param.args[1];
                    if (nameObj instanceof String
                            && (sManagedKeys.contains(nameObj)
                                    || ALWAYS_MUTABLE_FLAGS.contains(nameObj))) {
                        param.args[3] = Boolean.TRUE;
                        Log.i(TAG, "Promoted immutable flag to mutable: " + nameObj);
                    }
                }
            });
            Log.i(TAG, "Hooked FlagManager: " + r.flagManagerClass + "." + r.createFlagMethod);
        } catch (Throwable t) {
            Log.e(TAG, "Failed to hook FlagManager (fail-closed)", t);
        }
    }

    private static void installGenAiRouteHook(
            ClassLoader cl, DexFingerprinter.Resolved r) {
        try {
            final Class<?> tagClass = cl.loadClass(r.proofreadTagClass);
            final Method getter = tagClass.getDeclaredMethod(r.handlerGetterMethod);
            final Method refresher = tagClass.getDeclaredMethod(r.refreshTagsMethod);
            refresher.setAccessible(true);
            sRefreshTagsMethod = refresher;

            final Class<?> readinessClass = cl.loadClass(r.readinessClass);
            Method isReady = null;
            for (Method m : readinessClass.getDeclaredMethods()) {
                if (m.getName().equals(r.isReadyMethod)
                        && Modifier.isStatic(m.getModifiers())
                        && m.getParameterCount() == 1
                        && m.getReturnType() == boolean.class) {
                    isReady = m;
                    break;
                }
            }
            if (isReady == null) {
                Log.w(TAG, "Could not bind readiness query method; skipping GenAi route hook");
                return;
            }
            isReady.setAccessible(true);
            sIsReadyMethod = isReady;
            bindReadinessMap(readinessClass);

            if (r.serverGenAiClass != null) {
                bindServerGenAi(cl, r.serverGenAiClass);
            }

            XposedBridge.hookMethod(getter, new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) {
                    final Integer probe = sProbeOverride.get();
                    if (probe != null) {
                        param.setResult(probe);
                        return;
                    }
                    if (!sWritingToolsManaged) return;
                    if (hasActiveNonServerHandler()) return;

                    final Object raw = param.getResult();
                    if (!(raw instanceof Integer)) return;
                    final int orig = (Integer) raw;

                    int serverId = sServerHandlerId;
                    if (serverId == 0) {
                        serverId = probeServerHandlerId(orig);
                    }
                    if (serverId > 0 && orig != serverId) {
                        param.setResult(serverId);
                    }
                }
            });
            Log.i(TAG, "Hooked GenAi handler getter: "
                    + r.proofreadTagClass + "." + r.handlerGetterMethod);
        } catch (Throwable t) {
            Log.e(TAG, "Failed to hook GenAi handler route (fail-closed)", t);
        }
    }

    private static void bindReadinessMap(Class<?> readinessClass) {
        sReadinessClass = readinessClass;
        try {
            // Find the static String->Entry map in ComponentsReadinessManager.
            for (Field f : readinessClass.getDeclaredFields()) {
                if (!Modifier.isStatic(f.getModifiers())) continue;
                if (!Map.class.isAssignableFrom(f.getType())) continue;
                f.setAccessible(true);
                final Map<?, ?> map = (Map<?, ?>) f.get(null);
                if (map == null) continue;
                if (!Modifier.isPublic(f.getModifiers())) {
                    sTagNameMap = map;
                    return;
                }
            }
        } catch (Throwable t) {
            Log.w(TAG, "Could not bind readiness tag map", t);
        }
    }

    private static Map<?, ?> resolveTagNameMap(String probeKey) {
        final Map<?, ?> current = sTagNameMap;
        if (current != null && current.containsKey(probeKey)) return current;
        final Class<?> cls = sReadinessClass;
        if (cls == null) return current;
        try {
            for (Field f : cls.getDeclaredFields()) {
                if (!Modifier.isStatic(f.getModifiers())) continue;
                if (!Map.class.isAssignableFrom(f.getType())) continue;
                f.setAccessible(true);
                final Map<?, ?> map = (Map<?, ?>) f.get(null);
                if (map != null && map.containsKey(probeKey)) {
                    sTagNameMap = map;
                    return map;
                }
            }
        } catch (Throwable ignored) {
        }
        return current;
    }

    private static void bindServerGenAi(ClassLoader cl, String className) {
        try {
            final Class<?> cls = cl.loadClass(className);
            for (Method m : cls.getDeclaredMethods()) {
                if (Modifier.isStatic(m.getModifiers())
                        && m.getParameterCount() == 0
                        && m.getReturnType() == cls) {
                    m.setAccessible(true);
                    sServerGenAiSingleton = m;
                    break;
                }
            }
            // Unique instance field whose type is an interface implemented by cls (advd b).
            final Set<Class<?>> ifaces = new HashSet<>();
            Collections.addAll(ifaces, cls.getInterfaces());
            for (Field f : cls.getDeclaredFields()) {
                if (Modifier.isStatic(f.getModifiers())) continue;
                if (ifaces.contains(f.getType())) {
                    f.setAccessible(true);
                    sServerGenAiDelegateField = f;
                    break;
                }
            }
        } catch (Throwable t) {
            Log.w(TAG, "Could not bind ServerSideGenAi holder (non-fatal)", t);
        }
    }

    private static boolean hasActiveNonServerHandler() {
        // Primary check: OnDevice or Hybrid readiness/provisioned tags active.
        if (isTagReady("OnDeviceModelReadyTag")
                || isTagReady("OnDeviceModelProvisionedTag")
                || isTagReady("HybridModelReadyTag")
                || isTagReady("HybridModelProvisionedTag")) {
            return true;
        }
        // Secondary check: ServerSideGenAi delegate field non-null (OnDevice/Hybrid attached).
        try {
            if (sServerGenAiSingleton != null && sServerGenAiDelegateField != null) {
                final Object holder = sServerGenAiSingleton.invoke(null);
                if (holder != null && sServerGenAiDelegateField.get(holder) != null) {
                    return true;
                }
            }
        } catch (Throwable ignored) {
            // Safe fallback to tag checks above.
        }
        return false;
    }

    /**
     * Dynamically determines which integer handler ID maps to {@code ProofreadModelReadyTag}
     * ({@code SERVER}) on this Gboard build without hardcoding enum values.
     */
    private static synchronized int probeServerHandlerId(int orig) {
        if (sServerHandlerId != 0) return sServerHandlerId;
        if (sRefreshTagsMethod == null || sIsReadyMethod == null) return -1;

        // Only probe once ProofreadModelReadyTag itself is initialized and ready.
        if (!isTagReady("ProofreadModelReadyTag")) return 0;

        try {
            // First verify whether orig itself already maps to ProofreadModelReadyTag.
            // On 18.8.0 before ManagedConfigs runs (writing_tools still false), orig IS 2 (SERVER)!
            // Saving orig as sServerHandlerId ensures later calls returning 1 (NONE) after
            // ManagedConfigs sets writing_tools=true are cleanly redirected back to 2 (SERVER).
            sProbeOverride.set(orig);
            sRefreshTagsMethod.invoke(null);
            if (isTagReady("CurrentHandlerModelReadyTag")
                    && isTagReady("CurrentHandlerModelProvisionedTag")) {
                sServerHandlerId = orig;
                Log.i(TAG, "Resolved dynamic GenAi server handler from native fallback: SERVER="
                        + orig);
                return orig;
            }

            // Otherwise find the dynamic SERVER enum value (e.g. 2 when orig=1 NONE on 18.8.0).
            final int[] candidates = {2, 1, 3, 4, 5};
            for (int k : candidates) {
                if (k == orig) continue;
                sProbeOverride.set(k);
                sRefreshTagsMethod.invoke(null);
                if (isTagReady("CurrentHandlerModelReadyTag")
                        && isTagReady("CurrentHandlerModelProvisionedTag")) {
                    sServerHandlerId = k;
                    Log.i(TAG, "Resolved dynamic GenAi server handler: NONE=" + orig
                            + " -> SERVER=" + k);
                    return k;
                }
            }
            // Restore original state on failure.
            sProbeOverride.set(orig);
            sRefreshTagsMethod.invoke(null);
        } catch (Throwable t) {
            Log.e(TAG, "Server handler probe failed", t);
        } finally {
            sProbeOverride.remove();
        }
        sServerHandlerId = -1;
        Log.w(TAG, "Could not resolve SERVER handler enum id; failing closed");
        return -1;
    }

    private static boolean isTagReady(String tagName) {
        try {
            final Map<?, ?> map = resolveTagNameMap(tagName);
            final Method isReady = sIsReadyMethod;
            if (map == null || isReady == null) return false;
            final Object entry = map.get(tagName);
            if (entry == null) return false;
            Field tagField = sEntryTagField;
            if (tagField == null) {
                final Class<?> tagParamType = isReady.getParameterTypes()[0];
                for (Field f : entry.getClass().getDeclaredFields()) {
                    if (tagParamType.isAssignableFrom(f.getType())) {
                        f.setAccessible(true);
                        tagField = f;
                        sEntryTagField = f;
                        break;
                    }
                }
            }
            if (tagField == null) return false;
            final Object tagObj = tagField.get(entry);
            if (tagObj == null) return false;
            return Boolean.TRUE.equals(isReady.invoke(null, tagObj));
        } catch (Throwable ignored) {
            return false;
        }
    }

    private static void triggerTagRefresh() {
        final Method refresher = sRefreshTagsMethod;
        if (refresher == null) return;
        try {
            refresher.invoke(null);
        } catch (Throwable t) {
            Log.w(TAG, "Tag refresh failed", t);
        }
    }

    private static void refreshRestrictions(Context ctx) {
        try {
            final RestrictionsManager rm =
                    (RestrictionsManager) ctx.getSystemService(Context.RESTRICTIONS_SERVICE);
            final Bundle b = rm != null ? rm.getApplicationRestrictions() : null;
            if (b == null || b.isEmpty()) {
                sManagedKeys = Collections.emptySet();
                sWritingToolsManaged = false;
                return;
            }
            final Set<String> keys = new HashSet<>(b.keySet());
            keys.remove("preferences");
            sManagedKeys = Collections.unmodifiableSet(keys);
            sWritingToolsManaged = b.getBoolean("writing_tools", false);
        } catch (Throwable t) {
            Log.w(TAG, "Could not read application restrictions", t);
        }
    }

    private static void registerRestrictionsReceiver(Context ctx) {
        try {
            final IntentFilter filter = new IntentFilter(
                    Intent.ACTION_APPLICATION_RESTRICTIONS_CHANGED);
            ctx.registerReceiver(new BroadcastReceiver() {
                @Override
                public void onReceive(Context c, Intent intent) {
                    refreshRestrictions(c);
                    // Reset probe if Writing Tools toggled on after a cold start without it.
                    if (sWritingToolsManaged && sServerHandlerId == -1) {
                        sServerHandlerId = 0;
                    }
                    triggerTagRefresh();
                }
            }, filter, Context.RECEIVER_NOT_EXPORTED);
        } catch (Throwable t) {
            Log.w(TAG, "Could not register restrictions receiver", t);
        }
    }

    private static DexFingerprinter.Resolved loadOrScanFingerprints(
            Context ctx, XC_LoadPackage.LoadPackageParam lp) {
        final String stamp = buildApkStamp(ctx, lp);
        final File cacheFile = new File(ctx.getNoBackupFilesDir(), CACHE_FILE);

        final DexFingerprinter.Resolved cached = readCache(cacheFile, stamp);
        if (cached != null) {
            Log.i(TAG, "Loaded cached fingerprints for stamp=" + stamp);
            return cached;
        }

        final List<File> apks = new ArrayList<>();
        if (lp.appInfo != null) {
            if (lp.appInfo.sourceDir != null) apks.add(new File(lp.appInfo.sourceDir));
            if (lp.appInfo.splitSourceDirs != null) {
                for (String split : lp.appInfo.splitSourceDirs) {
                    if (split != null) apks.add(new File(split));
                }
            }
        }
        try {
            final DexFingerprinter.Resolved fresh = DexFingerprinter.scanApks(apks);
            writeCache(cacheFile, stamp, fresh);
            return fresh;
        } catch (Throwable t) {
            Log.e(TAG, "DEX fingerprint scan failed", t);
            return new DexFingerprinter.Resolved();
        }
    }

    private static String buildApkStamp(Context ctx, XC_LoadPackage.LoadPackageParam lp) {
        long versionCode = 0L;
        long lastUpdate = 0L;
        long baseSize = 0L;
        try {
            final PackageInfo pi = ctx.getPackageManager().getPackageInfo(GBOARD_PKG, 0);
            versionCode = pi.getLongVersionCode();
            lastUpdate = pi.lastUpdateTime;
        } catch (Throwable ignored) {
        }
        if (lp.appInfo != null && lp.appInfo.sourceDir != null) {
            baseSize = new File(lp.appInfo.sourceDir).length();
        }
        return CACHE_SCHEMA + ":" + versionCode + ":" + lastUpdate + ":" + baseSize;
    }

    private static DexFingerprinter.Resolved readCache(File file, String expectedStamp) {
        if (!file.isFile()) return null;
        final Properties p = new Properties();
        try (FileInputStream in = new FileInputStream(file)) {
            p.load(in);
        } catch (Throwable ignored) {
            return null;
        }
        if (!expectedStamp.equals(p.getProperty("stamp"))) return null;
        final DexFingerprinter.Resolved r = new DexFingerprinter.Resolved();
        r.proofreadTagClass = emptyToNull(p.getProperty("proofreadTagClass"));
        r.handlerGetterMethod = emptyToNull(p.getProperty("handlerGetterMethod"));
        r.refreshTagsMethod = emptyToNull(p.getProperty("refreshTagsMethod"));
        r.readinessClass = emptyToNull(p.getProperty("readinessClass"));
        r.isReadyMethod = emptyToNull(p.getProperty("isReadyMethod"));
        r.flagManagerClass = emptyToNull(p.getProperty("flagManagerClass"));
        r.createFlagMethod = emptyToNull(p.getProperty("createFlagMethod"));
        r.serverGenAiClass = emptyToNull(p.getProperty("serverGenAiClass"));
        return r;
    }

    private static void writeCache(File file, String stamp, DexFingerprinter.Resolved r) {
        final Properties p = new Properties();
        p.setProperty("stamp", stamp);
        putIfNonNull(p, "proofreadTagClass", r.proofreadTagClass);
        putIfNonNull(p, "handlerGetterMethod", r.handlerGetterMethod);
        putIfNonNull(p, "refreshTagsMethod", r.refreshTagsMethod);
        putIfNonNull(p, "readinessClass", r.readinessClass);
        putIfNonNull(p, "isReadyMethod", r.isReadyMethod);
        putIfNonNull(p, "flagManagerClass", r.flagManagerClass);
        putIfNonNull(p, "createFlagMethod", r.createFlagMethod);
        putIfNonNull(p, "serverGenAiClass", r.serverGenAiClass);
        try (FileOutputStream out = new FileOutputStream(file)) {
            p.store(out, "Yasvara Ketik dynamic Gboard fingerprints");
        } catch (Throwable t) {
            Log.w(TAG, "Could not save fingerprint cache", t);
        }
    }

    private static String emptyToNull(String s) {
        return (s == null || s.isEmpty()) ? null : s;
    }

    private static void putIfNonNull(Properties p, String k, String v) {
        if (v != null) p.setProperty(k, v);
    }
}
