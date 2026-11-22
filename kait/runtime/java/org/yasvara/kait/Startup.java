package org.yasvara.kait;

import org.yasvara.kait.ipc.IFrameworkService;
import org.yasvara.kait.util.Utils;
import org.yasvara.kait.impl.core.KaitStartup;
import org.yasvara.kait.impl.di.KaitBootstrap;
import org.yasvara.kait.legacy.LegacyDelegateImpl;

import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedInit;

public class Startup {

    public static void bootstrapXposed(boolean systemServerStarted) {
        try {
            KaitStartup.bootstrap(XposedInit.startsSystemServer, systemServerStarted);
            XposedInit.loadLegacyModules();
        } catch (Throwable t) {
            Utils.logE("Error during framework initialization", t);
        }
    }

    /**
     * Registers a pre-built {@code LoadedApk} (the LSPatch rootless target) with the modern hooks so
     * its package lifecycle is dispatched when its class loader is realized. See
     * {@link KaitStartup#trackLoadedApk(Object)}.
     */
    public static void trackLoadedApk(Object loadedApk) {
        KaitStartup.trackLoadedApk(loadedApk);
    }

    public static void initXposed(boolean isSystem, String processName, String appDir, IFrameworkService service) {
        // Establish the Dependency Injection contract
        KaitBootstrap.INSTANCE.init(new LegacyDelegateImpl());

        // Initialize legacy resources and state
        XposedBridge.initXResources();
        XposedInit.startsSystemServer = isSystem;

        // Hand off execution to the modern framework initialization
        KaitStartup.init(isSystem, processName, appDir, service);
    }
}
