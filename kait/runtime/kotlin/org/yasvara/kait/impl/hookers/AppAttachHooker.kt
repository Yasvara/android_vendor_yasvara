package org.yasvara.kait.impl.hookers

import io.github.libxposed.api.XposedInterface
import org.yasvara.kait.impl.di.KaitBootstrap

/**
 * Intercepts the early ApplicationThread attachment phase. Triggers the legacy compatibility layer
 * to load modern modules into the process.
 *
 * Note: module UI service delivery deliberately does NOT happen here. At attach() time the bound
 * application does not exist yet, so the package name is unknowable
 * (ActivityThread.currentPackageName() is null). Delivery happens in the module-loading paths
 * instead, via KaitAppService.deliverForSelf.
 */
object AppAttachHooker : XposedInterface.Hooker {
    override fun intercept(chain: XposedInterface.Chain): Any? {
        // Execute the actual attach() method first
        val result = chain.proceed()

        // Delegate legacy module loading via DI
        val activityThread = chain.thisObject
        if (activityThread != null) {
            KaitBootstrap.withLegacy { delegate -> delegate.loadModules(activityThread) }
        }

        return result
    }
}
