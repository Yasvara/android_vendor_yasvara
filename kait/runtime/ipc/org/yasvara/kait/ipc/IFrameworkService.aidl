package org.yasvara.kait.ipc;

import android.os.Bundle;
import android.os.IBinder;
import android.os.ParcelFileDescriptor;

import io.github.libxposed.service.HookedProcess;
import io.github.libxposed.service.IHotReloadCallback;

import org.yasvara.kait.ipc.IProcessChannel;
import org.yasvara.kait.ipc.LoadedModule;

/**
 * Per-process IPC interface between a Kait-injected process and {@code system_server}.
 *
 * <p>Every call is authenticated by {@code Binder.getCallingUid()} against the process registry
 * established at rendezvous. Transaction IDs are implicit — always append new methods at the end.
 */
interface IFrameworkService {
    boolean isLogMuted();

    List<LoadedModule> getLegacyModules();

    List<LoadedModule> getModules();

    String getPrefsPath(String packageName);

    @nullable ParcelFileDescriptor openManagerApk();

    @nullable IBinder requestManagerService();

    /** Must stay synchronous so binder records calling pid/uid cleanly. */
    void attachProcessChannel(IProcessChannel channel);

    @nullable ParcelFileDescriptor openAppDataFile(String path);

    List<String> getModuleScope(String module);

    void setModuleScope(String module, in List<String> packages);

    /** Returns live hooked target processes for the caller's own module (API 102 hot reload). */
    List<HookedProcess> getRunningTargets(String module);

    /** Dispatches an asynchronous hot reload to a running hooked target for the caller's module. */
    void hotReloadModule(String module, long targetId, in @nullable Bundle data,
            IHotReloadCallback callback);

    /**
     * Pushes a preference diff from a module's UI process to every hooked process subscribed to
     * {@code group} via {@code IRemotePreferenceCallback}.
     */
    void notifyRemotePreferencesChanged(String module, String group, in Bundle diff);
}
