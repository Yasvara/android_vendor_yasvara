package org.yasvara.kait.nativebridge;

import java.lang.reflect.Executable;
import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.List;

/** Test double for HookBridge used by host JVM unit tests. */
public final class HookBridge {
    public static final List<Object> registered = new ArrayList<>();
    public static boolean nextHookResult = true;
    public static boolean nextReplaceResult = true;
    public static boolean nextUnhookResult = true;

    public static void reset() {
        registered.clear();
        nextHookResult = true;
        nextReplaceResult = true;
        nextUnhookResult = true;
    }

    public static boolean hookMethod(
            boolean useModernApi,
            Executable hookMethod,
            Class<?> hooker,
            int priority,
            Object callback) {
        if (nextHookResult) registered.add(callback);
        return nextHookResult;
    }

    public static boolean unhookMethod(
            boolean useModernApi, Executable hookMethod, Object callback) {
        if (nextUnhookResult) registered.remove(callback);
        return nextUnhookResult;
    }

    public static boolean replaceCallback(
            boolean useModernApi,
            Executable hookMethod,
            Object oldCallback,
            Object newCallback,
            int newPriority) {
        if (!nextReplaceResult) return false;
        int idx = registered.indexOf(oldCallback);
        if (idx < 0) return false;
        registered.set(idx, newCallback);
        return true;
    }

    public static Object invokeOriginalMethod(
            Executable method, Object thisObject, Object... args)
            throws IllegalAccessException, IllegalArgumentException, InvocationTargetException {
        throw new UnsupportedOperationException("Use testOriginalInvoker or backup in host tests");
    }
}
