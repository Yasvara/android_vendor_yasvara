package org.yasvara.kait;

/**
 * Management surface of Yasvara's ROM-native Kait hooking framework.
 *
 * <p>Reached exclusively through the stealth transaction code {@code '_YKM'} on {@code activity}
 * by system, shell, or holders of {@code yasvara.permission.MANAGE_KAIT}. Never registered in
 * {@code servicemanager}.
 */
interface IYasvaraKait {
    /** Package names of installed Xposed/Kait modules (loadable APKs), enabled or not. */
    List<String> listModules(int userId);

    /** Why a module cannot be loaded, or null when it can. */
    @nullable String getModuleProblem(String module, int userId);

    boolean isModuleEnabled(String module);

    void setModuleEnabled(String module, boolean enabled);

    /** Packages the module is scoped to for this user. */
    List<String> getScope(String module, int userId);

    /**
     * Replaces the module's scope for this user. Apps added or removed are force-stopped so the
     * change applies on their next start.
     */
    void setScope(String module, int userId, in List<String> packages);

    /** Packages the module author recommends (scope.list / xposedscope), possibly empty. */
    List<String> getRecommendedScope(String module, int userId);

    /** Force-stops a package so it starts again with the current scope. */
    void restartApp(String packageName, int userId);

    /** Processes currently running with the Kait runtime attached ("processName:pid"). */
    List<String> getInjectedProcesses();

    /**
     * Packages automatically bypassed by the crash circuit breaker after repeated crashes
     * immediately following Kait attachment.
     */
    List<String> getCrashBypassedPackages(int userId);

    /** Clears the crash circuit-breaker bypass for a package so Kait attaches again. */
    void clearCrashBypass(String packageName, int userId);

    /** Human-readable framework identity and version (e.g. "Kait 2.0"). */
    String getFrameworkVersion();
}
