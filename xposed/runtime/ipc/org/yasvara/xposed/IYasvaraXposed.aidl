package org.yasvara.xposed;

/**
 * The management surface of the ROM's Xposed runtime, registered with servicemanager as
 * "yasvara_xposed". Only the system, shell and holders of yasvara.permission.MANAGE_XPOSED may
 * call it; unprivileged apps are not even allowed to look the service up.
 *
 * Nothing is enabled and no app is in any scope until a caller says so.
 */
interface IYasvaraXposed {
    /** Package names of installed Xposed modules (loadable APKs), enabled or not. */
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

    /** Packages the module author recommends (module scope.list), possibly empty. */
    List<String> getRecommendedScope(String module, int userId);

    /** Force-stops a package so it starts again with the current scope. */
    void restartApp(String packageName, int userId);

    /** Packages with at least one process currently running with the runtime loaded. */
    List<String> getInjectedProcesses();
}
