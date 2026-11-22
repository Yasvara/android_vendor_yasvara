package org.yasvara.kaittest;

import android.app.Activity;
import android.util.Log;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XSharedPreferences;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

/** Hooks Activity.onResume of whatever the user scoped it to, and reads its own preferences. */
public class TestModule implements IXposedHookLoadPackage {
    private static final String TAG = "YasvaraKaitTest";
    private static final String SELF = "org.yasvara.kaittest";

    @Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam lp) {
        Log.i(TAG, "handleLoadPackage " + lp.packageName + " process=" + lp.processName
                + " first=" + lp.isFirstApplication);
        XposedBridge.log(TAG + ": loaded into " + lp.packageName);

        final XSharedPreferences prefs = new XSharedPreferences(SELF);
        Log.i(TAG, "prefs file=" + prefs.getFile() + " greeting=" + prefs.getString("greeting", "<none>"));

        XposedHelpers.findAndHookMethod(Activity.class, "onResume", new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam param) {
                Activity a = (Activity) param.thisObject;
                a.setTitle(prefs.getString("greeting", "hooked by Kait"));
                Log.i(TAG, "onResume hooked in " + a.getClass().getName());
            }
        });
    }
}
