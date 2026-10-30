/*
 * SPDX-FileCopyrightText: The Yasvara Project
 * SPDX-License-Identifier: Apache-2.0
 */
package org.yasvara.teststore;

import android.app.PendingIntent;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageInstaller;
import android.util.Log;

import java.io.FileInputStream;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * "am broadcast -n org.yasvara.teststore/.SelfUpdate [--es apk /data/local/tmp/x.apk]" installs
 * this APK (or the given one, same package) over itself the way a store does (silent
 * self-update). The commit result comes back to the same receiver and is
 * logged as "TestStore: result status=<n> msg=<...>".
 */
public class SelfUpdate extends BroadcastReceiver {
    private static final String TAG = "TestStore";
    private static final String ACTION_RESULT = "org.yasvara.teststore.RESULT";

    @Override
    public void onReceive(Context context, Intent intent) {
        if (ACTION_RESULT.equals(intent.getAction())) {
            int status = intent.getIntExtra(PackageInstaller.EXTRA_STATUS, 99);
            Log.i(TAG, "result status=" + status
                    + " msg=" + intent.getStringExtra(PackageInstaller.EXTRA_STATUS_MESSAGE));
            // With "--ez confirm true", show the confirmation like a foreground store would
            // (needs "Display over other apps" for the background start).
            if (status == PackageInstaller.STATUS_PENDING_USER_ACTION
                    && context.getSharedPreferences("t", 0).getBoolean("confirm", false)) {
                Intent confirm = intent.getParcelableExtra(Intent.EXTRA_INTENT, Intent.class);
                if (confirm != null) {
                    context.startActivity(confirm.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK));
                }
            }
            return;
        }
        context.getSharedPreferences("t", 0).edit()
                .putBoolean("confirm", intent.getBooleanExtra("confirm", false)).commit();
        PendingResult pending = goAsync();
        new Thread(() -> {
            try {
                update(context, intent.getStringExtra("apk"));
            } catch (Throwable t) {
                Log.e(TAG, "update failed", t);
            } finally {
                pending.finish();
            }
        }).start();
    }

    /** Installs apk (default: this app's own APK) as an update of this package. */
    private static void update(Context context, String apk) throws Exception {
        if (apk == null) apk = context.getApplicationInfo().sourceDir;
        PackageInstaller installer = context.getPackageManager().getPackageInstaller();
        PackageInstaller.SessionParams params =
                new PackageInstaller.SessionParams(PackageInstaller.SessionParams.MODE_FULL_INSTALL);
        params.setAppPackageName(context.getPackageName());
        params.setRequireUserAction(PackageInstaller.SessionParams.USER_ACTION_NOT_REQUIRED);
        int id = installer.createSession(params);
        try (PackageInstaller.Session session = installer.openSession(id)) {
            try (InputStream in = new FileInputStream(apk);
                    OutputStream out = session.openWrite("base.apk", 0, -1)) {
                byte[] buf = new byte[64 * 1024];
                int n;
                while ((n = in.read(buf)) > 0) out.write(buf, 0, n);
                session.fsync(out);
            }
            Intent result = new Intent(ACTION_RESULT).setClass(context, SelfUpdate.class);
            PendingIntent pi = PendingIntent.getBroadcast(context, id, result,
                    PendingIntent.FLAG_MUTABLE | PendingIntent.FLAG_UPDATE_CURRENT);
            Log.i(TAG, "committing session " + id);
            session.commit(pi.getIntentSender());
        }
    }
}
