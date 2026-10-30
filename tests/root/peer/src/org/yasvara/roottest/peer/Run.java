/*
 * SPDX-FileCopyrightText: The Yasvara Project
 * SPDX-License-Identifier: Apache-2.0
 */
package org.yasvara.roottest.peer;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.os.SystemClock;
import android.util.Log;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.concurrent.TimeUnit;

/**
 * Runs {@code sh -c <cmd>} as this app, the way Termux would run `su`, and logs every output
 * line as "RootPeer: [tag] line" followed by "[tag] exit=N ms=M". Intent extras: cmd, tag.
 */
public final class Run extends BroadcastReceiver {
    private static final String TAG = "RootPeer";

    @Override
    public void onReceive(Context context, Intent intent) {
        // android:exported="false" is the barrier: only root, the shell uid of an adb session and this
        // app can reach this receiver. (getSentFromUid() is -1 unless the sender opts in, so it
        // cannot serve as a check here.)
        final String cmd = intent.getStringExtra("cmd");
        final String tag = intent.getStringExtra("tag") == null ? "t" : intent.getStringExtra("tag");
        if (cmd == null) return;
        final PendingResult pending = goAsync();
        new Thread(() -> {
            long t0 = SystemClock.elapsedRealtime();
            try {
                Process p = new ProcessBuilder("/system/bin/sh", "-c", cmd).redirectErrorStream(true).start();
                try (BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream()))) {
                    String line;
                    while ((line = r.readLine()) != null) Log.i(TAG, "[" + tag + "] " + line);
                }
                if (!p.waitFor(30, TimeUnit.SECONDS)) p.destroyForcibly();
                Log.i(TAG, "[" + tag + "] exit=" + p.exitValue() + " ms=" + (SystemClock.elapsedRealtime() - t0));
            } catch (Throwable t) {
                Log.i(TAG, "[" + tag + "] error=" + t);
            } finally {
                pending.finish();
            }
        }).start();
    }
}
