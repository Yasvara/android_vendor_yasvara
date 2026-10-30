/*
 * SPDX-FileCopyrightText: The Yasvara Project
 * SPDX-License-Identifier: Apache-2.0
 */
package org.yasvara.roottest.admin;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.os.IBinder;
import android.os.ServiceManager;
import android.util.Log;

import com.android.server.yasvara.root.IYasvaraRoot;

/**
 * Drives YasvaraRootService for the device tests. Extras: op, tag and, per op, pkg, tier,
 * scope, ms, ns, flags, key, value, uid, limit. Logs "RootAdmin: [tag] result".
 */
public final class Cmd extends BroadcastReceiver {
    private static final String TAG = "RootAdmin";

    @Override
    public void onReceive(Context context, Intent intent) {
        // android:exported="false" is the barrier: only root, the shell uid of an adb session and this
        // app can reach this receiver. (getSentFromUid() is -1 unless the sender opts in, so it
        // cannot serve as a check here.)
        String op = intent.getStringExtra("op");
        String tag = intent.getStringExtra("tag") == null ? "t" : intent.getStringExtra("tag");
        try {
            IBinder b = ServiceManager.getService("yasvara_root");
            if (b == null) {
                Log.i(TAG, "[" + tag + "] no service");
                return;
            }
            IYasvaraRoot s = IYasvaraRoot.Stub.asInterface(b);
            String out;
            switch (op == null ? "" : op) {
                case "state": out = "state=" + s.getState() + " enabled=" + s.isEnabled(); break;
                case "enable": out = "ok=" + s.setEnabled(true); break;
                case "disable": out = "ok=" + s.setEnabled(false); break;
                case "freeze": out = "ok=" + s.setFrozen(true); break;
                case "unfreeze": out = "ok=" + s.setFrozen(false); break;
                case "enroll":
                    out = "ok=" + s.setGrant(intent.getStringExtra("pkg"), 0,
                            intent.getIntExtra("tier", 1), intent.getIntExtra("scope", 0),
                            intent.getLongExtra("ms", 0), intent.getIntExtra("ns", 1),
                            intent.getIntExtra("flags", 0));
                    break;
                case "revoke": out = "ok=" + s.revoke(intent.getIntExtra("uid", -1)); break;
                case "revokeall": s.revokeAll(); out = "ok"; break;
                case "grants": out = String.join("\n", s.listGrants()); break;
                case "audit": out = String.join("\n", s.getAudit(intent.getIntExtra("limit", 20))); break;
                case "denied": out = String.join("\n", s.getDenied()); break;
                case "selftest": out = s.selfTest(); break;
                case "getopt": out = "value=" + s.getOption(intent.getStringExtra("key")); break;
                case "setopt":
                    out = "ok=" + s.setOption(intent.getStringExtra("key"), intent.getIntExtra("value", 0));
                    break;
                default: out = "unknown op " + op;
            }
            for (String line : out.split("\n")) Log.i(TAG, "[" + tag + "] " + line);
            Log.i(TAG, "[" + tag + "] done");
        } catch (Throwable t) {
            Log.i(TAG, "[" + tag + "] error=" + t);
        }
    }
}
