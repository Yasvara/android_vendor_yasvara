/*
 * SPDX-FileCopyrightText: The Yasvara Project
 * SPDX-License-Identifier: Apache-2.0
 */
package org.yasvara.roottest.scan;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.net.LocalSocket;
import android.net.LocalSocketAddress;
import android.os.Build;
import android.system.ErrnoException;
import android.system.Os;
import android.system.OsConstants;
import android.system.StructStat;
import android.util.Log;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.Arrays;
import java.util.TreeSet;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;

/**
 * SPEC-0007 T0: records everything an app that is NOT enrolled for root can observe about
 * Akar, as sorted "section|key|value" lines in files/report.txt. A line starting with "!" is a
 * leak: something that names or demonstrates Akar. Lines are free of pids, inode numbers and
 * times so two reports can be diffed (exposure.sh).
 *
 * Read-only: it stats, lists, reads and connects; it never writes outside its own files dir.
 * The one connection to the daemon socket reads the first frame and closes, which the daemon
 * records as an ordinary refusal.
 */
public final class Scan extends BroadcastReceiver {
    private static final String TAG = "RootScan";

    /** Names and contents that are Akar's own. */
    private static final Pattern OURS = Pattern.compile(
            "(?i)yasvara_(su|rootd|root)|yasvara\\.root|MANAGE_ROOT|\\bakar\\b|yasvara_su_client");
    /** What any userdebug ROM carries; reported for information, not as an Akar leak. */
    private static final Pattern STOCK = Pattern.compile("(?i)magisk|ksu|supersu|\\bsu_exec\\b|u:r:su:s0");
    /** Directory entries worth reporting by name. */
    private static final Pattern NAMES = Pattern.compile("(?i)^su$|^\\.s$|yasvara_(su|rootd)|akar|magisk|ksu");

    private final TreeSet<String> out = new TreeSet<>();
    private int leaks;

    @Override
    public void onReceive(Context context, Intent intent) {
        final PendingResult pending = goAsync();
        new Thread(() -> {
            try {
                run(context);
            } catch (Throwable t) {
                Log.e(TAG, "scan failed", t);
            } finally {
                pending.finish();
            }
        }).start();
    }

    private void add(boolean leak, String section, String key, String value) {
        if (leak) leaks++;
        out.add((leak ? "!" : " ") + section + "|" + key + "|" + value);
    }

    private void run(Context c) throws Exception {
        probePaths();
        listDirs();
        readFiles();
        props();
        services();
        packages(c);
        sockets();
        execs();
        build();
        File f = new File(c.getFilesDir(), "report.txt");
        try (FileWriter w = new FileWriter(f)) {
            for (String l : out) w.write(l + "\n");
        }
        Log.i(TAG, "done lines=" + out.size() + " leaks=" + leaks);
    }

    // ---- filesystem ----------------------------------------------------------------------------

    private static String errno(ErrnoException e) {
        return "errno=" + OsConstants.errnoName(e.errno);
    }

    private static String describe(String path) {
        try {
            StructStat s = Os.lstat(path);
            String type = OsConstants.S_ISDIR(s.st_mode) ? "dir" : OsConstants.S_ISLNK(s.st_mode) ? "link"
                    : OsConstants.S_ISREG(s.st_mode) ? "file" : OsConstants.S_ISSOCK(s.st_mode) ? "sock" : "other";
            String extra = "";
            if (OsConstants.S_ISLNK(s.st_mode)) {
                try {
                    extra = " ->" + Os.readlink(path);
                } catch (ErrnoException e) {
                    extra = " ->" + errno(e);
                }
            }
            boolean x;
            try {
                x = Os.access(path, OsConstants.X_OK);
            } catch (ErrnoException e) {
                x = false;
            }
            return type + " mode=" + Integer.toOctalString(s.st_mode & 07777) + " uid=" + s.st_uid
                    + " gid=" + s.st_gid + " x=" + x + extra;
        } catch (ErrnoException e) {
            return errno(e);
        }
    }

    private void probePaths() {
        String[] paths = {
                "/system/bin/su", "/system/xbin/su", "/system/xbin", "/system_ext/bin/su",
                "/system_ext/bin/yasvara_rootd", "/sbin/su", "/su/bin/su", "/vendor/bin/su",
                "/product/bin/su", "/data/local/tmp/su", "/dev/socket", "/dev/socket/yasvara_su",
                "/dev/socket/akar", "/data/misc", "/data/misc/yasvara_root",
                "/data/misc/yasvara_root/grants.v1", "/data/misc/yasvara_root/events.sock",
                "/data/misc/yasvara_root/ctl.sock", "/data/misc/yasvara_root/run", "/data/misc/yasvara_root/run/ctl.sock",
                "/data/misc/yasvara_root/enrolled.set",
                "/system/xbin/yasvara_su", "/system/xbin/yasvara_rootd", "/system/xbin/.s",
                "/system_ext/xbin", "/system/etc/init/yasvara_rootd.rc",
                "/system_ext/etc/init/yasvara_rootd.rc", "/system_ext/etc/selinux",
        };
        for (String p : paths) {
            String d = describe(p);
            // Anything that exists and is not an access error says "something is here".
            boolean visible = !d.startsWith("errno=");
            add(visible, "path", p, d);
        }
    }

    private void listDirs() {
        String[] dirs = {"/system/bin", "/system_ext/bin", "/system/xbin", "/dev/socket",
                "/system_ext/etc/init", "/system/etc/init", "/data/misc", "/system_ext/etc/selinux",
                "/system_ext/etc/permissions", "/system/etc/permissions"};
        for (String d : dirs) {
            String[] names = new File(d).list();
            if (names == null) {
                add(false, "list", d, "unreadable");
                continue;
            }
            Arrays.sort(names);
            add(false, "list", d, "count=" + names.length);
            for (String n : names) {
                if (NAMES.matcher(n).find()) add(true, "list", d + "/" + n, "present");
            }
        }
    }

    private void readFiles() {
        String[] files = {
                "/system/etc/selinux/plat_sepolicy.cil", "/system/etc/selinux/plat_file_contexts",
                "/system_ext/etc/selinux/system_ext_sepolicy.cil",
                "/system_ext/etc/selinux/system_ext_file_contexts",
                "/system_ext/etc/selinux/system_ext_service_contexts",
                "/system_ext/etc/selinux/system_ext_property_contexts",
                "/system_ext/etc/init/yasvara_rootd.rc", "/proc/net/unix", "/proc/self/mountinfo",
                "/proc/mounts", "/proc/version", "/proc/cmdline", "/sys/fs/selinux/enforce",
                "/proc/self/attr/current",
        };
        TreeSet<String> all = new TreeSet<>(Arrays.asList(files));
        for (String dir : new String[]{"/system_ext/etc/permissions", "/system/etc/permissions",
                "/product/etc/permissions"}) {
            String[] names = new File(dir).list();
            if (names != null) for (String n : names) all.add(dir + "/" + n);
        }
        for (String f : all) {
            int ours = 0, stock = 0;
            String result;
            try (BufferedReader r = new BufferedReader(new InputStreamReader(new FileInputStream(f)), 1 << 16)) {
                String line;
                long chars = 0;
                while ((line = r.readLine()) != null && chars < (16 << 20)) {
                    chars += line.length();
                    if (OURS.matcher(line).find()) ours++;
                    if (STOCK.matcher(line).find()) stock++;
                }
                result = "readable ours=" + ours + " stock=" + stock;
            } catch (Exception e) {
                result = e.getMessage() != null && e.getMessage().contains("EACCES") ? "errno=EACCES"
                        : e.getMessage() != null && e.getMessage().contains("ENOENT") ? "errno=ENOENT" : "unreadable";
                ours = 0;
            }
            // Report every file that was probed in the fixed list; the permission-file sweep only
            // when it names Akar.
            boolean fixed = Arrays.asList(files).contains(f);
            if (fixed || ours > 0) add(ours > 0, "read", f, result);
        }
    }

    // ---- properties, services, packages --------------------------------------------------------

    private static String[] sh(String cmd) {
        try {
            Process p = new ProcessBuilder("/system/bin/sh", "-c", cmd).redirectErrorStream(true).start();
            StringBuilder sb = new StringBuilder();
            try (InputStream in = p.getInputStream()) {
                byte[] b = new byte[8192];
                int n;
                while ((n = in.read(b)) > 0 && sb.length() < (4 << 20)) sb.append(new String(b, 0, n));
            }
            if (!p.waitFor(10, TimeUnit.SECONDS)) p.destroyForcibly();
            return new String[]{Integer.toString(p.exitValue()), sb.toString()};
        } catch (Exception e) {
            return new String[]{"-1", "error=" + e};
        }
    }

    private void props() {
        Pattern interesting = Pattern.compile("(?i)debuggable|build\\.(type|tags)|verifiedbootstate|flash\\.locked"
                + "|device_state|selinux|adb\\.root|service\\.adb|ro\\.secure|yasvara\\.root");
        for (String l : sh("getprop")[1].split("\n")) {
            if (interesting.matcher(l).find() || OURS.matcher(l).find()) {
                add(OURS.matcher(l).find(), "prop", l.replaceAll("^\\[([^\\]]*)\\]: \\[(.*)\\]$", "$1"),
                        l.replaceAll("^\\[([^\\]]*)\\]: \\[(.*)\\]$", "$2"));
            }
        }
    }

    private void services() {
        String[] r = sh("service list");
        if (!"0".equals(r[0])) {
            add(false, "svc", "service list", "exit=" + r[0]);
            return;
        }
        for (String l : r[1].split("\n")) {
            if (OURS.matcher(l).find()) add(true, "svc", l.replaceAll("^\\d+\\s+", ""), "listed");
        }
    }

    private void packages(Context c) {
        PackageManager pm = c.getPackageManager();
        for (PackageInfo p : pm.getInstalledPackages(0)) {
            if (Pattern.compile("(?i)yasvara|laras|akar|magisk|supersu|ksu").matcher(p.packageName).find()) {
                add(false, "pkg", p.packageName, "visible");
            }
        }
        for (String perm : new String[]{"yasvara.permission.MANAGE_ROOT", "yasvara.permission.MANAGE_TRUST"}) {
            try {
                pm.getPermissionInfo(perm, 0);
                add(true, "perm", perm, "visible");
            } catch (PackageManager.NameNotFoundException e) {
                add(false, "perm", perm, "not found");
            }
        }
    }

    // ---- the daemon socket and the client ------------------------------------------------------

    private void sockets() {
        for (String path : new String[]{"/dev/socket/yasvara_su", "/dev/socket/akar",
                "/data/misc/yasvara_root/run/ctl.sock", "/system/xbin/.s/ctl.sock",
                "/data/misc/yasvara_root/events.sock"}) {
            LocalSocket s = new LocalSocket();
            try {
                s.connect(new LocalSocketAddress(path, LocalSocketAddress.Namespace.FILESYSTEM));
                s.setSoTimeout(1000);
                byte[] b = new byte[16];
                int n = s.getInputStream().read(b);
                // First frame of the daemon: magic, kind, status, reason (never any secret).
                String frame = n == 16 ? "frame kind=" + b[4] + " status=" + b[5] + " reason=" + b[6] : "read=" + n;
                add(true, "conn", path, "connected " + frame);
            } catch (Exception e) {
                String m = String.valueOf(e.getMessage());
                String name = m.contains("EACCES") ? "EACCES" : m.contains("ENOENT") ? "ENOENT"
                        : m.contains("ECONNREFUSED") ? "ECONNREFUSED" : m;
                add(false, "conn", path, "errno=" + name);
            } finally {
                try {
                    s.close();
                } catch (Exception ignored) {
                }
            }
        }
    }

    private void execs() {
        // `su -v` is answered by the client itself and never reaches the daemon.
        String[] v = sh("/system/bin/su -v 2>&1");
        add("0".equals(v[0]), "exec", "su -v", "exit=" + v[0] + " " + v[1].trim().replace('\n', ' '));
        String[] w = sh("command -v su");
        add("0".equals(w[0]), "exec", "command -v su", "exit=" + w[0] + " " + w[1].trim());
        String[] x = sh("ls -l /system/xbin/su /system/bin/su 2>&1");
        add(false, "exec", "ls su", x[1].trim().replace('\n', ' '));
    }

    private void build() {
        add(false, "build", "type/tags", Build.TYPE + " " + Build.TAGS);
        add(false, "build", "fingerprint", Build.FINGERPRINT);
        String[] v = sh("cat /proc/version");
        add(false, "build", "proc/version", v[1].trim());
        String[] ctx = sh("cat /proc/self/attr/current");
        add(false, "selinux", "own context", ctx[1].trim().replaceAll("\\u0000", ""));
        String[] e = sh("cat /sys/fs/selinux/enforce");
        add(false, "selinux", "enforce", e[1].trim());
    }
}
