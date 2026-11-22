/*
 * SPDX-FileCopyrightText: The Yasvara Project
 * SPDX-License-Identifier: Apache-2.0
 */
package yasvara.pantau;

import android.os.ParcelFileDescriptor;

/**
 * Lazy native telemetry & HUD daemon interface.
 *
 * Oneway calls never stall system_server or Pentas on sampling; readers map the sealed memfd
 * returned by {@link #snapshotFd} read-only and read the seqlock without per-tick IPC.
 */
interface IPantau {
    /** Passes raw `Settings.Secure pentas_hud` profile string; Rust parses and owns the schema. */
    oneway void configure(in @utf8InCpp String hudProfile);

    /** Notifies game start/end (uid < 0 = session end) or focused task/uid update. */
    oneway void session(int taskId, int uid, boolean isGame);

    /** Sets the Pentas panel's active metric consumer bitmask (0 when panel closed). */
    oneway void setConsumers(long consumerMask);

    /** Pushes zero-poll system events (thermal, display, battery, wifi/cell, screen, hud pin). */
    oneway void event(int kind, long a, long b);

    /** Pushes focused-task FPS from SurfaceFlinger (fps * 100). */
    oneway void pushFps(int fpsX100);

    /** Notifies display rotation/size/refresh rate change (from DisplayManager). */
    oneway void displayChanged(int rotation, int widthPx, int heightPx, int refreshHz);

    /** Pushes 4 Monet dark ARGB colors: [surface, primary, onSurface, onSurfaceVariant]. */
    oneway void setMonet(in int[] argb4);

    /** Moves a widget during edit mode (single setPosition transaction, zero redraw). */
    oneway void moveWidget(int widgetId, int x, int y);

    /** Lazily caches an app's friendly label and 28x28 RGBA8888 icon for the native Processes HUD. */
    oneway void pushUidMeta(int uid, in @utf8InCpp String label, in byte[] rgba28x28);

    /** Event-driven transport & signal metadata (Wi-Fi standard/freq/RSSI + Mobile 5G/4G RSRP). */
    oneway void pushNetMeta(int linkMask, int wifiStd, int wifiFreqMhz, int wifiLinkMbps,
            int wifiRssiDbm, int cellGen, int cellLevel, int cellRsrpDbm);

    /** Parents native HUD container under Display 0 Accessibility Overlays so scrcpy mirrors it. */
    oneway void setHudParent(in IBinder parentHandle);

    /** Returns a dup of the sealed shared-memory Snapshot memfd for read-only client mapping. */
    ParcelFileDescriptor snapshotFd();

    /** Executes a structured `cmd pantau <cmd>` JSON query (`status`, `snap`, ...). */
    @utf8InCpp String query(in @utf8InCpp String cmd);
}
