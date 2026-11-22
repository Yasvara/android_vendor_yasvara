/*
 * SPDX-FileCopyrightText: The Yasvara Project
 * SPDX-License-Identifier: Apache-2.0
 */
package yasvara.padat;

/**
 * Lazy native F2FS per-app realtime compression daemon interface.
 *
 * All policy, Smart Probe entropy/LZ4 analysis, and atomic compression/decompression
 * logic lives in `libpadat` (std-only Rust). `padatd` is a thin Binder shim woken on demand
 * by `servicemanager` and exits automatically when idle.
 */
interface IPadat {
    /** Returns kernel F2FS compression status, counters, battery temp, and job state as JSON. */
    @utf8InCpp String statusJson();

    /** Returns `/data/system/padat/policy.json` (normalized defaults if absent). */
    @utf8InCpp String getPolicyJson();

    /** Validates and atomically writes policy JSON; returns 0 or negative errno. */
    int setPolicyJson(in @utf8InCpp String json);

    /** Dry-run Smart Probe scan of a package for a given profile and scope bitmask. */
    @utf8InCpp String scanPackageJson(in @utf8InCpp String pkg, int algo, int level,
            int clusterKb, int scopeMask);

    /** Atomically compresses eligible files in a package and marks directories for inheritance. */
    @utf8InCpp String compressPackageJson(in @utf8InCpp String pkg, int algo, int level,
            int clusterKb, int scopeMask, boolean allowRunning);

    /** Fast incremental sync after app/in-game updates: reclaims new blocks & compresses moved patches. */
    @utf8InCpp String syncPackageJson(in @utf8InCpp String pkg, int algo, int level,
            int clusterKb, int scopeMask);

    /** Atomically decompresses compressed files in a package and clears directory inheritance. */
    @utf8InCpp String decompressPackageJson(in @utf8InCpp String pkg, int scopeMask,
            boolean allowRunning);

    /** Recursively runs `F2FS_IOC_RELEASE_COMPRESS_BLOCKS` on already-compressed files. */
    @utf8InCpp String releasePathJson(in @utf8InCpp String path);

    /** Fast stat-only summary across all installed packages under `/data/app` as JSON array. */
    @utf8InCpp String allStatsJson();

    /** Removes any orphaned `.padat.tmp.*` files left behind by a power loss. */
    long cleanupStaleTemps();

    /** Applies `FS_COMPR_FL` + V2 compress option directly to a directory for realtime inheritance. */
    int applyDirProfile(in @utf8InCpp String path, int algo, int level, int clusterKb);

    /** Pauses or resumes active background compression (e.g. game launch or thermal throttle). */
    oneway void setPaused(boolean paused);

    /** Cancels the currently running compression/decompression job at the next chunk boundary. */
    oneway void cancelJob();
}
