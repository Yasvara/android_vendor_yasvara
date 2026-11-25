/*
 * SPDX-FileCopyrightText: The Yasvara Project
 * SPDX-License-Identifier: Apache-2.0
 */
package yasvara.pasang;

/**
 * Lazy native In-OS Live CoW OTA & Recovery Bridge daemon (`pasangd`).
 *
 * All OTA planning, 7-Layer Hyper-Flash Sub-Partition dm-linear Extent Aliasing,
 * CrAU v2 parsing, AVB inspection, and OverlayFS management live in `libpasang`
 * (zero-dependency Rust). `pasangd` is woken on demand by `servicemanager` and
 * auto-exits after 30s idle (0 KB idle RAM).
 */
interface IPasang {
    /** Live OTA phase, progress percentage, MB/s, ETA, and Extent Alias savings as JSON. */
    @utf8InCpp String statusJson();

    /** Active/inactive A/B slot state, `super` free space, VAB merge status, and overlay summary. */
    @utf8InCpp String slotInfoJson();

    /** Inspects mounted OverlayFS partitions and `/mnt/scratch/overlay` upperdir counts (dev). */
    @utf8InCpp String overlayStatusJson();

    /** Clears `/mnt/scratch/overlay/<part>/upper` immediately and returns removal report JSON (dev). */
    @utf8InCpp String cleanOverlaysNowJson();

    /** Dry-run CoW OTA plan for a local OTA ZIP or `payload.bin` (returns savings & space JSON). */
    @utf8InCpp String planOtaJson(in @utf8InCpp String path, in @utf8InCpp String optionsJson);

    /**
     * Starts an asynchronous In-OS Live CoW OTA install.
     * Returns 0 on launch, -16 (EBUSY) if already running, or negative errno on error.
     */
    int startOta(in @utf8InCpp String path, in @utf8InCpp String optionsJson);

    /** Requests clean cancellation of an active OTA at the next chunk boundary. */
    oneway void cancelOta();

    /** Atomically writes the 32-byte Material You seed POD to `/metadata/yasvara/recovery_theme.bin`. */
    int writeRecoveryTheme(int seedArgb, boolean oledBlack, in @utf8InCpp String locale);

    /** Triggers a clean userspace reboot into the newly committed inactive slot. */
    int rebootToNewSlot();
}
