/*
 * SPDX-FileCopyrightText: The Yasvara Project
 * SPDX-License-Identifier: Apache-2.0
 */

package vendor.yasvara.hentak;

/**
 * Hentak's learned game-sound tagger on the NPU, for audioserver's haptics worker.
 *
 * The session is one shared memory region (layout `hentak::tagger::Shm`): the caller writes the
 * game track's 48 kHz mono audio into its ring and reads, from its result block, what is sounding
 * at the ring's newest sample (12 labels and their levels against the mix). The tagger labels the
 * newest window every 40 ms, and at once when the caller bumps the request word.
 */
@VintfStability
interface ITagger {
    /** Version of the shared memory layout this service speaks. */
    const int SHM_VERSION = 1;

    /** Starts tagging; returns the session memory. A new attach replaces the previous session. */
    ParcelFileDescriptor attach();

    /** Stops tagging; the NPU goes idle until the next attach. */
    void detach();
}
