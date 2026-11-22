/*
 * SPDX-FileCopyrightText: The Yasvara Project
 * SPDX-License-Identifier: Apache-2.0
 */
import android.security.yasvara.YasvaraBootDigest;

import java.util.Arrays;

/** Tests the production codec/resolver without Android stubs or a connected device. */
public final class BootDigestHostTest {
    private static int checks;

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
        checks++;
    }

    public static void main(String[] args) {
        byte[] sha256 = new byte[32];
        byte[] sha512 = new byte[64];
        for (int i = 0; i < sha256.length; i++) sha256[i] = (byte) (i * 9);
        for (int i = 0; i < sha512.length; i++) sha512[i] = (byte) (255 - i * 3);
        String hex256 = YasvaraBootDigest.encode(sha256);
        String hex512 = YasvaraBootDigest.encode(sha512);
        check(hex256.length() == 64, "SHA-256 size");
        check(hex512.length() == 128, "SHA-512 size");
        check(Arrays.equals(sha256, YasvaraBootDigest.decodeCanonical(hex256)), "SHA-256 roundtrip");
        check(Arrays.equals(sha512, YasvaraBootDigest.decodeCanonical(hex512)), "SHA-512 roundtrip");
        for (String invalid : new String[] {null, "", "ab", "a".repeat(63), "a".repeat(65),
                "a".repeat(127), "a".repeat(129), "g".repeat(64), "Ａ".repeat(64),
                hex256.toUpperCase(java.util.Locale.ROOT), " " + hex256, hex256 + "\n"}) {
            check(YasvaraBootDigest.decodeCanonical(invalid) == null, "reject malformed canonical");
        }
        check(YasvaraBootDigest.normalize(" \t" + hex256.toUpperCase(java.util.Locale.ROOT) + "\n")
                .equals(hex256), "normalize external whitespace/case");
        String colonHash = String.join(":", hex512.split("(?<=\\G..)"));
        check(hex512.equals(YasvaraBootDigest.normalize(colonHash)), "normalize separated SHA-512");
        check(YasvaraBootDigest.normalize("a".repeat(513)) == null, "bound external input");
        check(YasvaraBootDigest.normalize("0x" + hex256) == null, "reject hex prefixes");
        check(YasvaraBootDigest.normalize("zz" + hex256.substring(2)) == null, "reject nonhex");
        check(YasvaraBootDigest.encode(null) == null, "missing attestation is not a digest");
        check(YasvaraBootDigest.encode(new byte[31]) == null, "reject truncated attestation");
        check(YasvaraBootDigest.select(null, null) == null, "no invented fallback");
        check(YasvaraBootDigest.select("broken", new byte[1]) == null, "invalid sources unavailable");
        YasvaraBootDigest.Selection fromProperty = YasvaraBootDigest.select(hex256, null);
        check(fromProperty.digest.equals(hex256) && fromProperty.source.equals("bootloader"),
                "bootloader measurement");
        YasvaraBootDigest.Selection fromTee = YasvaraBootDigest.select("", sha256);
        check(fromTee.digest.equals(hex256) && fromTee.source.equals("tee"), "TEE fallback");
        check(YasvaraBootDigest.select("broken", sha512).digest.equals(hex512), "invalid property fallback");
        check(YasvaraBootDigest.select(hex512, sha512).source.equals("bootloader"), "agreeing sources");
        check(YasvaraBootDigest.select(hex256, sha512) == null, "length disagreement preserved");
        byte[] other = sha256.clone();
        other[0] ^= 1;
        check(YasvaraBootDigest.select(hex256, other) == null, "value disagreement preserved");
        check(YasvaraBootDigest.matches(hex256, sha256), "matching original hash");
        check(!YasvaraBootDigest.matches(hex256, other), "mismatched original hash");
        check(!YasvaraBootDigest.matches("", null), "unavailable must not compare equal");
        byte[] decoded = YasvaraBootDigest.decodeCanonical(hex256);
        decoded[0] ^= 1;
        check(Arrays.equals(sha256, YasvaraBootDigest.decodeCanonical(hex256)), "no mutable shared digest");
        System.out.println("Boot digest codec/resolver: " + checks + " checks passed");
    }
}
