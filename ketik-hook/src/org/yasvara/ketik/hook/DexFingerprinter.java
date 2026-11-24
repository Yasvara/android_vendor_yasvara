/*
 * SPDX-FileCopyrightText: The Yasvara Project
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
package org.yasvara.ketik.hook;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * Pure-Java, zero-dependency DEX v035-v041 structural fingerprinter for Gboard.
 *
 * <p>Avoids pinning obfuscated R8 class names (e.g. {@code aicd}, {@code adfy}). Instead, resolves
 * target classes and method names by scanning DEX string pools first (skipping non-matching DEX
 * shards in a few milliseconds), then inspecting Dalvik {@code const-string} /
 * {@code const-string/jumbo} references inside {@code code_item} bytecode of the matching shard.
 */
public final class DexFingerprinter {

    // Stable R8-surviving anchors (Trace.beginSection / Flogger / Component tag registry strings).
    static final String ANCHOR_MODEL_READY = "CurrentHandlerModelReadyTag";
    static final String ANCHOR_EVER_PROVISIONED = "HandlerEverProvisionedTag";
    static final String ANCHOR_HANDLER_START =
            "ProofreadModelTag.notifyHandlerStart->NotificationCenter.notify";

    static final String ANCHOR_READINESS =
            "com/google/android/libraries/inputmethod/notificationcenter/ComponentsReadinessManager";
    static final String ANCHOR_READY_TRACE =
            "ComponentsReadinessManager.notifyOnComponentsReady->NotificationCenter.notify";
    static final String ANCHOR_UNREADY_TRACE =
            "ComponentsReadinessManager.notifyOnComponentsUnready->NotificationCenter.clearNotification";

    static final String ANCHOR_FLAG_MANAGER =
            "com/google/android/libraries/inputmethod/flag/FlagManager";

    static final String ANCHOR_SERVER_GENAI = "ServerSideGenAi";

    private static final Set<String> ALL_ANCHORS = new HashSet<>(Arrays.asList(
            ANCHOR_MODEL_READY,
            ANCHOR_EVER_PROVISIONED,
            ANCHOR_HANDLER_START,
            ANCHOR_READINESS,
            ANCHOR_READY_TRACE,
            ANCHOR_UNREADY_TRACE,
            ANCHOR_FLAG_MANAGER,
            ANCHOR_SERVER_GENAI));

    /** Resolved obfuscated symbol names for a specific Gboard APK version. */
    public static final class Resolved {
        /** ProofreadModelTag class (e.g. ahux in 18.5.6, aicd in 18.8.0). */
        public String proofreadTagClass;
        /** Unique public static ()I handler-type getter in proofreadTagClass. */
        public String handlerGetterMethod;
        /** Unique public static ()V tag-refresh method in proofreadTagClass. */
        public String refreshTagsMethod;

        /** ComponentsReadinessManager class (e.g. agxa in 18.5.6, aheb in 18.8.0). */
        public String readinessClass;
        /** Unique public static (Tag)Z readiness-query method in readinessClass. */
        public String isReadyMethod;

        /** FlagManager class (e.g. adcd in 18.5.6, adfy in 18.8.0). */
        public String flagManagerClass;
        /** Unique (Class, String, Object, boolean) flag-factory method in flagManagerClass. */
        public String createFlagMethod;

        /** GenAiManager / ServerSideGenAi holder class (e.g. adov in 18.5.6, adtl in 18.8.0). */
        public String serverGenAiClass;

        public boolean hasGenAiRoute() {
            return proofreadTagClass != null
                    && handlerGetterMethod != null
                    && refreshTagsMethod != null
                    && readinessClass != null
                    && isReadyMethod != null;
        }

        public boolean hasFlagManager() {
            return flagManagerClass != null && createFlagMethod != null;
        }

        public boolean isComplete() {
            return hasGenAiRoute() && hasFlagManager() && serverGenAiClass != null;
        }

        @Override
        public String toString() {
            return "Resolved{proofread=" + proofreadTagClass + "." + handlerGetterMethod
                    + "/" + refreshTagsMethod
                    + ", readiness=" + readinessClass + "." + isReadyMethod
                    + ", flagManager=" + flagManagerClass + "." + createFlagMethod
                    + ", serverGenAi=" + serverGenAiClass + "}";
        }
    }

    /** Dalvik instruction lengths in 16-bit code units for opcodes 0x00..0xFF. */
    private static final byte[] OPCODE_WIDTH = buildOpcodeWidthTable();

    private DexFingerprinter() {}

    /** Scans base APK (and any split APKs) for all Gboard anchors. */
    public static Resolved scanApks(List<File> apkFiles) throws IOException {
        final Resolved out = new Resolved();
        for (File apk : apkFiles) {
            if (apk == null || !apk.isFile()) continue;
            try (ZipFile zip = new ZipFile(apk)) {
                final Enumeration<? extends ZipEntry> entries = zip.entries();
                while (entries.hasMoreElements()) {
                    final ZipEntry entry = entries.nextElement();
                    final String name = entry.getName();
                    if (!name.endsWith(".dex") || name.indexOf('/') >= 0) continue;
                    final byte[] dex = readAll(zip.getInputStream(entry), entry.getSize());
                    scanDex(dex, out);
                    if (out.isComplete()) return out;
                }
            }
        }
        return out;
    }

    /** Scans a single DEX byte array, filling any unresolved fields in {@code out}. */
    public static void scanDex(byte[] dex, Resolved out) {
        if (dex == null || dex.length < 0x70) return;
        // DEX magic: "dex\n0XX\0"
        if (dex[0] != 'd' || dex[1] != 'e' || dex[2] != 'x' || dex[3] != '\n') return;

        final ByteBuffer buf = ByteBuffer.wrap(dex).order(ByteOrder.LITTLE_ENDIAN);
        final int stringIdsSize = buf.getInt(0x38);
        final int stringIdsOff = buf.getInt(0x3C);
        final int typeIdsSize = buf.getInt(0x40);
        final int typeIdsOff = buf.getInt(0x44);
        final int protoIdsSize = buf.getInt(0x48);
        final int protoIdsOff = buf.getInt(0x4C);
        final int methodIdsSize = buf.getInt(0x58);
        final int methodIdsOff = buf.getInt(0x5C);
        final int classDefsSize = buf.getInt(0x60);
        final int classDefsOff = buf.getInt(0x64);

        if (stringIdsSize <= 0 || classDefsSize <= 0) return;

        // Stage 1: Fast string-pool probe. Skip entire DEX if none of our needed anchors exist.
        final Map<Integer, String> wantedStrings = new HashMap<>();
        for (int i = 0; i < stringIdsSize; i++) {
            final int dataOff = buf.getInt(stringIdsOff + i * 4);
            final String s = readMutf8IfCandidate(dex, dataOff);
            if (s != null && ALL_ANCHORS.contains(s)) {
                wantedStrings.put(i, s);
            }
        }
        if (wantedStrings.isEmpty()) return;

        final boolean wantProofread = !out.hasGenAiRoute()
                && wantedStrings.containsValue(ANCHOR_MODEL_READY)
                && wantedStrings.containsValue(ANCHOR_EVER_PROVISIONED);
        final boolean wantReadiness = (out.readinessClass == null || out.isReadyMethod == null)
                && wantedStrings.containsValue(ANCHOR_READINESS);
        final boolean wantFlagManager = !out.hasFlagManager()
                && wantedStrings.containsValue(ANCHOR_FLAG_MANAGER);
        final boolean wantServerGenAi = out.serverGenAiClass == null
                && wantedStrings.containsValue(ANCHOR_SERVER_GENAI);

        if (!wantProofread && !wantReadiness && !wantFlagManager && !wantServerGenAi) return;

        // Stage 2: Walk class_defs in this matching DEX shard only.
        for (int c = 0; c < classDefsSize; c++) {
            final int defOff = classDefsOff + c * 32;
            final int classIdx = buf.getInt(defOff);
            final int classDataOff = buf.getInt(defOff + 24);
            if (classDataOff == 0) continue;

            final List<MethodInfo> methods = parseClassMethods(dex, classDataOff);
            if (methods.isEmpty()) continue;

            // Collect anchor strings referenced in this class's methods (per-method + union).
            final Set<String> classAnchors = new HashSet<>();
            Map<MethodInfo, Set<String>> methodAnchors = null;
            for (MethodInfo mi : methods) {
                if (mi.codeOff == 0) continue;
                final Set<String> hits = findConstStrings(dex, buf, mi.codeOff, wantedStrings);
                if (!hits.isEmpty()) {
                    classAnchors.addAll(hits);
                    if (methodAnchors == null) methodAnchors = new HashMap<>();
                    methodAnchors.put(mi, hits);
                }
            }
            if (classAnchors.isEmpty()) continue;

            final String className = descriptorToClassName(
                    readTypeDescriptor(dex, buf, stringIdsOff, typeIdsOff, classIdx));
            if (className == null) continue;

            // 1. ProofreadModelTag (aicd / ahux)
            if (wantProofread
                    && classAnchors.contains(ANCHOR_MODEL_READY)
                    && classAnchors.contains(ANCHOR_EVER_PROVISIONED)) {
                String getter = null;
                String refresher = null;
                int getterCount = 0;
                int refresherCount = 0;
                for (MethodInfo mi : methods) {
                    if ((mi.accessFlags & ACC_STATIC) == 0 || (mi.accessFlags & ACC_PUBLIC) == 0) {
                        continue;
                    }
                    final String mName = readMethodName(dex, buf, stringIdsOff, methodIdsOff, mi.methodIdx);
                    if ("<clinit>".equals(mName) || "<init>".equals(mName)) continue;
                    final String shorty = readMethodShorty(
                            dex, buf, stringIdsOff, protoIdsOff, methodIdsOff, mi.methodIdx);
                    if ("I".equals(shorty)) {
                        getter = mName;
                        getterCount++;
                    } else if ("V".equals(shorty)) {
                        refresher = mName;
                        refresherCount++;
                    }
                }
                if (getterCount == 1 && refresherCount == 1) {
                    out.proofreadTagClass = className;
                    out.handlerGetterMethod = getter;
                    out.refreshTagsMethod = refresher;
                }
            }

            // 2. ComponentsReadinessManager (aheb / agxa)
            if (wantReadiness && classAnchors.contains(ANCHOR_READINESS)) {
                String isReady = null;
                int readyCount = 0;
                for (MethodInfo mi : methods) {
                    if ((mi.accessFlags & ACC_STATIC) == 0 || (mi.accessFlags & ACC_PUBLIC) == 0) {
                        continue;
                    }
                    final String shorty = readMethodShorty(
                            dex, buf, stringIdsOff, protoIdsOff, methodIdsOff, mi.methodIdx);
                    if (!"ZL".equals(shorty)) continue;
                    final Set<String> mh = methodAnchors != null ? methodAnchors.get(mi) : null;
                    if (mh != null && (mh.contains(ANCHOR_READY_TRACE)
                            || mh.contains(ANCHOR_UNREADY_TRACE))) {
                        continue;
                    }
                    isReady = readMethodName(dex, buf, stringIdsOff, methodIdsOff, mi.methodIdx);
                    readyCount++;
                }
                if (readyCount == 1) {
                    out.readinessClass = className;
                    out.isReadyMethod = isReady;
                }
            }

            // 3. FlagManager (adfy / adcd)
            if (wantFlagManager && classAnchors.contains(ANCHOR_FLAG_MANAGER)) {
                String creator = null;
                int creatorCount = 0;
                for (MethodInfo mi : methods) {
                    if ((mi.accessFlags & ACC_STATIC) != 0) continue;
                    final String shorty = readMethodShorty(
                            dex, buf, stringIdsOff, protoIdsOff, methodIdsOff, mi.methodIdx);
                    if (!"LLLLZ".equals(shorty)) continue;
                    final List<String> params = readMethodParamTypes(
                            dex, buf, stringIdsOff, typeIdsOff, protoIdsOff, methodIdsOff, mi.methodIdx);
                    if (params.size() == 4
                            && "Ljava/lang/Class;".equals(params.get(0))
                            && "Ljava/lang/String;".equals(params.get(1))
                            && "Ljava/lang/Object;".equals(params.get(2))
                            && "Z".equals(params.get(3))) {
                        creator = readMethodName(dex, buf, stringIdsOff, methodIdsOff, mi.methodIdx);
                        creatorCount++;
                    }
                }
                if (creatorCount == 1) {
                    out.flagManagerClass = className;
                    out.createFlagMethod = creator;
                }
            }

            // 4. ServerSideGenAi holder (adtl / adov)
            if (wantServerGenAi && classAnchors.contains(ANCHOR_SERVER_GENAI)) {
                out.serverGenAiClass = className;
            }
        }
    }

    private static final int ACC_PUBLIC = 0x0001;
    private static final int ACC_STATIC = 0x0008;

    private static final class MethodInfo {
        final int methodIdx;
        final int accessFlags;
        final int codeOff;

        MethodInfo(int methodIdx, int accessFlags, int codeOff) {
            this.methodIdx = methodIdx;
            this.accessFlags = accessFlags;
            this.codeOff = codeOff;
        }
    }

    private static List<MethodInfo> parseClassMethods(byte[] dex, int off) {
        final int[] pos = {off};
        final int staticFields = readUleb128(dex, pos);
        final int instanceFields = readUleb128(dex, pos);
        final int directMethods = readUleb128(dex, pos);
        final int virtualMethods = readUleb128(dex, pos);

        for (int i = 0; i < staticFields + instanceFields; i++) {
            readUleb128(dex, pos); // field_idx_diff
            readUleb128(dex, pos); // access_flags
        }

        final List<MethodInfo> out = new ArrayList<>(directMethods + virtualMethods);
        int methodIdx = 0;
        for (int i = 0; i < directMethods; i++) {
            methodIdx += readUleb128(dex, pos);
            final int flags = readUleb128(dex, pos);
            final int codeOff = readUleb128(dex, pos);
            out.add(new MethodInfo(methodIdx, flags, codeOff));
        }
        methodIdx = 0;
        for (int i = 0; i < virtualMethods; i++) {
            methodIdx += readUleb128(dex, pos);
            final int flags = readUleb128(dex, pos);
            final int codeOff = readUleb128(dex, pos);
            out.add(new MethodInfo(methodIdx, flags, codeOff));
        }
        return out;
    }

    private static Set<String> findConstStrings(
            byte[] dex, ByteBuffer buf, int codeOff, Map<Integer, String> wanted) {
        final int insnsSize = buf.getInt(codeOff + 12);
        final int insnsStart = codeOff + 16;
        Set<String> hits = null;
        int u = 0;
        while (u < insnsSize) {
            final int unitOff = insnsStart + (u << 1);
            if (unitOff + 2 > dex.length) break;
            final int unit0 = buf.getShort(unitOff) & 0xFFFF;
            final int op = unit0 & 0xFF;

            if (unit0 == 0x0100) { // packed-switch-payload
                if (u + 2 > insnsSize) break;
                final int sz = buf.getShort(unitOff + 2) & 0xFFFF;
                u += sz * 2 + 4;
                continue;
            } else if (unit0 == 0x0200) { // sparse-switch-payload
                if (u + 2 > insnsSize) break;
                final int sz = buf.getShort(unitOff + 2) & 0xFFFF;
                u += sz * 4 + 2;
                continue;
            } else if (unit0 == 0x0300) { // fill-array-data-payload
                if (u + 4 > insnsSize) break;
                final int elemWidth = buf.getShort(unitOff + 2) & 0xFFFF;
                final int sz = buf.getInt(unitOff + 4);
                u += 4 + (int) (((long) elemWidth * (long) sz + 1L) >>> 1);
                continue;
            }

            if (op == 0x1A && u + 2 <= insnsSize) { // const-string
                final int strIdx = buf.getShort(unitOff + 2) & 0xFFFF;
                final String hit = wanted.get(strIdx);
                if (hit != null) {
                    if (hits == null) hits = new HashSet<>(4);
                    hits.add(hit);
                }
            } else if (op == 0x1B && u + 3 <= insnsSize) { // const-string/jumbo
                final int strIdx = buf.getInt(unitOff + 2);
                final String hit = wanted.get(strIdx);
                if (hit != null) {
                    if (hits == null) hits = new HashSet<>(4);
                    hits.add(hit);
                }
            }

            final int w = OPCODE_WIDTH[op];
            u += (w > 0 ? w : 1);
        }
        return hits == null ? java.util.Collections.emptySet() : hits;
    }

    /**
     * Fast MUTF-8 reader that rejects strings whose UTF-16 length cannot match any anchor before
     * allocating a {@link String}.
     */
    private static String readMutf8IfCandidate(byte[] dex, int off) {
        final int[] pos = {off};
        final int utf16Len = readUleb128(dex, pos);
        // Shortest anchor is "ServerSideGenAi" (15); longest is 90.
        if (utf16Len < 15 || utf16Len > 120) return null;
        return decodeMutf8(dex, pos[0], utf16Len);
    }

    private static String readStringAt(byte[] dex, ByteBuffer buf, int stringIdsOff, int strIdx) {
        final int dataOff = buf.getInt(stringIdsOff + strIdx * 4);
        final int[] pos = {dataOff};
        final int utf16Len = readUleb128(dex, pos);
        return decodeMutf8(dex, pos[0], utf16Len);
    }

    private static String readTypeDescriptor(
            byte[] dex, ByteBuffer buf, int stringIdsOff, int typeIdsOff, int typeIdx) {
        final int descIdx = buf.getInt(typeIdsOff + typeIdx * 4);
        return readStringAt(dex, buf, stringIdsOff, descIdx);
    }

    private static String readMethodName(
            byte[] dex, ByteBuffer buf, int stringIdsOff, int methodIdsOff, int methodIdx) {
        final int nameIdx = buf.getInt(methodIdsOff + methodIdx * 8 + 4);
        return readStringAt(dex, buf, stringIdsOff, nameIdx);
    }

    private static String readMethodShorty(
            byte[] dex, ByteBuffer buf, int stringIdsOff, int protoIdsOff, int methodIdsOff,
            int methodIdx) {
        final int protoIdx = buf.getShort(methodIdsOff + methodIdx * 8 + 2) & 0xFFFF;
        final int shortyIdx = buf.getInt(protoIdsOff + protoIdx * 12);
        return readStringAt(dex, buf, stringIdsOff, shortyIdx);
    }

    private static List<String> readMethodParamTypes(
            byte[] dex, ByteBuffer buf, int stringIdsOff, int typeIdsOff, int protoIdsOff,
            int methodIdsOff, int methodIdx) {
        final int protoIdx = buf.getShort(methodIdsOff + methodIdx * 8 + 2) & 0xFFFF;
        final int paramsOff = buf.getInt(protoIdsOff + protoIdx * 12 + 8);
        if (paramsOff == 0) return java.util.Collections.emptyList();
        final int count = buf.getInt(paramsOff);
        final List<String> params = new ArrayList<>(count);
        for (int i = 0; i < count; i++) {
            final int typeIdx = buf.getShort(paramsOff + 4 + i * 2) & 0xFFFF;
            params.add(readTypeDescriptor(dex, buf, stringIdsOff, typeIdsOff, typeIdx));
        }
        return params;
    }

    private static String descriptorToClassName(String desc) {
        if (desc == null || desc.length() < 3 || desc.charAt(0) != 'L'
                || desc.charAt(desc.length() - 1) != ';') {
            return null;
        }
        return desc.substring(1, desc.length() - 1).replace('/', '.');
    }

    private static int readUleb128(byte[] data, int[] pos) {
        int result = 0;
        int shift = 0;
        int p = pos[0];
        while (p < data.length) {
            final int b = data[p++] & 0xFF;
            result |= (b & 0x7F) << shift;
            if ((b & 0x80) == 0) break;
            shift += 7;
        }
        pos[0] = p;
        return result;
    }

    private static String decodeMutf8(byte[] data, int off, int utf16Len) {
        final char[] chars = new char[utf16Len];
        int p = off;
        int out = 0;
        while (out < utf16Len && p < data.length) {
            final int a = data[p++] & 0xFF;
            if (a == 0) break;
            if (a < 0x80) {
                chars[out++] = (char) a;
            } else if ((a & 0xE0) == 0xC0) {
                if (p >= data.length) break;
                final int b = data[p++] & 0xFF;
                chars[out++] = (char) (((a & 0x1F) << 6) | (b & 0x3F));
            } else if ((a & 0xF0) == 0xE0) {
                if (p + 1 >= data.length) break;
                final int b = data[p++] & 0xFF;
                final int c = data[p++] & 0xFF;
                chars[out++] = (char) (((a & 0x0F) << 12) | ((b & 0x3F) << 6) | (c & 0x3F));
            } else {
                break;
            }
        }
        return new String(chars, 0, out);
    }

    private static byte[] readAll(InputStream in, long declaredSize) throws IOException {
        try (InputStream s = in) {
            final int cap = declaredSize > 0 && declaredSize < 64 * 1024 * 1024
                    ? (int) declaredSize : 65536;
            final ByteArrayOutputStream bos = new ByteArrayOutputStream(cap);
            final byte[] tmp = new byte[32768];
            int n;
            while ((n = s.read(tmp)) >= 0) {
                if (n > 0) bos.write(tmp, 0, n);
            }
            return bos.toByteArray();
        }
    }

    private static byte[] buildOpcodeWidthTable() {
        final byte[] w = new byte[256];
        Arrays.fill(w, (byte) 1);
        w[0x02] = 2; w[0x03] = 3;
        w[0x05] = 2; w[0x06] = 3;
        w[0x08] = 2; w[0x09] = 3;
        w[0x13] = 2; w[0x14] = 3; w[0x15] = 2;
        w[0x16] = 2; w[0x17] = 3; w[0x18] = 5; w[0x19] = 2;
        w[0x1A] = 2; w[0x1B] = 3; w[0x1C] = 2;
        w[0x1F] = 2; w[0x20] = 2;
        w[0x22] = 2; w[0x23] = 2;
        w[0x24] = 3; w[0x25] = 3; w[0x26] = 3;
        w[0x29] = 2; w[0x2A] = 3;
        w[0x2B] = 3; w[0x2C] = 3;
        for (int i = 0x2D; i <= 0x3D; i++) w[i] = 2;
        for (int i = 0x44; i <= 0x6D; i++) w[i] = 2;
        for (int i = 0x6E; i <= 0x72; i++) w[i] = 3;
        for (int i = 0x74; i <= 0x78; i++) w[i] = 3;
        for (int i = 0x90; i <= 0xAF; i++) w[i] = 2;
        for (int i = 0xD0; i <= 0xE2; i++) w[i] = 2;
        w[0xFA] = 4; w[0xFB] = 4;
        w[0xFC] = 3; w[0xFD] = 3;
        w[0xFE] = 2; w[0xFF] = 2;
        return w;
    }
}
