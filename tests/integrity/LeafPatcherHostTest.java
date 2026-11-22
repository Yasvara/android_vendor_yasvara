/*
 * SPDX-FileCopyrightText: The Yasvara Project
 * SPDX-License-Identifier: Apache-2.0
 */
package android.security.yasvara;

import com.android.internal.org.bouncycastle.asn1.ASN1Boolean;
import com.android.internal.org.bouncycastle.asn1.ASN1Encodable;
import com.android.internal.org.bouncycastle.asn1.ASN1EncodableVector;
import com.android.internal.org.bouncycastle.asn1.ASN1Enumerated;
import com.android.internal.org.bouncycastle.asn1.ASN1Integer;
import com.android.internal.org.bouncycastle.asn1.ASN1ObjectIdentifier;
import com.android.internal.org.bouncycastle.asn1.ASN1OctetString;
import com.android.internal.org.bouncycastle.asn1.ASN1Sequence;
import com.android.internal.org.bouncycastle.asn1.ASN1TaggedObject;
import com.android.internal.org.bouncycastle.asn1.DEROctetString;
import com.android.internal.org.bouncycastle.asn1.DERSequence;
import com.android.internal.org.bouncycastle.asn1.DERTaggedObject;
import com.android.internal.org.bouncycastle.asn1.x500.X500Name;
import com.android.internal.org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import com.android.internal.org.bouncycastle.asn1.x509.BasicConstraints;
import com.android.internal.org.bouncycastle.asn1.x509.Extension;
import com.android.internal.org.bouncycastle.asn1.x509.KeyUsage;
import com.android.internal.org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import com.android.internal.org.bouncycastle.cert.X509CertificateHolder;
import com.android.internal.org.bouncycastle.cert.X509v3CertificateBuilder;
import com.android.internal.org.bouncycastle.operator.ContentSigner;
import com.android.internal.org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Map;

/**
 * End-to-end tests of the actual production patcher/parser, not a host reimplementation.
 * All keys/certificates are generated in memory; bootHash is the already-decoded canonical
 * digest at the Request boundary (property selection/decoding has its own host test).
 */
public final class LeafPatcherHostTest {
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final ASN1ObjectIdentifier PROBE_OID =
            new ASN1ObjectIdentifier("1.3.6.1.4.1.55555.1");
    private static final Map<Integer, String> IDS = Map.of(
            710, "host-brand", 711, "host-device", 712, "host-product",
            716, "host-manufacturer", 717, "host-model");
    private static final Date NOT_BEFORE = new Date(System.currentTimeMillis() - 60_000);
    private static final Date NOT_AFTER = new Date(System.currentTimeMillis() + 86_400_000L);
    private static final List<String> FAILURES = new ArrayList<>();
    private static int cases;
    private static int checks;
    private static long serial;

    private final KeyPair hardwareKey = newKey();
    private final KeyPair issuerKey = newKey();
    private final X509Certificate hardwareRoot = root("Ephemeral hardware root", hardwareKey);
    private final X509Certificate issuerRoot = root("Ephemeral patch issuer", issuerKey);

    private LeafPatcherHostTest() throws Exception {}

    @FunctionalInterface
    private interface TestCase {
        void run() throws Exception;
    }

    private static void check(boolean condition, String message) {
        checks++;
        if (!condition) throw new AssertionError(message);
    }

    private static void bytes(byte[] expected, byte[] actual, String message) {
        check(Arrays.equals(expected, actual), message);
    }

    private static void run(String name, TestCase test) {
        cases++;
        try {
            test.run();
            System.out.println("PASS " + name);
        } catch (Throwable failure) {
            FAILURES.add(name + ": " + failure);
            System.err.println("FAIL " + name);
            failure.printStackTrace(System.err);
        }
    }

    private static byte[] randomBytes(int size) {
        byte[] value = new byte[size];
        RANDOM.nextBytes(value);
        return value;
    }

    private static byte[] different(byte[] value) {
        byte[] changed = value.clone();
        changed[0] ^= 1;
        return changed;
    }

    private static KeyPair newKey() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"), RANDOM);
        return generator.generateKeyPair();
    }

    /** JDK signing is used only to create fixtures; patch() uses its real BC signer. */
    private static final class JdkSigner implements ContentSigner {
        private final ByteArrayOutputStream output = new ByteArrayOutputStream();
        private final PrivateKey key;
        private final String algorithm;

        JdkSigner(PrivateKey key) {
            this(key, "SHA256withECDSA");
        }

        JdkSigner(PrivateKey key, String algorithm) {
            this.key = key;
            this.algorithm = algorithm;
        }

        @Override
        public AlgorithmIdentifier getAlgorithmIdentifier() {
            return new DefaultSignatureAlgorithmIdentifierFinder().find(algorithm);
        }

        @Override
        public OutputStream getOutputStream() {
            return output;
        }

        @Override
        public byte[] getSignature() {
            try {
                Signature signature = Signature.getInstance(algorithm);
                signature.initSign(key, RANDOM);
                signature.update(output.toByteArray());
                return signature.sign();
            } catch (Exception error) {
                throw new IllegalStateException("Cannot sign ephemeral test certificate", error);
            }
        }
    }

    private static X509Certificate certificate(X509v3CertificateBuilder builder, PrivateKey key)
            throws Exception {
        return certificate(builder, key, "SHA256withECDSA");
    }

    private static X509Certificate certificate(X509v3CertificateBuilder builder, PrivateKey key,
            String algorithm) throws Exception {
        return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(
                new ByteArrayInputStream(builder.build(new JdkSigner(key, algorithm)).getEncoded()));
    }

    private static X509Certificate root(String commonName, KeyPair key) throws Exception {
        X500Name name = new X500Name("CN=" + commonName);
        X509v3CertificateBuilder builder = new X509v3CertificateBuilder(name,
                BigInteger.valueOf(++serial), NOT_BEFORE, NOT_AFTER, name,
                SubjectPublicKeyInfo.getInstance(key.getPublic().getEncoded()));
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        builder.addExtension(Extension.keyUsage, true,
                new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
        X509Certificate root = certificate(builder, key.getPrivate());
        root.verify(key.getPublic());
        return root;
    }

    private static DERTaggedObject rootTag(ASN1Encodable key, ASN1Encodable locked,
            ASN1Encodable state, ASN1Encodable hash) {
        return new DERTaggedObject(true, 704,
                new DERSequence(new ASN1Encodable[] {key, locked, state, hash}));
    }

    private static DERTaggedObject rootTag(byte[] key, byte[] hash) {
        return rootTag(new DEROctetString(key), ASN1Boolean.FALSE,
                new ASN1Enumerated(2), new DEROctetString(hash));
    }

    private static ASN1Encodable[] description(byte[] nonce, int attestationLevel,
            int keymasterLevel, ASN1Encodable... roots) {
        ASN1EncodableVector tee = new ASN1EncodableVector();
        tee.add(new DERTaggedObject(true, 2, new ASN1Integer(3)));
        tee.add(new DERTaggedObject(true, 3, new ASN1Integer(256)));
        tee.add(new DERTaggedObject(true, 702, new ASN1Integer(0)));
        for (ASN1Encodable root : roots) tee.add(root);
        tee.add(new DERTaggedObject(true, 705, new ASN1Integer(110000)));
        tee.add(new DERTaggedObject(true, 706, new ASN1Integer(202001)));
        for (int tag : new int[] {710, 711, 712, 713, 716, 717}) {
            tee.add(new DERTaggedObject(true, tag, new DEROctetString(randomBytes(12))));
        }
        tee.add(new DERTaggedObject(true, 718, new ASN1Integer(20200101)));
        tee.add(new DERTaggedObject(true, 719, new ASN1Integer(20200101)));
        tee.add(new DERTaggedObject(true, 724, new DEROctetString(randomBytes(32))));
        return new ASN1Encodable[] {
                new ASN1Integer(400), new ASN1Enumerated(attestationLevel),
                new ASN1Integer(400), new ASN1Enumerated(keymasterLevel),
                new DEROctetString(nonce), new DEROctetString(randomBytes(16)),
                new DERSequence(new DERTaggedObject(true, 701,
                        new ASN1Integer(NOT_BEFORE.getTime()))), new DERSequence(tee),
        };
    }

    private X509Certificate leaf(PublicKey publicKey, X509Certificate issuer, PrivateKey signingKey,
            BigInteger leafSerial, ASN1Encodable[] description) throws Exception {
        return leaf(publicKey, issuer, signingKey, leafSerial, description, "SHA256withECDSA");
    }

    private X509Certificate leaf(PublicKey publicKey, X509Certificate issuer, PrivateKey signingKey,
            BigInteger leafSerial, ASN1Encodable[] description, String signatureAlgorithm)
            throws Exception {
        X509v3CertificateBuilder builder = new X509v3CertificateBuilder(
                new X509CertificateHolder(issuer.getEncoded()).getSubject(), leafSerial,
                NOT_BEFORE, NOT_AFTER, new X500Name("CN=Ephemeral application leaf"),
                SubjectPublicKeyInfo.getInstance(publicKey.getEncoded()));
        builder.addExtension(YasvaraAttestation.ATTESTATION_OID, false,
                new DERSequence(description));
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));
        builder.addExtension(PROBE_OID, false, new DEROctetString(new byte[] {1, 4, 9}));
        return certificate(builder, signingKey, signatureAlgorithm);
    }

    private final class Fixture {
        final KeyPair key = newKey();
        final byte[] nonce = randomBytes(32);
        final byte[] hash;
        final byte[] bootKey;
        final X509Certificate leaf;
        final YasvaraAttestation.Record record;

        Fixture(int hashSize, boolean zeroKey, int attestationLevel, int keymasterLevel)
                throws Exception {
            hash = randomBytes(hashSize);
            bootKey = zeroKey ? new byte[32] : randomBytes(64);
            leaf = LeafPatcherHostTest.this.leaf(key.getPublic(), hardwareRoot,
                    hardwareKey.getPrivate(), BigInteger.valueOf(++serial),
                    description(nonce, attestationLevel, keymasterLevel, rootTag(bootKey, hash)));
            leaf.verify(hardwareRoot.getPublicKey());
            record = YasvaraAttestation.parse(leaf);
            check(record != null, "original attestation must parse");
        }

        YasvaraLeafPatcher.Request request() {
            YasvaraLeafPatcher.Request request = new YasvaraLeafPatcher.Request();
            request.realLeaf = leaf;
            // Each request gets its own parsed record so adversarial tests cannot leak mutations.
            request.record = YasvaraAttestation.parse(leaf);
            request.keyboxPrivateKey = issuerKey.getPrivate();
            request.keyboxChain = List.of(issuerRoot);
            request.osVersion = 160000;
            request.osPatch = 202610;
            request.vendorPatch = 20261031;
            request.bootPatch = 20261031;
            request.bootHash = hash.clone();
            request.attestIdOverrides = IDS;
            return request;
        }
    }

    private static ASN1Encodable[] rawDescription(X509Certificate certificate) throws Exception {
        X509CertificateHolder holder = new X509CertificateHolder(certificate.getEncoded());
        return ASN1Sequence.getInstance(holder.getExtension(YasvaraAttestation.ATTESTATION_OID)
                .getExtnValue().getOctets()).toArray();
    }

    private static ASN1TaggedObject tag(ASN1Sequence sequence, int tagNumber) {
        ASN1TaggedObject found = null;
        for (ASN1Encodable item : sequence) {
            if (item instanceof ASN1TaggedObject
                    && ((ASN1TaggedObject) item).getTagNo() == tagNumber) {
                check(found == null, "duplicate tag " + tagNumber);
                found = (ASN1TaggedObject) item;
            }
        }
        check(found != null, "missing tag " + tagNumber);
        return found;
    }

    private static ASN1Sequence tee(ASN1Encodable[] description) {
        return ASN1Sequence.getInstance(description[7]);
    }

    private void preservesRoot(int hashSize, boolean zeroKey, int attestationLevel,
            int keymasterLevel) throws Exception {
        Fixture fixture = new Fixture(hashSize, zeroKey, attestationLevel, keymasterLevel);
        YasvaraLeafPatcher.Request request = fixture.request();
        byte[] originalDer = fixture.leaf.getEncoded();
        byte[] originalTee = request.record.teeEnforced.getEncoded();
        byte[] canonical = request.bootHash.clone();
        Certificate[] result = YasvaraLeafPatcher.patch(request);
        check(result != null, "real signing/selfVerify must produce a replacement chain");
        check(result.length == 2 && result[1].equals(issuerRoot), "replacement issuer chain");
        X509Certificate patched = (X509Certificate) result[0];
        patched.verify(issuerRoot.getPublicKey());
        check(!Arrays.equals(originalDer, patched.getEncoded()), "patch must actually re-sign");
        check(patched.getIssuerX500Principal().equals(issuerRoot.getSubjectX500Principal()),
                "new ephemeral issuer used");
        bytes(fixture.key.getPublic().getEncoded(), patched.getPublicKey().getEncoded(),
                "original public key");
        bytes(new X509CertificateHolder(originalDer).getSubjectPublicKeyInfo().getEncoded(),
                new X509CertificateHolder(patched.getEncoded()).getSubjectPublicKeyInfo().getEncoded(),
                "SPKI DER unchanged");
        check(fixture.leaf.getSerialNumber().equals(patched.getSerialNumber()), "serial unchanged");
        check(fixture.leaf.getSubjectX500Principal().equals(patched.getSubjectX500Principal()),
                "subject unchanged");
        check(fixture.leaf.getNotBefore().equals(patched.getNotBefore())
                && fixture.leaf.getNotAfter().equals(patched.getNotAfter()), "validity unchanged");
        for (ASN1ObjectIdentifier oid : new ASN1ObjectIdentifier[] {
                PROBE_OID, Extension.basicConstraints, Extension.keyUsage}) {
            bytes(fixture.leaf.getExtensionValue(oid.getId()), patched.getExtensionValue(oid.getId()),
                    "non-attestation extension unchanged: " + oid);
        }
        ASN1Encodable[] before = rawDescription(fixture.leaf);
        ASN1Encodable[] after = rawDescription(patched);
        for (int index = 0; index < 7; index++) {
            bytes(before[index].toASN1Primitive().getEncoded(), after[index].toASN1Primitive()
                    .getEncoded(), "KeyDescription field unchanged: " + index);
        }
        check(ASN1Enumerated.getInstance(after[1]).getValue().intValueExact() == attestationLevel,
                "attestation security level unchanged");
        check(ASN1Enumerated.getInstance(after[3]).getValue().intValueExact() == keymasterLevel,
                "keymaster security level unchanged");
        ASN1TaggedObject patchedRoot = tag(tee(after), 704);
        ASN1Sequence root = ASN1Sequence.getInstance(patchedRoot.getBaseObject());
        bytes(fixture.bootKey, ASN1OctetString.getInstance(root.getObjectAt(0)).getOctets(),
                "boot key unchanged, including zero key/length");
        check(ASN1Boolean.getInstance(root.getObjectAt(1)).isTrue(),
                "deviceLocked spoofed to TRUE for Strong Integrity");
        check(ASN1Enumerated.getInstance(root.getObjectAt(2)).getValue().intValueExact() == 0,
                "verifiedBootState spoofed to Verified(0) for Strong Integrity");
        bytes(fixture.hash, ASN1OctetString.getInstance(root.getObjectAt(3)).getOctets(),
                "hardware boot hash unchanged");
        for (int preservedTag : new int[] {2, 3, 702, 713, 724}) {
            bytes(tag(tee(before), preservedTag).getEncoded(), tag(tee(after), preservedTag).getEncoded(),
                    "unrelated hardware tag unchanged: " + preservedTag);
        }
        for (int patchTag : new int[] {718, 719}) {
            check(ASN1Integer.getInstance(tag(tee(after), patchTag).getBaseObject()).getValue()
                    .intValueExact() == 20261031, "full YYYYMMDD patch level: " + patchTag);
        }
        check(ASN1Integer.getInstance(tag(tee(after), 705).getBaseObject()).getValue()
                .intValueExact() == request.osVersion, "OS version update retained");
        check(ASN1Integer.getInstance(tag(tee(after), 706).getBaseObject()).getValue()
                .intValueExact() == request.osPatch, "OS patch update retained");
        for (Map.Entry<Integer, String> identity : IDS.entrySet()) {
            bytes(identity.getValue().getBytes(java.nio.charset.StandardCharsets.UTF_8),
                    ASN1OctetString.getInstance(tag(tee(after), identity.getKey()).getBaseObject())
                            .getOctets(), "identity override retained: " + identity.getKey());
        }
        YasvaraAttestation.Record patchedRecord = YasvaraAttestation.parse(patched);
        check(patchedRecord != null, "patched attestation must parse");
        bytes(fixture.nonce, patchedRecord.challenge, "nonce unchanged");
        bytes(fixture.bootKey, patchedRecord.verifiedBootKey, "parsed hardware key unchanged");
        bytes(fixture.hash, patchedRecord.verifiedBootHash, "parsed hardware hash unchanged");
        check(Boolean.TRUE.equals(patchedRecord.deviceLocked), "parser reports locked after spoof");
        check(Integer.valueOf(0).equals(patchedRecord.verifiedBootState), "parser reports Verified after spoof");
        check(YasvaraLeafPatcher.selfVerify(fixture.leaf, fixture.record, patched, issuerRoot),
                "production selfVerify accepts spoofed locked RootOfTrust");
        bytes(originalDer, fixture.leaf.getEncoded(), "original certificate not mutated");
        bytes(originalTee, request.record.teeEnforced.getEncoded(), "request record not mutated");
        bytes(canonical, request.bootHash, "canonical request digest not mutated");
    }

    private void rejectsRoot(String name, Fixture fixture, ASN1Encodable... roots) {
        run(name, () -> {
            YasvaraLeafPatcher.Request request = fixture.request();
            request.realLeaf = leaf(fixture.key.getPublic(), hardwareRoot, hardwareKey.getPrivate(),
                    BigInteger.valueOf(++serial), description(fixture.nonce, 1, 2, roots));
            request.record = YasvaraAttestation.parse(request.realLeaf);
            check(YasvaraLeafPatcher.patch(request) == null, "malformed/duplicate root must not patch");
        });
    }

    private X509Certificate tampered(Fixture fixture, ASN1Encodable[] description) throws Exception {
        X509Certificate forged = leaf(fixture.key.getPublic(), issuerRoot, issuerKey.getPrivate(),
                fixture.leaf.getSerialNumber(), description);
        forged.verify(issuerRoot.getPublicKey());
        return forged;
    }

    private static ASN1Encodable[] replaceRoot(ASN1Encodable[] description, ASN1Encodable root) {
        ASN1Encodable[] changed = description.clone();
        ASN1EncodableVector items = new ASN1EncodableVector();
        for (ASN1Encodable item : tee(description)) {
            items.add(item instanceof ASN1TaggedObject && ((ASN1TaggedObject) item).getTagNo() == 704
                    ? root : item);
        }
        changed[7] = new DERSequence(items);
        return changed;
    }

    private void rejectTampering(String name, Fixture fixture, ASN1Encodable[] description) {
        run(name, () -> check(!YasvaraLeafPatcher.selfVerify(fixture.leaf, fixture.record,
                tampered(fixture, description), issuerRoot), "selfVerify must reject " + name));
    }

    private void negativeCases() throws Exception {
        Fixture fixture = new Fixture(32, true, 1, 2);
        run("missing canonical digest", () -> {
            YasvaraLeafPatcher.Request request = fixture.request();
            request.bootHash = null;
            check(YasvaraLeafPatcher.patch(request) == null, "missing canonical must not patch");
        });
        run("mismatched canonical digest", () -> {
            YasvaraLeafPatcher.Request request = fixture.request();
            request.bootHash = different(fixture.hash);
            check(YasvaraLeafPatcher.patch(request) == null, "mismatched canonical must not patch");
        });
        run("canonical digest length mismatch", () -> {
            YasvaraLeafPatcher.Request request = fixture.request();
            request.bootHash = randomBytes(64);
            check(YasvaraLeafPatcher.patch(request) == null, "32/64-byte mismatch must not patch");
        });
        run("empty canonical digest", () -> {
            YasvaraLeafPatcher.Request request = fixture.request();
            request.bootHash = new byte[0];
            check(YasvaraLeafPatcher.patch(request) == null, "empty canonical must not patch");
        });
        run("caller record cannot replace actual hardware hash", () -> {
            YasvaraLeafPatcher.Request request = fixture.request();
            request.bootHash = different(fixture.hash);
            request.record.verifiedBootHash = request.bootHash.clone();
            check(YasvaraLeafPatcher.patch(request) == null, "validate hash against actual original leaf");
        });
        run("caller record cannot promote hardware state", () -> {
            YasvaraLeafPatcher.Request request = fixture.request();
            request.record.deviceLocked = true;
            request.record.verifiedBootState = 0;
            check(YasvaraLeafPatcher.patch(request) == null, "forged parsed root must not patch");
        });
        DERTaggedObject valid = rootTag(fixture.bootKey, fixture.hash);
        DEROctetString key = new DEROctetString(fixture.bootKey);
        DEROctetString hash = new DEROctetString(fixture.hash);
        rejectsRoot("missing RootOfTrust", fixture);
        rejectsRoot("non-sequence RootOfTrust", fixture,
                new DERTaggedObject(true, 704, new DEROctetString(randomBytes(8))));
        rejectsRoot("truncated RootOfTrust", fixture, new DERTaggedObject(true, 704,
                new DERSequence(new ASN1Encodable[] {key, ASN1Boolean.FALSE, new ASN1Enumerated(2)})));
        rejectsRoot("non-octet boot key", fixture,
                rootTag(new ASN1Integer(0), ASN1Boolean.FALSE, new ASN1Enumerated(2), hash));
        rejectsRoot("non-boolean lock", fixture,
                rootTag(key, new ASN1Integer(0), new ASN1Enumerated(2), hash));
        rejectsRoot("non-enumerated boot state", fixture,
                rootTag(key, ASN1Boolean.FALSE, new ASN1Integer(2), hash));
        rejectsRoot("non-numeric boot state", fixture,
                rootTag(key, ASN1Boolean.FALSE, new DEROctetString(new byte[] {2}), hash));
        rejectsRoot("out-of-range boot state", fixture,
                rootTag(key, ASN1Boolean.FALSE, new ASN1Enumerated(4), hash));
        rejectsRoot("non-octet boot hash", fixture,
                rootTag(key, ASN1Boolean.FALSE, new ASN1Enumerated(2), new ASN1Integer(0)));
        rejectsRoot("duplicate identical roots", fixture, valid, valid);
        rejectsRoot("duplicate conflicting roots", fixture,
                rootTag(fixture.bootKey, different(fixture.hash)), valid);
        rejectsRoot("duplicate malformed root after valid root", fixture, valid,
                new DERTaggedObject(true, 704, new DERSequence()));
        rejectsRoot("duplicate malformed root before valid root", fixture,
                new DERTaggedObject(true, 704, new DERSequence()), valid);

        ASN1Encodable[] original = rawDescription(fixture.leaf);
        rejectTampering("selfVerify rejects boot-key mutation", fixture,
                replaceRoot(original, rootTag(different(fixture.bootKey), fixture.hash)));
        rejectTampering("selfVerify rejects boot-hash mutation", fixture,
                replaceRoot(original, rootTag(fixture.bootKey, different(fixture.hash))));
        rejectTampering("selfVerify rejects unlocked demotion", fixture,
                replaceRoot(original, rootTag(key, ASN1Boolean.FALSE, new ASN1Enumerated(0), hash)));
        rejectTampering("selfVerify rejects Unverified demotion", fixture,
                replaceRoot(original, rootTag(key, ASN1Boolean.TRUE, new ASN1Enumerated(2), hash)));
        for (int index : new int[] {1, 3}) {
            ASN1Encodable[] changed = original.clone();
            changed[index] = new ASN1Enumerated(index == 1 ? 2 : 1);
            rejectTampering("selfVerify rejects security-level mutation at index " + index,
                    fixture, changed);
        }
        ASN1Encodable[] changedNonce = original.clone();
        changedNonce[4] = new DEROctetString(different(fixture.nonce));
        rejectTampering("selfVerify rejects nonce mutation", fixture, changedNonce);
        run("selfVerify rejects SPKI mutation", () -> {
            X509Certificate forged = leaf(newKey().getPublic(), issuerRoot, issuerKey.getPrivate(),
                    fixture.leaf.getSerialNumber(), original);
            check(!YasvaraLeafPatcher.selfVerify(fixture.leaf, fixture.record, forged, issuerRoot),
                    "different application public key must be rejected");
        });
        run("Build identity fallback without Android JNI", () -> {
            YasvaraLeafPatcher.Request request = fixture.request();
            request.attestIdOverrides = null;
            Certificate[] result = YasvaraLeafPatcher.patch(request);
            check(result != null, "Build fallback must still sign successfully");
            bytes("host-build-brand".getBytes(java.nio.charset.StandardCharsets.UTF_8),
                    ASN1OctetString.getInstance(tag(tee(rawDescription((X509Certificate) result[0])),
                            710).getBaseObject()).getOctets(), "temporary Build stub used");
        });
    }

    private void signatureAndIdempotenceCases() throws Exception {
        Fixture fixture = new Fixture(32, false, 2, 2);
        run("SHA-384 leaf keeps a matching signature algorithm", () -> {
            KeyPair key = newKey();
            byte[] hash = randomBytes(32);
            X509Certificate leaf384 = leaf(key.getPublic(), hardwareRoot,
                    hardwareKey.getPrivate(), BigInteger.valueOf(++serial),
                    description(randomBytes(32), 2, 2, rootTag(randomBytes(64), hash)),
                    "SHA384withECDSA");
            leaf384.verify(hardwareRoot.getPublicKey());
            YasvaraLeafPatcher.Request request = fixture.request();
            request.realLeaf = leaf384;
            request.record = YasvaraAttestation.parse(leaf384);
            request.bootHash = hash;
            Certificate[] result = YasvaraLeafPatcher.patch(request);
            check(result != null, "SHA-384 leaf must patch");
            X509Certificate patched = (X509Certificate) result[0];
            check(patched.getSigAlgName().contains("SHA384"),
                    "patched signature algorithm must match its digest, got "
                            + patched.getSigAlgName());
            patched.verify(issuerRoot.getPublicKey());
        });
        run("already keybox-signed chain is not re-signed", () -> {
            Certificate[] first = YasvaraLeafPatcher.patch(fixture.request());
            check(first != null, "first patch must sign");
            check(YasvaraLeafPatcher.issuedBy(first, issuerRoot),
                    "chain issued by the active keybox must be detected");
            check(!YasvaraLeafPatcher.issuedBy(first, hardwareRoot),
                    "a different issuer must not count as already issued");
            check(!YasvaraLeafPatcher.issuedBy(
                            new Certificate[] {fixture.leaf, issuerRoot}, issuerRoot),
                    "an unrelated leaf must not count as already issued");
        });
        run("optional bootKey replaces all-zero hardware key only", () -> {
            Fixture zeroFixture = new Fixture(32, true, 1, 2);
            byte[] overrideKey = randomBytes(32);
            YasvaraLeafPatcher.Request req = zeroFixture.request();
            req.bootKey = overrideKey.clone();
            Certificate[] patchedZero = YasvaraLeafPatcher.patch(req);
            check(patchedZero != null, "zero boot key with req.bootKey override must patch");
            YasvaraAttestation.Record rec =
                    YasvaraAttestation.parse((X509Certificate) patchedZero[0]);
            bytes(overrideKey, rec.verifiedBootKey, "override bootKey substituted");

            YasvaraLeafPatcher.Request nonZeroReq = fixture.request();
            nonZeroReq.bootKey = overrideKey.clone();
            Certificate[] patchedReal = YasvaraLeafPatcher.patch(nonZeroReq);
            check(patchedReal != null, "non-zero boot key must keep original");
            YasvaraAttestation.Record realRec =
                    YasvaraAttestation.parse((X509Certificate) patchedReal[0]);
            bytes(fixture.bootKey, realRec.verifiedBootKey,
                    "non-zero hardware bootKey must not be overwritten");
        });
        run("all-zero hardware boot hash uses canonical req.bootHash", () -> {
            KeyPair key = newKey();
            byte[] canonical = randomBytes(32);
            X509Certificate zeroHashLeaf = leaf(key.getPublic(), hardwareRoot,
                    hardwareKey.getPrivate(), BigInteger.valueOf(++serial),
                    description(randomBytes(32), 1, 2, rootTag(randomBytes(32), new byte[32])));
            YasvaraLeafPatcher.Request req = fixture.request();
            req.realLeaf = zeroHashLeaf;
            req.record = YasvaraAttestation.parse(zeroHashLeaf);
            req.bootHash = canonical.clone();
            Certificate[] result = YasvaraLeafPatcher.patch(req);
            check(result != null, "all-zero hardware boot hash must use canonical bootHash");
            YasvaraAttestation.Record rec =
                    YasvaraAttestation.parse((X509Certificate) result[0]);
            bytes(canonical, rec.verifiedBootHash, "canonical bootHash substituted");
        });
    }

    public static void main(String[] args) throws Exception {
        check(Runtime.version().feature() == 21, "run with JDK 21");
        for (Class<?> production : new Class<?>[] {YasvaraLeafPatcher.class, YasvaraAttestation.class}) {
            check(production.getProtectionDomain().getCodeSource().getLocation().equals(
                    LeafPatcherHostTest.class.getProtectionDomain().getCodeSource().getLocation()),
                    "production class must be freshly compiled from source, not loaded from framework.jar");
        }
        LeafPatcherHostTest test = new LeafPatcherHostTest();
        for (int hashSize : new int[] {32, 64}) {
            for (boolean zeroKey : new boolean[] {true, false}) {
                for (int attestationLevel : new int[] {1, 2}) {
                    for (int keymasterLevel : new int[] {1, 2}) {
                        run("preserve hash=" + hashSize + " zeroKey=" + zeroKey + " security="
                                        + attestationLevel + "/" + keymasterLevel,
                                () -> test.preservesRoot(hashSize, zeroKey,
                                        attestationLevel, keymasterLevel));
                    }
                }
            }
        }
        test.negativeCases();
        test.signatureAndIdempotenceCases();
        System.out.println("LeafPatcher host: " + cases + " cases, " + checks + " checks, "
                + FAILURES.size() + " failures");
        if (!FAILURES.isEmpty()) {
            throw new AssertionError("Production behavior failures:\n" + String.join("\n", FAILURES));
        }
    }
}
