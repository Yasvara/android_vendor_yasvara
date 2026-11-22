/*
 * SPDX-FileCopyrightText: The Yasvara Project
 * SPDX-License-Identifier: Apache-2.0
 */
package android.security.yasvara;

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
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.List;

/** Host checks for keybox parsing: key/certificate agreement and chain linkage. */
public final class KeyboxProviderHostTest {
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final Date NOT_BEFORE = new Date(System.currentTimeMillis() - 60_000);
    private static final Date NOT_AFTER = new Date(System.currentTimeMillis() + 86_400_000L);
    private static final List<String> FAILURES = new ArrayList<>();
    private static int cases;
    private static long serial;

    @FunctionalInterface
    private interface TestCase {
        void run() throws Exception;
    }

    private KeyboxProviderHostTest() {}

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
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

    private static KeyPair newKey() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"), RANDOM);
        return generator.generateKeyPair();
    }

    private static final class JdkSigner implements ContentSigner {
        private final ByteArrayOutputStream output = new ByteArrayOutputStream();
        private final PrivateKey key;

        JdkSigner(PrivateKey key) {
            this.key = key;
        }

        @Override
        public AlgorithmIdentifier getAlgorithmIdentifier() {
            return new DefaultSignatureAlgorithmIdentifierFinder().find("SHA256withECDSA");
        }

        @Override
        public OutputStream getOutputStream() {
            return output;
        }

        @Override
        public byte[] getSignature() {
            try {
                Signature signature = Signature.getInstance("SHA256withECDSA");
                signature.initSign(key, RANDOM);
                signature.update(output.toByteArray());
                return signature.sign();
            } catch (Exception error) {
                throw new IllegalStateException(error);
            }
        }
    }

    private static X509Certificate certificate(X509v3CertificateBuilder builder, PrivateKey key)
            throws Exception {
        return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(
                new ByteArrayInputStream(builder.build(new JdkSigner(key)).getEncoded()));
    }

    private static X509Certificate root(String name, KeyPair key) throws Exception {
        X500Name subject = new X500Name("CN=" + name);
        X509v3CertificateBuilder builder = new X509v3CertificateBuilder(subject,
                BigInteger.valueOf(++serial), NOT_BEFORE, NOT_AFTER, subject,
                SubjectPublicKeyInfo.getInstance(key.getPublic().getEncoded()));
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        builder.addExtension(Extension.keyUsage, true,
                new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
        return certificate(builder, key.getPrivate());
    }

    private static String pem(String type, byte[] der) {
        return "-----BEGIN " + type + "-----\n"
                + Base64.getMimeEncoder(64, new byte[] {'\n'}).encodeToString(der)
                + "\n-----END " + type + "-----";
    }

    private static String keybox(String algorithm, PrivateKey key,
            List<X509Certificate> chain) throws Exception {
        StringBuilder xml = new StringBuilder();
        xml.append("<AndroidAttestation><NumberOfKeyboxes>1</NumberOfKeyboxes>")
                .append("<Keybox DeviceID=\"host\"><Key algorithm=\"")
                .append(algorithm).append("\">");
        if (key != null) {
            xml.append("<PrivateKey format=\"pem\">")
                    .append(pem("PRIVATE KEY", key.getEncoded()))
                    .append("</PrivateKey>");
        }
        xml.append("<CertificateChain><NumberOfCertificates>")
                .append(chain.size()).append("</NumberOfCertificates>");
        for (X509Certificate certificate : chain) {
            xml.append("<Certificate format=\"pem\">")
                    .append(pem("CERTIFICATE", certificate.getEncoded()))
                    .append("</Certificate>");
        }
        xml.append("</CertificateChain></Key></Keybox></AndroidAttestation>");
        return xml.toString();
    }

    private static void expectInvalid(String name, String xml) {
        YasvaraKeyboxProvider.ParseResult result = YasvaraKeyboxProvider.parse(xml);
        check(!result.isValid(), name + " must be rejected");
        check(result.error == YasvaraKeyboxProvider.ERROR_INVALID_KEYBOX,
                name + " must report ERROR_INVALID_KEYBOX, got " + result.error);
    }

    public static void main(String[] args) throws Exception {
        check(Runtime.version().feature() == 21, "run with JDK 21");
        for (Class<?> production : new Class<?>[] {
                YasvaraKeyboxProvider.class, YasvaraKeyMaterial.class}) {
            check(production.getProtectionDomain().getCodeSource().getLocation().equals(
                    KeyboxProviderHostTest.class.getProtectionDomain().getCodeSource().getLocation()),
                    "production class must be freshly compiled from source, not loaded from framework.jar");
        }

        KeyPair rootKey = newKey();
        KeyPair leafKey = newKey();
        KeyPair otherKey = newKey();
        X509Certificate root = root(rootKey);
        X509Certificate sameNameRoot = root("host keybox root", newKey());
        X509Certificate leaf = leaf("host keybox leaf", root, leafKey, rootKey);

        run("valid private keybox", () -> {
            YasvaraKeyboxProvider.ParseResult result = YasvaraKeyboxProvider.parse(
                    keybox("ecdsa", leafKey.getPrivate(), List.of(leaf, root)));
            check(result.isValid(), "valid keybox must parse: " + result.error);
            check(result.keyboxes.size() == 1, "one keybox");
            check(result.keyboxes.get(0).hasPrivateKey(), "private key retained");
            check(result.keyboxes.get(0).leaf().equals(leaf), "leaf first");
        });
        run("public-only keybox", () -> {
            YasvaraKeyboxProvider.ParseResult result = YasvaraKeyboxProvider.parse(
                    keybox("ecdsa", null, List.of(leaf, root)));
            check(result.isValid(), "public chain must parse: " + result.error);
            check(!result.keyboxes.get(0).hasPrivateKey(), "no private key");
        });
        run("private key does not match certificate", () -> expectInvalid(
                "mismatched private key",
                keybox("ecdsa", otherKey.getPrivate(), List.of(leaf, root))));
        run("chain issuer does not match", () -> expectInvalid(
                "reversed chain", keybox("ecdsa", leafKey.getPrivate(), List.of(root, leaf))));
        run("chain signature does not verify", () -> expectInvalid(
                "same-name wrong issuer key",
                keybox("ecdsa", leafKey.getPrivate(), List.of(leaf, sameNameRoot))));
        run("algorithm differs from certificate", () -> expectInvalid(
                "rsa label on EC leaf",
                keybox("rsa", leafKey.getPrivate(), List.of(leaf, root))));
        run("single certificate is too short", () -> {
            YasvaraKeyboxProvider.ParseResult result = YasvaraKeyboxProvider.parse(
                    keybox("ecdsa", leafKey.getPrivate(), List.of(leaf)));
            check(result.error == YasvaraKeyboxProvider.ERROR_CHAIN_TOO_SHORT,
                    "expected chain-too-short, got " + result.error);
        });

        System.out.println("KeyboxProvider host: " + cases + " cases, "
                + FAILURES.size() + " failures");
        if (!FAILURES.isEmpty()) {
            throw new AssertionError("Production behavior failures:\n" + String.join("\n", FAILURES));
        }
    }

    private static X509Certificate root(KeyPair key) throws Exception {
        return root("host keybox root", key);
    }

    private static X509Certificate leaf(String name, X509Certificate issuer, KeyPair key,
            KeyPair issuerKey) throws Exception {
        X509v3CertificateBuilder builder = new X509v3CertificateBuilder(
                new X509CertificateHolder(issuer.getEncoded()).getSubject(),
                BigInteger.valueOf(++serial), NOT_BEFORE, NOT_AFTER,
                new X500Name("CN=" + name),
                SubjectPublicKeyInfo.getInstance(key.getPublic().getEncoded()));
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        return certificate(builder, issuerKey.getPrivate());
    }
}
