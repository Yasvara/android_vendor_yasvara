/*
 * SPDX-FileCopyrightText: The Yasvara Project
 * SPDX-License-Identifier: Apache-2.0
 */
package com.android.server.yasvara;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Base64;
import java.util.Comparator;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Stream;

/** Exercises the production store with public sample XML, never real certificates or keys. */
public final class KeyboxStoreHostTest {
    private static final String OLD = sample("old");
    private static final String NEW = sample("new");
    private static int checks;

    private KeyboxStoreHostTest() {}

    public static void main(String[] args) throws Exception {
        Path temporary = Path.of(args[0]);
        normalization();
        roundTrip(temporary);
        migration(temporary);
        canonicalPrecedence(temporary);
        rollback(temporary);
        migrationFailures(temporary);
        committedFailures(temporary);
        clearAndRestart(temporary);
        invalidStorage(temporary);
        publishedConfig(temporary);
        System.out.println("Canonical keybox store: " + checks + " checks passed");
    }

    private static String sample(String value) {
        return "<AndroidAttestation><PublicSample>" + value
                + "</PublicSample></AndroidAttestation>";
    }

    private static String encoded(String xml) {
        return Base64.getMimeEncoder(24, new byte[] {'\n'})
                .encodeToString(xml.getBytes(StandardCharsets.UTF_8));
    }

    private static String parseSample(String xml) {
        if (!xml.startsWith("<AndroidAttestation><PublicSample>")
                || !xml.endsWith("</PublicSample></AndroidAttestation>")) {
            throw new IllegalArgumentException("invalid public sample");
        }
        return xml;
    }

    private static void publishedConfig(Path root) throws Exception {
        try (Fixture f = new Fixture(root)) {
            f.install(OLD);
            f.store.publishConfig("targets", "com.example.one\ncom.example.two\n");
            Path targets = f.directory.resolve("targets");
            check("com.example.one\ncom.example.two\n".equals(Files.readString(targets)),
                    "targets published");
            check(Files.getPosixFilePermissions(targets).equals(
                    PosixFilePermissions.fromString("rw-r-----")), "targets are 0640");
            f.store.publishConfig("targets", "com.example.three\n");
            check("com.example.three\n".equals(Files.readString(targets)), "targets replaced");
            f.checkCanonical(OLD);
            f.checkNoTemporaryFiles();
            expect(IllegalArgumentException.class, () -> f.store.publishConfig("../x", "a"));
            expect(IllegalArgumentException.class, () -> f.store.publishConfig(".hidden", "a"));
            f.files.failure = Failure.RENAME;
            expect(IOException.class, () -> f.store.publishConfig("targets", "com.example.four\n"));
            f.files.failure = Failure.NONE;
            check("com.example.three\n".equals(Files.readString(targets)),
                    "failed publication keeps previous targets");
            f.checkNoTemporaryFiles();
        }
    }

    private static void normalization() throws Exception {
        check(OLD.equals(YasvaraKeyboxStore.normalize(" \n" + OLD + "\t")), "trim XML");
        check(OLD.equals(YasvaraKeyboxStore.normalize(encoded(OLD))), "decode base64 XML");
        check(OLD.equals(YasvaraKeyboxStore.normalize(encoded(" \n" + OLD + "\n"))),
                "trim decoded XML");
        for (String bad : new String[] {null, "", " \n", "not base64!", encoded("not XML"),
                "x".repeat(YasvaraKeyboxStore.MAX_CHARS + 1)}) {
            expect(IllegalArgumentException.class, () -> YasvaraKeyboxStore.normalize(bad));
        }
    }

    private static void roundTrip(Path root) throws Exception {
        try (Fixture f = new Fixture(root)) {
            f.load();
            check(f.ram.get() == null && !Files.exists(f.canonical), "empty startup");
            f.install(" \n" + OLD + "\n");
            f.checkCanonical(OLD);
            check(OLD.equals(f.ram.get()), "RAM adopted committed raw import");
            Object oldInode = Files.getAttribute(f.canonical, "unix:ino");
            f.install(encoded(NEW));
            f.checkCanonical(NEW);
            check(NEW.equals(f.ram.get()), "RAM adopted normalized base64 import");
            check(!oldInode.equals(Files.getAttribute(f.canonical, "unix:ino")),
                    "replacement uses a new inode");
            f.ram.set(null);
            f.load();
            check(NEW.equals(f.ram.get()), "restart loads canonical import");
            f.checkNoTemporaryFiles();
        }
    }

    private static void migration(Path root) throws Exception {
        for (String input : new String[] {OLD, encoded(OLD)}) {
            try (Fixture f = new Fixture(root)) {
                Files.writeString(f.legacy, input);
                f.load();
                f.checkCanonical(OLD);
                check(OLD.equals(f.ram.get()), "migration publishes before RAM adoption");
                check(!Files.exists(f.legacy), "migration retires legacy file");
                f.ram.set(null);
                f.load();
                check(OLD.equals(f.ram.get()), "migrated canonical survives restart");
            }
        }
    }

    private static void canonicalPrecedence(Path root) throws Exception {
        try (Fixture f = new Fixture(root)) {
            f.install(NEW);
            Files.writeString(f.legacy, OLD);
            f.files.failure = Failure.RENAME;
            f.ram.set(null);
            f.load();
            check(NEW.equals(f.ram.get()), "canonical wins without republishing");
            check(!Files.exists(f.legacy), "canonical startup retires stale legacy");
        }
        try (Fixture f = new Fixture(root)) {
            Files.writeString(f.canonical, "<invalid/>");
            Files.writeString(f.legacy, OLD);
            expect(IllegalArgumentException.class, f::load);
            check(f.ram.get() == null, "invalid canonical never loads legacy into RAM");
            check(OLD.equals(Files.readString(f.legacy)), "invalid canonical leaves legacy alone");
            check("<invalid/>".equals(Files.readString(f.canonical)),
                    "invalid canonical is not overwritten from legacy");
        }
        try (Fixture f = new Fixture(root)) {
            Files.writeString(f.canonical, encoded(NEW));
            Files.writeString(f.legacy, OLD);
            f.load();
            f.checkCanonical(NEW);
            check(NEW.equals(f.ram.get()), "canonical wrapper normalized for native reader");
        }
    }

    private static void rollback(Path root) throws Exception {
        for (Failure failure : new Failure[] {Failure.WRITE, Failure.RENAME,
                Failure.ATOMIC_UNSUPPORTED}) {
            try (Fixture f = new Fixture(root)) {
                f.install(OLD);
                Files.writeString(f.legacy, OLD);
                f.files.failure = failure;
                expect(IOException.class, () -> f.install(NEW));
                f.checkCanonical(OLD);
                check(OLD.equals(f.ram.get()), "failed import keeps old RAM");
                check(Files.exists(f.legacy), "failed import does not retire legacy");
                f.checkNoTemporaryFiles();
                expect(IOException.class, f::clear);
                f.checkCanonical(OLD);
                check(OLD.equals(f.ram.get()), "failed clear keeps old RAM");
                check(Files.exists(f.legacy), "failed clear does not retire legacy");
                f.checkNoTemporaryFiles();
                f.files.failure = Failure.NONE;
                f.load();
                check(OLD.equals(f.ram.get()), "rollback survives restart");
            }
        }
        try (Fixture f = new Fixture(root)) {
            f.install(OLD);
            expect(IllegalArgumentException.class, () -> f.install("<invalid/>"));
            f.checkCanonical(OLD);
            check(OLD.equals(f.ram.get()), "validation failure never publishes");
        }
    }

    private static void migrationFailures(Path root) throws Exception {
        try (Fixture f = new Fixture(root)) {
            Files.writeString(f.legacy, "<invalid/>");
            expect(IllegalArgumentException.class, f::load);
            check(!Files.exists(f.canonical) && f.ram.get() == null,
                    "migration validates before publishing");
            check(Files.exists(f.legacy), "invalid legacy is retained for explicit recovery");
        }
        for (Failure failure : new Failure[] {Failure.WRITE, Failure.RENAME}) {
            try (Fixture f = new Fixture(root)) {
                Files.writeString(f.legacy, encoded(OLD));
                f.files.failure = failure;
                expect(IOException.class, f::load);
                check(!Files.exists(f.canonical) && f.ram.get() == null,
                        "failed migration does not create Java-only state");
                check(Files.exists(f.legacy), "failed migration retains its source");
                f.checkNoTemporaryFiles();
                f.files.failure = Failure.NONE;
                f.load();
                f.checkCanonical(OLD);
                check(OLD.equals(f.ram.get()), "migration retries after precommit failure");
            }
        }
        try (Fixture f = new Fixture(root)) {
            Files.writeString(f.legacy, OLD);
            f.files.failure = Failure.CLEANUP;
            expect(IOException.class, f::load);
            f.checkCanonical(OLD);
            check(OLD.equals(f.ram.get()), "committed migration survives cleanup failure in RAM");
            Files.writeString(f.legacy, NEW);
            f.ram.set(null);
            expect(IOException.class, f::load);
            check(OLD.equals(f.ram.get()), "restart never remigrates stale legacy");
        }
    }

    private static void committedFailures(Path root) throws Exception {
        for (Failure failure : new Failure[] {Failure.DIRECTORY_SYNC, Failure.CLEANUP,
                Failure.LEGACY_SYNC}) {
            try (Fixture f = new Fixture(root)) {
                f.install(OLD);
                Files.writeString(f.legacy, OLD);
                f.files.failure = failure;
                expect(IOException.class, () -> f.install(NEW));
                f.checkCanonical(NEW);
                check(NEW.equals(f.ram.get()), "postcommit failure keeps RAM coherent with disk");
                f.files.failure = Failure.NONE;
                f.ram.set(null);
                f.load();
                check(NEW.equals(f.ram.get()), "committed import wins on restart");
            }
        }
    }

    private static void clearAndRestart(Path root) throws Exception {
        for (Failure failure : new Failure[] {Failure.NONE, Failure.DIRECTORY_SYNC,
                Failure.CLEANUP, Failure.LEGACY_SYNC}) {
            try (Fixture f = new Fixture(root)) {
                f.install(OLD);
                Files.writeString(f.legacy, OLD);
                f.files.failure = failure;
                if (failure == Failure.NONE) f.clear();
                else expect(IOException.class, f::clear);
                f.checkCanonical("");
                check(f.ram.get() == null, "committed clear never leaves stale RAM");
                // Even an undeleted/reintroduced source cannot supersede the clear marker.
                Files.writeString(f.legacy, OLD);
                f.ram.set(OLD);
                if (failure == Failure.CLEANUP || failure == Failure.LEGACY_SYNC) {
                    expect(IOException.class, f::load);
                } else {
                    f.load();
                }
                check(f.ram.get() == null, "clear marker prevents resurrection on restart");
                f.files.failure = Failure.NONE;
                f.load();
                check(!Files.exists(f.legacy), "cleanup can be retried after committed clear");
                f.install(encoded(NEW));
                f.checkCanonical(NEW);
                check(NEW.equals(f.ram.get()), "explicit import can replace clear marker");
                f.clear();
                f.clear();
                f.checkCanonical("");
                f.checkNoTemporaryFiles();
            }
        }
        try (Fixture f = new Fixture(root)) {
            Files.writeString(f.legacy, OLD);
            f.clear();
            f.load();
            check(f.ram.get() == null && !Files.exists(f.legacy),
                    "clear before initial migration suppresses legacy");
        }
    }

    private static void invalidStorage(Path root) throws Exception {
        try (Fixture f = new Fixture(root)) {
            Files.delete(f.directory);
            Files.writeString(f.legacy, OLD);
            expect(IOException.class, f::load);
            expect(IOException.class, () -> f.install(NEW));
            expect(IOException.class, f::clear);
            check(!Files.exists(f.directory), "service never creates init-owned directory");
            check(f.ram.get() == null && Files.exists(f.legacy),
                    "missing init setup does not activate or remove legacy");
        }
        try (Fixture f = new Fixture(root)) {
            Files.writeString(f.legacy, OLD);
            Files.createSymbolicLink(f.canonical, f.legacy);
            expect(IOException.class, f::load);
            check(f.ram.get() == null, "canonical symlink cannot trigger fallback");
        }
        try (Fixture f = new Fixture(root)) {
            Files.writeString(f.canonical, "x".repeat(YasvaraKeyboxStore.MAX_CHARS * 4 + 1));
            Files.writeString(f.legacy, OLD);
            expect(IOException.class, f::load);
            check(f.ram.get() == null && Files.exists(f.legacy), "stored input is bounded");
        }
    }

    private enum Failure { NONE, WRITE, RENAME, ATOMIC_UNSUPPORTED, DIRECTORY_SYNC, CLEANUP,
        LEGACY_SYNC }

    private static final class TestFiles extends YasvaraKeyboxStore.FileOperations {
        final Path directory;
        Failure failure = Failure.NONE;

        TestFiles(Path directory) {
            this.directory = directory;
        }

        @Override void writeAndSync(Path path, byte[] bytes) throws IOException {
            check(directory.equals(path.getParent()), "staging file stays in canonical directory");
            check(Files.getPosixFilePermissions(path).equals(
                    PosixFilePermissions.fromString("rw-------")), "staging starts 0600");
            if (failure == Failure.WRITE) {
                Files.writeString(path, "partial public sample");
                throw new IOException("injected write/fsync failure");
            }
            super.writeAndSync(path, bytes);
        }

        @Override void replace(Path source, Path target) throws IOException {
            check(Files.getPosixFilePermissions(source).equals(
                    PosixFilePermissions.fromString("rw-r-----")), "publication is 0640");
            if (failure == Failure.RENAME) throw new IOException("injected rename failure");
            if (failure == Failure.ATOMIC_UNSUPPORTED) {
                throw new AtomicMoveNotSupportedException(source.toString(), target.toString(),
                        "injected unsupported atomic move");
            }
            super.replace(source, target);
        }

        @Override void syncDirectory(Path path) throws IOException {
            if ((failure == Failure.DIRECTORY_SYNC && path.equals(directory))
                    || (failure == Failure.LEGACY_SYNC && !path.equals(directory))) {
                throw new IOException("injected directory fsync failure");
            }
            super.syncDirectory(path);
        }

        @Override boolean deleteIfExists(Path path) throws IOException {
            if (failure == Failure.CLEANUP) throw new IOException("injected legacy cleanup failure");
            return super.deleteIfExists(path);
        }
    }

    private static final class Fixture implements AutoCloseable {
        final Path root;
        final Path directory;
        final Path canonical;
        final Path legacy;
        final TestFiles files;
        final YasvaraKeyboxStore store;
        final AtomicReference<String> ram = new AtomicReference<>();

        Fixture(Path parent) throws IOException {
            root = Files.createTempDirectory(parent, "keybox-case-");
            directory = Files.createDirectory(root.resolve("canonical"));
            Files.setAttribute(directory, "unix:mode", 02750);
            canonical = directory.resolve("keybox.xml");
            legacy = Files.createDirectory(root.resolve("legacy")).resolve("keybox.xml");
            files = new TestFiles(directory);
            store = new YasvaraKeyboxStore(directory, legacy, files);
        }

        void load() throws IOException {
            store.load(KeyboxStoreHostTest::parseSample, ram::set);
        }

        void install(String raw) throws IOException {
            String xml = YasvaraKeyboxStore.normalize(raw);
            String parsed = parseSample(xml);
            store.install(xml, () -> ram.set(parsed));
        }

        void clear() throws IOException {
            store.clear(() -> ram.set(null));
        }

        void checkCanonical(String expected) throws IOException {
            check(expected.equals(Files.readString(canonical)), "canonical contains committed XML");
            check(Files.getPosixFilePermissions(canonical).equals(
                    PosixFilePermissions.fromString("rw-r-----")), "canonical mode is 0640");
            check(Files.getAttribute(canonical, "unix:gid").equals(
                    Files.getAttribute(directory, "unix:gid")), "directory group is inherited");
        }

        void checkNoTemporaryFiles() throws IOException {
            try (Stream<Path> paths = Files.list(directory)) {
                check(paths.noneMatch(p -> p.getFileName().toString().startsWith(".keybox-")),
                        "no staging leftovers after completed/failed operations");
            }
        }

        @Override public void close() throws IOException {
            try (Stream<Path> paths = Files.walk(root)) {
                for (Path path : paths.sorted(Comparator.reverseOrder()).toList()) {
                    Files.delete(path);
                }
            }
        }
    }

    private interface ThrowingRunnable {
        void run() throws Exception;
    }

    private static void expect(Class<? extends Exception> type, ThrowingRunnable action)
            throws Exception {
        try {
            action.run();
        } catch (Exception e) {
            check(type.isInstance(e), "expected " + type.getSimpleName() + ", got " + e);
            return;
        }
        throw new AssertionError("expected " + type.getSimpleName());
    }

    private static void check(boolean condition, String label) {
        checks++;
        if (!condition) throw new AssertionError(label);
    }
}
