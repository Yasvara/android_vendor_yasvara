package de.robv.android.xposed.services;

import android.os.ParcelFileDescriptor;
import android.system.ErrnoException;
import android.system.Os;
import android.system.StructStat;

import org.matrix.vector.impl.core.VectorServiceClient;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;

/**
 * Yasvara: {@link BaseService} for a process that has no direct access to the files it wants.
 *
 * <p>Upstream Xposed solved the same problem with a binder service in system_server (the SELinux
 * file service); here system_server opens a module's preference file and hands the descriptor
 * over, see {@code IFrameworkService#openAppDataFile}. Reads are whole-file, which is all
 * {@code XSharedPreferences} needs.
 */
public final class BinderFileService extends BaseService {

    private static ParcelFileDescriptor open(String filename) throws IOException {
        ensureAbsolutePath(filename);
        ParcelFileDescriptor pfd = VectorServiceClient.INSTANCE.openAppDataFile(filename);
        if (pfd == null) throw new FileNotFoundException("No such file or directory: " + filename);
        return pfd;
    }

    @Override
    public boolean checkFileAccess(String filename, int mode) {
        if ((mode & (W_OK | X_OK)) != 0) return false;
        try (ParcelFileDescriptor ignored = open(filename)) {
            return true;
        } catch (IOException e) {
            return false;
        }
    }

    @Override
    public FileResult statFile(String filename) throws IOException {
        try (ParcelFileDescriptor pfd = open(filename)) {
            return stat(pfd);
        }
    }

    private static FileResult stat(ParcelFileDescriptor pfd) throws IOException {
        try {
            StructStat st = Os.fstat(pfd.getFileDescriptor());
            return new FileResult(st.st_size, st.st_mtim.tv_sec * 1000L + st.st_mtim.tv_nsec / 1_000_000L);
        } catch (ErrnoException e) {
            throw new IOException(e);
        }
    }

    private static byte[] readAll(ParcelFileDescriptor pfd) throws IOException {
        try (InputStream in = new FileInputStream(pfd.getFileDescriptor())) {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buf = new byte[8192];
            int n;
            while ((n = in.read(buf)) != -1) out.write(buf, 0, n);
            return out.toByteArray();
        }
    }

    @Override
    public byte[] readFile(String filename) throws IOException {
        try (ParcelFileDescriptor pfd = open(filename)) {
            return readAll(pfd);
        }
    }

    @Override
    public FileResult readFile(String filename, long previousSize, long previousTime) throws IOException {
        try (ParcelFileDescriptor pfd = open(filename)) {
            FileResult st = stat(pfd);
            if (previousSize == st.size && previousTime == st.mtime) return st;
            return new FileResult(readAll(pfd), st.size, st.mtime);
        }
    }

    @Override
    public FileResult readFile(String filename, int offset, int length, long previousSize,
                               long previousTime) throws IOException {
        FileResult whole = readFile(filename, previousSize, previousTime);
        if (whole.content == null || (offset <= 0 && length <= 0)) return whole;
        int from = Math.max(offset, 0);
        int len = length <= 0 ? whole.content.length - from : length;
        if (from + len > whole.content.length) {
            throw new IllegalArgumentException("Range out of bounds for " + filename);
        }
        byte[] part = new byte[len];
        System.arraycopy(whole.content, from, part, 0, len);
        return new FileResult(part, whole.size, whole.mtime);
    }
}
