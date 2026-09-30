package com.stegolab.stegobox.container;

import com.stegolab.stegobox.crypto.Crypto;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * Streaming tail-append container: hide and extract without ever holding the payload in memory.
 * Peak memory is a couple of 64 KiB buffers, so hiding a multi-hundred-MB file is fine.
 *
 * <p>Layout is identical to {@link Envelope#serialize()} (byte compatible).
 */
public final class StreamContainer {

    private static final int BUF = 64 * 1024;

    private StreamContainer() {}

    // ------------------------------------------------------------------ writing

    /**
     * Writes {@code header} followed by the AEAD-encrypted contents of {@code payloadFile}.
     * The caller must have already written the cover bytes to {@code out}.
     */
    public static void sealFileTo(OutputStream out, byte[] header,
                                  int cipher, byte[] key, byte[] nonce, byte[] aad,
                                  File payloadFile) throws IOException {
        out.write(header);
        try (InputStream in = new BufferedInputStream(new FileInputStream(payloadFile), BUF)) {
            Crypto.sealStream(cipher, key, nonce, aad, in, out);
        }
    }

    // ------------------------------------------------------------------ reading

    /** Offset of the LAST occurrence of {@code magic}, or -1. Uses O(1) memory. */
    public static long findLastEnvelopeOffset(InputStream in, byte[] magic) throws IOException {
        int keep = magic.length - 1;
        byte[] carry = new byte[keep];
        int carryLen = 0;
        long base = 0;                       // stream offset of buf[0]
        long found = -1;
        byte[] buf = new byte[BUF];
        int n;
        while ((n = in.read(buf)) > 0) {
            int total = carryLen + n;
            for (int i = 0; i + magic.length <= total; i++) {
                boolean hit = true;
                for (int j = 0; j < magic.length; j++) {
                    int idx = i + j;
                    byte b = idx < carryLen ? carry[idx] : buf[idx - carryLen];
                    if (b != magic[j]) { hit = false; break; }
                }
                if (hit) found = base - carryLen + i;
            }
            int need = Math.min(keep, total);
            byte[] nc = new byte[keep];
            for (int k = 0; k < need; k++) {
                int idx = total - need + k;
                nc[k] = idx < carryLen ? carry[idx] : buf[idx - carryLen];
            }
            carry = nc;
            carryLen = need;
            base += n;
        }
        return found;
    }

    /**
     * Streams the payload of the envelope that starts at {@code offset} into {@code out},
     * verifying the AEAD tag. Returns the parsed header fields.
     */
    public static Envelope.Fields extractAt(InputStream in, long offset, String password,
                                            OutputStream out) throws IOException {
        awaitFully(in, offset);
        Envelope.Header h = Envelope.readHeader(in);
        if (h == null) throw new IOException("未找到有效的 StegoBox 头");
        Envelope.Fields f = h.fields;
        byte[] key = f.keyFor(password);
        Crypto.openStream(f.cipher, key, f.nonce, f.aad(), in, out);
        return f;
    }

    /** Opens a fresh stream over the stego document (needed twice: scan, then read). */
    public interface Opener {
        InputStream open() throws IOException;
    }

    /**
     * Finds the envelope and streams it out. The document is opened twice — once to locate the
     * trailing envelope, once to read it — because scanning consumes the stream.
     * Returns null when no envelope is present.
     */
    public static Envelope.Fields extract(Opener opener, String password, OutputStream out)
            throws IOException {
        long at;
        try (InputStream scan = opener.open()) {
            at = findLastEnvelopeOffset(scan, Envelope.MAGIC);
        }
        if (at < 0) return null;
        try (InputStream in = opener.open()) {
            return extractAt(in, at, password, out);
        }
    }

    public static void awaitFully(InputStream in, long n) throws IOException {
        long left = n;
        while (left > 0) {
            long skipped = in.skip(left);
            if (skipped > 0) { left -= skipped; continue; }
            if (in.read() < 0) throw new IOException("数据被截断");
            left--;
        }
    }

    /** Opens a buffered output stream for a plain file, creating parent directories. */
    public static OutputStream openFileOutput(File f) throws IOException {
        File p = f.getParentFile();
        if (p != null && !p.exists() && !p.mkdirs()) throw new IOException("无法创建目录 " + p);
        return new BufferedOutputStream(new FileOutputStream(f), BUF);
    }
}