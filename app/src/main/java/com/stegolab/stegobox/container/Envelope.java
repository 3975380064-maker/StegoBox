package com.stegolab.stegobox.container;

import com.stegolab.stegobox.crypto.Crypto;
import com.stegolab.stegobox.crypto.Kdf;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Self-describing container envelope, version 3.
 *
 * <pre>
 * magic(5 "SGBX3") ver(1) carrier(1) cipher(1) keyMode(1) iters(4 BE)
 * salt(16) nonce(12) payloadLen(8 BE) sha256(32)
 * nameLen(2 BE) + nameUTF8            (0 =&gt; payload is a multi-file bundle/ZIP)
 * [if keyMode == EMBEDDED: pwLen(2 BE) + password]
 * payload                             (= ciphertext||tag, or plaintext when unencrypted)
 * </pre>
 *
 * keyMode: NONE (no encryption) / PASSWORD (receiver types it) / EMBEDDED (stored in the file).
 *
 * <p>The header layout is shared by the in-memory path ({@link #serialize()}) and the streaming
 * path ({@link #headerBytes}) so both produce byte-identical envelopes.
 */
public final class Envelope {

    public static final byte[] MAGIC = {'S', 'G', 'B', 'X', '3'};
    public static final int VERSION = 3;

    public static final int CARRIER_APPEND = 0;
    public static final int CARRIER_LSB = 1;

    public static final int KEY_NONE = 0;
    public static final int KEY_PASSWORD = 1;   // receiver must type it
    public static final int KEY_EMBEDDED = 2;   // stored in the file (no security)

    public static final int DEFAULT_ITERS = 200000;

    /** AEAD tag size in bytes (128-bit MAC), i.e. ciphertext = plaintext + TAG_LEN. */
    public static final int TAG_LEN = 16;

    /**
     * Length of the stored payload for a given plaintext length.
     * The header field {@code payloadLen} always describes the CIPHERTEXT (see {@link #parse}).
     */
    public static long payloadLengthFor(int cipher, long plaintextLen) {
        return cipher == Crypto.NONE ? plaintextLen : plaintextLen + TAG_LEN;
    }

    /** Size of the fixed part of the header, before the variable name / password blocks. */
    public static final int FIXED_HEADER =
            5 + 1 + 1 + 1 + 1 + 4 + 16 + 12 + 8 + 32;   // = 81

    /** Parsed header fields (no payload). */
    public static final class Fields {
        public final int carrier, cipher, keyMode, iters;
        public final byte[] salt, nonce, hash;
        public final String name;
        public final String embeddedPassword;
        public final long payloadLen;

        Fields(int carrier, int cipher, int keyMode, int iters, byte[] salt, byte[] nonce,
               byte[] hash, String name, String embeddedPassword, long payloadLen) {
            this.carrier = carrier;
            this.cipher = cipher;
            this.keyMode = keyMode;
            this.iters = iters;
            this.salt = salt;
            this.nonce = nonce;
            this.hash = hash;
            this.name = name;
            this.embeddedPassword = embeddedPassword;
            this.payloadLen = payloadLen;
        }

        public boolean isBundle() {
            return name == null || name.isEmpty();
        }

        /** AAD binds the header fields to the ciphertext. */
        public byte[] aad() {
            return Envelope.aad(carrier, cipher, keyMode, iters);
        }

        public byte[] keyFor(String userPassword) {
            String pw = (keyMode == KEY_EMBEDDED) ? embeddedPassword : userPassword;
            return Envelope.derive(cipher, keyMode, pw, salt, iters);
        }
    }

    public final int carrier, cipher, keyMode, iters;
    public final byte[] salt, nonce, hash, payload;
    public final String payloadName;            // null => bundle (zip)
    public final String embeddedPassword;

    private Envelope(int carrier, int cipher, int keyMode, int iters,
                     byte[] salt, byte[] nonce, byte[] hash,
                     String payloadName, byte[] payload, String embeddedPassword) {
        this.carrier = carrier;
        this.cipher = cipher;
        this.keyMode = keyMode;
        this.iters = iters;
        this.salt = salt;
        this.nonce = nonce;
        this.hash = hash;
        this.payloadName = payloadName;
        this.payload = payload;
        this.embeddedPassword = embeddedPassword;
    }

    // ------------------------------------------------------------------ header bytes

    /** Serialises only the header, for a payload of exactly {@code payloadLen} bytes. */
    public static byte[] headerBytes(int carrier, int cipher, int keyMode, int iters,
                                     byte[] salt, byte[] nonce, long payloadLen, byte[] hash,
                                     String name, String embeddedPassword) {
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        o.write(MAGIC, 0, MAGIC.length);
        o.write(VERSION);
        o.write(carrier);
        o.write(cipher);
        o.write(keyMode);
        writeInt(o, iters);
        o.write(salt, 0, salt.length);
        o.write(nonce, 0, nonce.length);
        writeLong(o, payloadLen);
        o.write(hash, 0, hash.length);
        byte[] nm = (name == null ? "" : name).getBytes(StandardCharsets.UTF_8);
        o.write((nm.length >>> 8) & 0xFF);
        o.write(nm.length & 0xFF);
        o.write(nm, 0, nm.length);
        if (keyMode == KEY_EMBEDDED) {
            byte[] p = (embeddedPassword == null ? "" : embeddedPassword).getBytes(StandardCharsets.UTF_8);
            o.write((p.length >>> 8) & 0xFF);
            o.write(p.length & 0xFF);
            o.write(p, 0, p.length);
        }
        return o.toByteArray();
    }

    /** Parsed header together with the number of bytes it occupied in the stream. */
    public static final class Header {
        public final Fields fields;
        public final int headerLength;

        Header(Fields fields, int headerLength) {
            this.fields = fields;
            this.headerLength = headerLength;
        }
    }

    /**
     * Reads exactly one header from the stream (magic .. optional name / password blocks) and
     * parses it. The stream is left positioned at the first payload byte.
     */
    public static Header readHeader(InputStream in) throws IOException {
        byte[] fixed = readFully(in, FIXED_HEADER);              // 81 bytes, includes payloadLen
        int keyMode = fixed[8] & 0xFF;

        byte[] nameLenB = readFully(in, 2);
        int nameLen = ((nameLenB[0] & 0xFF) << 8) | (nameLenB[1] & 0xFF);
        byte[] name = nameLen > 0 ? readFully(in, nameLen) : new byte[0];

        byte[] pwLenB = null, pw = new byte[0];
        if (keyMode == KEY_EMBEDDED) {
            pwLenB = readFully(in, 2);
            int pwLen = ((pwLenB[0] & 0xFF) << 8) | (pwLenB[1] & 0xFF);
            if (pwLen > 0) pw = readFully(in, pwLen);
        }

        ByteArrayOutputStream o = new ByteArrayOutputStream();
        o.write(fixed, 0, fixed.length);
        o.write(nameLenB, 0, 2);
        o.write(name, 0, name.length);
        if (pwLenB != null) {
            o.write(pwLenB, 0, 2);
            o.write(pw, 0, pw.length);
        }
        byte[] head = o.toByteArray();
        Fields f = readFields(head, 0);
        if (f == null) return null;
        return new Header(f, head.length);
    }

    private static byte[] readFully(InputStream in, int n) throws IOException {
        byte[] b = new byte[n];
        int off = 0;
        while (off < n) {
            int r = in.read(b, off, n - off);
            if (r < 0) throw new IOException("数据不完整");
            off += r;
        }
        return b;
    }

    public static Fields readFields(byte[] d, int off) {
        int p = off;
        for (int i = 0; i < MAGIC.length; i++) {
            if (d[p + i] != MAGIC[i]) return null;
        }
        p += MAGIC.length;
        int ver = d[p++] & 0xFF;
        if (ver != VERSION) return null;
        int carrier = d[p++] & 0xFF;
        int cipher = d[p++] & 0xFF;
        int keyMode = d[p++] & 0xFF;
        int iters = readInt(d, p); p += 4;
        byte[] salt = slice(d, p, Crypto.SALT_LEN); p += Crypto.SALT_LEN;
        byte[] nonce = slice(d, p, Crypto.NONCE_LEN); p += Crypto.NONCE_LEN;
        long len = readLong(d, p); p += 8;
        byte[] hash = slice(d, p, 32); p += 32;
        int nameLen = ((d[p] & 0xFF) << 8) | (d[p + 1] & 0xFF); p += 2;
        String name = nameLen == 0 ? null : new String(d, p, nameLen, StandardCharsets.UTF_8);
        p += nameLen;
        String pw = null;
        if (keyMode == KEY_EMBEDDED) {
            int n = ((d[p] & 0xFF) << 8) | (d[p + 1] & 0xFF); p += 2;
            pw = new String(d, p, n, StandardCharsets.UTF_8);
            p += n;
        }
        if (len < 0) return null;
        return new Fields(carrier, cipher, keyMode, iters, salt, nonce, hash, name, pw, len);
    }

    // ------------------------------------------------------------------ build / open

    public static Envelope build(int carrier, int cipher, int keyMode,
                                 String password, String payloadName, byte[] plain) {
        int iters = DEFAULT_ITERS;
        SecureRandom r = new SecureRandom();
        byte[] salt = new byte[Crypto.SALT_LEN];
        byte[] nonce = new byte[Crypto.NONCE_LEN];
        r.nextBytes(salt);
        r.nextBytes(nonce);
        byte[] hash = Kdf.sha256(plain);
        String embedded = (keyMode == KEY_EMBEDDED) ? password : null;
        byte[] key = derive(cipher, keyMode, password, salt, iters);
        byte[] payload = Crypto.seal(cipher, key, nonce, aad(carrier, cipher, keyMode, iters), plain);
        return new Envelope(carrier, cipher, keyMode, iters, salt, nonce, hash,
                payloadName, payload, embedded);
    }

    /** Decrypt + verify. For EMBEDDED mode the user-supplied password is ignored. */
    public byte[] decrypt(String userPassword) {
        String pw = (keyMode == KEY_EMBEDDED) ? embeddedPassword : userPassword;
        byte[] key = derive(cipher, keyMode, pw, salt, iters);
        byte[] pt = Crypto.open(cipher, key, nonce, aad(carrier, cipher, keyMode, iters), payload);
        if (!Arrays.equals(Kdf.sha256(pt), hash)) {
            throw new SecurityException("SHA-256 完整性校验失败");
        }
        return pt;
    }

    /** True when the plaintext is a bundle (multiple entries zipped by us). */
    public boolean isBundle() {
        return payloadName == null || payloadName.isEmpty();
    }

    private static byte[] derive(int cipher, int keyMode, String pw, byte[] salt, int iters) {
        if (cipher == Crypto.NONE || keyMode == KEY_NONE) return new byte[0];
        return Kdf.pbkdf2(pw == null ? "" : pw, salt, iters, Crypto.keyBits(cipher));
    }

    public static byte[] aad(int carrier, int cipher, int keyMode, int iters) {
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        o.write(MAGIC, 0, MAGIC.length);
        o.write(VERSION);
        o.write(carrier);
        o.write(cipher);
        o.write(keyMode);
        writeInt(o, iters);
        return o.toByteArray();
    }

    // ------------------------------------------------------------------ serialization

    public byte[] serialize() {
        byte[] head = headerBytes(carrier, cipher, keyMode, iters, salt, nonce,
                payload.length, hash, payloadName,
                keyMode == KEY_EMBEDDED ? embeddedPassword : null);
        byte[] out = new byte[head.length + payload.length];
        System.arraycopy(head, 0, out, 0, head.length);
        System.arraycopy(payload, 0, out, head.length, payload.length);
        return out;
    }

    /** Parse an envelope (header + inline payload) starting at {@code off}. */
    public static Envelope parse(byte[] d, int off) {
        try {
            Fields f = readFields(d, off);
            if (f == null) return null;
            int headLen = headerBytes(f.carrier, f.cipher, f.keyMode, f.iters, f.salt, f.nonce,
                    f.payloadLen, f.hash, f.name, f.embeddedPassword).length;
            int start = off + headLen;
            if (f.payloadLen < 0 || start + f.payloadLen > d.length) return null;
            byte[] payload = slice(d, start, (int) f.payloadLen);
            return new Envelope(f.carrier, f.cipher, f.keyMode, f.iters, f.salt, f.nonce, f.hash,
                    f.name, payload, f.embeddedPassword);
        } catch (Exception e) {
            return null;
        }
    }

    /** Find the last envelope in a byte stream (used by the tail-append carrier). */
    public static Envelope findEnvelope(byte[] data) {
        int at = -1;
        for (int i = data.length - MAGIC.length; i >= 0; i--) {
            boolean hit = true;
            for (int j = 0; j < MAGIC.length; j++) if (data[i + j] != MAGIC[j]) { hit = false; break; }
            if (hit) { at = i; break; }
        }
        return at < 0 ? null : parse(data, at);
    }

    // ------------------------------------------------------------------ helpers

    private static byte[] slice(byte[] d, int off, int len) {
        return Arrays.copyOfRange(d, off, off + len);
    }

    private static void writeInt(ByteArrayOutputStream o, int v) {
        o.write((v >>> 24) & 0xFF); o.write((v >>> 16) & 0xFF);
        o.write((v >>> 8) & 0xFF);  o.write(v & 0xFF);
    }

    private static void writeLong(ByteArrayOutputStream o, long v) {
        writeInt(o, (int) (v >>> 32));
        writeInt(o, (int) v);
    }

    private static int readInt(byte[] d, int p) {
        return ((d[p] & 0xFF) << 24) | ((d[p + 1] & 0xFF) << 16) | ((d[p + 2] & 0xFF) << 8) | (d[p + 3] & 0xFF);
    }

    private static long readLong(byte[] d, int p) {
        return ((long) readInt(d, p) << 32) | (readInt(d, p + 4) & 0xFFFFFFFFL);
    }
}