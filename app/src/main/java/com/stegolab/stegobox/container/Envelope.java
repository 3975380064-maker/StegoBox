package com.stegolab.stegobox.container;

import com.stegolab.stegobox.crypto.Crypto;
import com.stegolab.stegobox.crypto.Kdf;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Self-describing container envelope, version 3.
 *
 * Layout:
 *   magic(5 "SGBX3") ver(1) carrier(1) cipher(1) keyMode(1) iters(4 BE)
 *   salt(16) nonce(12) payloadLen(8 BE) plaintextSHA256(32)
 *   nameLen(2 BE) + nameUTF8        (0 => payload is a multi-file bundle/zip)
 *   [if keyMode == EMBEDDED: pwLen(2 BE) + pw bytes]
 *   payload  (= ciphertext||tag when encrypted, else plaintext)
 *
 * keyMode:
 *   NONE      -> no encryption (cipher must be NONE); SHA-256 only
 *   PASSWORD  -> receiver types the password ("手动输入")
 *   EMBEDDED  -> password stored in the file; receiver needs no input ("自动输入")
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

    private static byte[] aad(int carrier, int cipher, int keyMode, int iters) {
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
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        o.write(MAGIC, 0, MAGIC.length);
        o.write(VERSION);
        o.write(carrier);
        o.write(cipher);
        o.write(keyMode);
        writeInt(o, iters);
        o.write(salt, 0, salt.length);
        o.write(nonce, 0, nonce.length);
        writeLong(o, payload.length);
        o.write(hash, 0, hash.length);
        byte[] nm = (payloadName == null ? "" : payloadName).getBytes(StandardCharsets.UTF_8);
        o.write((nm.length >>> 8) & 0xFF);
        o.write(nm.length & 0xFF);
        o.write(nm, 0, nm.length);
        if (keyMode == KEY_EMBEDDED) {
            byte[] p = (embeddedPassword == null ? "" : embeddedPassword).getBytes(StandardCharsets.UTF_8);
            o.write((p.length >>> 8) & 0xFF);
            o.write(p.length & 0xFF);
            o.write(p, 0, p.length);
        }
        o.write(payload, 0, payload.length);
        return o.toByteArray();
    }

    public static Envelope parse(byte[] d, int off) {
        try {
            int p = off;
            for (int i = 0; i < MAGIC.length; i++) if (d[p + i] != MAGIC[i]) return null;
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
                pw = new String(d, p, n, StandardCharsets.UTF_8); p += n;
            }
            if (len < 0 || p + len > d.length) return null;
            byte[] payload = slice(d, p, (int) len);
            return new Envelope(carrier, cipher, keyMode, iters, salt, nonce, hash,
                    name, payload, pw);
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