package com.stegolab.stegobox.crypto;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.SM4Engine;
import org.bouncycastle.crypto.modes.AEADCipher;
import org.bouncycastle.crypto.modes.ChaCha20Poly1305;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * Unified AEAD layer over Bouncy Castle's low-level API.
 * No JCE provider is registered, so it cannot clash with Android's built-in BC provider.
 *
 *   AES  -> AES-256-GCM            (128-bit block, wraps GCMBlockCipher)
 *   SM4  -> SM4-GCM  (国密)         (128-bit block, wraps GCMBlockCipher)
 *   ChaCha -> ChaCha20-Poly1305    (RFC 8439)
 */
public final class Crypto {

    public static final int NONE = 0;
    public static final int AES = 1;
    public static final int CHACHA = 2;
    public static final int SM4 = 3;

    private static final int MAC_BITS = 128;
    public static final int NONCE_LEN = 12;
    public static final int SALT_LEN = 16;

    private Crypto() {}

    public static int keyBits(int cipher) {
        switch (cipher) {
            case AES:    return 256;
            case CHACHA: return 256;
            case SM4:    return 128;
            default:     return 0;
        }
    }

    public static String name(int cipher) {
        switch (cipher) {
            case AES:    return "AES-256-GCM";
            case CHACHA: return "ChaCha20-Poly1305";
            case SM4:    return "SM4-GCM (国密)";
            default:     return "不加密";
        }
    }

    public static byte[] seal(int cipher, byte[] key, byte[] nonce, byte[] aad, byte[] pt) {
        switch (cipher) {
            case AES:    return gcm(new AESEngine(), key, nonce, aad, pt, true);
            case SM4:    return gcm(new SM4Engine(), key, nonce, aad, pt, true);
            case CHACHA: return chacha(key, nonce, aad, pt, true);
            default:     return pt;
        }
    }

    public static byte[] open(int cipher, byte[] key, byte[] nonce, byte[] aad, byte[] ct) {
        switch (cipher) {
            case AES:    return gcm(new AESEngine(), key, nonce, aad, ct, false);
            case SM4:    return gcm(new SM4Engine(), key, nonce, aad, ct, false);
            case CHACHA: return chacha(key, nonce, aad, ct, false);
            default:     return ct;
        }
    }

    private static byte[] gcm(BlockCipher engine, byte[] key, byte[] nonce, byte[] aad,
                              byte[] in, boolean forEncryption) {
        GCMBlockCipher c = new GCMBlockCipher(engine);
        c.init(forEncryption, new AEADParameters(new KeyParameter(key), MAC_BITS, nonce, aad));
        byte[] out = new byte[c.getOutputSize(in.length)];
        int n = c.processBytes(in, 0, in.length, out, 0);
        try {
            n += c.doFinal(out, n);
        } catch (Exception e) {
            throw new SecurityException(forEncryption ? "加密失败" : "认证失败（密钥错误或数据被篡改）", e);
        }
        return trim(out, n);
    }

    private static byte[] chacha(byte[] key, byte[] nonce, byte[] aad, byte[] in, boolean forEncryption) {
        ChaCha20Poly1305 c = new ChaCha20Poly1305();
        c.init(forEncryption, new AEADParameters(new KeyParameter(key), MAC_BITS, nonce, aad));
        byte[] out = new byte[c.getOutputSize(in.length)];
        int n = c.processBytes(in, 0, in.length, out, 0);
        try {
            n += c.doFinal(out, n);
        } catch (Exception e) {
            throw new SecurityException(forEncryption ? "加密失败" : "认证失败（密钥错误或数据被篡改）", e);
        }
        return trim(out, n);
    }

    private static byte[] trim(byte[] a, int n) {
        if (n == a.length) return a;
        byte[] t = new byte[n];
        System.arraycopy(a, 0, t, 0, n);
        return t;
    }

    // ------------------------------------------------------------------ streaming

    private static final int CHUNK = 64 * 1024;

    private static AEADCipher newAead(int cipher, byte[] key, byte[] nonce, byte[] aad,
                                           boolean forEncryption) {
        AEADCipher c;
        if (cipher == CHACHA) {
            c = new ChaCha20Poly1305();
        } else if (cipher == AES) {
            c = new GCMBlockCipher(new AESEngine());
        } else {
            c = new GCMBlockCipher(new SM4Engine());
        }
        c.init(forEncryption, new AEADParameters(new KeyParameter(key), MAC_BITS, nonce, aad));
        return c;
    }

    /** Stream-encrypts {@code in} into {@code out} (ciphertext||tag). Memory use is O(CHUNK). */
    public static void sealStream(int cipher, byte[] key, byte[] nonce, byte[] aad,
                                  InputStream in, OutputStream out) throws IOException {
        if (cipher == NONE) {
            pipe(in, out);
            return;
        }
        pump(newAead(cipher, key, nonce, aad, true), in, out);
    }

    /** Stream-decrypts {@code in} (ciphertext||tag, read to EOF) into {@code out}. */
    public static void openStream(int cipher, byte[] key, byte[] nonce, byte[] aad,
                                  InputStream in, OutputStream out) throws IOException {
        if (cipher == NONE) {
            pipe(in, out);
            return;
        }
        pump(newAead(cipher, key, nonce, aad, false), in, out);
    }

    private static void pump(AEADCipher c, InputStream in, OutputStream out) throws IOException {
        byte[] buf = new byte[CHUNK];
        byte[] ob = new byte[CHUNK + 64];
        int n;
        try {
            while ((n = in.read(buf)) > 0) {
                int m = c.processBytes(buf, 0, n, ob, 0);
                if (m > 0) out.write(ob, 0, m);
            }
            int m = c.doFinal(ob, 0);
            if (m > 0) out.write(ob, 0, m);
        } catch (InvalidCipherTextException e) {
            throw new SecurityException("认证失败（密钥错误或数据被篡改）", e);
        }
        out.flush();
    }

    public static void pipe(InputStream in, OutputStream out) throws IOException {
        byte[] buf = new byte[CHUNK];
        int n;
        while ((n = in.read(buf)) > 0) out.write(buf, 0, n);
        out.flush();
    }
}