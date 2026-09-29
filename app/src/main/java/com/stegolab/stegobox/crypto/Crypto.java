package com.stegolab.stegobox.crypto;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.SM4Engine;
import org.bouncycastle.crypto.modes.ChaCha20Poly1305;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;

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
}