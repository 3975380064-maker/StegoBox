package com.stegolab.stegobox.crypto;

import org.bouncycastle.crypto.PBEParametersGenerator;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.bouncycastle.crypto.params.KeyParameter;

/** Key derivation (PBKDF2-HMAC-SHA256) and hashing (SHA-256), both via Bouncy Castle. */
public final class Kdf {

    private Kdf() {}

    public static byte[] pbkdf2(String password, byte[] salt, int iterations, int bits) {
        PKCS5S2ParametersGenerator gen = new PKCS5S2ParametersGenerator(new SHA256Digest());
        gen.init(PBEParametersGenerator.PKCS5PasswordToUTF8Bytes(password.toCharArray()), salt, iterations);
        return ((KeyParameter) gen.generateDerivedParameters(bits)).getKey();
    }

    public static byte[] sha256(byte[] data) {
        SHA256Digest d = new SHA256Digest();
        d.update(data, 0, data.length);
        byte[] out = new byte[32];
        d.doFinal(out, 0);
        return out;
    }

    public static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) sb.append(String.format("%02x", x));
        return sb.toString();
    }
}