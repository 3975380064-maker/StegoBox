package com.stegolab.stegobox.stego;

import com.stegolab.stegobox.container.Envelope;

/**
 * Tail-append carrier: the envelope is written after the cover image bytes.
 * The file stays a valid image; capacity is bounded only by file size.
 * Needs a lossless channel (any re-encode strips the payload).
 */
public final class TailAppend {

    private TailAppend() {}

    public static byte[] embed(byte[] cover, Envelope e) {
        byte[] env = e.serialize();
        byte[] out = new byte[cover.length + env.length];
        System.arraycopy(cover, 0, out, 0, cover.length);
        System.arraycopy(env, 0, out, cover.length, env.length);
        return out;
    }

    public static Envelope extract(byte[] fileBytes) {
        return Envelope.findEnvelope(fileBytes);
    }

    public static boolean looksLikeTailAppend(byte[] fileBytes) {
        return Envelope.findEnvelope(fileBytes) != null;
    }
}