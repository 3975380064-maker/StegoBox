package com.stegolab.stegobox.stego;

import android.graphics.Bitmap;

import java.io.ByteArrayOutputStream;

/**
 * Pixel LSB carrier: 1 bit per R/G/B byte, row-major, 32-bit length prefix.
 * Requires a lossless image format (PNG) and a channel that does not re-encode.
 */
public final class LsbStego {

    private LsbStego() {}

    public static Bitmap embed(Bitmap src, byte[] payload) {
        int w = src.getWidth(), h = src.getHeight();
        Bitmap out = src.copy(Bitmap.Config.ARGB_8888, true);
        int[] px = new int[w * h];
        out.getPixels(px, 0, w, 0, 0, w, h);

        byte[] framed = frame(payload);
        long needBits = (long) framed.length * 8;
        long capBits = (long) w * h * 3;
        if (needBits > capBits) {
            throw new IllegalArgumentException(
                    "图片容量不足：需要 " + needBits + " 位，只有 " + capBits + " 位。请换更大的图片，或改用「尾部追加」。");
        }

        int total = (int) needBits;
        int bit = 0;
        for (int i = 0; i < px.length && bit < total; i++) {
            int p = px[i];
            int r = (p >> 16) & 0xFF, g = (p >> 8) & 0xFF, b = p & 0xFF;
            for (int c = 0; c < 3 && bit < total; c++, bit++) {
                int v = (framed[bit >> 3] >> (7 - (bit & 7))) & 1;
                if (c == 0) r = (r & 0xFE) | v;
                else if (c == 1) g = (g & 0xFE) | v;
                else b = (b & 0xFE) | v;
            }
            // force alpha to opaque: ARGB_8888 bitmaps are premultiplied, and with a=0
            // the colour channels get scaled to 0, which would silently destroy the LSBs.
            px[i] = 0xFF000000 | (r << 16) | (g << 8) | b;
        }
        out.setPixels(px, 0, w, 0, 0, w, h);
        return out;
    }

    /** @return the framed payload bytes (envelope), or null if the image carries nothing. */
    public static byte[] extract(Bitmap bmp) {
        int w = bmp.getWidth(), h = bmp.getHeight();
        int[] px = new int[w * h];
        bmp.getPixels(px, 0, w, 0, 0, w, h);

        int[] pos = {0};
        long len = 0;
        for (int i = 0; i < 32; i++) len = (len << 1) | nextBit(px, pos);
        long capBytes = (long) w * h * 3 / 8;
        if (len <= 0 || len > capBytes) return null;

        byte[] out = new byte[(int) len];
        for (int i = 0; i < out.length; i++) {
            int v = 0;
            for (int j = 0; j < 8; j++) v = (v << 1) | nextBit(px, pos);
            out[i] = (byte) v;
        }
        return out;
    }

    private static int nextBit(int[] px, int[] pos) {
        int idx = pos[0]++;
        int i = idx / 3, c = idx % 3;
        int p = px[i];
        if (c == 0) return (p >> 16) & 1;
        if (c == 1) return (p >> 8) & 1;
        return p & 1;
    }

    private static byte[] frame(byte[] data) {
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        o.write((data.length >>> 24) & 0xFF);
        o.write((data.length >>> 16) & 0xFF);
        o.write((data.length >>> 8) & 0xFF);
        o.write(data.length & 0xFF);
        o.write(data, 0, data.length);
        return o.toByteArray();
    }
}