package com.stegolab.stegobox.stego;

import android.graphics.Bitmap;

import java.util.Locale;

/**
 * Minimal steganalysis so the app can *honestly* report how detectable its own output is.
 *
 * <p>Chi-square attack (Westfeld &amp; Pfitzmann): pixel values are grouped into Pairs of Values
 * (2i, 2i+1). The null hypothesis is "the LSB plane is random", i.e. the two counts of a pair are
 * equal. Natural images do <b>not</b> satisfy it (their pair counts differ), so the p-value is
 * small. LSB embedding equalises the pairs, so the statistic collapses and the p-value rises
 * towards 1.
 *
 * <p>Therefore: <b>p close to 1 → embedding suspected; p close to 0 → no evidence.</b>
 * (This matches the "probability of embedding" reported by StegExpose / aletheia style tools.)
 *
 * <p>Caveat: a very flat image (nearly constant colour) also has equal pair counts, which is a
 * known false positive of this test. {@link Result#lsbEntropy} is reported so that case can be
 * recognised (a flat image has an almost-constant LSB plane, i.e. entropy near 0).
 */
public final class Steganalysis {

    public static final class Result {
        public final double chiSquare;
        public final int dof;
        public final double pValue;      // ~1 => no evidence, ~0 => embedding detected
        public final double lsbEntropy;  // bits/sample, 1.0 = perfectly random LSB plane
        public final long samples;

        Result(double chiSquare, int dof, double pValue, double lsbEntropy, long samples) {
            this.chiSquare = chiSquare;
            this.dof = dof;
            this.pValue = pValue;
            this.lsbEntropy = lsbEntropy;
            this.samples = samples;
        }

        /** Human-readable verdict (Chinese). p ~1 means "matches a random LSB plane" => suspicious. */
        public String verdict() {
            String p = String.format(Locale.US, "%.3g", pValue);
            String e = String.format(Locale.US, "%.3f", lsbEntropy);
            if (lsbEntropy < 0.2 && pValue > 0.5) {
                return "图像过于平坦，χ² 结果不可靠（p=" + p + "，LSB 熵=" + e + "）";
            }
            if (pValue > 0.95) {
                return "强烈提示含 LSB 隐写（p=" + p + "，LSB 熵=" + e + "）→ 常规隐写分析可检出";
            }
            if (pValue > 0.5) {
                return "可疑：与随机 LSB 平面接近（p=" + p + "，LSB 熵=" + e + "）→ 建议降低嵌入率";
            }
            return "未见明显 LSB 隐写痕迹（p=" + p + "，LSB 熵=" + e + "）";
        }
    }

    private Steganalysis() {}

    public static Result analyze(Bitmap bmp) {
        int w = bmp.getWidth(), h = bmp.getHeight();
        int[] px = new int[w * h];
        bmp.getPixels(px, 0, w, 0, 0, w, h);
        return analyze(px);
    }

    public static Result analyze(int[] px) {
        int[][] hist = new int[3][256];
        for (int p : px) {
            hist[0][(p >> 16) & 0xFF]++;
            hist[1][(p >> 8) & 0xFF]++;
            hist[2][p & 0xFF]++;
        }

        // ---- chi-square over pairs of values (2i, 2i+1) ----
        double chi2 = 0;
        int dof = 0;
        for (int c = 0; c < 3; c++) {
            for (int i = 0; i < 128; i++) {
                int a = hist[c][2 * i];
                int b = hist[c][2 * i + 1];
                int n = a + b;
                if (n == 0) continue;
                double expected = n / 2.0;
                chi2 += (a - expected) * (a - expected) / expected;
                chi2 += (b - expected) * (b - expected) / expected;
                dof++;
            }
        }
        if (dof == 0) dof = 1;
        double pVal = chiSquareUpperTail(chi2, dof);

        // ---- LSB plane entropy (bits per sample) ----
        long ones = 0, total = 0;
        for (int p : px) {
            ones += (p & 1) + ((p >> 8) & 1) + ((p >> 16) & 1);
            total += 3;
        }
        double q = total == 0 ? 0 : (double) ones / total;
        double entropy = (q <= 0 || q >= 1) ? 0.0
                : -(q * Math.log(q) + (1 - q) * Math.log(1 - q)) / Math.log(2);

        return new Result(chi2, dof, pVal, entropy, px.length);
    }

    // ------------------------------------------------------------------ maths

    /** P(X &gt; x) for a chi-square variable with k degrees of freedom (regularised Q). */
    private static double chiSquareUpperTail(double x, int k) {
        if (x <= 0) return 1.0;
        return gammaQ(k / 2.0, x / 2.0);
    }

    private static double logGamma(double x) {
        double[] cof = {76.18009172947146, -86.50532032941677, 24.01409824083091,
                -1.231739572450155, 0.1208650973866179e-2, -0.5395239384953e-5};
        double y = x, tmp = x + 5.5;
        tmp -= (x + 0.5) * Math.log(tmp);
        double ser = 1.000000000190015;
        for (int j = 0; j < 6; j++) ser += cof[j] / ++y;
        return -tmp + Math.log(2.5066282746310005 * ser / x);
    }

    /** Regularised lower incomplete gamma P(a,x). */
    private static double gammaP(double a, double x) {
        if (x < 0 || a <= 0) return 0;
        if (x < a + 1.0) {
            double ap = a, sum = 1.0 / a, del = sum;
            for (int n = 1; n < 300; n++) {
                ap += 1.0;
                del *= x / ap;
                sum += del;
                if (Math.abs(del) < Math.abs(sum) * 1e-14) break;
            }
            return sum * Math.exp(-x + a * Math.log(x) - logGamma(a));
        }
        return 1.0 - gammaQ(a, x);
    }

    /** Regularised upper incomplete gamma Q(a,x) via continued fraction. */
    private static double gammaQ(double a, double x) {
        if (x < a + 1.0) return 1.0 - gammaP(a, x);
        double b = x + 1.0 - a, c = 1e300, d = 1.0 / b, h = d;
        for (int i = 1; i < 300; i++) {
            double an = -i * (i - a);
            b += 2.0;
            d = an * d + b;
            if (Math.abs(d) < 1e-300) d = 1e-300;
            c = b + an / c;
            if (Math.abs(c) < 1e-300) c = 1e-300;
            d = 1.0 / d;
            double del = d * c;
            h *= del;
            if (Math.abs(del - 1.0) < 1e-14) break;
        }
        return Math.exp(-x + a * Math.log(x) - logGamma(a)) * h;
    }
}