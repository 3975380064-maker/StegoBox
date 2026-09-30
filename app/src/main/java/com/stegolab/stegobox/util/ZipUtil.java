package com.stegolab.stegobox.util;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

/** Minimal ZIP helpers. Extraction sanitises names (no absolute paths / ".."). */
public final class ZipUtil {

    private ZipUtil() {}

    public static byte[] zip(String[] names, byte[][] datas) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        Set<String> used = new HashSet<>();
        try (ZipOutputStream z = new ZipOutputStream(bos)) {
            for (int i = 0; i < names.length; i++) {
                String name = safe(names[i]);
                if (name.isEmpty()) name = "file" + (i + 1);
                // ZipOutputStream throws on duplicate entries, and gallery picks often
                // share the same display name -> make every entry unique.
                name = unique(name, used);
                z.putNextEntry(new ZipEntry(name));
                z.write(datas[i]);
                z.closeEntry();
            }
        }
        return bos.toByteArray();
    }

    /** Makes {@code name} unique inside {@code used} by appending (2), (3), … */
    public static String uniqueName(String name, Set<String> used) {
        if (used.add(name)) return name;
        int dot = name.lastIndexOf('.');
        String base = dot > 0 ? name.substring(0, dot) : name;
        String ext = dot > 0 ? name.substring(dot) : "";
        for (int k = 2; ; k++) {
            String cand = base + "(" + k + ")" + ext;
            if (used.add(cand)) return cand;
        }
    }

    private static String unique(String name, Set<String> used) {
        return uniqueName(name, used);
    }

    public static Map<String, byte[]> unzip(byte[] data) throws IOException {
        Map<String, byte[]> out = new LinkedHashMap<>();
        try (ZipInputStream z = new ZipInputStream(new ByteArrayInputStream(data))) {
            ZipEntry e;
            byte[] buf = new byte[8192];
            while ((e = z.getNextEntry()) != null) {
                if (e.isDirectory()) continue;
                String name = safe(e.getName());
                if (name.isEmpty()) continue;
                ByteArrayOutputStream bos = new ByteArrayOutputStream();
                int n;
                while ((n = z.read(buf)) > 0) bos.write(buf, 0, n);
                out.put(name, bos.toByteArray());
            }
        }
        return out;
    }

    public static boolean isZip(byte[] d) {
        return d.length > 3 && d[0] == 'P' && d[1] == 'K' && d[2] == 3 && d[3] == 4;
    }

    public static String safe(String n) {
        n = n.replace('\\', '/');
        StringBuilder sb = new StringBuilder();
        for (String p : n.split("/")) {
            if (p.isEmpty() || p.equals(".") || p.equals("..")) continue;
            if (sb.length() > 0) sb.append('/');
            sb.append(p);
        }
        return sb.toString();
    }
}