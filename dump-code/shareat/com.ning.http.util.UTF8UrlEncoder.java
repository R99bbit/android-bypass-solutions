package com.ning.http.util;

public class UTF8UrlEncoder {
    private static final char[] HEX = "0123456789ABCDEF".toCharArray();
    private static final int[] SAFE_ASCII = new int[128];
    private static final boolean encodeSpaceUsingPlus;

    static {
        boolean z;
        if (System.getProperty("com.com.ning.http.util.UTF8UrlEncoder.encodeSpaceUsingPlus") == null) {
            z = false;
        } else {
            z = true;
        }
        encodeSpaceUsingPlus = z;
        for (int i = 97; i <= 122; i++) {
            SAFE_ASCII[i] = 1;
        }
        for (int i2 = 65; i2 <= 90; i2++) {
            SAFE_ASCII[i2] = 1;
        }
        for (int i3 = 48; i3 <= 57; i3++) {
            SAFE_ASCII[i3] = 1;
        }
        SAFE_ASCII[45] = 1;
        SAFE_ASCII[46] = 1;
        SAFE_ASCII[95] = 1;
        SAFE_ASCII[126] = 1;
    }

    private UTF8UrlEncoder() {
    }

    public static String encode(String input) {
        StringBuilder sb = new StringBuilder(input.length() + 16);
        appendEncoded(sb, input);
        return sb.toString();
    }

    public static StringBuilder appendEncoded(StringBuilder sb, String input) {
        int[] safe = SAFE_ASCII;
        int i = 0;
        int len = input.length();
        while (i < len) {
            int c = input.codePointAt(i);
            if (c > 127) {
                appendMultiByteEncoded(sb, c);
            } else if (safe[c] != 0) {
                sb.append((char) c);
            } else {
                appendSingleByteEncoded(sb, c);
            }
            i += Character.charCount(c);
        }
        return sb;
    }

    private static final void appendSingleByteEncoded(StringBuilder sb, int value) {
        if (!encodeSpaceUsingPlus || value != 32) {
            sb.append('%');
            sb.append(HEX[value >> 4]);
            sb.append(HEX[value & 15]);
            return;
        }
        sb.append('+');
    }

    private static final void appendMultiByteEncoded(StringBuilder sb, int value) {
        if (value < 2048) {
            appendSingleByteEncoded(sb, (value >> 6) | 192);
            appendSingleByteEncoded(sb, (value & 63) | 128);
        } else if (value < 65536) {
            appendSingleByteEncoded(sb, (value >> 12) | 224);
            appendSingleByteEncoded(sb, ((value >> 6) & 63) | 128);
            appendSingleByteEncoded(sb, (value & 63) | 128);
        } else {
            appendSingleByteEncoded(sb, (value >> 18) | 240);
            appendSingleByteEncoded(sb, ((value >> 12) & 63) | 128);
            appendSingleByteEncoded(sb, ((value >> 6) & 63) | 128);
            appendSingleByteEncoded(sb, (value & 63) | 128);
        }
    }
}