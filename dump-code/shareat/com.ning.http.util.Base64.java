package com.ning.http.util;

public final class Base64 {
    private static final char[] lookup = new char[64];
    private static final byte[] reverseLookup = new byte[256];

    static {
        for (int i = 0; i < 26; i++) {
            lookup[i] = (char) (i + 65);
        }
        int i2 = 26;
        int j = 0;
        while (i2 < 52) {
            lookup[i2] = (char) (j + 97);
            i2++;
            j++;
        }
        int i3 = 52;
        int j2 = 0;
        while (i3 < 62) {
            lookup[i3] = (char) (j2 + 48);
            i3++;
            j2++;
        }
        lookup[62] = '+';
        lookup[63] = '/';
        for (int i4 = 0; i4 < 256; i4++) {
            reverseLookup[i4] = -1;
        }
        for (int i5 = 90; i5 >= 65; i5--) {
            reverseLookup[i5] = (byte) (i5 - 65);
        }
        for (int i6 = 122; i6 >= 97; i6--) {
            reverseLookup[i6] = (byte) ((i6 - 97) + 26);
        }
        for (int i7 = 57; i7 >= 48; i7--) {
            reverseLookup[i7] = (byte) ((i7 - 48) + 52);
        }
        reverseLookup[43] = 62;
        reverseLookup[47] = 63;
        reverseLookup[61] = 0;
    }

    private Base64() {
    }

    public static String encode(byte[] bytes) {
        StringBuilder buf = new StringBuilder(((bytes.length + 2) / 3) * 4);
        int end = bytes.length - 2;
        int i = 0;
        while (i < end) {
            int i2 = i + 1;
            int i3 = i2 + 1;
            int chunk = ((bytes[i] & 255) << 16) | ((bytes[i2] & 255) << 8) | (bytes[i3] & 255);
            buf.append(lookup[chunk >> 18]);
            buf.append(lookup[(chunk >> 12) & 63]);
            buf.append(lookup[(chunk >> 6) & 63]);
            buf.append(lookup[chunk & 63]);
            i = i3 + 1;
        }
        int len = bytes.length;
        if (i < len) {
            int i4 = i + 1;
            int chunk2 = (bytes[i] & 255) << 16;
            buf.append(lookup[chunk2 >> 18]);
            if (i4 < len) {
                int chunk3 = chunk2 | ((bytes[i4] & 255) << 8);
                buf.append(lookup[(chunk3 >> 12) & 63]);
                buf.append(lookup[(chunk3 >> 6) & 63]);
            } else {
                buf.append(lookup[(chunk2 >> 12) & 63]);
                buf.append('=');
            }
            buf.append('=');
        }
        return buf.toString();
    }

    public static byte[] decode(String encoded) {
        int padding = 0;
        for (int i = encoded.length() - 1; encoded.charAt(i) == '='; i--) {
            padding++;
        }
        int length = ((encoded.length() * 6) / 8) - padding;
        byte[] bytes = new byte[length];
        int index = 0;
        int n = encoded.length();
        for (int i2 = 0; i2 < n; i2 += 4) {
            int word = (reverseLookup[encoded.charAt(i2)] << 18) + (reverseLookup[encoded.charAt(i2 + 1)] << 12) + (reverseLookup[encoded.charAt(i2 + 2)] << 6) + reverseLookup[encoded.charAt(i2 + 3)];
            int j = 0;
            while (j < 3 && index + j < length) {
                bytes[index + j] = (byte) (word >> ((2 - j) * 8));
                j++;
            }
            index += 3;
        }
        return bytes;
    }
}