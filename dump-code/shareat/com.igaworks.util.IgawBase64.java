package com.igaworks.util;

public class IgawBase64 {
    private static char[] map1 = new char[64];
    private static byte[] map2 = new byte[128];

    static {
        int i;
        int i2 = 0;
        char c = 'A';
        while (true) {
            i = i2;
            if (c > 'Z') {
                break;
            }
            i2 = i + 1;
            map1[i] = c;
            c = (char) (c + 1);
        }
        char c2 = 'a';
        while (c2 <= 'z') {
            map1[i] = c2;
            c2 = (char) (c2 + 1);
            i++;
        }
        char c3 = '0';
        while (c3 <= '9') {
            map1[i] = c3;
            c3 = (char) (c3 + 1);
            i++;
        }
        int i3 = i + 1;
        map1[i] = '+';
        int i4 = i3 + 1;
        map1[i3] = '/';
        for (int i5 = 0; i5 < map2.length; i5++) {
            map2[i5] = -1;
        }
        for (int i6 = 0; i6 < 64; i6++) {
            map2[map1[i6]] = (byte) i6;
        }
    }

    public static String encodeString(String s) {
        if (s == null || s.equals("")) {
            return "";
        }
        return new String(encode(s.getBytes()));
    }

    public static char[] encode(byte[] in) {
        return encode(in, in.length);
    }

    public static char[] encode(byte[] in, int iLen) {
        int i1;
        int ip;
        int i2;
        int oDataLen = ((iLen * 4) + 2) / 3;
        char[] out = new char[(((iLen + 2) / 3) * 4)];
        int ip2 = 0;
        int op = 0;
        while (true) {
            int op2 = op;
            int ip3 = ip2;
            if (ip3 >= iLen) {
                return out;
            }
            int ip4 = ip3 + 1;
            int i0 = in[ip3] & 255;
            if (ip4 < iLen) {
                ip = ip4 + 1;
                i1 = in[ip4] & 255;
            } else {
                i1 = 0;
                ip = ip4;
            }
            if (ip < iLen) {
                ip2 = ip + 1;
                i2 = in[ip] & 255;
            } else {
                i2 = 0;
                ip2 = ip;
            }
            int o2 = ((i1 & 15) << 2) | (i2 >>> 6);
            int o3 = i2 & 63;
            int op3 = op2 + 1;
            out[op2] = map1[i0 >>> 2];
            int op4 = op3 + 1;
            out[op3] = map1[((i0 & 3) << 4) | (i1 >>> 4)];
            out[op4] = op4 < oDataLen ? map1[o2] : '=';
            int op5 = op4 + 1;
            out[op5] = op5 < oDataLen ? map1[o3] : '=';
            op = op5 + 1;
        }
    }

    public static String decodeString(String s) {
        return new String(decode(s));
    }

    public static byte[] decode(String s) {
        return decode(s.toCharArray());
    }

    /* JADX WARNING: Incorrect type for immutable var: ssa=char, code=int, for r8v2, types: [char] */
    /* JADX WARNING: Incorrect type for immutable var: ssa=char, code=int, for r9v2, types: [char] */
    public static byte[] decode(char[] in) {
        int i2;
        int i3;
        int ip;
        int iLen = in.length;
        if (iLen % 4 != 0) {
            throw new IllegalArgumentException("Length of Base64 encoded input string is not a multiple of 4.");
        }
        while (iLen > 0 && in[iLen - 1] == '=') {
            iLen--;
        }
        int oLen = (iLen * 3) / 4;
        byte[] out = new byte[oLen];
        int op = 0;
        int ip2 = 0;
        while (ip2 < iLen) {
            int ip3 = ip2 + 1;
            char i0 = in[ip2];
            int ip4 = ip3 + 1;
            char i1 = in[ip3];
            if (ip4 < iLen) {
                i2 = in[ip4];
                ip4++;
            } else {
                i2 = 65;
            }
            if (ip4 < iLen) {
                ip = ip4 + 1;
                i3 = in[ip4];
            } else {
                i3 = 65;
                ip = ip4;
            }
            if (i0 > 127 || i1 > 127 || i2 > 127 || i3 > 127) {
                throw new IllegalArgumentException("Illegal character in Base64 encoded data.");
            }
            byte b0 = map2[i0];
            byte b1 = map2[i1];
            byte b2 = map2[i2];
            byte b3 = map2[i3];
            if (b0 < 0 || b1 < 0 || b2 < 0 || b3 < 0) {
                throw new IllegalArgumentException("Illegal character in Base64 encoded data.");
            }
            int o1 = ((b1 & 15) << 4) | (b2 >>> 2);
            int o2 = ((b2 & 3) << 6) | b3;
            int op2 = op + 1;
            out[op] = (byte) ((b0 << 2) | (b1 >>> 4));
            if (op2 < oLen) {
                op = op2 + 1;
                out[op2] = (byte) o1;
            } else {
                op = op2;
            }
            if (op < oLen) {
                out[op] = (byte) o2;
                op++;
                ip2 = ip;
            } else {
                ip2 = ip;
            }
        }
        return out;
    }

    private IgawBase64() {
    }
}