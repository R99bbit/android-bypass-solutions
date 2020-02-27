package org.jboss.netty.util.internal.jzlib;

final class Adler32 {
    private static final int BASE = 65521;
    private static final int NMAX = 5552;

    static long adler32(long adler, byte[] buf, int index, int len) {
        if (buf == null) {
            return 1;
        }
        long s1 = adler & 65535;
        long s2 = (adler >> 16) & 65535;
        while (len > 0) {
            int k = len < NMAX ? len : NMAX;
            len -= k;
            int index2 = index;
            while (k >= 16) {
                int index3 = index2 + 1;
                long s12 = s1 + ((long) (buf[index2] & 255));
                long s22 = s2 + s12;
                int index4 = index3 + 1;
                long s13 = s12 + ((long) (buf[index3] & 255));
                long s23 = s22 + s13;
                int index5 = index4 + 1;
                long s14 = s13 + ((long) (buf[index4] & 255));
                long s24 = s23 + s14;
                int index6 = index5 + 1;
                long s15 = s14 + ((long) (buf[index5] & 255));
                long s25 = s24 + s15;
                int index7 = index6 + 1;
                long s16 = s15 + ((long) (buf[index6] & 255));
                long s26 = s25 + s16;
                int index8 = index7 + 1;
                long s17 = s16 + ((long) (buf[index7] & 255));
                long s27 = s26 + s17;
                int index9 = index8 + 1;
                long s18 = s17 + ((long) (buf[index8] & 255));
                long s28 = s27 + s18;
                int index10 = index9 + 1;
                long s19 = s18 + ((long) (buf[index9] & 255));
                long s29 = s28 + s19;
                int index11 = index10 + 1;
                long s110 = s19 + ((long) (buf[index10] & 255));
                long s210 = s29 + s110;
                int index12 = index11 + 1;
                long s111 = s110 + ((long) (buf[index11] & 255));
                long s211 = s210 + s111;
                int index13 = index12 + 1;
                long s112 = s111 + ((long) (buf[index12] & 255));
                long s212 = s211 + s112;
                int index14 = index13 + 1;
                long s113 = s112 + ((long) (buf[index13] & 255));
                long s213 = s212 + s113;
                int index15 = index14 + 1;
                long s114 = s113 + ((long) (buf[index14] & 255));
                long s214 = s213 + s114;
                int index16 = index15 + 1;
                long s115 = s114 + ((long) (buf[index15] & 255));
                long s215 = s214 + s115;
                int index17 = index16 + 1;
                long s116 = s115 + ((long) (buf[index16] & 255));
                long s216 = s215 + s116;
                index2 = index17 + 1;
                s1 = s116 + ((long) (buf[index17] & 255));
                s2 = s216 + s1;
                k -= 16;
            }
            if (k != 0) {
                do {
                    int index18 = index2;
                    index2 = index18 + 1;
                    s1 += (long) (buf[index18] & 255);
                    s2 += s1;
                    k--;
                } while (k != 0);
            }
            index = index2;
            s1 %= 65521;
            s2 %= 65521;
        }
        return (s2 << 16) | s1;
    }

    private Adler32() {
    }
}