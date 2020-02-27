package org.jboss.netty.util.internal.jzlib;

import android.support.v4.app.FrameMetricsAggregator;
import android.support.v4.internal.view.SupportMenu;

final class InfCodes {
    private static final int BADCODE = 9;
    private static final int COPY = 5;
    private static final int DIST = 3;
    private static final int DISTEXT = 4;
    private static final int END = 8;
    private static final int LEN = 1;
    private static final int LENEXT = 2;
    private static final int LIT = 6;
    private static final int START = 0;
    private static final int WASH = 7;
    private static final int[] inflate_mask = {0, 1, 3, 7, 15, 31, 63, 127, 255, FrameMetricsAggregator.EVERY_DURATION, 1023, 2047, 4095, 8191, 16383, 32767, SupportMenu.USER_MASK};
    private byte dbits;
    private int dist;
    private int[] dtree;
    private int dtree_index;
    private int get;
    private byte lbits;
    private int len;
    private int lit;
    private int[] ltree;
    private int ltree_index;
    private int mode;
    private int need;
    private int[] tree;
    private int tree_index;

    InfCodes() {
    }

    /* access modifiers changed from: 0000 */
    public void init(int bl, int bd, int[] tl, int tl_index, int[] td, int td_index) {
        this.mode = 0;
        this.lbits = (byte) bl;
        this.dbits = (byte) bd;
        this.ltree = tl;
        this.ltree_index = tl_index;
        this.dtree = td;
        this.dtree_index = td_index;
        this.tree = null;
    }

    /* access modifiers changed from: 0000 */
    /* JADX WARNING: Code restructure failed: missing block: B:132:0x0677, code lost:
        r12 = r13;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:168:?, code lost:
        return r24.inflate_flush(r25, r26);
     */
    /* JADX WARNING: Code restructure failed: missing block: B:169:?, code lost:
        return r24.inflate_flush(r25, -3);
     */
    /* JADX WARNING: Code restructure failed: missing block: B:171:?, code lost:
        return r24.inflate_flush(r25, r26);
     */
    /* JADX WARNING: Code restructure failed: missing block: B:46:0x02b2, code lost:
        r14 = r23.need;
        r19 = r18;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:47:0x02b8, code lost:
        if (r15 >= r14) goto L_0x0303;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:48:0x02ba, code lost:
        if (r17 == 0) goto L_0x02d1;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:49:0x02bc, code lost:
        r26 = 0;
        r17 = r17 - 1;
        r10 = r10 | ((r25.next_in[r19] & 255) << r15);
        r15 = r15 + 8;
        r19 = r19 + 1;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:50:0x02d1, code lost:
        r24.bitb = r10;
        r24.bitk = r15;
        r25.avail_in = r17;
        r25.total_in += (long) (r19 - r25.next_in_index);
        r25.next_in_index = r19;
        r24.write = r20;
        r18 = r19;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:51:0x0303, code lost:
        r22 = (r23.tree_index + (inflate_mask[r14] & r10)) * 3;
        r10 = r10 >> r23.tree[r22 + 1];
        r15 = r15 - r23.tree[r22 + 1];
        r11 = r23.tree[r22];
     */
    /* JADX WARNING: Code restructure failed: missing block: B:52:0x0329, code lost:
        if ((r11 & 16) == 0) goto L_0x0346;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:53:0x032b, code lost:
        r23.get = r11 & 15;
        r23.dist = r23.tree[r22 + 2];
        r23.mode = 4;
        r18 = r19;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:55:0x0348, code lost:
        if ((r11 & 64) != 0) goto L_0x0361;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:56:0x034a, code lost:
        r23.need = r11;
        r23.tree_index = (r22 / 3) + r23.tree[r22 + 2];
        r18 = r19;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:57:0x0361, code lost:
        r23.mode = 9;
        r25.msg = "invalid distance code";
        r24.bitb = r10;
        r24.bitk = r15;
        r25.avail_in = r17;
        r25.total_in += (long) (r19 - r25.next_in_index);
        r25.next_in_index = r19;
        r24.write = r20;
        r18 = r19;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:64:0x040a, code lost:
        r12 = r20 - r23.dist;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:65:0x0410, code lost:
        if (r12 >= 0) goto L_0x043d;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:66:0x0412, code lost:
        r12 = r12 + r24.end;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:67:0x0418, code lost:
        r21 = r20 + 1;
        r13 = r12 + 1;
        r24.window[r20] = r24.window[r12];
        r16 = r16 - 1;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:68:0x042e, code lost:
        if (r13 != r24.end) goto L_0x0677;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:69:0x0430, code lost:
        r12 = 0;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:70:0x0431, code lost:
        r23.len--;
        r20 = r21;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:72:0x0441, code lost:
        if (r23.len == 0) goto L_0x04ee;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:73:0x0443, code lost:
        if (r16 != 0) goto L_0x0418;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:75:0x044b, code lost:
        if (r20 != r24.end) goto L_0x0465;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:77:0x0451, code lost:
        if (r24.read == 0) goto L_0x0465;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:78:0x0453, code lost:
        r20 = 0;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:79:0x045b, code lost:
        if (0 >= r24.read) goto L_0x04d9;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:80:0x045d, code lost:
        r16 = (r24.read - 0) - 1;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:81:0x0465, code lost:
        if (r16 != 0) goto L_0x0418;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:82:0x0467, code lost:
        r24.write = r20;
        r26 = r24.inflate_flush(r25, r26);
        r20 = r24.write;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:83:0x047d, code lost:
        if (r20 >= r24.read) goto L_0x04e0;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:84:0x047f, code lost:
        r16 = (r24.read - r20) - 1;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:86:0x048d, code lost:
        if (r20 != r24.end) goto L_0x04a7;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:88:0x0493, code lost:
        if (r24.read == 0) goto L_0x04a7;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:89:0x0495, code lost:
        r20 = 0;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:90:0x049d, code lost:
        if (0 >= r24.read) goto L_0x04e7;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:91:0x049f, code lost:
        r16 = (r24.read - 0) - 1;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:92:0x04a7, code lost:
        if (r16 != 0) goto L_0x0418;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:93:0x04a9, code lost:
        r24.bitb = r10;
        r24.bitk = r15;
        r25.avail_in = r17;
        r25.total_in += (long) (r18 - r25.next_in_index);
        r25.next_in_index = r18;
        r24.write = r20;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:94:0x04d9, code lost:
        r16 = r24.end - 0;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:95:0x04e0, code lost:
        r16 = r24.end - r20;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:96:0x04e7, code lost:
        r16 = r24.end - 0;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:97:0x04ee, code lost:
        r23.mode = 0;
     */
    public int proc(InfBlocks s, ZStream z, int r) {
        int p = z.next_in_index;
        int n = z.avail_in;
        int b = s.bitb;
        int k = s.bitk;
        int q = s.write;
        int m = q < s.read ? (s.read - q) - 1 : s.end - q;
        while (true) {
            switch (this.mode) {
                case 0:
                    if (m >= 258 && n >= 10) {
                        s.bitb = b;
                        s.bitk = k;
                        z.avail_in = n;
                        z.total_in += (long) (p - z.next_in_index);
                        z.next_in_index = p;
                        s.write = q;
                        r = inflate_fast(this.lbits, this.dbits, this.ltree, this.ltree_index, this.dtree, this.dtree_index, s, z);
                        p = z.next_in_index;
                        n = z.avail_in;
                        b = s.bitb;
                        k = s.bitk;
                        q = s.write;
                        m = q < s.read ? (s.read - q) - 1 : s.end - q;
                        if (r != 0) {
                            this.mode = r == 1 ? 7 : 9;
                            break;
                        }
                    }
                    this.need = this.lbits;
                    this.tree = this.ltree;
                    this.tree_index = this.ltree_index;
                    this.mode = 1;
                case 1:
                    int j = this.need;
                    int p2 = p;
                    while (k < j) {
                        if (n != 0) {
                            r = 0;
                            n--;
                            b |= (z.next_in[p2] & 255) << k;
                            k += 8;
                            p2++;
                        } else {
                            s.bitb = b;
                            s.bitk = k;
                            z.avail_in = n;
                            z.total_in += (long) (p2 - z.next_in_index);
                            z.next_in_index = p2;
                            s.write = q;
                            int i = p2;
                            return s.inflate_flush(z, r);
                        }
                    }
                    int tindex = (this.tree_index + (inflate_mask[j] & b)) * 3;
                    b >>>= this.tree[tindex + 1];
                    k -= this.tree[tindex + 1];
                    int e = this.tree[tindex];
                    if (e == 0) {
                        this.lit = this.tree[tindex + 2];
                        this.mode = 6;
                        p = p2;
                        break;
                    } else if ((e & 16) != 0) {
                        this.get = e & 15;
                        this.len = this.tree[tindex + 2];
                        this.mode = 2;
                        p = p2;
                        break;
                    } else if ((e & 64) == 0) {
                        this.need = e;
                        this.tree_index = (tindex / 3) + this.tree[tindex + 2];
                        p = p2;
                        break;
                    } else if ((e & 32) != 0) {
                        this.mode = 7;
                        p = p2;
                        break;
                    } else {
                        this.mode = 9;
                        z.msg = "invalid literal/length code";
                        s.bitb = b;
                        s.bitk = k;
                        z.avail_in = n;
                        z.total_in += (long) (p2 - z.next_in_index);
                        z.next_in_index = p2;
                        s.write = q;
                        int i2 = p2;
                        return s.inflate_flush(z, -3);
                    }
                case 2:
                    int j2 = this.get;
                    int p3 = p;
                    while (k < j2) {
                        if (n != 0) {
                            r = 0;
                            n--;
                            b |= (z.next_in[p3] & 255) << k;
                            k += 8;
                            p3++;
                        } else {
                            s.bitb = b;
                            s.bitk = k;
                            z.avail_in = n;
                            z.total_in += (long) (p3 - z.next_in_index);
                            z.next_in_index = p3;
                            s.write = q;
                            int i3 = p3;
                            return s.inflate_flush(z, r);
                        }
                    }
                    this.len += inflate_mask[j2] & b;
                    b >>= j2;
                    k -= j2;
                    this.need = this.dbits;
                    this.tree = this.dtree;
                    this.tree_index = this.dtree_index;
                    this.mode = 3;
                    p = p3;
                    break;
                case 3:
                    break;
                case 4:
                    int j3 = this.get;
                    int p4 = p;
                    while (k < j3) {
                        if (n != 0) {
                            r = 0;
                            n--;
                            b |= (z.next_in[p4] & 255) << k;
                            k += 8;
                            p4++;
                        } else {
                            s.bitb = b;
                            s.bitk = k;
                            z.avail_in = n;
                            z.total_in += (long) (p4 - z.next_in_index);
                            z.next_in_index = p4;
                            s.write = q;
                            int i4 = p4;
                            return s.inflate_flush(z, r);
                        }
                    }
                    this.dist += inflate_mask[j3] & b;
                    b >>= j3;
                    k -= j3;
                    this.mode = 5;
                    p = p4;
                    break;
                case 5:
                    break;
                case 6:
                    if (m == 0) {
                        if (q == s.end && s.read != 0) {
                            q = 0;
                            m = 0 < s.read ? (s.read - 0) - 1 : s.end - 0;
                        }
                        if (m == 0) {
                            s.write = q;
                            int r2 = s.inflate_flush(z, r);
                            int q2 = s.write;
                            int m2 = q2 < s.read ? (s.read - q2) - 1 : s.end - q2;
                            if (q2 == s.end && s.read != 0) {
                                q2 = 0;
                                m2 = 0 < s.read ? (s.read - 0) - 1 : s.end - 0;
                            }
                            if (m == 0) {
                                s.bitb = b;
                                s.bitk = k;
                                z.avail_in = n;
                                z.total_in += (long) (p - z.next_in_index);
                                z.next_in_index = p;
                                s.write = q;
                                return s.inflate_flush(z, r2);
                            }
                        }
                    }
                    r = 0;
                    s.window[q] = (byte) this.lit;
                    m--;
                    this.mode = 0;
                    q++;
                    break;
                case 7:
                    if (k > 7) {
                        k -= 8;
                        n++;
                        p--;
                    }
                    s.write = q;
                    int r3 = s.inflate_flush(z, r);
                    q = s.write;
                    if (s.read == s.write) {
                        this.mode = 8;
                        break;
                    } else {
                        s.bitb = b;
                        s.bitk = k;
                        z.avail_in = n;
                        z.total_in += (long) (p - z.next_in_index);
                        z.next_in_index = p;
                        s.write = q;
                        return s.inflate_flush(z, r3);
                    }
                case 8:
                    break;
                case 9:
                    s.bitb = b;
                    s.bitk = k;
                    z.avail_in = n;
                    z.total_in += (long) (p - z.next_in_index);
                    z.next_in_index = p;
                    s.write = q;
                    return s.inflate_flush(z, -3);
                default:
                    s.bitb = b;
                    s.bitk = k;
                    z.avail_in = n;
                    z.total_in += (long) (p - z.next_in_index);
                    z.next_in_index = p;
                    s.write = q;
                    return s.inflate_flush(z, -2);
            }
        }
        s.bitb = b;
        s.bitk = k;
        z.avail_in = n;
        z.total_in += (long) (p - z.next_in_index);
        z.next_in_index = p;
        s.write = q;
        return s.inflate_flush(z, 1);
    }

    static int inflate_fast(int bl, int bd, int[] tl, int tl_index, int[] td, int td_index, InfBlocks s, ZStream z) {
        int m;
        int m2;
        int r;
        int q;
        int r2;
        int q2;
        int q3;
        int p = z.next_in_index;
        int n = z.avail_in;
        int b = s.bitb;
        int k = s.bitk;
        int q4 = s.write;
        if (q4 < s.read) {
            m = (s.read - q4) - 1;
        } else {
            m = s.end - q4;
        }
        int ml = inflate_mask[bl];
        int md = inflate_mask[bd];
        int q5 = q4;
        while (true) {
            int p2 = p;
            if (k < 20) {
                n--;
                p = p2 + 1;
                b |= (z.next_in[p2] & 255) << k;
                k += 8;
            } else {
                int t = b & ml;
                int[] tp = tl;
                int tp_index = tl_index;
                int tp_index_t_3 = (tp_index + t) * 3;
                int e = tp[tp_index_t_3];
                if (e == 0) {
                    b >>= tp[tp_index_t_3 + 1];
                    k -= tp[tp_index_t_3 + 1];
                    q2 = q5 + 1;
                    s.window[q5] = (byte) tp[tp_index_t_3 + 2];
                    m2--;
                    p = p2;
                } else {
                    while (true) {
                        b >>= tp[tp_index_t_3 + 1];
                        k -= tp[tp_index_t_3 + 1];
                        if ((e & 16) != 0) {
                            int e2 = e & 15;
                            int c = tp[tp_index_t_3 + 2] + (inflate_mask[e2] & b);
                            int b2 = b >> e2;
                            int k2 = k - e2;
                            while (k2 < 15) {
                                n--;
                                b2 |= (z.next_in[p2] & 255) << k2;
                                k2 += 8;
                                p2++;
                            }
                            int t2 = b2 & md;
                            int[] tp2 = td;
                            int tp_index2 = td_index;
                            int tp_index_t_32 = (tp_index2 + t2) * 3;
                            int e3 = tp2[tp_index_t_32];
                            while (true) {
                                b2 >>= tp2[tp_index_t_32 + 1];
                                k2 -= tp2[tp_index_t_32 + 1];
                                if ((e3 & 16) != 0) {
                                    int e4 = e3 & 15;
                                    while (k2 < e4) {
                                        n--;
                                        b2 |= (z.next_in[p2] & 255) << k2;
                                        k2 += 8;
                                        p2++;
                                    }
                                    int d = tp2[tp_index_t_32 + 2] + (inflate_mask[e4] & b2);
                                    b = b2 >> e4;
                                    k = k2 - e4;
                                    m2 -= c;
                                    if (q5 >= d) {
                                        int r3 = q5 - d;
                                        if (q5 - r3 <= 0 || 2 <= q5 - r3) {
                                            System.arraycopy(s.window, r3, s.window, q5, 2);
                                            q = q5 + 2;
                                            r = r3 + 2;
                                            c -= 2;
                                        } else {
                                            int q6 = q5 + 1;
                                            int r4 = r3 + 1;
                                            s.window[q5] = s.window[r3];
                                            r = r4 + 1;
                                            s.window[q6] = s.window[r4];
                                            c -= 2;
                                            q = q6 + 1;
                                        }
                                    } else {
                                        r = q5 - d;
                                        do {
                                            r += s.end;
                                        } while (r < 0);
                                        int e5 = s.end - r;
                                        if (c > e5) {
                                            c -= e5;
                                            if (q5 - r <= 0 || e5 <= q5 - r) {
                                                System.arraycopy(s.window, r, s.window, q5, e5);
                                                q = q5 + e5;
                                                int r5 = r + e5;
                                            } else {
                                                while (true) {
                                                    int q7 = q5;
                                                    q5 = q7 + 1;
                                                    r2 = r + 1;
                                                    s.window[q7] = s.window[r];
                                                    e5--;
                                                    if (e5 == 0) {
                                                        break;
                                                    }
                                                    r = r2;
                                                }
                                                int i = r2;
                                                q = q5;
                                            }
                                            r = 0;
                                        } else {
                                            q = q5;
                                        }
                                    }
                                    if (q - r <= 0 || c <= q - r) {
                                        System.arraycopy(s.window, r, s.window, q, c);
                                        q2 = q + c;
                                        int r6 = r + c;
                                        p = p2;
                                    } else {
                                        while (true) {
                                            q3 = q + 1;
                                            int r7 = r + 1;
                                            s.window[q] = s.window[r];
                                            c--;
                                            if (c == 0) {
                                                break;
                                            }
                                            r = r7;
                                            q = q3;
                                        }
                                        q2 = q3;
                                        p = p2;
                                    }
                                } else if (e3 == false || !true) {
                                    t2 = t2 + tp2[tp_index_t_32 + 2] + (inflate_mask[e3] & b2);
                                    tp_index_t_32 = (tp_index2 + t2) * 3;
                                    e3 = tp2[tp_index_t_32];
                                } else {
                                    z.msg = "invalid distance code";
                                    int c2 = z.avail_in - n;
                                    if ((k2 >> 3) < c2) {
                                        c2 = k2 >> 3;
                                    }
                                    int p3 = p2 - c2;
                                    s.bitb = b2;
                                    s.bitk = k2 - (c2 << 3);
                                    z.avail_in = n + c2;
                                    z.total_in += (long) (p3 - z.next_in_index);
                                    z.next_in_index = p3;
                                    s.write = q5;
                                    int i2 = q5;
                                    return -3;
                                }
                            }
                        } else if ((e & 64) == 0) {
                            t = t + tp[tp_index_t_3 + 2] + (inflate_mask[e] & b);
                            tp_index_t_3 = (tp_index + t) * 3;
                            e = tp[tp_index_t_3];
                            if (e == 0) {
                                b >>= tp[tp_index_t_3 + 1];
                                k -= tp[tp_index_t_3 + 1];
                                q2 = q5 + 1;
                                s.window[q5] = (byte) tp[tp_index_t_3 + 2];
                                m2--;
                                p = p2;
                                break;
                            }
                        } else if ((e & 32) != 0) {
                            int c3 = z.avail_in - n;
                            if ((k >> 3) < c3) {
                                c3 = k >> 3;
                            }
                            int p4 = p2 - c3;
                            s.bitb = b;
                            s.bitk = k - (c3 << 3);
                            z.avail_in = n + c3;
                            z.total_in += (long) (p4 - z.next_in_index);
                            z.next_in_index = p4;
                            s.write = q5;
                            int i3 = q5;
                            return 1;
                        } else {
                            z.msg = "invalid literal/length code";
                            int c4 = z.avail_in - n;
                            if ((k >> 3) < c4) {
                                c4 = k >> 3;
                            }
                            int p5 = p2 - c4;
                            s.bitb = b;
                            s.bitk = k - (c4 << 3);
                            z.avail_in = n + c4;
                            z.total_in += (long) (p5 - z.next_in_index);
                            z.next_in_index = p5;
                            s.write = q5;
                            int i4 = q5;
                            return -3;
                        }
                    }
                }
                if (m2 < 258 || n < 10) {
                    int c5 = z.avail_in - n;
                } else {
                    q5 = q2;
                }
            }
        }
        int c52 = z.avail_in - n;
        if ((k >> 3) < c52) {
            c52 = k >> 3;
        }
        int p6 = p - c52;
        s.bitb = b;
        s.bitk = k - (c52 << 3);
        z.avail_in = n + c52;
        z.total_in += (long) (p6 - z.next_in_index);
        z.next_in_index = p6;
        s.write = q2;
        return 0;
    }
}