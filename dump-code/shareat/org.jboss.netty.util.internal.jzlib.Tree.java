package org.jboss.netty.util.internal.jzlib;

import org.jboss.netty.handler.codec.http.HttpConstants;

final class Tree {
    static final byte[] _dist_code = {0, 1, 2, 3, 4, 4, 5, 5, 6, 6, 6, 6, 7, 7, 7, 7, 8, 8, 8, 8, 8, 8, 8, 8, 9, 9, 9, 9, 9, 9, 9, 9, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, HttpConstants.CR, HttpConstants.CR, HttpConstants.CR, HttpConstants.CR, HttpConstants.CR, HttpConstants.CR, HttpConstants.CR, HttpConstants.CR, HttpConstants.CR, HttpConstants.CR, HttpConstants.CR, HttpConstants.CR, HttpConstants.CR, HttpConstants.CR, HttpConstants.CR, HttpConstants.CR, HttpConstants.CR, HttpConstants.CR, HttpConstants.CR, HttpConstants.CR, HttpConstants.CR, HttpConstants.CR, HttpConstants.CR, HttpConstants.CR, HttpConstants.CR, HttpConstants.CR, HttpConstants.CR, HttpConstants.CR, HttpConstants.CR, HttpConstants.CR, HttpConstants.CR, HttpConstants.CR, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 0, 0, 16, 17, 18, 18, 19, 19, 20, 20, 20, 20, 21, 21, 21, 21, 22, 22, 22, 22, 22, 22, 22, 22, 23, 23, 23, 23, 23, 23, 23, 23, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29};
    static final byte[] _length_code = {0, 1, 2, 3, 4, 5, 6, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 12, 12, HttpConstants.CR, HttpConstants.CR, HttpConstants.CR, HttpConstants.CR, 14, 14, 14, 14, 15, 15, 15, 15, 16, 16, 16, 16, 16, 16, 16, 16, 17, 17, 17, 17, 17, 17, 17, 17, 18, 18, 18, 18, 18, 18, 18, 18, 19, 19, 19, 19, 19, 19, 19, 19, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 22, 22, 22, 22, 22, 22, 22, 22, 22, 22, 22, 22, 22, 22, 22, 22, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 28};
    static final int[] base_dist = {0, 1, 2, 3, 4, 6, 8, 12, 16, 24, 32, 48, 64, 96, 128, 192, 256, 384, 512, 768, 1024, 1536, 2048, 3072, 4096, 6144, 8192, 12288, 16384, 24576};
    static final int[] base_length = {0, 1, 2, 3, 4, 5, 6, 7, 8, 10, 12, 14, 16, 20, 24, 28, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 0};
    static final byte[] bl_order = {16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, HttpConstants.CR, 2, 14, 1, 15};
    static final int[] extra_blbits = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 3, 7};
    static final int[] extra_dbits = {0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13};
    static final int[] extra_lbits = {0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0};
    short[] dyn_tree;
    int max_code;
    StaticTree stat_desc;

    Tree() {
    }

    static int d_code(int dist) {
        return dist < 256 ? _dist_code[dist] : _dist_code[(dist >>> 7) + 256];
    }

    /* JADX WARNING: type inference failed for: r14v16, types: [short[]] */
    /* JADX WARNING: type inference failed for: r9v0, types: [short] */
    /* JADX WARNING: type inference failed for: r9v1, types: [int] */
    /* JADX WARNING: type inference failed for: r9v2 */
    /* JADX WARNING: type inference failed for: r9v3, types: [int] */
    /* JADX WARNING: type inference failed for: r9v5 */
    /* JADX WARNING: type inference failed for: r9v6 */
    /* JADX WARNING: type inference failed for: r9v7 */
    /* JADX WARNING: type inference failed for: r9v8 */
    /* JADX WARNING: Multi-variable type inference failed. Error: jadx.core.utils.exceptions.JadxRuntimeException: No candidate types for var: r9v2
      assigns: []
      uses: []
      mth insns count: 165
    	at jadx.core.dex.visitors.typeinference.TypeSearch.fillTypeCandidates(TypeSearch.java:237)
    	at java.base/java.util.ArrayList.forEach(ArrayList.java:1540)
    	at jadx.core.dex.visitors.typeinference.TypeSearch.run(TypeSearch.java:53)
    	at jadx.core.dex.visitors.typeinference.TypeInferenceVisitor.runMultiVariableSearch(TypeInferenceVisitor.java:104)
    	at jadx.core.dex.visitors.typeinference.TypeInferenceVisitor.visit(TypeInferenceVisitor.java:97)
    	at jadx.core.dex.visitors.DepthTraversal.visit(DepthTraversal.java:27)
    	at jadx.core.dex.visitors.DepthTraversal.lambda$visit$1(DepthTraversal.java:14)
    	at java.base/java.util.ArrayList.forEach(ArrayList.java:1540)
    	at jadx.core.dex.visitors.DepthTraversal.visit(DepthTraversal.java:14)
    	at jadx.core.ProcessClass.process(ProcessClass.java:30)
    	at jadx.core.ProcessClass.lambda$processDependencies$0(ProcessClass.java:49)
    	at java.base/java.util.ArrayList.forEach(ArrayList.java:1540)
    	at jadx.core.ProcessClass.processDependencies(ProcessClass.java:49)
    	at jadx.core.ProcessClass.process(ProcessClass.java:35)
    	at jadx.api.JadxDecompiler.processClass(JadxDecompiler.java:311)
    	at jadx.api.JavaClass.decompile(JavaClass.java:62)
     */
    /* JADX WARNING: Unknown variable types count: 5 */
    private void gen_bitlen(Deflate s) {
        ? r9;
        short[] tree = this.dyn_tree;
        short[] stree = this.stat_desc.static_tree;
        int[] extra = this.stat_desc.extra_bits;
        int base = this.stat_desc.extra_base;
        int max_length = this.stat_desc.max_length;
        int overflow = 0;
        for (int bits = 0; bits <= 15; bits++) {
            s.bl_count[bits] = 0;
        }
        tree[(s.heap[s.heap_max] * 2) + 1] = 0;
        int h = s.heap_max + 1;
        while (h < 573) {
            int n = s.heap[h];
            int bits2 = tree[(tree[(n * 2) + 1] * 2) + 1] + 1;
            if (bits2 > max_length) {
                bits2 = max_length;
                overflow++;
            }
            tree[(n * 2) + 1] = (short) bits2;
            if (n <= this.max_code) {
                short[] sArr = s.bl_count;
                sArr[bits2] = (short) (sArr[bits2] + 1);
                int xbits = 0;
                if (n >= base) {
                    xbits = extra[n - base];
                }
                short f = tree[n * 2];
                s.opt_len += (bits2 + xbits) * f;
                if (stree != null) {
                    s.static_len += (stree[(n * 2) + 1] + xbits) * f;
                }
            }
            h++;
        }
        if (overflow != 0) {
            do {
                int bits3 = max_length - 1;
                while (s.bl_count[bits3] == 0) {
                    bits3--;
                }
                short[] sArr2 = s.bl_count;
                sArr2[bits3] = (short) (sArr2[bits3] - 1);
                short[] sArr3 = s.bl_count;
                int i = bits3 + 1;
                sArr3[i] = (short) (sArr3[i] + 2);
                short[] sArr4 = s.bl_count;
                sArr4[max_length] = (short) (sArr4[max_length] - 1);
                overflow -= 2;
            } while (overflow > 0);
            for (int bits4 = max_length; bits4 != 0; bits4--) {
                ? r92 = s.bl_count[bits4];
                while (r92 != 0) {
                    h--;
                    int m = s.heap[h];
                    if (m > this.max_code) {
                        r9 = r92;
                    } else {
                        if (tree[(m * 2) + 1] != bits4) {
                            s.opt_len = (int) (((long) s.opt_len) + ((((long) bits4) - ((long) tree[(m * 2) + 1])) * ((long) tree[m * 2])));
                            tree[(m * 2) + 1] = (short) bits4;
                        }
                        r9 = r92 - 1;
                    }
                    r92 = r9;
                }
            }
        }
    }

    /* access modifiers changed from: 0000 */
    public void build_tree(Deflate s) {
        int node;
        short[] tree = this.dyn_tree;
        short[] stree = this.stat_desc.static_tree;
        int elems = this.stat_desc.elems;
        int max_code2 = -1;
        s.heap_len = 0;
        s.heap_max = 573;
        for (int n = 0; n < elems; n++) {
            if (tree[n * 2] != 0) {
                int[] iArr = s.heap;
                int i = s.heap_len + 1;
                s.heap_len = i;
                max_code2 = n;
                iArr[i] = n;
                s.depth[n] = 0;
            } else {
                tree[(n * 2) + 1] = 0;
            }
        }
        while (s.heap_len < 2) {
            int[] iArr2 = s.heap;
            int i2 = s.heap_len + 1;
            s.heap_len = i2;
            if (max_code2 < 2) {
                max_code2++;
                node = max_code2;
            } else {
                node = 0;
            }
            iArr2[i2] = node;
            tree[node * 2] = 1;
            s.depth[node] = 0;
            s.opt_len--;
            if (stree != null) {
                s.static_len -= stree[(node * 2) + 1];
            }
        }
        this.max_code = max_code2;
        for (int n2 = s.heap_len / 2; n2 >= 1; n2--) {
            s.pqdownheap(tree, n2);
        }
        int node2 = elems;
        while (true) {
            int n3 = s.heap[1];
            int[] iArr3 = s.heap;
            int[] iArr4 = s.heap;
            int i3 = s.heap_len;
            s.heap_len = i3 - 1;
            iArr3[1] = iArr4[i3];
            s.pqdownheap(tree, 1);
            int m = s.heap[1];
            int[] iArr5 = s.heap;
            int i4 = s.heap_max - 1;
            s.heap_max = i4;
            iArr5[i4] = n3;
            int[] iArr6 = s.heap;
            int i5 = s.heap_max - 1;
            s.heap_max = i5;
            iArr6[i5] = m;
            tree[node2 * 2] = (short) (tree[n3 * 2] + tree[m * 2]);
            s.depth[node2] = (byte) (Math.max(s.depth[n3], s.depth[m]) + 1);
            short s2 = (short) node2;
            tree[(m * 2) + 1] = s2;
            tree[(n3 * 2) + 1] = s2;
            int node3 = node2 + 1;
            s.heap[1] = node2;
            s.pqdownheap(tree, 1);
            if (s.heap_len < 2) {
                int[] iArr7 = s.heap;
                int i6 = s.heap_max - 1;
                s.heap_max = i6;
                iArr7[i6] = s.heap[1];
                gen_bitlen(s);
                gen_codes(tree, max_code2, s.bl_count);
                return;
            }
            node2 = node3;
        }
    }

    private static void gen_codes(short[] tree, int max_code2, short[] bl_count) {
        short[] next_code = new short[16];
        short code = 0;
        for (int bits = 1; bits <= 15; bits++) {
            code = (short) ((bl_count[bits - 1] + code) << 1);
            next_code[bits] = code;
        }
        for (int n = 0; n <= max_code2; n++) {
            short len = tree[(n * 2) + 1];
            if (len != 0) {
                short s = next_code[len];
                next_code[len] = (short) (s + 1);
                tree[n * 2] = (short) bi_reverse(s, len);
            }
        }
    }

    private static int bi_reverse(int code, int len) {
        int res = 0;
        do {
            code >>>= 1;
            res = (res | (code & 1)) << 1;
            len--;
        } while (len > 0);
        return res >>> 1;
    }
}