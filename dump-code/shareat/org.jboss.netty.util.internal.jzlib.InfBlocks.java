package org.jboss.netty.util.internal.jzlib;

import android.support.v4.app.FrameMetricsAggregator;
import android.support.v4.internal.view.SupportMenu;

final class InfBlocks {
    private static final int BAD = 9;
    private static final int BTREE = 4;
    private static final int CODES = 6;
    private static final int DONE = 8;
    private static final int DRY = 7;
    private static final int DTREE = 5;
    private static final int LENS = 1;
    private static final int STORED = 2;
    private static final int TABLE = 3;
    private static final int TYPE = 0;
    private static final int[] border = {16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15};
    private static final int[] inflate_mask = {0, 1, 3, 7, 15, 31, 63, 127, 255, FrameMetricsAggregator.EVERY_DURATION, 1023, 2047, 4095, 8191, 16383, 32767, SupportMenu.USER_MASK};
    private final int[] bb = new int[1];
    int bitb;
    int bitk;
    private int[] blens;
    private long check;
    private final Object checkfn;
    private final InfCodes codes = new InfCodes();
    final int end;
    private int[] hufts = new int[4320];
    private int index;
    private final InfTree inftree = new InfTree();
    private int last;
    private int left;
    private int mode;
    int read;
    private int table;
    private final int[] tb = new int[1];
    byte[] window;
    int write;

    InfBlocks(ZStream z, Object checkfn2, int w) {
        this.window = new byte[w];
        this.end = w;
        this.checkfn = checkfn2;
        this.mode = 0;
        reset(z, null);
    }

    /* access modifiers changed from: 0000 */
    public void reset(ZStream z, long[] c) {
        if (c != null) {
            c[0] = this.check;
        }
        this.mode = 0;
        this.bitk = 0;
        this.bitb = 0;
        this.write = 0;
        this.read = 0;
        if (this.checkfn != null) {
            long adler32 = Adler32.adler32(0, null, 0, 0);
            this.check = adler32;
            z.adler = adler32;
        }
    }

    /* access modifiers changed from: 0000 */
    /* JADX WARNING: Code restructure failed: missing block: B:100:0x048a, code lost:
        r31.bitb = r19;
        r31.bitk = r24;
        r32.avail_in = r26;
        r32.total_in += (long) (r28 - r32.next_in_index);
        r32.next_in_index = r28;
        r31.write = r29;
        r27 = r28;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:101:0x04c0, code lost:
        r4 = r31.blens;
        r5 = border;
        r6 = r31.index;
        r31.index = r6 + 1;
        r4[r5[r6]] = r19 & 7;
        r19 = r19 >>> 3;
        r24 = r24 - 3;
        r27 = r28;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:103:0x04e4, code lost:
        if (r31.index >= 19) goto L_0x04fc;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:104:0x04e6, code lost:
        r4 = r31.blens;
        r5 = border;
        r6 = r31.index;
        r31.index = r6 + 1;
        r4[r5[r6]] = 0;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:105:0x04fc, code lost:
        r31.bb[0] = 7;
        r30 = r31.inftree.inflate_trees_bits(r31.blens, r31.bb, r31.tb, r31.hufts, r32);
     */
    /* JADX WARNING: Code restructure failed: missing block: B:106:0x051e, code lost:
        if (r30 == 0) goto L_0x0566;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:107:0x0520, code lost:
        r33 = r30;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:108:0x0525, code lost:
        if (r33 != -3) goto L_0x0532;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:109:0x0527, code lost:
        r31.blens = null;
        r31.mode = 9;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:110:0x0532, code lost:
        r31.bitb = r19;
        r31.bitk = r24;
        r32.avail_in = r26;
        r32.total_in += (long) (r27 - r32.next_in_index);
        r32.next_in_index = r27;
        r31.write = r29;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:111:0x0566, code lost:
        r31.index = 0;
        r31.mode = 5;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:112:0x0570, code lost:
        r30 = r31.table;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:113:0x0583, code lost:
        if (r31.index < (((r30 & 31) + 258) + ((r30 >> 5) & 31))) goto L_0x060c;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:114:0x0585, code lost:
        r31.tb[0] = -1;
        r10 = new int[1];
        r11 = new int[1];
        r8 = new int[]{9};
        r9 = new int[]{6};
        r30 = r31.table;
        r30 = r31.inftree.inflate_trees_dynamic((r30 & 31) + android.support.v4.view.InputDeviceCompat.SOURCE_KEYBOARD, ((r30 >> 5) & 31) + 1, r31.blens, r8, r9, r10, r11, r31.hufts, r32);
     */
    /* JADX WARNING: Code restructure failed: missing block: B:115:0x05c4, code lost:
        if (r30 == 0) goto L_0x07d2;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:117:0x05c9, code lost:
        if (r30 != -3) goto L_0x05d6;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:118:0x05cb, code lost:
        r31.blens = null;
        r31.mode = 9;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:119:0x05d6, code lost:
        r31.bitb = r19;
        r31.bitk = r24;
        r32.avail_in = r26;
        r32.total_in += (long) (r27 - r32.next_in_index);
        r32.next_in_index = r27;
        r31.write = r29;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:11:0x008f, code lost:
        r31.bitb = r19;
        r31.bitk = r24;
        r32.avail_in = r26;
        r32.total_in += (long) (r28 - r32.next_in_index);
        r32.next_in_index = r28;
        r31.write = r29;
        r27 = r28;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:120:0x060c, code lost:
        r30 = r31.bb[0];
     */
    /* JADX WARNING: Code restructure failed: missing block: B:121:0x0615, code lost:
        r28 = r27;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:122:0x0619, code lost:
        if (r24 >= r30) goto L_0x066a;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:123:0x061b, code lost:
        if (r26 == 0) goto L_0x0634;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:124:0x061d, code lost:
        r33 = 0;
        r26 = r26 - 1;
        r27 = r28 + 1;
        r19 = r19 | ((r32.next_in[r28] & 255) << r24);
        r24 = r24 + 8;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:125:0x0634, code lost:
        r31.bitb = r19;
        r31.bitk = r24;
        r32.avail_in = r26;
        r32.total_in += (long) (r28 - r32.next_in_index);
        r32.next_in_index = r28;
        r31.write = r29;
        r27 = r28;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:127:0x0672, code lost:
        if (r31.tb[0] != -1) goto L_0x0674;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:128:0x0674, code lost:
        r30 = r31.hufts[((r31.tb[0] + (inflate_mask[r30] & r19)) * 3) + 1];
        r20 = r31.hufts[((r31.tb[0] + (inflate_mask[r30] & r19)) * 3) + 2];
     */
    /* JADX WARNING: Code restructure failed: missing block: B:129:0x06a8, code lost:
        if (r20 >= 16) goto L_0x06c2;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:12:0x00c4, code lost:
        r30 = r19 & 7;
        r31.last = r30 & 1;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:130:0x06aa, code lost:
        r19 = r19 >>> r30;
        r24 = r24 - r30;
        r4 = r31.blens;
        r5 = r31.index;
        r31.index = r5 + 1;
        r4[r5] = r20;
        r27 = r28;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:132:0x06c6, code lost:
        if (r20 != 18) goto L_0x06f1;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:133:0x06c8, code lost:
        r21 = 7;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:135:0x06ce, code lost:
        if (r20 != 18) goto L_0x06f4;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:136:0x06d0, code lost:
        r23 = 11;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:138:0x06d6, code lost:
        if (r24 >= (r30 + r21)) goto L_0x072d;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:139:0x06d8, code lost:
        if (r26 == 0) goto L_0x06f7;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:13:0x00ce, code lost:
        switch((r30 >>> 1)) {
            case 0: goto L_0x00d5;
            case 1: goto L_0x00e5;
            case 2: goto L_0x0113;
            case 3: goto L_0x011d;
            default: goto L_0x00d1;
        };
     */
    /* JADX WARNING: Code restructure failed: missing block: B:140:0x06da, code lost:
        r33 = 0;
        r26 = r26 - 1;
        r19 = r19 | ((r32.next_in[r28] & 255) << r24);
        r24 = r24 + 8;
        r28 = r28 + 1;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:141:0x06f1, code lost:
        r21 = r20 - 14;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:142:0x06f4, code lost:
        r23 = 3;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:143:0x06f7, code lost:
        r31.bitb = r19;
        r31.bitk = r24;
        r32.avail_in = r26;
        r32.total_in += (long) (r28 - r32.next_in_index);
        r32.next_in_index = r28;
        r31.write = r29;
        r27 = r28;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:144:0x072d, code lost:
        r19 = r19 >>> r30;
        r23 = r23 + (inflate_mask[r21] & r19);
        r19 = r19 >>> r21;
        r24 = (r24 - r30) - r21;
        r21 = r31.index;
        r30 = r31.table;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:145:0x0754, code lost:
        if ((r21 + r23) > (((r30 & 31) + 258) + ((r30 >> 5) & 31))) goto L_0x0761;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:147:0x075a, code lost:
        if (r20 != 16) goto L_0x07ab;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:149:0x075f, code lost:
        if (r21 >= 1) goto L_0x07ab;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:14:0x00d1, code lost:
        r27 = r28;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:150:0x0761, code lost:
        r31.blens = null;
        r31.mode = 9;
        r32.msg = "invalid bit length repeat";
        r31.bitb = r19;
        r31.bitk = r24;
        r32.avail_in = r26;
        r32.total_in += (long) (r28 - r32.next_in_index);
        r32.next_in_index = r28;
        r31.write = r29;
        r27 = r28;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:152:0x07af, code lost:
        if (r20 != 16) goto L_0x07cf;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:153:0x07b1, code lost:
        r20 = r31.blens[r21 - 1];
     */
    /* JADX WARNING: Code restructure failed: missing block: B:154:0x07b9, code lost:
        r22 = r21 + 1;
        r31.blens[r21] = r20;
        r23 = r23 - 1;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:155:0x07c3, code lost:
        if (r23 != 0) goto L_0x0944;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:156:0x07c5, code lost:
        r31.index = r22;
        r27 = r28;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:157:0x07cf, code lost:
        r20 = 0;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:158:0x07d2, code lost:
        r31.codes.init(r8[0], r9[0], r31.hufts, r10[0], r31.hufts, r11[0]);
        r31.mode = 6;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:159:0x07f4, code lost:
        r31.bitb = r19;
        r31.bitk = r24;
        r32.avail_in = r26;
        r32.total_in += (long) (r27 - r32.next_in_index);
        r32.next_in_index = r27;
        r31.write = r29;
        r33 = r31.codes.proc(r31, r32, r33);
     */
    /* JADX WARNING: Code restructure failed: missing block: B:15:0x00d5, code lost:
        r24 = r24 - 3;
        r30 = r24 & 7;
        r19 = (r19 >>> 3) >>> r30;
        r24 = r24 - r30;
        r31.mode = 1;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:160:0x0833, code lost:
        if (r33 == 1) goto L_0x083b;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:162:0x083b, code lost:
        r33 = 0;
        r27 = r32.next_in_index;
        r26 = r32.avail_in;
        r19 = r31.bitb;
        r24 = r31.bitk;
        r29 = r31.write;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:163:0x0861, code lost:
        if (r29 >= r31.read) goto L_0x0878;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:164:0x0863, code lost:
        r25 = (r31.read - r29) - 1;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:166:0x086f, code lost:
        if (r31.last != 0) goto L_0x087f;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:167:0x0871, code lost:
        r31.mode = 0;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:168:0x0878, code lost:
        r25 = r31.end - r29;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:169:0x087f, code lost:
        r31.mode = 7;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:16:0x00e5, code lost:
        r8 = new int[1];
        r9 = new int[1];
        r10 = new int[1][];
        r11 = new int[1][];
        org.jboss.netty.util.internal.jzlib.InfTree.inflate_trees_fixed(r8, r9, r10, r11);
        r31.codes.init(r8[0], r9[0], r10[0], 0, r11[0], 0);
        r19 = r19 >>> 3;
        r24 = r24 - 3;
        r31.mode = 6;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:170:0x0884, code lost:
        r31.write = r29;
        r33 = inflate_flush(r32, r33);
        r29 = r31.write;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:171:0x089c, code lost:
        if (r31.read == r31.write) goto L_0x08d2;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:172:0x089e, code lost:
        r31.bitb = r19;
        r31.bitk = r24;
        r32.avail_in = r26;
        r32.total_in += (long) (r27 - r32.next_in_index);
        r32.next_in_index = r27;
        r31.write = r29;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:173:0x08d2, code lost:
        r31.mode = 8;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:174:0x08d8, code lost:
        r31.bitb = r19;
        r31.bitk = r24;
        r32.avail_in = r26;
        r32.total_in += (long) (r27 - r32.next_in_index);
        r32.next_in_index = r27;
        r31.write = r29;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:176:0x0944, code lost:
        r21 = r22;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:17:0x0113, code lost:
        r19 = r19 >>> 3;
        r24 = r24 - 3;
        r31.mode = 3;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:18:0x011d, code lost:
        r31.mode = 9;
        r32.msg = "invalid block type";
        r31.bitb = r19 >>> 3;
        r31.bitk = r24 - 3;
        r32.avail_in = r26;
        r32.total_in += (long) (r28 - r32.next_in_index);
        r32.next_in_index = r28;
        r31.write = r29;
        r27 = r28;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:20:0x016a, code lost:
        if (r24 >= 32) goto L_0x01bb;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:21:0x016c, code lost:
        if (r26 == 0) goto L_0x0185;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:225:?, code lost:
        return inflate_flush(r32, r33);
     */
    /* JADX WARNING: Code restructure failed: missing block: B:226:?, code lost:
        return inflate_flush(r32, -3);
     */
    /* JADX WARNING: Code restructure failed: missing block: B:227:?, code lost:
        return inflate_flush(r32, r33);
     */
    /* JADX WARNING: Code restructure failed: missing block: B:228:?, code lost:
        return inflate_flush(r32, -3);
     */
    /* JADX WARNING: Code restructure failed: missing block: B:231:?, code lost:
        return inflate_flush(r32, r33);
     */
    /* JADX WARNING: Code restructure failed: missing block: B:233:?, code lost:
        return inflate_flush(r32, r33);
     */
    /* JADX WARNING: Code restructure failed: missing block: B:234:?, code lost:
        return inflate_flush(r32, r33);
     */
    /* JADX WARNING: Code restructure failed: missing block: B:235:?, code lost:
        return inflate_flush(r32, r30);
     */
    /* JADX WARNING: Code restructure failed: missing block: B:236:?, code lost:
        return inflate_flush(r32, r33);
     */
    /* JADX WARNING: Code restructure failed: missing block: B:237:?, code lost:
        return inflate_flush(r32, r33);
     */
    /* JADX WARNING: Code restructure failed: missing block: B:238:?, code lost:
        return inflate_flush(r32, -3);
     */
    /* JADX WARNING: Code restructure failed: missing block: B:239:?, code lost:
        return inflate_flush(r32, r33);
     */
    /* JADX WARNING: Code restructure failed: missing block: B:23:0x0185, code lost:
        r31.bitb = r19;
        r31.bitk = r24;
        r32.avail_in = r26;
        r32.total_in += (long) (r28 - r32.next_in_index);
        r32.next_in_index = r28;
        r31.write = r29;
        r27 = r28;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:240:?, code lost:
        return inflate_flush(r32, r33);
     */
    /* JADX WARNING: Code restructure failed: missing block: B:241:?, code lost:
        return inflate_flush(r32, 1);
     */
    /* JADX WARNING: Code restructure failed: missing block: B:25:0x01c8, code lost:
        if ((((r19 ^ -1) >>> 16) & android.support.v4.internal.view.SupportMenu.USER_MASK) == (65535 & r19)) goto L_0x020f;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:26:0x01ca, code lost:
        r31.mode = 9;
        r32.msg = "invalid stored block lengths";
        r31.bitb = r19;
        r31.bitk = r24;
        r32.avail_in = r26;
        r32.total_in += (long) (r28 - r32.next_in_index);
        r32.next_in_index = r28;
        r31.write = r29;
        r27 = r28;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:27:0x020f, code lost:
        r31.left = 65535 & r19;
        r24 = 0;
        r19 = 0;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:28:0x0220, code lost:
        if (r31.left == 0) goto L_0x022b;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:29:0x0222, code lost:
        r4 = 2;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:30:0x0223, code lost:
        r31.mode = r4;
        r27 = r28;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:32:0x022f, code lost:
        if (r31.last == 0) goto L_0x0233;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:33:0x0231, code lost:
        r4 = 7;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:34:0x0233, code lost:
        r4 = 0;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:75:0x0369, code lost:
        if (r24 >= 14) goto L_0x03ba;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:76:0x036b, code lost:
        if (r26 == 0) goto L_0x0384;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:78:0x0384, code lost:
        r31.bitb = r19;
        r31.bitk = r24;
        r32.avail_in = r26;
        r32.total_in += (long) (r28 - r32.next_in_index);
        r32.next_in_index = r28;
        r31.write = r29;
        r27 = r28;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:79:0x03ba, code lost:
        r30 = r19 & 16383;
        r31.table = r30;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:80:0x03ca, code lost:
        if ((r30 & 31) > 29) goto L_0x03d4;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:82:0x03d2, code lost:
        if (((r30 >> 5) & 31) <= 29) goto L_0x0419;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:84:0x0419, code lost:
        r30 = ((r30 & 31) + 258) + ((r30 >> 5) & 31);
     */
    /* JADX WARNING: Code restructure failed: missing block: B:85:0x0427, code lost:
        if (r31.blens == null) goto L_0x0432;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:87:0x0430, code lost:
        if (r31.blens.length >= r30) goto L_0x0478;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:88:0x0432, code lost:
        r31.blens = new int[r30];
     */
    /* JADX WARNING: Code restructure failed: missing block: B:89:0x043a, code lost:
        r19 = r19 >>> 14;
        r24 = r24 - 14;
        r31.index = 0;
        r31.mode = 4;
        r27 = r28;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:8:0x0074, code lost:
        if (r24 >= 3) goto L_0x00c4;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:91:0x0456, code lost:
        if (r31.index >= ((r31.table >>> 10) + 4)) goto L_0x04de;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:92:0x045a, code lost:
        r28 = r27;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:93:0x045d, code lost:
        if (r24 >= 3) goto L_0x04c0;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:94:0x045f, code lost:
        if (r26 == 0) goto L_0x048a;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:95:0x0461, code lost:
        r33 = 0;
        r26 = r26 - 1;
        r27 = r28 + 1;
        r19 = r19 | ((r32.next_in[r28] & 255) << r24);
        r24 = r24 + 8;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:96:0x0478, code lost:
        r21 = 0;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:98:0x047e, code lost:
        if (r21 >= r30) goto L_0x043a;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:99:0x0480, code lost:
        r31.blens[r21] = 0;
        r21 = r21 + 1;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:9:0x0076, code lost:
        if (r26 == 0) goto L_0x008f;
     */
    public int proc(ZStream z, int r) {
        int p;
        int p2 = z.next_in_index;
        int n = z.avail_in;
        int b = this.bitb;
        int k = this.bitk;
        int q = this.write;
        int m = q < this.read ? (this.read - q) - 1 : this.end - q;
        while (true) {
            switch (this.mode) {
                case 0:
                    while (true) {
                        int p3 = p2;
                        r = 0;
                        n--;
                        p2 = p3 + 1;
                        b |= (z.next_in[p3] & 255) << k;
                        k += 8;
                        break;
                    }
                case 1:
                    while (true) {
                        int p4 = p2;
                        r = 0;
                        n--;
                        p2 = p4 + 1;
                        b |= (z.next_in[p4] & 255) << k;
                        k += 8;
                        break;
                    }
                case 2:
                    if (n != 0) {
                        if (m == 0) {
                            if (q == this.end && this.read != 0) {
                                q = 0;
                                m = 0 < this.read ? (this.read - 0) - 1 : this.end - 0;
                            }
                            if (m == 0) {
                                this.write = q;
                                int r2 = inflate_flush(z, r);
                                q = this.write;
                                int m2 = q < this.read ? (this.read - q) - 1 : this.end - q;
                                if (q == this.end && this.read != 0) {
                                    q = 0;
                                    m2 = 0 < this.read ? (this.read - 0) - 1 : this.end - 0;
                                }
                                if (m == 0) {
                                    this.bitb = b;
                                    this.bitk = k;
                                    z.avail_in = n;
                                    z.total_in += (long) (p2 - z.next_in_index);
                                    z.next_in_index = p2;
                                    this.write = q;
                                    return inflate_flush(z, r2);
                                }
                            }
                        }
                        r = 0;
                        int t = this.left;
                        if (t > n) {
                            t = n;
                        }
                        if (t > m) {
                            t = m;
                        }
                        System.arraycopy(z.next_in, p2, this.window, q, t);
                        p2 += t;
                        n -= t;
                        q += t;
                        m -= t;
                        int i = this.left - t;
                        this.left = i;
                        if (i == 0) {
                            this.mode = this.last != 0 ? 7 : 0;
                            break;
                        } else {
                            break;
                        }
                    } else {
                        this.bitb = b;
                        this.bitk = k;
                        z.avail_in = 0;
                        z.total_in += (long) (p2 - z.next_in_index);
                        z.next_in_index = p2;
                        this.write = q;
                        return inflate_flush(z, r);
                    }
                case 3:
                    while (true) {
                        p = p2;
                        r = 0;
                        n--;
                        p2 = p + 1;
                        b |= (z.next_in[p] & 255) << k;
                        k += 8;
                        break;
                    }
                case 4:
                    break;
                case 5:
                    break;
                case 6:
                    break;
                case 7:
                    break;
                case 8:
                    break;
                case 9:
                    this.bitb = b;
                    this.bitk = k;
                    z.avail_in = n;
                    z.total_in += (long) (p2 - z.next_in_index);
                    z.next_in_index = p2;
                    this.write = q;
                    return inflate_flush(z, -3);
                default:
                    this.bitb = b;
                    this.bitk = k;
                    z.avail_in = n;
                    z.total_in += (long) (p2 - z.next_in_index);
                    z.next_in_index = p2;
                    this.write = q;
                    return inflate_flush(z, -2);
            }
        }
        this.mode = 9;
        z.msg = "too many length or distance symbols";
        this.bitb = b;
        this.bitk = k;
        z.avail_in = n;
        z.total_in += (long) (p - z.next_in_index);
        z.next_in_index = p;
        this.write = q;
        int i2 = p;
        return inflate_flush(z, -3);
    }

    /* access modifiers changed from: 0000 */
    public void free(ZStream z) {
        reset(z, null);
        this.window = null;
        this.hufts = null;
    }

    /* access modifiers changed from: 0000 */
    public void set_dictionary(byte[] d, int start, int n) {
        System.arraycopy(d, start, this.window, 0, n);
        this.write = n;
        this.read = n;
    }

    /* access modifiers changed from: 0000 */
    public int sync_point() {
        return this.mode == 1 ? 1 : 0;
    }

    /* access modifiers changed from: 0000 */
    public int inflate_flush(ZStream z, int r) {
        int p = z.next_out_index;
        int q = this.read;
        int n = (q <= this.write ? this.write : this.end) - q;
        if (n > z.avail_out) {
            n = z.avail_out;
        }
        if (n != 0 && r == -5) {
            r = 0;
        }
        z.avail_out -= n;
        z.total_out += (long) n;
        if (this.checkfn != null) {
            long adler32 = Adler32.adler32(this.check, this.window, q, n);
            this.check = adler32;
            z.adler = adler32;
        }
        System.arraycopy(this.window, q, z.next_out, p, n);
        int p2 = p + n;
        int q2 = q + n;
        if (q2 == this.end) {
            if (this.write == this.end) {
                this.write = 0;
            }
            int n2 = this.write - 0;
            if (n2 > z.avail_out) {
                n2 = z.avail_out;
            }
            if (n2 != 0 && r == -5) {
                r = 0;
            }
            z.avail_out -= n2;
            z.total_out += (long) n2;
            if (this.checkfn != null) {
                long adler322 = Adler32.adler32(this.check, this.window, 0, n2);
                this.check = adler322;
                z.adler = adler322;
            }
            System.arraycopy(this.window, 0, z.next_out, p2, n2);
            p2 += n2;
            q2 = 0 + n2;
        }
        z.next_out_index = p2;
        this.read = q2;
        return r;
    }
}