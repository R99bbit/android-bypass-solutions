package org.jboss.netty.util.internal.jzlib;

import android.support.v4.app.FragmentTransaction;
import android.support.v4.view.InputDeviceCompat;
import android.support.v7.widget.helper.ItemTouchHelper.Callback;
import com.facebook.internal.FacebookRequestErrorClassification;
import com.igaworks.adbrix.util.CPEConstant;
import com.loopj.android.http.BuildConfig;

final class InfTree {
    static final int BMAX = 15;
    static final int[] cpdext = {0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13};
    static final int[] cpdist = {1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, InputDeviceCompat.SOURCE_KEYBOARD, 385, InputDeviceCompat.SOURCE_DPAD, 769, InputDeviceCompat.SOURCE_GAMEPAD, 1537, 2049, 3073, FragmentTransaction.TRANSIT_FRAGMENT_OPEN, 6145, 8193, 12289, 16385, 24577};
    static final int[] cplens = {3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258, 0, 0};
    static final int[] cplext = {0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0, 112, 112};
    static final int fixed_bd = 5;
    static final int fixed_bl = 9;
    static final int[] fixed_td = {80, 5, 1, 87, 5, InputDeviceCompat.SOURCE_KEYBOARD, 83, 5, 17, 91, 5, FragmentTransaction.TRANSIT_FRAGMENT_OPEN, 81, 5, 5, 89, 5, InputDeviceCompat.SOURCE_GAMEPAD, 85, 5, 65, 93, 5, 16385, 80, 5, 3, 88, 5, InputDeviceCompat.SOURCE_DPAD, 84, 5, 33, 92, 5, 8193, 82, 5, 9, 90, 5, 2049, 86, 5, 129, 192, 5, 24577, 80, 5, 2, 87, 5, 385, 83, 5, 25, 91, 5, 6145, 81, 5, 7, 89, 5, 1537, 85, 5, 97, 93, 5, 24577, 80, 5, 4, 88, 5, 769, 84, 5, 49, 92, 5, 12289, 82, 5, 13, 90, 5, 3073, 86, 5, 193, 192, 5, 24577};
    static final int[] fixed_tl = {96, 7, 256, 0, 8, 80, 0, 8, 16, 84, 8, 115, 82, 7, 31, 0, 8, 112, 0, 8, 48, 0, 9, 192, 80, 7, 10, 0, 8, 96, 0, 8, 32, 0, 9, 160, 0, 8, 0, 0, 8, 128, 0, 8, 64, 0, 9, 224, 80, 7, 6, 0, 8, 88, 0, 8, 24, 0, 9, 144, 83, 7, 59, 0, 8, 120, 0, 8, 56, 0, 9, 208, 81, 7, 17, 0, 8, 104, 0, 8, 40, 0, 9, 176, 0, 8, 8, 0, 8, 136, 0, 8, 72, 0, 9, 240, 80, 7, 4, 0, 8, 84, 0, 8, 20, 85, 8, 227, 83, 7, 43, 0, 8, 116, 0, 8, 52, 0, 9, 200, 81, 7, 13, 0, 8, 100, 0, 8, 36, 0, 9, 168, 0, 8, 4, 0, 8, 132, 0, 8, 68, 0, 9, 232, 80, 7, 8, 0, 8, 92, 0, 8, 28, 0, 9, 152, 84, 7, 83, 0, 8, 124, 0, 8, 60, 0, 9, 216, 82, 7, 23, 0, 8, 108, 0, 8, 44, 0, 9, 184, 0, 8, 12, 0, 8, 140, 0, 8, 76, 0, 9, 248, 80, 7, 3, 0, 8, 82, 0, 8, 18, 85, 8, 163, 83, 7, 35, 0, 8, 114, 0, 8, 50, 0, 9, 196, 81, 7, 11, 0, 8, 98, 0, 8, 34, 0, 9, 164, 0, 8, 2, 0, 8, 130, 0, 8, 66, 0, 9, 228, 80, 7, 7, 0, 8, 90, 0, 8, 26, 0, 9, 148, 84, 7, 67, 0, 8, 122, 0, 8, 58, 0, 9, 212, 82, 7, 19, 0, 8, 106, 0, 8, 42, 0, 9, 180, 0, 8, 10, 0, 8, 138, 0, 8, 74, 0, 9, 244, 80, 7, 5, 0, 8, 86, 0, 8, 22, 192, 8, 0, 83, 7, 51, 0, 8, 118, 0, 8, 54, 0, 9, 204, 81, 7, 15, 0, 8, 102, 0, 8, 38, 0, 9, 172, 0, 8, 6, 0, 8, 134, 0, 8, 70, 0, 9, 236, 80, 7, 9, 0, 8, 94, 0, 8, 30, 0, 9, 156, 84, 7, 99, 0, 8, 126, 0, 8, 62, 0, 9, 220, 82, 7, 27, 0, 8, 110, 0, 8, 46, 0, 9, 188, 0, 8, 14, 0, 8, 142, 0, 8, 78, 0, 9, 252, 96, 7, 256, 0, 8, 81, 0, 8, 17, 85, 8, 131, 82, 7, 31, 0, 8, 113, 0, 8, 49, 0, 9, 194, 80, 7, 10, 0, 8, 97, 0, 8, 33, 0, 9, 162, 0, 8, 1, 0, 8, 129, 0, 8, 65, 0, 9, 226, 80, 7, 6, 0, 8, 89, 0, 8, 25, 0, 9, BuildConfig.VERSION_CODE, 83, 7, 59, 0, 8, 121, 0, 8, 57, 0, 9, 210, 81, 7, 17, 0, 8, 105, 0, 8, 41, 0, 9, CPEConstant.DIALOG_REWARD_HEIGHT_PORTRAIT, 0, 8, 9, 0, 8, 137, 0, 8, 73, 0, 9, 242, 80, 7, 4, 0, 8, 85, 0, 8, 21, 80, 8, 258, 83, 7, 43, 0, 8, 117, 0, 8, 53, 0, 9, 202, 81, 7, 13, 0, 8, 101, 0, 8, 37, 0, 9, 170, 0, 8, 5, 0, 8, 133, 0, 8, 69, 0, 9, 234, 80, 7, 8, 0, 8, 93, 0, 8, 29, 0, 9, 154, 84, 7, 83, 0, 8, 125, 0, 8, 61, 0, 9, 218, 82, 7, 23, 0, 8, 109, 0, 8, 45, 0, 9, 186, 0, 8, 13, 0, 8, 141, 0, 8, 77, 0, 9, Callback.DEFAULT_SWIPE_ANIMATION_DURATION, 80, 7, 3, 0, 8, 83, 0, 8, 19, 85, 8, 195, 83, 7, 35, 0, 8, 115, 0, 8, 51, 0, 9, 198, 81, 7, 11, 0, 8, 99, 0, 8, 35, 0, 9, 166, 0, 8, 3, 0, 8, 131, 0, 8, 67, 0, 9, 230, 80, 7, 7, 0, 8, 91, 0, 8, 27, 0, 9, 150, 84, 7, 67, 0, 8, 123, 0, 8, 59, 0, 9, 214, 82, 7, 19, 0, 8, 107, 0, 8, 43, 0, 9, 182, 0, 8, 11, 0, 8, 139, 0, 8, 75, 0, 9, 246, 80, 7, 5, 0, 8, 87, 0, 8, 23, 192, 8, 0, 83, 7, 51, 0, 8, 119, 0, 8, 55, 0, 9, 206, 81, 7, 15, 0, 8, 103, 0, 8, 39, 0, 9, 174, 0, 8, 7, 0, 8, 135, 0, 8, 71, 0, 9, 238, 80, 7, 9, 0, 8, 95, 0, 8, 31, 0, 9, 158, 84, 7, 99, 0, 8, 127, 0, 8, 63, 0, 9, 222, 82, 7, 27, 0, 8, 111, 0, 8, 47, 0, 9, FacebookRequestErrorClassification.EC_INVALID_TOKEN, 0, 8, 15, 0, 8, 143, 0, 8, 79, 0, 9, 254, 96, 7, 256, 0, 8, 80, 0, 8, 16, 84, 8, 115, 82, 7, 31, 0, 8, 112, 0, 8, 48, 0, 9, 193, 80, 7, 10, 0, 8, 96, 0, 8, 32, 0, 9, 161, 0, 8, 0, 0, 8, 128, 0, 8, 64, 0, 9, 225, 80, 7, 6, 0, 8, 88, 0, 8, 24, 0, 9, 145, 83, 7, 59, 0, 8, 120, 0, 8, 56, 0, 9, 209, 81, 7, 17, 0, 8, 104, 0, 8, 40, 0, 9, 177, 0, 8, 8, 0, 8, 136, 0, 8, 72, 0, 9, 241, 80, 7, 4, 0, 8, 84, 0, 8, 20, 85, 8, 227, 83, 7, 43, 0, 8, 116, 0, 8, 52, 0, 9, 201, 81, 7, 13, 0, 8, 100, 0, 8, 36, 0, 9, 169, 0, 8, 4, 0, 8, 132, 0, 8, 68, 0, 9, 233, 80, 7, 8, 0, 8, 92, 0, 8, 28, 0, 9, 153, 84, 7, 83, 0, 8, 124, 0, 8, 60, 0, 9, 217, 82, 7, 23, 0, 8, 108, 0, 8, 44, 0, 9, 185, 0, 8, 12, 0, 8, 140, 0, 8, 76, 0, 9, 249, 80, 7, 3, 0, 8, 82, 0, 8, 18, 85, 8, 163, 83, 7, 35, 0, 8, 114, 0, 8, 50, 0, 9, 197, 81, 7, 11, 0, 8, 98, 0, 8, 34, 0, 9, 165, 0, 8, 2, 0, 8, 130, 0, 8, 66, 0, 9, 229, 80, 7, 7, 0, 8, 90, 0, 8, 26, 0, 9, 149, 84, 7, 67, 0, 8, 122, 0, 8, 58, 0, 9, 213, 82, 7, 19, 0, 8, 106, 0, 8, 42, 0, 9, 181, 0, 8, 10, 0, 8, 138, 0, 8, 74, 0, 9, 245, 80, 7, 5, 0, 8, 86, 0, 8, 22, 192, 8, 0, 83, 7, 51, 0, 8, 118, 0, 8, 54, 0, 9, 205, 81, 7, 15, 0, 8, 102, 0, 8, 38, 0, 9, 173, 0, 8, 6, 0, 8, 134, 0, 8, 70, 0, 9, 237, 80, 7, 9, 0, 8, 94, 0, 8, 30, 0, 9, 157, 84, 7, 99, 0, 8, 126, 0, 8, 62, 0, 9, 221, 82, 7, 27, 0, 8, 110, 0, 8, 46, 0, 9, 189, 0, 8, 14, 0, 8, 142, 0, 8, 78, 0, 9, 253, 96, 7, 256, 0, 8, 81, 0, 8, 17, 85, 8, 131, 82, 7, 31, 0, 8, 113, 0, 8, 49, 0, 9, 195, 80, 7, 10, 0, 8, 97, 0, 8, 33, 0, 9, 163, 0, 8, 1, 0, 8, 129, 0, 8, 65, 0, 9, 227, 80, 7, 6, 0, 8, 89, 0, 8, 25, 0, 9, 147, 83, 7, 59, 0, 8, 121, 0, 8, 57, 0, 9, 211, 81, 7, 17, 0, 8, 105, 0, 8, 41, 0, 9, 179, 0, 8, 9, 0, 8, 137, 0, 8, 73, 0, 9, 243, 80, 7, 4, 0, 8, 85, 0, 8, 21, 80, 8, 258, 83, 7, 43, 0, 8, 117, 0, 8, 53, 0, 9, 203, 81, 7, 13, 0, 8, 101, 0, 8, 37, 0, 9, 171, 0, 8, 5, 0, 8, 133, 0, 8, 69, 0, 9, 235, 80, 7, 8, 0, 8, 93, 0, 8, 29, 0, 9, 155, 84, 7, 83, 0, 8, 125, 0, 8, 61, 0, 9, 219, 82, 7, 23, 0, 8, 109, 0, 8, 45, 0, 9, 187, 0, 8, 13, 0, 8, 141, 0, 8, 77, 0, 9, 251, 80, 7, 3, 0, 8, 83, 0, 8, 19, 85, 8, 195, 83, 7, 35, 0, 8, 115, 0, 8, 51, 0, 9, 199, 81, 7, 11, 0, 8, 99, 0, 8, 35, 0, 9, 167, 0, 8, 3, 0, 8, 131, 0, 8, 67, 0, 9, 231, 80, 7, 7, 0, 8, 91, 0, 8, 27, 0, 9, 151, 84, 7, 67, 0, 8, 123, 0, 8, 59, 0, 9, 215, 82, 7, 19, 0, 8, 107, 0, 8, 43, 0, 9, 183, 0, 8, 11, 0, 8, 139, 0, 8, 75, 0, 9, 247, 80, 7, 5, 0, 8, 87, 0, 8, 23, 192, 8, 0, 83, 7, 51, 0, 8, 119, 0, 8, 55, 0, 9, 207, 81, 7, 15, 0, 8, 103, 0, 8, 39, 0, 9, 175, 0, 8, 7, 0, 8, 135, 0, 8, 71, 0, 9, 239, 80, 7, 9, 0, 8, 95, 0, 8, 31, 0, 9, 159, 84, 7, 99, 0, 8, 127, 0, 8, 63, 0, 9, 223, 82, 7, 27, 0, 8, 111, 0, 8, 47, 0, 9, 191, 0, 8, 15, 0, 8, 143, 0, 8, 79, 0, 9, 255};
    private int[] c;
    private int[] hn;
    private int[] r;
    private int[] u;
    private int[] v;
    private int[] x;

    InfTree() {
    }

    /* JADX WARNING: Code restructure failed: missing block: B:91:0x02e4, code lost:
        r12 = r12 + 1;
        r15 = r16;
     */
    private int huft_build(int[] b, int bindex, int n, int s, int[] d, int[] e, int[] t, int[] m, int[] hp, int[] hn2, int[] v2) {
        int p;
        int p2 = 0;
        int i = n;
        do {
            int[] iArr = this.c;
            int i2 = b[bindex + p2];
            iArr[i2] = iArr[i2] + 1;
            p2++;
            i--;
        } while (i != 0);
        if (this.c[0] == n) {
            t[0] = -1;
            m[0] = 0;
            return 0;
        }
        int l = m[0];
        int j = 1;
        while (j <= 15 && this.c[j] == 0) {
            j++;
        }
        int k = j;
        if (l < j) {
            l = j;
        }
        int i3 = 15;
        while (i3 != 0 && this.c[i3] == 0) {
            i3--;
        }
        int g = i3;
        if (l > i3) {
            l = i3;
        }
        m[0] = l;
        int y = 1 << j;
        while (j < i3) {
            int y2 = y - this.c[j];
            if (y2 < 0) {
                return -3;
            }
            j++;
            y = y2 << 1;
        }
        int y3 = y - this.c[i3];
        if (y3 < 0) {
            return -3;
        }
        int[] iArr2 = this.c;
        iArr2[i3] = iArr2[i3] + y3;
        int j2 = 0;
        this.x[1] = 0;
        int p3 = 1;
        int xp = 2;
        while (true) {
            i3--;
            if (i3 == 0) {
                break;
            }
            j2 += this.c[p3];
            this.x[xp] = j2;
            xp++;
            p3++;
        }
        int i4 = 0;
        int p4 = 0;
        do {
            int j3 = b[bindex + p4];
            if (j3 != 0) {
                int[] iArr3 = this.x;
                int i5 = iArr3[j3];
                iArr3[j3] = i5 + 1;
                v2[i5] = i4;
            }
            p4++;
            i4++;
        } while (i4 < n);
        int n2 = this.x[g];
        int i6 = 0;
        this.x[0] = 0;
        int p5 = 0;
        int h = -1;
        int w = -l;
        this.u[0] = 0;
        int q = 0;
        int z = 0;
        while (k <= g) {
            int a = this.c[k];
            while (true) {
                int p6 = p;
                int a2 = a;
                a = a2 - 1;
                if (a2 == 0) {
                    break;
                }
                while (k > w + l) {
                    h++;
                    w += l;
                    int z2 = g - w;
                    if (z2 > l) {
                        z2 = l;
                    }
                    int j4 = k - w;
                    int f = 1 << j4;
                    if (f > a + 1) {
                        int f2 = f - (a + 1);
                        int xp2 = k;
                        if (j4 < z2) {
                            while (true) {
                                j4++;
                                if (j4 >= z2) {
                                    break;
                                }
                                int f3 = f2 << 1;
                                xp2++;
                                if (f3 <= this.c[xp2]) {
                                    break;
                                }
                                f2 = f3 - this.c[xp2];
                            }
                        }
                    }
                    z = 1 << j4;
                    if (hn2[0] + z > 1440) {
                        int i7 = p6;
                        return -3;
                    }
                    q = hn2[0];
                    this.u[h] = q;
                    hn2[0] = hn2[0] + z;
                    if (h != 0) {
                        this.x[h] = i6;
                        this.r[0] = (byte) j4;
                        this.r[1] = (byte) l;
                        int j5 = i6 >>> (w - l);
                        this.r[2] = (q - this.u[h - 1]) - j5;
                        System.arraycopy(this.r, 0, hp, (this.u[h - 1] + j5) * 3, 3);
                    } else {
                        t[0] = q;
                    }
                }
                this.r[1] = (byte) (k - w);
                if (p6 >= n2) {
                    this.r[0] = 192;
                    p = p6;
                } else if (v2[p6] < s) {
                    this.r[0] = (byte) (v2[p6] < 256 ? 0 : 96);
                    p = p6 + 1;
                    this.r[2] = v2[p6];
                } else {
                    this.r[0] = (byte) (e[v2[p6] - s] + 16 + 64);
                    p = p6 + 1;
                    this.r[2] = d[v2[p6] - s];
                }
                int f4 = 1 << (k - w);
                for (int j6 = i6 >>> w; j6 < z; j6 += f4) {
                    System.arraycopy(this.r, 0, hp, (q + j6) * 3, 3);
                }
                int j7 = 1 << (k - 1);
                while ((i6 & j7) != 0) {
                    i6 ^= j7;
                    j7 >>>= 1;
                }
                i6 ^= j7;
                while ((i6 & ((1 << w) - 1)) != this.x[h]) {
                    h--;
                    w -= l;
                }
            }
        }
        return (y3 == 0 || g == 1) ? 0 : -5;
    }

    /* access modifiers changed from: 0000 */
    public int inflate_trees_bits(int[] c2, int[] bb, int[] tb, int[] hp, ZStream z) {
        initWorkArea(19);
        this.hn[0] = 0;
        int result = huft_build(c2, 0, 19, 19, null, null, tb, bb, hp, this.hn, this.v);
        if (result == -3) {
            z.msg = "oversubscribed dynamic bit lengths tree";
            return result;
        } else if (result != -5 && bb[0] != 0) {
            return result;
        } else {
            z.msg = "incomplete dynamic bit lengths tree";
            return -3;
        }
    }

    /* access modifiers changed from: 0000 */
    public int inflate_trees_dynamic(int nl, int nd, int[] c2, int[] bl, int[] bd, int[] tl, int[] td, int[] hp, ZStream z) {
        initWorkArea(288);
        this.hn[0] = 0;
        int result = huft_build(c2, 0, nl, InputDeviceCompat.SOURCE_KEYBOARD, cplens, cplext, tl, bl, hp, this.hn, this.v);
        if (result != 0 || bl[0] == 0) {
            if (result == -3) {
                z.msg = "oversubscribed literal/length tree";
            } else if (result != -4) {
                z.msg = "incomplete literal/length tree";
                result = -3;
            }
            return result;
        }
        initWorkArea(288);
        int result2 = huft_build(c2, nl, nd, 0, cpdist, cpdext, td, bd, hp, this.hn, this.v);
        if (result2 == 0 && (bd[0] != 0 || nl <= 257)) {
            return 0;
        }
        if (result2 == -3) {
            z.msg = "oversubscribed distance tree";
        } else if (result2 == -5) {
            z.msg = "incomplete distance tree";
            result2 = -3;
        } else if (result2 != -4) {
            z.msg = "empty distance tree with lengths";
            result2 = -3;
        }
        return result2;
    }

    static int inflate_trees_fixed(int[] bl, int[] bd, int[][] tl, int[][] td) {
        bl[0] = 9;
        bd[0] = 5;
        tl[0] = fixed_tl;
        td[0] = fixed_td;
        return 0;
    }

    private void initWorkArea(int vsize) {
        if (this.hn == null) {
            this.hn = new int[1];
            this.v = new int[vsize];
            this.c = new int[16];
            this.r = new int[3];
            this.u = new int[15];
            this.x = new int[16];
            return;
        }
        if (this.v.length < vsize) {
            this.v = new int[vsize];
        } else {
            for (int i = 0; i < vsize; i++) {
                this.v[i] = 0;
            }
        }
        for (int i2 = 0; i2 < 16; i2++) {
            this.c[i2] = 0;
        }
        for (int i3 = 0; i3 < 3; i3++) {
            this.r[i3] = 0;
        }
        System.arraycopy(this.c, 0, this.u, 0, 15);
        System.arraycopy(this.c, 0, this.x, 0, 16);
    }
}