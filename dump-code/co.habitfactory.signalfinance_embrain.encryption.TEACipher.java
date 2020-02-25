package co.habitfactory.signalfinance_embrain.encryption;

public class TEACipher {
    static final /* synthetic */ boolean $assertionsDisabled = false;
    private static final int CUPS = 32;
    private static final int SUGAR = -1640531527;
    private static final int UNSUGAR = -957401312;
    private int[] S = new int[4];

    public TEACipher(byte[] bArr) {
        if (bArr == null) {
            throw new RuntimeException("Invalid key: Key was null");
        } else if (bArr.length >= 16) {
            int i = 0;
            int i2 = 0;
            while (i < 4) {
                int i3 = i2 + 1;
                int i4 = i3 + 1;
                byte b = (bArr[i2] & 255) | ((bArr[i3] & 255) << 8);
                int i5 = i4 + 1;
                byte b2 = b | ((bArr[i4] & 255) << 16);
                this.S[i] = b2 | ((bArr[i5] & 255) << 24);
                i++;
                i2 = i5 + 1;
            }
        } else {
            throw new RuntimeException("Invalid key: Length was less than 16 bytes");
        }
    }

    public byte[] encrypt(byte[] bArr) {
        int[] iArr = new int[((((bArr.length / 8) + (bArr.length % 8 == 0 ? 0 : 1)) * 2) + 1)];
        iArr[0] = bArr.length;
        pack(bArr, iArr, 1);
        brew(iArr);
        return unpack(iArr, 0, iArr.length * 4);
    }

    public byte[] decrypt(byte[] bArr) {
        int[] iArr = new int[(bArr.length / 4)];
        pack(bArr, iArr, 0);
        unbrew(iArr);
        return unpack(iArr, 1, iArr[0]);
    }

    /* access modifiers changed from: 0000 */
    public void brew(int[] iArr) {
        for (int i = 1; i < iArr.length; i += 2) {
            int i2 = 32;
            int i3 = iArr[i];
            int i4 = i + 1;
            int i5 = iArr[i4];
            int i6 = 0;
            while (true) {
                int i7 = i2 - 1;
                if (i2 <= 0) {
                    break;
                }
                i6 -= 1640531527;
                int[] iArr2 = this.S;
                i3 += (((i5 << 4) + iArr2[0]) ^ i5) + ((i5 >>> 5) ^ i6) + iArr2[1];
                i5 += (((i3 << 4) + iArr2[2]) ^ i3) + ((i3 >>> 5) ^ i6) + iArr2[3];
                i2 = i7;
            }
            iArr[i] = i3;
            iArr[i4] = i5;
        }
    }

    /* access modifiers changed from: 0000 */
    public void unbrew(int[] iArr) {
        for (int i = 1; i < iArr.length; i += 2) {
            int i2 = 32;
            int i3 = iArr[i];
            int i4 = i + 1;
            int i5 = iArr[i4];
            int i6 = UNSUGAR;
            while (true) {
                int i7 = i2 - 1;
                if (i2 <= 0) {
                    break;
                }
                int[] iArr2 = this.S;
                i5 -= ((((i3 << 4) + iArr2[2]) ^ i3) + ((i3 >>> 5) ^ i6)) + iArr2[3];
                i3 -= ((((i5 << 4) + iArr2[0]) ^ i5) + ((i5 >>> 5) ^ i6)) + iArr2[1];
                i6 += 1640531527;
                i2 = i7;
            }
            iArr[i] = i3;
            iArr[i4] = i5;
        }
    }

    /* JADX WARNING: type inference failed for: r3v2 */
    /* JADX WARNING: type inference failed for: r3v3, types: [int] */
    /* JADX WARNING: type inference failed for: r3v5 */
    /* JADX WARNING: type inference failed for: r3v6 */
    /* JADX WARNING: type inference failed for: r3v7 */
    /* JADX WARNING: type inference failed for: r3v8 */
    /* access modifiers changed from: 0000 */
    /* JADX WARNING: Multi-variable type inference failed. Error: jadx.core.utils.exceptions.JadxRuntimeException: No candidate types for var: r3v2
      assigns: []
      uses: []
      mth insns count: 24
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
    	at jadx.api.JadxDecompiler.processClass(JadxDecompiler.java:311)
    	at jadx.api.JavaClass.decompile(JavaClass.java:62)
     */
    /* JADX WARNING: Unknown variable types count: 3 */
    public void pack(byte[] bArr, int[] iArr, int i) {
        ? r3;
        iArr[i] = 0;
        int i2 = i;
        int i3 = 0;
        ? r32 = 24;
        while (i3 < bArr.length) {
            iArr[i2] = iArr[i2] | ((bArr[i3] & 255) << r32);
            if (r32 == 0) {
                i2++;
                if (i2 < iArr.length) {
                    iArr[i2] = 0;
                }
                r3 = 24;
            } else {
                r3 = r32 - 8;
            }
            i3++;
            r32 = r3;
        }
    }

    /* access modifiers changed from: 0000 */
    public byte[] unpack(int[] iArr, int i, int i2) {
        byte[] bArr = new byte[i2];
        int i3 = i;
        int i4 = 0;
        for (int i5 = 0; i5 < i2; i5++) {
            bArr[i5] = (byte) ((iArr[i3] >> (24 - (i4 * 8))) & 255);
            i4++;
            if (i4 == 4) {
                i3++;
                i4 = 0;
            }
        }
        return bArr;
    }
}