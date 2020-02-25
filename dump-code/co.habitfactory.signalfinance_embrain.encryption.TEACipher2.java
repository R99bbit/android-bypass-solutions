package co.habitfactory.signalfinance_embrain.encryption;

public class TEACipher2 {
    private int[] KEY = new int[4];

    private static int transform(byte b) {
        return b < 0 ? b + 256 : b;
    }

    public TEACipher2(byte[] bArr) {
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
                this.KEY[i] = b2 | ((bArr[i5] & 255) << 24);
                i++;
                i2 = i5 + 1;
            }
        } else {
            throw new RuntimeException("Invalid key: Length was less than 16 bytes");
        }
    }

    public byte[] encrypt(byte[] bArr, int i, int i2) {
        int[] byteToInt = byteToInt(bArr, i);
        int i3 = byteToInt[0];
        int i4 = byteToInt[1];
        int[] iArr = this.KEY;
        int i5 = iArr[0];
        int i6 = iArr[1];
        int i7 = iArr[2];
        int i8 = iArr[3];
        int i9 = i4;
        int i10 = 0;
        int i11 = i3;
        for (int i12 = 0; i12 < i2; i12++) {
            i10 -= 1640531527;
            i11 += (((i9 << 4) + i5) ^ (i9 + i10)) ^ ((i9 >> 5) + i6);
            i9 += (((i11 << 4) + i7) ^ (i11 + i10)) ^ ((i11 >> 5) + i8);
        }
        byteToInt[0] = i11;
        byteToInt[1] = i9;
        return intToByte(byteToInt, 0);
    }

    public byte[] decrypt(byte[] bArr, int i, int[] iArr, int i2) {
        int[] byteToInt = byteToInt(bArr, i);
        int i3 = byteToInt[0];
        int i4 = byteToInt[1];
        int i5 = iArr[0];
        int i6 = iArr[1];
        int i7 = iArr[2];
        int i8 = iArr[3];
        int i9 = i2 == 32 ? -957401312 : i2 == 16 ? -478700656 : i2 * -1640531527;
        int i10 = i9;
        int i11 = i4;
        int i12 = i3;
        for (int i13 = 0; i13 < i2; i13++) {
            i11 -= (((i12 << 4) + i7) ^ (i12 + i10)) ^ ((i12 >> 5) + i8);
            i12 -= (((i11 << 4) + i5) ^ (i11 + i10)) ^ ((i11 >> 5) + i6);
            i10 -= -1640531527;
        }
        byteToInt[0] = i12;
        byteToInt[1] = i11;
        return intToByte(byteToInt, 0);
    }

    private int[] byteToInt(byte[] bArr, int i) {
        int[] iArr = new int[(bArr.length >> 2)];
        int i2 = 0;
        while (i < bArr.length) {
            iArr[i2] = transform(bArr[i + 3]) | (transform(bArr[i + 2]) << 8) | (transform(bArr[i + 1]) << 16) | (bArr[i] << 24);
            i2++;
            i += 4;
        }
        return iArr;
    }

    private byte[] intToByte(int[] iArr, int i) {
        byte[] bArr = new byte[(iArr.length << 2)];
        int i2 = 0;
        while (i < bArr.length) {
            bArr[i + 3] = (byte) (iArr[i2] & 255);
            bArr[i + 2] = (byte) ((iArr[i2] >> 8) & 255);
            bArr[i + 1] = (byte) ((iArr[i2] >> 16) & 255);
            bArr[i] = (byte) ((iArr[i2] >> 24) & 255);
            i2++;
            i += 4;
        }
        return bArr;
    }
}