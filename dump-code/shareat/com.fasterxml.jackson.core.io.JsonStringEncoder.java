package com.fasterxml.jackson.core.io;

import com.fasterxml.jackson.core.util.BufferRecycler;
import com.fasterxml.jackson.core.util.ByteArrayBuilder;
import com.fasterxml.jackson.core.util.TextBuffer;
import java.lang.ref.SoftReference;

public final class JsonStringEncoder {
    private static final byte[] HEX_BYTES = CharTypes.copyHexBytes();
    private static final char[] HEX_CHARS = CharTypes.copyHexChars();
    private static final int INT_0 = 48;
    private static final int INT_BACKSLASH = 92;
    private static final int INT_U = 117;
    private static final int SURR1_FIRST = 55296;
    private static final int SURR1_LAST = 56319;
    private static final int SURR2_FIRST = 56320;
    private static final int SURR2_LAST = 57343;
    protected static final ThreadLocal<SoftReference<JsonStringEncoder>> _threadEncoder = new ThreadLocal<>();
    protected ByteArrayBuilder _byteBuilder;
    protected final char[] _quoteBuffer = new char[6];
    protected TextBuffer _textBuffer;

    public JsonStringEncoder() {
        this._quoteBuffer[0] = '\\';
        this._quoteBuffer[2] = '0';
        this._quoteBuffer[3] = '0';
    }

    public static JsonStringEncoder getInstance() {
        SoftReference softReference = _threadEncoder.get();
        JsonStringEncoder jsonStringEncoder = softReference == null ? null : (JsonStringEncoder) softReference.get();
        if (jsonStringEncoder != null) {
            return jsonStringEncoder;
        }
        JsonStringEncoder jsonStringEncoder2 = new JsonStringEncoder();
        _threadEncoder.set(new SoftReference(jsonStringEncoder2));
        return jsonStringEncoder2;
    }

    /* JADX WARNING: Code restructure failed: missing block: B:10:0x0030, code lost:
        if (r9 >= 0) goto L_0x006b;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:11:0x0032, code lost:
        r2 = _appendNumericEscape(r2, r11._quoteBuffer);
     */
    /* JADX WARNING: Code restructure failed: missing block: B:13:0x003b, code lost:
        if ((r1 + r2) <= r3.length) goto L_0x0072;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:14:0x003d, code lost:
        r9 = r3.length - r1;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:15:0x003f, code lost:
        if (r9 <= 0) goto L_0x0046;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:16:0x0041, code lost:
        java.lang.System.arraycopy(r11._quoteBuffer, 0, r3, r1, r9);
     */
    /* JADX WARNING: Code restructure failed: missing block: B:17:0x0046, code lost:
        r3 = r0.finishCurrentSegment();
        r1 = r2 - r9;
        java.lang.System.arraycopy(r11._quoteBuffer, r9, r3, 0, r1);
     */
    /* JADX WARNING: Code restructure failed: missing block: B:18:0x0051, code lost:
        r2 = r4;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:26:0x006b, code lost:
        r2 = _appendNamedEscape(r9, r11._quoteBuffer);
     */
    /* JADX WARNING: Code restructure failed: missing block: B:27:0x0072, code lost:
        java.lang.System.arraycopy(r11._quoteBuffer, 0, r3, r1, r2);
        r1 = r1 + r2;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:9:0x0028, code lost:
        r4 = r2 + 1;
        r2 = r12.charAt(r2);
        r9 = r6[r2];
     */
    public char[] quoteAsString(String str) {
        int i;
        TextBuffer textBuffer = this._textBuffer;
        if (textBuffer == null) {
            textBuffer = new TextBuffer(null);
            this._textBuffer = textBuffer;
        }
        char[] emptyAndGetCurrentSegment = textBuffer.emptyAndGetCurrentSegment();
        int[] iArr = CharTypes.get7BitOutputEscapes();
        int length = iArr.length;
        int length2 = str.length();
        int i2 = 0;
        int i3 = 0;
        loop0:
        while (i3 < length2) {
            while (true) {
                char charAt = str.charAt(i3);
                if (charAt < length && iArr[charAt] != 0) {
                    break;
                }
                if (i2 >= emptyAndGetCurrentSegment.length) {
                    emptyAndGetCurrentSegment = textBuffer.finishCurrentSegment();
                    i = 0;
                } else {
                    i = i2;
                }
                i2 = i + 1;
                emptyAndGetCurrentSegment[i] = charAt;
                i3++;
                if (i3 >= length2) {
                    break loop0;
                }
            }
        }
        textBuffer.setCurrentLength(i2);
        return textBuffer.contentsAsArray();
    }

    public byte[] quoteAsUTF8(String str) {
        int i;
        int i2;
        byte[] bArr;
        char c;
        int i3;
        int i4;
        int i5;
        ByteArrayBuilder byteArrayBuilder = this._byteBuilder;
        if (byteArrayBuilder == null) {
            byteArrayBuilder = new ByteArrayBuilder((BufferRecycler) null);
            this._byteBuilder = byteArrayBuilder;
        }
        int length = str.length();
        byte[] resetAndGetFirstSegment = byteArrayBuilder.resetAndGetFirstSegment();
        int i6 = 0;
        int i7 = 0;
        loop0:
        while (i7 < length) {
            int[] iArr = CharTypes.get7BitOutputEscapes();
            while (true) {
                char charAt = str.charAt(i7);
                if (charAt <= 127 && iArr[charAt] == 0) {
                    if (i6 >= resetAndGetFirstSegment.length) {
                        resetAndGetFirstSegment = byteArrayBuilder.finishCurrentSegment();
                        i5 = 0;
                    } else {
                        i5 = i6;
                    }
                    i6 = i5 + 1;
                    resetAndGetFirstSegment[i5] = (byte) charAt;
                    i7++;
                    if (i7 >= length) {
                        break loop0;
                    }
                }
            }
            if (i6 >= resetAndGetFirstSegment.length) {
                resetAndGetFirstSegment = byteArrayBuilder.finishCurrentSegment();
                i6 = 0;
            }
            int i8 = i7 + 1;
            char charAt2 = str.charAt(i7);
            if (charAt2 <= 127) {
                i6 = _appendByteEscape(charAt2, iArr[charAt2], byteArrayBuilder, i6);
                resetAndGetFirstSegment = byteArrayBuilder.getCurrentSegment();
                i7 = i8;
            } else {
                if (charAt2 <= 2047) {
                    i2 = i6 + 1;
                    resetAndGetFirstSegment[i6] = (byte) ((charAt2 >> 6) | 192);
                    bArr = resetAndGetFirstSegment;
                    c = (charAt2 & '?') | 128;
                } else if (charAt2 < SURR1_FIRST || charAt2 > SURR2_LAST) {
                    int i9 = i6 + 1;
                    resetAndGetFirstSegment[i6] = (byte) ((charAt2 >> 12) | 224);
                    if (i9 >= resetAndGetFirstSegment.length) {
                        resetAndGetFirstSegment = byteArrayBuilder.finishCurrentSegment();
                        i = 0;
                    } else {
                        i = i9;
                    }
                    i2 = i + 1;
                    resetAndGetFirstSegment[i] = (byte) (((charAt2 >> 6) & 63) | 128);
                    bArr = resetAndGetFirstSegment;
                    c = (charAt2 & '?') | 128;
                } else {
                    if (charAt2 > SURR1_LAST) {
                        _illegalSurrogate(charAt2);
                    }
                    if (i8 >= length) {
                        _illegalSurrogate(charAt2);
                    }
                    int i10 = i8 + 1;
                    int _convertSurrogate = _convertSurrogate(charAt2, str.charAt(i8));
                    if (_convertSurrogate > 1114111) {
                        _illegalSurrogate(_convertSurrogate);
                    }
                    int i11 = i6 + 1;
                    resetAndGetFirstSegment[i6] = (byte) ((_convertSurrogate >> 18) | 240);
                    if (i11 >= resetAndGetFirstSegment.length) {
                        resetAndGetFirstSegment = byteArrayBuilder.finishCurrentSegment();
                        i3 = 0;
                    } else {
                        i3 = i11;
                    }
                    int i12 = i3 + 1;
                    resetAndGetFirstSegment[i3] = (byte) (((_convertSurrogate >> 12) & 63) | 128);
                    if (i12 >= resetAndGetFirstSegment.length) {
                        resetAndGetFirstSegment = byteArrayBuilder.finishCurrentSegment();
                        i4 = 0;
                    } else {
                        i4 = i12;
                    }
                    i2 = i4 + 1;
                    resetAndGetFirstSegment[i4] = (byte) (((_convertSurrogate >> 6) & 63) | 128);
                    i8 = i10;
                    byte[] bArr2 = resetAndGetFirstSegment;
                    c = (_convertSurrogate & '?') | 128;
                    bArr = bArr2;
                }
                if (i2 >= bArr.length) {
                    bArr = byteArrayBuilder.finishCurrentSegment();
                    i2 = 0;
                }
                int i13 = i2 + 1;
                bArr[i2] = (byte) c;
                resetAndGetFirstSegment = bArr;
                i7 = i8;
                i6 = i13;
            }
        }
        return this._byteBuilder.completeAndCoalesce(i6);
    }

    public byte[] encodeAsUTF8(String str) {
        int i;
        int i2;
        int i3;
        int i4;
        int i5;
        ByteArrayBuilder byteArrayBuilder = this._byteBuilder;
        if (byteArrayBuilder == null) {
            byteArrayBuilder = new ByteArrayBuilder((BufferRecycler) null);
            this._byteBuilder = byteArrayBuilder;
        }
        int length = str.length();
        byte[] resetAndGetFirstSegment = byteArrayBuilder.resetAndGetFirstSegment();
        int length2 = resetAndGetFirstSegment.length;
        int i6 = 0;
        int i7 = 0;
        loop0:
        while (true) {
            if (i7 >= length) {
                i = i6;
                break;
            }
            int i8 = i7 + 1;
            char charAt = str.charAt(i7);
            int i9 = length2;
            byte[] bArr = resetAndGetFirstSegment;
            int i10 = i6;
            int i11 = i9;
            while (charAt <= 127) {
                if (i10 >= i11) {
                    bArr = byteArrayBuilder.finishCurrentSegment();
                    i11 = bArr.length;
                    i10 = 0;
                }
                int i12 = i10 + 1;
                bArr[i10] = (byte) charAt;
                if (i8 >= length) {
                    i = i12;
                    break loop0;
                }
                charAt = str.charAt(i8);
                i8++;
                i10 = i12;
            }
            if (i10 >= i11) {
                bArr = byteArrayBuilder.finishCurrentSegment();
                i11 = bArr.length;
                i2 = 0;
            } else {
                i2 = i10;
            }
            if (charAt < 2048) {
                i3 = i2 + 1;
                bArr[i2] = (byte) ((charAt >> 6) | 192);
                i4 = charAt;
                i7 = i8;
            } else if (charAt < SURR1_FIRST || charAt > SURR2_LAST) {
                int i13 = i2 + 1;
                bArr[i2] = (byte) ((charAt >> 12) | 224);
                if (i13 >= i11) {
                    bArr = byteArrayBuilder.finishCurrentSegment();
                    i11 = bArr.length;
                    i13 = 0;
                }
                bArr[i13] = (byte) (((charAt >> 6) & 63) | 128);
                i3 = i13 + 1;
                i4 = charAt;
                i7 = i8;
            } else {
                if (charAt > SURR1_LAST) {
                    _illegalSurrogate(charAt);
                }
                if (i8 >= length) {
                    _illegalSurrogate(charAt);
                }
                int i14 = i8 + 1;
                int _convertSurrogate = _convertSurrogate(charAt, str.charAt(i8));
                if (_convertSurrogate > 1114111) {
                    _illegalSurrogate(_convertSurrogate);
                }
                int i15 = i2 + 1;
                bArr[i2] = (byte) ((_convertSurrogate >> 18) | 240);
                if (i15 >= i11) {
                    bArr = byteArrayBuilder.finishCurrentSegment();
                    i11 = bArr.length;
                    i15 = 0;
                }
                int i16 = i15 + 1;
                bArr[i15] = (byte) (((_convertSurrogate >> 12) & 63) | 128);
                if (i16 >= i11) {
                    bArr = byteArrayBuilder.finishCurrentSegment();
                    i11 = bArr.length;
                    i5 = 0;
                } else {
                    i5 = i16;
                }
                bArr[i5] = (byte) (((_convertSurrogate >> 6) & 63) | 128);
                i3 = i5 + 1;
                i4 = _convertSurrogate;
                i7 = i14;
            }
            if (i3 >= i11) {
                bArr = byteArrayBuilder.finishCurrentSegment();
                i11 = bArr.length;
                i3 = 0;
            }
            int i17 = i3 + 1;
            bArr[i3] = (byte) ((i4 & 63) | 128);
            resetAndGetFirstSegment = bArr;
            length2 = i11;
            i6 = i17;
        }
        return this._byteBuilder.completeAndCoalesce(i);
    }

    private int _appendNumericEscape(int i, char[] cArr) {
        cArr[1] = 'u';
        cArr[4] = HEX_CHARS[i >> 4];
        cArr[5] = HEX_CHARS[i & 15];
        return 6;
    }

    private int _appendNamedEscape(int i, char[] cArr) {
        cArr[1] = (char) i;
        return 2;
    }

    private int _appendByteEscape(int i, int i2, ByteArrayBuilder byteArrayBuilder, int i3) {
        byteArrayBuilder.setCurrentSegmentLength(i3);
        byteArrayBuilder.append(92);
        if (i2 < 0) {
            byteArrayBuilder.append(117);
            if (i > 255) {
                int i4 = i >> 8;
                byteArrayBuilder.append(HEX_BYTES[i4 >> 4]);
                byteArrayBuilder.append(HEX_BYTES[i4 & 15]);
                i &= 255;
            } else {
                byteArrayBuilder.append(48);
                byteArrayBuilder.append(48);
            }
            byteArrayBuilder.append(HEX_BYTES[i >> 4]);
            byteArrayBuilder.append(HEX_BYTES[i & 15]);
        } else {
            byteArrayBuilder.append((byte) i2);
        }
        return byteArrayBuilder.getCurrentSegmentLength();
    }

    protected static int _convertSurrogate(int i, int i2) {
        if (i2 >= SURR2_FIRST && i2 <= SURR2_LAST) {
            return 65536 + ((i - SURR1_FIRST) << 10) + (i2 - SURR2_FIRST);
        }
        throw new IllegalArgumentException("Broken surrogate pair: first char 0x" + Integer.toHexString(i) + ", second 0x" + Integer.toHexString(i2) + "; illegal combination");
    }

    protected static void _illegalSurrogate(int i) {
        throw new IllegalArgumentException(UTF8Writer.illegalSurrogateDesc(i));
    }
}