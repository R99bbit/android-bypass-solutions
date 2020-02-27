package com.fasterxml.jackson.core.io;

import java.io.IOException;
import java.io.OutputStream;
import java.io.Writer;

public final class UTF8Writer extends Writer {
    static final int SURR1_FIRST = 55296;
    static final int SURR1_LAST = 56319;
    static final int SURR2_FIRST = 56320;
    static final int SURR2_LAST = 57343;
    private final IOContext _context;
    private OutputStream _out;
    private byte[] _outBuffer;
    private final int _outBufferEnd;
    private int _outPtr;
    private int _surrogate = 0;

    public UTF8Writer(IOContext iOContext, OutputStream outputStream) {
        this._context = iOContext;
        this._out = outputStream;
        this._outBuffer = iOContext.allocWriteEncodingBuffer();
        this._outBufferEnd = this._outBuffer.length - 4;
        this._outPtr = 0;
    }

    public Writer append(char c) throws IOException {
        write((int) c);
        return this;
    }

    public void close() throws IOException {
        if (this._out != null) {
            if (this._outPtr > 0) {
                this._out.write(this._outBuffer, 0, this._outPtr);
                this._outPtr = 0;
            }
            OutputStream outputStream = this._out;
            this._out = null;
            byte[] bArr = this._outBuffer;
            if (bArr != null) {
                this._outBuffer = null;
                this._context.releaseWriteEncodingBuffer(bArr);
            }
            outputStream.close();
            int i = this._surrogate;
            this._surrogate = 0;
            if (i > 0) {
                illegalSurrogate(i);
            }
        }
    }

    public void flush() throws IOException {
        if (this._out != null) {
            if (this._outPtr > 0) {
                this._out.write(this._outBuffer, 0, this._outPtr);
                this._outPtr = 0;
            }
            this._out.flush();
        }
    }

    public void write(char[] cArr) throws IOException {
        write(cArr, 0, cArr.length);
    }

    public void write(char[] cArr, int i, int i2) throws IOException {
        char c;
        if (i2 >= 2) {
            if (this._surrogate > 0) {
                i2--;
                write(convertSurrogate(cArr[i]));
                i++;
            }
            int i3 = this._outPtr;
            byte[] bArr = this._outBuffer;
            int i4 = this._outBufferEnd;
            int i5 = i2 + i;
            int i6 = i;
            while (i6 < i5) {
                if (i3 >= i4) {
                    this._out.write(bArr, 0, i3);
                    i3 = 0;
                }
                int i7 = i6 + 1;
                char c2 = cArr[i6];
                if (c2 < 128) {
                    int i8 = i3 + 1;
                    bArr[i3] = (byte) c2;
                    int i9 = i5 - i7;
                    int i10 = i4 - i8;
                    if (i9 <= i10) {
                        i10 = i9;
                    }
                    int i11 = i10 + i7;
                    int i12 = i8;
                    int i13 = i7;
                    while (i13 < i11) {
                        int i14 = i13 + 1;
                        char c3 = cArr[i13];
                        if (c3 >= 128) {
                            char c4 = c3;
                            i3 = i12;
                            i6 = i14;
                            c = c4;
                        } else {
                            bArr[i12] = (byte) c3;
                            i12++;
                            i13 = i14;
                        }
                    }
                    int i15 = i12;
                    i6 = i13;
                    i3 = i15;
                } else {
                    char c5 = c2;
                    i6 = i7;
                    c = c5;
                }
                if (c < 2048) {
                    int i16 = i3 + 1;
                    bArr[i3] = (byte) ((c >> 6) | 192);
                    i3 = i16 + 1;
                    bArr[i16] = (byte) ((c & '?') | 128);
                } else if (c < SURR1_FIRST || c > SURR2_LAST) {
                    int i17 = i3 + 1;
                    bArr[i3] = (byte) ((c >> 12) | 224);
                    int i18 = i17 + 1;
                    bArr[i17] = (byte) (((c >> 6) & 63) | 128);
                    i3 = i18 + 1;
                    bArr[i18] = (byte) ((c & '?') | 128);
                } else {
                    if (c > SURR1_LAST) {
                        this._outPtr = i3;
                        illegalSurrogate(c);
                    }
                    this._surrogate = c;
                    if (i6 >= i5) {
                        break;
                    }
                    int i19 = i6 + 1;
                    int convertSurrogate = convertSurrogate(cArr[i6]);
                    if (convertSurrogate > 1114111) {
                        this._outPtr = i3;
                        illegalSurrogate(convertSurrogate);
                    }
                    int i20 = i3 + 1;
                    bArr[i3] = (byte) ((convertSurrogate >> 18) | 240);
                    int i21 = i20 + 1;
                    bArr[i20] = (byte) (((convertSurrogate >> 12) & 63) | 128);
                    int i22 = i21 + 1;
                    bArr[i21] = (byte) (((convertSurrogate >> 6) & 63) | 128);
                    i3 = i22 + 1;
                    bArr[i22] = (byte) ((convertSurrogate & 63) | 128);
                    i6 = i19;
                }
            }
            this._outPtr = i3;
        } else if (i2 == 1) {
            write((int) cArr[i]);
        }
    }

    public void write(int i) throws IOException {
        int i2;
        if (this._surrogate > 0) {
            i = convertSurrogate(i);
        } else if (i >= SURR1_FIRST && i <= SURR2_LAST) {
            if (i > SURR1_LAST) {
                illegalSurrogate(i);
            }
            this._surrogate = i;
            return;
        }
        if (this._outPtr >= this._outBufferEnd) {
            this._out.write(this._outBuffer, 0, this._outPtr);
            this._outPtr = 0;
        }
        if (i < 128) {
            byte[] bArr = this._outBuffer;
            int i3 = this._outPtr;
            this._outPtr = i3 + 1;
            bArr[i3] = (byte) i;
            return;
        }
        int i4 = this._outPtr;
        if (i < 2048) {
            int i5 = i4 + 1;
            this._outBuffer[i4] = (byte) ((i >> 6) | 192);
            i2 = i5 + 1;
            this._outBuffer[i5] = (byte) ((i & 63) | 128);
        } else if (i <= 65535) {
            int i6 = i4 + 1;
            this._outBuffer[i4] = (byte) ((i >> 12) | 224);
            int i7 = i6 + 1;
            this._outBuffer[i6] = (byte) (((i >> 6) & 63) | 128);
            i2 = i7 + 1;
            this._outBuffer[i7] = (byte) ((i & 63) | 128);
        } else {
            if (i > 1114111) {
                illegalSurrogate(i);
            }
            int i8 = i4 + 1;
            this._outBuffer[i4] = (byte) ((i >> 18) | 240);
            int i9 = i8 + 1;
            this._outBuffer[i8] = (byte) (((i >> 12) & 63) | 128);
            int i10 = i9 + 1;
            this._outBuffer[i9] = (byte) (((i >> 6) & 63) | 128);
            i2 = i10 + 1;
            this._outBuffer[i10] = (byte) ((i & 63) | 128);
        }
        this._outPtr = i2;
    }

    public void write(String str) throws IOException {
        write(str, 0, str.length());
    }

    public void write(String str, int i, int i2) throws IOException {
        char c;
        if (i2 >= 2) {
            if (this._surrogate > 0) {
                i2--;
                write(convertSurrogate(str.charAt(i)));
                i++;
            }
            int i3 = this._outPtr;
            byte[] bArr = this._outBuffer;
            int i4 = this._outBufferEnd;
            int i5 = i2 + i;
            int i6 = i;
            while (i6 < i5) {
                if (i3 >= i4) {
                    this._out.write(bArr, 0, i3);
                    i3 = 0;
                }
                int i7 = i6 + 1;
                char charAt = str.charAt(i6);
                if (charAt < 128) {
                    int i8 = i3 + 1;
                    bArr[i3] = (byte) charAt;
                    int i9 = i5 - i7;
                    int i10 = i4 - i8;
                    if (i9 <= i10) {
                        i10 = i9;
                    }
                    int i11 = i10 + i7;
                    int i12 = i8;
                    int i13 = i7;
                    while (i13 < i11) {
                        int i14 = i13 + 1;
                        char charAt2 = str.charAt(i13);
                        if (charAt2 >= 128) {
                            char c2 = charAt2;
                            i3 = i12;
                            i6 = i14;
                            c = c2;
                        } else {
                            bArr[i12] = (byte) charAt2;
                            i12++;
                            i13 = i14;
                        }
                    }
                    int i15 = i12;
                    i6 = i13;
                    i3 = i15;
                } else {
                    char c3 = charAt;
                    i6 = i7;
                    c = c3;
                }
                if (c < 2048) {
                    int i16 = i3 + 1;
                    bArr[i3] = (byte) ((c >> 6) | 192);
                    i3 = i16 + 1;
                    bArr[i16] = (byte) ((c & '?') | 128);
                } else if (c < SURR1_FIRST || c > SURR2_LAST) {
                    int i17 = i3 + 1;
                    bArr[i3] = (byte) ((c >> 12) | 224);
                    int i18 = i17 + 1;
                    bArr[i17] = (byte) (((c >> 6) & 63) | 128);
                    i3 = i18 + 1;
                    bArr[i18] = (byte) ((c & '?') | 128);
                } else {
                    if (c > SURR1_LAST) {
                        this._outPtr = i3;
                        illegalSurrogate(c);
                    }
                    this._surrogate = c;
                    if (i6 >= i5) {
                        break;
                    }
                    int i19 = i6 + 1;
                    int convertSurrogate = convertSurrogate(str.charAt(i6));
                    if (convertSurrogate > 1114111) {
                        this._outPtr = i3;
                        illegalSurrogate(convertSurrogate);
                    }
                    int i20 = i3 + 1;
                    bArr[i3] = (byte) ((convertSurrogate >> 18) | 240);
                    int i21 = i20 + 1;
                    bArr[i20] = (byte) (((convertSurrogate >> 12) & 63) | 128);
                    int i22 = i21 + 1;
                    bArr[i21] = (byte) (((convertSurrogate >> 6) & 63) | 128);
                    i3 = i22 + 1;
                    bArr[i22] = (byte) ((convertSurrogate & 63) | 128);
                    i6 = i19;
                }
            }
            this._outPtr = i3;
        } else if (i2 == 1) {
            write((int) str.charAt(i));
        }
    }

    /* access modifiers changed from: protected */
    public int convertSurrogate(int i) throws IOException {
        int i2 = this._surrogate;
        this._surrogate = 0;
        if (i >= SURR2_FIRST && i <= SURR2_LAST) {
            return ((i2 - SURR1_FIRST) << 10) + 65536 + (i - SURR2_FIRST);
        }
        throw new IOException("Broken surrogate pair: first char 0x" + Integer.toHexString(i2) + ", second 0x" + Integer.toHexString(i) + "; illegal combination");
    }

    protected static void illegalSurrogate(int i) throws IOException {
        throw new IOException(illegalSurrogateDesc(i));
    }

    protected static String illegalSurrogateDesc(int i) {
        if (i > 1114111) {
            return "Illegal character point (0x" + Integer.toHexString(i) + ") to output; max is 0x10FFFF as per RFC 4627";
        }
        if (i < SURR1_FIRST) {
            return "Illegal character point (0x" + Integer.toHexString(i) + ") to output";
        }
        if (i <= SURR1_LAST) {
            return "Unmatched first part of surrogate pair (0x" + Integer.toHexString(i) + ")";
        }
        return "Unmatched second part of surrogate pair (0x" + Integer.toHexString(i) + ")";
    }
}