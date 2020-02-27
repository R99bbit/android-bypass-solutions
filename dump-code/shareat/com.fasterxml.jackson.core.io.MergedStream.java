package com.fasterxml.jackson.core.io;

import java.io.IOException;
import java.io.InputStream;

public final class MergedStream extends InputStream {
    byte[] _buffer;
    protected final IOContext _context;
    final int _end;
    final InputStream _in;
    int _ptr;

    public MergedStream(IOContext iOContext, InputStream inputStream, byte[] bArr, int i, int i2) {
        this._context = iOContext;
        this._in = inputStream;
        this._buffer = bArr;
        this._ptr = i;
        this._end = i2;
    }

    public int available() throws IOException {
        if (this._buffer != null) {
            return this._end - this._ptr;
        }
        return this._in.available();
    }

    public void close() throws IOException {
        freeMergedBuffer();
        this._in.close();
    }

    public void mark(int i) {
        if (this._buffer == null) {
            this._in.mark(i);
        }
    }

    public boolean markSupported() {
        return this._buffer == null && this._in.markSupported();
    }

    public int read() throws IOException {
        if (this._buffer == null) {
            return this._in.read();
        }
        byte[] bArr = this._buffer;
        int i = this._ptr;
        this._ptr = i + 1;
        byte b = bArr[i] & 255;
        if (this._ptr < this._end) {
            return b;
        }
        freeMergedBuffer();
        return b;
    }

    public int read(byte[] bArr) throws IOException {
        return read(bArr, 0, bArr.length);
    }

    public int read(byte[] bArr, int i, int i2) throws IOException {
        if (this._buffer == null) {
            return this._in.read(bArr, i, i2);
        }
        int i3 = this._end - this._ptr;
        if (i2 > i3) {
            i2 = i3;
        }
        System.arraycopy(this._buffer, this._ptr, bArr, i, i2);
        this._ptr += i2;
        if (this._ptr < this._end) {
            return i2;
        }
        freeMergedBuffer();
        return i2;
    }

    public void reset() throws IOException {
        if (this._buffer == null) {
            this._in.reset();
        }
    }

    public long skip(long j) throws IOException {
        long j2;
        if (this._buffer != null) {
            int i = this._end - this._ptr;
            if (((long) i) > j) {
                this._ptr += (int) j;
                return j;
            }
            freeMergedBuffer();
            j2 = ((long) i) + 0;
            j -= (long) i;
        } else {
            j2 = 0;
        }
        if (j > 0) {
            j2 += this._in.skip(j);
        }
        return j2;
    }

    private void freeMergedBuffer() {
        byte[] bArr = this._buffer;
        if (bArr != null) {
            this._buffer = null;
            if (this._context != null) {
                this._context.releaseReadIOBuffer(bArr);
            }
        }
    }
}