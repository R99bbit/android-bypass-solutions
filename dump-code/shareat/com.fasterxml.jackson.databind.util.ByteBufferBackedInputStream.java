package com.fasterxml.jackson.databind.util;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;

public class ByteBufferBackedInputStream extends InputStream {
    protected final ByteBuffer _buffer;

    public ByteBufferBackedInputStream(ByteBuffer byteBuffer) {
        this._buffer = byteBuffer;
    }

    public int available() {
        return this._buffer.remaining();
    }

    public int read() throws IOException {
        if (this._buffer.hasRemaining()) {
            return this._buffer.get() & 255;
        }
        return -1;
    }

    public int read(byte[] bArr, int i, int i2) throws IOException {
        if (!this._buffer.hasRemaining()) {
            return -1;
        }
        int min = Math.min(i2, this._buffer.remaining());
        this._buffer.get(bArr, i, min);
        return min;
    }
}