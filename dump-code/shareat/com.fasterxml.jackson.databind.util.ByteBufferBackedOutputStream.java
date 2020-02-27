package com.fasterxml.jackson.databind.util;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;

public class ByteBufferBackedOutputStream extends OutputStream {
    protected final ByteBuffer _buffer;

    public ByteBufferBackedOutputStream(ByteBuffer byteBuffer) {
        this._buffer = byteBuffer;
    }

    public void write(int i) throws IOException {
        this._buffer.put((byte) i);
    }

    public void write(byte[] bArr, int i, int i2) throws IOException {
        this._buffer.put(bArr, i, i2);
    }
}