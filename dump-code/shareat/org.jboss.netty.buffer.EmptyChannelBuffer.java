package org.jboss.netty.buffer;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.channels.GatheringByteChannel;
import java.nio.channels.ScatteringByteChannel;

public class EmptyChannelBuffer extends BigEndianHeapChannelBuffer {
    private static final byte[] BUFFER = new byte[0];

    EmptyChannelBuffer() {
        super(BUFFER);
    }

    public void clear() {
    }

    public void readerIndex(int readerIndex) {
        if (readerIndex != 0) {
            throw new IndexOutOfBoundsException("Invalid readerIndex: " + readerIndex + " - Maximum is 0");
        }
    }

    public void writerIndex(int writerIndex) {
        if (writerIndex != 0) {
            throw new IndexOutOfBoundsException("Invalid writerIndex: " + writerIndex + " - Maximum is 0");
        }
    }

    public void setIndex(int readerIndex, int writerIndex) {
        if (writerIndex != 0 || readerIndex != 0) {
            throw new IndexOutOfBoundsException("Invalid writerIndex: " + writerIndex + " - Maximum is " + readerIndex + " or " + capacity());
        }
    }

    public void markReaderIndex() {
    }

    public void resetReaderIndex() {
    }

    public void markWriterIndex() {
    }

    public void resetWriterIndex() {
    }

    public void discardReadBytes() {
    }

    public ChannelBuffer readBytes(int length) {
        checkReadableBytes(length);
        return this;
    }

    public ChannelBuffer readSlice(int length) {
        checkReadableBytes(length);
        return this;
    }

    public void readBytes(byte[] dst, int dstIndex, int length) {
        checkReadableBytes(length);
    }

    public void readBytes(byte[] dst) {
        checkReadableBytes(dst.length);
    }

    public void readBytes(ChannelBuffer dst) {
        checkReadableBytes(dst.writableBytes());
    }

    public void readBytes(ChannelBuffer dst, int length) {
        checkReadableBytes(length);
    }

    public void readBytes(ChannelBuffer dst, int dstIndex, int length) {
        checkReadableBytes(length);
    }

    public void readBytes(ByteBuffer dst) {
        checkReadableBytes(dst.remaining());
    }

    public int readBytes(GatheringByteChannel out, int length) throws IOException {
        checkReadableBytes(length);
        return 0;
    }

    public void readBytes(OutputStream out, int length) throws IOException {
        checkReadableBytes(length);
    }

    public void skipBytes(int length) {
        checkReadableBytes(length);
    }

    public void writeBytes(byte[] src, int srcIndex, int length) {
        checkWritableBytes(length);
    }

    public void writeBytes(ChannelBuffer src, int length) {
        checkWritableBytes(length);
    }

    public void writeBytes(ChannelBuffer src, int srcIndex, int length) {
        checkWritableBytes(length);
    }

    public void writeBytes(ByteBuffer src) {
        checkWritableBytes(src.remaining());
    }

    public int writeBytes(InputStream in, int length) throws IOException {
        checkWritableBytes(length);
        return 0;
    }

    public int writeBytes(ScatteringByteChannel in, int length) throws IOException {
        checkWritableBytes(length);
        return 0;
    }

    public void writeZero(int length) {
        checkWritableBytes(length);
    }

    private void checkWritableBytes(int length) {
        if (length != 0) {
            if (length > 0) {
                throw new IndexOutOfBoundsException("Writable bytes exceeded - Need " + length + ", maximum is " + 0);
            }
            throw new IndexOutOfBoundsException("length < 0");
        }
    }

    /* access modifiers changed from: protected */
    public void checkReadableBytes(int length) {
        if (length != 0) {
            if (length > 0) {
                throw new IndexOutOfBoundsException("Not enough readable bytes - Need " + length + ", maximum is " + readableBytes());
            }
            throw new IndexOutOfBoundsException("length < 0");
        }
    }
}