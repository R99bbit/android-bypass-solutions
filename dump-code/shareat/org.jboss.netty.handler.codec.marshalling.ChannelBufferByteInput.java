package org.jboss.netty.handler.codec.marshalling;

import java.io.IOException;
import org.jboss.marshalling.ByteInput;
import org.jboss.netty.buffer.ChannelBuffer;

class ChannelBufferByteInput implements ByteInput {
    private final ChannelBuffer buffer;

    public ChannelBufferByteInput(ChannelBuffer buffer2) {
        this.buffer = buffer2;
    }

    public void close() throws IOException {
    }

    public int available() throws IOException {
        return this.buffer.readableBytes();
    }

    public int read() throws IOException {
        if (this.buffer.readable()) {
            return this.buffer.readByte() & 255;
        }
        return -1;
    }

    public int read(byte[] array) throws IOException {
        return read(array, 0, array.length);
    }

    public int read(byte[] dst, int dstIndex, int length) throws IOException {
        int available = available();
        if (available == 0) {
            return -1;
        }
        int length2 = Math.min(available, length);
        this.buffer.readBytes(dst, dstIndex, length2);
        return length2;
    }

    public long skip(long bytes) throws IOException {
        int readable = this.buffer.readableBytes();
        if (((long) readable) < bytes) {
            bytes = (long) readable;
        }
        this.buffer.readerIndex((int) (((long) this.buffer.readerIndex()) + bytes));
        return bytes;
    }
}