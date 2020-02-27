package org.jboss.netty.handler.stream;

import java.io.InputStream;
import java.io.PushbackInputStream;
import org.jboss.netty.buffer.ChannelBuffers;

public class ChunkedStream implements ChunkedInput {
    static final int DEFAULT_CHUNK_SIZE = 8192;
    private final int chunkSize;
    private final PushbackInputStream in;
    private long offset;

    public ChunkedStream(InputStream in2) {
        this(in2, 8192);
    }

    public ChunkedStream(InputStream in2, int chunkSize2) {
        if (in2 == null) {
            throw new NullPointerException("in");
        } else if (chunkSize2 <= 0) {
            throw new IllegalArgumentException("chunkSize: " + chunkSize2 + " (expected: a positive integer)");
        } else {
            if (in2 instanceof PushbackInputStream) {
                this.in = (PushbackInputStream) in2;
            } else {
                this.in = new PushbackInputStream(in2);
            }
            this.chunkSize = chunkSize2;
        }
    }

    public long getTransferredBytes() {
        return this.offset;
    }

    public boolean hasNextChunk() throws Exception {
        int b = this.in.read();
        if (b < 0) {
            return false;
        }
        this.in.unread(b);
        return true;
    }

    public boolean isEndOfInput() throws Exception {
        return !hasNextChunk();
    }

    public void close() throws Exception {
        this.in.close();
    }

    public Object nextChunk() throws Exception {
        int chunkSize2;
        if (!hasNextChunk()) {
            return null;
        }
        if (this.in.available() <= 0) {
            chunkSize2 = this.chunkSize;
        } else {
            chunkSize2 = Math.min(this.chunkSize, this.in.available());
        }
        byte[] chunk = new byte[chunkSize2];
        int readBytes = 0;
        do {
            int localReadBytes = this.in.read(chunk, readBytes, chunkSize2 - readBytes);
            if (localReadBytes < 0) {
                break;
            }
            readBytes += localReadBytes;
            this.offset += (long) localReadBytes;
        } while (readBytes != chunkSize2);
        return ChannelBuffers.wrappedBuffer(chunk, 0, readBytes);
    }
}