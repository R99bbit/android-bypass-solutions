package org.jboss.netty.handler.stream;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import org.jboss.netty.buffer.ChannelBuffers;

public class ChunkedNioFile implements ChunkedInput {
    private final int chunkSize;
    private final long endOffset;
    private final FileChannel in;
    private long offset;
    private final long startOffset;

    public ChunkedNioFile(File in2) throws IOException {
        this(new FileInputStream(in2).getChannel());
    }

    public ChunkedNioFile(File in2, int chunkSize2) throws IOException {
        this(new FileInputStream(in2).getChannel(), chunkSize2);
    }

    public ChunkedNioFile(FileChannel in2) throws IOException {
        this(in2, 8192);
    }

    public ChunkedNioFile(FileChannel in2, int chunkSize2) throws IOException {
        this(in2, 0, in2.size(), chunkSize2);
    }

    public ChunkedNioFile(FileChannel in2, long offset2, long length, int chunkSize2) throws IOException {
        if (in2 == null) {
            throw new NullPointerException("in");
        } else if (offset2 < 0) {
            throw new IllegalArgumentException("offset: " + offset2 + " (expected: 0 or greater)");
        } else if (length < 0) {
            throw new IllegalArgumentException("length: " + length + " (expected: 0 or greater)");
        } else if (chunkSize2 <= 0) {
            throw new IllegalArgumentException("chunkSize: " + chunkSize2 + " (expected: a positive integer)");
        } else {
            if (offset2 != 0) {
                in2.position(offset2);
            }
            this.in = in2;
            this.chunkSize = chunkSize2;
            this.startOffset = offset2;
            this.offset = offset2;
            this.endOffset = offset2 + length;
        }
    }

    public long getStartOffset() {
        return this.startOffset;
    }

    public long getEndOffset() {
        return this.endOffset;
    }

    public long getCurrentOffset() {
        return this.offset;
    }

    public boolean hasNextChunk() throws Exception {
        return this.offset < this.endOffset && this.in.isOpen();
    }

    public boolean isEndOfInput() throws Exception {
        return !hasNextChunk();
    }

    public void close() throws Exception {
        this.in.close();
    }

    public Object nextChunk() throws Exception {
        long offset2 = this.offset;
        if (offset2 >= this.endOffset) {
            return null;
        }
        int chunkSize2 = (int) Math.min((long) this.chunkSize, this.endOffset - offset2);
        byte[] chunkArray = new byte[chunkSize2];
        ByteBuffer chunk = ByteBuffer.wrap(chunkArray);
        int readBytes = 0;
        do {
            int localReadBytes = this.in.read(chunk);
            if (localReadBytes < 0) {
                break;
            }
            readBytes += localReadBytes;
        } while (readBytes != chunkSize2);
        this.offset += (long) readBytes;
        return ChannelBuffers.wrappedBuffer(chunkArray);
    }
}