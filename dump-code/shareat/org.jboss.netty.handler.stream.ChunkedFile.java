package org.jboss.netty.handler.stream;

import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import org.jboss.netty.buffer.ChannelBuffers;

public class ChunkedFile implements ChunkedInput {
    private final int chunkSize;
    private final long endOffset;
    private final RandomAccessFile file;
    private long offset;
    private final long startOffset;

    public ChunkedFile(File file2) throws IOException {
        this(file2, 8192);
    }

    public ChunkedFile(File file2, int chunkSize2) throws IOException {
        this(new RandomAccessFile(file2, "r"), chunkSize2);
    }

    public ChunkedFile(RandomAccessFile file2) throws IOException {
        this(file2, 8192);
    }

    public ChunkedFile(RandomAccessFile file2, int chunkSize2) throws IOException {
        this(file2, 0, file2.length(), chunkSize2);
    }

    public ChunkedFile(RandomAccessFile file2, long offset2, long length, int chunkSize2) throws IOException {
        if (file2 == null) {
            throw new NullPointerException("file");
        } else if (offset2 < 0) {
            throw new IllegalArgumentException("offset: " + offset2 + " (expected: 0 or greater)");
        } else if (length < 0) {
            throw new IllegalArgumentException("length: " + length + " (expected: 0 or greater)");
        } else if (chunkSize2 <= 0) {
            throw new IllegalArgumentException("chunkSize: " + chunkSize2 + " (expected: a positive integer)");
        } else {
            this.file = file2;
            this.startOffset = offset2;
            this.offset = offset2;
            this.endOffset = offset2 + length;
            this.chunkSize = chunkSize2;
            file2.seek(offset2);
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
        return this.offset < this.endOffset && this.file.getChannel().isOpen();
    }

    public boolean isEndOfInput() throws Exception {
        return !hasNextChunk();
    }

    public void close() throws Exception {
        this.file.close();
    }

    public Object nextChunk() throws Exception {
        long offset2 = this.offset;
        if (offset2 >= this.endOffset) {
            return null;
        }
        int chunkSize2 = (int) Math.min((long) this.chunkSize, this.endOffset - offset2);
        byte[] chunk = new byte[chunkSize2];
        this.file.readFully(chunk);
        this.offset = ((long) chunkSize2) + offset2;
        return ChannelBuffers.wrappedBuffer(chunk);
    }
}