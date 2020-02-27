package com.ning.http.client.generators;

import com.ning.http.client.BodyGenerator;
import com.ning.http.client.RandomAccessBody;
import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.WritableByteChannel;

public class FileBodyGenerator implements BodyGenerator {
    private final File file;
    private final long regionLength;
    private final long regionSeek;

    protected static class FileBody implements RandomAccessBody {
        private final FileChannel channel = this.file.getChannel();
        private final RandomAccessFile file;
        private final long length;

        public FileBody(File file2) throws IOException {
            this.file = new RandomAccessFile(file2, "r");
            this.length = file2.length();
        }

        public FileBody(File file2, long regionSeek, long regionLength) throws IOException {
            this.file = new RandomAccessFile(file2, "r");
            this.length = regionLength;
            if (regionSeek > 0) {
                this.file.seek(regionSeek);
            }
        }

        public long getContentLength() {
            return this.length;
        }

        public long read(ByteBuffer buffer) throws IOException {
            return (long) this.channel.read(buffer);
        }

        public long transferTo(long position, long count, WritableByteChannel target) throws IOException {
            if (count > this.length) {
                count = this.length;
            }
            return this.channel.transferTo(position, count, target);
        }

        public void close() throws IOException {
            this.file.close();
        }
    }

    public FileBodyGenerator(File file2) {
        if (file2 == null) {
            throw new IllegalArgumentException("no file specified");
        }
        this.file = file2;
        this.regionLength = file2.length();
        this.regionSeek = 0;
    }

    public FileBodyGenerator(File file2, long regionSeek2, long regionLength2) {
        if (file2 == null) {
            throw new IllegalArgumentException("no file specified");
        }
        this.file = file2;
        this.regionLength = regionLength2;
        this.regionSeek = regionSeek2;
    }

    public RandomAccessBody createBody() throws IOException {
        return new FileBody(this.file, this.regionSeek, this.regionLength);
    }
}