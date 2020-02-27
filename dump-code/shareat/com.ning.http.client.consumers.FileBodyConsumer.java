package com.ning.http.client.consumers;

import com.ning.http.client.ResumableBodyConsumer;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;

public class FileBodyConsumer implements ResumableBodyConsumer {
    private final RandomAccessFile file;

    public FileBodyConsumer(RandomAccessFile file2) {
        this.file = file2;
    }

    public void consume(ByteBuffer byteBuffer) throws IOException {
        this.file.write(byteBuffer.array(), byteBuffer.arrayOffset() + byteBuffer.position(), byteBuffer.remaining());
    }

    public void close() throws IOException {
        this.file.close();
    }

    public long getTransferredBytes() throws IOException {
        return this.file.length();
    }

    public void resume() throws IOException {
        this.file.seek(getTransferredBytes());
    }
}