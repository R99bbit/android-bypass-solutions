package com.ning.http.client.extra;

import com.ning.http.client.resumable.ResumableListener;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ResumableRandomAccessFileListener implements ResumableListener {
    private static final Logger logger = LoggerFactory.getLogger(ThrottleRequestFilter.class);
    private final RandomAccessFile file;

    public ResumableRandomAccessFileListener(RandomAccessFile file2) {
        this.file = file2;
    }

    public void onBytesReceived(ByteBuffer buffer) throws IOException {
        this.file.seek(this.file.length());
        this.file.write(buffer.array());
    }

    public void onAllBytesReceived() {
        if (this.file != null) {
            try {
                this.file.close();
            } catch (IOException e) {
            }
        }
    }

    public long length() {
        try {
            return this.file.length();
        } catch (IOException e) {
            return 0;
        }
    }
}