package com.ning.http.client.generators;

import com.ning.http.client.Body;
import com.ning.http.client.BodyGenerator;
import java.io.IOException;
import java.nio.ByteBuffer;

public class ByteArrayBodyGenerator implements BodyGenerator {
    /* access modifiers changed from: private */
    public final byte[] bytes;

    protected final class ByteBody implements Body {
        private boolean eof = false;
        private int lastPosition = 0;

        protected ByteBody() {
        }

        public long getContentLength() {
            return (long) ByteArrayBodyGenerator.this.bytes.length;
        }

        public long read(ByteBuffer byteBuffer) throws IOException {
            if (this.eof) {
                return -1;
            }
            int remaining = ByteArrayBodyGenerator.this.bytes.length - this.lastPosition;
            if (remaining <= byteBuffer.capacity()) {
                byteBuffer.put(ByteArrayBodyGenerator.this.bytes, this.lastPosition, remaining);
                this.eof = true;
                return (long) remaining;
            }
            byteBuffer.put(ByteArrayBodyGenerator.this.bytes, this.lastPosition, byteBuffer.capacity());
            this.lastPosition += byteBuffer.capacity();
            return (long) byteBuffer.capacity();
        }

        public void close() throws IOException {
            this.lastPosition = 0;
            this.eof = false;
        }
    }

    public ByteArrayBodyGenerator(byte[] bytes2) {
        this.bytes = bytes2;
    }

    public Body createBody() throws IOException {
        return new ByteBody();
    }
}