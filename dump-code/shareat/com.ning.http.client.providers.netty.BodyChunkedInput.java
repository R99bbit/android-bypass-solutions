package com.ning.http.client.providers.netty;

import com.ning.http.client.Body;
import java.nio.ByteBuffer;
import org.jboss.netty.buffer.ChannelBuffers;
import org.jboss.netty.handler.stream.ChunkedInput;

class BodyChunkedInput implements ChunkedInput {
    private static final int DEFAULT_CHUNK_SIZE = 8192;
    private final Body body;
    private final int chunkSize;
    private final int contentLength;
    private boolean endOfInput;

    public BodyChunkedInput(Body body2) {
        if (body2 == null) {
            throw new IllegalArgumentException("no body specified");
        }
        this.body = body2;
        this.contentLength = (int) body2.getContentLength();
        if (this.contentLength <= 0) {
            this.chunkSize = 8192;
        } else {
            this.chunkSize = Math.min(this.contentLength, 8192);
        }
    }

    public boolean hasNextChunk() throws Exception {
        throw new UnsupportedOperationException();
    }

    public Object nextChunk() throws Exception {
        boolean z = true;
        if (this.endOfInput) {
            return null;
        }
        ByteBuffer buffer = ByteBuffer.allocate(this.chunkSize);
        long r = this.body.read(buffer);
        if (r < 0) {
            this.endOfInput = true;
            return null;
        }
        if (r != ((long) this.contentLength) && (r >= ((long) this.chunkSize) || this.contentLength <= 0)) {
            z = false;
        }
        this.endOfInput = z;
        buffer.flip();
        return ChannelBuffers.wrappedBuffer(buffer);
    }

    public boolean isEndOfInput() throws Exception {
        return this.endOfInput;
    }

    public void close() throws Exception {
        this.body.close();
    }
}