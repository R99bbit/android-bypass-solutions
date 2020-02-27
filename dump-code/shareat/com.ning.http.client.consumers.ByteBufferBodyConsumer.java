package com.ning.http.client.consumers;

import com.ning.http.client.BodyConsumer;
import java.io.IOException;
import java.nio.ByteBuffer;

public class ByteBufferBodyConsumer implements BodyConsumer {
    private final ByteBuffer byteBuffer;

    public ByteBufferBodyConsumer(ByteBuffer byteBuffer2) {
        this.byteBuffer = byteBuffer2;
    }

    public void consume(ByteBuffer byteBuffer2) throws IOException {
        byteBuffer2.put(byteBuffer2);
    }

    public void close() throws IOException {
        this.byteBuffer.flip();
    }
}