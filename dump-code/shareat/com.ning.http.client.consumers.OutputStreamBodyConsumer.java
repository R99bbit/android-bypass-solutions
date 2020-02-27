package com.ning.http.client.consumers;

import com.ning.http.client.BodyConsumer;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;

public class OutputStreamBodyConsumer implements BodyConsumer {
    private final OutputStream outputStream;

    public OutputStreamBodyConsumer(OutputStream outputStream2) {
        this.outputStream = outputStream2;
    }

    public void consume(ByteBuffer byteBuffer) throws IOException {
        this.outputStream.write(byteBuffer.array(), byteBuffer.arrayOffset() + byteBuffer.position(), byteBuffer.remaining());
    }

    public void close() throws IOException {
        this.outputStream.close();
    }
}