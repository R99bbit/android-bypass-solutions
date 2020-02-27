package com.ning.http.client;

import java.io.IOException;
import java.nio.ByteBuffer;

public interface BodyConsumer {
    void close() throws IOException;

    void consume(ByteBuffer byteBuffer) throws IOException;
}