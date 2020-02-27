package com.ning.http.client;

import java.io.IOException;
import java.nio.ByteBuffer;

public interface Body {
    void close() throws IOException;

    long getContentLength();

    long read(ByteBuffer byteBuffer) throws IOException;
}