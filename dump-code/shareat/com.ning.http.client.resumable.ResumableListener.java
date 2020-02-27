package com.ning.http.client.resumable;

import java.io.IOException;
import java.nio.ByteBuffer;

public interface ResumableListener {
    long length();

    void onAllBytesReceived();

    void onBytesReceived(ByteBuffer byteBuffer) throws IOException;
}