package com.squareup.okhttp.ws;

import java.io.IOException;
import okio.Buffer;
import okio.BufferedSink;

public interface WebSocket {

    public enum PayloadType {
        TEXT,
        BINARY
    }

    void close(int i, String str) throws IOException;

    BufferedSink newMessageSink(PayloadType payloadType);

    void sendMessage(PayloadType payloadType, Buffer buffer) throws IOException;

    void sendPing(Buffer buffer) throws IOException;
}