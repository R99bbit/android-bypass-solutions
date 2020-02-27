package com.ning.http.client.websocket;

import java.io.Closeable;

public interface WebSocket extends Closeable {
    WebSocket addWebSocketListener(WebSocketListener webSocketListener);

    void close();

    boolean isOpen();

    WebSocket removeWebSocketListener(WebSocketListener webSocketListener);

    WebSocket sendMessage(byte[] bArr);

    WebSocket sendPing(byte[] bArr);

    WebSocket sendPong(byte[] bArr);

    WebSocket sendTextMessage(String str);

    WebSocket stream(byte[] bArr, int i, int i2, boolean z);

    WebSocket stream(byte[] bArr, boolean z);

    WebSocket streamText(String str, boolean z);
}