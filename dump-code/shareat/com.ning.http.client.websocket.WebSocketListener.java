package com.ning.http.client.websocket;

public interface WebSocketListener {
    void onClose(WebSocket webSocket);

    void onError(Throwable th);

    void onOpen(WebSocket webSocket);
}