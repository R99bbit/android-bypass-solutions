package com.ning.http.client.websocket;

public interface WebSocketCloseCodeReasonListener {
    void onClose(WebSocket webSocket, int i, String str);
}