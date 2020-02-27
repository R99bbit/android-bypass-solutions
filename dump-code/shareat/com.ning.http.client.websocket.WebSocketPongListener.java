package com.ning.http.client.websocket;

public interface WebSocketPongListener extends WebSocketListener {
    void onPong(byte[] bArr);
}