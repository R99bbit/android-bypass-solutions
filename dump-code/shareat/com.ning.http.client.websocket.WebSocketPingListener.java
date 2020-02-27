package com.ning.http.client.websocket;

public interface WebSocketPingListener extends WebSocketListener {
    void onPing(byte[] bArr);
}