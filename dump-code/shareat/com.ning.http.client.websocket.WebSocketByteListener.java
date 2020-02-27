package com.ning.http.client.websocket;

public interface WebSocketByteListener extends WebSocketListener {
    void onFragment(byte[] bArr, boolean z);

    void onMessage(byte[] bArr);
}