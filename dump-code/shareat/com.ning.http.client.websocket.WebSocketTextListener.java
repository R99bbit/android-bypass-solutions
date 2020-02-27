package com.ning.http.client.websocket;

public interface WebSocketTextListener extends WebSocketListener {
    void onFragment(String str, boolean z);

    void onMessage(String str);
}