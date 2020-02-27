package com.ning.http.client.websocket;

public class DefaultWebSocketListener implements WebSocketByteListener, WebSocketTextListener, WebSocketPingListener, WebSocketPongListener {
    protected WebSocket webSocket;

    public void onMessage(byte[] message) {
    }

    public void onFragment(byte[] fragment, boolean last) {
    }

    public void onPing(byte[] message) {
    }

    public void onPong(byte[] message) {
    }

    public void onMessage(String message) {
    }

    public void onFragment(String fragment, boolean last) {
    }

    public void onOpen(WebSocket websocket) {
        this.webSocket = websocket;
    }

    public void onClose(WebSocket websocket) {
        this.webSocket = null;
    }

    public void onError(Throwable t) {
    }
}