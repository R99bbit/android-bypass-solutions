package com.nuvent.shareat.event;

public class SocketReceiveEvent {
    private int key;
    private String params;

    public SocketReceiveEvent(int key2, String params2) {
        this.key = key2;
        this.params = params2;
    }

    public int getKey() {
        return this.key;
    }

    public String getParams() {
        return this.params;
    }
}