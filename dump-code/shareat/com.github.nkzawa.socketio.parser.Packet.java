package com.github.nkzawa.socketio.parser;

public class Packet<T> {
    public int attachments;
    public T data;
    public int id = -1;
    public String nsp;
    public int type = -1;

    public Packet() {
    }

    public Packet(int type2) {
        this.type = type2;
    }

    public Packet(int type2, T data2) {
        this.type = type2;
        this.data = data2;
    }
}