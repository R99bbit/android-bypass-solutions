package com.github.nkzawa.engineio.parser;

public class Packet<T> {
    public static final String CLOSE = "close";
    public static final String ERROR = "error";
    public static final String MESSAGE = "message";
    public static final String NOOP = "noop";
    public static final String OPEN = "open";
    public static final String PING = "ping";
    public static final String PONG = "pong";
    public static final String UPGRADE = "upgrade";
    public T data;
    public String type;

    public Packet(String type2) {
        this(type2, null);
    }

    public Packet(String type2, T data2) {
        this.type = type2;
        this.data = data2;
    }
}