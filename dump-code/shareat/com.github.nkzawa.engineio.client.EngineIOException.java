package com.github.nkzawa.engineio.client;

public class EngineIOException extends Exception {
    public Object code;
    public String transport;

    public EngineIOException() {
    }

    public EngineIOException(String message) {
        super(message);
    }

    public EngineIOException(String message, Throwable cause) {
        super(message, cause);
    }

    public EngineIOException(Throwable cause) {
        super(cause);
    }
}