package com.nuvent.shareat.exception;

public class NetworkException extends Exception {
    private String message;

    public NetworkException() {
    }

    public NetworkException(Throwable error, String message2) {
        super(error);
        this.message = message2;
    }

    public String getMessage() {
        return super.getMessage() + " " + this.message;
    }

    public String toString() {
        return super.getMessage() + " " + this.message;
    }
}