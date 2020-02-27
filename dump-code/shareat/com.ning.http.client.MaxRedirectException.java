package com.ning.http.client;

public class MaxRedirectException extends Exception {
    private static final long serialVersionUID = 1;

    public MaxRedirectException() {
    }

    public MaxRedirectException(String msg) {
        super(msg);
    }

    public MaxRedirectException(Throwable cause) {
        super(cause);
    }

    public MaxRedirectException(String message, Throwable cause) {
        super(message, cause);
    }
}