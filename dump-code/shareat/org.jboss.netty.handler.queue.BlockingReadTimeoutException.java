package org.jboss.netty.handler.queue;

import java.io.InterruptedIOException;

public class BlockingReadTimeoutException extends InterruptedIOException {
    private static final long serialVersionUID = 356009226872649493L;

    public BlockingReadTimeoutException() {
    }

    public BlockingReadTimeoutException(String message, Throwable cause) {
        super(message);
        initCause(cause);
    }

    public BlockingReadTimeoutException(String message) {
        super(message);
    }

    public BlockingReadTimeoutException(Throwable cause) {
        initCause(cause);
    }
}