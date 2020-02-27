package org.jboss.netty.handler.timeout;

public class WriteTimeoutException extends TimeoutException {
    private static final long serialVersionUID = -7746685254523245218L;

    public WriteTimeoutException() {
    }

    public WriteTimeoutException(String message, Throwable cause) {
        super(message, cause);
    }

    public WriteTimeoutException(String message) {
        super(message);
    }

    public WriteTimeoutException(Throwable cause) {
        super(cause);
    }
}