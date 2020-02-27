package org.jboss.netty.handler.timeout;

public class ReadTimeoutException extends TimeoutException {
    private static final long serialVersionUID = -4596059237992273913L;

    public ReadTimeoutException() {
    }

    public ReadTimeoutException(String message, Throwable cause) {
        super(message, cause);
    }

    public ReadTimeoutException(String message) {
        super(message);
    }

    public ReadTimeoutException(Throwable cause) {
        super(cause);
    }
}