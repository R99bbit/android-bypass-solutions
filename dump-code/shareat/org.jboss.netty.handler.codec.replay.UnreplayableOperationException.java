package org.jboss.netty.handler.codec.replay;

public class UnreplayableOperationException extends UnsupportedOperationException {
    private static final long serialVersionUID = 8577363912862364021L;

    public UnreplayableOperationException() {
    }

    public UnreplayableOperationException(String message) {
        super(message);
    }

    public UnreplayableOperationException(Throwable cause) {
        super(cause);
    }

    public UnreplayableOperationException(String message, Throwable cause) {
        super(message, cause);
    }
}