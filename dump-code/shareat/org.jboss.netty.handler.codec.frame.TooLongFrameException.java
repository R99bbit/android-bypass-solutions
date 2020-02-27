package org.jboss.netty.handler.codec.frame;

public class TooLongFrameException extends Exception {
    private static final long serialVersionUID = -1995801950698951640L;

    public TooLongFrameException() {
    }

    public TooLongFrameException(String message, Throwable cause) {
        super(message, cause);
    }

    public TooLongFrameException(String message) {
        super(message);
    }

    public TooLongFrameException(Throwable cause) {
        super(cause);
    }
}