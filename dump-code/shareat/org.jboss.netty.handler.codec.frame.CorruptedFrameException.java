package org.jboss.netty.handler.codec.frame;

public class CorruptedFrameException extends Exception {
    private static final long serialVersionUID = 3918052232492988408L;

    public CorruptedFrameException() {
    }

    public CorruptedFrameException(String message, Throwable cause) {
        super(message, cause);
    }

    public CorruptedFrameException(String message) {
        super(message);
    }

    public CorruptedFrameException(Throwable cause) {
        super(cause);
    }
}