package org.jboss.netty.handler.timeout;

import org.jboss.netty.channel.ChannelException;

public class TimeoutException extends ChannelException {
    private static final long serialVersionUID = 4673641882869672533L;

    public TimeoutException() {
    }

    public TimeoutException(String message, Throwable cause) {
        super(message, cause);
    }

    public TimeoutException(String message) {
        super(message);
    }

    public TimeoutException(Throwable cause) {
        super(cause);
    }
}