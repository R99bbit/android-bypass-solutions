package org.jboss.netty.channel;

public class ChannelHandlerLifeCycleException extends RuntimeException {
    private static final long serialVersionUID = 8764799996088850672L;

    public ChannelHandlerLifeCycleException() {
    }

    public ChannelHandlerLifeCycleException(String message, Throwable cause) {
        super(message, cause);
    }

    public ChannelHandlerLifeCycleException(String message) {
        super(message);
    }

    public ChannelHandlerLifeCycleException(Throwable cause) {
        super(cause);
    }
}