package org.jboss.netty.channel;

import org.jboss.netty.util.internal.StackTraceSimplifier;

public class DefaultExceptionEvent implements ExceptionEvent {
    private final Throwable cause;
    private final Channel channel;

    public DefaultExceptionEvent(Channel channel2, Throwable cause2) {
        if (channel2 == null) {
            throw new NullPointerException("channel");
        } else if (cause2 == null) {
            throw new NullPointerException("cause");
        } else {
            this.channel = channel2;
            this.cause = cause2;
            StackTraceSimplifier.simplify(cause2);
        }
    }

    public Channel getChannel() {
        return this.channel;
    }

    public ChannelFuture getFuture() {
        return Channels.succeededFuture(getChannel());
    }

    public Throwable getCause() {
        return this.cause;
    }

    public String toString() {
        return getChannel().toString() + " EXCEPTION: " + this.cause;
    }
}