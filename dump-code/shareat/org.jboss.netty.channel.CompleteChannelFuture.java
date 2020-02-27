package org.jboss.netty.channel;

import java.util.concurrent.TimeUnit;
import org.jboss.netty.logging.InternalLogger;
import org.jboss.netty.logging.InternalLoggerFactory;

public abstract class CompleteChannelFuture implements ChannelFuture {
    private static final InternalLogger logger = InternalLoggerFactory.getInstance(CompleteChannelFuture.class);
    private final Channel channel;

    protected CompleteChannelFuture(Channel channel2) {
        if (channel2 == null) {
            throw new NullPointerException("channel");
        }
        this.channel = channel2;
    }

    public void addListener(ChannelFutureListener listener) {
        try {
            listener.operationComplete(this);
        } catch (Throwable t) {
            if (logger.isWarnEnabled()) {
                logger.warn("An exception was thrown by " + ChannelFutureListener.class.getSimpleName() + '.', t);
            }
        }
    }

    public void removeListener(ChannelFutureListener listener) {
    }

    public ChannelFuture await() throws InterruptedException {
        if (!Thread.interrupted()) {
            return this;
        }
        throw new InterruptedException();
    }

    public boolean await(long timeout, TimeUnit unit) throws InterruptedException {
        if (!Thread.interrupted()) {
            return true;
        }
        throw new InterruptedException();
    }

    public boolean await(long timeoutMillis) throws InterruptedException {
        if (!Thread.interrupted()) {
            return true;
        }
        throw new InterruptedException();
    }

    public ChannelFuture awaitUninterruptibly() {
        return this;
    }

    public boolean awaitUninterruptibly(long timeout, TimeUnit unit) {
        return true;
    }

    public boolean awaitUninterruptibly(long timeoutMillis) {
        return true;
    }

    public Channel getChannel() {
        return this.channel;
    }

    public boolean isDone() {
        return true;
    }

    public boolean setProgress(long amount, long current, long total) {
        return false;
    }

    public boolean setFailure(Throwable cause) {
        return false;
    }

    public boolean setSuccess() {
        return false;
    }

    public boolean cancel() {
        return false;
    }

    public boolean isCancelled() {
        return false;
    }
}