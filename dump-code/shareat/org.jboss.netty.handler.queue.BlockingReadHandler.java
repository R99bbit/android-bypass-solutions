package org.jboss.netty.handler.queue;

import java.io.IOException;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import org.jboss.netty.channel.ChannelEvent;
import org.jboss.netty.channel.ChannelHandlerContext;
import org.jboss.netty.channel.ChannelStateEvent;
import org.jboss.netty.channel.ExceptionEvent;
import org.jboss.netty.channel.MessageEvent;
import org.jboss.netty.channel.SimpleChannelUpstreamHandler;
import org.jboss.netty.util.internal.DeadLockProofWorker;

public class BlockingReadHandler<E> extends SimpleChannelUpstreamHandler {
    static final /* synthetic */ boolean $assertionsDisabled = (!BlockingReadHandler.class.desiredAssertionStatus());
    private volatile boolean closed;
    private final BlockingQueue<ChannelEvent> queue;

    public BlockingReadHandler() {
        this(new LinkedBlockingQueue());
    }

    public BlockingReadHandler(BlockingQueue<ChannelEvent> queue2) {
        if (queue2 == null) {
            throw new NullPointerException("queue");
        }
        this.queue = queue2;
    }

    /* access modifiers changed from: protected */
    public BlockingQueue<ChannelEvent> getQueue() {
        return this.queue;
    }

    public boolean isClosed() {
        return this.closed;
    }

    public E read() throws IOException, InterruptedException {
        ChannelEvent e = readEvent();
        if (e == null) {
            return null;
        }
        if (e instanceof MessageEvent) {
            return getMessage((MessageEvent) e);
        }
        if (e instanceof ExceptionEvent) {
            throw ((IOException) new IOException().initCause(((ExceptionEvent) e).getCause()));
        }
        throw new IllegalStateException();
    }

    public E read(long timeout, TimeUnit unit) throws IOException, InterruptedException {
        ChannelEvent e = readEvent(timeout, unit);
        if (e == null) {
            return null;
        }
        if (e instanceof MessageEvent) {
            return getMessage((MessageEvent) e);
        }
        if (e instanceof ExceptionEvent) {
            throw ((IOException) new IOException().initCause(((ExceptionEvent) e).getCause()));
        }
        throw new IllegalStateException();
    }

    public ChannelEvent readEvent() throws InterruptedException {
        detectDeadLock();
        if (isClosed() && getQueue().isEmpty()) {
            return null;
        }
        ChannelEvent e = getQueue().take();
        if (!(e instanceof ChannelStateEvent)) {
            return e;
        }
        if ($assertionsDisabled || this.closed) {
            return null;
        }
        throw new AssertionError();
    }

    public ChannelEvent readEvent(long timeout, TimeUnit unit) throws InterruptedException, BlockingReadTimeoutException {
        detectDeadLock();
        if (isClosed() && getQueue().isEmpty()) {
            return null;
        }
        ChannelEvent e = getQueue().poll(timeout, unit);
        if (e == null) {
            throw new BlockingReadTimeoutException();
        } else if (!(e instanceof ChannelStateEvent)) {
            return e;
        } else {
            if ($assertionsDisabled || this.closed) {
                return null;
            }
            throw new AssertionError();
        }
    }

    private static void detectDeadLock() {
        if (DeadLockProofWorker.PARENT.get() != null) {
            throw new IllegalStateException("read*(...) in I/O thread causes a dead lock or sudden performance drop. Implement a state machine or call read*() from a different thread.");
        }
    }

    public void messageReceived(ChannelHandlerContext ctx, MessageEvent e) throws Exception {
        getQueue().put(e);
    }

    public void exceptionCaught(ChannelHandlerContext ctx, ExceptionEvent e) throws Exception {
        getQueue().put(e);
    }

    public void channelClosed(ChannelHandlerContext ctx, ChannelStateEvent e) throws Exception {
        this.closed = true;
        getQueue().put(e);
    }

    private E getMessage(MessageEvent e) {
        return e.getMessage();
    }
}