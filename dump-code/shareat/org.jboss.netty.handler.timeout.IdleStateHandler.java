package org.jboss.netty.handler.timeout;

import java.util.concurrent.TimeUnit;
import org.jboss.netty.channel.ChannelHandler.Sharable;
import org.jboss.netty.channel.ChannelHandlerContext;
import org.jboss.netty.channel.ChannelStateEvent;
import org.jboss.netty.channel.Channels;
import org.jboss.netty.channel.LifeCycleAwareChannelHandler;
import org.jboss.netty.channel.MessageEvent;
import org.jboss.netty.channel.SimpleChannelUpstreamHandler;
import org.jboss.netty.channel.WriteCompletionEvent;
import org.jboss.netty.util.ExternalResourceReleasable;
import org.jboss.netty.util.Timeout;
import org.jboss.netty.util.Timer;
import org.jboss.netty.util.TimerTask;

@Sharable
public class IdleStateHandler extends SimpleChannelUpstreamHandler implements LifeCycleAwareChannelHandler, ExternalResourceReleasable {
    final long allIdleTimeMillis;
    final long readerIdleTimeMillis;
    final Timer timer;
    final long writerIdleTimeMillis;

    private final class AllIdleTimeoutTask implements TimerTask {
        private final ChannelHandlerContext ctx;

        AllIdleTimeoutTask(ChannelHandlerContext ctx2) {
            this.ctx = ctx2;
        }

        public void run(Timeout timeout) throws Exception {
            if (!timeout.isCancelled() && this.ctx.getChannel().isOpen()) {
                State state = (State) this.ctx.getAttachment();
                long currentTime = System.currentTimeMillis();
                long lastIoTime = Math.max(state.lastReadTime, state.lastWriteTime);
                long nextDelay = IdleStateHandler.this.allIdleTimeMillis - (currentTime - lastIoTime);
                if (nextDelay <= 0) {
                    state.allIdleTimeout = IdleStateHandler.this.timer.newTimeout(this, IdleStateHandler.this.allIdleTimeMillis, TimeUnit.MILLISECONDS);
                    IdleStateHandler.this.fireChannelIdle(this.ctx, IdleState.ALL_IDLE, lastIoTime);
                    return;
                }
                state.allIdleTimeout = IdleStateHandler.this.timer.newTimeout(this, nextDelay, TimeUnit.MILLISECONDS);
            }
        }
    }

    private final class ReaderIdleTimeoutTask implements TimerTask {
        private final ChannelHandlerContext ctx;

        ReaderIdleTimeoutTask(ChannelHandlerContext ctx2) {
            this.ctx = ctx2;
        }

        public void run(Timeout timeout) throws Exception {
            if (!timeout.isCancelled() && this.ctx.getChannel().isOpen()) {
                State state = (State) this.ctx.getAttachment();
                long currentTime = System.currentTimeMillis();
                long lastReadTime = state.lastReadTime;
                long nextDelay = IdleStateHandler.this.readerIdleTimeMillis - (currentTime - lastReadTime);
                if (nextDelay <= 0) {
                    state.readerIdleTimeout = IdleStateHandler.this.timer.newTimeout(this, IdleStateHandler.this.readerIdleTimeMillis, TimeUnit.MILLISECONDS);
                    IdleStateHandler.this.fireChannelIdle(this.ctx, IdleState.READER_IDLE, lastReadTime);
                    return;
                }
                state.readerIdleTimeout = IdleStateHandler.this.timer.newTimeout(this, nextDelay, TimeUnit.MILLISECONDS);
            }
        }
    }

    private static final class State {
        volatile Timeout allIdleTimeout;
        volatile long lastReadTime;
        volatile long lastWriteTime;
        volatile Timeout readerIdleTimeout;
        int state;
        volatile Timeout writerIdleTimeout;

        State() {
        }
    }

    private final class WriterIdleTimeoutTask implements TimerTask {
        private final ChannelHandlerContext ctx;

        WriterIdleTimeoutTask(ChannelHandlerContext ctx2) {
            this.ctx = ctx2;
        }

        public void run(Timeout timeout) throws Exception {
            if (!timeout.isCancelled() && this.ctx.getChannel().isOpen()) {
                State state = (State) this.ctx.getAttachment();
                long currentTime = System.currentTimeMillis();
                long lastWriteTime = state.lastWriteTime;
                long nextDelay = IdleStateHandler.this.writerIdleTimeMillis - (currentTime - lastWriteTime);
                if (nextDelay <= 0) {
                    state.writerIdleTimeout = IdleStateHandler.this.timer.newTimeout(this, IdleStateHandler.this.writerIdleTimeMillis, TimeUnit.MILLISECONDS);
                    IdleStateHandler.this.fireChannelIdle(this.ctx, IdleState.WRITER_IDLE, lastWriteTime);
                    return;
                }
                state.writerIdleTimeout = IdleStateHandler.this.timer.newTimeout(this, nextDelay, TimeUnit.MILLISECONDS);
            }
        }
    }

    public IdleStateHandler(Timer timer2, int readerIdleTimeSeconds, int writerIdleTimeSeconds, int allIdleTimeSeconds) {
        this(timer2, (long) readerIdleTimeSeconds, (long) writerIdleTimeSeconds, (long) allIdleTimeSeconds, TimeUnit.SECONDS);
    }

    public IdleStateHandler(Timer timer2, long readerIdleTime, long writerIdleTime, long allIdleTime, TimeUnit unit) {
        if (timer2 == null) {
            throw new NullPointerException("timer");
        } else if (unit == null) {
            throw new NullPointerException("unit");
        } else {
            this.timer = timer2;
            if (readerIdleTime <= 0) {
                this.readerIdleTimeMillis = 0;
            } else {
                this.readerIdleTimeMillis = Math.max(unit.toMillis(readerIdleTime), 1);
            }
            if (writerIdleTime <= 0) {
                this.writerIdleTimeMillis = 0;
            } else {
                this.writerIdleTimeMillis = Math.max(unit.toMillis(writerIdleTime), 1);
            }
            if (allIdleTime <= 0) {
                this.allIdleTimeMillis = 0;
            } else {
                this.allIdleTimeMillis = Math.max(unit.toMillis(allIdleTime), 1);
            }
        }
    }

    public long getReaderIdleTimeInMillis() {
        return this.readerIdleTimeMillis;
    }

    public long getWriterIdleTimeInMillis() {
        return this.writerIdleTimeMillis;
    }

    public long getAllIdleTimeInMillis() {
        return this.allIdleTimeMillis;
    }

    public void releaseExternalResources() {
        this.timer.stop();
    }

    public void beforeAdd(ChannelHandlerContext ctx) throws Exception {
        if (ctx.getPipeline().isAttached()) {
            initialize(ctx);
        }
    }

    public void afterAdd(ChannelHandlerContext ctx) throws Exception {
    }

    public void beforeRemove(ChannelHandlerContext ctx) throws Exception {
        destroy(ctx);
    }

    public void afterRemove(ChannelHandlerContext ctx) throws Exception {
    }

    public void channelOpen(ChannelHandlerContext ctx, ChannelStateEvent e) throws Exception {
        initialize(ctx);
        ctx.sendUpstream(e);
    }

    public void channelClosed(ChannelHandlerContext ctx, ChannelStateEvent e) throws Exception {
        destroy(ctx);
        ctx.sendUpstream(e);
    }

    public void messageReceived(ChannelHandlerContext ctx, MessageEvent e) throws Exception {
        ((State) ctx.getAttachment()).lastReadTime = System.currentTimeMillis();
        ctx.sendUpstream(e);
    }

    public void writeComplete(ChannelHandlerContext ctx, WriteCompletionEvent e) throws Exception {
        if (e.getWrittenAmount() > 0) {
            ((State) ctx.getAttachment()).lastWriteTime = System.currentTimeMillis();
        }
        ctx.sendUpstream(e);
    }

    /* JADX WARNING: Code restructure failed: missing block: B:11:0x0033, code lost:
        if (r8.writerIdleTimeMillis <= 0) goto L_0x0046;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:12:0x0035, code lost:
        r0.writerIdleTimeout = r8.timer.newTimeout(new org.jboss.netty.handler.timeout.IdleStateHandler.WriterIdleTimeoutTask(r8, r9), r8.writerIdleTimeMillis, java.util.concurrent.TimeUnit.MILLISECONDS);
     */
    /* JADX WARNING: Code restructure failed: missing block: B:14:0x004a, code lost:
        if (r8.allIdleTimeMillis <= 0) goto L_?;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:15:0x004c, code lost:
        r0.allIdleTimeout = r8.timer.newTimeout(new org.jboss.netty.handler.timeout.IdleStateHandler.AllIdleTimeoutTask(r8, r9), r8.allIdleTimeMillis, java.util.concurrent.TimeUnit.MILLISECONDS);
     */
    /* JADX WARNING: Code restructure failed: missing block: B:22:?, code lost:
        return;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:23:?, code lost:
        return;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:7:0x0010, code lost:
        r2 = java.lang.System.currentTimeMillis();
        r0.lastWriteTime = r2;
        r0.lastReadTime = r2;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:8:0x001c, code lost:
        if (r8.readerIdleTimeMillis <= 0) goto L_0x002f;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:9:0x001e, code lost:
        r0.readerIdleTimeout = r8.timer.newTimeout(new org.jboss.netty.handler.timeout.IdleStateHandler.ReaderIdleTimeoutTask(r8, r9), r8.readerIdleTimeMillis, java.util.concurrent.TimeUnit.MILLISECONDS);
     */
    private void initialize(ChannelHandlerContext ctx) {
        State state = state(ctx);
        synchronized (state) {
            switch (state.state) {
                case 1:
                case 2:
                    return;
                default:
                    state.state = 1;
                    break;
            }
        }
    }

    /* JADX WARNING: Code restructure failed: missing block: B:10:0x0015, code lost:
        r0.readerIdleTimeout.cancel();
        r0.readerIdleTimeout = null;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:12:0x001e, code lost:
        if (r0.writerIdleTimeout == null) goto L_0x0027;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:13:0x0020, code lost:
        r0.writerIdleTimeout.cancel();
        r0.writerIdleTimeout = null;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:15:0x0029, code lost:
        if (r0.allIdleTimeout == null) goto L_?;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:16:0x002b, code lost:
        r0.allIdleTimeout.cancel();
        r0.allIdleTimeout = null;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:25:?, code lost:
        return;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:26:?, code lost:
        return;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:9:0x0013, code lost:
        if (r0.readerIdleTimeout == null) goto L_0x001c;
     */
    private static void destroy(ChannelHandlerContext ctx) {
        State state = state(ctx);
        synchronized (state) {
            if (state.state == 1) {
                state.state = 2;
            }
        }
    }

    private static State state(ChannelHandlerContext ctx) {
        synchronized (ctx) {
            State state = (State) ctx.getAttachment();
            if (state != null) {
                return state;
            }
            State state2 = new State();
            ctx.setAttachment(state2);
            return state2;
        }
    }

    /* access modifiers changed from: private */
    public void fireChannelIdle(ChannelHandlerContext ctx, IdleState state, long lastActivityTimeMillis) {
        final ChannelHandlerContext channelHandlerContext = ctx;
        final IdleState idleState = state;
        final long j = lastActivityTimeMillis;
        ctx.getPipeline().execute(new Runnable() {
            public void run() {
                try {
                    IdleStateHandler.this.channelIdle(channelHandlerContext, idleState, j);
                } catch (Throwable t) {
                    Channels.fireExceptionCaught(channelHandlerContext, t);
                }
            }
        });
    }

    /* access modifiers changed from: protected */
    public void channelIdle(ChannelHandlerContext ctx, IdleState state, long lastActivityTimeMillis) throws Exception {
        ctx.sendUpstream(new DefaultIdleStateEvent(ctx.getChannel(), state, lastActivityTimeMillis));
    }
}