package org.jboss.netty.handler.timeout;

import java.util.concurrent.TimeUnit;
import org.jboss.netty.channel.ChannelHandler.Sharable;
import org.jboss.netty.channel.ChannelHandlerContext;
import org.jboss.netty.channel.ChannelStateEvent;
import org.jboss.netty.channel.Channels;
import org.jboss.netty.channel.LifeCycleAwareChannelHandler;
import org.jboss.netty.channel.MessageEvent;
import org.jboss.netty.channel.SimpleChannelUpstreamHandler;
import org.jboss.netty.util.ExternalResourceReleasable;
import org.jboss.netty.util.Timeout;
import org.jboss.netty.util.Timer;
import org.jboss.netty.util.TimerTask;

@Sharable
public class ReadTimeoutHandler extends SimpleChannelUpstreamHandler implements LifeCycleAwareChannelHandler, ExternalResourceReleasable {
    static final ReadTimeoutException EXCEPTION = new ReadTimeoutException();
    final long timeoutMillis;
    final Timer timer;

    private final class ReadTimeoutTask implements TimerTask {
        private final ChannelHandlerContext ctx;

        ReadTimeoutTask(ChannelHandlerContext ctx2) {
            this.ctx = ctx2;
        }

        public void run(Timeout timeout) throws Exception {
            if (!timeout.isCancelled() && this.ctx.getChannel().isOpen()) {
                State state = (State) this.ctx.getAttachment();
                long nextDelay = ReadTimeoutHandler.this.timeoutMillis - (System.currentTimeMillis() - state.lastReadTime);
                if (nextDelay <= 0) {
                    state.timeout = ReadTimeoutHandler.this.timer.newTimeout(this, ReadTimeoutHandler.this.timeoutMillis, TimeUnit.MILLISECONDS);
                    fireReadTimedOut(this.ctx);
                    return;
                }
                state.timeout = ReadTimeoutHandler.this.timer.newTimeout(this, nextDelay, TimeUnit.MILLISECONDS);
            }
        }

        private void fireReadTimedOut(final ChannelHandlerContext ctx2) throws Exception {
            ctx2.getPipeline().execute(new Runnable() {
                public void run() {
                    try {
                        ReadTimeoutHandler.this.readTimedOut(ctx2);
                    } catch (Throwable t) {
                        Channels.fireExceptionCaught(ctx2, t);
                    }
                }
            });
        }
    }

    private static final class State {
        volatile long lastReadTime = System.currentTimeMillis();
        int state;
        volatile Timeout timeout;

        State() {
        }
    }

    public ReadTimeoutHandler(Timer timer2, int timeoutSeconds) {
        this(timer2, (long) timeoutSeconds, TimeUnit.SECONDS);
    }

    public ReadTimeoutHandler(Timer timer2, long timeout, TimeUnit unit) {
        if (timer2 == null) {
            throw new NullPointerException("timer");
        } else if (unit == null) {
            throw new NullPointerException("unit");
        } else {
            this.timer = timer2;
            if (timeout <= 0) {
                this.timeoutMillis = 0;
            } else {
                this.timeoutMillis = Math.max(unit.toMillis(timeout), 1);
            }
        }
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

    /* JADX WARNING: Code restructure failed: missing block: B:16:?, code lost:
        return;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:17:?, code lost:
        return;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:8:0x0014, code lost:
        if (r6.timeoutMillis <= 0) goto L_?;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:9:0x0016, code lost:
        r0.timeout = r6.timer.newTimeout(new org.jboss.netty.handler.timeout.ReadTimeoutHandler.ReadTimeoutTask(r6, r7), r6.timeoutMillis, java.util.concurrent.TimeUnit.MILLISECONDS);
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

    /* JADX WARNING: Code restructure failed: missing block: B:10:0x0014, code lost:
        r0.timeout.cancel();
        r0.timeout = null;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:19:?, code lost:
        return;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:20:?, code lost:
        return;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:9:0x0012, code lost:
        if (r0.timeout == null) goto L_?;
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

    /* access modifiers changed from: protected */
    public void readTimedOut(ChannelHandlerContext ctx) throws Exception {
        Channels.fireExceptionCaught(ctx, (Throwable) EXCEPTION);
    }
}