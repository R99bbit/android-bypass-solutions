package org.jboss.netty.handler.execution;

import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import org.jboss.netty.channel.ChannelDownstreamHandler;
import org.jboss.netty.channel.ChannelEvent;
import org.jboss.netty.channel.ChannelHandler.Sharable;
import org.jboss.netty.channel.ChannelHandlerContext;
import org.jboss.netty.channel.ChannelState;
import org.jboss.netty.channel.ChannelStateEvent;
import org.jboss.netty.channel.ChannelUpstreamHandler;
import org.jboss.netty.util.ExternalResourceReleasable;

@Sharable
public class ExecutionHandler implements ChannelUpstreamHandler, ChannelDownstreamHandler, ExternalResourceReleasable {
    private final Executor executor;
    private final boolean handleDownstream;
    private final boolean handleUpstream;

    public ExecutionHandler(Executor executor2) {
        this(executor2, false, true);
    }

    @Deprecated
    public ExecutionHandler(Executor executor2, boolean handleDownstream2) {
        this(executor2, handleDownstream2, true);
    }

    public ExecutionHandler(Executor executor2, boolean handleDownstream2, boolean handleUpstream2) {
        if (executor2 == null) {
            throw new NullPointerException("executor");
        } else if (handleDownstream2 || handleUpstream2) {
            this.executor = executor2;
            this.handleDownstream = handleDownstream2;
            this.handleUpstream = handleUpstream2;
        } else {
            throw new IllegalArgumentException("You must handle at least handle one event type");
        }
    }

    public Executor getExecutor() {
        return this.executor;
    }

    public void releaseExternalResources() {
        Executor executor2 = getExecutor();
        if (executor2 instanceof ExecutorService) {
            ((ExecutorService) executor2).shutdown();
        }
        if (executor2 instanceof ExternalResourceReleasable) {
            ((ExternalResourceReleasable) executor2).releaseExternalResources();
        }
    }

    public void handleUpstream(ChannelHandlerContext context, ChannelEvent e) throws Exception {
        if (this.handleUpstream) {
            this.executor.execute(new ChannelUpstreamEventRunnable(context, e, this.executor));
        } else {
            context.sendUpstream(e);
        }
    }

    public void handleDownstream(ChannelHandlerContext ctx, ChannelEvent e) throws Exception {
        if (handleReadSuspend(ctx, e)) {
            return;
        }
        if (this.handleDownstream) {
            this.executor.execute(new ChannelDownstreamEventRunnable(ctx, e, this.executor));
        } else {
            ctx.sendDownstream(e);
        }
    }

    /* access modifiers changed from: protected */
    public boolean handleReadSuspend(ChannelHandlerContext ctx, ChannelEvent e) {
        boolean readSuspended;
        if (e instanceof ChannelStateEvent) {
            ChannelStateEvent cse = (ChannelStateEvent) e;
            if (cse.getState() == ChannelState.INTEREST_OPS && (((Integer) cse.getValue()).intValue() & 1) != 0) {
                if (ctx.getAttachment() != null) {
                    readSuspended = true;
                } else {
                    readSuspended = false;
                }
                if (readSuspended) {
                    e.getFuture().setSuccess();
                    return true;
                }
            }
        }
        return false;
    }
}