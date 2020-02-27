package org.jboss.netty.handler.execution;

import java.util.concurrent.Executor;
import org.jboss.netty.channel.ChannelEvent;
import org.jboss.netty.channel.ChannelHandlerContext;

public class ChannelDownstreamEventRunnable extends ChannelEventRunnable {
    public ChannelDownstreamEventRunnable(ChannelHandlerContext ctx, ChannelEvent e, Executor executor) {
        super(ctx, e, executor);
    }

    /* access modifiers changed from: protected */
    public void doRun() {
        this.ctx.sendDownstream(this.e);
    }
}