package org.jboss.netty.handler.traffic;

import org.jboss.netty.channel.ChannelHandlerContext;
import org.jboss.netty.channel.ChannelStateEvent;
import org.jboss.netty.util.ObjectSizeEstimator;
import org.jboss.netty.util.Timer;

public class ChannelTrafficShapingHandler extends AbstractTrafficShapingHandler {
    public ChannelTrafficShapingHandler(Timer timer, long writeLimit, long readLimit, long checkInterval) {
        super(timer, writeLimit, readLimit, checkInterval);
    }

    public ChannelTrafficShapingHandler(Timer timer, long writeLimit, long readLimit) {
        super(timer, writeLimit, readLimit);
    }

    public ChannelTrafficShapingHandler(Timer timer, long checkInterval) {
        super(timer, checkInterval);
    }

    public ChannelTrafficShapingHandler(Timer timer) {
        super(timer);
    }

    public ChannelTrafficShapingHandler(ObjectSizeEstimator objectSizeEstimator, Timer timer, long writeLimit, long readLimit, long checkInterval) {
        super(objectSizeEstimator, timer, writeLimit, readLimit, checkInterval);
    }

    public ChannelTrafficShapingHandler(ObjectSizeEstimator objectSizeEstimator, Timer timer, long writeLimit, long readLimit) {
        super(objectSizeEstimator, timer, writeLimit, readLimit);
    }

    public ChannelTrafficShapingHandler(ObjectSizeEstimator objectSizeEstimator, Timer timer, long checkInterval) {
        super(objectSizeEstimator, timer, checkInterval);
    }

    public ChannelTrafficShapingHandler(ObjectSizeEstimator objectSizeEstimator, Timer timer) {
        super(objectSizeEstimator, timer);
    }

    public void channelClosed(ChannelHandlerContext ctx, ChannelStateEvent e) throws Exception {
        if (this.trafficCounter != null) {
            this.trafficCounter.stop();
        }
        super.channelClosed(ctx, e);
    }

    public void channelConnected(ChannelHandlerContext ctx, ChannelStateEvent e) throws Exception {
        ctx.setAttachment(Boolean.TRUE);
        ctx.getChannel().setReadable(false);
        if (this.trafficCounter == null && this.timer != null) {
            this.trafficCounter = new TrafficCounter(this, this.timer, "ChannelTC" + ctx.getChannel().getId(), this.checkInterval);
        }
        if (this.trafficCounter != null) {
            this.trafficCounter.start();
        }
        super.channelConnected(ctx, e);
        ctx.setAttachment(null);
        ctx.getChannel().setReadable(true);
    }
}