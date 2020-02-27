package org.jboss.netty.channel;

public class SimpleChannelDownstreamHandler implements ChannelDownstreamHandler {
    public void handleDownstream(ChannelHandlerContext ctx, ChannelEvent e) throws Exception {
        if (e instanceof MessageEvent) {
            writeRequested(ctx, (MessageEvent) e);
        } else if (e instanceof ChannelStateEvent) {
            ChannelStateEvent evt = (ChannelStateEvent) e;
            switch (evt.getState()) {
                case OPEN:
                    if (!Boolean.TRUE.equals(evt.getValue())) {
                        closeRequested(ctx, evt);
                        return;
                    }
                    return;
                case BOUND:
                    if (evt.getValue() != null) {
                        bindRequested(ctx, evt);
                        return;
                    } else {
                        unbindRequested(ctx, evt);
                        return;
                    }
                case CONNECTED:
                    if (evt.getValue() != null) {
                        connectRequested(ctx, evt);
                        return;
                    } else {
                        disconnectRequested(ctx, evt);
                        return;
                    }
                case INTEREST_OPS:
                    setInterestOpsRequested(ctx, evt);
                    return;
                default:
                    ctx.sendDownstream(e);
                    return;
            }
        } else {
            ctx.sendDownstream(e);
        }
    }

    public void writeRequested(ChannelHandlerContext ctx, MessageEvent e) throws Exception {
        ctx.sendDownstream(e);
    }

    public void bindRequested(ChannelHandlerContext ctx, ChannelStateEvent e) throws Exception {
        ctx.sendDownstream(e);
    }

    public void connectRequested(ChannelHandlerContext ctx, ChannelStateEvent e) throws Exception {
        ctx.sendDownstream(e);
    }

    public void setInterestOpsRequested(ChannelHandlerContext ctx, ChannelStateEvent e) throws Exception {
        ctx.sendDownstream(e);
    }

    public void disconnectRequested(ChannelHandlerContext ctx, ChannelStateEvent e) throws Exception {
        ctx.sendDownstream(e);
    }

    public void unbindRequested(ChannelHandlerContext ctx, ChannelStateEvent e) throws Exception {
        ctx.sendDownstream(e);
    }

    public void closeRequested(ChannelHandlerContext ctx, ChannelStateEvent e) throws Exception {
        ctx.sendDownstream(e);
    }
}