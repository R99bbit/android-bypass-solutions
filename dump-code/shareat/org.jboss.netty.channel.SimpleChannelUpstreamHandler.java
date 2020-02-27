package org.jboss.netty.channel;

import java.util.List;
import org.jboss.netty.logging.InternalLogger;
import org.jboss.netty.logging.InternalLoggerFactory;

public class SimpleChannelUpstreamHandler implements ChannelUpstreamHandler {
    private static final InternalLogger logger = InternalLoggerFactory.getInstance(SimpleChannelUpstreamHandler.class.getName());

    public void handleUpstream(ChannelHandlerContext ctx, ChannelEvent e) throws Exception {
        if (e instanceof MessageEvent) {
            messageReceived(ctx, (MessageEvent) e);
        } else if (e instanceof WriteCompletionEvent) {
            writeComplete(ctx, (WriteCompletionEvent) e);
        } else if (e instanceof ChildChannelStateEvent) {
            ChildChannelStateEvent evt = (ChildChannelStateEvent) e;
            if (evt.getChildChannel().isOpen()) {
                childChannelOpen(ctx, evt);
            } else {
                childChannelClosed(ctx, evt);
            }
        } else if (e instanceof ChannelStateEvent) {
            ChannelStateEvent evt2 = (ChannelStateEvent) e;
            switch (evt2.getState()) {
                case OPEN:
                    if (Boolean.TRUE.equals(evt2.getValue())) {
                        channelOpen(ctx, evt2);
                        return;
                    } else {
                        channelClosed(ctx, evt2);
                        return;
                    }
                case BOUND:
                    if (evt2.getValue() != null) {
                        channelBound(ctx, evt2);
                        return;
                    } else {
                        channelUnbound(ctx, evt2);
                        return;
                    }
                case CONNECTED:
                    if (evt2.getValue() != null) {
                        channelConnected(ctx, evt2);
                        return;
                    } else {
                        channelDisconnected(ctx, evt2);
                        return;
                    }
                case INTEREST_OPS:
                    channelInterestChanged(ctx, evt2);
                    return;
                default:
                    ctx.sendUpstream(e);
                    return;
            }
        } else if (e instanceof ExceptionEvent) {
            exceptionCaught(ctx, (ExceptionEvent) e);
        } else {
            ctx.sendUpstream(e);
        }
    }

    public void messageReceived(ChannelHandlerContext ctx, MessageEvent e) throws Exception {
        ctx.sendUpstream(e);
    }

    public void exceptionCaught(ChannelHandlerContext ctx, ExceptionEvent e) throws Exception {
        ChannelHandler last = ctx.getPipeline().getLast();
        if (!(last instanceof ChannelUpstreamHandler) && (ctx instanceof DefaultChannelPipeline)) {
            List<String> names = ctx.getPipeline().getNames();
            int i = names.size() - 1;
            while (true) {
                if (i < 0) {
                    break;
                }
                ChannelHandler handler = ctx.getPipeline().get(names.get(i));
                if (handler instanceof ChannelUpstreamHandler) {
                    last = handler;
                    break;
                }
                i--;
            }
        }
        if (this == last) {
            logger.warn("EXCEPTION, please implement " + getClass().getName() + ".exceptionCaught() for proper handling.", e.getCause());
        }
        ctx.sendUpstream(e);
    }

    public void channelOpen(ChannelHandlerContext ctx, ChannelStateEvent e) throws Exception {
        ctx.sendUpstream(e);
    }

    public void channelBound(ChannelHandlerContext ctx, ChannelStateEvent e) throws Exception {
        ctx.sendUpstream(e);
    }

    public void channelConnected(ChannelHandlerContext ctx, ChannelStateEvent e) throws Exception {
        ctx.sendUpstream(e);
    }

    public void channelInterestChanged(ChannelHandlerContext ctx, ChannelStateEvent e) throws Exception {
        ctx.sendUpstream(e);
    }

    public void channelDisconnected(ChannelHandlerContext ctx, ChannelStateEvent e) throws Exception {
        ctx.sendUpstream(e);
    }

    public void channelUnbound(ChannelHandlerContext ctx, ChannelStateEvent e) throws Exception {
        ctx.sendUpstream(e);
    }

    public void channelClosed(ChannelHandlerContext ctx, ChannelStateEvent e) throws Exception {
        ctx.sendUpstream(e);
    }

    public void writeComplete(ChannelHandlerContext ctx, WriteCompletionEvent e) throws Exception {
        ctx.sendUpstream(e);
    }

    public void childChannelOpen(ChannelHandlerContext ctx, ChildChannelStateEvent e) throws Exception {
        ctx.sendUpstream(e);
    }

    public void childChannelClosed(ChannelHandlerContext ctx, ChildChannelStateEvent e) throws Exception {
        ctx.sendUpstream(e);
    }
}