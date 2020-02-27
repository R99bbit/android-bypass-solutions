package org.jboss.netty.handler.codec.oneone;

import org.jboss.netty.channel.Channel;
import org.jboss.netty.channel.ChannelDownstreamHandler;
import org.jboss.netty.channel.ChannelEvent;
import org.jboss.netty.channel.ChannelHandlerContext;
import org.jboss.netty.channel.Channels;
import org.jboss.netty.channel.MessageEvent;

public abstract class OneToOneEncoder implements ChannelDownstreamHandler {
    /* access modifiers changed from: protected */
    public abstract Object encode(ChannelHandlerContext channelHandlerContext, Channel channel, Object obj) throws Exception;

    protected OneToOneEncoder() {
    }

    public void handleDownstream(ChannelHandlerContext ctx, ChannelEvent evt) throws Exception {
        if (!(evt instanceof MessageEvent)) {
            ctx.sendDownstream(evt);
            return;
        }
        MessageEvent e = (MessageEvent) evt;
        if (!doEncode(ctx, e)) {
            ctx.sendDownstream(e);
        }
    }

    /* access modifiers changed from: protected */
    public boolean doEncode(ChannelHandlerContext ctx, MessageEvent e) throws Exception {
        Object originalMessage = e.getMessage();
        Object encodedMessage = encode(ctx, e.getChannel(), originalMessage);
        if (originalMessage == encodedMessage) {
            return false;
        }
        if (encodedMessage != null) {
            Channels.write(ctx, e.getFuture(), encodedMessage, e.getRemoteAddress());
        }
        return true;
    }
}