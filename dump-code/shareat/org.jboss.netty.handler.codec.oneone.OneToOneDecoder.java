package org.jboss.netty.handler.codec.oneone;

import org.jboss.netty.channel.Channel;
import org.jboss.netty.channel.ChannelEvent;
import org.jboss.netty.channel.ChannelHandlerContext;
import org.jboss.netty.channel.ChannelUpstreamHandler;
import org.jboss.netty.channel.Channels;
import org.jboss.netty.channel.MessageEvent;

public abstract class OneToOneDecoder implements ChannelUpstreamHandler {
    /* access modifiers changed from: protected */
    public abstract Object decode(ChannelHandlerContext channelHandlerContext, Channel channel, Object obj) throws Exception;

    protected OneToOneDecoder() {
    }

    public void handleUpstream(ChannelHandlerContext ctx, ChannelEvent evt) throws Exception {
        if (!(evt instanceof MessageEvent)) {
            ctx.sendUpstream(evt);
            return;
        }
        MessageEvent e = (MessageEvent) evt;
        Object originalMessage = e.getMessage();
        Object decodedMessage = decode(ctx, e.getChannel(), originalMessage);
        if (originalMessage == decodedMessage) {
            ctx.sendUpstream(evt);
        } else if (decodedMessage != null) {
            Channels.fireMessageReceived(ctx, decodedMessage, e.getRemoteAddress());
        }
    }
}