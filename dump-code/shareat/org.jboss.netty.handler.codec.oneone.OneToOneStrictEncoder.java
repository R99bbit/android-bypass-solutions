package org.jboss.netty.handler.codec.oneone;

import org.jboss.netty.channel.ChannelHandlerContext;
import org.jboss.netty.channel.MessageEvent;

public abstract class OneToOneStrictEncoder extends OneToOneEncoder {
    /* access modifiers changed from: protected */
    public boolean doEncode(ChannelHandlerContext ctx, MessageEvent e) throws Exception {
        boolean doEncode;
        synchronized (ctx.getChannel()) {
            doEncode = super.doEncode(ctx, e);
        }
        return doEncode;
    }
}