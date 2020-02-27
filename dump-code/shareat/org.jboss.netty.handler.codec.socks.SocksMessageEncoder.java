package org.jboss.netty.handler.codec.socks;

import org.jboss.netty.buffer.ChannelBuffer;
import org.jboss.netty.buffer.ChannelBuffers;
import org.jboss.netty.channel.Channel;
import org.jboss.netty.channel.ChannelHandler.Sharable;
import org.jboss.netty.channel.ChannelHandlerContext;
import org.jboss.netty.handler.codec.oneone.OneToOneEncoder;

@Sharable
public class SocksMessageEncoder extends OneToOneEncoder {
    private static final int DEFAULT_ENCODER_BUFFER_SIZE = 1024;
    private static final String name = "SOCKS_MESSAGE_ENCODER";

    public static String getName() {
        return name;
    }

    /* access modifiers changed from: protected */
    public Object encode(ChannelHandlerContext ctx, Channel channel, Object msg) throws Exception {
        if (!(msg instanceof SocksMessage)) {
            return null;
        }
        ChannelBuffer buffer = ChannelBuffers.buffer(1024);
        ((SocksMessage) msg).encodeAsByteBuf(buffer);
        return buffer;
    }
}