package org.jboss.netty.handler.codec.protobuf;

import com.google.protobuf.MessageLite;
import com.google.protobuf.MessageLite.Builder;
import org.jboss.netty.channel.Channel;
import org.jboss.netty.channel.ChannelHandler.Sharable;
import org.jboss.netty.channel.ChannelHandlerContext;
import org.jboss.netty.handler.codec.oneone.OneToOneEncoder;

@Sharable
public class ProtobufEncoder extends OneToOneEncoder {
    /* access modifiers changed from: protected */
    public Object encode(ChannelHandlerContext ctx, Channel channel, Object msg) throws Exception {
        if (msg instanceof MessageLite) {
            byte[] array = ((MessageLite) msg).toByteArray();
            return ctx.getChannel().getConfig().getBufferFactory().getBuffer(array, 0, array.length);
        } else if (!(msg instanceof Builder)) {
            return msg;
        } else {
            byte[] array2 = ((Builder) msg).build().toByteArray();
            return ctx.getChannel().getConfig().getBufferFactory().getBuffer(array2, 0, array2.length);
        }
    }
}