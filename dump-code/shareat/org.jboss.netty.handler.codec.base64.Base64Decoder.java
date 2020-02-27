package org.jboss.netty.handler.codec.base64;

import org.jboss.netty.buffer.ChannelBuffer;
import org.jboss.netty.buffer.ChannelBuffers;
import org.jboss.netty.channel.Channel;
import org.jboss.netty.channel.ChannelHandler.Sharable;
import org.jboss.netty.channel.ChannelHandlerContext;
import org.jboss.netty.handler.codec.oneone.OneToOneDecoder;
import org.jboss.netty.util.CharsetUtil;

@Sharable
public class Base64Decoder extends OneToOneDecoder {
    private final Base64Dialect dialect;

    public Base64Decoder() {
        this(Base64Dialect.STANDARD);
    }

    public Base64Decoder(Base64Dialect dialect2) {
        if (dialect2 == null) {
            throw new NullPointerException("dialect");
        }
        this.dialect = dialect2;
    }

    /* access modifiers changed from: protected */
    public Object decode(ChannelHandlerContext ctx, Channel channel, Object msg) throws Exception {
        if (msg instanceof String) {
            msg = ChannelBuffers.copiedBuffer((CharSequence) (String) msg, CharsetUtil.US_ASCII);
        } else if (!(msg instanceof ChannelBuffer)) {
            return msg;
        }
        ChannelBuffer src = (ChannelBuffer) msg;
        return Base64.decode(src, src.readerIndex(), src.readableBytes(), this.dialect);
    }
}