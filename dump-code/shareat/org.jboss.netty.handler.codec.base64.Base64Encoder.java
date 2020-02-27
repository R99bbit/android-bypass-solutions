package org.jboss.netty.handler.codec.base64;

import org.jboss.netty.buffer.ChannelBuffer;
import org.jboss.netty.channel.Channel;
import org.jboss.netty.channel.ChannelHandler.Sharable;
import org.jboss.netty.channel.ChannelHandlerContext;
import org.jboss.netty.handler.codec.oneone.OneToOneEncoder;

@Sharable
public class Base64Encoder extends OneToOneEncoder {
    private final boolean breakLines;
    private final Base64Dialect dialect;

    public Base64Encoder() {
        this(true);
    }

    public Base64Encoder(boolean breakLines2) {
        this(breakLines2, Base64Dialect.STANDARD);
    }

    public Base64Encoder(boolean breakLines2, Base64Dialect dialect2) {
        if (dialect2 == null) {
            throw new NullPointerException("dialect");
        }
        this.breakLines = breakLines2;
        this.dialect = dialect2;
    }

    /* access modifiers changed from: protected */
    public Object encode(ChannelHandlerContext ctx, Channel channel, Object msg) throws Exception {
        if (!(msg instanceof ChannelBuffer)) {
            return msg;
        }
        ChannelBuffer src = (ChannelBuffer) msg;
        return Base64.encode(src, src.readerIndex(), src.readableBytes(), this.breakLines, this.dialect);
    }
}