package org.jboss.netty.handler.codec.string;

import java.nio.charset.Charset;
import org.jboss.netty.buffer.ChannelBuffers;
import org.jboss.netty.channel.Channel;
import org.jboss.netty.channel.ChannelHandler.Sharable;
import org.jboss.netty.channel.ChannelHandlerContext;
import org.jboss.netty.handler.codec.oneone.OneToOneEncoder;

@Sharable
public class StringEncoder extends OneToOneEncoder {
    private final Charset charset;

    public StringEncoder() {
        this(Charset.defaultCharset());
    }

    public StringEncoder(Charset charset2) {
        if (charset2 == null) {
            throw new NullPointerException("charset");
        }
        this.charset = charset2;
    }

    @Deprecated
    public StringEncoder(String charsetName) {
        this(Charset.forName(charsetName));
    }

    /* access modifiers changed from: protected */
    public Object encode(ChannelHandlerContext ctx, Channel channel, Object msg) throws Exception {
        if (msg instanceof String) {
            return ChannelBuffers.copiedBuffer(ctx.getChannel().getConfig().getBufferFactory().getDefaultOrder(), (CharSequence) (String) msg, this.charset);
        }
        return msg;
    }
}