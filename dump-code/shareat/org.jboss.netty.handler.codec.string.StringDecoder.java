package org.jboss.netty.handler.codec.string;

import java.nio.charset.Charset;
import org.jboss.netty.buffer.ChannelBuffer;
import org.jboss.netty.channel.Channel;
import org.jboss.netty.channel.ChannelHandler.Sharable;
import org.jboss.netty.channel.ChannelHandlerContext;
import org.jboss.netty.handler.codec.oneone.OneToOneDecoder;

@Sharable
public class StringDecoder extends OneToOneDecoder {
    private final Charset charset;

    public StringDecoder() {
        this(Charset.defaultCharset());
    }

    public StringDecoder(Charset charset2) {
        if (charset2 == null) {
            throw new NullPointerException("charset");
        }
        this.charset = charset2;
    }

    @Deprecated
    public StringDecoder(String charsetName) {
        this(Charset.forName(charsetName));
    }

    /* access modifiers changed from: protected */
    public Object decode(ChannelHandlerContext ctx, Channel channel, Object msg) throws Exception {
        return !(msg instanceof ChannelBuffer) ? msg : ((ChannelBuffer) msg).toString(this.charset);
    }
}