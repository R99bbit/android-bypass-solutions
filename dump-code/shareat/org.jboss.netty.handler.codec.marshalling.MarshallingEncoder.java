package org.jboss.netty.handler.codec.marshalling;

import org.jboss.marshalling.Marshaller;
import org.jboss.netty.buffer.ChannelBuffer;
import org.jboss.netty.channel.Channel;
import org.jboss.netty.channel.ChannelHandler.Sharable;
import org.jboss.netty.channel.ChannelHandlerContext;
import org.jboss.netty.handler.codec.oneone.OneToOneEncoder;

@Sharable
public class MarshallingEncoder extends OneToOneEncoder {
    private static final byte[] LENGTH_PLACEHOLDER = new byte[4];
    private final int estimatedLength;
    private final MarshallerProvider provider;

    public MarshallingEncoder(MarshallerProvider provider2) {
        this(provider2, 512);
    }

    public MarshallingEncoder(MarshallerProvider provider2, int estimatedLength2) {
        if (estimatedLength2 < 0) {
            throw new IllegalArgumentException("estimatedLength: " + estimatedLength2);
        }
        this.estimatedLength = estimatedLength2;
        this.provider = provider2;
    }

    /* access modifiers changed from: protected */
    public Object encode(ChannelHandlerContext ctx, Channel channel, Object msg) throws Exception {
        Marshaller marshaller = this.provider.getMarshaller(ctx);
        ChannelBufferByteOutput output = new ChannelBufferByteOutput(ctx.getChannel().getConfig().getBufferFactory(), this.estimatedLength);
        output.getBuffer().writeBytes(LENGTH_PLACEHOLDER);
        marshaller.start(output);
        marshaller.writeObject(msg);
        marshaller.finish();
        marshaller.close();
        ChannelBuffer encoded = output.getBuffer();
        encoded.setInt(0, encoded.writerIndex() - 4);
        return encoded;
    }
}