package org.jboss.netty.handler.codec.marshalling;

import org.jboss.marshalling.Marshaller;
import org.jboss.netty.channel.Channel;
import org.jboss.netty.channel.ChannelHandler.Sharable;
import org.jboss.netty.channel.ChannelHandlerContext;
import org.jboss.netty.handler.codec.oneone.OneToOneEncoder;

@Sharable
public class CompatibleMarshallingEncoder extends OneToOneEncoder {
    private final MarshallerProvider provider;

    public CompatibleMarshallingEncoder(MarshallerProvider provider2) {
        this.provider = provider2;
    }

    /* access modifiers changed from: protected */
    public Object encode(ChannelHandlerContext ctx, Channel channel, Object msg) throws Exception {
        Marshaller marshaller = this.provider.getMarshaller(ctx);
        ChannelBufferByteOutput output = new ChannelBufferByteOutput(ctx.getChannel().getConfig().getBufferFactory(), 256);
        marshaller.start(output);
        marshaller.writeObject(msg);
        marshaller.finish();
        marshaller.close();
        return output.getBuffer();
    }
}