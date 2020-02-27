package org.jboss.netty.handler.codec.marshalling;

import org.jboss.marshalling.Unmarshaller;
import org.jboss.netty.buffer.ChannelBuffer;
import org.jboss.netty.channel.Channel;
import org.jboss.netty.channel.ChannelHandlerContext;
import org.jboss.netty.handler.codec.frame.LengthFieldBasedFrameDecoder;

public class MarshallingDecoder extends LengthFieldBasedFrameDecoder {
    private final UnmarshallerProvider provider;

    public MarshallingDecoder(UnmarshallerProvider provider2) {
        this(provider2, 1048576);
    }

    public MarshallingDecoder(UnmarshallerProvider provider2, int maxObjectSize) {
        super(maxObjectSize, 0, 4, 0, 4);
        this.provider = provider2;
    }

    /* access modifiers changed from: protected */
    public Object decode(ChannelHandlerContext ctx, Channel channel, ChannelBuffer buffer) throws Exception {
        ChannelBuffer frame = (ChannelBuffer) super.decode(ctx, channel, buffer);
        if (frame == null) {
            return null;
        }
        Unmarshaller unmarshaller = this.provider.getUnmarshaller(ctx);
        try {
            unmarshaller.start(new ChannelBufferByteInput(frame));
            Object readObject = unmarshaller.readObject();
            unmarshaller.finish();
            return readObject;
        } finally {
            unmarshaller.close();
        }
    }

    /* access modifiers changed from: protected */
    public ChannelBuffer extractFrame(ChannelBuffer buffer, int index, int length) {
        return buffer.slice(index, length);
    }
}