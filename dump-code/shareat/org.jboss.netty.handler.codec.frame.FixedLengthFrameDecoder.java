package org.jboss.netty.handler.codec.frame;

import org.jboss.netty.buffer.ChannelBuffer;
import org.jboss.netty.buffer.ChannelBufferFactory;
import org.jboss.netty.channel.Channel;
import org.jboss.netty.channel.ChannelHandlerContext;

public class FixedLengthFrameDecoder extends FrameDecoder {
    private final boolean allocateFullBuffer;
    private final int frameLength;

    public FixedLengthFrameDecoder(int frameLength2) {
        this(frameLength2, false);
    }

    public FixedLengthFrameDecoder(int frameLength2, boolean allocateFullBuffer2) {
        if (frameLength2 <= 0) {
            throw new IllegalArgumentException("frameLength must be a positive integer: " + frameLength2);
        }
        this.frameLength = frameLength2;
        this.allocateFullBuffer = allocateFullBuffer2;
    }

    /* access modifiers changed from: protected */
    public Object decode(ChannelHandlerContext ctx, Channel channel, ChannelBuffer buffer) throws Exception {
        if (buffer.readableBytes() < this.frameLength) {
            return null;
        }
        ChannelBuffer extractFrame = extractFrame(buffer, buffer.readerIndex(), this.frameLength);
        buffer.skipBytes(this.frameLength);
        return extractFrame;
    }

    /* access modifiers changed from: protected */
    public ChannelBuffer newCumulationBuffer(ChannelHandlerContext ctx, int minimumCapacity) {
        ChannelBufferFactory factory = ctx.getChannel().getConfig().getBufferFactory();
        if (this.allocateFullBuffer) {
            return factory.getBuffer(this.frameLength);
        }
        return super.newCumulationBuffer(ctx, minimumCapacity);
    }
}