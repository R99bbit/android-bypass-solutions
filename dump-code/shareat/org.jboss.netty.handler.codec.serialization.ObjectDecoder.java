package org.jboss.netty.handler.codec.serialization;

import org.jboss.netty.buffer.ChannelBuffer;
import org.jboss.netty.buffer.ChannelBufferInputStream;
import org.jboss.netty.channel.Channel;
import org.jboss.netty.channel.ChannelHandlerContext;
import org.jboss.netty.handler.codec.frame.LengthFieldBasedFrameDecoder;

public class ObjectDecoder extends LengthFieldBasedFrameDecoder {
    private final ClassResolver classResolver;

    @Deprecated
    public ObjectDecoder() {
        this(1048576);
    }

    public ObjectDecoder(ClassResolver classResolver2) {
        this(1048576, classResolver2);
    }

    @Deprecated
    public ObjectDecoder(int maxObjectSize) {
        this(maxObjectSize, ClassResolvers.weakCachingResolver(null));
    }

    public ObjectDecoder(int maxObjectSize, ClassResolver classResolver2) {
        super(maxObjectSize, 0, 4, 0, 4);
        if (classResolver2 == null) {
            throw new NullPointerException("classResolver");
        }
        this.classResolver = classResolver2;
    }

    @Deprecated
    public ObjectDecoder(int maxObjectSize, ClassLoader classLoader) {
        this(maxObjectSize, ClassResolvers.weakCachingResolver(classLoader));
    }

    /* access modifiers changed from: protected */
    public Object decode(ChannelHandlerContext ctx, Channel channel, ChannelBuffer buffer) throws Exception {
        ChannelBuffer frame = (ChannelBuffer) super.decode(ctx, channel, buffer);
        if (frame == null) {
            return null;
        }
        return new CompactObjectInputStream(new ChannelBufferInputStream(frame), this.classResolver).readObject();
    }

    /* access modifiers changed from: protected */
    public ChannelBuffer extractFrame(ChannelBuffer buffer, int index, int length) {
        return buffer.slice(index, length);
    }
}