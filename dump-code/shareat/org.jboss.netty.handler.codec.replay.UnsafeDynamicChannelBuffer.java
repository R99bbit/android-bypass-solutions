package org.jboss.netty.handler.codec.replay;

import org.jboss.netty.buffer.ChannelBufferFactory;
import org.jboss.netty.buffer.DynamicChannelBuffer;

@Deprecated
class UnsafeDynamicChannelBuffer extends DynamicChannelBuffer {
    UnsafeDynamicChannelBuffer(ChannelBufferFactory factory, int minimumCapacity) {
        super(factory.getDefaultOrder(), minimumCapacity, factory);
    }

    UnsafeDynamicChannelBuffer(ChannelBufferFactory factory) {
        this(factory, 256);
    }

    /* access modifiers changed from: protected */
    public void checkReadableBytes(int minReaderRemaining) {
    }
}