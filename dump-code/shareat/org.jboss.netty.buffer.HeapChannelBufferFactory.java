package org.jboss.netty.buffer;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public class HeapChannelBufferFactory extends AbstractChannelBufferFactory {
    private static final HeapChannelBufferFactory INSTANCE_BE = new HeapChannelBufferFactory(ByteOrder.BIG_ENDIAN);
    private static final HeapChannelBufferFactory INSTANCE_LE = new HeapChannelBufferFactory(ByteOrder.LITTLE_ENDIAN);

    public static ChannelBufferFactory getInstance() {
        return INSTANCE_BE;
    }

    public static ChannelBufferFactory getInstance(ByteOrder endianness) {
        if (endianness == ByteOrder.BIG_ENDIAN) {
            return INSTANCE_BE;
        }
        if (endianness == ByteOrder.LITTLE_ENDIAN) {
            return INSTANCE_LE;
        }
        if (endianness == null) {
            throw new NullPointerException("endianness");
        }
        throw new IllegalStateException("Should not reach here");
    }

    public HeapChannelBufferFactory() {
    }

    public HeapChannelBufferFactory(ByteOrder defaultOrder) {
        super(defaultOrder);
    }

    public ChannelBuffer getBuffer(ByteOrder order, int capacity) {
        return ChannelBuffers.buffer(order, capacity);
    }

    public ChannelBuffer getBuffer(ByteOrder order, byte[] array, int offset, int length) {
        return ChannelBuffers.wrappedBuffer(order, array, offset, length);
    }

    public ChannelBuffer getBuffer(ByteBuffer nioBuffer) {
        if (nioBuffer.hasArray()) {
            return ChannelBuffers.wrappedBuffer(nioBuffer);
        }
        ChannelBuffer buf = getBuffer(nioBuffer.order(), nioBuffer.remaining());
        int pos = nioBuffer.position();
        buf.writeBytes(nioBuffer);
        nioBuffer.position(pos);
        return buf;
    }
}