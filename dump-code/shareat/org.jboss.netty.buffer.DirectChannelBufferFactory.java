package org.jboss.netty.buffer;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public class DirectChannelBufferFactory extends AbstractChannelBufferFactory {
    private static final DirectChannelBufferFactory INSTANCE_BE = new DirectChannelBufferFactory(ByteOrder.BIG_ENDIAN);
    private static final DirectChannelBufferFactory INSTANCE_LE = new DirectChannelBufferFactory(ByteOrder.LITTLE_ENDIAN);
    private final Object bigEndianLock;
    private final Object littleEndianLock;
    private ChannelBuffer preallocatedBEBuf;
    private int preallocatedBEBufPos;
    private final int preallocatedBufCapacity;
    private ChannelBuffer preallocatedLEBuf;
    private int preallocatedLEBufPos;

    public static ChannelBufferFactory getInstance() {
        return INSTANCE_BE;
    }

    public static ChannelBufferFactory getInstance(ByteOrder defaultEndianness) {
        if (defaultEndianness == ByteOrder.BIG_ENDIAN) {
            return INSTANCE_BE;
        }
        if (defaultEndianness == ByteOrder.LITTLE_ENDIAN) {
            return INSTANCE_LE;
        }
        if (defaultEndianness == null) {
            throw new NullPointerException("defaultEndianness");
        }
        throw new IllegalStateException("Should not reach here");
    }

    public DirectChannelBufferFactory() {
        this(ByteOrder.BIG_ENDIAN);
    }

    public DirectChannelBufferFactory(int preallocatedBufferCapacity) {
        this(ByteOrder.BIG_ENDIAN, preallocatedBufferCapacity);
    }

    public DirectChannelBufferFactory(ByteOrder defaultOrder) {
        this(defaultOrder, 1048576);
    }

    public DirectChannelBufferFactory(ByteOrder defaultOrder, int preallocatedBufferCapacity) {
        super(defaultOrder);
        this.bigEndianLock = new Object();
        this.littleEndianLock = new Object();
        if (preallocatedBufferCapacity <= 0) {
            throw new IllegalArgumentException("preallocatedBufCapacity must be greater than 0: " + preallocatedBufferCapacity);
        }
        this.preallocatedBufCapacity = preallocatedBufferCapacity;
    }

    public ChannelBuffer getBuffer(ByteOrder order, int capacity) {
        ChannelBuffer slice;
        if (order == null) {
            throw new NullPointerException("order");
        } else if (capacity < 0) {
            throw new IllegalArgumentException("capacity: " + capacity);
        } else if (capacity == 0) {
            return ChannelBuffers.EMPTY_BUFFER;
        } else {
            if (capacity >= this.preallocatedBufCapacity) {
                return ChannelBuffers.directBuffer(order, capacity);
            }
            if (order == ByteOrder.BIG_ENDIAN) {
                slice = allocateBigEndianBuffer(capacity);
            } else {
                slice = allocateLittleEndianBuffer(capacity);
            }
            slice.clear();
            return slice;
        }
    }

    public ChannelBuffer getBuffer(ByteOrder order, byte[] array, int offset, int length) {
        if (array == null) {
            throw new NullPointerException("array");
        } else if (offset < 0) {
            throw new IndexOutOfBoundsException("offset: " + offset);
        } else if (length == 0) {
            return ChannelBuffers.EMPTY_BUFFER;
        } else {
            if (offset + length > array.length) {
                throw new IndexOutOfBoundsException("length: " + length);
            }
            ChannelBuffer buf = getBuffer(order, length);
            buf.writeBytes(array, offset, length);
            return buf;
        }
    }

    public ChannelBuffer getBuffer(ByteBuffer nioBuffer) {
        if (!nioBuffer.isReadOnly() && nioBuffer.isDirect()) {
            return ChannelBuffers.wrappedBuffer(nioBuffer);
        }
        ChannelBuffer buf = getBuffer(nioBuffer.order(), nioBuffer.remaining());
        int pos = nioBuffer.position();
        buf.writeBytes(nioBuffer);
        nioBuffer.position(pos);
        return buf;
    }

    private ChannelBuffer allocateBigEndianBuffer(int capacity) {
        ChannelBuffer slice;
        synchronized (this.bigEndianLock) {
            if (this.preallocatedBEBuf == null) {
                this.preallocatedBEBuf = ChannelBuffers.directBuffer(ByteOrder.BIG_ENDIAN, this.preallocatedBufCapacity);
                slice = this.preallocatedBEBuf.slice(0, capacity);
                this.preallocatedBEBufPos = capacity;
            } else if (this.preallocatedBEBuf.capacity() - this.preallocatedBEBufPos >= capacity) {
                slice = this.preallocatedBEBuf.slice(this.preallocatedBEBufPos, capacity);
                this.preallocatedBEBufPos += capacity;
            } else {
                this.preallocatedBEBuf = ChannelBuffers.directBuffer(ByteOrder.BIG_ENDIAN, this.preallocatedBufCapacity);
                slice = this.preallocatedBEBuf.slice(0, capacity);
                this.preallocatedBEBufPos = capacity;
            }
        }
        return slice;
    }

    private ChannelBuffer allocateLittleEndianBuffer(int capacity) {
        ChannelBuffer slice;
        synchronized (this.littleEndianLock) {
            if (this.preallocatedLEBuf == null) {
                this.preallocatedLEBuf = ChannelBuffers.directBuffer(ByteOrder.LITTLE_ENDIAN, this.preallocatedBufCapacity);
                slice = this.preallocatedLEBuf.slice(0, capacity);
                this.preallocatedLEBufPos = capacity;
            } else if (this.preallocatedLEBuf.capacity() - this.preallocatedLEBufPos >= capacity) {
                slice = this.preallocatedLEBuf.slice(this.preallocatedLEBufPos, capacity);
                this.preallocatedLEBufPos += capacity;
            } else {
                this.preallocatedLEBuf = ChannelBuffers.directBuffer(ByteOrder.LITTLE_ENDIAN, this.preallocatedBufCapacity);
                slice = this.preallocatedLEBuf.slice(0, capacity);
                this.preallocatedLEBufPos = capacity;
            }
        }
        return slice;
    }
}