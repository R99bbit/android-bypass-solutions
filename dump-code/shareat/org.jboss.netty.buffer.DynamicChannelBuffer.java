package org.jboss.netty.buffer;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.GatheringByteChannel;
import java.nio.channels.ScatteringByteChannel;

public class DynamicChannelBuffer extends AbstractChannelBuffer {
    private ChannelBuffer buffer;
    private final ByteOrder endianness;
    private final ChannelBufferFactory factory;

    public DynamicChannelBuffer(int estimatedLength) {
        this(ByteOrder.BIG_ENDIAN, estimatedLength);
    }

    public DynamicChannelBuffer(ByteOrder endianness2, int estimatedLength) {
        this(endianness2, estimatedLength, HeapChannelBufferFactory.getInstance(endianness2));
    }

    public DynamicChannelBuffer(ByteOrder endianness2, int estimatedLength, ChannelBufferFactory factory2) {
        if (estimatedLength < 0) {
            throw new IllegalArgumentException("estimatedLength: " + estimatedLength);
        } else if (endianness2 == null) {
            throw new NullPointerException("endianness");
        } else if (factory2 == null) {
            throw new NullPointerException("factory");
        } else {
            this.factory = factory2;
            this.endianness = endianness2;
            this.buffer = factory2.getBuffer(order(), estimatedLength);
        }
    }

    public void ensureWritableBytes(int minWritableBytes) {
        int newCapacity;
        if (minWritableBytes > writableBytes()) {
            if (capacity() == 0) {
                newCapacity = 1;
            } else {
                newCapacity = capacity();
            }
            int minNewCapacity = writerIndex() + minWritableBytes;
            while (newCapacity < minNewCapacity) {
                newCapacity <<= 1;
                if (newCapacity == 0) {
                    throw new IllegalStateException("Maximum size of 2gb exceeded");
                }
            }
            ChannelBuffer newBuffer = factory().getBuffer(order(), newCapacity);
            newBuffer.writeBytes(this.buffer, 0, writerIndex());
            this.buffer = newBuffer;
        }
    }

    public ChannelBufferFactory factory() {
        return this.factory;
    }

    public ByteOrder order() {
        return this.endianness;
    }

    public boolean isDirect() {
        return this.buffer.isDirect();
    }

    public int capacity() {
        return this.buffer.capacity();
    }

    public boolean hasArray() {
        return this.buffer.hasArray();
    }

    public byte[] array() {
        return this.buffer.array();
    }

    public int arrayOffset() {
        return this.buffer.arrayOffset();
    }

    public byte getByte(int index) {
        return this.buffer.getByte(index);
    }

    public short getShort(int index) {
        return this.buffer.getShort(index);
    }

    public int getUnsignedMedium(int index) {
        return this.buffer.getUnsignedMedium(index);
    }

    public int getInt(int index) {
        return this.buffer.getInt(index);
    }

    public long getLong(int index) {
        return this.buffer.getLong(index);
    }

    public void getBytes(int index, byte[] dst, int dstIndex, int length) {
        this.buffer.getBytes(index, dst, dstIndex, length);
    }

    public void getBytes(int index, ChannelBuffer dst, int dstIndex, int length) {
        this.buffer.getBytes(index, dst, dstIndex, length);
    }

    public void getBytes(int index, ByteBuffer dst) {
        this.buffer.getBytes(index, dst);
    }

    public int getBytes(int index, GatheringByteChannel out, int length) throws IOException {
        return this.buffer.getBytes(index, out, length);
    }

    public void getBytes(int index, OutputStream out, int length) throws IOException {
        this.buffer.getBytes(index, out, length);
    }

    public void setByte(int index, int value) {
        this.buffer.setByte(index, value);
    }

    public void setShort(int index, int value) {
        this.buffer.setShort(index, value);
    }

    public void setMedium(int index, int value) {
        this.buffer.setMedium(index, value);
    }

    public void setInt(int index, int value) {
        this.buffer.setInt(index, value);
    }

    public void setLong(int index, long value) {
        this.buffer.setLong(index, value);
    }

    public void setBytes(int index, byte[] src, int srcIndex, int length) {
        this.buffer.setBytes(index, src, srcIndex, length);
    }

    public void setBytes(int index, ChannelBuffer src, int srcIndex, int length) {
        this.buffer.setBytes(index, src, srcIndex, length);
    }

    public void setBytes(int index, ByteBuffer src) {
        this.buffer.setBytes(index, src);
    }

    public int setBytes(int index, InputStream in, int length) throws IOException {
        return this.buffer.setBytes(index, in, length);
    }

    public int setBytes(int index, ScatteringByteChannel in, int length) throws IOException {
        return this.buffer.setBytes(index, in, length);
    }

    public void writeByte(int value) {
        ensureWritableBytes(1);
        super.writeByte(value);
    }

    public void writeShort(int value) {
        ensureWritableBytes(2);
        super.writeShort(value);
    }

    public void writeMedium(int value) {
        ensureWritableBytes(3);
        super.writeMedium(value);
    }

    public void writeInt(int value) {
        ensureWritableBytes(4);
        super.writeInt(value);
    }

    public void writeLong(long value) {
        ensureWritableBytes(8);
        super.writeLong(value);
    }

    public void writeBytes(byte[] src, int srcIndex, int length) {
        ensureWritableBytes(length);
        super.writeBytes(src, srcIndex, length);
    }

    public void writeBytes(ChannelBuffer src, int srcIndex, int length) {
        ensureWritableBytes(length);
        super.writeBytes(src, srcIndex, length);
    }

    public void writeBytes(ByteBuffer src) {
        ensureWritableBytes(src.remaining());
        super.writeBytes(src);
    }

    public int writeBytes(InputStream in, int length) throws IOException {
        ensureWritableBytes(length);
        return super.writeBytes(in, length);
    }

    public int writeBytes(ScatteringByteChannel in, int length) throws IOException {
        ensureWritableBytes(length);
        return super.writeBytes(in, length);
    }

    public void writeZero(int length) {
        ensureWritableBytes(length);
        super.writeZero(length);
    }

    public ChannelBuffer duplicate() {
        return new DuplicatedChannelBuffer((ChannelBuffer) this);
    }

    public ChannelBuffer copy(int index, int length) {
        DynamicChannelBuffer copiedBuffer = new DynamicChannelBuffer(order(), Math.max(length, 64), factory());
        copiedBuffer.buffer = this.buffer.copy(index, length);
        copiedBuffer.setIndex(0, length);
        return copiedBuffer;
    }

    public ChannelBuffer slice(int index, int length) {
        if (index == 0) {
            if (length == 0) {
                return ChannelBuffers.EMPTY_BUFFER;
            }
            return new TruncatedChannelBuffer(this, length);
        } else if (length == 0) {
            return ChannelBuffers.EMPTY_BUFFER;
        } else {
            return new SlicedChannelBuffer(this, index, length);
        }
    }

    public ByteBuffer toByteBuffer(int index, int length) {
        return this.buffer.toByteBuffer(index, length);
    }
}